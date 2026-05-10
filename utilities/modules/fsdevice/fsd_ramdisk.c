/*
  (c) 2026 Chris Royle
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

/* This implements a dummy FS device driver which serves up 
 * a single file of a given length, stored in RAM on a device
 * of 400k, free space 400k less the file length. The file can be
 * written to because it's stored in RAM.
 *
 * It is designed to illustrate how to write an FS device driver
 * for the Pi FS (2.2), such as something that reads floppy images,
 * which I suppose could include non-Acorn format if the relevant
 * filename translation gets implemented */

/* First, special comment which is grep'ped out by a script to
 * pick up the 'register' function and puts it in the fsdevice_list.h
 * file.
 */

/* Driver registration function. Called by the bridge at startup so that
 * the driver is known to all FSes.
 *
 * Returns: fs_device * ready populated, or NULL on failure.
 */

FSDEVICE_REGISTER(fsd_ramdisk_register);

#include "fs.h"
#include "econet-hpbridge.h"

/* Driver name & description */

#define DRIVERNAME "RAMDISC"
#define DRIVERDESCRIPTION "RAM disc driver"

/* Define our defaults; these will eventually come from JSON within the Driver section, or FS (in that order of preference)
 * and if not set in either, then these are the default
 */

#define DISCSIZE 400 /* Kilobytes */
#define SECTORSIZE 256 /* Bytes */
#define DIRSECTORS 2 /* Notional number of sectors required for a directory, including root */

/* Max filename length */

#define RAMDISKMAXFNLENGTH ECONET_ABS_MAX_FILENAME_LENGTH

/* A user handle to a file 
 * We don't bother with whether its read or write - the FS handles
 * the interlocking.
 */

struct fsd_ramdisk_handle {
	off_t		cursor; /* Current cursor */
	void *		file; /* Upward pointer; requires cast */
	struct fsd_ramdisk_handle *prev, *next; /* Next handle to this file */
};

/* 
 * Structure holding a directory entry
 */

struct fsd_ramdisk_dirent {
	char		name[RAMDISKMAXFNLENGTH+1]; /* NULL terminated, not 0x0D */
	enum 		{ FSD_RAM_FILE = 1, FSD_RAM_DIR } type;
	union {
		struct {
			uint8_t	perm;
			uint32_t	load, exec;
			uint32_t	length;
			void 		*data; /* eb_malloc()d data space */
		}; /* If a file, this is its content */
		void *directory; /* If a directory, points to a fsd_ramdisk_dir */
	};
	uint16_t	owner; /* Object owner. Obviously if mounted on two different FSs, this might get confusing. */
	struct fsd_ramdisk_handle *handles; /* Linked list of handles. NULL if file not open */
	struct fsd_ramdisk_dirent *prev, *next; /* Null for first/last; the list is kept in order */
};

/*
 * Structure which holds a directory catalogue
 */

struct fsd_ramdisk_dir {
	struct fsd_ramdisk_dirent	*first; /* Pointer to first in sorted list */
	char				*name; /* Pointer, set to the name field in fsd_ramdisk_dirent relevant to this dir; points to a string in fsd_ramdisk_instance if this is the root directory */
};

/* 
 * An instance of a disk
 */

struct fsd_ramdisk_disc {
	uint32_t		sectors_total; /* RAM disk size in sectors */
	uint32_t		sectors_free; /* Free sectors */
	uint16_t		sector_size; /* Size of a single sector */
	uint8_t			sectors_per_dir; /* Number of notional sectors occupied by a directory */
	uint32_t		num_dirents; /* Number of directory entries including $ */
	uint16_t		num_mounts; /* Concurrent mounts */
	uint16_t		num_open; /* Number of open files - so we don't umount with things open */
	char			name[17]; /* Disk name */
	char			rootdirname [2]; /* Gives *name in fsd_ramdisk_dir for the root something to point to */
	struct fsd_ramdisk_dir	*root; /* Pointer to root directory */
	void			*mounts; /* Pointer to first mount */
	void			*instance; /* Upward pointer to instance */
	struct fsd_ramdisk_disc	*prev, *next; /* Prev/Next discs in this instance */
};

struct fsd_ramdisk_disc_mount {
	struct fsd_ramdisk_disc	*disc; /* Upward pointer */
	uint16_t	num_open; /* Number of open files - so we don't unmount if things are open */
	struct fsd_ramdisk_disc_mount *prev, *next; /* List links */
};

struct fsd_ramdisk_instance {
	struct __fs_station	*station; /* Server we're mounted on */
	struct fsd_ramdisk_disc *first; /* Pointer to first disc */
	struct fsd_ramdisk_instance *prev, *next;
};

struct fsd_ramdisk_instance *fsd_ramdisk_instances = NULL;

/* Function prototypes */

fs_device *	fsd_ramdisk_register(void);
int 		fsd_ramdisk_unregister(fs_device *);
fs_device_instance * fsd_ramdisk_init(void *, struct json_object *);
int 		fsd_ramdisk_release (fs_device_instance *);
fs_device_mount * fsd_ramdisk_mount (void *, fs_device_instance *, char *params, uint32_t flags);
int 		fsd_ramdisk_umount (fs_device_mount *);
char *		fsd_ramdisk_get_discname (fs_device_mount *);
int		fsd_ramdisk_open (fs_device_mount *, const char *, int flags, fs_device_handle **);
int		fsd_ramdisk_close (fs_device_handle *);
ssize_t		fsd_ramdisk_read (fs_device_handle *, void *, size_t len);
ssize_t		fsd_ramdisk_write (fs_device_handle *, const void *, size_t len);
off_t		fsd_ramdisk_seek (fs_device_handle *, off_t, int);
off_t		fsd_ramdisk_tell (fs_device_handle *);
int		fsd_ramdisk_getattr (fs_device_mount *, const char *, void **);
int		fsd_ramdisk_setattr (fs_device_mount *, const char *, void *);
uint32_t	fsd_ramdisk_getsysid (fs_device_mount *, const char *);
int		fsd_ramdisk_normalize_wildcard (fs_device_mount *, unsigned char *, void *, unsigned short);
int		fsd_ramdisk_statvfs (fs_device_mount *, struct statvfs *);
int		fsd_ramdisk_create (fs_device_mount *, const char *, size_t);
int		fsd_ramdisk_truncate (fs_device_mount *, const char *, size_t);
int		fsd_ramdisk_unlink (fs_device_mount *, const char *);

static __fs_device_funcs fsd_ramdisk_funcs = {
	.dev_report_schema = NULL, /* Not implemented in this driver */
	.dev_unregister = fsd_ramdisk_unregister,
	.fs_init = fsd_ramdisk_init,
	.fs_release = fsd_ramdisk_release,
	.mount = fsd_ramdisk_mount,
	.umount = fsd_ramdisk_umount,
	.get_discname = fsd_ramdisk_get_discname,
	.open = fsd_ramdisk_open,
	.close = fsd_ramdisk_close,
	.read = fsd_ramdisk_read,
	.write = fsd_ramdisk_write,
	.seek = fsd_ramdisk_seek,
	.tell = fsd_ramdisk_tell,
	.getattr = fsd_ramdisk_getattr,
	.setattr = fsd_ramdisk_setattr,
	.getsysid = fsd_ramdisk_getsysid,
	.normalize_wildcard = fsd_ramdisk_normalize_wildcard,
	.statvfs = fsd_ramdisk_statvfs,
	.create = fsd_ramdisk_create,
	.truncate = fsd_ramdisk_truncate,
	.unlink = fsd_ramdisk_unlink
};

/* Sector calculator
 */

uint32_t fsd_ramdisk_sectors(struct fsd_ramdisk_disc *d, uint32_t filesize)
{
	return (filesize / d->sector_size) + ((filesize % d->sector_size) ? 1 : 0); /* Sectors, and add one for a partial */
}


fs_device *fsd_ramdisk_register(void)
{
	fs_device *fsd_ramdisk = fsd_malloc("FS Device driver RAMdisk fs_device_proto struct", sizeof(fs_device));

	if (fsd_ramdisk)
	{
		fsd_ramdisk->device_name = fsd_malloc("FS Device driver RAMdisk device name string", strlen(DRIVERNAME)+1);
		fsd_ramdisk->device_description = fsd_malloc("FS Device driver RAMdisk device description", strlen(DRIVERDESCRIPTION)+1);
		if (!fsd_ramdisk->device_name || !fsd_ramdisk->device_description)
		{
			eb_debug (1, 0, "FSDEV", "Unable to allocate memory for device info for driver %s", DRIVERNAME);
			if (fsd_ramdisk->device_name) fsd_free("FS Device driver RAMdisk device name string", fsd_ramdisk->device_name);
			if (fsd_ramdisk->device_description) fsd_free("FS Device driver RAMdisk device name description", fsd_ramdisk->device_description);
			fsd_free("FS Device driver RAMdisk fs_device_proto", fsd_ramdisk);
			return NULL;
		}
		else
		{
			strcpy(fsd_ramdisk->device_name, DRIVERNAME);
			strcpy(fsd_ramdisk->device_description, DRIVERDESCRIPTION);
			fsd_ramdisk->device_funcs = &fsd_ramdisk_funcs;
			fsd_ramdisk->next = NULL;
		}
	}
	else
		fs_debug (1, 0, "FSDEV", "Unable to allocate memory for fs_device struct for driver %s", DRIVERNAME);

	return fsd_ramdisk; /* Will be NULL if eb_malloc failed */
}

/* fsd_ramdisk_unregister 
 *
 * Called by the bridge (not the FS) when it's time to unload -
 * e.g. on bridge quit.
 *
 * The function can assume that the bridge has already taken the struct
 * out of its linked list, so that it can be free()d.
 */

int 	fsd_ramdisk_unregister(fs_device *d)
{

	struct fsd_ramdisk_instance *fsdi = fsd_ramdisk_instances; /* We need to free them */
	struct fsd_ramdisk_instance *n;

	while (fsdi)
	{
		n = fsdi->next;
		fsd_ramdisk_release ( (fs_device_instance *) fsdi);
		fsdi = n;
	}

	fsd_ramdisk_instances = NULL;

	/* That's all the instances released */

	fsd_free ("Freeing RAMdisc device structure", d);

	return 0;

}

/* fsd_ramdisk_init
 *
 * Called by a FS that wishes to have a means of mounting
 * devices using this driver. This exists because in future
 * it may be that only particular drivers are available
 * in particular FS instances.
 *
 * Parameters
 *
 * dev - pointer to __fs_station (cast to void) on which to be to be instantiated
 * json - pointer to json_object of parameters for this device in this FS (e.g. location of disc images). (Will be NULL if no object in the condif.)
 *
 * Returns
 *
 * fs_device_instance * - data stored by the FS for this instantiation. NULL is a failure, but the FS doesn't look into what's inside
 *
 * NB: This particular device driver has a single RAM disk per FS. If your device might have
 * many different virtual discs accessible to each FS, you'll want to just set up some private data here
 * and use the params parameter on mount to discriminate which one they want!
 *
 */

fs_device_instance *fsd_ramdisk_init (void *stn_void, struct json_object *json)
{
	struct __fs_station *stn = (struct __fs_station *) stn_void;
	struct fsd_ramdisk_instance *fsdi = NULL;
	uint8_t found = 0;

	/* See if this station has already initialized? */

	fsdi = fsd_ramdisk_instances;

	while (!found && fsdi)
	{
		if (fsdi->station == stn)
			found = 1;
		else fsdi = fsdi->next;
	}

	if (found)
	{
		fs_debug_full (0, 1, stn, 0, 0, "Attempt to initialize RAMdisk driver a second time!");
		return NULL;
	}

	/* Otherwise, allocate a new instance */

	fsdi = fsd_malloc ("RAMdisk instance struct", sizeof(struct fsd_ramdisk_instance));

	if (!fsdi)
	{
		fs_debug_full (0, 1, stn, 0, 0, "Unable to allocate memory for new RAMdisk instance!");
		return NULL;
	}

	fsdi->station = stn;
	fsdi->prev = fsdi->next = NULL;
	fsdi->first = NULL; /* No discs until someone tries to mount one */

	return fsdi;

}


/* Delete a file, freeing up its storage as you go.
 * Caller will need to splice the pointer called 'file'
 * out of the list before or after calling this function.
 *
 * Called with fsdi so that free space can be maintained.
 *
 * Returns 0 for success, -1 if file is NULL or not a file.
 *
 */

int fsd_ramdisk_delete_file (struct fsd_ramdisk_disc *fsdd, struct fsd_ramdisk_dirent *file)
{
	int ret = -1;

	if (file && file->type == FSD_RAM_FILE)
	{
		fsdd->sectors_free += fsd_ramdisk_sectors(fsdd, file->length);
		fsdd->num_dirents--;
		fsd_free ("RAMdisk file data", file->data);
		fsd_free ("RAMdisk file struct", file);
		ret = 0;
	}

	return ret;
}

/* Delete a directory, recursively, and then free its memory. 
 * The caller will then need to take the pointer to this
 * directory out of its parent's list of directory entries.
 *
 * Called with fsdi so that free space can be maintained.
 *
 * Returns 0 for success, -1 if dir is NULL or not a directory
 *
 */

void fsd_ramdisk_delete_dir_recursive (struct fsd_ramdisk_disc *fsdd, struct fsd_ramdisk_dir *dir)
{
	struct fsd_ramdisk_dirent *de = dir->first; /* First directory entry */

	/* Go through each directory entry and delete */

	while (de)
	{
		if (de->type == FSD_RAM_DIR)
			fsd_ramdisk_delete_dir_recursive (fsdd, (struct fsd_ramdisk_dir *) de->directory);
		else
			fsd_ramdisk_delete_file (fsdd, de);

		de = de->next;
	}

	/* Free up this directory */

	fsdd->sectors_free += fsdd->sectors_per_dir;
	fsdd->num_dirents--;

	fsd_free ("RAMdisk driver freeing directory structure", dir);

}

/* fsd_ramdisk_release
 *
 * Detach instance from FS. Enables cleanup of a given instance.
 *
 * Parameters
 *
 * device - the instance to be detached
 *
 * Return
 *
 * 0 - Success
 * Anything else - Error
 */

int fsd_ramdisk_release (fs_device_instance *device)
{
	struct fsd_ramdisk_instance *fsdi = (struct fsd_ramdisk_instance *) device;
	struct fsd_ramdisk_disc *fsdd;

	if (fsdi)
	{
		fsdd = fsdi->first;

		fs_debug_full (0, 1, fsdi->station, 0, 0, "Releasing RAMdisk driver");

		/* Cycle through the disks */

		while (fsdd)
		{
			struct fsd_ramdisk_disc *n = fsdd->next, *p = fsdd->prev;

			if (fsdd->num_mounts)
			{
				fs_debug_full(0, 1, fsdi->station, 0, 0, "Unable to release RAMdisk driver - disc %s is mounted", fsdd->name);
				return -1;
			}

			/* Delete contents of disc */

			fsd_ramdisk_delete_dir_recursive (fsdd, fsdd->root);

			/* The mount list should already be empty, so nothing to free */

			/* Free the disk */

			fsd_free ("Freeing RAMdisk disk structure", fsdd);

			if (p)
				p->next = n; /* Though this should never happen! */
			else	fsdi->first = n;

			if (n)
				n->prev = p;

			fsdd = n;
		}

		/* Free the instance */

		/* Splice it out of the driver's list */

		if (fsdi->next)
			fsdi->next->prev = fsdi->prev;

		if (fsdi->prev)
			fsdi->prev->next = fsdi->next;
		else
			fsd_ramdisk_instances = fsdi->next;

		fsd_free ("RAMdisc driver freeing private storage", fsdi);

		return 0; /* Success */
	}
	else
		eb_debug (0, 1, "FSDEVICE", "Attempt to release NULL RAMdisk");

	return -1;

}

/* fsd_ramdisk_ismounted_bydisc
 *
 * Is a particular disc mounted by reference to its disc structure?
 */

int fsd_ramdisk_ismounted_bydisc(struct fsd_ramdisk_disc *fsdd)
{
	if (fsdd->mounts)
		return 1;
	else
		return 0;
}

/*
 * fsd_ramdisk_ismounted_byname
 *
 * Returns 1 if the specified disc name is mounted
 */

int fsd_ramdisk_ismounted_byname(char *discname, struct fsd_ramdisk_instance *fsdi)
{
	regex_t	disc_regex;
	uint8_t found = 0;
	struct fsd_ramdisk_disc *fsdd; /* Tracks which disc on the instance we're looking at */
	
	if (regcomp(&disc_regex, "^" FSACORNREGEX "{1,16}$", REG_EXTENDED | REG_ICASE)) /* non-zero is failure */
	{
		eb_debug (0, 1, "RAMDISK", "Unable to compile disc name regex");
		return 0;
	}

	/* Traverse the instance's list of mounts */

	fsdd = fsdi->first;

	while (!found && fsdd)
	{
		if (!regexec(&disc_regex, fsdd->name, 0, NULL, 0)) /* Found disc */
		{
			if (fsd_ramdisk_ismounted_bydisc(fsdd)) /* There's at least one mount */
				found = 1;
			else
				fsdd = fsdd->next;
		}
		else
			fsdd = fsdd->next;
	}

	regfree(&disc_regex);

	return found;
}

/* fsd_ramdisk_disc_exists
 *
 * Check if a disc exists on an instance and, if it does,
 * return its disc structure
 *
 * discname must already be upper case
 *
 */

struct fsd_ramdisk_disc * fsd_ramdisk_disc_exists (char * discname, struct fsd_ramdisk_instance *fsdi)
{
	struct fsd_ramdisk_disc *fsdd = fsdi->first; /* Start at first disc */

	while (fsdd && strcmp(fsdd->name, discname)) /* Not found */
		fsdd = fsdd->next;

	return fsdd; /* Will be NULL if we trip off end of list */

}

/* fsd_ramdisk_mount
 *
 * Mount a disc into a particular FS
 *
 * Parameters
 *
 * device - instance of the driver to mount with
 * params - parameter string off the command line, the bit beyond '*FSMOUNT <disc no.> <driver name>'
 * flags - some flags we haven't defined at the time I wrote this, probably will include FSD_READONLY for read only discs
 *
 * Return
 *
 * fs_device_mount * - private data from this driver used to identify this mount. FS won't look inside it.
 *
 */

fs_device_mount * fsd_ramdisk_mount (void *station, fs_device_instance *device, char *params, uint32_t flags)
{
	struct fsd_ramdisk_instance *fsdi = (struct fsd_ramdisk_instance *) device;

	struct fsd_ramdisk_disc_mount *fsdm = NULL;
	struct fsd_ramdisk_disc *fsdd = NULL;

	regex_t param_regex;
	regmatch_t param_match[5];
	int matches;

	char 	discname[17];
	uint8_t	discname_length;

	if (regcomp(&param_regex, "^\\s*(" FSACORNREGEX "{1,16})\\s*$", REG_EXTENDED | REG_ICASE))
	{
		eb_debug (0, 1, "RAMDISK", "Unable to compile disc name regex");
		return NULL;
	}

	if ((matches = regexec(&param_regex, params, 1, param_match, 0))) /* Failed */
	{
		eb_debug (0, 1, "RAMDISK", "Unable to execute disc name regex");
		regfree (&param_regex);
		return NULL;
	}

	if (param_match[1].rm_so == -1) /* Not found */
	{
		regfree (&param_regex);
		return NULL;
	}

	discname_length = param_match[1].rm_eo - param_match[1].rm_so;

	memcpy (discname, params + param_match[1].rm_so, discname_length);

	discname[discname_length] = 0; /* Terminate */

	/* Convert to uppercase */

	fs_toupper(discname);
	
	if (!(fsdd = fsd_ramdisk_disc_exists(discname, fsdi))) /* If the disc doesn't exist, make one */
	{
		FS_LIST_MAKENEW(struct fsd_ramdisk_disc, fsdi->first, 1, fsdd, "RAMDISK", "New disc structure");

		if (fsdd) /* Succeeded */
		{
			struct fsd_ramdisk_dir *root;

			root = fsd_malloc("RAMDisk root directory", sizeof (struct fsd_ramdisk_dir));

			if (!root) /* Created */
				fs_debug_full (0, 1, fsdi->station, 0, 0, "Unable to allocate memory for RAMdisk root dir");
			else
			{
				/* Set up root dir */

				strcpy (fsdd->rootdirname, "$");
				root->name = fsdd->rootdirname;
				root->first = NULL; /* Empty root directory */

				fsdd->root = root; /* Set up disc pointer to root dir */
				strcpy (fsdd->name, discname); /* Copy the provided disc name */
				fsdd->sector_size = SECTORSIZE; /* Will eventually come from FS or Drivers JSON, or default to this */
				fsdd->sectors_total = (DISCSIZE * 1024) / fsdd->sector_size; /* Defaults for now, until we get JSON from the FS */
				fsdd->sectors_per_dir = DIRSECTORS;
				fsdd->sectors_free = fsdd->sectors_total - fsdd->sectors_per_dir; /* Deduct space for root dir */
				fsdd->num_mounts = 0; /* We are mounting this now, but we'll increment this when we manage it */
				fsdd->num_open = 0; /* Disc not mounted, no files open */
				fsdd->num_dirents = 1; /* Just $ */
				fsdd->mounts = NULL; /* Nothing mounted yet - but will be in a mo */
				fsdd->instance = (void *) fsdi; /* Upward pointer */

				fs_debug_full (0, 2, fsdi->station, 0, 0, "RAMDisk initialized %dk, disc name %s", (fsdd->sectors_total * SECTORSIZE) / 1024, fsdd->name);
			}
		}
		else
			fs_debug_full (0, 1, fsdi->station, 0, 0, "Unable to allocate new disc structure for %s", discname);
	}

	/* If by here we have a disc, mount it (again if necessary) */

	if (fsdd)
	{
		FS_LIST_MAKENEW(struct fsd_ramdisk_disc_mount, fsdd->mounts, 1, fsdm, "RAMDISK", "New RAMDISK mount structure");

		if (!fsdm) /* Failed */
			fs_debug_full (0, 1, fsdi->station, 0, 0, "Failed to allocate memory for RAMDISK mount");
		else
		{
			fsdm->disc = fsdd; /* The next & prev will have been set up by FS_LIST_MAKENEW() */
			fsdm->num_open = 0; /* Nothing open at present */
			fsdd->num_mounts++;
		}
	}

	regfree (&param_regex);

	return (fs_device_mount *) fsdm; /* Will be NULL on failued; otherwise points to a mount */

}
		
/*
 * fsd_ramdisk_umount
 *
 * Umount the disc from a particular FS.
 *
 * Parameters
 *
 * mount_instance - the structure of our mount instance, which this routine will free
 *
 * Returns
 *
 * 0 - Success
 * 1 - Not.
 */

int fsd_ramdisk_umount (fs_device_mount *mount_instance)
{
	struct fsd_ramdisk_disc_mount *fsdm = (struct fsd_ramdisk_disc_mount *) mount_instance;
	struct fsd_ramdisk_instance *fsdi;
	struct fsd_ramdisk_disc *fsdd;

	if (fsdm)
	{
		/* Find instance */

		fsdi = (struct fsd_ramdisk_instance *) fsdm->disc->instance; /* Requires cast as defined as void */
		fsdd = fsdm->disc;
	
		if (!fsdm->num_open) /* Should not be anything open or we cannot umount */
		{

			/* We don't destroy the disc on an umount - we might want it again. We destroy them on a _release call */
	
			if (fsdd->num_mounts) /* Should always be > 0 otherwise there's a problem */
			{
				/* Reduce disc mount count & report */

				fsdd->num_mounts--;
				fs_debug_full (0, 1, fsdi->station, 0, 0, "Unmounting RAMdisk %s", fsdd->name);

				/* Splice out of list */

				FS_LIST_SPLICEFREE(fsdd->mounts,fsdm,"RAMDISK","Free RAMdisk mount structure");

				return 0; /* Success */
			}
			else
				fs_debug_full (0, 1, fsdi->station, 0, 0, "Unmounting RAMdisk failed: identified disc is not mounted!");
		}
		else
			fs_debug_full (0, 1, fsdi->station, 0, 0, "Cannot umount RAMdisk %s: files open", fsdd->name);

	}
	else
		eb_debug (0, 1, "FSDEVICE", "Attempt to unmount RAMdisk but NULL disk provided!");

	return -1; /* Failed */

}


/* 
 * fsd_ramdisk_get_discname
 *
 * Get the mounted disc name
 *
 * Parameters
 *
 * mount_instance - the mount for which we want the name
 *
 * Returns
 *
 * char * pointer to name
 */

char *fsd_ramdisk_get_discname(fs_device_mount *mount_instance)
{
	struct fsd_ramdisk_disc_mount *fsdm = (struct fsd_ramdisk_disc_mount *) mount_instance;

	if (fsdm)
		return fsdm->disc->name; /* Disc name */
	else	
	{
		eb_debug (0, 1, "FSDEVICE", "Attempt to get name of NULL RAMdisk!");
		return NULL;
	}
}

/* fsd_ramdisk_statvfs
 *
 * Get disk info
 */

int	fsd_ramdisk_statvfs (fs_device_mount *mount, struct statvfs *svb)
{

	struct fsd_ramdisk_disc_mount *fsdm = (struct fsd_ramdisk_disc_mount *) mount;
	struct fsd_ramdisk_disc *fsdd;
	int	ret;

	if (fsdm)
	{
		fsdd = fsdm->disc; /* Disc instance */

		svb->f_bsize = fsdd->sector_size; /* Block size */
		svb->f_frsize = svb->f_bsize; /* Fragment size */
		svb->f_blocks = fsdd->sectors_total; /* Total blocks */
		svb->f_bavail = svb->f_bfree = fsdd->sectors_free; /* Free blocks */
		svb->f_files = fsdd->num_dirents; /* Number of dirs/files (inodes in Unix speak) */
		svb->f_favail = svb->f_ffree = 4096-svb->f_files; /* Fudge! */
		svb->f_fsid = svb->f_flag = 0; /* Not used within Pi FS */
		svb->f_namemax = 10; /* Max filename length */

		ret = 0;
	}
	else
	{
		eb_debug (0, 1, "FSDEVICE", "Attempt to call fsd_ramdisk_statvfs with NULL mount!");
		ret = -1;
	}

	return ret;
}

/* Unwritten prototypes */
#if 0
int		fsd_ramdisk_open (fs_device_mount *, char *, int flags, fs_device_handle **);
int		fsd_ramdisk_close (fs_device_handle *);
ssize_t		fsd_ramdisk_read (fs_device_handle *, void *, size_t len);
ssize_t		fsd_ramdisk_write (fs_device_handle *, const void *, size_t len);
int		fsd_ramdisk_getattr (fs_device_mount *, const char *, void **);
int		fsd_ramdisk_setattr (fs_device_mount *, const char *, void *);
int		fsd_ramdisk_normalize_wildcard (fs_device_mount *, unsigned char *, void *, unsigned short);
int		fsd_ramdisk_create (fs_device_mount *, const char *, size_t);
int		fsd_ramdisk_truncate (fs_device_mount *, const char *, size_t);
int		fsd_ramdisk_unlink (fs_device_mount *, const char *);
#endif

/* fsd_ramdisk_open
 *
 * Open a file on a disk
 *
 * Returns 0 for success; puts the handle in final parameter
 */

int		fsd_ramdisk_open (fs_device_mount * fsdm, const char * p, int flags, fs_device_handle **handle) 
{
	return 1;
}

/* fsd_ramdisk_close
 *
 * Close file
 *
 * Returns 0 for success
 */

int		fsd_ramdisk_close (fs_device_handle * fsdh)
{
	return 1;
}

/* 
 * fsd_ramdisk_read
 *
 * Read from open file
 *
 * Returns same as open().2
 */

ssize_t		fsd_ramdisk_read (fs_device_handle * fsdh, void * buf, size_t len)
{
	return -1;
}

/* fsd_ramdisk_write
 *
 * Mirrors write().2
 */ 

ssize_t		fsd_ramdisk_write (fs_device_handle * fsdh, const void * buf, size_t len)
{
	return -1;
}

/*
 * fsd_ramdisk_getattr
 *
 * Get Acorn attributes
 */

int		fsd_ramdisk_getattr (fs_device_mount *fsdm, const char *p, void ** attr)
{
	return 0;
}

/*
 * fsd_ramdisk_setattr
 *
 * Set Acorn attributes
 */

int		fsd_ramdisk_setattr (fs_device_mount *fsdm, const char *p, void * attr)
{
	return 0;
}

/* fsd_ramdisk_create
 *
 * Create new file of given size
 */

int		fsd_ramdisk_create (fs_device_mount *fsdm, const char *p, size_t sz)
{
	return -1;
}

/* fsd_ramdisk_truncate
 *
 * Set file size (this can shrink a file as well)
 */

int		fsd_ramdisk_truncate (fs_device_mount *fsdm, const char *p, size_t sz)
{
	return -1;
}

/* fsd_ramdisk_unlink
 *
 * Delete a file
 */

int		fsd_ramdisk_unlink (fs_device_mount * fsdm, const char *p)
{
	return -1;
}

/* 
 * RAMDISK normalize function
 *
 * mount - the mounted device to search on
 * path - the path to normalize (which can include wildcards)
 * result - is void, but is actually struct path * - where to put your results. Must complete just the same was as fsop_normalize_path_wildcard() in fs.c
 * wildcard - 1 = do wildcard match; otherwise don't.
 *
 * Return value:
 * -1 - Failure
 *  0 - Hard failure. See result->error for why. (See defines for FS_PATH_ERR... constants
 *  1 - Success
 */

int		fsd_ramdisk_normalize_wildcard (	fs_device_mount *mount, 
							unsigned char *path, 
							void *result, 
							unsigned short wildcard
						)
{
	struct path *res = (struct path *) result;
	struct path_entry *pe; /* Used to create new entries */
	int ret = -1;



	return ret;
}

/* File status functions */

/* fsd_ramdisk_tell
 *
 * Return current cursor on handle
 */

off_t		fsd_ramdisk_tell (fs_device_handle *h)
{
	struct fsd_ramdisk_handle *fsdh = (struct fsd_ramdisk_handle *) h;

	if (fsdh)
		return fsdh->cursor;
	else
	{
		eb_debug (0, 1, "RAMDISK", "fsd_ramdisk_tell() called with NULL handle");
		return 0;
	}
}


/* fsd_ramdisk_seek
 *
 * move cursor
 *
 * Just as per lseek(), this will allow setting cursor beyond EOF and will not extend the file by doing so.
 * A write at that point will put zeros on the end of the file before the written data.
 */

off_t		fsd_ramdisk_seek (fs_device_handle *h, off_t newcursor, int whence)
{
	off_t	final;
	struct fsd_ramdisk_handle * fsdh = (struct fsd_ramdisk_handle *) h;
	struct fsd_ramdisk_dirent * de;

	if (!fsdh)
	{
		eb_debug (0, 1, "RAMDISK", "fsd_ramdisk_seek() called with NULL handle");
		return 0;
	}

	de = (struct fsd_ramdisk_dirent *) fsdh->file;

	final = newcursor + (whence == SEEK_CUR ? fsdh->cursor :
			    whence == SEEK_END ? de->length : 0);

	fsdh->cursor = final;

	return final;

}

/* fsd_ramdisk_getsysid 
 *
 * Get System file ID. 
 *
 */

uint32_t	fsd_ramdisk_getsysid (fs_device_mount * fsdm, const char * p)
{
	return 0; /* for now */
}

