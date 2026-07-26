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

/*
 * We define this because the
 * macros in fsdevice.h use it for 
 * inserting text into eb_debug, eb_malloc, etc.
 *
 * Must define it before the main includes
 *
 */

#define FSDEVICE "SYS"

#include "econet-hpbridge.h"
#include "fs.h"

struct fsd_SYS_instance;
struct fsd_SYS_disc;
struct fsd_SYS_mount;
static struct fs_device_funcs fsd_SYS_funcs;
uint16_t fsd_SYS_max_discno = 0;

/* Represents a disc */

struct fsd_SYS_disc {
	uint8_t	index;
	uint32_t	blocksize; /* In bytes */
	struct fsd_SYS_instance	*instance; /* Parent instance */
	struct fsd_SYS_disc	*next, *prev;
	uint32_t	readers, writers; /* Interlocks */
	uint8_t		readonly; /* Whether read only */
	char 	name[16]; /* Name of disc */
	char	path[128]; /* Full pathname to disc, from root of system filesystem */
};

/* 
 * Identifies when there is something mounted within our mount
 */

struct fsd_SYS_submount {
	char	*where; /* Path from root of parent mount */
	fs_device_mount	*mount; /* The mount point itself - which has a ref to the driver in it */
	struct fsd_SYS_submount *next, *prev; /* List of submounts on this mount */
};

/* 
 * A mount of one of our discs 
 */

struct fsd_SYS_mount {
	fs_device	*device; /* Must be first element - the driver subsystem does a cast to dig this out */
	struct __fs_station	*server; /* Must be second element for the same reason - the stub struct wants it here */
	struct fsd_SYS_instance	*instance; /* Instance on which this mount has been created */
	uint8_t		readonly; /* Mount is read only */
	struct fsd_SYS_disc	*disc; /* Disc being mounted */
	uint8_t			fs_disc; /* FS Disc index containing this mount */
	uint8_t		readers, writers; /* Count, so that we can cope with > 1 mount if interlock is ok */
	int			flags; /* Mount flags */
	struct fsd_SYS_submount *submounts; /* Linked list of submounts */
	struct fsd_SYS_mount *next, *prev; /* links */
};

/* Instance of our driver on a particular FS */

struct fsd_SYS_instance {
	fs_device	*device; /* Parent device pointer */
	struct __fs_station *fs_parent; /* Parent fileserver */
	char directory[128]; /* Server root dir, where we found our "discs" */
	uint8_t	use_inf; /* Use :inf files for perms etc. */
	struct fsd_SYS_disc	*discs; /* First disc */
	struct fsd_SYS_mount	*mounts; /* Mount list */
	struct fsd_SYS_instance *next, *prev; 
};

fs_device	*fsd_SYS_registration_struct = NULL;

struct fsd_SYS_instance	*fsd_SYS_instance_list = NULL;

struct fsd_SYS_handle {
	/* First two elements mandatory for the main driver subsystem to identify device & mount */
	fs_device	*device;
	struct fsd_SYS_mount	*mount;
	FILE 	*handle;
	uint8_t	flags; /* bit 1 = writing; bit 0 = read */
};

/* 
 * FS SYS driver
 *
 * Implements a driver which reads/writes the underlying
 * Linux/Unix filesystem
 */

/* Prototypes - only needed in this file */

struct json_object * fsd_SYS_report_schema (void);
fs_device_instance * fsd_SYS_init (struct __fs_station *, struct json_object *);
int fsd_SYS_release (fs_device_instance *);
int fsd_SYS_unregister (void);
fs_device_mount * fsd_SYS_mount (fs_device_instance *, char *, uint32_t, uint8_t, int *);
int fsd_SYS_umount (fs_device_mount *);
int fsd_SYS_register_disc(fs_device_instance *, char *, char *, uint32_t);
char * fsd_SYS_getdiscname (fs_device_mount *);
int fsd_SYS_open (fs_device_mount *, const char *, int, fs_device_handle **, int *);
int fsd_SYS_close (fs_device_handle *, int *);
int fsd_SYS_read (fs_device_handle *, void *, size_t, int *);
int fsd_SYS_write (fs_device_handle *, const void *, size_t, int *);
int fsd_SYS_seek (fs_device_handle *, off_t, int, int *);
off_t fsd_SYS_tell (fs_device_handle *, int *);
int fsd_SYS_getattr (fs_device_mount *, const char *, struct objattr *);
int fsd_SYS_getattr_unix (struct fsd_SYS_mount *, char *, struct objattr *);
int fsd_SYS_setattr (fs_device_mount *, const char *, struct objattr *);
int fsd_SYS_setattr_unix (struct fsd_SYS_mount *, char *, struct objattr *);
int fsd_SYS_getsysid (fs_device_mount *, const char *);
int fsd_SYS_statvfs (fs_device_mount *, struct statvfs *, int *);
int fsd_SYS_create (fs_device_mount *, const char *, size_t, int *);
int fsd_SYS_truncate (fs_device_handle *, size_t, int *);
int fsd_SYS_unlink (fs_device_mount *, const char *, int *);
int16_t fsd_SYS_getdiscblocksize (fs_device_mount *);

void fsd_SYS_path_acorn_to_unix(char *);
void fsd_SYS_path_unix_to_acorn(char *);

/* Convert Acorn filename to Unix-compatible */

void fsd_SYS_path_acorn_to_unix(char *path)
{
	uint32_t count = 0;
	uint8_t first_char = 1; /* Used to track when we are on first character of a name within a directory, so that we convert / to & instead of ., so taht we don't go creating .files in Unix directories, and instead we use & */

	while (count < strlen(path))
	{
		uint8_t	old_first_char;

		old_first_char = first_char;

		first_char = 0;

		if (*(path+count) == '/')
			*(path+count) = (old_first_char ? '&' : '.');
		else if (*(path+count) == '.')
		{
			*(path+count) = '/'; /* Dir separator */
			first_char = 1;
		}

		count++;
	}
}

/* Convert Unix-compatible filename to Acorn */

void fsd_SYS_unix_to_acorn(char *path)
{
	uint32_t count = 0;

	while (count < strlen(path))
	{
		if (*(path+count) == '/') /* Dir separator */
			*(path+count) = '.';
		if (*(path+count) == '&' || *(path+count) == '.') /* . in Unix is / in Acorn; but & is used instead of . at start of a filename to avoid creating dotfiles */
			*(path+count) = '/';

		count++;
	}
}

/* Convert PiFS perms to Acorn Perms & vice-versa */

uint8_t	fsd_SYS_perm_to_acorn(struct __fs_station *s, uint8_t fs_perm, uint8_t is_dir)
{

	uint8_t r;

	r = fs_perm & FS_PERM_H; // High bit

	if (is_dir)
		r |= 0x20;

	if (fs_perm & FS_PERM_L)
		r |= 0x10;

	if (s->config->fs_sjfunc && (fs_perm & FS_PERM_H)) // SJ research Privacy bit
		r |= ((fs_perm & (FS_PERM_H)) ? 0x40 : 0);

	r |= ((fs_perm & (FS_PERM_OWN_R | FS_PERM_OWN_W)) << 2);
	r |= ((fs_perm & (FS_PERM_OTH_R | FS_PERM_OTH_W)) >> 4);

	if (is_dir && s->config->fs_mask_dir_wrr && ((fs_perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)) // (OTH_W) added here because we want to provide full real perms if OTH_W is set
		r &= 0xF2;  // Acorn OWN_W, OWN_R, OTH_R bits (inverse of) 

	return r;
}

uint8_t fsd_SYS_perm_to_pifs(struct __fs_station *s, uint8_t acorn_perm)
{
	uint8_t r;

	r = 0;

	// We don't try and do the Acorn WR/R mask for directories here because we don't know if it's a directory. It's done in the normalize routine instead

	if (s->config->fs_sjfunc) r |= (acorn_perm & 0x40) ? FS_PERM_H : 0; // Hidden / Private. This is MDFS only really
	r |= (acorn_perm & 0x10) ? FS_PERM_L : 0; // Locked
	r |= (acorn_perm & 0x08) ? FS_PERM_OWN_W : 0; // Owner write
	r |= (acorn_perm & 0x04) ? FS_PERM_OWN_R : 0; // Owner read
	r |= (acorn_perm & 0x02) ? FS_PERM_OTH_W : 0; // Other write
	r |= (acorn_perm & 0x01) ? FS_PERM_OTH_R : 0; // Other read

	return r;

}

/* Registration function.
 *
 * Returns malloc'd struct with our data in it 
 * or NULL on failure. If already registered, it just returns
 * the same struct and logs an error.
 *
 */

fs_device * fsd_SYS_register (void)
{
	if (!fsd_SYS_registration_struct) /* Do nothing if already registered */
	{
		fsd_SYS_registration_struct = fsd_malloc("fs_device struct", sizeof(fs_device));

		if (!fsd_SYS_registration_struct)
			fsd_debug (1, "Unable to malloc() for registration struct");
		else
		{
			/* Fill in our struct */
			fsd_SYS_registration_struct->device_name = "SYS";
			fsd_SYS_registration_struct->device_description = "System filesystem driver";
			fsd_SYS_registration_struct->device_funcs = &fsd_SYS_funcs;
			fsd_debug (3, "Registered SYS fileserver device driver");
		}
	}
	else
		fsd_debug (1, "Attempt to register driver a second time");

	return fsd_SYS_registration_struct;
}

/* Driver initialization on a given FS
 *
 * Gets passed the JSON object comprising its driver config key from within the "drivers" array under
 * "fileserver" on the relevant station.
 *
 * Returns an instance struct, or NULL for failure.
 */

fs_device_instance * fsd_SYS_init (struct __fs_station *f, struct json_object *j)
{
	struct fsd_SYS_instance 	*ret;
	char				autoinf[1024];

	//struct __fs_station *f = (struct __fs_station *) fs;
	// DIR *dir;
	// struct dirent *entry;
	// uint16_t	discs_found = 0;

	/* We actually don't care about the JSON - we crib
	 * our directory straight out of the parent FS...
	 */

	FS_LIST_MAKENEW(struct fsd_SYS_instance, fsd_SYS_instance_list, 1, ret, "FS", FSDEVICE "New instance struct");

	if (!ret)
	{
		fsd_debug(1, "Initialization failed - Unable to allocate struct");
		return NULL;
	}

	strncpy (ret->directory, f->directory, 127);
	ret->fs_parent = f;
	
	snprintf (autoinf, 1023, "%s/auto_inf", ret->directory);

	if (!access(autoinf, F_OK))
		ret->use_inf = 1;

	ret->device = fsd_SYS_registration_struct;

	return (fs_device_instance *) ret;

}

/* 
 * Remove device instance on a given fileserver
 *
 * Basically take it out of our list of instances.
 *
 * It is the caller's responsibility to ensure 
 * nothing is using the device!
 *
 * Returns 0 for success, 1 for failure.
 *
 */

int fsd_SYS_release (fs_device_instance *fs)
{
	struct fsd_SYS_disc *d, *n;
	struct fsd_SYS_instance *i = (struct fsd_SYS_instance *) fs;

	if (i->mounts) /* Busy */
		return FSD_BUSY;

	/* Free our discs */

	d = i->discs;

	while (d)
	{
		n = d->next;
		fsd_free("Freeing disc struct", d);
		d = n;
	}

	FS_LIST_SPLICEFREE(fsd_SYS_instance_list, i, "FSDEVICE", FSDEVICE ": Freeing instance");

	return FSD_SUCCESS;

}

/* Release driver from whole bridge. Clean everything up. 
 *
 * Returns 0 for success, 1 for failure
 */

int fsd_SYS_unregister (void)
{
	if (fsd_SYS_instance_list) /* Busy! */
		return FSD_BUSY;

	fsd_free ("Freeing registration struct", fsd_SYS_registration_struct);

	fsd_SYS_registration_struct = NULL; /* Just in case we re-register */

	return 0;
}

/* CLI */

int fsd_SYS_cli (fs_device_instance *i, char *cmd)
{
	return FSD_CLI_UNKNOWN; /* We don't presently implemnent anything */
}

/*
 * Mount an existing disc and return a mount struct for it,
 * or NULL for failure.
 */

fs_device_mount * fsd_SYS_mount (fs_device_instance *i, char *params, uint32_t flags, uint8_t fs_disc, int *err)
{

	struct fsd_SYS_instance * instance = (struct fsd_SYS_instance *) i;
	struct fsd_SYS_mount *m;
	struct fsd_SYS_disc *d = NULL; /* Disc we are mounting */
	uint8_t	ro = !!(flags & FSD_MOUNTFLAG_READONLY);
	struct fsd_param p[20];
	uint8_t	param_count = 0;
	char discname[17];
	char rostring[3];

	if (!i)
	{
		*err = FSD_BADPARAMS;
		return NULL;
	}

	param_count = fsd_parse_params(params, p, 0);
	
	/* Required parameters are (i) existing registered disc name, (ii) [optional] "RO" for read only */

	if (param_count > 2 || param_count < 1)
	{
		fsd_debug (1, "Bad parameters");
		*err = FSD_BADPARAMS;
		return NULL;
	}

	fsd_param_extract(params, p, 0, discname, 16, 0);
	fs_toupper(discname);

	if (param_count == 2)
	{
		fsd_param_extract(params, p, 2, rostring, 2, 0);
		if (!strcasecmp(rostring, "RO"))
			ro = 1;
		else
		{
			fsd_debug (1, "Second parameter can only be 'RO'");
			*err = FSD_BADPARAMS;
			return NULL;
		}
	}

	d = instance->discs;

	while (d)
	{
		if (!strcmp(discname, d->name))
			break;

		d = d->next;
	}

	/* Did we find the disc? */

	if (!d)
	{
		*err = FSD_MOUNTERR_UNKNOWN_DISC;
		return NULL;
	}

	/* See if the disc is writable if we want to write */

	if (d->readonly)
		ro = 1; /* Force readonly if disc is readonly */
	
	/* Make sure it's mountable */

	if (d->writers) /* Can't mount if something else has it read/write - we allow a single writer to a disc if there are already readers*/
	{
		fsd_debug (1, "Cannot mount - already mounted read/write elsewhere");
		*err = FSD_MOUNTERR_ALREADY_MOUNTED;
		return NULL;
	}
			   
	/* Ok, mount it */

	/* Update counts */

	if (!ro)
		d->writers++;
	else	d->readers++;

	FS_LIST_MAKENEW(struct fsd_SYS_mount, instance->mounts, 1, m, "FS", FSDEVICE " New mount struct");

	/* Initialize it */

	m->device = instance->device;
	m->server = instance->fs_parent;
	m->instance = instance;
	m->disc = d;
	m->readonly = ro;
	m->readers = 0; /* Readers & writers on the mount */
	m->writers = 0;
	m->flags = flags; /* So we know what kind of mount it was */
	m->submounts = NULL; /* No submounts yet */
	m->fs_disc = fs_disc; /* FS Disc number. Stored here so we can put it in struct path_entry on get_dirents */

	return (fs_device_mount *) m;
}

/*
 * Umount a mount from within an instance
 *
 * Returns 0 for success; otherwise failure
 */

int fsd_SYS_umount (fs_device_mount *m)
{

	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;

	if (!mount)
		return FSD_UMOUNTERR_INVALID;

	/* Is anything open on the mount? Or a submount? If so, refuse */

	if (mount->readers != 0 || mount->writers != 0 || mount->submounts) /* Busy */
		return FSD_BUSY;

	/* Decrement the count on the underlying disc */

	if (mount->readonly)
		mount->disc->readers--;
	else	mount->disc->writers--;
	
	/* So should be safe to unmount */

	FS_LIST_SPLICEFREE(mount->instance->mounts, mount, "FS", FSDEVICE " freeing mount struct");

	return 0;

}

/* Register a disc name 
 * Returns an fsd_error
 */

int fsd_SYS_register_disc(fs_device_instance *i, char *disc, char *params, uint32_t flags)
{
	struct fsd_param p[20];
	char discpath_param[128];
	char rostring[3];
	uint8_t	ro = 0;
	char discname[17];
	struct fsd_SYS_disc *d;
	struct fsd_SYS_instance *instance;
	int param_count;

	if (!i)
		return FSD_BADPARAMS;

	instance = (struct fsd_SYS_instance *) i;

	param_count = fsd_parse_params(params, p, 0);
	
	/* Required parameters are (i) disc path (and if it doesn't have the '/' prefix, we treat it as within the FS home dir and then (ii) [optional] "RO" for read only */

	if (param_count > 2 || param_count < 1)
	{
		fsd_debug (1, "Bad parameters");
		return FSD_BADPARAMS;
	}

	fsd_param_extract(params, p, 0, discpath_param, 127, 0);

	if (param_count == 2)
	{
		fsd_param_extract(params, p, 1, rostring, 2, 0);
		if (!strncasecmp(rostring, "RO", 2))
			ro = 1;
	}

	strncpy(discname, disc, 16);
	discname[16] = '\0'; /* Terminate just in case */

	fs_toupper(discname);

	/* Search our extant discs to see if we already have this one */

	d = instance->discs;

	while (d)
	{
		if (!strcmp(discpath_param, d->path))
			break;

		d = d->next;
	}

	if (d && !(flags & FSD_DISCFLAG_CANEXIST)) /* Barf if we have found a disc and it cannot already exist */
	{
		return FSD_EXISTS;
	}

	if (!d) /* Not a known disc - create one */
	{
		struct statvfs	  sv;

		if (fsd_SYS_max_discno == 255) /* Run out of discs! */
		{
			fsd_debug_fmt (1, "Attempt to mount %s failed - out of disc numbers!", discpath_param);
			return FSD_EXHAUSTED;
		}

		FS_LIST_MAKENEW(struct fsd_SYS_disc, instance->discs, 1, d, "FS", FSDEVICE " New disc struct");
		d->instance = instance;
		strncpy(d->name, discname, 16);
		strncpy(d->path, discpath_param, 127);
		d->readers = d->writers = 0;
		d->index = fsd_SYS_max_discno++;
		d->readonly = ro;

		/* Get blocksize */

		if (statvfs(d->path, &sv) == 0)
			d->blocksize = sv.f_bsize;
		else
		{
			fsd_debug_fmt (1, "Unable to statvfs() for disc %s (%s) - %s", d->name, d->path, strerror(errno));
			return FSD_MOUNTERR_UNKNOWN_DISC;
		}
	}

	/* By here, d contains a pointer to one of our discs */

	/* But just in case */

	if (!d)
		return FSD_NODISC;

	return 0; /* Success */
}

int fsd_SYS_unregister_disc (fs_device_instance *i, char *name)
{

	char discname[17];
	struct fsd_SYS_disc *d;
	struct fsd_SYS_instance *instance;

	if (!i)
		return FSD_BADPARAMS;

	instance = (struct fsd_SYS_instance *) i;

	d = instance->discs; 

	strncpy (discname, name, 16);
	discname[16] = '\0';

	/* Find the disc */

	while (d)
	{
		if (!strncasecmp(discname, d->name, 16))
			break;
		d = d->next;
	}

	if (!d)
		return FSD_NODISC;

	if (d->writers != 0 || d->readers != 0)
		return FSD_BUSY;

	/* Disc is not busy - splice it out */

	FS_LIST_SPLICEFREE(instance->discs, d, "FSDEVICE", "Free up a disc");

	return FSD_SUCCESS;
}

/* Return pointer to disc name of mounted disc
 * or NULL if not mounted
 */

char * fsd_SYS_getdiscname (fs_device_mount *m)
{
	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;

	return (char *) mount->disc->name;
}

/* Open a file on a mount.
 *
 * The path is from the root of the disc that is mounted,
 * not from the root of the FS disc.
 *
 * Returns 0 for success, and anything else for failure. Puts any
 * errno value in the last parameter. Returns a pointer to a FILE in the handle,
 * since we are just using stdio here.
 *
 * flags are the same as for open().
 *
 */

int fsd_SYS_open (fs_device_mount *m, const char *path, int flags, fs_device_handle **r_handle, int *fs_errno)
{
	FILE *	opened_fh;
	char	syspath[1024];
	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;
	struct fsd_SYS_handle *handle = NULL;

	if (!mount)
		return FSD_BADMOUNT;

	fsd_SYS_path_acorn_to_unix((char *) path);

	snprintf (syspath, 1023, "%s/%s", 
			mount->disc->path, /* Full underlying filesystem path to this disc */
			path); /* Pathname we want */

	if (flags == 1) /* Just read */
		opened_fh = fopen(syspath, "r");
	else if (flags == 2) /* Update */
		opened_fh = fopen(syspath, "r+");
	else	opened_fh = fopen(syspath, "w+"); /* Overwrite */

	/* Copy errno & handle */

	*fs_errno = errno;

	*r_handle = NULL;

	handle = fsd_malloc("New handle struct", sizeof(struct fsd_SYS_handle));

	/* Signal correct return state */

	if (handle)
	{
		handle->handle = opened_fh;
		handle->flags = flags;
		handle->device = (fs_device *) mount->instance;
		handle->mount = mount;

		if (flags & 0x02) mount->writers++;
		else mount->readers++;

		*r_handle = handle;
		return 0;
	}
	else	return 1;

}

/* Close a handle.
 *
 * Returns 0 for success, else failure.
 * Puts errno value in fs_errno.
 */

int fsd_SYS_close (fs_device_handle *h, int *fs_errno)
{

	struct fsd_SYS_handle *handle = (struct fsd_SYS_handle *) h;

	/* We don't ask any questions here, we just
	 * trust we're being given a FILE* to close and
	 * we'll close it.
	 */

	int ret;

	if (!handle)
		return FSD_BADHANDLE;

	ret = fclose(handle->handle);

	if (!ret)
	{
		if (handle->flags & 0x02)
			handle->mount->writers--;
		else	handle->mount->readers--;
	}

	fsd_free ("Free handle struct", handle);

	*fs_errno = errno;

	return ret;

}

/* Read from a file
 *
 * Does just what fread() does
 *
 */

int fsd_SYS_read (fs_device_handle *h, void *buf, size_t len, int *fs_errno)
{
	int ret;
	struct fsd_SYS_handle *handle = (struct fsd_SYS_handle *) h;

	if (!handle)
		return FSD_BADHANDLE;

	ret = fread(buf, 1, len, handle->handle);

	*fs_errno = errno;

	return ret;
}

/*
 * Write to a file
 *
 * Does just what fwrite() does
 */

int fsd_SYS_write (fs_device_handle *h, const void *buf, size_t len, int *fs_errno)
{
	int ret;
	struct fsd_SYS_handle *handle = (struct fsd_SYS_handle *) h;

	if (!handle)
		return FSD_BADHANDLE;

	ret = fwrite(buf, len, 1, handle->handle);

	*fs_errno = errno;

	return ret;
}

/* Move file pointer in filesystem
 *
 * Does just what fseek() does
 */

int fsd_SYS_seek (fs_device_handle *h, off_t offset, int whence, int *fs_errno)
{
	int ret;
	struct fsd_SYS_handle *handle = (struct fsd_SYS_handle *) h;

	if (!handle)
		return FSD_BADHANDLE;

	ret = fseek(handle->handle, offset, whence);

	*fs_errno = errno;

	return ret;
}

/* Report current pointer
 *
 * Does what ftell() does
 */

off_t fsd_SYS_tell (fs_device_handle *h, int *fs_errno)
{

	int ret;
	struct fsd_SYS_handle *handle = (struct fsd_SYS_handle *) h;

	if (!handle)
		return FSD_BADHANDLE;

	ret = ftell(handle->handle);

	*fs_errno = errno;

	return ret;
}

/* Pars either an xattr econet_birth, or the equivalent in a dotfile and store it in objattr */

void fsd_SYS_parse_birth (char *attr, struct objattr *r)
{
	char	tmp[11];
	unsigned char   day_s[3], myear_s[3], hour_s[3], min_s[3], sec_s[3];

	strncpy(tmp, attr, 10);

	memcpy(day_s, tmp, 2);
	memcpy(myear_s, &(tmp[2]), 2);
	memcpy(hour_s, &(tmp[4]), 2);
	memcpy(min_s, &(tmp[6]), 2);
	memcpy(sec_s, &(tmp[8]), 2);
	day_s[2] = myear_s[2] = hour_s[2] = min_s[2] = sec_s[2] = 0;
	r->c_day = strtoul(day_s, 0, 16);
	r->c_monthyear = strtoul(myear_s, 0, 16);
	r->c_hour = strtoul(hour_s, 0, 10);
	r->c_min = strtoul(min_s, 0, 10);
	r->c_sec = strtoul(sec_s, 0, 10);
}

/* Read inf file - returns 1 for failure; 0 for success */

/* Inf file formats:
 *
 * owner load exec perm
 * or
 * owner load exec perm homeof
 * or
 * owner load exec perm homeof birth
 *
 * birth format is as per the xattr: ddmyhhmmss where
 * 	dd is day in hex
 * 	my is monthyear in hex
 * 	hh, mm, ss
 */

int fsd_SYS_read_inf (struct __fs_station *s, char *syspath, struct objattr *r, uint8_t is_dir)
{
	char	infpath[1024];

	snprintf (infpath, 1023, "%s:inf", syspath);

	if (!access(infpath, R_OK))
	{
		FILE *dotfile;
		unsigned short owner, perm, homeof;
		unsigned long load, exec;
		int sixparams;
		char birth[11];

		dotfile = fopen(infpath, "r");

		homeof = 0;

		if ((sixparams = fscanf(dotfile, "%hx %lx %lx %hx %hx %10s", &owner, &load, &exec, &perm, &homeof, birth)) != 6)
			if (fscanf(dotfile, "%hx %lx %lx %hx %hx", &owner, &load, &exec, &perm, &homeof) != 5)
				fscanf(dotfile, "%hx %lx %lx %hx", &owner, &load, &exec, &perm);

		r->owner = owner;
		r->load = load;
		r->exec = exec;
		r->perm = perm;
		r->homeof = homeof;
		r->acorn_perm = fsd_SYS_perm_to_acorn(s, r->perm, is_dir);

		if (sixparams != 6) /* birthdate not present */
			r->c_day = r->c_monthyear = r->c_hour = r->c_min = r->c_sec = 0;
		else
			fsd_SYS_parse_birth(birth, r);

		fclose(dotfile);
	}
	else
		return 1;
			
	return 0;
}


/* Get acorn attributes 
 * 
 * Puts result in *attr
 *
 * Returns 0 for success; otherwise 1.
 */

int fsd_SYS_getattr (fs_device_mount *m, const char *path, struct objattr *r)
{
	char	syspath[1024];
	//struct objattr *r = (struct objattr *) a;
	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;

	if (!mount)
		return FSD_BADMOUNT;

	fsd_SYS_path_acorn_to_unix((char *) path);

	snprintf (syspath, 1023, "%s/%s", 
			mount->disc->path, /* Full underlying filesystem path to this disc */
			path); /* Pathname we want */

	return fsd_SYS_getattr_unix (mount, syspath, r);
}

/* getattr operating on unix filesystem */

int fsd_SYS_getattr_unix (struct fsd_SYS_mount *mount, char *syspath, struct objattr *r)
{
	uint8_t	is_dir = 0;
	unsigned char   attrbuf[20];
	struct stat statbuf;
	struct __fs_station *f = mount->disc->instance->fs_parent;

	// Default values
	r->owner=0; // syst
	r->load=0;
	r->exec=0;

	/* Set up default perms */

	if ((is_dir = fs_isdir(syspath)))
		r->perm = FS_CONF_DEFAULT_DIR_PERM(f);
	else    r->perm = FS_CONF_DEFAULT_FILE_PERM(f);

	if (mount->instance->use_inf)
		return fsd_SYS_read_inf(f, syspath, r, is_dir);

	r->acorn_perm = fsd_SYS_perm_to_acorn(f, r->perm, is_dir);

	r->homeof=0;

	if (getxattr((const char *) syspath, "user.econet_owner", attrbuf, 4) >= 0) // Attribute found
	{
		attrbuf[4] = '\0';
		r->owner = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) syspath, "user.econet_load", attrbuf, 8) >= 0) // Attribute found
	{
		attrbuf[8] = '\0';
		r->load = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) syspath, "user.econet_exec", attrbuf, 8) >= 0) // Attribute found
	{
		attrbuf[8] = '\0';
		r->exec = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) syspath, "user.econet_perm", attrbuf, 2) >= 0) // Attribute found
	{
		attrbuf[2] = '\0';
		r->perm = strtoul((const char * ) attrbuf, NULL, 16);
	}

	r->acorn_perm = fsd_SYS_perm_to_acorn(mount->instance->fs_parent, r->perm, is_dir);

	if (getxattr((const char *) syspath, "user.econet_homeof", attrbuf, 4) >= 0) // Attribute found
	{
		attrbuf[4] = '\0';
		r->homeof = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) syspath, "user.econet_birth", attrbuf, 10) >= 0)
		fsd_SYS_parse_birth(attrbuf, r);

	r->sysid = 0;

	if (!stat(syspath, &statbuf))
	{
		struct tm	ct;

		r->length = statbuf.st_size;
		r->sysid = statbuf.st_ino;

		if (S_ISREG(statbuf.st_mode))
			r->ftype = FS_FTYPE_FILE;
		else if (S_ISDIR(statbuf.st_mode))
			r->ftype = FS_FTYPE_DIR;
		else r->ftype = FS_FTYPE_SPECIAL;

		if (!(S_ISREG(statbuf.st_mode)))
			r->load = r->exec = 0;

		/* Modification time */

		localtime_r(&(statbuf.st_mtime), &ct);
		fs_date_to_two_bytes (ct.tm_mday, ct.tm_mon+1, ct.tm_year, &(r->monthyear), &(r->day));
		r->hour = ct.tm_hour;
		r->min = ct.tm_min;
		r->sec = ct.tm_sec;

		/* Create time is done above */
	}

	return 0;

}

/*
 * fsd_SYS_write_inf - write out a :inf file
 */

int fsd_SYS_write_inf (struct __fs_station *s, char *syspath, struct objattr *r, uint8_t is_dir)
{

	char	infpath[1024];
	FILE *	dotfile;

	snprintf (infpath, 1023, "%s:inf", syspath);

	dotfile = fopen(infpath, "w");

	if (dotfile)
	{
		fprintf (dotfile, "%04X %08lX %08lX %02X %04X %02X%02X%02X%02X%02X",
				r->owner,
				r->load,
				r->exec,
				r->perm,
				r->homeof,
				r->c_day,
				r->c_monthyear,
				r->c_hour,
				r->c_min,
				r->c_sec);

		fclose(dotfile);
	}
	else return 1;

	return 0;

}

/* 
 * Set attributs to those in 'a'
 *
 * If any of bits 8-15 of a->perm are set, it will preserve the existing permissions, applying 
 * the defaults if no present perms are available.
 */

int fsd_SYS_setattr (fs_device_mount *m, const char *path, struct objattr *attr)
{

	//struct objattr * attr = (struct objattr *) a;
	char	syspath[1024];
	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;

	if (!mount)
		return FSD_BADMOUNT;

	fsd_SYS_path_acorn_to_unix((char *) path);

	snprintf (syspath, 1023, "%200s/%800s", 
			mount->disc->path, /* Full underlying filesystem path to this disc */
			path); /* Pathname we want */

	return fsd_SYS_setattr_unix (mount, (char *) path, attr);
}

/* setattr operating on the Unix underlying FS */
int fsd_SYS_setattr_unix (struct fsd_SYS_mount *mount, char *syspath, struct objattr *attr)
{

	uint8_t		is_dir = 0;
	unsigned char   attrbuf[20];
	unsigned short 	perm;
	uint8_t		acorn_perm;
	char 		old_owner[10];
	struct __fs_station 	*f = mount->disc->instance->fs_parent;

	is_dir = fs_isdir(syspath);

	perm = attr->perm; 
	acorn_perm = attr->acorn_perm;

	if (perm & 0xff00)
	{
		/* Preserve permission */

		struct objattr existing;

		if (!fsd_SYS_getattr(mount, syspath, &existing))
		{
			perm = existing.perm;
			acorn_perm = existing.acorn_perm;
		}
		else	
		{
			perm = (is_dir ? (FS_CONF_DEFAULT_DIR_PERM(f)) : (FS_CONF_DEFAULT_FILE_PERM(f)));
			acorn_perm = fsd_SYS_perm_to_acorn(f, perm, is_dir);
		}

	}

	perm &= 0xFF;
	acorn_perm &= 0xFF;

	if (((perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == 0) && is_dir)
	{
		perm |= FS_CONF_DEFAULT_DIR_PERM(f); // imply default if dir perm given as 'no perms'
		acorn_perm = fsd_SYS_perm_to_acorn(f, perm, is_dir);
		// No equivalent for files, because can justifiably set to, e.g. "/"
	}

	if (mount->instance->use_inf)
		return fsd_SYS_write_inf(f, syspath, attr, is_dir);

	sprintf ((char * ) attrbuf, "%02X", (perm & 0xff));

	if (setxattr((const char *) syspath, "user.econet_perm", (const void *) attrbuf, 2, 0)) // Flags = 0 means create if not exist, replace if does
		fs_debug (0, 1, "Failed to set permission on %s\n", syspath);

	// See if owner is being changed
	
	sprintf((char * ) attrbuf, "%04X", attr->owner);

	if (getxattr((const char *) syspath, "user.econet_owner", old_owner, 4) >= 0) // Attribute found
	{
		old_owner[4] = 0;
		if (strcasecmp(old_owner, attrbuf))
			fs_debug (0, 1, "Owner being changed from %s to %s on file %s", old_owner, attrbuf, syspath);
	}

	if (setxattr((const char *) syspath, "user.econet_owner", (const void *) attrbuf, 4, 0))
		fs_debug (0, 1, "Failed to set owner on %s", syspath);

	sprintf((char * ) attrbuf, "%08lX", attr->load);

	if (setxattr((const char *) syspath, "user.econet_load", (const void *) attrbuf, 8, 0))
		fs_debug (0, 1, "Failed to set load address on %s", syspath);

	sprintf((char * ) attrbuf, "%08lX", attr->exec);

	if (setxattr((const char *) syspath, "user.econet_exec", (const void *) attrbuf, 8, 0))
		fs_debug (0, 1, "Failed to set exec address on %s: %s", syspath, strerror(errno));

	sprintf((char *) attrbuf, "%04X", attr->homeof);

	if (setxattr((const char *) syspath, "user.econet_homeof", (const void *) attrbuf, 4, 0))
		fs_debug (0, 1, "Failed to set home directory flag on %s: %s", syspath, strerror(errno));

	sprintf((char *) attrbuf, "%02X%02X%02X%02X%02X", attr->c_day, attr->c_monthyear, attr->c_hour, attr->c_min, attr->c_sec);

	if (setxattr((const char *) syspath, "user.econet_birth", (const void *) attrbuf, 10, 0))
		fs_debug (0, 1, "Failed to birth date on %s", syspath, strerror(errno));

	/* NB we don't try to set the system ID... */

	return 0;

}

/* Truncate / extend file */

int fsd_SYS_truncate (fs_device_handle *h, size_t sz, int *fs_errno)
{

	struct fsd_SYS_handle *handle = (struct fsd_SYS_handle *) h;
	int ret;

	ret = ftruncate(fileno(handle->handle), sz);

	*fs_errno = errno;

	return ret;

}

/* Create directory */

int fsd_SYS_cdir (fs_device_mount *m, const char *path, int *fs_errno)
{

	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;
	char syspath[1024];
	//struct objattr oa;

	if (!mount)
		return FSD_BADMOUNT;

	fsd_SYS_path_acorn_to_unix((char *) path);

	snprintf (syspath, 1023, "%s/%s", 
			mount->disc->path, /* Full underlying filesystem path to this disc */
			path); /* Pathname we want */

	if (!access(syspath, R_OK)) /* Exists */
	{
		*fs_errno = EEXIST;
		return FSD_SYSERR;
	}

	if (mkdir(syspath, 0770))
	{
		*fs_errno = errno;
		return FSD_SYSERR;
	}

	/* Set create time only - the fsop function does the setting of other attributes */

#if 0 /* Do this in fsop_1b */
	/* And we should probably move this into fsop_1b too */

	fsop_set_create_time_now(syspath);
#endif

	return 0; /* Success */
}

/* Unlink file (and its :inf if there is one) */

int fsd_SYS_unlink (fs_device_mount *m, const char *path, int *fs_errno)
{

	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;
	int ret;
	char syspath[1024];

	if (!mount)
		return FSD_BADMOUNT;

	fsd_SYS_path_acorn_to_unix((char *) path);

	snprintf (syspath, 1023, "%s/%s", 
			mount->disc->path, /* Full underlying filesystem path to this disc */
			path); /* Pathname we want */

	if (fs_isdir(syspath))
		ret = rmdir((const char *) syspath);
	else	ret = unlink((const char *) syspath);

	*fs_errno = errno;

	return ret;
}

/* Get disc names, return number malloc()d.
 * Note, FS library routine fsd_free_disc_ents will free up the list, 
 * and it'll be the same for everyone.
 */

int fsd_SYS_getdiscs (fs_device_instance *i, fs_device_disc **list)
{
	struct fsd_SYS_instance *instance = (struct fsd_SYS_instance *) i;
	fs_device_disc	*entry;
	struct fsd_SYS_disc	*d;
	uint16_t	count = 0;

	d = instance->discs;

	while (d)
	{
		entry = fsd_malloc("New FSD Disc list structure", sizeof(fs_device_disc));

		strncpy (entry->name, d->name, 16);
		entry->index = d->index;
		entry->next = *list;
		*list = entry;
		count++;
		d = d->next;
	}

	return count;

}

/* 
 * Return block size. We have worked out what this is when
 * we scanned the disc.
 */

int16_t fsd_SYS_getdiscblocksize (fs_device_mount *m)
{
	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;

	if (!mount)
		return FSD_BADMOUNT;

	return mount->disc->blocksize;

}

/* Get directory entries - must return them in acorn format! */

/* NB matching which filenames we want from a regexp is done by the main
 * FSD harness for all drviers
 */

int fsd_SYS_get_dir_ents (fs_device_mount *m, char *dirpath, fs_device_dir_entry **result, uint8_t *max_fname_length, int *fs_errno)
{
	struct fsd_SYS_mount *mount = (struct fsd_SYS_mount *) m;
	struct __fs_station	*server;
	uint16_t	entries, results;
	struct dirent	**namelist;
	char 		syspath[1024];
	char		acorndir[1024];
	char		acornentry[1200];
	uint16_t	counter;
	struct objattr	oa_parent;

	*result = NULL; /* Initialize */

	if (!mount)
		return FSD_BADMOUNT;

	server = mount->disc->instance->fs_parent;

	strcpy (acorndir, dirpath);

	fsd_SYS_path_acorn_to_unix((char *) dirpath);

	snprintf (syspath, 1023, "%s/%s", 
			mount->disc->path, /* Full underlying filesystem path to this disc */
			dirpath); /* Pathname we want */

	if (!fs_isdir(syspath)) /* We can only search directories */
		return FSD_NOTDIRECTORY;

	results = scandir(syspath, &namelist, NULL, fs_alphacasesort);

	if (results == -1) /* Error */
	{
		*fs_errno = errno;
		return FSD_SCANDIR_FAILURE;
	}

	fsd_SYS_getattr_unix(mount, syspath, &oa_parent);

	entries = counter = 0;

	while (counter < results)
	{
		fs_device_dir_entry	*new_p;

		if (	(strlen(namelist[counter]->d_name) <= server->config->fs_fnamelen)
		&&	(*(namelist[counter]->d_name) != '.') /* Ignore dotfiles */
		)
		{
			uint8_t		fname_length;
			char 		unixpath[2048];
			struct fsd_SYS_submount	*submount = mount->submounts;

			FS_LIST_MAKENEW(fs_device_dir_entry, *result, 0, new_p, "FS", "New " FSDEVICE " dir entry struct"); /* 0 = put on tail, maintaining alphabetical order - TODO: Change the sort function on scandir to sort into reverse order and then just put them on the head of this list */

			strncpy (new_p->name, namelist[counter]->d_name, server->config->fs_fnamelen);
			fs_unix_to_acorn(new_p->name);

			/* See if max filename length in this dir has increase */

			if ((fname_length = strlen(new_p->name)) > *max_fname_length)
				*max_fname_length = fname_length;

			snprintf (unixpath, 2047, "%s/%s", syspath, namelist[counter]->d_name);

			/* Get attributes, or dump it if we can't */

			if (fsd_SYS_getattr_unix (mount, unixpath, &(new_p->attr)))
			{
				fsd_debug_fmt (2, "Unable to stat %s", unixpath);
				FS_LIST_SPLICEFREE(*result, new_p, "FS", "Free path_entry when could not stat");
				counter++;
				continue;
			}

			/* Now see if it's a submount point */

			snprintf (acornentry, 1199, "%s.%s", acorndir, new_p->name);

			while (submount)
			{
				if (!strcasecmp(acornentry, submount->where)) /* Found a sub-mount */
				{
					new_p->mount = (fs_device_mount *) submount->mount;
					break;
				}
				else
					submount = submount->next;
			}

			entries++;
		}

		counter++;

	}

	/* Free the scandir list */

	if (results > 0) fs_free_scandir_list(&namelist, results);

	/* Free the regexp */

	regfree (&(server->r_wildcard));

	*fs_errno = errno;

	return entries;

}

/* Our struct of functions */

static struct fs_device_funcs fsd_SYS_funcs = {
	.dev_report_schema = NULL, /* For now  - we don't actually have any parameters */
	.fs_init = fsd_SYS_init,
	.dev_unregister = fsd_SYS_unregister,
	.fs_release = fsd_SYS_release,
	.cli = fsd_SYS_cli,
	.mount = fsd_SYS_mount,
	.umount = fsd_SYS_umount,
	.register_disc = fsd_SYS_register_disc,
	.unregister_disc = fsd_SYS_unregister_disc,
	.get_discname = fsd_SYS_getdiscname,
	.get_discs = fsd_SYS_getdiscs,
	.get_disc_blocksize = fsd_SYS_getdiscblocksize,
	.open = fsd_SYS_open,
	.close = fsd_SYS_close,
	.read = fsd_SYS_read,
	.write = fsd_SYS_write,
	.seek = fsd_SYS_seek,
	.tell = fsd_SYS_tell,
	.getattr = fsd_SYS_getattr,
	.setattr = fsd_SYS_setattr,
	.get_dir_ents = fsd_SYS_get_dir_ents,
	.truncate = fsd_SYS_truncate,
	.cdir = fsd_SYS_cdir,
	.unlink = fsd_SYS_unlink

};

FSDEVICE_REGISTER(fsd_SYS_register,"*nix filesystem driver");

