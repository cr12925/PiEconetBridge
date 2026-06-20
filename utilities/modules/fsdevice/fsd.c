
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

#include "econet-hpbridge.h"
#include "fs.h"

#define FSDEVICE "FSDEVICE" /* For free/malloc/debug */

/* This provides the harness for calling the relevant FS device function
 * and getting its results back to the caller. It also provides parsing
 * routines for parameters
 */

uint16_t fsd_parse_params (char *s, struct fsd_param *p, uint16_t start)
{
	char 	*str = s + start;
	uint16_t	len;
	uint16_t	count = 0, index = 0;

	len = strlen(str);

	while (count < len && index < 20)
	{
		while (count < len)
		{
			if (*(str+count) == ' ') count++;
			else break;
		}

		if (count < len)
		{
			p->fsdp_start = count + start;

			/* Find end */

			while (count < len && (*(str+count) != ' ')) count++;

			p->fsdp_end = count - 1 + start;

			p++;
			index++; /* Number of valid entries in p */
		}
		else /* At end */
		{
			return index;
		}

		count++;
	}

	return index;

}

/* Extract a parameter into a string pointer */

void fsd_param_extract (char *s, struct fsd_param *p, uint8_t index, char *output, uint8_t maxlen, uint16_t param_start)
{
        uint8_t         count = 0;
        uint8_t         real_length;
        char *          start = s; // s+5;

        p += index;

        real_length = (p->fsdp_end - p->fsdp_start) + 1;

        while (count < maxlen && count < real_length)
        {
                *(output + count) = *(start + count + p->fsdp_start);
                count++;
        }

        *(output + count) = '\0';

        return;

}

/* Free a list of disc entries */

void fsd_free_disc_ents (fs_device_disc *d)
{
	fs_device_disc	*n;

	while (d)
	{
		n = d->next;

		fsd_free("Free disc name struct", d);

		d = n;
	}

	return;
}

/* Find driver struct on this server */

fs_device_local * fsd_find_local (struct __fs_station *f, char *driver_name)
{
	fs_device_local 	*r; /* Result */

	r = f->devices;

	if (!r)
		fs_debug_full (0, 0, f, 0, 0, "No devices configured!");

	while (r)
	{
		if (!strcasecmp(driver_name, r->device->device_name))
			break;

		r = r->next;
	}

	return r;
}

/*
 * Find device struct for driver on this server
 */

fs_device * fsd_find_driver (struct __fs_station *f, char *driver_name)
{
	fs_device_local 	*r;

	if ((r = fsd_find_local(f, driver_name)))
		return r->device;

	return NULL; /* Not found */
}

/* Find instance on a server */

fs_device_instance * fsd_find_instance (struct __fs_station *f, char *driver_name)
{
	fs_device_local		*l; /* Device local struct */

	if ((l = fsd_find_local(f, driver_name)))
		return l->instance;

	return NULL; /* Not found */

}

/* dev_report_schema wrapper */

struct json_object * fsd_dev_report_schema (fs_device *device)
{
	if (device && device->device_funcs->dev_report_schema)
		return (device->device_funcs->dev_report_schema) ();
	else	return NULL;
}

/* init a driver on a particular fileserver */

fs_device_instance * fsd_init (fs_device *device, struct __fs_station *fs, struct json_object *j)
{
	if (device && device->device_funcs->fs_init)
		return (device->device_funcs->fs_init) (fs, j);
	else	return NULL;
}

/* unregister from bridge as a whole */

int fsd_unregister (fs_device *device)
{
	if (device && device->device_funcs->dev_unregister)
		return (device->device_funcs->dev_unregister) ();
	else	return FSD_MISSINGFUNC;
}

/* Release (opposite of init) from given fileserver */

int fsd_release (fs_device *device, fs_device_instance *instance)
{
	if (device && device->device_funcs->fs_release)
		return (device->device_funcs->fs_release) (instance);
	else	return FSD_MISSINGFUNC;
}

/* mount on an instance */

fs_device_mount * fsd_mount (fs_device *device, struct __fs_station *fs, fs_device_instance *instance, char *params, uint32_t flags, uint8_t fs_disc, int *fs_error)
{
	if (device && device->device_funcs->mount)
		return (device->device_funcs->mount) (fs, instance, params, flags, fs_disc, fs_error);
	else
	{
		*fs_error = FSD_MISSINGFUNC;
		return NULL;
	}
}

/* umount */

int fsd_umount (fs_device *device, fs_device_mount *mount)
{
	if (device && device->device_funcs->umount)
		return (device->device_funcs->umount) (mount);
	else
		return FSD_MISSINGFUNC;
}

/* Return list of discs *
 * Populates a linked list of *discs which must be freed after use with fsd_free_disc_ents()
 * Returns number of entries (0 is valid) and negative is an error
 */

int fsd_get_discs (fs_device *device, fs_device_instance *instance, fs_device_disc **discs)
{
	if (device && device->device_funcs->get_discs)
		return (device->device_funcs->get_discs) (instance, discs);
	else	return FSD_MISSINGFUNC;
}

/* get disc name
 * returns pointer to disc name, null terminated
 */

char *fsd_get_discname (fs_device *device, fs_device_mount *mount)
{
	if (device && device->device_funcs->get_discname)
		return (device->device_funcs->get_discname) (mount);
	else	return NULL;
}

/* get disc blocksize */
/* Returns block size in bytes, or -ve for error */

int16_t fsd_get_disc_blocksize (fs_device *device, fs_device_mount *mount)
{
	if (device && device->device_funcs->get_disc_blocksize)
		return (device->device_funcs->get_disc_blocksize) (mount);
	else	return 0;
}

/* Open file named 'path' within mount 'mount' on device 'device';
 * flags = 
 *   1: Read only
 *   2: Write only
 *   3: Update
 *
 * *handle_out will contain pointer to the driver's internal, opaque handle struct,
 * and equivalent of errno will be put in *fs_errno.
 *
 * NB first element of fs_device_mount must be fs_device *, and we cast to dig it out
 */

int fsd_open(fs_device_mount *mount, const char *path, int flags, fs_device_handle **handle_out, int *fs_errno)
{

	fs_device *device; 

	if (!mount) return FSD_BADMOUNT;
	else device = (fs_device *) ((struct __fs_device_mount_stub *) mount)->device;

	if (device && device->device_funcs->open)
		return (device->device_funcs->open) (mount, path, flags, handle_out, fs_errno);
	else	return FSD_MISSINGFUNC;
}

/* Close *handle on *mount within *device. Result = 0 means success, otherwise error.
 * Equivalent of errno in *fs_errno.
 *
 * NB first two elements of an opaque handle must be:
 * void *device;
 * void *mount;
 *
 * so that we can pick them up.
 */

int fsd_close(fs_device_handle *handle, int *fs_errno)
{
	struct __fs_device_handle_stub *hs = (struct __fs_device_handle_stub *) handle;
	fs_device *device = NULL;

	if (hs)
		device = hs->device;

	if (device && device->device_funcs->close)
		return (device->device_funcs->close) (handle, fs_errno);
	else	return FSD_MISSINGFUNC;
}

/* Read from *handle on *device into &buf, length len.
 *
 * Same semantics as read(). errno equivalent put in *fs_errno.
 */

ssize_t fsd_read (fs_device_handle *handle, void *buf, size_t len, int *fs_errno)
{
	struct __fs_device_handle_stub *hs = (struct __fs_device_handle_stub *) handle;
	fs_device *	device = NULL;

	if (hs)
		device = hs->device;

	if (device && device->device_funcs->read)
		return (device->device_funcs->read) (handle, buf, len, fs_errno);
	else	return FSD_MISSINGFUNC;
}

/* Write to *handle on *device with data at *buf, length len, errno equivalent returned in fs_error. Returns data written
 */

ssize_t fsd_write (fs_device_handle *handle, const void *buf, size_t len, int *fs_errno)
{
	struct __fs_device_handle_stub *hs = (struct __fs_device_handle_stub *) handle;
	fs_device *	device = NULL;

	if (hs)
		device = hs->device;

	if (device && device->device_funcs->write)
		return (device->device_funcs->write) (handle, buf, len, fs_errno);
	else	return FSD_MISSINGFUNC;
}

/* Seek on a device handle */

int fsd_seek (fs_device_handle *handle, off_t offset, int whence, int *fs_errno)
{

	struct __fs_device_handle_stub *hs = (struct __fs_device_handle_stub *) handle;
	fs_device *	device = NULL;

	if (hs)
		device = hs->device;

	if (device && device->device_funcs->seek)
		return (device->device_funcs->seek) (handle, offset, whence, fs_errno);
	else	return FSD_MISSINGFUNC;

}

/* find file pointer on a device handle */

off_t fsd_tell (fs_device_handle *handle, int *fs_errno)
{

	struct __fs_device_handle_stub *hs = (struct __fs_device_handle_stub *) handle;
	fs_device *	device = NULL;

	if (hs)
		device = hs->device;

	if (device && device->device_funcs->tell)
		return (device->device_funcs->tell) (handle, fs_errno);
	else	return FSD_MISSINGFUNC;
}

/* Truncate */

int fsd_truncate (fs_device_handle *handle, size_t sz, int *fs_errno)
{
	struct __fs_device_handle_stub *hs = (struct __fs_device_handle_stub *) handle;
	fs_device *	device = NULL;

	if (hs)
		device = hs->device;

	if (device && device->device_funcs->truncate)
		return (device->device_funcs->truncate) (handle, sz, fs_errno);
	else	return FSD_MISSINGFUNC;
}

/* Create dir on a mount */

int fsd_cdir (fs_device_mount *mount, const char *path, int *fs_errno)
{

	fs_device *device; 

	if (!mount) return FSD_BADMOUNT;
	else device = ((struct __fs_device_mount_stub *) mount)->device;

	if (device && device->device_funcs->cdir)
		return (device->device_funcs->cdir) (mount, path, fs_errno);
	else 	return FSD_MISSINGFUNC;
}

/* Unlink a file on a mount */

int fsd_unlink (fs_device_mount *mount, const char *path, int *fs_errno)
{

	fs_device *device; 

	if (!mount) return FSD_BADMOUNT;
	else device = ((struct __fs_device_mount_stub *) mount)->device;

	if (device && device->device_funcs->unlink)
		return (device->device_funcs->unlink) (mount, path, fs_errno);
	else 	return FSD_MISSINGFUNC;
}

/* get attributes for file by name on a mount */

int fsd_getattr (fs_device_mount *mount, const char *path, struct objattr *attr)
{
	fs_device *device; 

	if (!mount) return FSD_BADMOUNT;
	else device = ((struct __fs_device_mount_stub *) mount)->device;

	if (device && device->device_funcs->getattr)
		return (device->device_funcs->getattr) (mount, path, attr);
	else	return FSD_MISSINGFUNC;
}

/* set attributes for file by name on a mount */

int fsd_setattr (fs_device_mount *mount, const char *path, struct objattr *attr)
{
	fs_device *device; 

	if (!mount) return FSD_BADMOUNT;
	else device = ((struct __fs_device_mount_stub *) mount)->device;

	if (device && device->device_funcs->setattr)
		return (device->device_funcs->setattr) (mount, path, attr);
	else	return FSD_MISSINGFUNC;
}

/* Get directory entries.
 *
 * The device function:
 * Returns >= 0 for number of entries found. Does NOT filter by wildcard, just
 * returns whole directory as a link list of fs_device_dir_entry * structs, which
 * it must allocate, and which there is a function above to free up. The 
 * device function must set *max_fname_len to the length of the longest filename
 * in the directory. For each file, it must populate the attributes in the
 * fs_device_dir_entry struct, including any sub-mounts.
 *
 * THIS function does a wildcard filter on it, and fills in the ownership
 * data from the fileserver the mount is on.
 *
 * If dir = "" then that's $ on this disc. 
 * If wildcard_needle = "" then the request is for all entries.
 *
 */

int fsd_get_dir_ents (fs_device_mount *mount, char *dir, char *wildcard_needle, fs_device_dir_entry **ents, uint8_t *max_fname_len, int *fs_errno)
{

	fs_device *device; 
	struct __fs_station *f;
	fs_device_dir_entry *l;

	if (!mount) return FSD_BADMOUNT;
	else 
	{
		device = ((struct __fs_device_mount_stub *) mount)->device;
		f = ((struct __fs_device_mount_stub *) mount)->server;
	}

	if (device && device->device_funcs->get_dir_ents)
	{
		int	ret;

		ret = (device->device_funcs->get_dir_ents) (mount, dir, ents, max_fname_len, fs_errno);

		/* Now sift for wildcards */

		/* Now put in user names on what's left */

		l = *ents;

		while (l)
		{
			strncpy(l->attr.ownername, f->users[l->attr.owner].username, 10);
			l = l->next;
		}

		/* Then sort out permissions - see fs.c:get_wildcard_entries */
		
		return ret;
	}

	return FSD_MISSINGFUNC;
}

void fsd_free_dir_ents (fs_device_dir_entry *l)
{
	fs_device_dir_entry *mine = l;

	while (mine)
	{
		fs_device_dir_entry *n = mine->next;

		FS_LIST_SPLICEFREE(l, mine, "FSDEVICE", "Freeing direntry structure");

		mine = n;

	}
}

char * fsd_strerror(int err)
{
	switch (err)
	{
		case 0: return "Success"; break;
		case -1: return "See system errno"; break;
		case -2: return "Memory allocation problem"; break;
		case -3: return "Bad parameters"; break;
		case -4: return "Mount: unknown disc"; break;
		case -5: return "Mount: bad disc number"; break;
		case -6: return "Mount: already mounted"; break;
		case -7: return "Busy"; break;
		case -8: return "Unmount: invalid mount"; break;
		case -9: return "Bad mount"; break;
		case -10: return "Missing driver function"; break;
		case -11: return "Not a directory"; break;
		case -12: return "Scandir failure"; break;
		case -13: return "Regex failure"; break;
		case -14: return "Bad handle"; break;
		case -15: return "Disc not available"; break;
		case -16: return "Object exists"; break;
		default: return "Unknown error"; break;
	}
}

uint8_t	fsd_test_harness (struct __fs_station *s, char *drivername, char *parameters)
{
	fs_device_instance	*instance;
	fs_device_mount		*mount;
	fs_device_local		*local;
	fs_device		*device;
	fs_device_dir_entry	*direntries;

	int			ret = 0, dirents, fsd_errno;
	uint8_t			max_fname_len;


	fs_debug_full (0, 1, s, 0, 0, "HARNESS: Called with parameters %s, %s", drivername, parameters);

	/* First, obtain the instance of this driver on this server */

	local = fsd_find_local(s, drivername);

	if (local)
	{
		instance = local->instance;
		device = local->device;
	}
	else
	{
		fs_debug_full (0, 1, s, 0, 0, "HARNESS: Test harness unable to find local instance of %s on this server", drivername);
		return 1;
	}

	fs_debug_full (0, 1, s, 0, 0, "HARNESS: Instance of %s found at %p (local) on device %s at %p", drivername, instance, device->device_name, device);

	/* Then attempt to mount something */

	mount = fsd_mount(device, s, instance, parameters, 0, 0, &fsd_errno);

	if (!mount || fsd_errno)
	{
		fs_debug_full (0, 1, s, 0, 0, "HARNESS: Could not obtain mount for %s:'%s' (ret = %d - %s)", drivername, parameters, fsd_errno, fsd_strerror(fsd_errno));
		return 1;
	}

	fs_debug_full (0, 1, s, 0, 0, "HARNESS: Mount for '%s:%s' obtained at %p", drivername, parameters, mount);

	fs_debug_full (0, 1, s, 0, 0, "HARNESS: Discname reported as '%s' with blocksize %d",
			fsd_get_discname(device, mount),
			fsd_get_disc_blocksize(device, mount));

	/* Get a directory listing for the root of this disc */

	direntries = NULL;

	dirents = fsd_get_dir_ents (mount, "", "", &direntries, &max_fname_len, &fsd_errno);

	if (dirents < 0)
		fs_debug_full(0, 1, s, 0, 0, "HARNESS: fsd_get_dir_ents for $ returned error %d (%s)", fsd_errno, fsd_strerror(fsd_errno));
	else
		fs_debug_full(0, 1, s, 0, 0, "HARNESS: Root directory of mount reported to have %d entries, max length %d", dirents, max_fname_len);

	if (dirents >= 0)
	{
		fs_device_dir_entry *d = direntries;

		/* Do more here */

		while (d)
		{
			fs_debug_full(0, 1, s, 0, 0, "HARNESS: -- %s (perm: %02X, acorn_perm: %02X, load: %08X, exec: %08X, length = %08X, owner: %04X (%s), sysid: %08X, type = %1d)", d->name, d->attr.perm, d->attr.acorn_perm, d->attr.load, d->attr.exec, d->attr.length, d->attr.owner, d->attr.ownername, d->attr.sysid, d->attr.ftype);
			d = d->next;
		}
		
	}
	else
		ret = 1;

	fsd_free_dir_ents(direntries);

	fs_debug_full(0, 1, s, 0, 0, "HARNESS: Freed dir entries list");

	/* Try and make our test directory */

	if (fsd_cdir(mount, "HARNESS", &fsd_errno))
	{
		fs_debug_full(0, 1, s, 0, 0, "HARNESS: Failed to make test directory! (fsd_error = %d (%s))", fsd_errno, fsd_strerror(fsd_errno));
		ret = 1;
	}
	else
		fs_debug_full(0, 1, s, 0, 0, "HARNESS: Successfully made test dir ('HARNESS') in root dir");

	/* Then unmount it */

	if (fsd_umount(device, mount))
	{
		fs_debug_full (0, 1, s, 0, 0, "HARNESS: un-mount %s:%s failed", drivername, parameters);
		ret = 1;
	}
	else
		fs_debug_full (0, 1, s, 0, 0, "HARNESS: unmounted %s:%s", drivername, parameters);

	return ret; /* Success */
}

/*
 * NOTE TODO:
 *
 * The get dirent routine needs to sort out:
 *
 * (1) Copying from the fsd dirent structure (load, exec, owner, ctime, etc.) - Normalizer can do this.
 * (2) Sorting out parent owner stuff - Normalizer can grab that, it knows where it is and may be on a different device
 * (3) Frigging the permissions (see fs.c:get_wildcard_entries)
 * (4) Sifting which of the dir entries match the wildcard
 * (5) Filling in the ownername field in the dirents - we can do all that for everyone
 */










