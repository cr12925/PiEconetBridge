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

#ifndef __INCLUDE_FSDEVICE_H
#define __INCLUDE_FSDEVICE_H

#include <sys/statvfs.h>

/*
 * Each device is required to provide a 'register' function which
 * returns an
 * eb_malloc()'d pointer to a struct __fs_device_proto, which the
 * *bridge* will add to its list of known FS Devices.
 *
 * Each FS can then in principle mount using any of those
 * device types, though in future it will be possible to 
 * configure the list of which device types can be used on 
 * an individual FS instance.
 *
 * The bridge will report an error if the device name provided
 * in the struct is the same as an existing FS device driver
 * on a case-insensitive basis.
 *
 */

/* __fs_device_proto
 *
 * Return from register function. Anything register() puts in *next will be overwritten by the bridge
 */

struct __fs_device_proto {
	char 			*device_name; /* Short name - e.g. 'ADFS' used in the *MOUNT command to identify driver */
	char			*device_description; /* Text description e.g. 'ADFS floppy image device' */
	void 			*device_funcs; /* Pointer to __fs_device_funcs, ready populated for this device - must cast to (struct __fs_device_funcs *) */
	struct __fs_device_proto	*next;
};

typedef struct __fs_device_proto fs_device;
/*
 * Each device must also provide an __init() function which is 
 * called by the FS before it tries to mount any devices. This
 * can provide parameters - e.g. where disc images are stored.
 *
 * The function will be passed a struct __fs_station * to identify
 * which FS is trying to initialize the driver.
 *
 * The __init() function is one of the functions to be provided
 * in the fs_device_funcs structure.
 *
 * It must return an fs_device_instance pointer which is passed
 * back to it on mount, and must be tracked by the device driver
 * in its fs_device_mount structure, thus any calls to open, read, etc.
 * can be tagged to a particular instance of the driver on a 
 * particular FS.
 *
 */

typedef void fs_device_instance;

/* fs_device_mount is the return value from the device's mount function
 * and must uniquely identify a device. It is passed back to the
 * FS device driver with each call in order to identify which
 * mounted device is being referred to. If one device is mounted
 * more than once, it is up to the driver whether it puts something
 * inside the data pointed to by fs_device to discriminate against
 * each one.
 */

typedef void fs_device_mount;

/* fs_device_handle is the return value from a successful open. 
 * It is a pointer to a struct which is then passed back to the driver
 * to identify a given open file. It is a pointer because the FS
 * presently opens files and stores a stream handle (FILE *) for 
 * system-opened files, and fs_device_handle will be stored in the
 * same space, possibly as a union.
 *
 * The driver can allocate and store whatever it needs in the
 * destination of the pointer - the FS will not enquire into it.
 *
 */

typedef void fs_device_handle;

/* FS Mountable device prototypes */

typedef struct {
	struct json_object * (*dev_report_schema) (void); /* Function the bridge will call when it wants the device to provide its JSON config schema, to include in the JSON schema to enable the web config system to work. Not presently implemented. CAN be NULL if no parameters */
	fs_device_instance * (*fs_init) (void *, struct json_object *); /* Init on particular fileserver station identified by first parameter; second parameter is pointer to json_object containing config parameters within this FS, from econet-hpbridge.json. First parameter is a struct __fs_station * cast to void * because the __fs_station struct is defined after this file is included. */
	int (*dev_unregister) (fs_device *); /* Unregister device driver. Device must verify that it is not in use! */
	int (*fs_release) (fs_device_instance *); /* Opposite of fs_init() - deregisters from a particular fileserver */

	/* Disc lifecycle */
	fs_device_mount * (*mount) (void *station, fs_device_instance *device, char *params, uint32_t flags); /* station is the FS station mounting the device, device is the registered device, params is everything after '*FSMOUNT <disc no.> <driver_name>' on the mount command line */
	int (*umount) (fs_device_mount *mnt); /* Umount - caused by *FSUMOUNT <disc no.>, which the FS uses to look up whether whether the disc is removable, and if so finds the fs_device_mount struct and passes it. Return is 0 for success, anything else for failure. If successful, the FS will take the disc out of the active disc lists. */
	char * (*get_discname) (fs_device_mount *mnt); /* Retrieve 16-character disc name */

	/* File handle operations */
	int (*open) (fs_device_mount *mount, const char *path, int flags, fs_device_handle **handle_out);
	int (*close) (fs_device_handle *handle);
	ssize_t (*read) (fs_device_handle *handle, void *buf, size_t len);
	ssize_t (*write) (fs_device_handle *handle, const void *buf, size_t len);
	off_t (*seek) (fs_device_handle *handle, off_t offset, int whence);
	off_t (*tell) (fs_device_handle *handle);

	/* Metadata */
	int (*getattr) (fs_device_mount *mount, const char *path, void **attr); /* Final parameter is struct objattr ** cast to void ** because struct objattr is defined after this file is included */
	int (*setattr) (fs_device_mount *mount, const char *path, void *attr); /* Final parameter is struct objattr * cast to void * because struct objattr is defined after this file is included */
	uint32_t (*getsysid) (fs_device_mount *mount, const char *path); /* Obtain system file ID. In the system driver, this is the inode number. This is actually a 24-bit number in 32-bit storage */

	/* Directory */
	int (*normalize_wildcard) (fs_device_mount *mount, unsigned char *path_from_device_root, void *result, unsigned short wildcard); /* Param 2 is ASCII path from root of this FS device (NOT from top level; devices may in the future be mounted other than at a disc mount point, and is in ACORN format; void * result is struct path * cast to void * because struct path is defined after this file is included. wildcard = 0 means turn off wildcard search - must find precise match */

	/* Disc-level */
	int (*statvfs) (fs_device_mount *mount, struct statvfs *stat); /* Populate a statvfs structure for the virtual disc */
	int (*create) (fs_device_mount *mount, const char *path, size_t alloc); /* Create file; set attributes with setattr if successful */
	int (*truncate) (fs_device_mount *mount, const char *path, size_t new_size); /* Truncate / expand */
	int (*unlink) (fs_device_mount *mount, const char *path); /* unlink / delete */
	
} __fs_device_funcs;


#define FSDEVICE_REGISTER(p) { 0 } /* Dummy define - the string is picked up by the fsdevice_list.h builder */

#endif
