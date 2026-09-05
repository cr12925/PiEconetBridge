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

/* Some debug and malloc shortcuts */

#define fsd_malloc(desc,size)	eb_malloc(__FILE__, __LINE__, "FSDEVICE", FSDEVICE ": " desc, size)
#define fsd_free(desc,ptr)	eb_free(__FILE__, __LINE__, "FSDEVICE", FSDEVICE ": " desc, ptr)
#define fsd_debug(level, fmt)	eb_debug (0, level, "FSDEVICE", "FS               " FSDEVICE ": " fmt)
#define fsd_debug_fmt(level, fmt, ...)	eb_debug (0, level, "FSDEVICE", FSDEVICE ": " fmt, __VA_ARGS__)

/* Prototypes */

struct fs_device_funcs;

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

/* disc name entry for disc discovery */

struct __fsd_disc_entry {
	char	name[17];
	uint16_t	index;
	struct __fsd_disc_entry *next;
};

typedef struct __fsd_disc_entry fs_device_disc;

/* __fs_device_proto
 *
 * Return from register function. Anything register() puts in *next will be overwritten by the bridge
 */

struct __fs_device_proto {
	char 			*device_name; /* Short name - e.g. 'ADFS' used in the *MOUNT command to identify driver */
	char			*device_description; /* Text description e.g. 'ADFS floppy image device' */
	struct fs_device_funcs	*device_funcs; /* Pointer to __fs_device_funcs, ready populated for this device - must cast to (struct __fs_device_funcs *) */
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

/* Stub used to extract device pointer from an instance */

struct __fs_device_instance_stub {
	fs_device	*device; /* FSD Device this instance is on */
	struct __fs_station	*server; /* Fileserver this instance is on */
};

typedef struct __fs_device_instance_stub fs_device_instance_stub;

/* __fs_device_local
 *
 * List of FS devices initialized on a FS. 
 *
 * List pointed to by server->devices
 */

struct __fs_device_local {
	fs_device	*device;
	fs_device_instance	*instance; /* On this server */
	struct __fs_device_local *next, *prev;
};

typedef struct __fs_device_local fs_device_local;


/* fs_device_mount is the return value from the device's mount function
 * and must uniquely identify a device. It is passed back to the
 * FS device driver with each call in order to identify which
 * mounted device is being referred to. If one device is mounted
 * more than once, it is up to the driver whether it puts something
 * inside the data pointed to by fs_device to discriminate against
 * each one.
 */

typedef void fs_device_mount;

/* mount stub - used by the driver subsystem to cast & dig out the 
 * device. First element in any private fs_device_mount must be
 * fs_device *. These elements MUST appear in this order with
 * these types in the device's internal fs_device_mount structure
 * so that the main driver broker can extract them
 */

struct __fs_device_mount_stub {
	fs_device	*device;
	struct __fs_station	*server;
	fs_device_instance	*instance;
	uint8_t		readonly;
	/* Private drivers may have other things here */
};

typedef struct __fs_device_mount_stub fs_device_mount_stub;

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

struct __fs_device_handle_stub {
	fs_device	*device;
	fs_device_mount	*mount;
	/* Individual devices will have other stuff too. This is here to
	 * enable the driver subsystem to cast a handle & find out the
	 * device & mount
	 */
};
	
typedef struct __fs_device_handle_stub fs_device_handle_stub;

/* Acorn directory entry */

struct __fs_device_dir_entry {
	char	name[ECONET_ABS_MAX_FILENAME_LENGTH+1];
	struct objattr	attr;
	fs_device_mount	*mount; /* non-NULL if this is a mount point */
	struct __fs_device_dir_entry *next, *prev; /* prev is unused, but it's there so we can use FS_LIST_MAKENEW / FS_LIST_SPLICEFREE */
};

typedef struct __fs_device_dir_entry fs_device_dir_entry;

/* FS Mountable device prototypes */

struct fs_device_funcs {
	struct json_object * (*dev_report_schema) (void); /* Function the bridge will call when it wants the device to provide its JSON config schema, to include in the JSON schema to enable the web config system to work. Not presently implemented. CAN be NULL if no parameters */
	fs_device_instance * (*fs_init) (struct __fs_station *, struct json_object *); /* Init on particular fileserver station identified by first parameter; second parameter is pointer to json_object containing config parameters within this FS, from econet-hpbridge.json. First parameter is a struct __fs_station * cast to void * because the __fs_station struct is defined after this file is included. */
	int (*dev_unregister) (void); /* Unregister device driver. Device must verify that it is not in use! */
	int (*fs_release) (fs_device_instance *); /* Opposite of fs_init() - deregisters from a particular fileserver */

	/* CLI hook */

	int (*cli) (fs_device_instance *, char *); /* Passes the device-specific part of *FSDCMD <driver> <dev-specific> to the driver - allows implementation of own commands */

	/* Disc lifecycle */
	fs_device_mount * (*mount) (fs_device_instance *device, char *params, uint32_t flags, uint8_t fs_disc, int *); /* station is the FS station mounting the device, device is the registered device, params is everything after '*FSMOUNT <disc no.> <driver_name>' on the mount command line */
	int (*umount) (fs_device_mount *mnt); /* Umount - caused by *FSUMOUNT <disc no.>, which the FS uses to look up whether whether the disc is removable, and if so finds the fs_device_mount struct and passes it. Return is 0 for success, anything else for failure. If successful, the FS will take the disc out of the active disc lists. */

	/* Disc ops */

	/* Register a disc */

	int (*register_disc) (fs_device_instance *, char *, char *, uint32_t); /* Register a disc with name of first char * parameter, and necessary params in second char *, on the instance identified */

	/* Unregister a disc */

	int (*unregister_disc) (fs_device_instance *, char *); /* Unregister a disc if it is no longer in use */

	/* Return list of discs known to this driver */
	int (*get_discs) (fs_device_instance *, fs_device_disc **); /* malloc & return all the disc names known to this driver at fs_disc_entry, and return number returned */

	/* Get disc name of mounted disc */
	char * (*get_discname) (fs_device_mount *); /* Retrieve 16-character disc name */

	/* Get block size of disc */
	int16_t (*get_disc_blocksize) (fs_device_mount *);

	/* File handle operations */
	int (*open) (fs_device_mount *mount, const char *path, int flags, fs_device_handle **handle_out, int *fs_errno);
	int (*close) (fs_device_handle *handle, int *fs_errno);
	ssize_t (*read) (fs_device_handle *handle, void *buf, size_t len, int *fs_errno);
	ssize_t (*write) (fs_device_handle *handle, const void *buf, size_t len, int *fs_errno);
	int (*seek) (fs_device_handle *handle, off_t offset, int whence, int *fs_errno);
	off_t (*tell) (fs_device_handle *handle, int *fs_errno);
	int (*truncate) (fs_device_handle *, size_t new_size, int *fs_errno); /* Truncate / expand */

	/* File/dir-level */
	int (*cdir) (fs_device_mount *mount, const char *path, int *fs_errno); /* Create dir */
	int (*unlink) (fs_device_mount *mount, const char *path, int *fs_errno); /* unlink / delete */
	int (*getattr) (fs_device_mount *mount, const char *path, struct objattr *attr); /* Final parameter is struct objattr * cast to void * because struct objattr is defined after this file is included */
	int (*setattr) (fs_device_mount *mount, const char *path, struct objattr *attr); /* Final parameter is struct objattr * cast to void * because struct objattr is defined after this file is included */

	/* Directory operations */
	int (*get_dir_ents) (fs_device_mount *, char *, fs_device_dir_entry **, uint8_t *, int *fs_errno); /* Get directory index, with all attributes - the result is put in like getdirent, and there's a utility function in fsdevice.c which will free a linked list of those items */

};

/* 
 * Externs for utilities functions & main harness for device drivers
 */

struct fsd_param {
	uint16_t fsdp_start;
	uint16_t fsdp_end;
};

/* Utilitty prototypes */

extern uint16_t fsd_parse_params (char *, struct fsd_param *, uint16_t);
extern void fsd_param_extract (char *, struct fsd_param *, uint8_t, char *, uint8_t, uint16_t);
extern void fsd_free_disc_ents (fs_device_disc *);
extern fs_device * fsd_find_driver (struct __fs_station *, char *);
extern fs_device_instance * fsd_find_instance (struct __fs_station *, char *);
extern fs_device_local * fsd_find_local (struct __fs_station *, char *);

/* Main device driver wrapper prototypes */

struct json_object * fsd_dev_report_schema (fs_device *);
fs_device_instance * fsd_init (fs_device *, struct __fs_station *, struct json_object *);
int fsd_cli (fs_device_instance *, char *); 
int fsd_unregister (fs_device *); /* Return value is an FSD error */
int fsd_release (fs_device *, fs_device_instance *); /* Return value is an FSD error */
fs_device_mount *fsd_mount (fs_device_instance *, char *, uint32_t, uint8_t, int *); /* Final int * is an FSD error */
int fsd_umount (fs_device_mount *); /* Return value is an FSD error */
int fsd_register_disc (fs_device_instance *, char *, char *, uint32_t); /* Return value is an FSD Error */
int fsd_unregister_disc (fs_device_instance *, char *); /* Return value is an FSD Error */
int fsd_get_discs (fs_device *, fs_device_instance *, fs_device_disc **); /* Return value is an FSD Error */
char *fsd_get_discname (fs_device *, fs_device_mount *);
int16_t fsd_get_disc_blocksize (fs_device *, fs_device_mount *); /* If return is 0, there was an error */
int fsd_open (fs_device_mount *, const char *, int flags, fs_device_handle **, int *); /* Return value is an FSD Error; the last int * is system errno */
#define FSD_OPENIN 1
#define FSD_OPENOUT 2
#define FSD_OPENUP 3
int fsd_close (fs_device_handle *, int *); /* Ditto open */
ssize_t fsd_read (fs_device_handle *, void *, size_t, int *); /* Return value is equivalent of system read() OR FSD Error, final int* is system errno */
ssize_t fsd_write (fs_device_handle *, const void *, size_t, int *); /* Ditto read */
int fsd_seek (fs_device_handle *, off_t, int, int *); /* Ditto read */
off_t fsd_tell (fs_device_handle *, int *); /* Ditto read */
int fsd_truncate (fs_device_handle *, size_t, int *); /* Ditto read */
int fsd_cdir (fs_device_mount *, const char *, int *); /* DItto read */
int fsd_unlink (fs_device_mount *, const char *, int *); /* Ditto read */
int fsd_getattr (fs_device_mount *, const char *, struct objattr *); /* Return value is FSD Error */
int fsd_setattr (fs_device_mount *, const char *, struct objattr *); /* Return value is FSD Error */
int fsd_get_dir_ents (fs_device_mount *, char *, char *, fs_device_dir_entry **, uint8_t *, int *); /* Ditto read */
void fsd_free_dir_ents (fs_device_dir_entry *);

/* Execute test harness */
uint8_t fsd_test_harness (struct __fs_station *, char *, char *);

/* Convert FSD error to string */
char *fsd_strerror(int);

#define FSDEVICE_REGISTER(p,s) void __p(void) {  }; /* Dummy define - the string is picked up by the fsdevice_list.h builder */

/* Some flags defines for use on mount */
#define FSD_MOUNTFLAG_READONLY (1)

/* And for registering discs */
#define FSD_DISCFLAG_NONE	(0)
#define FSD_DISCFLAG_CANEXIST (1)

/* Some return values */

#define FSD_SUCCESS		0
#define FSD_SYSERR		-1 /* See errno - system call returned error */
#define FSD_NOMEM		-2 /* Memory allocation error */
#define FSD_BADPARAMS		-3 /* Bad parameters */
#define FSD_MOUNTERR_UNKNOWN_DISC	-4 /* Disc name / number unknown to driver */
#define FSD_MOUNTERR_BAD_DISC_NUMBER	-5 /* Bad disc number requested for mount */
#define FSD_MOUNTERR_ALREADY_MOUNTED	-6 /* Already mounted read/write elsewhere */
#define FSD_BUSY		-7	/* Mount / instance / whatever is busy - cannot do as asked */
#define FSD_UMOUNTERR_INVALID	-8	/* Invalid mount */
#define FSD_BADMOUNT		-9 	/* Bad mount (NULL) passed to function */
#define FSD_MISSINGFUNC		-10	/* A function is set to NULL in the driver's function map, probably when it shouldn't be */
#define FSD_NOTDIRECTORY	-11	/* Request to search a path which was not a directory */
#define FSD_SCANDIR_FAILURE	-12	/* scandir() or equivalent failed in some way */
#define FSD_SCANDIR_REGEX_FAILURE	-13	/* regcomp() in the scandir() or equivalent of a drvier failure */
#define FSD_BADHANDLE		-14	/* Bad handle passed to driver */
#define FSD_NODISC		-15	/* Disc you attempted to mount is not available */
#define FSD_EXISTS		-16	/* You tried to do something on a file/dir which exists, or register a disc which already exists */
#define FSD_EXHAUSTED		-17 	/* Out of resources */
#define FSD_READONLY		-18	/* Whatever you tried to do, it was a write operation on something read only (e.g. a disc, a mount) */
#define FSD_CLI_UNKNOWN		-19	/* CLI did not know the command offered */
#define FSD_PTR_CHECK_FAIL	-20	/* Internal test routine's pointer check failed to match */
#endif
