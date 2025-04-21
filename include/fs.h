/*
  (c) 2024 Chris Royle
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

/* General includes for FS */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <regex.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <resolv.h>
#include <sys/socket.h>
#include <termios.h>
#include <pthread.h>
#include <poll.h>
#if __has_include(<libexplain/ferror.h>)
	#include <libexplain/ferror.h>
#else
	#define __NO_LIBEXPLAIN
#endif

#include "econet-gpio-consumer.h"
#include "econet-hpbridge.h"
#include "econet-fs-hpbridge-common.h"

/*
 * Pi Econet Bridge FS include header
 *
 */

/* Some constants, many of which will go away when the FS becomes threaded */

#define FS_DEFAULT_NAMELEN 10

// Implements basic AUN fileserver within the econet bridge

#define ECONET_MAX_FS_SERVERS 4
#define ECONET_MAX_FS_USERS 256 // Total defined on a server, not total logged in
#define ECONET_MAX_FS_ACTIVE 80 // Maximum simultaneous logged in users (after all they all need at least 3 handles...)
#define ECONET_MAX_FS_DISCS 10 // Don't change this. It won't end well.
#define ECONET_MAX_FS_DIRS 256 // maximum number of active directory handles
#define ECONET_MAX_FS_FILES 512 // Maximum number of active file handles
#define FS_MAX_OPEN_FILES 33 // Really 32 because we don't use entry 0 - maximum per user

#define ECONET_MAX_FILENAME_LENGTH (f->server->config->fs_fnamelen)
// Do NOT change this. Some format string lengths and array lengths are still hard coded.  (And some of the
// arrays are of length 81 to take a null byte as well. So to make this fully flexible, a number of arrays
// need to be altered, and some format strings need to be built with sprintf so that the right length
// can be incorporated before that (second) format string can be used... sort of a work in progress!
#define ECONET_ABS_MAX_FILENAME_LENGTH 80
#define ECONET_MAX_PATH_ENTRIES 30
#define ECONET_MAX_PATH_LENGTH ((ECONET_MAX_PATH_ENTRIES * (ECONET_ABS_MAX_FILENAME_LENGTH + 1)) + 1)

// Definitions common to HP Bridge and FS
#include "../include/econet-fs-hpbridge-common.h"

// PiFS privilege bytes

// Our native privs
#define FS_PRIV_SYSTEM 0x80
#define FS_PRIV_LOCKED 0x40
#define FS_PRIV_NOPASSWORDCHANGE 0x20
#define FS_PRIV_USER 0x01
#define FS_PRIV_INVALID 0x00

// MDFS-related privs in our native format - this doesn't work because we don't check for priv & FS_PRIV_SYSTEM for example, we check equality. Use the macro and fix the macro. TODO.
#define FS_PRIV_PERMENABLE 0x08
#define FS_PRIV_NOSHORTSAVE 0x04
#define FS_PRIV_RUNONLY 0x02
#define FS_PRIV_NOLIB 0x10 /* Yes, this one is different - we don't have 0x10 as a flag in our native priv system */

// MDFS privilege bits in MDFS format
#define MDFS_PRIV_PWUNLOCKED 0x01
#define MDFS_PRIV_SYST 0x02
#define MDFS_PRIV_NOSHORTSAVE 0x04
#define MDFS_PRIV_PERMENABLE 0x08
#define MDFS_PRIV_NOLIB 0x10
#define MDFS_PRIV_RUNONLY 0x20

// priv2 bits
#define FS_PRIV2_BRIDGE 0x01 /* Can access *FAST, can use the FSOP to shut down the bridge (power off) etc.  */
#define FS_PRIV2_CHROOT 0x02 /* Make user home dir appear as root */
#define FS_PRIV2_HIDEOTHERS 0x04 /* Don't show other users in fs_users() */
#define FS_PRIV2_ANFSNAMEBODGE 0x08 /* ANFS strips the colon off the start of a filename if it appears to be a disc number instead of a disc name. This privilege causes the normalizer to spot [0-9].$ and replace with :[0-9].$ in filenames. This is a per user priv because it can break filenames! */
#define FS_PRIV2_FIXOPT 0x10 /* User cannot change boot option */

/* user *opt 4,x options */
#define FS_BOOTOPT_OFF 0x00
#define FS_BOOTOPT_LOAD 0x01
#define FS_BOOTOPT_RUN 0x02
#define FS_BOOTOPT_EXEC 0x03

#define FS_MAX_BULK_SIZE 0x1000 // 4k - see RiscOS PRM

#define FS_MAX_TAPE_DRIVES 4 // Max number of tape drives available, numbered 0 ... n-1. Not a good idea to put this beyond 10 given there's a call to receive mounted tape names.

/* Reported version string */
#define FS_VERSION_STRING "3 Pi Econet HP Bridge FS 2.20"

/* Various important struct definitions */

/* Structure to be passed to the machine registration thread */

struct __fs_machine_peek_reg {
	struct __fs_station	*s; /* Server - used when calling the update function, but not within an FS itself*/
	uint8_t		net;
	uint8_t		stn;
	uint32_t	mtype;
	struct __fs_machine_peek_reg	*next, *prev;
};
			
/* __fs_station - instance information about a fileserver instance */

struct __fs_station {
        unsigned char 		net; // Network number of this server
        unsigned char 		stn; // Station number of this server
        unsigned char 		directory[256]; // Root directory
        uint16_t 		total_users; // How many entries in users?
	uint16_t		total_groups; // Number of entries in groups
	uint32_t		seq;
	uint8_t			tapedrive; // Currently selected tape drive number
	unsigned char	 	tapedrives[FS_MAX_TAPE_DRIVES][11]; // One per drive, indicates which tape is mounted; tape name up to 10 characters, null terminated
        int 			total_discs;
	struct __fs_config	*config; // Pointer to my config
	struct __fs_disc	*discs; // Pointer to discs
	struct __fs_file	*files; // Pointer to open files
	struct __fs_active	*actives; // Pointer to actives
	struct __fs_user	*users; // Pointer to (effectively) the mmaped password data
	struct __fs_group	*groups; // Pointer to mmaped group file
	struct __fs_bulk_port	*bulkports; // Pointer to list of bulk ports
	struct __fs_machine_peek_reg	*peeks; // List of pending machine peeks
	uint8_t			bulkport_use[32]; // Bitmap - Need to move this to the local device in the bridge
	uint8_t			enabled; // Whether server enabled
	struct __eb_device	*fs_device; // Pointer to device housing this server in the main bridge 
	pthread_mutex_t		fs_mutex; // Lock when this FS is working
	pthread_mutex_t		fs_mpeek_mutex; // Lock we sit on waiting for machine peeks
	pthread_cond_t		fs_condition; // Condition the FS waits on for traffic
	pthread_t		fs_thread; // FS thread 
	struct __eb_packetqueue	*fs_workqueue; // Packets to be processed by this FS
	regex_t			r_pathname; // Pathname by filename length
	regex_t			r_wildcard, r_discname, r_discwildcard; /* Regexes for filenames */
	struct __fs_station	*next, *prev; // Up and down the tree
};

/* __fs_config - config of an individual fileserver instance */

struct __fs_config {
        uint8_t fs_acorn_home; // != 0 means implement acorn home directory ownership semantics
        uint8_t fs_sjfunc; // != 0 means turn on SJ MDFS functionality
        uint8_t fs_bigchunks; // Whether we use 4k chunks on data bursts, or 1.25k (BeebEm compatibility - it appears to have a buffer overrun!)
        uint8_t fs_pwtenchar; // Set to non-zero when the FS has run the 6 to 10 character password conversion, by moving the fullname field along by 5 chracters
        uint8_t fs_fnamelen; // Live (modifiable!) max filename length. Must be less than ECONET_MAX_FILENAME_LENGTH. When changed, this has to recompile the fs regex
        uint8_t fs_infcolon; // Uses :inf for alternative to xattrs instead of .inf, and maps Acorn / to Unix . instead of Unix :
        uint8_t fs_manyhandle; // Enables user handles > 8, and presents them as 8-bit integers rather than handle n presented as 2^n (which is what FS 3 does with its limit of 8 handles)
        uint8_t fs_mdfsinfo; // Enables longer output from *INFO akin to MDFS
        uint8_t fs_pifsperms; // Enables more flexible permissions on directories and enforces them
        uint8_t fs_default_dir_perm; // Default permission to apply to a directory when created / if no xattr file. Will pick wr/r if config file exists (existing fileserver), or wr/ otherwise (for level3-alikeness)
        uint8_t fs_default_file_perm; // Ditto for files. If the config file exists, it'll pick wr/r for backward compat; otherwise wr/ for level3-alikeness
        uint8_t fs_mask_dir_wrr; // Whether to mask off the wr/r bits on a directory in human and non-human-readable output. These are implied if a client sets perms on a directory to &00 anyway. Won't mask if ((perms & wr/r) != wr/r) so that manually set permissions are shown/returned.
        uint8_t pad[243]; // Spare spare in the config
};

/* __fs_discs - disc information for a particular server */

struct __fs_disc {
	unsigned char 		name[17];
	uint8_t			index; /* Disc number - ready for new structure */
	struct __fs_disc	*next, *prev;
	struct __fs_station	*server; /* Upward reference */
};

/* __fs_file - open file information for a particular server */

struct __fs_file {
        unsigned char 	name[1024];
        FILE 		*handle;
        int 		readers, writers; // Used for locking; when readers = writers = 0 we close the file
	struct __fs_file 	*next, *prev; /* Pointers for new structure */
};

#if 0
/* Not used */
/* __fs_dir - open directory information for a particular server */

struct __fs_dir {
        unsigned char 	name[1024];
        DIR 		*handle;
        int 		readers; // When 0, we close the handle
	struct __fs_dir 	*next, *prev; /* Pointers for new structure */
};
#endif

/* __fs_bulk_port - fileserver bulk (data burst) port list */

struct __fs_bulk_port {
	struct __fs_file *handle;
	struct __fs_active *active; // Station this goes to
	uint8_t	bulkport; // Bulk port number
        unsigned char ack_port;
        unsigned char reply_port;
        unsigned char rx_ctrl;
        unsigned long length;
        unsigned long received;
        unsigned short mode; // as in 1 read, 2 updated, 3 write & truncate (I think!)
        unsigned short is_gbpb; // 0 = no user handle because we are doing a fs_save
        unsigned short user_handle; // index into active[server][active_id].fhandles[] so that cursor can be updated
        unsigned long long last_receive; // Time of last receipt so that we can garbage collect
        unsigned char acornname[ECONET_ABS_MAX_FILENAME_LENGTH+2]; // Tail path segment - enables *SAVE to return it on final close // Was 12
	uint8_t		is_32bit; // Used to signal whether the close packet needs to be 32 bit
	struct __fs_bulk_port		*next, *prev; /* Pointers for new structure */
};

/* File handling struct definitions */

struct path_entry {
        short ftype;
        int owner, parent_owner;
        unsigned char ownername[11];
        unsigned short perm, parent_perm, my_perm;
        unsigned short homeof;
        unsigned long load, exec, length, internal;
        unsigned char unixpath[1024], unixfname[ECONET_ABS_MAX_FILENAME_LENGTH+1], acornname[ECONET_ABS_MAX_FILENAME_LENGTH+1]; // unixfname / acornname were 15, but now 81 to handle max 80 character filenames
        unsigned char day, monthyear, hour, min, sec; // Modified date / time
        unsigned char c_day, c_monthyear, c_hour, c_min, c_sec;
        struct path_entry *next, *parent;
};

/* Object attributes definition */

struct objattr {
        unsigned short perm;
        unsigned short owner;
        unsigned long load, exec;
        unsigned short homeof;
};

#define FS_PATH_ERR_NODIR 0x01 // Path searched for had a directory that did not exist
#define FS_PATH_ERR_FORMAT 0x02 // Path searched for contained invalid material (e.g. started with a '.')
#define FS_PATH_ERR_NODISC 0x03 // Selected disc does not exist
#define FS_PATH_ERR_TYPE 0x04 // What we found was neither file nor directory (even on following a symlink)
#define FS_PATH_ERR_LENGTH 0x05 // Path provided was too long or too short

struct path {
        unsigned short error; // One of FS_PATH_ERR* - only valid if function returns 0
        short ftype; // ECONET_FTYPE_DIR, ECONET_FTYPE_FILE
        // If ftype == NOTFOUND, the rest of the fields are invalid
        unsigned char discname[30]; // Actually max 10 chars. This is just safety.
        short disc; // Disc number
        unsigned char path[12][ECONET_ABS_MAX_FILENAME_LENGTH+1]; // Path elements in order, relative to root // Was 30, 11 - adjusted to 12 paths to keep within the typical 1024 byte path block in the code
        unsigned char acornname[ECONET_ABS_MAX_FILENAME_LENGTH+1]; // Acorn format filename - tail end - gets populated on not found for non-wildcard searches to enable *SAVE to return it
        short npath; // Number of entries in path[]. 1 means last entry is [0]
        unsigned char path_from_root[2560]; // Path from root directory in Econet format // Was 256 - extended for long fnames
        uint16_t owner; // Owner user ID
        uint16_t parent_owner;
        uint16_t homeof;
        unsigned char ownername[11]; // Readable name of owner
        uint8_t perm; // Permissions for owner & other - ECONET_PERM_... etc.
        uint8_t parent_perm; // If object is not found or is a file, this contains permission on parent dir
        uint8_t my_perm; // This user's access rights to this object - i.e. only bottom 3 bits of perm, adjusted for ownership
        uint32_t load, exec, length;
        uint32_t internal; // System internal name for file. (aka inode number for us)
        struct objattr attr; // Not yet in use generally
        unsigned char unixpath[1024]; // Full unix path from / in the filesystem (done because Econet is case insensitive)
        unsigned char acornfullpath[1024]; // Full acorn path within this server, including disc name
        unsigned char unixfname[ECONET_ABS_MAX_FILENAME_LENGTH+5]; // As stored on disc, in case different case to what was requested // Was 15 before long fnames
        unsigned char day; // day of month last written
        unsigned char monthyear; // Top 4 bits years since 1981; bottom four are month (Not very y2k...)
        unsigned char hour, min, sec; // Hours mins sec of modification time
        unsigned char c_day, c_monthyear, c_hour, c_min, c_sec; // Date/time of Creation
	uint8_t max_fname_length; // Maximum length of any filename matching this query
        struct path_entry *paths, *paths_tail; // pointers to head and tail of a linked like of path_entry structs. These are dynamically malloced by the wildcard normalize function and must be freed by the caller. If FS_FTYPE_NOTFOUND, then both will be NULL.
};

/* Normalize defines */

#define FS_FTYPE_NOTFOUND 0
#define FS_FTYPE_FILE 1
#define FS_FTYPE_DIR 2
#define FS_FTYPE_SPECIAL 3 // Not sure what I'll use that for, but we'll have it anyhow

/* Permissions-handling definitions */

// PiFS file / dir permission bits

#define FS_PERM_H 0x80 // Hidden - doesn't show up in directory list, but can be opened (not accessible to non-owner)
#define FS_PERM_OTH_W 0x20 // Write by others
#define FS_PERM_OTH_R 0x10 // Read by others
#define FS_PERM_EXEC 0x08 // Execute only
#define FS_PERM_L 0x04 // Locked
#define FS_PERM_OWN_W 0x02 // Write by owner
#define FS_PERM_OWN_R 0x01 // Read by owner

#define FS_PERM_PRESERVE 0xff00 // Special 16-bit value fed to fs_setxattr() to stop it overwriting perms

// Defines to test permission bits
// p = perm byte
// b = bit required

#define FS_PERM_SET(p,b)        (((p) & (b)) ? 1 : 0)
#define FS_PERM_UNSET(p,b)      (((p) & (b)) ? 0 : 1)

// Defines to implement file & dir access permissions
// In each case:
//   s = server number
//   a = active_id
//   p = file perms (the whole 8 bits)
//   o = file owner
//   pp = parent dir perms
//   po = parent owner

// The following are derived from watching what ANFS does/doesn't do when talking to a Level 4 server as both owner and non-owner
// of a file. It was found that SYST is just equivalent to owner

// Actual owner
#define FS_PERM_ISOWNER(a,o)  ((FS_ACTIVE_UID((a)) == (o)) ? 1 : 0)
// Effective owner - i.e. actual owner or system priv
#define FS_PERM_EFFOWNER(a,o) (FS_ACTIVE_SYST((a)) || FS_PERM_ISOWNER((a),(o)) ? 1 : 0)

// Object visible to this user - as distinct from readable - this is testing the hidden bit
#define FS_PERM_VISIBLE(a,p,o)        (!FS_PERM_SET((p), FS_PERM_H) || FS_PERM_EFFOWNER((a),(o)))

// Can create new file if it doesn't exist already
#define FS_PERM_CREATE(a,p,o,pp,po)   ((FS_PERM_EFFOWNER((a),(po)) && (!FS_CONFIG_PIFSPERMS((a->server)) || FS_PERM_SET((pp), FS_PERM_OWN_W))) || (FS_CONFIG_PIFSPERMS((a->server)) && FS_PERM_SET((pp), FS_PERM_OTH_W) && FS_PERM_SET((pp), FS_PERM_OWN_W)))

// Can SAVE - only if unlocked and we effectively own it. Non-owners cannot save unless PiFS perms enabled.
// Even then, only if both owner & other W are set, which is similar to what happens when non-owner read is
// requested in L4, which requires both OTH_R and OWN_R set.
#define FS_PERM_SAVE(a,p,o,pp,po) ((FS_PERM_UNSET((p), FS_PERM_L) && (\
                (FS_PERM_EFFOWNER((a),(o))) ||\
                (FS_CONF_PIFSPERMS((a->server)) && FS_PERM_SET((p), FS_PERM_OWN_W) && FS_PERM_SET((p), FS_PERM_OTH_W)) \
                ))
// Can LOAD - note that L4 enforces both R/ and /r for a non-owner to read, so R/ is required whether owner or not
#define FS_PERM_LOAD(a,p,o,pp,po) (\
                (!FS_CONFIG_PIFSPERMS((a->server)) || (FS_PERM_SET_((pp), FS_PERM_OWN_R) && (FS_PERM_EFFOWNER((a), (po)) || FS_PERM_SET((pp), FS_PERM_OTH_R)))) && \
                (FS_PERM_SET((p), FS_PERM_OWN_R) && (FS_PERM_EFFOWNER((a),(o)) || FS_PERM_SET((p), FS_PERM_OTH_R))) \
                )

// Can RENAME - Owner always can unless locked, non-owner never can - except if PIFS PERMS enabled, in which case they can if they have write access to the parent
#define FS_PERM_RENAME(a,p,o,pp,po) (\
                FS_PERM_UNSET((p), FS_PERM_L) && \
                ( \
                        ( \
                         FS_CONFIG_PIFSPERMS((a->server)) && \
                                (FS_PERM_SET((pp), FS_PERM_OWN_W) && (FS_PERM_EFFOWNER((a),(po)) || FS_PERM_SET((pp), FS_PERM_OTH_W))) \
                        ) \
                        || \
                        (!FS_CONFIG_PIFSPERMS((a->server) && FS_PERM_EFFOWNER((a),(o)))) \
                ))

// Can OPENIN
#define FS_PERM_OPENIN  FS_PERM_LOAD

// Can OPENOUT - Level 4 forbids this on WL/ but allows it on +R or +W (wither +L or -L!) - looks like this is (+L && +R) || (+W || +R). In Acorn world, OPENOUT *always* fails for non-owner. In PIFS world, it will succeed if +W/w
#define FS_PERM_OPENOUT(a,p,o,pp,po) \
        ( \
          (FS_PERM_EFFOWNER((a),(o)) && ( (FS_PERM_SET((p), FS_PERM_L) && FS_PERM_SET((p), FS_PERM_OWN_R)) || (FS_PERM_SET((p), FS_PERM_OWN_R) || FS_PERM_SET((p), FS_PERM_OWN_W)) ) ) \
          || \
          (FS_CONF_PIFSPERMS((a->server)) && FS_PERM_SET((p), FS_PERM_OWN_W) && FS_PERM_SET((p), FS_PERM_OTH_W)) \
        )

// Can OPENUP - Level 4 does same as OPENOUT
#define FS_PERM_OPENUP FS_PERM_OPENOUT

// Can BPUT/S - Owner: requires +R,+W,-L. Other requires +W/+W and -L
#define FS_PERM_WRITE(a,p,o,pp,po) \
        ( FS_PERM_UNSET((p), FS_PERM_L) && \
          (FS_PERM_EFFOWNER((a),(o)) ? \
           (FS_PERM_SET((p), FS_PERM_OWN_R) && FS_PERM_SET((p), FS_PERM_OWN_W)) \
         : (FS_PERM_SET((p), FS_PERM_OWN_W) && FS_PERM_SET((p), FS_PERM OTH(W))) \
         ) \
         )

/* FS Configuration and dir mask defines */

#define FS_CONF_PIFSPERMS(s)    (FS_CONFIG(s,fs_pifsperms) == 0x80 ? 0 : 1)
#define FS_CONF_DEFAULT_DIR_PERM(s)     (s->config->fs_default_dir_perm)
#define FS_CONF_DEFAULT_FILE_PERM(s)    (s->config->fs_default_file_perm)
#define FS_ACORN_DIR_MASK       (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R)

/* Macros to find user information */

#define FS_DISC_VIS(s,u,d) ((d >= 16) || (s->users[(u)].home_disc == (d)) || !(s->users[(u)].discmask & (1 << (d))))

// Macro to provide a shortcut to getting a user's real ID when the caller only knows the index into active[]
#define FS_ACTIVE_UID(a) (a->userid)
// Macro to identify if we have system privileges
#define FS_ACTIVE_SYST(a) (a->server->users[a->userid].priv & FS_PRIV_SYSTEM)
// Macro to identify if we have bridge privileges
#define FS_ACTIVE_BRIDGE(a) (a->server->users[a->userid].priv2 & FS_PRIV2_BRIDGE)

// Macro to get us at the user config from an fs_active
#define FS_UINFO(a)	a->server->users[a->userid]

// Macro to get us serverconfig from fsop_data
#define FS_CONFIG(s,n)	(s->config->n)
/*
 * Bulk transfer structures
 *
 * For *LOAD / *RUN / fs_getbytes()
 */

// When fs_load_queue is not null (see below), the main loop in the bridge will call fs_execute_load_queue to dump one packet off the head of each queue to the destination station
struct __pq {
        struct __econet_packet_udp *packet; // Don't bother with internal 4 byte src/dest header - they are given as parameters to aun_send.
        int len; // Packet data length
	struct __fs_station	*server; // Upward link to server ready for tx routine
	uint8_t		is_32bit;	// Whether to close with a 32 bit length when we are reading dynamically instead of queues
        uint16_t delay; // in milliseconds - to cope with RISC OS not listening...
        struct __pq *next;
};

#if 0
/* now disused */
struct load_queue {
	struct __fs_station	*server;
	struct __fs_active	*active; /* Identify client & address */
        unsigned queue_type; // For later use with getbytes() - but for now assume always a load
	struct __fs_file	*internal_handle; // Pointer to the file we're reading
	uint8_t			user_handle; // Index to active->fhandles for this transaction - e.g. to update cursor on gbpb
        uint8_t			mode; // Internal mode
	uint8_t			ctrl; // Ctrl byte for close packet on GBPB calls
        uint32_t        	ack_seq_trigger; // Sequence number for which we receive an ack which will trigger next transmission
        time_t          	last_ack_rx; // Last time we received an ACK from this station - used for garbage collection
	/* For future use - when implemented, we can dump the packet queue and its memory usage ...  */
	uint32_t		start_ptr, send_len, sent_len; /* filepos to start at, length to send (in chunk_size lumps), amount sent already - to calculate next packet start pos */
	uint16_t		chunk_size;
        struct load_queue 	*next;
        struct __pq 		*pq_head, *pq_tail; /* Will be disused when the load dequeuer reads on a just in time basis */

};
#endif

struct __fs_active_load_queue {
        unsigned 		queue_type; // Is this FsOp_Load or GBPB? (Changes the padding and termination packet)
        struct __fs_file        *internal_handle; // Pointer to the file we're reading
        uint8_t                 user_handle; // Index to active->fhandles for this transaction - e.g. to update cursor on gbpb. Invalid on FsOp_Load
        uint8_t                 mode; // Internal file opening mode - so that the close_interlock closes the right mode
        uint8_t                 ctrl; // Ctrl byte for close packet on GBPB calls
	uint8_t			client_dataport, client_finalackport; // Ports to send stuff to
        uint32_t                ack_seq_trigger; // Sequence number for which we receive an ack which will trigger next transmission
        time_t                  last_ack_rx; // Last time we received an ACK from this station - used for garbage collection
        /* For future use - when implemented, we can dump the packet queue and its memory usage ...  */
        uint32_t                start_ptr, send_bytes, sent_bytes, cursor, valid_bytes; /* filepos to start at, length to send (in chunk_size lumps), amount sent already - to calculate next packet start pos */
	uint8_t			pasteof; /* Signals to the dequeuer if it is already past EOF so it doesn't bother trying to read again */
	uint8_t			is_32bit; /* Signals whether we need a 32 bit close packet */
        uint16_t                chunk_size;
        struct __fs_active_load_queue       *next, *prev;
};

/* Main user structs etc. */

/* __fs_user - password file info for a single user */

struct __fs_user {
        unsigned char username[10];
        unsigned char password[11];
        unsigned char fullname[25];
        unsigned char priv;
        unsigned char bootopt;
        unsigned char home[80];
        uint8_t         unused1[8];
	uint32_t	quota_total; // Kb?
	uint32_t	quota_used;
        unsigned char lib[80];
        uint8_t         unused2[16];
        unsigned char home_disc;
        unsigned char year, month, day, hour, min, sec; // Last login time
        uint8_t         priv2;
        uint16_t        discmask; // 1 bit per disk number, if set the system will not show that disc to the user. discmask must never have the bit set which refers to the home drive. The FS_DISC_VIS macro deliberately will always return 1 for the home drive
        char unused[6];
};

/* MDFS user structure, for generating MDFS pw file */

struct mdfs_user {
        unsigned char   username[10]; // 0x0D terminated if less than 10 chars - MDFS manual seems to have only 9 bytes for a 10 character username. Looks like a misprint
        unsigned char   password[10]; // Ditto
        uint8_t         opt;
        uint8_t         flag; /* bit 0:Pw unlocked; 1:syst priv; 2: No short saves; 3: Permanent *ENABLE; 4: No lib; 5: RUn only */
        uint8_t         offset_root[3]; /* File offset to URD, or 0 if "normal", whatever that may be */
        uint8_t         offset_lib[3]; /* File offset to LIB, or 0 if "normal" */
        uint8_t         uid[2];
        uint8_t         reserved[2]; /* Assume not supposed to use this! */
        uint8_t         owner_map[32]; /* Bitmap of account ownership */
};

/* __fs_group - group info; presently unused */

struct __fs_group {
	unsigned char grouopname[10];
};

/* __fs_user_fhandle - user filehandle */

struct __fs_user_fhandle {
		struct __fs_file 	*handle; /* System file handle */ 
                unsigned long cursor; // Our pointer into the file
                unsigned long cursor_old; // Previous cursor in case we get a repeated request, we can go back
                unsigned short mode; // 1 = read, 2 = openup, 3 = openout
                unsigned char sequence; // Oscillates 0-1-0-1... This variable stores the LAST b0 of ctrl byte received, so when we get new traffic it should be *different* to what's in here.
                unsigned short pasteof; // Signals when there has already been one attempt to read past EOF and if there's another we need to generate an error
                unsigned short is_dir; // Looks like Acorn systems can OPENIN() a directory so there has to be a single set of handles between dirs & files. So if this is non-zero, the handle element is a pointer into fs_dirs, not fs_files.
                char acornfullpath[1024]; // Full Acorn path, used for calculating relative paths
                char acorntailpath[ECONET_ABS_MAX_FILENAME_LENGTH+1];
};

/* __fs_active - cache information about a logged in user */

struct __fs_active {
        uint8_t net, stn;
        uint16_t userid; // Index into users[n][]

	struct __fs_station	*server; /* Upward reference to server housing this active user */
	struct __fs_user	*user; /* Pointer to __fs_station->user[userid] */

        uint8_t root, current, lib; // Handles
        unsigned char root_dir[1024], current_dir[1024], lib_dir[1024]; // Paths relative to root
        unsigned char root_dir_tail[ECONET_ABS_MAX_FILENAME_LENGTH+1], lib_dir_tail[ECONET_ABS_MAX_FILENAME_LENGTH+1], current_dir_tail[ECONET_ABS_MAX_FILENAME_LENGTH+1]; // Just the last element of path, or $ // these were 15
        uint8_t home_disc, current_disc, lib_disc; // Currently selected disc for each of the three handles
        unsigned char urd_unix_path[1024]; // Used for chroot purposes - stored at login / sdisc

        uint8_t bootopt;

        uint8_t priv; // Copy of priv bits from user info

	uint32_t machinepeek; /* Machinepeek result if it's happened */
	uint32_t chunk_size; /* Max bulk transfer outbound chunk size */
	uint8_t manyhandles; /* 1 = 32 handles, 0 = 8 */

        uint8_t printer; // Index into this station's printer array which shows which printer has been selected - defaults to &ff to signal 'none'.

	struct __fs_user_fhandle fhandles[FS_MAX_OPEN_FILES];
	//uint32_t	handle_map; /* New structure - 1 bit per handle if handle is in use / valid. To find a free handle, XOR with &FFFFFFFF and if 0 then no free handles (for 32 bit machines), if XOR = &FFFFFF00 then no free handles for 8 bit machines. To find first new handle, just keep looking at least significant bit - if 0, then you've found a handle, otherwise shift right one bit. */
	struct __fs_active_load_queue	*load_queue;

        uint8_t sequence; // Used to detect duplicate transmissions on putbyte - oscillates 0-1-0-1 - low bit of ctrl byte in packet. Gets re-set whenever there is an operation which is not a putbyte, so that successive putbytes get the tracker, but anything else in the way resets it

	struct __fs_active	*next, *prev; /* Ready for full implementation of new structure */
};

/*
 * Scheduled backup structure
 *
 */

struct __fs_backup {
	uint64_t	when; // Time scheduled for backup
	uint8_t		print_output; // MDFS as 0 = off, 1 = parallel, 2 = serial. Not sure whether we'll bother with this.
	unsigned char	tapename[11]; // 10 characters - tape name to back up to. Let's hope it's in the drive...
	struct {
			uint8_t	tape_partition; // Partition number to back up to
			unsigned char disc_name[11]; // MDFS has max 10 character disc names
	} jobs[8]; // MDFS seems to limit to 8 partitions
	
};

struct __fs_tapeid_block {
	unsigned char	identifier[11]; // Gets set to "SJ Research"
	uint8_t		usage; // 0 = blank, 1 = used
	unsigned char	tapename[10]; // No null on end. Termiante with 0x0D if shorter than 10 characters.
	uint16_t	passes; // Number of tape passes
	unsigned char	description[80]; // Terminated with 0x0D
	uint8_t		fmt_dayyear, fmt_monthyear, fmt_hour, fmt_min; // looks like a 7-bit-bodge date/time when tape was formatted
	uint8_t		reserved[20]; // For what?
	struct {
			uint8_t	flag; // Bottom two bits 00=Blank, 01=OK, 10=Corrupt
			unsigned char	disc_name[10]; // Termianted 0x0D presumably if less than 10 characters
			uint8_t		bkp_dayyear, bkp_monthyear, bkp_hour, bkp_min;
			uint32_t	data_start_block;
			uint32_t	length; // In kilobytes
			unsigned char	error_info[8]; // Who knows what this might be.
			uint8_t		reserved[33]; // For what?
	} content[14]; // MDFS prescribes "Up to 14".
};

/*
 * fsop_data struct
 *
 * Information fed to a standard fsop() function
 */

struct fsop_data {
	uint8_t				net, stn;  	/* Client */
	struct __fs_active *		active;		/* Active user struct, or NULL */
	struct __fs_user *		user;		/* Pointer to PW file entry for this user, or NULL */
	uint16_t			userid;		/* Entry in PW file */
	struct __fs_station *		server;		/* fs_station struct for server */
	uint8_t *			data;		/* Data portion of packet received */
	uint16_t			datalen;	/* Amount of data payload in packet */
	uint8_t				ptype;		/* Packet type of incoming packet */
	uint8_t				port; 		/* Port number of incoming packet */
	uint8_t				ctrl;		/* Control byte received */
	uint32_t			seq;		/* Sequence number of incoming packet */
	uint8_t				urd, cwd, lib; 	/* Pre-decoded handles from packet */
	uint8_t				reply_port;	/* Pre-decoded reply-port from packet */
};

/*
 * Macros to use instead of various variables we use in 
 * FSOP functions
 *
 * The f variable is in the standard function decl for
 * FSOP() functions
 *
 */

#define FSOP_NET	f->net
#define FSOP_STN	f->stn
#define FSOP_REPLY_PORT	*(f->data)
#define FSOP_ACTIVE	(f->active)
#define FSOP_USER	f->userid
#define FSOP_UINFO(u)	(&(f->server->users[(u)]))
#define FSOP_FSOP	*(f->data+1)
#define FSOP_URD	*(f->data+2)
#define FSOP_CWD	*(f->data+3)
#define FSOP_LIB	*(f->data+4)
#define FSOP_ARG	*(f->data+5)
#define FSOP_CTRL	(f->ctrl)
#define FSOP_PORT	(f->port)
#define FSOP_SEQ	(f->seq)

/* 
 * fsop_list struct
 *
 * Holds list of known fsop functions
 *
 */

#define FSOP_F_LOGGEDIN 	0x01
#define FSOP_F_SYST	0x02
#define FSOP_F_32BIT	0x04
#define FSOP_F_MDFS	0x08 /* Only works if MDFS functions enabled */
#define FSOP_F_NONE	0x00

typedef void (*fsop_func) (struct fsop_data *);

struct fsop_list {
	uint8_t		flags; /* b0: Must be logged in; b1: Must be SYST; b2: call function with 32bit flag set */
	fsop_func	func; /* Function to all when traffic for this operation received */
}; /* Stored as an array whose index is the fsop number */

/* Macro to register handler function */

/* Note, n is a two-digit hex number */
#
#define FSOP_SET(h,f)      fsops[0x##h] = (struct fsop_list) { .flags = f, .func = fsop_##h }

/* 
 * Struct for passing parameters to an oscli_func
 */
/* FSOP Oscli parameters struct */

struct oscli_params {
        uint8_t         op_s; /* Start pointer in string */
        uint8_t         op_e; /* End pointer in string + 1 (i.e. the trailing space) */
};

/* FSOP Oscli command list for new structure */

typedef void (*oscli_func) (struct fsop_data *, struct oscli_params *, uint8_t, uint8_t);

struct fsop_00_cmd {
        unsigned char *         cmd;    /* Command in full. If there has to be a space in the command, then use 0x80 and it'll not be parsed as a space */
        uint8_t                 flags;  /* See below - bitwise OR */
        uint8_t                 p_min;  /* Minimum number of parameters */
        uint8_t                 p_max;  /* Maximum number of parameters */
        uint8_t                 abbrev; /* Minimum characters for abbreviation */
	oscli_func		func;   /* Handler for this command */
        struct fsop_00_cmd      *next;
};

/* FSOP Oscli macros */

#define FSOP_00(n) void fsop_00_##n(struct fsop_data *f, struct oscli_params *p, uint8_t num, uint8_t param_start)
#define FSOP_00_EXTERN(n) extern void fsop_00_##n(struct fsop_data *, struct oscli_params *, uint8_t, uint8_t)
#define FSOP_OSCLI(c,f,m,max,abbr) fsop_00_addcmd(fsop_00_mkcmd(#c,f,m,max,abbr,fsop_00_##c))

#define FSOP_00_ANON	0x00 /* Anyone can do this */
#define FSOP_00_LOGGEDIN 0x01 /* Only if user is logged in */
#define FSOP_00_SYSTEM	0x02 /* Only if user is syst */
#define FSOP_00_32BIT	0x04 /* Only if user is on a 32 bit client */
#define FSOP_00_BRIDGE 0x08 /* Only if user has bridge privileges */

/* Defines for switching discs */

#define FSOP_MOVE_DISC_URD 0x01
#define FSOP_MOVE_DISC_CWD 0x02
#define FSOP_MOVE_DISC_LIB 0x03
#define FSOP_MOVE_DISC_INVIS 0x60
#define FSOP_MOVE_DISC_NOTFOUND 0x10
#define FSOP_MOVE_DISC_NOTDIR 0x20
#define FSOP_MOVE_DISC_UNREADABLE 0x30
#define FSOP_MOVE_DISC_UNMAPPABLE 0x40
#define FSOP_MOVE_DISC_CHANNEL 0x50
#define FSOP_MOVE_DISC_SUCCESS 0x00

/* Some externs for functions within fsop_00_oscli.c which manage the command list */

extern struct fsop_00_cmd * fsop_00_match (unsigned char *, uint8_t *); /* Tells us whether a command exists in the list, so we use new structure not old. Feed the OSCLI command (abbreviated) in here and you'll get a pointer to the struct or NULL if not found, uint8_t * is index of character AFTER command end (either the end of the word, or the '.' for an abbreviation) */
extern void fsop_00_addcmd (struct fsop_00_cmd *); /* Add the malloced command with its parameters to the list. */
extern struct fsop_00_cmd * fsop_00_mkcmd(unsigned char *, uint8_t, uint8_t, uint8_t, uint8_t, oscli_func);
extern uint8_t fsop_00_oscli_parse(unsigned char *, struct oscli_params *, uint8_t);
extern void fsop_00_oscli_extract(unsigned char *, struct oscli_params *, uint8_t, char *, uint8_t, uint8_t);
#define FSOP_EXTRACT(f,n,v,l)	fsop_00_oscli_extract(f->data,p,n,v,l,param_start)


/* FSOP Definition macro */
#define FSOP(n) void fsop_##n(struct fsop_data *f)
#define FSOP_EXTERN(n)	extern void fsop_##n(struct fsop_data *)

/* Some bog standard reply packet stuff */

#define FS_REPLY_DATA(c)	struct __econet_packet_udp reply = { .p.port = FSOP_REPLY_PORT, .p.ctrl = c, .p.ptype = ECONET_AUN_DATA, .p.data[0] = 0, .p.data[1] = 0 };

#define FS_REPLY_COUNTER()	uint16_t	__rcoutner = 0;

/* We have a second version because sometimes we used 'r' in the main code so it's easier not to change it! */
#define FS_R_DATA(c)	struct __econet_packet_udp r = { .p.port = FSOP_REPLY_PORT, .p.ctrl = c, .p.ptype = ECONET_AUN_DATA, .p.data[0] = 0, .p.data[1] = 0 };

/*
 * FSOP Function externs
 */

/* Some externs for transmission from fs.c */

extern void fsop_reply_ok_with_data(struct fsop_data *, uint8_t *, uint16_t);
extern void fsop_reply_ok(struct fsop_data *);
extern void fsop_error(struct fsop_data *, uint8_t, char *);
extern void fsop_error_ctrl(struct fsop_data *, uint8_t, uint8_t, char *);
extern void fs_debug (uint8_t, uint8_t, char *, ...);
extern void fs_debug_full (uint8_t, uint8_t, struct __fs_station *, uint8_t, uint8_t, char *, ...);

/* Externs for internal file handling from fs.c */
extern struct __fs_file * fsop_open_interlock(struct fsop_data *, unsigned char *, uint8_t, int8_t *, uint8_t);
//extern struct __fs_dir * fsop_get_dir_handle(struct fsop_data *, unsigned char *);
extern void fsop_close_interlock(struct __fs_station *, struct __fs_file *, uint8_t);
//extern void fsop_close_dir_handle(struct __fs_station *, struct __fs_dir *);
extern uint8_t fsop_allocate_user_file_channel(struct __fs_active *);
extern void fsop_deallocate_user_file_channel(struct __fs_active *, uint8_t);
extern uint8_t fsop_allocate_user_dir_channel(struct __fs_active *, struct __fs_file *);
extern void fsop_deallocate_user_dir_channel(struct __fs_active *, uint8_t);
extern uint8_t fsop_find_bulk_port(struct __fs_station *);
extern void fs_acorn_to_unix(char *, uint8_t);
extern void fs_unix_to_acorn(char *);
extern uint8_t fsop_perm_from_acorn(struct __fs_station *, uint8_t);
extern uint8_t fsop_perm_to_acorn(struct __fs_station *, uint8_t, uint8_t);
extern int16_t fsop_get_acorn_entries(struct fsop_data *, unsigned char *);
extern unsigned char *pathname_to_dotfile(unsigned char *, uint8_t);

/* Externs for load/getbytes dequeuer system in fs.c */

extern struct load_queue * fsop_load_enqueue(struct fsop_data *, struct __econet_packet_udp *, uint16_t, struct __fs_file *, uint8_t, uint32_t, uint8_t, uint16_t, uint8_t, uint8_t);

/* And some defines for use with fsop_load_enqueu */

#define FS_ENQUEUE_LOAD 1
#define FS_ENQUEUE_GETBYTES 2

/* Externs to deal with users from fs.c */
extern int fsop_find_userid(struct fsop_data *, uint8_t, uint8_t);
extern uint8_t fs_isdir(char *);
extern void fs_read_xattr(unsigned char *, struct objattr *, struct fsop_data *);
extern void fs_write_xattr(unsigned char *, uint16_t, uint16_t, uint32_t, uint32_t, uint16_t, struct fsop_data *);
extern uint8_t fsop_exists(struct fsop_data *, unsigned char *);
extern void fsop_write_user(struct __fs_station *, int, unsigned char *);
extern struct __fs_active * fsop_stn_logged_in(struct __fs_station *, uint8_t, uint8_t);
extern struct __fs_active * fsop_stn_logged_in_lock(struct __fs_station *, uint8_t, uint8_t);
extern int fsop_get_discno(struct fsop_data *, char *);
extern void fsop_get_disc_name(struct __fs_station *, uint8_t, unsigned char *);
extern void fsop_set_disc_name(struct __fs_station *, uint8_t, unsigned char *);
extern void fsop_get_username_lock(struct __fs_active *, char *);
extern uint8_t fsop_writedisclist(struct __fs_station *, unsigned char *);
extern void fsop_dump_handle_list(FILE *, struct __fs_station *);

/* Externals for string manipulation from fs.c */
extern void fs_copy_to_cr(unsigned char *, unsigned char *, unsigned short);
extern uint16_t fs_copy_terminate(unsigned char *, unsigned char *, uint16_t, uint8_t);
int16_t fsop_get_uid(struct __fs_station *, char *);
extern void fs_toupper(char *);
extern void fs_copy_padded(unsigned char *, unsigned char *, uint16_t);

/* Externs for printer stuff */

int8_t fsop_get_user_printer(struct __fs_active *);

/* Externs from fs.c for machine peek types */
unsigned char * fsop_machine_type_str (uint16_t);

/* Externs from fsop_00_oscli.c */

extern void fsop_lsb_reply (char *, uint8_t, uint32_t);

/* Externs for fileserver control from fs.c */

extern uint8_t fs_get_maxdiscs();
extern void fsop_shutdown(struct __fs_station *);
extern int fs_normalize_path(int, int, unsigned char *, short, struct path *);
extern int fs_normalize_path_wildcard(int, int, unsigned char *, short, struct path *, unsigned short);
extern int fsop_normalize_path(struct fsop_data *, unsigned char *, short, struct path *);
extern int fsop_normalize_path_wildcard(struct fsop_data *, unsigned char *, short, struct path *, unsigned short);
extern void fs_free_wildcard_list(struct path *);
extern void fs_get_parameters (uint8_t, uint32_t *, uint8_t *);
extern void fsop_get_parameters (struct __fs_station *, uint32_t *, uint8_t *);
extern void fsop_set_parameters (struct __fs_station *, uint32_t, uint8_t);
extern uint8_t fsop_clear_syst_pw (struct __fs_station *);
extern uint8_t fsop_write_server_config(struct __fs_station *);
extern void fsop_write_readable_config(struct __fs_station *);
extern void fs_store_tail_path(char *, char *);
extern void fsop_read_xattr(unsigned char *, struct objattr *, struct fsop_data *);
extern void fsop_write_xattr(unsigned char *, uint16_t, uint16_t, uint32_t, uint32_t, uint16_t, struct fsop_data *);
extern void fsop_get_create_time(unsigned char *, uint8_t *, uint8_t *, uint8_t *, uint8_t *, uint8_t *);
extern void fsop_set_create_time(unsigned char *, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);
extern void fsop_set_create_time_now(unsigned char *);

/* Some date functions from fs.c */
uint8_t fs_year_from_two_bytes(uint8_t, uint8_t);
uint8_t fs_month_from_two_bytes(uint8_t, uint8_t);
uint8_t fs_day_from_two_bytes(uint8_t, uint8_t);

/* Externs for cross-fertilised functions */

extern void fsop_bye_internal(struct __fs_active *, uint8_t, uint8_t);

/* Externs for tx */
extern int fsop_aun_send(struct __econet_packet_udp *, int, struct fsop_data *);
extern int fsop_aun_send_noseq(struct __econet_packet_udp *, int, struct fsop_data *);
extern int raw_fsop_aun_send(struct __econet_packet_udp *, int, struct __fs_station *, uint8_t, uint8_t);
extern int raw_fsop_aun_send_noseq(struct __econet_packet_udp *, int, struct __fs_station *, uint8_t, uint8_t);
extern void fsop_error_ctrl(struct fsop_data *, uint8_t, uint8_t, char *);
extern void fsop_error(struct fsop_data *, uint8_t, char *);
extern void fsop_reply_ok(struct fsop_data *);
extern void fsop_reply_success(struct fsop_data *, uint8_t, uint8_t);
extern void fsop_reply_ok_with_data(struct fsop_data *, uint8_t *, uint16_t);
extern void * fsop_register_machine (struct __fs_machine_peek_reg *);

/* Externs for the HPB */
void fsop_setup(void);
uint8_t fsop_is_enabled (struct __fs_station *);
struct __fs_station *fsop_initialize(struct __eb_device *, char *);
int8_t fsop_run(struct __fs_station *);

/* Port allocator in the HPB */

uint8_t	eb_port_allocate(struct __eb_device *, uint8_t, port_func, void *);
void	eb_port_deallocate(struct __eb_device *, uint8_t);

/* Macro to enable easy tx of a standard FS_REPLY_DATA block */
#define fsop_send(n)	fsop_aun_send(&reply, (n), f)

/* Externs for time / date */
extern void fs_date_to_two_bytes(unsigned short, unsigned short, unsigned short, unsigned char *, unsigned char *);

/* Some externs from econet-hpbridge.c */

extern uint32_t eb_get_local_seq(struct __eb_device *);

// routine in econet-bridge.c to find a printer definition
extern int8_t get_printer(unsigned char, unsigned char, char*);

// printer information routines in econet-bridge.c
extern uint8_t get_printer_info (unsigned char, unsigned char, uint8_t, char *, char *, uint8_t *, uint8_t *, short *);
extern uint8_t set_printer_info (unsigned char, unsigned char, uint8_t, char *, char *, uint8_t, ushort);
extern uint8_t get_printer_total (unsigned char, unsigned char);
extern void send_printjob (char *, uint8_t, uint8_t, uint8_t, uint8_t, char *, char *, char *, char *);
extern char * get_user_print_handler (uint8_t, uint8_t, uint8_t, char *, char *);

// memory allocation in the bridge

extern void * eb_malloc(char *, int, char *, char *, size_t);
extern void eb_free (char *, int, char *, char *, void *);

// Server timing
extern float timediffstart(void);

/* Some defines for regular expressions and handle manipulation */

// the ] as second character is a special location for that character - it loses its
// special meaning as 'end of character class' so you can match on it.
#define FSACORNREGEX    "[]\\(\\)\\'\\*\\#A-Za-z0-9\\+_\x81-\xfe;[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FSREGEX    "[]\\(\\)\\'\\*\\#A-Za-z0-9\\+_\x81-\xfe;:[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FSDOTREGEX "[]\\(\\)\\'\\*\\#A-Za-z0-9\\+_\x81-\xfe;\\.[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
/* 20250315 Next line added to support wildcard disc names */
#define FSDISCREGEX    "[]\\(\\)\\'A-Za-z0-9\\+_\x81-\xfe;[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FS_NETCONF_REGEX_ONE "^NETCONF(IG)?\\s+([\\+\\-][A-Z]+)\\s*"

#define FS_DIVHANDLE(a,x) ((a->manyhandles == 0) ? (  (  ((x) == 128) ? 8 : ((x) == 64) ? 7 : ((x) == 32) ? 6 : ((x) == 16) ? 5 : ((x) == 8) ? 4 : ((x) == 4) ? 3 : ((x) == 2) ? 2 : ((x) == 1) ? 1 : (x))) : (x))
#define FS_MULHANDLE(a,x) ((a->manyhandles != 0) ? (x) : (1 << ((x) - 1)))

/* Some linked list manipulation macros */

/* Create new struct of type t, put it on l, put it on the head (1) or tail (0) of the queue of such structs at l, and put the pointer (or null) in p,
 * use module & descr as parameters to eb_malloc()
 */

#define FS_LIST_MAKENEW(t,l,head,p,module,descr) \
{ \
	fs_debug(0, 4, "Allocate %d for %s on list at %s in %s for %s", sizeof(t), #p, #l, module, descr);\
	p = eb_malloc(__FILE__, __LINE__, module, descr, sizeof(t)); \
	memset (p, 0, sizeof(t)); \
	if (head) \
	{ \
		p->next = l; \
		if (p->next) p->next->prev = p; \
		p->prev = NULL; \
		l = p; \
		fs_debug(0,4,"List head is %p, allocated at %p, next = %p, prev = %p", l, p, p->next, p->prev); \
	} \
	else \
	{ \
		if (!(l)) \
		{ \
			l = p; \
			p->next = NULL; \
			p->prev = NULL; \
		} \
		else \
		{ \
			t	*tmp; \
			tmp = l; \
			while (tmp->next) tmp=tmp->next;\
			p->prev = tmp; \
			tmp->next = p;\
			p->next = NULL; \
		} \
		fs_debug(0,4,"List head is %p, allocated at %p, next = %p, prev = %p", l, p, p->next, p->prev); \
	} \
}

#define FS_LIST_SPLICEFREE(l,p,module,descr) \
{ \
	fs_debug (0, 4, "Free %p on list at %p - %s %s", p, l, module, descr); \
	if (p->prev) \
		p->prev->next = p->next; \
	else \
		l = p->next; \
	\
	if (p->next) \
		p->next->prev = p->prev; \
	\
	fs_debug(0,4,"List head is %p, freeing %p, next = %p, prev = %p", l, p, p->next, p->prev); 	\
	\
	eb_free (__FILE__, __LINE__, module, descr, p); \
}

// Utility macros to write into reply data

#define FS_PUT8(r,l,v) r[(l)] = (v) & 0xff

#define FS_PUT16(r,l,v)\
	r[(l) + 1] = ((v) & 0xff00) >> 8;\
	FS_PUT8((r),(l),(v))

#define FS_PUT24(r,l,v)\
	r[(l) + 2] = ((v) & 0xff0000) >> 16;\
	FS_PUT16((r),(l),(v))

#define FS_PUT32(r,l,v)\
	r[(l) + 3] = ((v) & 0xff000000) >> 24;\
	FS_PUT24((r),(l),(v))

// Equivalents to use __rcounter and increment it.

#define FS_CPUT8(v) reply.p.data[__rcounter++] = (v)

#define FS_CPUT16(v) \
	FS_CPUT8((v));\
	FS_CPUTB((((v) & 0xff00) >> 8))

#define FS_CPUT24(v)i \
	FS_CPUT16((v));\
	FS_CPUTB((((v) & 0xff0000) >> 16))

#define FS_CPUT32(r,l,v) `\
	FS_CPUT24((v));\
	FS_CPUTB((((v) & 0xff000000) >> 24))

/* List of externs for FSOP functions */

FSOP_EXTERN(00);
FSOP_EXTERN(01);
FSOP_EXTERN(02);
FSOP_EXTERN(03);
FSOP_EXTERN(04);
FSOP_EXTERN(05);
FSOP_EXTERN(06);
FSOP_EXTERN(07);
FSOP_EXTERN(08);
FSOP_EXTERN(09);
FSOP_EXTERN(0a);
FSOP_EXTERN(0b);
FSOP_EXTERN(0c);
FSOP_EXTERN(0d);
FSOP_EXTERN(0e);
FSOP_EXTERN(0f);
FSOP_EXTERN(10);
FSOP_EXTERN(11);
FSOP_EXTERN(12);
FSOP_EXTERN(13);
FSOP_EXTERN(14);
FSOP_EXTERN(15);
FSOP_EXTERN(16);
FSOP_EXTERN(17);
FSOP_EXTERN(18);
FSOP_EXTERN(19);
FSOP_EXTERN(1a);
FSOP_EXTERN(1b);
FSOP_EXTERN(1c);
FSOP_EXTERN(1d);
FSOP_EXTERN(1e);
FSOP_EXTERN(1f);
FSOP_EXTERN(20);
FSOP_EXTERN(26);
FSOP_EXTERN(27);
FSOP_EXTERN(28);
FSOP_EXTERN(29);
FSOP_EXTERN(2a);
FSOP_EXTERN(2b);
FSOP_EXTERN(2c);
FSOP_EXTERN(2e);
FSOP_EXTERN(40);
FSOP_EXTERN(41);
FSOP_EXTERN(42);
FSOP_EXTERN(43);
FSOP_EXTERN(60);

/* List of OSCLI externs */

/* The catalogue function */
extern void fsop_00_catalogue (struct fsop_data *, struct oscli_params *, uint8_t, uint8_t);

FSOP_00_EXTERN(ACCESS);
FSOP_00_EXTERN(BRIDGEVER);
FSOP_00_EXTERN(BRIDGEUSER);
FSOP_00_EXTERN(BYE);
FSOP_00_EXTERN(CHOWN);
FSOP_00_EXTERN(COPY);
FSOP_00_EXTERN(DELETE);
FSOP_00_EXTERN(DIR);
FSOP_00_EXTERN(DISCMASK);
FSOP_00_EXTERN(DISKMASK);
FSOP_00_EXTERN(FSCONFIG);
FSOP_00_EXTERN(INFO);
FSOP_00_EXTERN(LIB);
FSOP_00_EXTERN(LINK);
FSOP_00_EXTERN(LOAD);
FSOP_00_EXTERN(LOGIN);
FSOP_00_EXTERN(LOGOFF);
FSOP_00_EXTERN(MKLINK);
FSOP_00_EXTERN(NEWUSER);
FSOP_00_EXTERN(OWNER);
FSOP_00_EXTERN(PASS);
FSOP_00_EXTERN(PRINTER);
FSOP_00_EXTERN(PRINTOUT);
FSOP_00_EXTERN(PRIV);
FSOP_00_EXTERN(RENAME);
FSOP_00_EXTERN(REMUSER);
FSOP_00_EXTERN(RENUSER);
FSOP_00_EXTERN(SAVE);
FSOP_00_EXTERN(SDISC);
FSOP_00_EXTERN(SETHOME);
FSOP_00_EXTERN(SETLIB);
FSOP_00_EXTERN(SETOPT);
FSOP_00_EXTERN(SETOWNER);
FSOP_00_EXTERN(SETPASS);
FSOP_00_EXTERN(UNLINK);

extern short fs_sevenbitbodge;
extern short normalize_debug;
extern uint8_t fs_set_syst_bridgepriv;

