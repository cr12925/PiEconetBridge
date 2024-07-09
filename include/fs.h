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

#include "../include/econet-gpio-consumer.h"
#include "../include/econet-hpbridge.h"

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

#define ECONET_MAX_FILENAME_LENGTH (fs_config[server].fs_fnamelen)
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

/* Reported version string */
#define FS_VERSION_STRING "3 Pi Econet HP Bridge FS 2.20"

/* Various important struct definitions */

/* __fs_station - instance information about a fileserver instance */

struct __fs_station {
        unsigned char net; // Network number of this server
        unsigned char stn; // Station number of this server
        unsigned char directory[256]; // Root directory
        unsigned int total_users; // How many entries in users[][]?
        int total_discs;
	struct __fs_config	*config; // Pointer to my config
	struct __fs_disc	*discs; // Pointer to discs
	struct __fs_file	*files; // Pointer to open files
	struct __fs_dir		*dirs; // Pointer to open dirs
	struct __fs_active	*actives; // Pointer to actives
	struct __fs_user	*users; // Pointer to (effectively) the password data
	uint8_t		*enabled; // Pointer to entry in fs_enabled
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
	unsigned char name[17];
};

/* __fs_file - open file information for a particular server */

struct __fs_file {
        unsigned char name[1024];
        FILE *handle;
        int readers, writers; // Used for locking; when readers = writers = 0 we close the file
};

/* __fs_dir - open directory information for a particular server */

struct __fs_dir {
        unsigned char name[1024];
        DIR *handle;
        int readers; // When 0, we close the handle

};

/* __fs_bulk_port - fileserver bulk (data burst) port list */

struct __fs_bulk_port {
        unsigned char net, stn;
        short handle; // -1 if available
        unsigned char ack_port;
        unsigned char reply_port;
        unsigned char rx_ctrl;
        unsigned long length;
        unsigned long received;
        unsigned short mode; // as in 1 read, 2 updated, 3 write & truncate (I think!)
        unsigned short active_id; // 0 = no user handle because we are doing a fs_save
        unsigned short user_handle; // index into active[server][active_id].fhandles[] so that cursor can be updated
        unsigned long long last_receive; // Time of last receipt so that we can garbage collect
        unsigned char acornname[ECONET_ABS_MAX_FILENAME_LENGTH+2]; // Tail path segment - enables *SAVE to return it on final close // Was 12
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
        void *next, *parent;
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
#define FS_PERM_ISOWNER(s,a,o)  ((FS_ACTIVE_UID((s),(a)) == (o)) ? 1 : 0)
// Effective owner - i.e. actual owner or system priv
#define FS_PERM_EFFOWNER(s,a,o) (FS_ACTIVE_SYST((s),(a)) || FS_PERM_ISOWNER((s),(a),(o)) ? 1 : 0)

// Object visible to this user - as distinct from readable - this is testing the hidden bit
#define FS_PERM_VISIBLE(s,a,p,o)        (!FS_PERM_SET((p), FS_PERM_H) || FS_PERM_EFFOWNER((s),(a),(o)))

// Can create new file if it doesn't exist already
#define FS_PERM_CREATE(s,a,p,o,pp,po)   ((FS_PERM_EFFOWNER((s),(a),(po)) && (!FS_CONFIG_PIFSPERMS((s)) || FS_PERM_SET((pp), FS_PERM_OWN_W))) || (FS_CONFIG_PIFSPERMS((s)) && FS_PERM_SET((pp), FS_PERM_OTH_W) && FS_PERM_SET((pp), FS_PERM_OWN_W)))

// Can SAVE - only if unlocked and we effectively own it. Non-owners cannot save unless PiFS perms enabled.
// Even then, only if both owner & other W are set, which is similar to what happens when non-owner read is
// requested in L4, which requires both OTH_R and OWN_R set.
#define FS_PERM_SAVE(s,a,p,o,pp,po) ((FS_PERM_UNSET((p), FS_PERM_L) && (\
                (FS_PERM_EFFOWNER((s),(a),(o))) ||\
                (FS_CONF_PIFSPERMS((s)) && FS_PERM_SET((p), FS_PERM_OWN_W) && FS_PERM_SET((p), FS_PERM_OTH_W)) \
                ))
// Can LOAD - note that L4 enforces both R/ and /r for a non-owner to read, so R/ is required whether owner or not
#define FS_PERM_LOAD(s,a,p,o,pp,po) (\
                (!FS_CONFIG_PIFSPERMS((s)) || (FS_PERM_SET_((pp), FS_PERM_OWN_R) && (FS_PERM_EFFOWNER((s), (a), (po)) || FS_PERM_SET((pp), FS_PERM_OTH_R)))) && \
                (FS_PERM_SET((p), FS_PERM_OWN_R) && (FS_PERM_EFFOWNER((s),(a),(o)) || FS_PERM_SET((p), FS_PERM_OTH_R))) \
                )

// Can RENAME - Owner always can unless locked, non-owner never can - except if PIFS PERMS enabled, in which case they can if they have write access to the parent
#define FS_PERM_RENAME(s,a,p,o,pp,po) (\
                FS_PERM_UNSET((p), FS_PERM_L) && \
                ( \
                        ( \
                         FS_CONFIG_PIFSPERMS((s)) && \
                                (FS_PERM_SET((pp), FS_PERM_OWN_W) && (FS_PERM_EFFOWNER((s),(a),(po)) || FS_PERM_SET((pp), FS_PERM_OTH_W))) \
                        ) \
                        || \
                        (!FS_CONFIG_PIFSPERMS((s) && FS_PERM_EFFOWNER((s),(a),(o)))) \
                ))

// Can OPENIN
#define FS_PERM_OPENIN  FS_PERM_LOAD

// Can OPENOUT - Level 4 forbids this on WL/ but allows it on +R or +W (wither +L or -L!) - looks like this is (+L && +R) || (+W || +R). In Acorn world, OPENOUT *always* fails for non-owner. In PIFS world, it will succeed if +W/w
#define FS_PERM_OPENOUT(s,a,p,o,pp,po) \
        ( \
          (FS_PERM_EFFOWNER((s),(a),(o)) && ( (FS_PERM_SET((p), FS_PERM_L) && FS_PERM_SET((p), FS_PERM_OWN_R)) || (FS_PERM_SET((p), FS_PERM_OWN_R) || FS_PERM_SET((p), FS_PERM_OWN_W)) ) ) \
          || \
          (FS_CONFIG_PIFSPERMS((s)) && FS_PERM_SET((p), FS_PERM_OWN_W) && FS_PERM_SET((p), FS_PERM_OTH_W)) \
        )

// Can OPENUP - Level 4 does same as OPENOUT
#define FS_PERM_OPENUP FS_PERM_OPENOUT

// Can BPUT/S - Owner: requires +R,+W,-L. Other requires +W/+W and -L
#define FS_PERM_WRITE(s,a,p,o,pp,po) \
        ( FS_PERM_UNSET((p), FS_PERM_L) && \
          (FS_PERM_EFFOWNER((s),(a),(o)) ? \
           (FS_PERM_SET((p), FS_PERM_OWN_R) && FS_PERM_SET((p), FS_PERM_OWN_W)) \
         : (FS_PERM_SET((p), FS_PERM_OWN_W) && FS_PERM_SET((p), FS_PERM OTH(W))) \
         ) \
         )

/* FS Configuration and dir mask defines */

#define FS_CONF_PIFSPERMS(s)    (fs_config[(s)].fs_pifsperms == 0x80 ? 0 : 1)
#define FS_CONF_DEFAULT_DIR_PERM(s)     (fs_config[(s)].fs_default_dir_perm)
#define FS_CONF_DEFAULT_FILE_PERM(s)    (fs_config[(s)].fs_default_file_perm)
#define FS_ACORN_DIR_MASK       (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R)

/* Macros to find user information */

#define FS_DISC_VIS(s,u,d) ((d >= 16) || (users[(s)][(u)].home_disc == (d)) || !(users[(s)][(u)].discmask & (1 << (d))))

// Macro to provide a shortcut to getting a user's real ID when the caller only knows the index into active[]
#define FS_ACTIVE_UID(s,a) (active[(s)][(a)].userid)
// Macro to identify if we have system privileges
#define FS_ACTIVE_SYST(s,a) (users[(s)][FS_ACTIVE_UID((s),(a))].priv & FS_PRIV_SYSTEM)
// Macro to identify if we have bridge privileges
#define FS_ACTIVE_BRIDGE(s,a) (users[(s)][FS_ACTIVE_UID((s),(a))].priv2 & FS_PRIV2_BRIDGE)

/* And some FSOP_ wrappers */
#define FSOP_PERM_ISOWNER(f,o)	((f)->user_id == (o) ? 1 : 0)
#define FSOP_PERM_EFFOWNER(f,o)	(FSOP_ACTIVE_SYST(f) || FSOP_PERM_ISOWNER((f),(o) ? 1 : 0)
#define FSOP_PERM_VISIBLE(f,p,o)	(!FS_PERM_SET((p), FS_PERM_H) || FSOP_PERM_EFFOWNER((f),(o))
#define FSOP_PERM_CREATE(f,p,o,pp,po)	FS_PERM_CREATE((f)->server_id, (f)->active_id,(p),(o),(pp),(po))
#define FSOP_PERM_SAVE(f,...)		FS_PERM_SAVE((f)->server_id, (f)->active_id,...)
#define FSOP_PERM_LOAD(f,...)		FS_PERM_LOAD((f)->server_id, (f)->active_id,...)
#define FSOP_PERM_RENAME(f,...)		FS_PERM_RENAME((f)->server_id, (f)->active_id,...)
#define FSOP_PERM_OPENIN		FSOP_PERM_LOAD
#define FSOP_PERM_OPENUP		FSOP_PERM_OPENOUT
#define FSOP_PERM_OPENOUT(f,...)	FS_PERM_OPENOUT((f)->server_id, (f)->active_id,...)
#define FSOP_PERM_WRITE(f,...)		FS_PERM_WRITE((f)->server_id, (f)->active_id,...)
#define FSOP_CONF_PIFSPERMS(f)		((f)->server->fs_config->fs_pifsperms == 0x80 ? 0 : 1)
#define FSOP_CONF_DEFAULT_DIR_PERM(f)	((f)->server->fs_config->fs.default_dir_perm)
#define FSOP_CONF_DEFAULT_FILE_PERM(f)	((f)->server->fs_config->fs_default_file_perm)
#define FSOP_SYST			((f)->user->priv & FS_PRIV_SYSTEM)
#define FSOP_BRIDGE			((f)->user->priv2 & FS_PRIV2_BRIDGE)

/*
 * Bulk transfer structures
 *
 * For *LOAD / *RUN / fs_getbytes()
 */

// When fs_load_queue is not null (see below), the main loop in the bridge will call fs_execute_load_queue to dump one packet off the head of each queue to the destination station
struct __pq {
        struct __econet_packet_udp *packet; // Don't bother with internal 4 byte src/dest header - they are given as parameters to aun_send.
        int len; // Packet data length
        uint16_t delay; // in milliseconds - to cope with RISC OS not listening...
        struct __pq *next;
};

struct load_queue {
        unsigned char net, stn; // Destination net, stn
        unsigned int server; // Determines source address
        unsigned queue_type; // For later use with getbytes() - but for now assume always a load
        unsigned char internal_handle; // Internal file handle to be closed at end / abort
        unsigned char mode; // Internal mode
        uint32_t        ack_seq_trigger; // Sequence number for which we receive an ack which will trigger next transmission
        time_t          last_ack_rx; // Last time we received an ACK from this station - used for garbage collection
        struct load_queue *next;
        struct __pq *pq_head, *pq_tail;

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
        uint8_t         unused1[16];
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

/* __fs_active - cache information about a logged in user */

struct __fs_active {
        unsigned char net, stn;
        unsigned int userid; // Index into users[n][]
        unsigned char root, current, lib; // Handles
        char root_dir[1024], current_dir[1024], lib_dir[1024]; // Paths relative to root
        char root_dir_tail[ECONET_ABS_MAX_FILENAME_LENGTH+1], lib_dir_tail[ECONET_ABS_MAX_FILENAME_LENGTH+1], current_dir_tail[ECONET_ABS_MAX_FILENAME_LENGTH+1]; // Just the last element of path, or $ // these were 15
        unsigned int home_disc, current_disc, lib_disc; // Currently selected disc for each of the three handles
        unsigned char bootopt;
        unsigned char priv;
        uint8_t printer; // Index into this station's printer array which shows which printer has been selected - defaults to &ff to signal 'none'.
        struct {
                short handle; // Pointer into fs_files
                unsigned long cursor; // Our pointer into the file
                unsigned long cursor_old; // Previous cursor in case we get a repeated request, we can go back
                unsigned short mode; // 1 = read, 2 = openup, 3 = openout
                unsigned char sequence; // Oscillates 0-1-0-1... This variable stores the LAST b0 of ctrl byte received, so when we get new traffic it should be *different* to what's in here.
                unsigned short pasteof; // Signals when there has already been one attempt to read past EOF and if there's another we need to generate an error
                unsigned short is_dir; // Looks like Acorn systems can OPENIN() a directory so there has to be a single set of handles between dirs & files. So if this is non-zero, the handle element is a pointer into fs_dirs, not fs_files.
                char acornfullpath[1024]; // Full Acorn path, used for calculating relative paths
                char acorntailpath[ECONET_ABS_MAX_FILENAME_LENGTH+1];
        } fhandles[FS_MAX_OPEN_FILES];
        unsigned char sequence; // Used to detect duplicate transmissions on putbyte - oscillates 0-1-0-1 - low bit of ctrl byte in packet. Gets re-set whenever there is an operation which is not a putbyte, so that successive putbytes get the tracker, but anything else in the way resets it
        unsigned char urd_unix_path[1024]; // Used for chroot purposes - stored at login / sdisc
};
/*
 * fsop_data struct
 *
 * Information fed to a standard fsop() function
 */

struct fsop_data {
	uint8_t				net, stn;  	/* Client */
	struct __fs_active *		active;		/* Active user struct, or NULL */
	uint8_t				active_id;	/* Pre-thread ID within the active[server][] array */
	struct __fs_user *		user;		/* Pointer to PW file entry for this user, or NULL */
	uint8_t				user_id;	/* Entry in PW file */
	struct __fs_station *		server;		/* fs_station struct for server */
	uint8_t				server_id;	/* Pre-thread ID within the fs_station[] array */
	uint8_t *			data;		/* Data portion of packet received */
	uint16_t			datalen;	/* Amount of data payload in packet */
	uint8_t				ctrl;		/* Control byte received */
	uint8_t				flags;		/* b0: 32bit variant, b1: run not load (for relevant FSOP) */
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
#define FSOP_ACTIVE	f->active_id
#define FSOP_USER	f->user_id
#define FSOP_UINFO(u)	(&users[f->server_id][(u)])
#define FSOP_SERVER	f->server_id
#define FSOP_FSOP	*(f->data+1)
#define FSOP_URD	*(f->data+2)
#define FSOP_CWD	*(f->data+3)
#define FSOP_LIB	*(f->data+4)
#define FSOP_ARG	*(f->data+5)

/* Some externs for the arrays of data */

extern struct __fs_active active[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_ACTIVE];
extern struct __fs_config fs_config[ECONET_MAX_FS_SERVERS];
extern struct __fs_user users[ECONET_MAX_FS_SERVERS+1][ECONET_MAX_FS_USERS];
extern struct __fs_group groups[ECONET_MAX_FS_SERVERS][256];
extern struct __fs_station fs_stations[ECONET_MAX_FS_SERVERS];
extern struct __fs_disc fs_discs[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_DISCS];
extern struct __fs_file fs_files[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_FILES];
extern struct __fs_dir fs_dirs[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_FILES];
extern struct __fs_bulk_port fs_bulk_ports[ECONET_MAX_FS_SERVERS][256];
extern struct load_queue *fs_load_queue;

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

/* Some externs for functions within fsop_00_oscli.c which manage the command list */

extern struct fsop_00_cmd * fsop_00_match (unsigned char *, uint8_t *); /* Tells us whether a command exists in the list, so we use new structure not old. Feed the OSCLI command (abbreviated) in here and you'll get a pointer to the struct or NULL if not found, uint8_t * is index of character AFTER command end (either the end of the word, or the '.' for an abbreviation) */
extern void fsop_00_addcmd (struct fsop_00_cmd *); /* Add the malloced command with its parameters to the list. */
extern struct fsop_00_cmd * fsop_00_mkcmd(unsigned char *, uint8_t, uint8_t, uint8_t, uint8_t, oscli_func);
extern uint8_t fsop_00_oscli_parse(unsigned char *, struct oscli_params *, uint8_t);
extern void fsop_00_oscli_extract(unsigned char *, struct oscli_params *, uint8_t, char *, uint8_t, uint8_t);


/* FSOP Definition macro */
#define FSOP(n) void fsop_##n(struct fsop_data *f)
#define FSOP_EXTERN(n)	extern void fsop_##n(struct fsop_data *)

/* Some bog standard reply packet stuff */

#define FS_REPLY_DATA(c)	struct __econet_packet_udp reply = { .p.port = FSOP_REPLY_PORT, .p.ctrl = c, .p.ptype = ECONET_AUN_DATA, .p.data[0] = 0, .p.data[1] = 0 }

/*
 * FSOP Function externs
 */

/* Some externs for transmission from fs.c */

extern void fsop_reply_ok_with_data(struct fsop_data *, uint8_t *, uint16_t);
extern void fsop_reply_ok(struct fsop_data *);
extern void fsop_error(struct fsop_data *, uint8_t, char *);
extern void fsop_error_ctrl(struct fsop_data *, uint8_t, uint8_t, char *);
extern void fs_debug (uint8_t, uint8_t, char *, ...);

#define fsop_debug fsdebug

/* Externals for string manipulation from fs.c */
extern void fs_copy_to_cr(unsigned char *, unsigned char *, unsigned short);
extern uint16_t fs_copy_terminate(unsigned char *, unsigned char *, uint16_t, uint8_t);
extern short fs_get_uid(int, char *);

/* Externs from fsop_00_oscli.c */

extern void fsop_lsb_reply (char *, uint8_t, uint32_t);

/* Externs for fileserver control from fs.c */

extern void fsop_shutdown(struct fsop_data *);
extern int fs_normalize_path(int, int, unsigned char *, short, struct path *);
extern int fs_normalize_path_wildcard(int, int, unsigned char *, short, struct path *, unsigned short);
extern int fsop_normalize_path(struct fsop_data *, unsigned char *, short, struct path *);
extern int fsop_normalize_path_wildcard(struct fsop_data *, unsigned char *, short, struct path *, unsigned short);
extern void fs_get_parameters (uint8_t, uint32_t *, uint8_t *);
extern void fsop_get_parameters (struct fsop_data *, uint32_t *, uint8_t *);
extern void fsop_set_parameters (struct fsop_data *, uint32_t, uint8_t);
extern void fsop_write_readable_config(struct fsop_data *f);

/* Externs for cross-fertilised functions */

extern void fsop_bye_internal(struct fsop_data *, unsigned short);

/* Externs for interlock open and close from fs.c */

extern short fs_open_interlock(int, unsigned char *, unsigned short, unsigned short);
extern void fs_close_interlock(int, unsigned short, unsigned short);

/* Externs for tx */
extern int fsop_aun_send(struct __econet_packet_udp *, int, struct fsop_data *);
extern int fsop_aun_send_noseq(struct __econet_packet_udp *, int, struct fsop_data *);

/* Macro to enable easy tx of a standard FS_REPLY_DATA block */
#define fsop_send(n)	fsop_aun_send(&reply, (n), f)

/* Externs for time / date */
extern void fs_date_to_two_bytes(unsigned short, unsigned short, unsigned short, unsigned char *, unsigned char *);

/* Some externs from econet-hpbridge.c */

extern uint32_t get_local_seq(unsigned char, unsigned char);

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
#define FS_NETCONF_REGEX_ONE "^NETCONF(IG)?\\s+([\\+\\-][A-Z]+)\\s*"

#define FS_DIVHANDLE(x) ((fs_config[server].fs_manyhandle == 0) ? (  (  ((x) == 128) ? 8 : ((x) == 64) ? 7 : ((x) == 32) ? 6 : ((x) == 16) ? 5 : ((x) == 8) ? 4 : ((x) == 4) ? 3 : ((x) == 2) ? 2 : ((x) == 1) ? 1 : (x))) : (x))
#define FS_MULHANDLE(x) ((fs_config[server].fs_manyhandle != 0) ? (x) : (1 << ((x) - 1)))

/* List of externs for FSOP functions */

FSOP_EXTERN(10);
FSOP_EXTERN(1a);
FSOP_EXTERN(17);
FSOP_EXTERN(18);
FSOP_EXTERN(19);
FSOP_EXTERN(20);
FSOP_EXTERN(40);
FSOP_EXTERN(60);

/* List of OSCLI externs */

/* The catalogue function */
extern void fsop_00_catalogue (struct fsop_data *, struct oscli_params *, uint8_t, uint8_t);
FSOP_00_EXTERN(BRIDGEVER);
FSOP_00_EXTERN(BYE);
FSOP_00_EXTERN(LOAD);
FSOP_00_EXTERN(OWNER);
FSOP_00_EXTERN(SAVE);

