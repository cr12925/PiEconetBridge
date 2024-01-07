/*
  (c) 2021 Chris Royle
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

/* Although written from scratch, this code could not have been
   developed without sight of the work published on github 
   at https://github.com/stardot/ArduinoFilestore
   The author of that code's efforts are acknowledged herein.
   In particular, what has been useful has been the insight into
   format of those calls and the necessary replies. Without that,
   this code would have taken significantly longer to create.

   I am told the author of that code is stardot.org.uk user
   @gazzaD - to whom I am very grateful.
*/

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
#if __has_include(<libexplain/ferror.h>)
	#include <libexplain/ferror.h>
#else
	#define __NO_LIBEXPLAIN
#endif

#include "../include/econet-gpio-consumer.h"
#ifdef BRIDGE_V2
	#include <pthread.h>
	#include <poll.h>
	#include "../include/econet-hpbridge.h"
#endif

// the ] as second character is a special location for that character - it loses its
// special meaning as 'end of character class' so you can match on it.
#define FSACORNREGEX    "[]\\*\\#A-Za-z0-9\\+_\x81-\xfe;[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FSREGEX    "[]\\*\\#A-Za-z0-9\\+_\x81-\xfe;:[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FSDOTREGEX "[]\\*\\#A-Za-z0-9\\+_\x81-\xfe;\\.[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FS_NETCONF_REGEX_ONE "^NETCONF\\s+([\\+\\-][A-Z]+)\\s*"

#define FS_DIVHANDLE(x)	((fs_config[server].fs_manyhandle == 0) ? (  (  ((x) == 128) ? 8 : ((x) == 64) ? 7 : ((x) == 32) ? 6 : ((x) == 16) ? 5 : ((x) == 8) ? 4 : ((x) == 4) ? 3 : ((x) == 2) ? 2 : ((x) == 1) ? 1 : (x))) : (x))
#define FS_MULHANDLE(x) ((fs_config[server].fs_manyhandle != 0) ? (x) : (1 << ((x) - 1)))

regex_t fs_netconf_regex_one;
short fs_netconf_regex_initialized = 0;

#ifdef BRIDGE_V2
	extern struct __eb_device * eb_find_station (uint8_t, struct __econet_packet_aun *);
	extern uint8_t eb_enqueue_output (struct __eb_device *, struct __econet_packet_aun *, uint16_t);
	extern void eb_add_stats (pthread_mutex_t *, uint64_t *, uint16_t);
#else
	extern int aun_send (struct __econet_packet_aun *, int);
	unsigned short fs_quiet = 0, fs_noisy = 0;
#endif

extern uint32_t get_local_seq(unsigned char, unsigned char);

// routine in econet-bridge.c to find a printer definition
extern int8_t get_printer(unsigned char, unsigned char, char*);

// printer information routines in econet-bridge.c
extern uint8_t get_printer_info (unsigned char, unsigned char, uint8_t, char *, char *, uint8_t *, uint8_t *, short *);
extern uint8_t set_printer_info (unsigned char, unsigned char, uint8_t, char *, char *, uint8_t, short);
extern uint8_t get_printer_total (unsigned char, unsigned char);
extern void send_printjob (char *, uint8_t, uint8_t, uint8_t, uint8_t, char *, char *, char *, char *);
extern char * get_user_print_handler (uint8_t, uint8_t, uint8_t, char *, char *);

// Server timing
extern float timediffstart(void);

short fs_sevenbitbodge; // Whether to use the spare 3 bits in the day byte for extra year information
short use_xattr=1 ; // When set use filesystem extended attributes, otherwise use a dotfile
short normalize_debug = 0; // Whether we spew out loads of debug about filename normalization

short fs_open_interlock(int, unsigned char *, unsigned short, unsigned short);
void fs_close_interlock(int, unsigned short, unsigned short);

void fs_write_readable_config(int);

// Parser
//#define FS_PARSE_DEBUG 1
uint8_t fs_parse_cmd (char *, char *, unsigned short, char **);

#ifndef BRIDGE_V2
	#define FS_VERSION_STRING "PiEconetBridge FS 2.1"
#else
	#define FS_VERSION_STRING "Pi Econet HP Bridge FS 2.1"
#endif

#define FS_DEFAULT_NAMELEN 10

// Implements basic AUN fileserver within the econet bridge

#define ECONET_MAX_FS_SERVERS 4
#define ECONET_MAX_FS_USERS 256
#define ECONET_MAX_FS_DISCS 10 // Don't change this. It won't end well.
#define ECONET_MAX_FS_DIRS 256 // maximum number of active directory handles
#define ECONET_MAX_FS_FILES 512 // Maximum number of active file handles

#define ECONET_MAX_FILENAME_LENGTH (fs_config[server].fs_fnamelen)
// Do NOT change this. Some format string lengths and array lengths are still hard coded.  (And some of the 
// arrays are of length 81 to take a null byte as well. So to make this fully flexible, a number of arrays
// need to be altered, and some format strings need to be built with sprintf so that the right length
// can be incorporated before that (second) format string can be used... sort of a work in progress!
#define ECONET_ABS_MAX_FILENAME_LENGTH 80
#define ECONET_MAX_PATH_ENTRIES 30
#define ECONET_MAX_PATH_LENGTH ((ECONET_MAX_PATH_ENTRIES * (ECONET_ABS_MAX_FILENAME_LENGTH + 1)) + 1)

// PiFS privilege bytes
// MDFS-related privs in our native format
#define FS_PRIV_PERMENABLE 0x80
#define FS_PRIV_NOSHORTSAVE 0x40
#define FS_PRIV_RUNONLY 0x20
#define FS_PRIV_NOLIB 0x10
// Our native privs
#define FS_PRIV_SYSTEM 0x80
#define FS_PRIV_LOCKED 0x40
#define FS_PRIV_NOPASSWORDCHANGE 0x20
#define FS_PRIV_USER 0x01
#define FS_PRIV_INVALID 0x00

// MDFS privilege bits in MDFS format
#define MDFS_PRIV_PWUNLOCKED 0x01
#define MDFS_PRIV_SYST 0x02
#define MDFS_PRIV_NOSHORTSAVE 0x04
#define MDFS_PRIV_PERMENABLE 0x08
#define MDFS_PRIV_NOLIB 0x10
#define MDFS_PRIV_RUNONLY 0x20

#define FS_BOOTOPT_OFF 0x00
#define FS_BOOTOPT_LOAD 0x01
#define FS_BOOTOPT_RUN 0x02
#define FS_BOOTOPT_EXEC 0x03

#define FS_MAX_BULK_SIZE 0x1000 // 4k - see RiscOS PRM

#ifdef BRIDGE_V2
	/* Cache device pointer to V2 bridge devices per server
	   so that fs_aun_send can put things on the right queue
	*/

	struct __eb_device 	*fs_devices[ECONET_MAX_FS_SERVERS];
#endif

struct {
	uint8_t	fs_acorn_home; // != 0 means implement acorn home directory ownership semantics
	uint8_t fs_sjfunc; // != 0 means turn on SJ MDFS functionality
	uint8_t fs_bigchunks; // Whether we use 4k chunks on data bursts, or 1.25k (BeebEm compatibility - it appears to have a buffer overrun!)
	uint8_t fs_pwtenchar; // Set to non-zero when the FS has run the 6 to 10 character password conversion, by moving the fullname field along by 5 chracters
	uint8_t fs_fnamelen; // Live (modifiable!) max filename length. Must be less than ECONET_MAX_FILENAME_LENGTH. When changed, this has to recompile the fs regex
	uint8_t fs_infcolon; // Uses :inf for alternative to xattrs instead of .inf, and maps Acorn / to Unix . instead of Unix :
	uint8_t fs_manyhandle; // Enables user handles > 8, and presents them as 8-bit integers rather than handle n presented as 2^n (which is what FS 3 does with its limit of 8 handles)
	uint8_t fs_mdfsinfo; // Enables longer output from *INFO akin to MDFS
	uint8_t pad[248]; // Spare spare in the config
} fs_config[ECONET_MAX_FS_SERVERS];

struct fs_user {
	unsigned char username[10];
	unsigned char password[11];
	unsigned char fullname[25];
	unsigned char priv;
	unsigned char bootopt;
	unsigned char home[80];
	uint8_t		unused1[16];
	unsigned char lib[80];
	uint8_t		unused2[16];
	unsigned char home_disc;
	unsigned char year, month, day, hour, min, sec; // Last login time
	unsigned char groupmap[8]; // 1 bit for each of 256 groups
	char unused[1];
} users[ECONET_MAX_FS_SERVERS+1][ECONET_MAX_FS_USERS];
// MAX_FS_SERVERS+1 is because we use the last entry to sort a real server entry to produce an MDFS format password file.
// We don't use it for live data

struct {
	unsigned char groupname[10]; // First character null means unused.
} groups[ECONET_MAX_FS_SERVERS][256];

#define FS_MAX_OPEN_FILES 33 // Really 32 because we don't use entry 0

struct {
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
} active[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_USERS];

struct {
	unsigned char net; // Network number of this server
	unsigned char stn; // Station number of this server
	unsigned char directory[256]; // Root directory
	unsigned int total_users; // How many entries in users[][]?
	int total_discs;
} fs_stations[ECONET_MAX_FS_SERVERS];

struct {
	unsigned char name[17];
} fs_discs[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_DISCS];

struct {
	unsigned char name[1024];
	FILE *handle;
	int readers, writers; // Used for locking; when readers = writers = 0 we close the file 
} fs_files[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_FILES];

struct {
	unsigned char name[1024];
	DIR *handle;
	int readers; // When 0, we close the handle
} fs_dirs[ECONET_MAX_FS_SERVERS][ECONET_MAX_FS_FILES];

struct {
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
} fs_bulk_ports[ECONET_MAX_FS_SERVERS][256];

struct objattr {
	unsigned short perm;
	unsigned short owner;
	unsigned long load, exec;
	unsigned short homeof;
};

#define FS_FTYPE_NOTFOUND 0
#define FS_FTYPE_FILE 1
#define FS_FTYPE_DIR 2
#define FS_FTYPE_SPECIAL 3 // Not sure what I'll use that for, but we'll have it anyhow

#define FS_PERM_H 0x80 // Hidden - doesn't show up in directory list, but can be opened
#define FS_PERM_OTH_W 0x20 // Write by others
#define FS_PERM_OTH_R 0x10 // Read by others
#define FS_PERM_L 0x04 // Locked
#define FS_PERM_OWN_W 0x02 // Write by owner
#define FS_PERM_OWN_R 0x01 // Read by owner

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
	int owner; // Owner user ID
	int parent_owner;
	unsigned short homeof;
	unsigned char ownername[11]; // Readable name of owner
	unsigned short perm; // Permissions for owner & other - ECONET_PERM_... etc.
	unsigned short parent_perm; // If object is not found or is a file, this contains permission on parent dir
	unsigned short my_perm; // This user's access rights to this object - i.e. only bottom 3 bits of perm, adjusted for ownership
	unsigned long load, exec, length;
	unsigned long internal; // System internal name for file. (aka inode number for us)
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
	
// Structures used to queue bulk transfers on *LOAD/*RUN. May be adapted later to work on getbytes(), but the latter typically uses smaller number of packets and so doesn't interrupt FS flow like repeated *LOAD does
// When fs_load_queue is not null (see below), the main loop in the bridge will call fs_execute_load_queue to dump one packet off the head of each queue to the destination station
struct __pq {
	struct __econet_packet_udp *packet; // Don't bother with internal 4 byte src/dest header - they are given as parameters to aun_send.
	int len; // Packet data length
	struct __pq *next;
};

struct load_queue {
	unsigned char net, stn; // Destination net, stn
	unsigned int server; // Determines source address
	unsigned queue_type; // For later use with getbytes() - but for now assume always a load
	unsigned char internal_handle; // Internal file handle to be closed at end / abort
	unsigned char mode; // Internal mode
	struct load_queue *next;
	struct __pq *pq_head, *pq_tail;	

};

struct load_queue *fs_load_queue = NULL; // Pointer to first load_queue entry. If NULL, there are no load queues to execute. The load queue entries are enqueued so as to be sorted in server, net, stn order. 

/* MDFS Password file user format */

struct mdfs_user {
	unsigned char 	username[10]; // 0x0D terminated if less than 10 chars - MDFS manual seems to have only 9 bytes for a 10 character username. Looks like a misprint
	unsigned char 	password[10]; // Ditto
	uint8_t 	opt; 
	uint8_t		flag; /* bit 0:Pw unlocked; 1:syst priv; 2: No short saves; 3: Permanent *ENABLE; 4: No lib; 5: RUn only */
	uint8_t		offset_root[3]; /* File offset to URD, or 0 if "normal", whatever that may be */
	uint8_t		offset_lib[3]; /* File offset to LIB, or 0 if "normal" */
	uint8_t		uid[2];
	uint8_t		reserved[2]; /* Assume not supposed to use this! */
	uint8_t		owner_map[32]; /* Bitmap of account ownership */	
};

regex_t r_pathname, r_discname, r_wildcard;

int fs_count = 0;

extern void eb_debug_fmt (uint8_t, uint8_t, char *, char *);

void fs_debug (uint8_t death, uint8_t level, char *fmt, ...)
{

	va_list 	ap;
#ifdef BRIDGE_V2
	char		str[1024];
	char		padstr[1044];

#else
	if (level >= 2 && !fs_noisy)	return;
	if (level == 1 && fs_quiet)	return;
#endif

	va_start (ap, fmt);

#ifndef BRIDGE_V2

	/* Version 1 bridge code - do a simple fprintf to stderr */

	fprintf (stderr, "[+%15.6f]    FS: ", timediffstart());
	vfprintf (stderr, fmt, ap);
	fprintf (stderr, "\n");
	
	if (death)	exit(EXIT_FAILURE);

#else

	/* Version 2 bridge code */

	vsprintf (str, fmt, ap);
	strcpy (padstr, "                 ");
	strcat (padstr, str);
	eb_debug_fmt (death, level, "FS", padstr);

#endif

	va_end(ap);
}

// Copy src to dest length len, where src is space padded
// Reterminate dest with &0D instead of padding.
// Used for generating MDFS password file

void fs_mdfs_copy_terminate(unsigned char *dest, unsigned char *src, uint8_t len)
{
	int	c; // Generic counter

	memcpy(dest, src, len);

	c = len-1;

	while ((*(dest+c) == ' ') && (c > 0))
		c--;

	if ((c == 0) && *(dest+c) == ' ')
		*(dest+c) = 0x0D; // Empty password
	else if ((c != (len - 1)) && (*(dest+c+1)) == ' ')
		*(dest+c+1) = 0x0D;

}


uint8_t fs_pifs_to_mdfs_priv (uint8_t input)
{
	uint8_t 	output = 0;

	output |= (input & FS_PRIV_SYSTEM) ? MDFS_PRIV_SYST : 0;
	output |= (input & FS_PRIV_NOPASSWORDCHANGE) ? 0 : MDFS_PRIV_PWUNLOCKED;
	output |= (input & FS_PRIV_PERMENABLE) ? MDFS_PRIV_PERMENABLE : 0;
	output |= (input & FS_PRIV_NOSHORTSAVE) ? MDFS_PRIV_NOSHORTSAVE : 0;
	output |= (input & FS_PRIV_NOLIB) ? MDFS_PRIV_NOLIB : 0;
	output |= (input & FS_PRIV_RUNONLY) ? MDFS_PRIV_RUNONLY : 0;

	return output;

}

struct mdfs_dir {
	unsigned char	dirname[82]; // 80 characters max + CR - see MDFS manual - and one for a NULL terminator internaly to fs.c
	uint32_t	fileptr; // 0-based pointer in to the directory part of the file
} mdfs_dirs[ECONET_MAX_FS_USERS]; // UNlikely to be more than that

// Return a 0-based file pointer to the dirname specified in the mdfs_dirs struct above
// dir is an ordinary NULL-terminated string. The MDFS ones are 0x0D terminated 
// (and so the actual string in the MDFS password file can be 81 characters, being
// a maximum of 80 characters + 0x0D.
// So terminate dir with 0x0D and do a case-insensitive search for it in mdfs_dirs.
// If not found, add it, calculate the 0-based file ptr and return it. If found,
// return the file ptr.
// urdorlib is 0 if we are looking for a URD. If the directory is a URD and
// is $.<USERNAME> then return &FFFF ("normal" URD, converted to 0 when finalized)
// urdorlib is 1 means looking for a library. If the directory is $.LIBRARY
// then return &FFFF ("normal" LIB, set to 0 when finalized).
// If we run off the end of the list of directories and haven't found the one we're
// looking for, and it wasn't a "normal" directory, 0xFFFE is a rogue for "cannot
// allocate"
// The username field must already have the 0x0D terminator on it or be 10 characters
// The directory doesn't. It's just a null-terminated string

uint32_t fs_get_mdfs_dir_pointer(char *dir, uint8_t urdorlib, char *username)
{
	uint32_t	cumulative, counter;
	unsigned char	idir[82];
	unsigned char	username_null[12]; // NULL terminated username - it will come in either as 10 characters with no termination at all, or terminated 0x0D
	unsigned char	username_null_dollar[15];

	counter = 0;

	while (counter < 10 && (*(username+counter) != 0x0D))
	{
		username_null[counter] = *(username+counter);
		counter++;
	}

	username_null[counter++] = 0x00; // Terminate without 0x0D so we can compare with directory

	sprintf(username_null_dollar, "$.%s", username_null);

	idir[81] = 0x00; // In case it's an 80-character directory with no null on it

	if (strlen(dir) > 81)
		return 0xFFFFFFFE; // Can't allocate - in this case because the dir is too long

	strcpy(idir, dir);
	strcat(idir, "\x0D");

	if ((urdorlib && (!strcasecmp(dir, "LIBRARY") || !strcasecmp(dir, "$.LIBRARY"))) || (!strcasecmp(dir, username_null) || !strcasecmp(dir, username_null_dollar)))
		return 0xFFFFFFFF;

	cumulative = 0;
	counter = 0;

	while ((counter < ECONET_MAX_FS_USERS) && (mdfs_dirs[counter].dirname[0])) // Cycle through mdfs_dirs; stop if we find an empty entry
	{
		if (!strcasecmp(mdfs_dirs[counter].dirname, idir)) // Found it
			return mdfs_dirs[counter].fileptr;

		cumulative = mdfs_dirs[counter].fileptr + strlen(mdfs_dirs[counter].dirname);
		counter++;

	}

	if (counter == ECONET_MAX_FS_USERS)
		return 0xFFFFFFFE; // Cannot allocate - generates a log, but will then simply flag the directory as "normal" without a crash

	// By here, we haven't found the dir we're looking for, so add it at the current location and return the file ptr
	
	strcpy(mdfs_dirs[counter].dirname, idir);
	mdfs_dirs[counter].fileptr = cumulative;

	return cumulative;
}

// QSORT comparator function for usernames within mdfs_user struct
// Since they are all max 10 characters, terminated 0x0D if less than 10,
// we can just use memcmp.

int fs_mdfs_username_compare (const void *a, const void *b)
{
	return memcmp(a, b, 10);
}

// Take fs_users[server] and write an MDFS-format password file in the server root directory
void fs_make_mdfs_pw_file(int server)
{

	/*
	 *
	 * SLIGHT PROBLEM!
	 *
	 * According to the MDFS manual, the username field is only 9 bytes long, despite
	 * it saying that the field is terminated 0x0D if "less than 10 characters".
	 * Might be a typo in the byte numbering in the manual, but since I don't have an
	 * MDFS password file to look at, I can't tell. I could look at an MDFS password
	 * utility, but they are compressed and hard to read...
	 *
	 */

	uint32_t 	 	picounter, mucounter, dircounter;
	struct mdfs_user	mu[ECONET_MAX_FS_USERS];
	uint32_t 		diroffset;
	uint8_t			do_bytes[4];
	uint8_t			pointers[32][2]; // Entry numbers for users starting less than 'A' ([0]), first 'A' or 'B' ([1]) ... see MDFS manual v1.00 para 10.22. Only first 16 entries used. We have the rest to make it easy to write 64 bytes to the file with zeros at the end.
	unsigned char		mdfs_pwfile[1024];
	FILE			*pw; // Output MDFS Passwords file

	// users[ECONET_MAX_FS_SERVERS] is last entry in array (we define as that+1) and used as scratch space
	
	// Copy our native userbase into mdfs_user one by one, then sort mdfs_user,
	// Then build our directory list. Put a pointer into each user record which is based at 0
	// as being the start of the directory list when it will be in the file.
	// Then write a blank first 64 bytes (into which we put the index later), then write out the qsorted
	// records, then 64 &FFs, then write out the directory names.
	// Then update each valid user record's two directory indicies by adding the relevant actual file pointer
	// to the 0-based one which we wrote before.
	
	picounter = mucounter = 0;

	// Empty the directory list so that first character of each dir entry is null signifying unused
	memset (&mdfs_dirs, 0, sizeof(mdfs_dirs));

	// Cycle through out native password file and move the active users (and their IDs) into mu[]
	
	while (picounter < fs_stations[server].total_users)
	{
		if (users[server][picounter].priv) // Active user
		{
			uint32_t	fileptr;

			// Empty the destination struct
			memset(&(mu[mucounter]), 0, sizeof(struct mdfs_user));

			fs_mdfs_copy_terminate((unsigned char *) &(mu[mucounter].username), (unsigned char *) &(users[server][picounter].username), 10);
			fs_mdfs_copy_terminate((unsigned char *) &(mu[mucounter].password), (unsigned char *) &(users[server][picounter].password), 10);

			// Boot option
			mu[mucounter].opt = users[server][picounter].bootopt;

			// Privilege
			mu[mucounter].flag = fs_pifs_to_mdfs_priv(users[server][picounter].priv);

			// UID
			mu[mucounter].uid[0] = (picounter & 0xff);
			mu[mucounter].uid[1] = (picounter & 0xff00) >> 8;

			// Set pointers for URD & LIB
			
			fileptr = fs_get_mdfs_dir_pointer (users[server][picounter].home, 0, mu[mucounter].username);
			mu[mucounter].offset_root[0] = (fileptr & 0x000000FF);
			mu[mucounter].offset_root[1] = (fileptr & 0x0000FF00) >> 8;
			mu[mucounter].offset_root[2] = (fileptr & 0x00FF0000) >> 16;

			fileptr = fs_get_mdfs_dir_pointer (users[server][picounter].lib, 1, mu[mucounter].username);
			mu[mucounter].offset_lib[0] = (fileptr & 0x000000FF);
			mu[mucounter].offset_lib[1] = (fileptr & 0x0000FF00) >> 8;
			mu[mucounter].offset_lib[2] = (fileptr & 0x00FF0000) >> 16;

			mucounter++;
		}

		picounter++;
	}

	// Now add the user terminating block - 64 &FFs
	memset(&(mu[mucounter++]), 0xFF, 64);

	// When we get here, mucounter will contain the number of entries in mu[]. When written to the MDFS
	// password file, they are 64 bytes long each and will start from byte 64. After that follows a
	// So if there's (e.g.) 2 entries in mu[], including the 0xFF terminator,
	// the start of the directory information will be at byte 192.
	// So diroffset, which is to be added to the offset_root and offset_lib values needs to be increased
	// by (64 * (mucounter+1))
	// And we need to fixup 0xFFFFFFFF to be 0 (for "normal"), and 0xFFFFFFFE to be 0 (not found)
	//
	
	diroffset = (64 * (mucounter + 1));

	do_bytes[0] = (diroffset & 0x000000FF);
	do_bytes[1] = (diroffset & 0x0000FF00) >> 8;
	do_bytes[2] = (diroffset & 0x00FF0000) >> 16;
	do_bytes[3] = (diroffset & 0xFF000000) >> 24;

	dircounter = 0;

	while (dircounter < (mucounter-1)) // -1 so we don't try and change the 0xFF terminator block
	{
		if (
			(mu[dircounter].offset_root[2] == 0xFF) &&
			(mu[dircounter].offset_root[1] == 0xFF) &&
			((mu[dircounter].offset_root[0] & 0xFE) == 0xFE)
		   )
			memset(&(mu[dircounter].offset_root), 0, 3);
		else
		{
			uint16_t	total;
			uint8_t		bytecount;

			bytecount = 0;

			while (bytecount < 4)
			{
				total = mu[dircounter].offset_root[bytecount] + do_bytes[bytecount];
				mu[dircounter].offset_root[bytecount] = (total & 0xFF);
				if ((total > 0xFF) & (bytecount != 2))
					mu[dircounter].offset_root[bytecount]++; // Carry
				bytecount++;
			}
		}

		if (
			(mu[dircounter].offset_lib[2] == 0xFF) &&
			(mu[dircounter].offset_lib[1] == 0xFF) &&
			((mu[dircounter].offset_lib[0] & 0xFE) == 0xFE)
		   )
			memset(&(mu[dircounter].offset_lib), 0, 3);
		else
		{
			uint16_t	total;
			uint8_t		bytecount;

			bytecount = 0;

			while (bytecount < 4)
			{
				total = mu[dircounter].offset_lib[bytecount] + do_bytes[bytecount];
				mu[dircounter].offset_lib[bytecount] = (total & 0xFF);
				if ((total > 0xFF) & (bytecount != 2))
					mu[dircounter].offset_lib[bytecount]++; // Carry
				bytecount++;
			}
		}

		dircounter++;

	}

	// Now sort the entries
	
	qsort (&(mu[0]), mucounter-1, sizeof (struct mdfs_user), fs_mdfs_username_compare); // mucounter-1 so we don't sort the 0xFF block, though it would always end up at the end on the sort anyway I think

	// Now set up the pointer block for usernames... re-user dircounter since we've finished with it
	
	memset(&pointers, 0, sizeof(pointers));

	dircounter = 0;

	while (dircounter < (mucounter-1))
	{
		uint8_t		firstchar;
		uint8_t		pointer_index;

		firstchar = mu[dircounter].username[0];

		if ((firstchar >= 'A') && (firstchar <= 'Z'))
			pointer_index = ((firstchar - 'A') / 2) + 1;
		else if (firstchar < 'A')
			pointer_index = 0;
		else firstchar = 14;

		if (pointers[pointer_index][0] == 0 && pointers[pointer_index][1] == 0)
		{
			pointers[pointer_index][0] = (dircounter+1) & 0xFF;
			pointers[pointer_index][1] = ((dircounter+1) & 0xFF00) >> 8;
		}

		dircounter++;

	}	
	
	// Now write out the file, creating the pointer block (to users < 'A', first 'A' or 'B', etc. ...) as we go

	strcpy(mdfs_pwfile, fs_stations[server].directory);
	strcat(mdfs_pwfile, "/");
	strcat(mdfs_pwfile, "MDFSPasswords");

	pw = fopen(mdfs_pwfile, "w"); 

	if (!pw)
		fs_debug (0, 1, "Failed to open %s for writing", mdfs_pwfile);
	{
		uint16_t	counter;

		fwrite(pointers, 64, 1, pw);
		fwrite(mu, mucounter, 64, pw);

		counter = 0;

		while (counter < ECONET_MAX_FS_USERS)
		{
			if (mdfs_dirs[counter].dirname[0])
				fwrite(mdfs_dirs[counter].dirname, strlen(mdfs_dirs[counter].dirname), 1, pw);
			counter++;
		}

		fclose(pw);
	}

}

// Find username if it exists in server's userbase
short fs_get_uid(int server, char *username)
{
	unsigned short counter = 0;
	unsigned char padded_username[11];
	
	strcpy(padded_username, username);

	counter = strlen(padded_username);

	while (counter < 10) padded_username[counter++] = ' ';

	padded_username[counter] = '\0';

	counter = 0;

	while (counter < ECONET_MAX_FS_USERS && (strncasecmp(padded_username, users[server][counter].username, 10) != 0))
		counter++;

	return (counter < ECONET_MAX_FS_USERS ? counter : -1);

}

// Fill character array with username for a given active_id on this server. Put NULL in
// first byte if active id is invalid
void fs_get_username (int server, int active_id, char *username)
{

	if (active[server][active_id].stn == 0 && active[server][active_id].net == 0)
		*username = 0;
	else
	{
		short ptr = 0;

		while (ptr < 10)
		{
			*(username+ptr) = users[server][active[server][active_id].userid].username[ptr];
			ptr++;
		}

		*(username+ptr) = 0; // Null terminate

	}

}

// Find the tail end entry on path2 and store in path1. If path2 empty, store "$".
void fs_store_tail_path(char *path1, char *path2)
{
	char *pos;

	if ((pos = strrchr(path2, '.'))) //  found
		strcpy(path1, (pos + 1));
	else
		strcpy (path1, "$");
}


// Convert our perm storage to Acorn / MDFS format
unsigned char fs_perm_to_acorn(int server, unsigned char fs_perm, unsigned char ftype)
{
	unsigned char r;

	r = fs_perm & FS_PERM_H; // High bit

	if (ftype == FS_FTYPE_DIR)
		r |= 0x20;

	if (fs_perm & FS_PERM_L)
		r |= 0x10;

	if (fs_config[server].fs_sjfunc & FS_PERM_H) // SJ research Privacy bit
		r |= ((fs_perm & (FS_PERM_H)) ? 0x40 : 0);

	r |= ((fs_perm & (FS_PERM_OWN_R | FS_PERM_OWN_W)) << 2);
	r |= ((fs_perm & (FS_PERM_OTH_R | FS_PERM_OTH_W)) >> 4);
	
	//if (!fs_quiet) fprintf (stderr, "Converted perms %02X (ftype %02d) to Acorn %02X\n", fs_perm, ftype, r);
	// fs_debug (0, 1, "Converted perms %02X (ftype %02d) to Acorn %02X", fs_perm, ftype, r);
	return r;
	

}

// Convert acorn / MDFS perm to our format
unsigned char fs_perm_from_acorn(int server, unsigned char acorn_perm)
{
	unsigned char r;

	r = 0;

	if (fs_config[server].fs_sjfunc) r |= (acorn_perm & 0x40) ? FS_PERM_H : 0; // Hidden / Private. This is MDFS only really
	r |= (acorn_perm & 0x10) ? FS_PERM_L : 0; // Locked
	r |= (acorn_perm & 0x08) ? FS_PERM_OWN_W : 0; // Owner write
	r |= (acorn_perm & 0x04) ? FS_PERM_OWN_R : 0; // Owner read
	r |= (acorn_perm & 0x02) ? FS_PERM_OTH_W : 0; // Other write
	r |= (acorn_perm & 0x01) ? FS_PERM_OTH_R : 0; // Other read

	return r;

}

// Convert d/m/y to Acorn 2-byte format
void fs_date_to_two_bytes(unsigned short day, unsigned short month, unsigned short year, unsigned char *monthyear, unsigned char *dday)
{
	unsigned char year_internal;

	*dday = (unsigned char) (day & 0x1f);

	*monthyear = (unsigned char) (month & 0x0f);

	year_internal = year;

	if (year_internal >= 1900) year_internal -=1900;

	year_internal = year  - 81;

	//fprintf (stderr, "7 bit bodge is %s\n", (fs_sevenbitbodge ? "on" : "off"));
	// fs_debug (0, 1, "7 bit bodge is %s", (fs_sevenbitbodge ? "on" : "off"));

	if (!fs_sevenbitbodge)
	{
		year_internal -= 40;
		year_internal = year_internal << 4;
		*monthyear |= (year_internal & 0x0f);
		//fprintf (stderr, "Converted %02d/%02d/%02d to MY=%02X, D=%02X\n", day, month, year, *monthyear, *dday);
		//fs_debug (0, 1, "Converted %02d/%02d/%02d to MY=%02X, D=%02X", day, month, year, *monthyear, *dday);
	}
	else // use top three bits of day as low three bits of year
	{
		*dday |= ((year_internal & 0x70) << 1);
		*monthyear |= ((year_internal & 0x0f) << 4);
		//fprintf (stderr, "Converted %02d/%02d/%04d to MY=%02X, D=%02X\n", day, month, year, *monthyear, *dday);
		//fs_debug (0, 1, "Converted %02d/%02d/%04d to MY=%02X, D=%02X", day, month, year, *monthyear, *dday);
	}

}

unsigned short fs_year_from_two_bytes(unsigned char day, unsigned char monthyear)
{

	unsigned short r;

	if (!fs_sevenbitbodge)
		r = ((((monthyear & 0xf0) >> 4) + 81) % 100);
	else
		r = ((( ((monthyear & 0xf0) >> 4) | ((day & 0xe0) >> 1) ) + 81) % 100);

	//fprintf (stderr, "year_from2byte (%02x, %02x) = %02d\n", day, monthyear, r);
	//fs_debug (0, 1, "year_from2byte (%02x, %02x) = %02d", day, monthyear, r);

	return r;

}

unsigned short fs_month_from_two_bytes(unsigned char day, unsigned char monthyear)
{
	return (monthyear & 0x0f);
}

unsigned short fs_day_from_two_bytes(unsigned char day, unsigned char monthyear)
{
	return (day & 0x1f);
}

// Used with scandir
int fs_alphacasesort(const struct dirent **d1, const struct dirent **d2)
{

	int result;

	result = strcasecmp((*d1)->d_name, (*d2)->d_name);

	//fs_debug (0, 3, "fs_alphacasesort() comparing '%s' with '%s' and returning %d", (*d1)->d_name, (*d2)->d_name, result);

	return result;
}

// Often Econet clients send strings which are terminated with 0x0d. This copies them so we don't repeat the routine.
void fs_copy_to_cr(unsigned char *dest, unsigned char *src, unsigned short len)
{
	unsigned short count, srccount;

	srccount = count = 0;

	// Skip leading whitspace
	while (*(src+srccount) == ' ') srccount++;

	while (count < len && *(src+count) != 0x0d && *(src+count) != 0x00) // Catch null termination as well now
	{
		//if (*(src+srccount) != ' ') // Skip space - Done above. This version removed spaces within the command line, d'uh!
			*(dest+count++) = *(src+srccount);
		srccount++;
	}

	*(dest+count) = '\0';	
}

int fs_aun_send(struct __econet_packet_udp *p, int server, int len, unsigned short net, unsigned short stn)
{
	struct __econet_packet_aun a;

	memcpy(&(a.p.aun_ttype), p, len+8);
	a.p.padding = 0x00;
	a.p.seq = get_local_seq(fs_stations[server].net, fs_stations[server].stn);
		
	a.p.srcnet = fs_stations[server].net;
	a.p.srcstn = fs_stations[server].stn;
	a.p.dstnet = net;
	a.p.dststn = stn;

#ifdef BRIDGE_V2
	// Put the enqueue call here
	
	if (a.p.dstnet == 0)	a.p.dstnet = a.p.srcnet;
	eb_enqueue_output (fs_devices[server], &a, len);
	pthread_cond_signal(&(fs_devices[server]->qwake));
	eb_add_stats (&(fs_devices[server]->statsmutex), &(fs_devices[server]->b_out), len);

	return len;

#else
	return aun_send (&a, len + 8 + 4);
#endif

}

unsigned short fs_get_dir_handle(int server, unsigned int active_id, unsigned char *path)
{
	unsigned short count;

	unsigned short found;

	count = 0; found = 0;

	while (!found && count < FS_MAX_OPEN_FILES)
	{
		if (!strcasecmp((const char *) fs_dirs[server][count].name, (const char *) path)) // Already open
		{
			fs_dirs[server][count].readers++;	
			found = 1;
			return count;
		}
		else count++;
	}

	if (!found) // Open the directory
	{
		found = 0;
		count = 0;
		while (!found && count < FS_MAX_OPEN_FILES)
		{
			if (fs_dirs[server][count].handle == NULL)
			{
				found = 1;
				if (!(fs_dirs[server][count].handle = opendir((const char *) path))) // Open failed!
					return -1;
				fs_dirs[server][count].readers = 1;
				return count;	

			}
			else count++;

		}


	}

	return -1;
}

void fs_close_dir_handle(int server, unsigned short handle)
{
	if (!(fs_dirs[server][handle].handle)) // Not open!
		return;

	if (fs_dirs[server][handle].readers > 0)
		fs_dirs[server][handle].readers--;

	if (fs_dirs[server][handle].readers == 0) // Nobody left
	{
		closedir(fs_dirs[server][handle].handle);
		fs_dirs[server][handle].handle = NULL;
	}

	return;

}

// Find a user file channel
// Gives 0 on failure
unsigned short fs_allocate_user_file_channel(int server, unsigned int active_id)
{
	unsigned short count; // f is index into fs_files[server]

	count = 1; // Don't want to feed the user a directory handle 0

	while (active[server][active_id].fhandles[count].handle != -1 && count < FS_MAX_OPEN_FILES)
		count++;

	if (count >= (fs_config[server].fs_manyhandle ? FS_MAX_OPEN_FILES : 9)) return 0; // No handle available - if not in manyhandle mode, >= 9 is what we need because we can allocate up to and including 8

	active[server][active_id].fhandles[count].is_dir = 0;

	return count;

}

// Deallocate a file handle for a user
void fs_deallocate_user_file_channel(int server, unsigned int active_id, unsigned short channel)
{
	// Do nothing if it's actually a directory handle

	if (active[server][active_id].fhandles[channel].is_dir) return;

	active[server][active_id].fhandles[channel].handle = -1;
	
	return;
}

// Take a unix DIR* handle and find a slot for it in the user's data
unsigned short fs_allocate_user_dir_channel(int server, unsigned int active_id, short d)
{
	unsigned short count;

	count = 1; // Don't want to feed the user a directory handle 0

	while (active[server][active_id].fhandles[count].handle != -1 && count < FS_MAX_OPEN_FILES)
		count++;

	//if (count == FS_MAX_OPEN_FILES) return 0; // No handle available
	if (count >= (fs_config[server].fs_manyhandle ? FS_MAX_OPEN_FILES : 9)) return 0; // No handle available - see comment in the user file allocator for why this is 9

	active[server][active_id].fhandles[count].handle = d;
	active[server][active_id].fhandles[count].cursor = 0;
	active[server][active_id].fhandles[count].cursor_old = 0;
	active[server][active_id].fhandles[count].is_dir = 1;

	return count;

}

// Deallocate a directory handle for a user
void fs_deallocate_user_dir_channel(int server, unsigned int active_id, unsigned short channel)
{

	if (active[server][active_id].fhandles[channel].is_dir == 0) return;

	if (active[server][active_id].fhandles[channel].handle != -1)
		fs_close_dir_handle(server, active[server][active_id].fhandles[channel].handle);

	active[server][active_id].fhandles[channel].handle = -1;
	
	return;
}


int fs_reply_success(int server, unsigned short reply_port, unsigned short net, unsigned short stn, unsigned short command, unsigned short result)
{

	struct __econet_packet_udp reply;

	reply.p.ptype = ECONET_AUN_DATA;
	reply.p.port = reply_port;
	reply.p.ctrl = 0x80;
	reply.p.pad = 0x00;
	//reply.p.seq = (fs_stations[server].seq += 4);
	reply.p.seq = get_local_seq(fs_stations[server].net, fs_stations[server].stn);
	reply.p.data[0] = command;
	reply.p.data[1] = result;

	return fs_aun_send(&reply, server, 2, net, stn);

}

// Find index into users[server] with net,stn number
int fs_find_userid(int server, unsigned char net, unsigned char stn)
{

	unsigned int index = 0;

	while (index < ECONET_MAX_FS_USERS)
	{
		if (active[server][index].net == net && active[server][index].stn == stn)
			return active[server][index].userid;
	
		index++;
	}

	return -1;	 // userid may be 0

}

// Checks an open directory handle to see if *e exists on a case insensitive basis
// Returns 1 if it exists; otherwise 0
// On a successful return, gives the Unix name in the directory, adjusted for / -> : (Econet -> Unix)
// in *r

int fs_check_dir(DIR *h, char *e,  char *r)
{

	short found;
	struct dirent *d;

	found = 0;

	while ((d = readdir(h)) && !found)
	{
		// Examine, sort out xattr as need be, set parent_owner if we find it...
		// Not the case that the last entry has to be a file because this routine will be used for changing directory too

		if (!strcasecmp((const char *) d->d_name, (const char *) e)) // Match!
		{
			strcpy((char * ) r, d->d_name);
			found = 1;
			break;
		}
		
	}

	return found;

}

// These three functions emulate xattr for filesystems that can't
// handle it (enable with -x)
// Basically the file contains "owner load exec perm" values
//
// The filename is "path" + '.inf'
// This will be hidden at the Acorn layer because filenames can't have
// a dot in them (that's a directory separator in the Acorn world)

unsigned char *pathname_to_dotfile(unsigned char *path, uint8_t infcolon)
{
	unsigned char *dotfile;
	dotfile=malloc(strlen(path)+ECONET_ABS_MAX_FILENAME_LENGTH);
	strcpy(dotfile,path);
	// If last character is a / then strip it off; we want the
	// filename in the parent directory
	while (dotfile[strlen(dotfile)-1] == '/')
		dotfile[strlen(dotfile)-1] = '\0';
	strcat(dotfile, infcolon ? ":inf" : ".inf");
	return dotfile;
}

void fs_read_attr_from_file(unsigned char *path, struct objattr *r, int server)
{
	char *dotfile=pathname_to_dotfile(path, fs_config[server].fs_infcolon);
	FILE *f=fopen(dotfile,"r");
	if (f != NULL)
	{
		unsigned short owner, perm, homeof;
		unsigned long load, exec;

		homeof = 0;

		if (fscanf(f, "%hx %lx %lx %hx %hx", &owner, &load, &exec, &perm, &homeof) != 5)
			fscanf(f, "%hx %lx %lx %hx", &owner, &load, &exec, &perm);

		r->owner = owner;
		r->load = load;
		r->exec = exec;
		r->perm = perm;
		r->homeof = homeof;

		fclose(f);

	}

	free(dotfile);
	return;
}

void fs_write_attr_to_file(unsigned char *path, int owner, short perm, unsigned long load, unsigned long exec, int homeof, int server)
{
	char *dotfile=pathname_to_dotfile(path, fs_config[server].fs_infcolon);
	FILE *f=fopen(dotfile,"w");
	if (f != NULL)
	{
		fprintf(f, "%hx %lx %lx %hx %hx", owner, load, exec, perm, homeof);
		fclose(f);
	}
	else
		fs_debug (0, 1, "Could not open %s for writing: %s\n", path, strerror(errno));

	free(dotfile);
	return;
}

void fs_read_xattr(unsigned char *path, struct objattr *r, int server)
{
	// Default values
	r->owner=0; // syst
	r->load=0;
	r->exec=0;
	r->perm=FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
	r->homeof=0;

	char *dotfile=pathname_to_dotfile(path, server);
	int dotexists=access(dotfile, F_OK);
	free(dotfile);

	if (!use_xattr || dotexists==0)
	{
		fs_read_attr_from_file(path, r, server);
		return;
	}

	unsigned char attrbuf[20];

	if (getxattr((const char *) path, "user.econet_owner", attrbuf, 4) >= 0) // Attribute found
	{
		attrbuf[4] = '\0';
		r->owner = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) path, "user.econet_load", attrbuf, 8) >= 0) // Attribute found
	{
		attrbuf[8] = '\0';
		r->load = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) path, "user.econet_exec", attrbuf, 8) >= 0) // Attribute found
	{
		attrbuf[8] = '\0';
		r->exec = strtoul((const char * ) attrbuf, NULL, 16);
	}

	if (getxattr((const char *) path, "user.econet_perm", attrbuf, 2) >= 0) // Attribute found
	{
		attrbuf[2] = '\0';
		r->perm = strtoul((const char * ) attrbuf, NULL, 16);
	}
	if (getxattr((const char *) path, "user.econet_homeof", attrbuf, 4) >= 0) // Attribute found
	{
		attrbuf[4] = '\0';
		r->homeof = strtoul((const char * ) attrbuf, NULL, 16);
	}

	return;

}

void fs_write_xattr(unsigned char *path, int owner, short perm, unsigned long load, unsigned long exec, int homeof, int server)
{
	char *dotfile=pathname_to_dotfile(path, fs_config[server].fs_infcolon);
	int dotexists=access(dotfile, F_OK);
	free(dotfile);

	if (!use_xattr || dotexists==0)
	{
		fs_write_attr_to_file(path, owner, perm, load, exec, homeof, server);
		return;
	}

	unsigned char attrbuf[20];

	sprintf ((char * ) attrbuf, "%02x", perm);
	if (setxattr((const char *) path, "user.econet_perm", (const void *) attrbuf, 2, 0)) // Flags = 0 means create if not exist, replace if does
		fs_debug (0, 1, "Failed to set permission on %s\n", path);

	sprintf((char * ) attrbuf, "%04x", owner);
	if (setxattr((const char *) path, "user.econet_owner", (const void *) attrbuf, 4, 0))
		fs_debug (0, 1, "Failed to set owner on %s", path);

	sprintf((char * ) attrbuf, "%08lx", load);
	if (setxattr((const char *) path, "user.econet_load", (const void *) attrbuf, 8, 0))
		fs_debug (0, 1, "Failed to set load address on %s", path);

	sprintf((char * ) attrbuf, "%08lx", exec);
	if (setxattr((const char *) path, "user.econet_exec", (const void *) attrbuf, 8, 0))
		fs_debug (0, 1, "Failed to set exec address on %s: %s", path, strerror(errno));

	sprintf((char *) attrbuf, "%04x", homeof);
	if (setxattr((const char *) path, "user.econet_homeof", (const void *) attrbuf, 4, 0))
		fs_debug (0, 1, "Failed to set home directory flag on %s: %s", path, strerror(errno));
}

// Convert filename from acorn to unix (replace / with :)
void fs_acorn_to_unix(char *string, uint8_t infcolon)
{

	unsigned short counter = 0;

	while (*(string+counter) != '\0')
	{
		if (*(string+counter) == '/')
			*(string+counter) = (infcolon ? '.' : ':');
		else if (*(string+counter) == 0xA0) // Hard space
			*(string+counter) = '#';
		counter++;
	}

}

// Convert filename from unix to acorn format (replace : with /)
void fs_unix_to_acorn(char *string)
{

	unsigned short counter = 0;

	while (*(string+counter) != '\0')
	{
		if (*(string+counter) == ':')
			*(string+counter) = '/';
		else if (*(string+counter) == '.')
			*(string+counter) = '/';
		else if (*(string+counter) == '#')
			*(string+counter) = 0xA0; // Hard space
		counter++;
	}

}

// output must be suitably sized - the regex string is quite long!
void fs_wildcard_to_regex(char *input, char *output, uint8_t infcolon)
{

	unsigned short counter = 0;
	char internal[1024];

	strcpy(internal, "");

	while (*(input+counter) != '\0')
	{
		switch (*(input+counter))
		{
			case '#': // single character wildcard
				if (infcolon)
					strcat(internal, FSDOTREGEX);
				else
					strcat(internal, FSREGEX);
				break;
			case '*': // Multi-character regex
				if (infcolon)
					strcat(internal, FSDOTREGEX);
				else
					strcat(internal, FSREGEX);
				strcat(internal, "*");
				break;
			case '-': // Fall through
			case '+': // Escape these
			{
				unsigned char t[3];
				t[0] = '\\';
				t[1] = *(input+counter);
				t[2] = '\0';
				strcat(internal, t);
			}
				break;
			default:
			{
				// QUERY: Deal with high bit character regex here?

				unsigned char t[2];
				t[0] = *(input+counter);
				t[1] = '\0';
				strcat(internal, t);
			}
			break;

		}

		counter++;

	}
	
	sprintf(output, "^%s$", internal);

}

// Does a regcomp on string into r_wildcard to save the bother of coding the same every time
// Puts the right flags on the call too
int fs_compile_wildcard_regex(char *string)
{
	return regcomp(&r_wildcard, string, REG_EXTENDED | REG_ICASE | REG_NOSUB);
}

// Makes sure we aren't more than 10 characters long,
// does a case insensitive regex match on the r_wildcard regex (which
// the caller must have already provided and compiled)
int fs_scandir_filter(const struct dirent *d)
{
	
	int		result;

	result = regexec(&r_wildcard, d->d_name, 0, NULL, 0);

	//fs_debug (0, 3, "fs_scandir_filter() checking '%s' against regex returned %s", d->d_name, (result == 0 ? "success" : "failure"));

	if ((result == 0) /* && (strlen(d->d_name) <= ECONET_MAX_FILENAME_LENGTH) */ && strcasecmp(d->d_name, "lost+found")) // Length criteria commented out - cannot pass server parameter to scandir filter
		return 1;
	else	return 0;

}

// Frees a *SCANDIR* list of entries. NOT an fs_wildcard_entries chain.
void fs_free_scandir_list(struct dirent ***list, int n)
{

	struct dirent **l;

	l = *list;

	while (n--)
		free(l[n]);
	free (l);

}

void fs_free_wildcard_list(struct path *p)
{
	struct path_entry *pointer, *pointer_next;

	pointer = p->paths;

	while (pointer != NULL)
	{
		pointer_next = pointer->next;
		free (pointer);
		pointer = pointer_next;
	}	

}

// Wildcard directory search. Assumes that the acorn name provided has not yet been converted so that / needs switching for :
// mallocs a linked chain of struct path_entrys, and puts the address of the head in *head and the tail in *tail
// The calling function MUST free those up on or after return.
// The needle must already be converted from wildcards to regex-compatible text.
// 
int fs_get_wildcard_entries (int server, int userid, char *haystack, char *needle, struct path_entry **head, struct path_entry **tail)
{

	unsigned short counter, found;
	short results;
	struct path_entry *p, *new_p;
	char needle_wildcard[2048];
	struct dirent **namelist;
	struct stat statbuf;
	struct objattr oa, oa_parent;
	struct tm ct;

	found = counter = 0;
	*head = *tail = p = NULL;

	fs_acorn_to_unix(needle, fs_config[server].fs_infcolon);

	fs_wildcard_to_regex(needle, needle_wildcard, fs_config[server].fs_infcolon);

	if (normalize_debug) fs_debug (0, 2, "fs_get_wildcard_entries() - needle = '%s', needle_wildcard = '%s'", needle, needle_wildcard);

	if (fs_compile_wildcard_regex(needle_wildcard) != 0) // Error
		return -1;

	results = scandir(haystack, &namelist, fs_scandir_filter, fs_alphacasesort);

	if (results == -1) // Error - e.g. not found, or not a directory
		return -1;

	// Convert to a path_entry chain here and assign head & tail.

	fs_read_xattr(haystack, &oa_parent, server);
	
	while (counter < results)
	{
		//fprintf (stderr, "fs_get_wildcard_entries() loop counter %d of %d - %s\n", counter+1, results, namelist[counter]->d_name);
		//fs_debug (0, 3, "fs_get_wildcard_entries() loop counter %d of %d - %s", counter+1, results, namelist[counter]->d_name);

		// if() added when long filename support added because scandir filter cannot take server parameter

		if (	(strlen(namelist[counter]->d_name) <= ECONET_MAX_FILENAME_LENGTH) && 
			(strcmp(namelist[counter]->d_name, ".")) && 
			(strcmp(namelist[counter]->d_name, ".."))
		   )	// Exclude the special directories in case we have COLONMAP turned on
		{

			found++;

			new_p = malloc(sizeof(struct path_entry));	
			new_p->next = NULL;
			if (p == NULL)
			{
				new_p->parent = NULL;
				*head = new_p;
			}
			else
			{
				new_p->parent = p;
				p->next = new_p;
			}
	
			*tail = new_p;
	
			// Read parent information
	
			// ** Bug found by @sweh
			//fs_read_xattr(p->unixpath, &oa_parent);
	
			// Fill the struct
			
			strncpy (new_p->unixfname, namelist[counter]->d_name, ECONET_MAX_FILENAME_LENGTH);
			new_p->unixfname[ECONET_MAX_FILENAME_LENGTH] = '\0';
	
			strncpy (new_p->acornname, namelist[counter]->d_name, ECONET_MAX_FILENAME_LENGTH);
			new_p->acornname[ECONET_MAX_FILENAME_LENGTH] = '\0';
	
			fs_unix_to_acorn(new_p->acornname);
	
			sprintf (new_p->unixpath, "%s/%s", haystack, new_p->unixfname);
	
			if (stat(new_p->unixpath, &statbuf) != 0) // Error
			{
				fs_debug (0, 2, "Unable to stat %s", new_p->unixpath);
				free (new_p);
				counter++;
				continue;
			}
	
			//fs_debug (0, 3, "fs_get_wildcard_entries() loop counter %d of %d - ACORN:'%s', UNIX '%s'", counter+1, results, new_p->acornname, new_p->unixfname);
	
			p = new_p; // update p
	
			fs_read_xattr(p->unixpath, &oa, server);
	
			p->load = oa.load;
			p->exec = oa.exec;
			p->owner = oa.owner;
			p->perm = oa.perm;
			p->homeof = oa.homeof;
			p->length = statbuf.st_size;
	
			// If we own the object and it's a directory, and it has permissions 0, then spoof RW/
			if ((p->owner == userid) && S_ISDIR(statbuf.st_mode) && (p->perm == 0))
				p->perm = FS_PERM_OWN_R | FS_PERM_OWN_W;	
	
			p->parent_owner = oa_parent.owner;
			p->parent_perm = oa_parent.perm;
	
			// Parent must be a directory, so we frig the permissions to be WR/ if we own the parent and permissions are &00 (which L3FS would let us read/write to because we own it)
			
			if ((p->parent_owner == userid) && (p->parent_perm == 0))
				p->parent_perm = FS_PERM_OWN_R | FS_PERM_OWN_W;
	
			if (users[server][userid].priv & FS_PRIV_SYSTEM)
				p->my_perm = (p->perm & (FS_PERM_L | FS_PERM_OWN_W | FS_PERM_OWN_R));
			else if (p->owner == userid)
				p->my_perm = (p->perm & ~(FS_PERM_OTH_W | FS_PERM_OTH_R));
			else
				p->my_perm = (p->perm & (FS_PERM_L | FS_PERM_H)) | ((p->perm & (FS_PERM_OTH_W | FS_PERM_OTH_R)) >> 4);
	
			if (S_ISREG(statbuf.st_mode))
				p->ftype = FS_FTYPE_FILE;
			else if (S_ISDIR(statbuf.st_mode))
				p->ftype = FS_FTYPE_DIR;
			else	p->ftype = FS_FTYPE_SPECIAL;
	
			if (!(S_ISREG(statbuf.st_mode)))
				p->load = p->exec = 0;
		
			localtime_r(&(statbuf.st_mtime), &ct);
			fs_date_to_two_bytes (ct.tm_mday, ct.tm_mon+1, ct.tm_year, &(p->monthyear), &(p->day));	
			p->hour = ct.tm_hour;
			p->min = ct.tm_min;
			p->sec = ct.tm_sec;
	
			// Create time
			localtime_r(&(statbuf.st_ctime), &ct);
			fs_date_to_two_bytes(ct.tm_mday, ct.tm_mon+1, ct.tm_year, &(p->c_monthyear), &(p->c_day));
			p->c_hour = ct.tm_hour;
			p->c_min = ct.tm_min;
			p->c_sec = ct.tm_sec;
	
			p->internal = statbuf.st_ino;
			strncpy(p->ownername, users[server][p->owner].username, 10);
			p->ownername[10] = '\0';
	
		} // End of name length if() above

		counter++;
	}

	if (results > 0) fs_free_scandir_list(&namelist, results); // This needs to check results (not 'found') because results is how many scandir returned, not all of which might be 'found' because we apply the length criteria locally.

	// This version from update to long filenames, because this function (rather than scandir with its filter) now ascertains how many results matched, because scandir cannot apply the length criteria. 
	return found;

	// return results; // Old non-long-filenames version
}


// Split a pathname supplied by the user into its components. Always relative to
// root directory of the relevant disc
// Also retrieves attributes etc. and unix filename
// user is an index into active[server][]

// If wildcard = 0, the system will assume no wildcards. Otherwise wildcards enabled.

// We need to amend this to return -1 if it's a bad path so the calling routine can distinguish between no entries and bad pathname

int fs_normalize_path_wildcard(int server, int user, unsigned char *received_path, short relative_to, struct path *result, unsigned short wildcard)
{

	int ptr = 2;
	regmatch_t matches[20];
	unsigned char adjusted[1048];
	unsigned char path_internal[1024];
	unsigned char unix_segment[ECONET_ABS_MAX_FILENAME_LENGTH+10];
	struct objattr attr;
	int parent_owner = 0;
	short found;
	unsigned char path[1030];

	unsigned short homeof_found = 0; // Non-zero if we traverse a known home directory

	DIR *dir;
	//struct dirent *d;
	short count;

	result->npath = 0;
	result->paths = result->paths_tail = NULL;

	result->disc = -1; // Rogue so that we can tell if there was a discspec in the path

	/* Fudge the special files here if we have SYST privs */

	if (active[server][user].priv & FS_PRIV_SYSTEM)
	{
		unsigned char	final_path[30];
		unsigned char 	*acorn_start_ptr;

		final_path[0] = '\0';

		if ((strlen(received_path) >= 10) && !strcasecmp(received_path + strlen(received_path)-10, "%PASSWORDS"))
		{
			if (normalize_debug) fs_debug (0, 1, "Found request for special file %PASSWORDS");
			strcpy(final_path, "MDFSPasswords");
			acorn_start_ptr = received_path + strlen(received_path) - 10 + 1;
		}
		else if ((strlen(received_path) >= 9) && !strcasecmp(received_path + strlen(received_path)-9, "%PIPASSWD"))
		{
			if (normalize_debug) fs_debug (0, 1, "Found request for special file %PIPASSWD");
			strcpy(final_path, "Passwords");
			acorn_start_ptr = received_path + strlen(received_path) - 9 + 1;
		}
		else if ((strlen(received_path) >= 7) && !strcasecmp(received_path + strlen(received_path)-7, "%CONFIG"))
		{
			if (normalize_debug) fs_debug (0, 1, "Found request for special file %%CONFIG");
			strcpy(final_path, "Configuration.txt");
			acorn_start_ptr = received_path + strlen(received_path) - 7 + 1;
		}

		if (final_path[0] != '\0')
		{
			// Fudge our structures here and return
			struct tm t;
			struct stat s;
	
			result->error = 0;
			result->ftype = FS_FTYPE_FILE;
			strcpy(result->discname, fs_discs[server][users[server][active[server][user].userid].home_disc].name);
			result->disc = users[server][active[server][user].userid].home_disc;

			strcpy(result->path[0], acorn_start_ptr);
			strcpy(result->acornname, acorn_start_ptr);
			strcpy(result->path_from_root, acorn_start_ptr);
			sprintf(result->unixpath, "%s/%s", fs_stations[server].directory, final_path);
			sprintf(result->acornfullpath, "$.%s", acorn_start_ptr);
			strcpy(result->unixfname, final_path);
					
			if (normalize_debug) fs_debug (0, 1, "Special file data: result->path[0] = %s, result->acornname = %s, result->path_from_root = %s, result->unixpath = %s, result->acornfullpath = %s, result->unixfname = %s",
					result->path[0],
					result->acornname,
					result->path_from_root,
					result->unixpath,
					result->acornfullpath,
					result->unixfname
					);
			result->npath = 1;
			result->owner = result->parent_owner = 0;
			result->perm = result->my_perm = result->parent_perm = FS_PERM_OWN_W | FS_PERM_OWN_R;
			result->load = result->exec = 0;
			// Length & internal name here, and date fields
			result->paths = result->paths_tail = NULL;	
	
			if (stat(result->unixpath, &s)) // Failed stat // this should *never* happen, but just in case it does...
			{
				result->error = FS_PATH_ERR_NODIR;
				result->ftype = FS_FTYPE_NOTFOUND;
				return -1;
			}
	
			result->internal = s.st_ino;
			result->length = s.st_size;
	
			localtime_r(&(s.st_mtime), &t);
			fs_date_to_two_bytes (t.tm_mday, t.tm_mon+1, t.tm_year, &(result->monthyear), &(result->day));
			result->hour = t.tm_hour;
			result->min = t.tm_min;
			result->sec = t.tm_sec;
	
			// Create time
			localtime_r(&(s.st_ctime), &t);
			fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_monthyear), &(result->c_day));
			result->c_hour = t.tm_hour;
			result->c_min = t.tm_min;
			result->c_sec = t.tm_sec;
			
			return 1;

		}

		// Otherwise fall through to the normal routine
	}

	strcpy(path, received_path);
	
	if (normalize_debug) fs_debug(0,1, "path=%s, received_path=%s, relative to %d, wildcard = %d, server %d, user %d, active user fhandle.handle = %d, acornfullpath = %s", path, received_path, relative_to, wildcard, server, user, active[server][user].fhandles[relative_to].handle, active[server][user].fhandles[relative_to].acornfullpath);

	// If the handle we have for 'relative to' is invalid, then return directory error
	if ((relative_to > FS_MAX_OPEN_FILES) || (active[server][user].fhandles[relative_to].handle == -1))
	{
		result->error = FS_PATH_ERR_NODIR; return 0;
	}

	// Cope with null path relative to dir on another disc
	if (strlen(path) == 0 && relative_to != -1)
		strcpy(path, active[server][user].fhandles[relative_to].acornfullpath);
	else if (relative_to != -1 && (path[0] != ':' && path[0] != '$') && path[0] != '&')
		sprintf(path, "%s.%s", active[server][user].fhandles[relative_to].acornfullpath, received_path);

	if (normalize_debug && relative_to != -1) fs_debug (0, 1, "Path provided: '%s', relative to '%s'", received_path, active[server][user].fhandles[relative_to].acornfullpath);
	else if (normalize_debug) fs_debug (0, 1, "Path provided: '%s', relative to nowhere", received_path);

	// Truncate any path provided that has spaces in it
	count = 0; 
	while (count < strlen(path))
	{
		if (path[count] == 0x20) path[count] = '\0';
		count++;
	}

	memset(path_internal, 0, 1024);

	if (*path == ':') // Disc selection
	{

		int count, found = 0;

		// Exclude lost+found!
		if (strcasecmp(path+1, "lost+found") && regexec(&r_discname, (const char * ) path+1, 1, matches, 0) == 0)
		{
			strncpy((char * ) result->discname, (const char * ) path+1, matches[0].rm_eo - matches[0].rm_so);
			*(result->discname + matches[0].rm_eo - matches[0].rm_so) = '\0';
			//strcpy(adjusted, path+strlen((const char *) result->discname)+2); // +2 because there will be a : at the start, and a '.' at the end of the disc name	
			// Copy back to path
			if (*(path+strlen((const char *) result->discname)+2) == '$') // Can't specify home with disc specifier || *(path+strlen((const char *) result->discname)+2) == '&')
				strcpy ((char * ) path_internal, (const char * ) path + strlen((const char *) result->discname) + 2);
			else // insert a $. on the start
			{
				if (strlen(path) == (strlen((const char *) result->discname)+1)) // Just : and a disc name
					strcpy ((char *) path_internal, "$");
				else // There was more beyond the disc name, but not a $ so insert $.
				{
					strcpy ((char * ) path_internal, "$.");
					strcat (path_internal, path + strlen((const char *) result->discname) + 2);
				}
			}
			ptr = 0; // We have put the residual path at the start of path
		}
		else	{ result->error = FS_PATH_ERR_NODISC; return 0; } // Couldn't recognize disc name - bad path

		
		if ( (*(path + strlen((const char *) result->discname) + 1) != '.') && (*(path + strlen((const char *) result->discname) + 1) != '\0') ) // We had neither a '.' nor end of line after the disc name - probably bad. If end of line, then path_internal will have a $ on the front of it - see above.
		{
			result->error = FS_PATH_ERR_FORMAT;
			return 0; // Must be a '.' after the disc name. Was probably attempt at disc name longer than 10 chars.
		}

		// Now see if we know the disc name in our store...

		count = 0;
		while (count < ECONET_MAX_FS_DISCS && !found)
		{
			if (!strcasecmp((const char *) fs_discs[server][count].name, (const char *) result->discname))
				found = 1;
			else 	count++;
		}

		if (!found)
		{
			result->error = FS_PATH_ERR_NODISC;
			return 0; // Bad path - no such disc
		}

		result->disc = count;
	}
	else if (*path == '.') // Bad path - can't start with a .
	{
		result->error = FS_PATH_ERR_FORMAT;
		return 0;
	}
	else	
	{
		strcpy ((char * ) path_internal, (const char * ) path);
	}

	strcpy ((char * ) adjusted, (const char * ) "");

	if (normalize_debug) 
	{
		if (relative_to > 0)
			fs_debug (0, 1, "Normalize relative to handle %d, which has full acorn path %s", relative_to, active[server][user].fhandles[relative_to].acornfullpath);
		else	
			fs_debug (0, 1, "Normalize relative to nowhere.");
	}


	// New relative adjustment code

	// This probably now redundant given the relative adjustment at the head of this routine, but might be relevant if relative_path == -1;

	if (path_internal[0] == '$') // Absolute path given
	{
		if (normalize_debug) fs_debug (0, 1, "Found $ specifier with %02x as next character", path_internal[1]);
		switch (path_internal[1])
		{
			case '.': ptr = 2; break; 
			case 0: ptr = 1; break; // next routine will find an empty path
			default: result->error = FS_PATH_ERR_FORMAT; return 0; break; //Anything else is invalid
		}
		// Set up 'adjusted' accordingly
		strcpy(adjusted, path_internal + ptr);
	}
/* This section fails because for some reason active[server][user].root is garbage! - it is intended to let NFS clients (as opposed to ANFS) use the &.XXX path nomenclature
	else if (path_internal[0] == '&') // Append home directory
	{
		if (normalize_debug) fs_debug (0, 1, "Found & specifier with %02x as next character\n", path_internal[1]);
		switch (path_internal[1])
		{
			case '.': ptr = 2; break;
			default: result->error = FS_PATH_ERR_FORMAT; return 0; break; // Must have a . after & in a path
		}
		if (normalize_debug)
		{
			fs_debug (0, 1, "User id = %d, active id = %d, root handle = %d, full acorn path = %s\n", active[server][user].userid, user, active[server][user].root, active[server][user].fhandles[active[server][user].root].acornfullpath);
		}
		snprintf (adjusted, 1000, ":%s.%s.%s", fs_discs[server][users[server][active[server][user].userid].home_disc].name, active[server][user].fhandles[active[server][user].root].acornfullpath, path_internal + ptr);	
	}
*/
	else // relative path given - so give it relative to the relevant handle
	{
		unsigned short fp_ptr = 0;

		if (relative_to < 1) // Relative to nowhere
			strcpy(adjusted, "");
		else
		{
			while (active[server][user].fhandles[relative_to].acornfullpath[fp_ptr] != '.') fp_ptr++;
			// Now at end of disc name
			// Skip the '.$'
			fp_ptr += 2;
			if (active[server][user].fhandles[relative_to].acornfullpath[fp_ptr] == '.') // Path longer than just :DISC.$
				fp_ptr++;
	
			if (fp_ptr < strlen(active[server][user].fhandles[relative_to].acornfullpath))
			{
				sprintf(adjusted, "%s", active[server][user].fhandles[relative_to].acornfullpath + fp_ptr);
				if (strlen(path_internal) > 0) strcat(adjusted, ".");
			}
			else	strcpy(adjusted, "");
		}

		strcat(adjusted, path_internal);

	}
	
	if (result->disc == -1)
	{
		result->disc = active[server][user].current_disc; // Replace the rogue if we are not selecting a specific disc
		strcpy ((char * ) result->discname, (const char * ) fs_discs[server][result->disc].name);
		if (normalize_debug) fs_debug (0, 1, "No disc specified, choosing current disc: %d (%d) on server %d - %s (%s)\n", active[server][user].current_disc, result->disc, server, fs_discs[server][result->disc].name, result->discname);
	}

	if (normalize_debug) fs_debug (0, 1, "Disc selected = %d, %s\n", result->disc, (result->disc != -1) ? (char *) fs_discs[server][result->disc].name : (char *) "");
	if (normalize_debug) fs_debug (0, 1, "path_internal = %s (len %d)\n", path_internal, (int) strlen(path_internal));

	sprintf (result->acornfullpath, ":%s.$", fs_discs[server][result->disc].name);

	if (normalize_debug) fs_debug (0, 1, "Adjusted = %s / ptr = %d / path_internal = %s\n", adjusted, ptr, path_internal);

	strcpy ((char * ) result->path_from_root, (const char * ) adjusted);

	// if (normalize_debug) fs_debug (0, 1, "Adjusted = %s\n", adjusted);

	ptr = 0;

	while (result->npath < 30 && ptr < strlen((const char *) adjusted))
	{

		if ((*(adjusted + ptr) == '^'))
		{
			if (result->npath > 0) result->npath--;
			ptr++;
			if (*(adjusted + ptr) == '.') ptr++; // Skip any . that may be there
		}
		else
		{
			if (regexec(&r_pathname, adjusted + ptr, 1, matches, 0) == 0)
			{
				strncpy((char * ) result->path[result->npath], (const char * ) adjusted + ptr, matches[0].rm_eo - matches[0].rm_so);
				*(result->path[result->npath++] + matches[0].rm_eo - matches[0].rm_so) = '\0';
				ptr += (matches[0].rm_eo - matches[0].rm_so);
			}
			else
			{
				result->error = FS_PATH_ERR_FORMAT;
				return 0; // bad path	
			}
	
			if (ptr != strlen((const char *) adjusted) && *(adjusted + ptr) != '.') // Bad path - must have a dot next, otherwise the path element must be more than ten characters
			{
				result->error = FS_PATH_ERR_FORMAT;
				return 0;
			}
			else if (ptr != strlen((const char *) adjusted) && strlen((const char *) adjusted) == (ptr + 1)) // the '.' was at the end
			{
				result->error = FS_PATH_ERR_FORMAT;
				return 0;
			}
			else 	ptr++; // Move to start of next portion of path
		}

	
	}

	if (ptr < strlen((const char *) adjusted))
	{
		result->error = FS_PATH_ERR_LENGTH;
		return 0; // Path too long!
	}

	/* See if the file exists, in a case insensitive manner, figure out its Unix path, and load its attributes.
	   If no attributes, or some of them are missing, fill them in with appropriate defaults if the file exists */

	/* First build the unix path */

	sprintf (result->unixpath, "%s/%1d%s", fs_stations[server].directory, result->disc, fs_discs[server][result->disc].name);

	if (normalize_debug) fs_debug (0, 1, "Unix dir: %s\n", result->unixpath);
	if (normalize_debug) fs_debug (0, 1,  "npath = %d\n", result->npath);

	// Iterate through each directory looking for the next part of the path in a case insensitive matter, and if any of them lack extended attributes then add them in as we go (if the thing exists!)
	// Also do the conversion from '/' in an Acorn path to ':' in a unix filename ...

	count = 0;

	// Collect root directory info
	{
		struct stat s;
		struct tm t;
		//int owner;
		//char attrbuf[20];

		result->ftype = FS_FTYPE_DIR;
		
		sprintf(result->acornname, "%-10s", "$"); // Probably don't need to update this for >10 char filenames, all it does is put $ in the front of the path

		strcpy((char * ) result->unixfname, (const char * ) "");	 // Root dir - no name
		result->internal = s.st_ino; // Internal name = Inode number
		result->length = 0; // Probably wrong

		// Next, see if we have xattr and, if not, populate them. We do this for all paths along the way

		fs_read_xattr(result->unixpath,&attr, server);
		result->owner = 0; // Always SYST if root directory not owned
		result->load = 0;
		result->exec = 0;
		result->perm = FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
		result->my_perm = FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
		// Added 20231227
		result->parent_perm = result->perm;
		result->parent_owner = result->owner;

		if (!(active[server][user].priv & FS_PRIV_SYSTEM))
			result->my_perm = FS_PERM_OWN_R; // Read only my_perm for non-System users on a root directory
 
		result->homeof = 0;

		fs_write_xattr(result->unixpath, result->owner, result->perm, result->load, result->exec, result->homeof, server);

		stat(result->unixpath, &s);

		localtime_r(&(s.st_mtime), &t);
		fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->monthyear), &(result->day));

		result->hour = t.tm_hour;
		result->min = t.tm_min;
		result->sec = t.tm_sec;

		// Create time
		localtime_r(&(s.st_ctime), &t);
		fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_monthyear), &(result->c_day));
		result->c_hour = t.tm_hour;
		result->c_min = t.tm_min;
		result->c_sec = t.tm_sec;
		

	}

	if (wildcard)
	{
		int num_entries;
		unsigned short count = 0;

		char acorn_path[ECONET_ABS_MAX_FILENAME_LENGTH+10];
		struct path_entry *p; // Pointer for debug

		if (normalize_debug) fs_debug (0, 1, "Processing wildcard path with %d elements\n", result->npath);

		// Re-set path_from_root bceause we'll need to update it with the real acorn names
		strcpy(result->path_from_root, "");

		while (result->npath > 0 && (count < result->npath))
		{

			strcpy(acorn_path, result->path[count]); // Preserve result->path[count] as is, otherwise fs_get_wildcard_entries will convert it to unix, which we don't want
			if (normalize_debug) fs_debug (0, 1, "Processing path element %d - %s (Acorn: %s) in directory %s\n", count, result->path[count], acorn_path, result->unixpath);

			num_entries = fs_get_wildcard_entries(server, active[server][user].userid, result->unixpath, // Current search dir
					acorn_path, // Current segment in Acorn format (which the function will convert)
					&(result->paths), &(result->paths_tail));

			if (normalize_debug)
			{
				fs_debug (0, 1, "Wildcard search returned %d entries (result->paths = %8p):\n", num_entries, result->paths);
				p = result->paths;
				while (p != NULL)
				{
					fs_debug (0, 1, "Type %02x Owner %04x Parent owner %04x Owner %10s Perm %02x Parent Perm %02x My Perm %02x Load %08lX Exec %08lX Homeof %04x Length %08lX Int name %06lX Unixpath %s Unix fname %s Acorn Name %s Date %02d/%02d/%02d\n",
						p->ftype, p->owner, p->parent_owner, p->ownername,
						p->perm, p->parent_perm, p->my_perm,
						p->load, p->exec, p->homeof, p->length, p->internal,
						p->unixpath, p->unixfname, p->acornname,
						fs_day_from_two_bytes(p->day, p->monthyear),
						fs_month_from_two_bytes(p->day, p->monthyear),
						fs_year_from_two_bytes(p->day, p->monthyear));
						//p->day, p->monthyear & 0x0f, ((!fs_sevenbitbodge) ? (p->monthyear & 0xf0) >> 4) + 81 : (((((p->monthyear & 0xf0) << 1) | ((p->day & 0xe0) >> 5))+81) % 100));
					p = p->next;
				}
			}

			found = (num_entries > 0 ? 1 : 0);

			// If not on last leg, add first entry to path from root
			if (found && (count != result->npath-1))
			{
				if (strlen(result->path_from_root) != 0)
					strcat(result->path_from_root, ".");
				strcat(result->path_from_root, result->paths[0].acornname);
			}

			// Wildcard calls will need to add each successive acornname to the path_from_root for each entry separately - so on the final path element, we don't put it on so that the caller can do that

			if (found == 0) // Didn't find anything
			{

				// BUG: TODO: Need to set parent_owner, parent_perm and perm here in case we are trying to open a file for write. 20231227
				result->ftype = FS_FTYPE_NOTFOUND;
				
				// Copy to thing we didn't find to result->acornname so it can be reused in the caller
				strcpy (result->unixfname, acorn_path);
				strcpy (result->acornname, acorn_path);
				fs_acorn_to_unix(result->unixfname, fs_config[server].fs_infcolon);

				// If we are on the last segment and the filename does not contain wildcards, we return 1 to indicate that what was 
				// searched for wasn't there so that it can be written to. Obviously if it did contain wildcards then it can't be so we
				// return 0

				if (normalize_debug) fs_debug (0, 1, "Work out whether to return 1 or 0 when nothing found: num_entries returned %d, count = %d, result->npath-1=%d, search for wildcards is %s\n", num_entries, count, result->npath-1, (strchr(result->path[count], '*') == NULL && strchr(result->path[count], '#') == NULL) ? "in vain" : "successful");
				if ((count == result->npath-1) && (num_entries != -1) // Soft error if on last path entry unless we got an error from the wildcard search
					// && ((strchr(result->path[count], '*') == NULL) && (strchr(result->path[count], '#') == NULL))
				) // Only give a hard fail if we are not in last path segment
					return 1;

				if (normalize_debug) fs_debug (0, 1, "Signal a hard fail\n");
				result->error = FS_PATH_ERR_NODIR;
				return 0; // If not on last segment, this is a hard fail.
			}
				
			// Always copy the first entry into the main struction because we always want it.
			// Unless on last segment (when we want to leave all the path entries available to be freed by the caller)
			// we free them up here.
			//

			// So there's at least one entry, and it should be at *paths
			//
			//

			result->ftype = result->paths->ftype;
			result->parent_owner = result->paths->parent_owner;
			result->owner = result->paths->owner;
			result->perm = result->paths->perm;
			result->parent_perm = result->paths->parent_perm;
			result->my_perm = result->paths->my_perm;
			result->load = result->paths->load;
			result->exec = result->paths->exec;
			result->homeof = result->paths->homeof;
			result->length = result->paths->length;
			result->internal = result->paths->internal;
			strncpy (result->acornname, result->paths->acornname, ECONET_MAX_FILENAME_LENGTH);
			result->acornname[ECONET_MAX_FILENAME_LENGTH] = '\0';

			// If we are in Acorn Home Semantics mode, and we've found a home directory then update the info accordingly
			// I.e. once we are below a home directory, set owner for everything in there to the ID whose home directory we traversed

			if (homeof_found == 0 && result->homeof != 0)
				homeof_found = result->homeof;

			if (fs_config[server].fs_acorn_home && homeof_found)
			{
				struct path_entry *h;

				result->owner = homeof_found;
				result->my_perm = result->perm;
				h = result->paths;

				while (h)
				{
					h->owner = homeof_found;
					h->my_perm = h->perm;
					strncpy(h->ownername, users[server][h->owner].username, 10);
					h->ownername[10] = '\0';

					h = h->next;
				}

			}
			

			// Populate ownername. Done here in case it changed because of Acorn home semantics

			strncpy(result->ownername, result->paths->ownername, 10);
			result->ownername[10] = '\0';

			if (count < result->npath-1) // Add path to acornfullpath. When in wildcard mode, the caller is expected to add whichever element of paths[] they want to the acornpath to get the full path.
			{
				strcat(result->acornfullpath, ".");
				strcat(result->acornfullpath, result->paths->acornname);
			}

			strcpy (result->unixpath, result->paths->unixpath); // Always copy first entry to unixpath - means that our next npath entry will look in the first thing we found on the last wildcard search. That means, e.g. :ECONET.$.A*.WOMBAT.DR* will match the first thing in $ beginning 'A'.

			strncpy (result->unixfname, result->paths->unixfname, ECONET_MAX_FILENAME_LENGTH);
			result->unixfname[ECONET_MAX_FILENAME_LENGTH] = '\0';

			result->day = result->paths->day;
			result->monthyear = result->paths->monthyear;
			result->hour = result->paths->hour;
			result->min = result->paths->min;
			result->sec = result->paths->sec;

			result->c_day = result->paths->c_day;
			result->c_monthyear = result->paths->c_monthyear;
			result->c_hour = result->paths->c_hour;
			result->c_min = result->paths->c_min;
			result->c_sec = result->paths->c_sec;

			if (count != result->npath-1) // Not last segment - free up all the path_entries because we'll be junking them.
				fs_free_wildcard_list(result);

			count++;
		}

		if (normalize_debug) fs_debug (0, 1, "Returning full acorn path (wildcard - last path element to be added by caller) %s with my_perm = %02X, unix_path = %s", result->acornfullpath, result->my_perm, result->unixpath);

		return 1;
	}

	// This is the non-wildcard code

/* OLD - CAUSED NON-SYST USERS NOT TO BE ABLE TO READ $
	result->my_perm = result->perm = result->parent_perm = 0; // Clear down
*/
	result->my_perm = result->perm;
	result->parent_perm = result->perm;
	if (!( (active[server][user].priv & FS_PRIV_SYSTEM) || (active[server][user].userid == result->owner) ))
		result->my_perm = (result->my_perm & ~(FS_PERM_OWN_R | FS_PERM_OWN_W)) | ((result->my_perm & (FS_PERM_OTH_R | FS_PERM_OTH_W)) >> 4);

	while ((result->npath > 0) && count < result->npath)
	{
		char path_segment[ECONET_ABS_MAX_FILENAME_LENGTH+10]; // used to store the converted name (/ -> :)
		struct stat s;
		// OLD char attrbuf[20];
		unsigned short r_counter;
		unsigned short owner, perm;

		found = 0;

		if (normalize_debug) fs_debug (0, 1, "Examining %s\n", result->unixpath);

		// Convert pathname so that / -> :

		r_counter = 0; 

		while (result->path[count][r_counter] != '\0' && r_counter < ECONET_MAX_FILENAME_LENGTH)
		{
			if (result->path[count][r_counter] == '/')
				path_segment[r_counter] = (fs_config[server].fs_infcolon ? '.' : ':');
			else if (result->path[count][r_counter] == 0xA0)
				path_segment[r_counter] = '#'; // Hard space equivalent
			else	path_segment[r_counter] = result->path[count][r_counter];
			r_counter++;
		}
		path_segment[r_counter] = '\0';

// Begin old non-wildcard code
		
		dir = opendir(result->unixpath);

		if (!dir)
		{
			// Not found
			result->ftype = FS_FTYPE_NOTFOUND;
			return 1;
		}

		// if we are looking for last element in path (i.e. result->unixpath currently contains parent directory name)

		if (normalize_debug) fs_debug (0, 1, "Calling fs_check_dir(..., %s, ...)\n", path_segment);

		// If path_segment is found in dir, then it puts the unix name for that file in unix_segment
		found = fs_check_dir (dir, path_segment, unix_segment);

		closedir(dir);

		// Obtain permissions on dir - see if we can read it

		fs_read_xattr(result->unixpath, &attr, server);
		owner = attr.owner;
		perm = attr.perm;

		if (homeof_found == 0 && fs_config[server].fs_acorn_home && attr.homeof != 0)
			homeof_found = attr.homeof;

		if (homeof_found)
			owner = homeof_found;
		
		// Fudge parent perm if we own the object and permissions = &00
		if ((active[server][user].userid == attr.owner) && ((attr.perm & ~FS_PERM_L) == 0))
			perm = attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R;
		
		if (count == result->npath - 1) // Last segment
			result->parent_perm = perm;

		if (!	( 
				(active[server][user].priv & FS_PRIV_SYSTEM)
			||	(active[server][user].userid == owner) // Owner can always read own directory irrespective of permissions(!)
			||	(perm & FS_PERM_OTH_R) // Others can read the directory
			)
			&& !found) 
		{
			if (normalize_debug) fs_debug (0, 1, "This user cannot read dir %s\n", result->unixpath);
			result->ftype = FS_FTYPE_NOTFOUND;
			return 0; // Was 1. Needs to be a hard failure if the user can't read the directory we're looking in
		}
	
		if (!found) // Didn't find any dir entry
		{
			{

				result->ftype = FS_FTYPE_NOTFOUND;
				if (count == (result->npath - 1)) // Not found on last leg - return 1 so that we know it's safe to save there if we have permission
				{
				
					unsigned short r_counter = 0;
					char unix_segment[ECONET_ABS_MAX_FILENAME_LENGTH+10];
					while (result->path[count][r_counter] != '\0' && r_counter < ECONET_MAX_FILENAME_LENGTH)
					{
						if (result->path[count][r_counter] == '/')
							unix_segment[r_counter] = (fs_config[server].fs_infcolon ? '.' : ':');
						else if (result->path[count][r_counter] == 0xA0) // Hard space
							unix_segment[r_counter] = '#';
						else	unix_segment[r_counter] = result->path[count][r_counter];
						r_counter++;
					}
					unix_segment[r_counter] = '\0';
					strcat(result->unixpath, "/");
					strcat(result->unixpath, unix_segment); // Add these on a last leg not found so that the calling routine can open the file to write if it wants
					strcpy(result->unixfname, unix_segment); // For use by caller if we didn't find it
					// Populate the acorn name we were looking for so that things like fs_save() can easily return it
					strcpy(result->acornname, path_segment);
					result->parent_owner = parent_owner; // Otherwise this doesn't get properly updated
					if (normalize_debug) fs_debug (0, 1, "Non-Wildcard file (%s, unix %s) not found in dir %s - returning unixpath %s, acornname %s, parent_owner %04X\n", path_segment, unix_segment, result->unixpath, result->unixpath, result->acornname, result->parent_owner);
					return 1;
				}
				else	
				{
					result->error = FS_PATH_ERR_NODIR;
					return 0; // Fatal not found
				}
			}
		}

		if (normalize_debug) fs_debug (0, 1, "Found path segment %s in unix world = %s\n", path_segment, unix_segment);
		strcat(result->unixpath, "/");
		strcat(result->unixpath, unix_segment);

		// Add it to full acorn path
		strcat(result->acornfullpath, ".");
		strcat(result->acornfullpath, path_segment);

		if (normalize_debug) fs_debug (0, 1, "Attempting to stat %s\n", result->unixpath);

		if (!stat(result->unixpath, &s)) // Successful stat
		{

			//int owner;
			char dirname[1024];

			if (normalize_debug) fs_debug (0, 1, "stat(%s) succeeded\n", result->unixpath);
			if (!S_ISDIR(s.st_mode) && (count < (result->npath - 1))) // stat() follows symlinks so the first bit works across links; the second condition is because we only insist on directories for that part of the path except the last element, which might legitimately be FILE or DIR
			{
				result->ftype = FS_FTYPE_NOTFOUND; // Because something we encountered before end of path could not be a directory
				return 1;
			}

			if (normalize_debug) fs_debug (0, 1, "Non-leaf node %s confirmed to be a directory\n", result->unixpath);
			if ((S_ISDIR(s.st_mode) == 0) && (S_ISREG(s.st_mode) == 0)) // Soemthing is wrong
			{
				result->error = FS_PATH_ERR_TYPE;
				return 0; // Should either be file or directory - not block device etc.
			}

			if (normalize_debug) fs_debug (0, 1, "Proceeding to look at attributes on %s\n", result->unixpath);
			// Next, set internal name from inode number

			result->internal = s.st_ino; // Internal name = Inode number

			// Next, see if we have xattr and, if not, populate them. We do this for all paths along the way

			strcpy ((char * ) dirname, (const char * ) result->unixpath);
			// Need to add / for setxattr
			if (S_ISDIR(s.st_mode))	strcat(dirname, "/");

			fs_read_xattr(dirname, &attr, server);

			if (normalize_debug) fs_debug (0, 1, "fs_read_xattr yielded: Owner %04X, Load %08lX, Exec %08lX, Home Of %04X, Perm %02X\n", attr.owner, attr.load, attr.exec, attr.homeof, attr.perm);

			// If it's a directory with 0 permissions and we own it, set permissions to RW/

			if (normalize_debug) fs_debug (0, 1, "Looking to see if this user (id %04X) is the owner (%04X), if this is a dir and if perms (%02X) are &00\n", active[server][user].userid, attr.owner, attr.perm);
			if ((active[server][user].userid == attr.owner) && S_ISDIR(s.st_mode) && ((attr.perm & ~FS_PERM_L) == 0))
			{
				if (normalize_debug) fs_debug (0, 1, "Is a directory owned by the user with perm = 0 - setting permissions to WR/\n");
				attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R;
			}
		
			result->owner = attr.owner;
			result->load = attr.load;
			result->exec = attr.exec;
			result->perm = attr.perm;
			result->homeof = attr.homeof;
			
			result->attr.owner = attr.owner;
			result->attr.load = attr.load;
			result->attr.exec = attr.exec;
			result->attr.perm = attr.perm;
			result->attr.homeof = attr.homeof;


			if (homeof_found == 0 && fs_config[server].fs_acorn_home && attr.homeof != 0)
				homeof_found = attr.homeof;

			if (homeof_found)
				result->owner = result->attr.owner = homeof_found;
		
			result->parent_owner = parent_owner;

			parent_owner = result->owner; // Ready for next loop

			if (normalize_debug) fs_debug (0, 1, "Setting parent_owner = %04x, this object owned by %04x\n", result->parent_owner, result->owner);

			// Are we on the last entry? If so, this is the leaf we're looking for

			if (count == (result->npath - 1))
			{
				struct tm t;

				if (S_ISDIR(s.st_mode))
				{
					result->ftype = FS_FTYPE_DIR;
					result->load = result->exec = 0;	
					result->length = 0; // This might be wrong
				}
				else // Assume file
				{
					result->ftype = FS_FTYPE_FILE;
					result->length = s.st_size;
				}

				// Modification date

				localtime_r(&(s.st_mtime), &t);

				fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->monthyear), &(result->day));
				result->hour = t.tm_hour;
				result->min = t.tm_min;
				result->sec = t.tm_sec;

				// Create time
				localtime_r(&(s.st_ctime), &t);
				fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_day), &(result->c_monthyear));
				result->c_hour = t.tm_hour;
				result->c_min = t.tm_min;
				result->c_sec = t.tm_sec;

				if (active[server][user].priv & FS_PRIV_SYSTEM)
					result->my_perm = 0xff;
				else if (active[server][user].userid != result->owner)
					result->my_perm = (result->perm & FS_PERM_L) | ((result->perm & (FS_PERM_OTH_W | FS_PERM_OTH_R)) >> 4);
				else	result->my_perm = (result->perm & 0x0f);

				strcpy((char * ) result->unixfname, (const char * ) unix_segment);
	
			}
			
			strcpy((char * ) result->unixfname, (const char * ) unix_segment);

			// This gets converted to acorn below
			strncpy(result->acornname, unix_segment, ECONET_MAX_FILENAME_LENGTH);

			result->acornname[ECONET_MAX_FILENAME_LENGTH] = '\0';
			fs_unix_to_acorn(result->acornname);

		}
		else	return 0; // Something wrong - that should have existed

		count++;

	}
	
	if (normalize_debug) fs_debug (0, 1, "Returning full acorn path (non-wildcard) %s with permissions %02X, unix path %s", result->acornfullpath, result->my_perm, result->unixpath);

	strncpy((char * ) result->ownername, (const char * ) users[server][result->owner].username, 10); // Populate readable owner name
	result->ownername[10] = '\0';

	return 1; // Success

}

// The old format, non-wildcard function, for backward compat
// Will ultimately need modifying to copy the first entry in the found list into the 
// path structure and then free all the path entries that have been found.
int fs_normalize_path(int server, int user, unsigned char *path, short relative_to, struct path *result)
{
	if (0 && (!strcasecmp("%Passwords", path) || !strcasecmp("%Config", path)) && (users[server][active[server][user].userid].priv & FS_PRIV_SYSTEM)) // System priv user trying to normalize password file // Disabled - now done in the wildcard function instead
	{
		struct tm t;
		struct stat s;

		result->error = 0;
		result->ftype = FS_FTYPE_FILE;
		strcpy(result->discname, fs_discs[server][users[server][active[server][user].userid].home_disc].name);
		result->disc = users[server][active[server][user].userid].home_disc;
		if (!strcasecmp("%Passwords", path))
		{
			strcpy(result->path[0], "Passwords");
			strcpy(result->acornname, "Passwords");
			strcpy(result->path_from_root, "Passwords");
			sprintf (result->unixpath, "%s/Passwords", fs_stations[server].directory);
			sprintf (result->acornfullpath, "$.Passwords");
			sprintf (result->unixfname, "Passwords");
		}
		if (!strcasecmp("%Config", path))
		{

			strcpy(result->path[0], "Config");
			strcpy(result->acornname, "Config");
			strcpy(result->path_from_root, "Config");
			sprintf (result->unixpath, "%s/Configuration.txt", fs_stations[server].directory);
			sprintf (result->acornfullpath, "$.Config");
			sprintf (result->unixfname, "Configuration.txt");
		}

		result->npath = 1;
		result->owner = result->parent_owner = 0;
		result->perm = result->my_perm = result->parent_perm = FS_PERM_OWN_W | FS_PERM_OWN_R;
		result->load = result->exec = 0;
		// Length & internal name here, and date fields
		result->paths = result->paths_tail = NULL;	

		if (stat(result->unixpath, &s)) // Failed stat // this should *never* happen, but just in case it does...
		{
			result->error = FS_PATH_ERR_NODIR;
			result->ftype = FS_FTYPE_NOTFOUND;
			return -1;
		}

		result->internal = s.st_ino;
		result->length = s.st_size;

		localtime_r(&(s.st_mtime), &t);

		fs_date_to_two_bytes (t.tm_mday, t.tm_mon+1, t.tm_year, &(result->monthyear), &(result->day));
		result->hour = t.tm_hour;
		result->min = t.tm_min;
		result->sec = t.tm_sec;

		// Create time
		localtime_r(&(s.st_ctime), &t);
		fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_day), &(result->c_monthyear));
		result->c_hour = t.tm_hour;
		result->c_min = t.tm_min;
		result->c_sec = t.tm_sec;
		
		return 1;

	}
	else
		return fs_normalize_path_wildcard(server, user, path, relative_to, result, 0);
}

void fs_write_user(int server, int user, unsigned char *d) // Writes the 256 bytes at d to the user's record in the relevant password file
{

	char pwfile[1024];
	FILE *h;

	sprintf (pwfile, "%s/Passwords", fs_stations[server].directory);

	if ((h = fopen(pwfile, "r+")))
	{
		if (fseek(h, (256 * user), SEEK_SET))
			fs_debug (0, 1, "Attempt to write beyond end of user file\n");
		else if (fwrite(d, 256, 1, h) != 1)
				fs_debug (0, 1, "Error writing to password file\n");

		fclose(h);
	}
	else fs_debug (0, 0, "Error opening password file - %s\n", strerror(errno));

}

#ifndef BRIDGE_V2
int fs_initialize(unsigned char net, unsigned char stn, char *serverparam)
#else
int fs_initialize(struct __eb_device *device, unsigned char net, unsigned char stn, char *serverparam)
#endif
{
	
	DIR *d;
	struct dirent *entry;

	int old_fs_count = fs_count;
	
	FILE *passwd;
	char passwordfile[280], passwordfilecopy[300];
	int length;
	int portcount;
	char regex[256];

#ifdef FS_PARSE_DEBUG
	char *param;
#endif

#ifdef FS_PARSE_DEBUG
	fs_parse_cmd ("i am chris wobble\r", "I AM", 4, &param);
	fs_parse_cmd ("acc. stromboli wr/r\r", "ACCESS", 3, &param);
	fs_parse_cmd ("lo.file 6000    \r", "LOAD", 3, &param);
	fs_parse_cmd ("lo.file 6000\r", "LOAD", 2, &param);
	fs_parse_cmd ("lo.         file 6000\r", "LOAD", 2, &param);
	fs_parse_cmd ("del.       file      \r", "DELETE", 3, &param);
	fs_parse_cmd ("DELETE        MYFILE   \r", "DELETE", 3, &param);
#endif

// Seven bit bodge test harness

/*
	{
		unsigned char monthyear, day;

		fs_date_to_two_bytes(5, 8, 2021, &monthyear, &day);

		fs_debug (0, 1, "fs_date_to_two_bytes(5/8/2021) gave MY=%02X, D=%02X\n", monthyear, day);

	}

*/

// WILDCARD TEST HARNESS

/*
	char temp1[15], temp2[2048];
	struct dirent **namelist;
	int sr;

	strcpy(temp1, "FF12/3");
	fs_debug (0, 1, "temp1 = %s\n", temp1);
	fs_unix_to_acorn(temp1);
	fs_debug (0, 1, "fs_unix_to_acorn(temp1) = %s\n", temp1);
	fs_acorn_to_unix(temp1);
	fs_debug (0, 1, "fs_acorn_to_unix(temp1) = %s\n", temp1);
	
	strcpy(temp1, "#e*");
	fs_debug (0, 1, "Wildcard test = %s\n", temp1);

	fs_wildcard_to_regex(temp1, temp2);
	fs_debug (0, 1, "Wildcard regex = %s\n", temp2);

	fs_debug (0, 1, "Regex compile returned %d\n", fs_compile_wildcard_regex(temp2));
	sr = scandir("/econet/0ECONET/CHRIS", &namelist, fs_scandir_filter, fs_alphacasesort);
	
	regfree(&r_wildcard);

	if (sr == -1) fs_debug (0, 1, "scandir() test failed.\n");
	else while (sr--)
	{
		fs_debug (0, 1, "File index %d = %s\n", sr, namelist[sr]->d_name);
		free(namelist[sr]);	
	}
	free(namelist);
*/
	
// END OF WILDCARD TEST HARNESS

	fs_debug (0, 2, "Attempting to initialize server %d on %d.%d at directory %s", fs_count, net, stn, serverparam);

	// If there is a file in this directory called "auto_inf" then we
	// automatically turn on "-x" mode.  This should work transparently
	// for any filesystem that isn't currently inf'd 'cos reads will
	// get the xattr and writes will create a new inf file
	char *autoinf=malloc(strlen(serverparam)+15);
	strcpy(autoinf,serverparam);
	strcat(autoinf,"/auto_inf");
	if (access(autoinf, F_OK) == 0)
	{
		fs_debug (0, 1, "Automatically turned on -x mode because of %s", autoinf);
		use_xattr = 0;
	}
	free(autoinf);

	sprintf(regex, "^(%s{1,16})", FSREGEX);
	if (regcomp(&r_discname, regex, REG_EXTENDED) != 0)
		fs_debug (1, 0, "Unable to compile regex for disc names.");

	if (!fs_netconf_regex_initialized)
	{
		if (regcomp(&fs_netconf_regex_one, FS_NETCONF_REGEX_ONE, REG_EXTENDED) != 0)
			fs_debug (1, 0, "Unable to compile netconf regex.");
		fs_netconf_regex_initialized = 1;
	}

	// Ensure serverparam begins with /
	if (serverparam[0] != '/')
	{
		fs_debug (0, 1, "Bad directory name %s", serverparam);
		return -1;
	}

	d = opendir(serverparam);

	if (!d)
		fs_debug(1, 1, "Unable to open root directory %s", serverparam);
	else
	{

		FILE * cfgfile;

		strncpy ((char * ) fs_stations[fs_count].directory, (const char * ) serverparam, 255);
		fs_stations[fs_count].directory[255] = (char) 0; // Just in case
		fs_stations[fs_count].net = net;
		fs_stations[fs_count].stn = stn;

		// Clear state
		memset(active[fs_count], 0, sizeof(active)/ECONET_MAX_FS_SERVERS);
		//memset(fs_discs[fs_count], 0, sizeof(fs_discs)/ECONET_MAX_FS_SERVERS); // First character set to NULL in loop below
		memset(fs_files[fs_count], 0, sizeof(fs_files)/ECONET_MAX_FS_SERVERS);
		memset(fs_dirs[fs_count], 0, sizeof(fs_dirs)/ECONET_MAX_FS_SERVERS);
		memset(users[fs_count], 0, sizeof(users)/ECONET_MAX_FS_SERVERS); // Added 18.04.22 - we didn't seem to be doing this!
		memset(groups[fs_count], 0, sizeof(groups)/ECONET_MAX_FS_SERVERS); // Added 18.04.22 - beginning of group implementation
		memset(&(fs_config[fs_count]), 0, sizeof(fs_config)/ECONET_MAX_FS_SERVERS); // Added 03.05.22 - Per server configuration

		for (length = 0; length < ECONET_MAX_FS_DISCS; length++) // used temporarily as counter
		{
			//sprintf (fs_discs[fs_count][length].name, "%29s", "");
			fs_discs[fs_count][length].name[0] = '\0';
		}
	
		// Temporary use of the passwordfile variable

		// Set up some defaults in case we are writing a new file
		fs_config[fs_count].fs_acorn_home = 0;
		fs_config[fs_count].fs_sjfunc = 1;
		fs_config[fs_count].fs_pwtenchar = 1;
		fs_config[fs_count].fs_fnamelen = FS_DEFAULT_NAMELEN;

		sprintf(passwordfile, "%s/Configuration", fs_stations[fs_count].directory);
		cfgfile = fopen(passwordfile, "r+");

		if (!cfgfile) // Config file not present
		{
			if ((cfgfile = fopen(passwordfile, "w+")))
				fwrite(&(fs_config[fs_count]), 256, 1, cfgfile);
			else fs_debug (0, 1, "Unable to write configuration file at %s - not initializing", passwordfile);

			fs_write_readable_config(fs_count);
		}

		if (cfgfile)
		{
			int configlen;

			fseek(cfgfile, 0, SEEK_END);
			configlen = ftell(cfgfile);
			rewind(cfgfile);

			if (configlen != 256)
				fs_debug (0, 1, "Configuration file is incorrect length!");
			else
			{
				fread (&(fs_config[fs_count]), 256, 1, cfgfile);
				fs_debug (0, 2, "Configuration file loaded");
			}

			fs_write_readable_config(fs_count);
		}

		if (fs_config[fs_count].fs_fnamelen < 10 || fs_config[fs_count].fs_fnamelen > ECONET_ABS_MAX_FILENAME_LENGTH)
			fs_config[fs_count].fs_fnamelen = 10;

		// Filename regex compile moved here so we know how long the filenames are. We set this to maximum length because
		// the normalize routine sifts out maximum length for each individual server and there is only one regex compiled
		// because the scandir filter uses it, and that routine cannot take a server number as a parameter.

		/* 20231229 OLD 
		if (fs_config[fs_count].fs_infcolon)
			sprintf(regex, "^(%s{1,%d})", FSDOTREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);
		else
			sprintf(regex, "^(%s{1,%d})", FSREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);
		*/

		sprintf(regex, "^(%s{1,%d})", FSACORNREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);

		if (regcomp(&r_pathname, regex, REG_EXTENDED) != 0)
			fs_debug (1, 0, "Unable to compile regex for file and directory names.");

		// Load / Create password file

		sprintf(passwordfile, "%s/Passwords", fs_stations[fs_count].directory);
	
		passwd = fopen(passwordfile, "r+");
		
		if (!passwd)
		{
			fs_debug (0, 1, "No password file - initializing %s with SYST", passwordfile);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow="
			sprintf (users[fs_count][0].username, "%-10.10s", "SYST");
			sprintf (users[fs_count][0].password, "%-10.10s", "");
			sprintf (users[fs_count][0].fullname, "%-24.24s", "System User"); 
			users[fs_count][0].priv = FS_PRIV_SYSTEM;
			users[fs_count][0].bootopt = 0;
			sprintf (users[fs_count][0].home, "%-80.80s", "$");
			sprintf (users[fs_count][0].lib, "%-80.80s", "$.Library");
#pragma GCC diagnostic pop
			users[fs_count][0].home_disc = 0;
			users[fs_count][0].year = users[fs_count][0].month = users[fs_count][0].day = users[fs_count][0].hour = users[fs_count][0].min = users[fs_count][0].sec = 0; // Last login time
			if ((passwd = fopen(passwordfile, "w+")))
				fwrite(&(users[fs_count]), 256, 1, passwd);
			else fs_debug (0, 1, "Unable to write password file at %s - not initializing", passwordfile);
		}

		if (passwd) // Successful file open somewhere along the line
		{
			fseek (passwd, 0, SEEK_END);
			length = ftell(passwd); // Get file size
			rewind(passwd);
	
			if ((length % 256) != 0)
				fs_debug (0, 1, "Password file not a multiple of 256 bytes!");
			else if ((length > (256 * ECONET_MAX_FS_USERS)))
				fs_debug (0, 1, "Password file too long!");
			else	
			{
				int discs_found = 0;

				fs_debug (0, 2, "Password file read - %d user(s)", (length / 256));
				fread (&(users[fs_count]), 256, (length / 256), passwd);
				fs_stations[fs_count].total_users = (length / 256);
				fs_stations[fs_count].total_discs = 0;
		
				if (fs_config[fs_count].fs_pwtenchar == 0) // Shuffle full name field along 5 characters and blank out the 5 spaces
				{

					int u; // user count
					struct tm *t; 
					time_t	now;
					char sys_str[600];

					now = time(NULL);

					t = localtime(&now);

					snprintf (passwordfilecopy, 299, "%s.%04d%02d%02d:%02d%02d",
						passwordfile,
						t->tm_year, t->tm_mon, t->tm_mday,
						t->tm_hour, t->tm_min);

					snprintf (sys_str, 599, "cp %s %s", passwordfile, passwordfilecopy);

					system(sys_str);
					
					for (u = 0; u < fs_stations[fs_count].total_users; u++)
					{
						char old_realname[30];
						// Move real name 5 bytes further on (but our struct has been updated, so it's actually 5 bytes earlier than the struct suggests! And copy it, less 5 bytes

						memcpy (old_realname, &(users[fs_count][u].password[6]), 30);
						memcpy (users[fs_count][u].fullname, old_realname, 25);
						memset (&(users[fs_count][u].password[6]), 32, 5);

					}

					rewind(passwd);
					fwrite(&(users[fs_count]), length, 1, passwd);
					rewind(passwd);

					fs_config[fs_count].fs_pwtenchar = 1;

					rewind(cfgfile);
					fwrite (&(fs_config[fs_count]), 256, 1, cfgfile);
					rewind(cfgfile);

					fs_debug (0, 1, "Updated password file for 10 character passwords, and backed up password file to %s", passwordfilecopy);
				}

				fclose (cfgfile);

				// Make MDFS password file

				// fs_make_mdfs_pw_file(fs_count); // Causing problems in the directory build

				// Now load up the discs. These are named 0XXX, 1XXX ... FXXXX for discs 0-15
				while ((entry = readdir(d)) && discs_found < ECONET_MAX_FS_DISCS)
				{

					struct 	stat statbuf;
					char	fullname[1024];
					//int	l;

					sprintf(fullname, "%s/%s", serverparam, entry->d_name);

					//fprintf (stderr, "lstat(%s) = %d\n", fullname, (l = lstat(fullname, &statbuf)));
					//fprintf (stderr, "lstat(%s) st_mode & S_IFMT = %02X, d_type = %02X\n", fullname, statbuf.st_mode, entry->d_type);


					if (((entry->d_name[0] >= '0' && entry->d_name[0] <= '9') || (entry->d_name[0] >= 'A' && entry->d_name[0] <= 'F')) && (entry->d_type == DT_DIR || (entry->d_type == DT_LNK && (stat(fullname, &statbuf) == 0) && (S_ISDIR(statbuf.st_mode)))) && (strlen((const char *) entry->d_name) <= 17)) // Found a disc. Length 17 = index character + 16 name; we ignore directories which are longer than that because the disc name will be too long
					{
						int index;
						short count;
						
						index = (int) (entry->d_name[0] - '0');
						if (index > 9) index -= ('A' - '9' - 1);
	
						count = 0;
						while (count < 30 && (entry->d_name[count+1] != 0))
						{
							fs_discs[fs_count][index].name[count] = entry->d_name[1+count];
							count++;
						}
						fs_discs[fs_count][index].name[count] = 0;
					
						fs_debug (0, 2, "Initialized disc name %s (%d)", fs_discs[fs_count][index].name, index);
						discs_found++;
	
					}
				}
				
				closedir(d);
				
				fs_stations[fs_count].total_discs = discs_found;

				for (portcount = 0; portcount < 256; portcount++)
					fs_bulk_ports[fs_count][portcount].handle = -1; 
		
				if (discs_found > 0)
				{
					// Load / Initialize groups file here - TODO
					unsigned char groupfile[1024];
					FILE *group;

					sprintf(groupfile, "%s/Groups", fs_stations[fs_count].directory);
	
					group = fopen(groupfile, "r+");

					if (!group) // Doesn't exist - create it
					{

						fs_debug (0, 1, "No group file at %s - initializing", groupfile);
						if ((group = fopen(groupfile, "w+")))
							fwrite(&(groups[fs_count]), sizeof(groups)/ECONET_MAX_FS_SERVERS, 1, group);
						else fs_debug (0, 1, "Unable to write group file at %s - not initializing", groupfile);
					}

					if (group) // Got it somehow - created or it existed
					{

						int length; 

						fseek (group, 0, SEEK_END);
						length = ftell(group); // Get file size
						rewind(group);

						if (length != 2560)
							fs_debug (0, 1, "Group file is wrong length / corrupt - not initializing");
						else
						{
							// Load it and complete initialization
							fread (&(groups[fs_count]), 2560, 1, group);

							fs_count++; // Only now do we increment the counter, when everything's worked
						}
					}
					else fs_debug (0, 1, "Server %d - failed to initialize - cannot initialize or find Groups file!", fs_count);

					// (If there was still no group file here, fs_count won't increment and we don't initialize)
				}
				else fs_debug (0, 1, "Server %d - failed to find any discs!", fs_count);
			}
			fclose(passwd);
	
			//fs_debug (0, 1, "users = %8p, active = %8p, fs_stations = %8p, fs_discs = %8p, fs_files = %8p, fs_dirs = %8p, fs_bulk_ports = %8p\n",
					//users[fs_count], active[fs_count], fs_stations, fs_discs[fs_count], fs_files[fs_count], fs_dirs[fs_count], fs_bulk_ports[fs_count]);
		}
		
	}
	
	if (fs_count == old_fs_count) // We didn't initialize
		return -1;
	else	
	{

		/* Wildcard test harness on real data
		int result;
		struct path p;

		result = fs_normalize_path_wildcard(old_fs_count, 0, ":ECONET.$.R*.A.*mc*", -1, &p, 1);

		if (result)
		{
			struct path_entry *e;

			e = p.paths;

			while (e != NULL)
			{
					fs_debug (0, 1, "Type %02x Owner %04x Parent owner %04x Owner %10s Perm %02x Parent Perm %02x My Perm %02x Load %08lX Exec %08lX Length %08lX Int name %06lX Unixpath %s Unix fname %s Acorn Name %s Date %02d/%02d/%02d",
						e->ftype, e->owner, e->parent_owner, e->ownername,
						e->perm, e->parent_perm, e->my_perm,
						e->load, e->exec, e->length, e->internal,
						e->unixpath, e->unixfname, e->acornname,
						e->day, e->monthyear & 0x0f, ((e->monthyear & 0xf0) >> 4) + 81);
					e = e->next;

			}

			fs_free_wildcard_list(&p);
		}

		// Test to see if a non-existent filename gives us a 1 return but no path entries, so we know it's writable.
		// We should get a 0 if the tail of the path entry has any wildcards in it
		//

		result = fs_normalize_path_wildcard(old_fs_count, 0, ":ECONET.$.R*.WOBBLE", -1, &p, 1); // Should give us 1 & FS_FTYPE_NOTFOUND

		fs_debug (0, 1, "Normalize :ECONET.$.R*.WOBBLE returned %d and FTYPE %d", result, p.ftype);

		result = fs_normalize_path_wildcard(old_fs_count, 0, ":ECONET.$.R*.WOBBLE*", -1, &p, 1); // Should give us 1 & FS_FTYPE_NOTFOUND

		fs_debug (0, 1, "Normalize :ECONET.$.R*.WOBBLE* returned %d and FTYPE %d", result, p.ftype);

		// End of Wildcard test harness 
*/

#ifdef BRIDGE_V2
		/* Prime fs_devices */
		
		fs_devices[old_fs_count] = device;
#endif

#ifdef BRIDGE_V2
		fs_debug (0, 2, "Server %d successfully initialized on station %d.%d", old_fs_count, device->net, stn);
#else
		fs_debug (0, 1, "Server %d successfully initialized on station %d.%d", old_fs_count, net, stn);
#endif

		fs_write_readable_config(old_fs_count);

		return old_fs_count; // The index of the newly initialized server
	}
}

// Used when we must be able to specify a ctrl byte

void fs_error_ctrl(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned char ctrl, unsigned char error, char *msg)
{
	struct __econet_packet_udp reply;

	reply.p.port = reply_port;
	reply.p.ctrl = ctrl;
	reply.p.ptype = ECONET_AUN_DATA;
	reply.p.data[0] = 0x00;
	reply.p.data[1] = error;
	memcpy (&(reply.p.data[2]), msg, strlen((const char *) msg));
	reply.p.data[2+strlen(msg)] = 0x0d;

	// 8 = UDP Econet header, 2 = 0 and then error code, rest is message + 0x0d
	fs_aun_send (&reply, server, 2+(strlen(msg))+1, net, stn);

}

// Used when we don't need to send a particular control byte back
void fs_error(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned char error, char *msg)
{
	fs_error_ctrl(server, reply_port, net, stn, 0x80, error, msg);
}

void fs_reply_ok(int server, unsigned char reply_port, unsigned char net, unsigned char stn)
{

	struct __econet_packet_udp reply;

	reply.p.port = reply_port;
	reply.p.ctrl = 0x80;
	//reply.p.seq = (fs_stations[server].seq += 4);
	reply.p.seq = get_local_seq(fs_stations[server].net, fs_stations[server].stn);
	reply.p.pad = 0x00;
	reply.p.ptype = ECONET_AUN_DATA;
	reply.p.data[0] = 0x00;
	reply.p.data[1] = 0x00;

	fs_aun_send (&reply, server, 2, net, stn);
}

void fs_toupper(char *a)
{
	unsigned short counter = 0;

	while (*(a+counter) != 0)
	{
		if (*(a+counter) >= 'a' && *(a+counter) <= 'z')
			*(a+counter) -= 32;
		counter++;
	}

}

unsigned short fs_find_bulk_port(int server)
{
	int portcount;
	unsigned short found = 0;

	portcount = 1; // Don't try port 0... immediates!

	while (!found && portcount < 255)
	{
		if ((fs_bulk_ports[server][portcount].handle == -1) && (portcount != 0x99) && (portcount != 0xd1) && (portcount != 0x9f) && (portcount != 0xdf)) // 0xd1, 9f are print server; df will be the port server, 0x99 is the fileserver...
			found = 1;
		else portcount++;
	}

	if (found) return portcount;
	else return 0;
}

int fs_stn_logged_in(int server, unsigned char net, unsigned char stn)
{

	int count;

	short found = 0;

	count = 0;

	while (!found && (count < ECONET_MAX_FS_USERS))
	{
		if (	(active[server][count].net == net) &&
			(active[server][count].stn == stn) )
			return count;
		count++;
	}

	return -1;	
}

void fs_bye(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned short do_reply)
{

	struct __econet_packet_udp reply;
	int active_id;
	int count;

	active_id = fs_stn_logged_in(server, net, stn);

	fs_debug (0, 1, "            from %3d.%3d Bye", net, stn);

	// Close active files / handles

	
/*
	count = 1;
	while (count < FS_MAX_OPEN_FILES)
	{
		if (active[server][active_id].fhandles[count].handle != -1 && active[server][active_id].fhandles[count].is_dir)
			fs_deallocate_user_dir_channel(server, active_id, count);
		count++;
	}
*/

	count = 1;
	while (count < FS_MAX_OPEN_FILES)
	{
		if (active[server][active_id].fhandles[count].handle != -1 /* && (active[server][active_id].fhandles[count].is_dir == 0) */)
		{
			fs_close_interlock(server, active[server][active_id].fhandles[count].handle, active[server][active_id].fhandles[count].mode);
			fs_deallocate_user_file_channel(server, active_id, count);
		}
		count++;
	}

	//fs_debug (0, 1, "FS doing memset(%8p, 0, %d)", &(active[fs_stn_logged_in(server, net, stn)]), sizeof(active)/ECONET_MAX_FS_SERVERS);
	//fs_debug (0, 1, "FS bulk ports array at %8p", fs_bulk_ports[server]);
	//memset(&(active[fs_stn_logged_in(server, net, stn)]), 0, sizeof(active) / ECONET_MAX_FS_SERVERS);
	active[server][active_id].stn = active[server][active_id].net = 0; // Flag unused
	

	if (do_reply) // != 0 if we need to send a reply (i.e. user initiated bye) as opposed to 0 if this is an internal cleardown of a user
	{
	
		reply.p.ptype = ECONET_AUN_DATA;
		reply.p.port = reply_port;
		reply.p.ctrl = 0x80;
		reply.p.data[0] = reply.p.data[1] = 0;

		fs_aun_send(&reply, server, 2, net, stn);
	}
}

void fs_change_pw(int server, unsigned char reply_port, unsigned int userid, unsigned short net, unsigned short stn, unsigned char *params)
{
	char pw_cur[11], pw_new[13], pw_old[11]; // pw_new is 13 to cope with 10 character password in quotes
	int ptr;
	int new_ptr;

	if (users[server][userid].priv & FS_PRIV_NOPASSWORDCHANGE)
	{
		fs_error(server, reply_port, net, stn, 0xBA, "Insufficient privilege");
		return;
	}

	// Possibly replace with memcpy() ?
	strncpy((char * ) pw_cur, (const char * ) users[server][userid].password, 10);
	pw_cur[10] = '\0';

	// Find end of current password in params
	ptr = 0;
	while (ptr < strlen(params) && (ptr < 10) && *(params+ptr) != 0x0d && *(params+ptr) != ' ')
	{
		pw_old[ptr] = *(params+ptr);
		ptr++;
	}

	new_ptr = ptr; // Temp use of new_ptr
	while (new_ptr < 10) pw_old[new_ptr++] = ' ';

	pw_old[10] = '\0';

	if (ptr == strlen(params))
		fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
	else
	{

		uint8_t termination_char;

		new_ptr = 0;
		while (*(params+ptr) == ' ') ptr++; // Skip space
		//ptr++;

		// Copy new password
		while (ptr < strlen(params) && (*(params+ptr) != 0x0d) && (new_ptr < 12))
		{
			//fs_debug (0, 1, "Copying new password - ptr = %d, new_ptr = %d, character = %c", ptr, new_ptr, *(params+ptr));
			pw_new[new_ptr++] = *(params+ptr++);
		}

		termination_char = *(params+ptr);

		// If next character is not null and we have 10 characters then bad password

		if (new_ptr >= 10 && termination_char != 0x00) // The packet comes in with a 0x0d terminator, but the OSCLI (FSOp 0) command parser changes that to null termination
		{
			//fs_debug (0, 1, "Character at params+ptr = %d (%c), ptr = %d, new_ptr = %d", *(params+ptr), (*(params+ptr) < 32 || *(params+ptr) > 126) ? '.' : *(params+ptr) , ptr, new_ptr);
			fs_error(server, reply_port, net, stn, 0xFE, "Bad new password");
		}
		else
		{	
			for (; new_ptr < 12; new_ptr++)	pw_new[new_ptr] = ' ';

			pw_new[12] = '\0';

			// Strip quotes from new password if they are present

			if (pw_new[0] == '"' && strrchr(pw_new, '"') && strrchr(pw_new, '"') != &(pw_new[0])) // properly quoted password
			{
				uint8_t ctr = 1;
	
				while (ctr < 12)
				{
					pw_new[ctr-1] = pw_new[ctr];
					if (pw_new[ctr] == '"') 	pw_new[ctr-1] = ' ';
					ctr++;
				}

			}
			else if (pw_new[0] == '"') // Badly quoted password
			{
				fs_error(server, reply_port, net, stn, 0xB9, "Bad password");
				return;
			}


			if (	(*params == '\"' && *(params+1) == '\"' && !strcmp(pw_cur, "          "))    // Existing password blank and pass command starts with ""
				||	!strncasecmp((const char *) pw_cur, pw_old, 10))
			{
				unsigned char username[10];
				unsigned char blank_pw[11];
				
				strcpy ((char * ) blank_pw, (const char * ) "          ");

				// Correct current password
				if (!strncmp(pw_new, "\"\"        ", 10)) // user wants to change to blank password
					strncpy((char * ) users[server][userid].password, (const char * ) blank_pw, 10);
				else
					strncpy((char * ) users[server][userid].password, (const char * ) pw_new, 10);
				fs_write_user(server, userid, (char *) &(users[server][userid]));	
				fs_reply_success(server, reply_port, net, stn, 0, 0);
				strncpy((char * ) username, (const char * ) users[server][userid].username, 10);
				username[10] = 0;
				fs_debug (0, 1, "User %s changed password", username);
			}
			else	fs_error(server, reply_port, net, stn, 0xB9, "Bad password");
		}
	}

}

// Set boot option
void fs_set_bootopt(int server, unsigned char reply_port, unsigned int userid, unsigned short net, unsigned short stn, unsigned char *data)
{

	unsigned char new_bootopt;

	new_bootopt = *(data+5);

	if (new_bootopt > 7)
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Bad option");
		return;
	}

	fs_debug (0, 2, "%12sfrom %3d.%3d Set boot option %d", "", net, stn, new_bootopt);
	
	users[server][userid].bootopt = new_bootopt;
	active[server][fs_stn_logged_in(server,net,stn)].bootopt = new_bootopt;
	fs_write_user(server, userid, (char *) &(users[server][userid]));

	fs_reply_success(server, reply_port, net, stn, 0, 0);
	return;


}

void fs_login(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned char *command)
{

	char username[11];
	char password[11];

	unsigned short counter, stringptr;
	unsigned short found = 0;

	fs_toupper(command);
	memset (username, ' ', 10);
	memset (password, ' ', 10);

	stringptr = counter = 0; // Pointer in command now starts where the start of the username should be

	// Skip station number if provided

	if (isdigit(*command))
	{
		while ((*(command+stringptr) != ' ') && (stringptr < strlen(command))) stringptr++;
	}

	// Now skip any spaces
	while ((*(command+stringptr) == ' ') && (stringptr < strlen(command))) stringptr++;

	if (stringptr == strlen(command)) // Garbled *IAM
	{
		fs_error (server, reply_port, net, stn, 0xFF, "Garbled login command");
		return;
	}

	while (*(command + stringptr) != ' ' && *(command + stringptr) != 0 && (counter < 10))
	{
		username[counter] = *(command + stringptr);
		counter++;
		stringptr++;
	}

	username[10] = 0; // Terminate for logging purposes

	// Skip any whitespace
	while ((*(command + stringptr) == ' ') && (stringptr < strlen(command)))	stringptr++;

	if (*(command + stringptr) != 0) // There's a password too
	{
		unsigned short pw_counter = 0;

		//counter++;
	
		if (*(command + stringptr) == '"') stringptr++; // Skip any preliinary double quote

		while ((*(command + stringptr) != 0x00) && (pw_counter < 10) && (*(command + stringptr) != '"'))
		{
			password[pw_counter++] = *(command + stringptr);
			stringptr++;
		}

		for (; pw_counter < 10; pw_counter++) password[pw_counter] = ' ';
	}

	password[10] = 0; // Terminate for logging purposes

	counter = 0;

	while (counter < fs_stations[server].total_users && !found)
	{
		if (!strncasecmp(users[server][counter].username, username, 10) && (users[server][counter].priv != 0))
			found = 1;
		else
			counter++;
	}

	if (found)
	{
		if (strncasecmp((const char *) users[server][counter].password, password, 10))
		{
			fs_error(server, reply_port, net, stn, 0xBC, "Wrong password");
			fs_debug(0, 1, "            from %3d.%3d Login attempt - username '%s' - Wrong password", net, stn, username);
		}
		else if (users[server][counter].priv & FS_PRIV_LOCKED)
		{
			fs_error(server, reply_port, net, stn, 0xBC, "Account locked");
			fs_debug (0, 1, "           from %3d.%3d Login attempt - username '%s' - Account locked", net, stn, username);
		}
		else
		{
			int usercount = 0;
			short found = 0;	
			
			// Find a spare slot

			while (!found && (usercount < ECONET_MAX_FS_USERS))
			{
				if ((active[server][usercount].net == 0 && active[server][usercount].stn == 0) ||
				    (active[server][usercount].net == net && active[server][usercount].stn == stn)) // Allows us to overwrite an existing handle if the station is already logged in
					found = 1;
				else usercount++;
			}

			if (!found)
			{
				fs_debug (0, 1, "           from %3d.%3d Login attempt - username '%s' - server full", net, stn, username);
				fs_error(server, reply_port, net, stn, 0xB8, "Too many users");
			}
			else
			{
				short internal_handle; 
				char home[96], lib[96];
				struct path p;
				unsigned short count;

				struct __econet_packet_udp reply;

				if (fs_stn_logged_in(server, net, stn) != -1) // do a bye first
					fs_bye(server, reply_port, net, stn, 0);

				active[server][usercount].net = net;
				active[server][usercount].stn = stn;
				active[server][usercount].printer = 0xff; // No current printer selected
				active[server][usercount].userid = counter;
				active[server][usercount].bootopt = users[server][counter].bootopt;
				active[server][usercount].priv = users[server][counter].priv;
				active[server][usercount].userid = counter;
				active[server][usercount].current_disc = users[server][counter].home_disc; // Need to set here so that first normalize for URD works.

				for (count = 0; count < FS_MAX_OPEN_FILES; count++) active[server][usercount].fhandles[count].handle = -1; // Flag unused for files

				strncpy((char * ) home, (const char * ) users[server][counter].home, 96);
				home[96] = '\0';

				for (count = 0; count < 80; count++) if (home[count] == 0x20) home[count] = '\0'; // Remove spaces and null terminate

				if (home[0] == '\0')
				{
					sprintf(home, "$.%s", users[server][counter].username);
					home[80] = '\0';
					if (strchr(home, ' ')) *(strchr(home, ' ')) = '\0';
				}
				
				// First, user root

				if (!(fs_normalize_path(server, usercount, home, -1, &p)) || p.ftype == FS_FTYPE_NOTFOUND) // NOTE: because fs_normalize might look up current or home directory, home must be a complete path from $
				{
						unsigned short disc_count = 0;
						unsigned char tmp_path[1024];

						// If not found, have a look on the other discs
	
						while (disc_count < ECONET_MAX_FS_DISCS)
						{

							if (fs_discs[server][disc_count].name[0] != '\0') // Extant disc
							{
								sprintf(tmp_path, ":%s.%s", fs_discs[server][disc_count].name, home);
	
								if (!fs_normalize_path(server, usercount, tmp_path, -1, &p))
								{
									disc_count++;
								}
								else if (p.ftype != FS_FTYPE_DIR)
								{
									disc_count++;
								}
								else
									break;
							}
							else disc_count++;
						
						}
	
						if (disc_count == ECONET_MAX_FS_DISCS)
						{
							sprintf (tmp_path, ":%s.$", fs_discs[server][0].name);
							if (!(fs_normalize_path(server, usercount, tmp_path, -1, &p)) || p.ftype == FS_FTYPE_NOTFOUND) // Should NEVER happen....
							{
								fs_debug (0, 1, "%12sfrom %3d.%3d Login attempt - cannot find root dir %s", "", net, stn, home);
								fs_error (server, reply_port, net, stn, 0xFF, "Unable to map root.");
								active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
							}
						}
				}
						
				if (p.ftype != FS_FTYPE_DIR) // Root wasn't a directory!
				{
					fs_error (server, reply_port, net, stn, 0xA8, "Bad root directory.");
					active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
				}
					
				active[server][usercount].current_disc = p.disc; // Updated here once we know where the URD is for definite.

				if (fs_config[server].fs_acorn_home)
				{
					struct objattr oa;

					fs_read_xattr(p.unixpath, &oa, server);

					if (oa.homeof == 0)
						fs_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, active[server][usercount].userid, server);
				}

				internal_handle = fs_open_interlock(server, p.unixpath, 1, active[server][usercount].userid);

				if ((active[server][usercount].root = fs_allocate_user_dir_channel(server, usercount, internal_handle)) == 0) // Can't allocate
				{
					fs_error (server, reply_port, net, stn, 0xDE, "Root directory channel ?");
					fs_close_interlock(server, internal_handle, 1);
					active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
				}

				fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, active[server][usercount].root, internal_handle);
				strcpy(active[server][usercount].fhandles[active[server][usercount].root].acornfullpath, p.acornfullpath);
				fs_store_tail_path(active[server][usercount].fhandles[active[server][usercount].root].acorntailpath, p.acornfullpath);
				active[server][usercount].fhandles[active[server][usercount].root].mode = 1;

				snprintf(active[server][usercount].root_dir, 2600, "$.%s", p.path_from_root); // Was 260 

				if (p.npath == 0)	sprintf(active[server][usercount].root_dir_tail, "$         ");
				else			sprintf(active[server][usercount].root_dir_tail, "%-80s", p.path[p.npath-1]); // WAS 10

				// Just set CWD to URD

				internal_handle = fs_open_interlock(server, p.unixpath, 1, active[server][usercount].userid);

				if ((active[server][usercount].current = fs_allocate_user_dir_channel(server, usercount, internal_handle)) == 0) // Can't allocate a second handle for CWD on the root internal_handle
				{

					fs_error (server, reply_port, net, stn, 0xA8, "Can't map CWD!");
					active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
					fs_close_interlock(server, active[server][usercount].fhandles[active[server][usercount].root].handle, 1); // Close the old root directory
					fs_close_interlock(server, internal_handle, 1); // Close the CWD handle
					fs_deallocate_user_dir_channel(server, usercount, active[server][usercount].root);
					return;
				}

				fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, active[server][usercount].current, internal_handle);

				strcpy(active[server][usercount].fhandles[active[server][usercount].current].acornfullpath, p.acornfullpath);
				fs_store_tail_path(active[server][usercount].fhandles[active[server][usercount].current].acorntailpath, p.acornfullpath);
				active[server][usercount].fhandles[active[server][usercount].current].mode = 1;

				// Next, Library

				if (users[server][counter].lib[0] != '\0')
					strncpy((char * ) lib, (const char * ) users[server][counter].lib, 96);
				else	strcpy((char *) lib, "$.Library");

				lib[96] = '\0';
				for (count = 0; count < 80; count++) if (lib[count] == 0x20) lib[count] = '\0'; // Remove spaces and null terminate

				if (!fs_normalize_path(server, usercount, lib, -1, &p) || p.ftype != FS_FTYPE_DIR) // NOTE: because fs_normalize might look up current or home directory, home must be a complete path from $
				{

					// TODO - Search across all discs here

					// In default, go for root on disc 0

					fs_debug (0, 1, "%12sfrom %3d.%3d Login attempt - cannot find lib dir %s", "", net, stn, lib);
					if (!fs_normalize_path(server, usercount, "$", -1, &p)) // Use root as library directory instead
					{
						fs_error (server, reply_port, net, stn, 0xA8, "Unable to map library");
						active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
					}

				}
						
				if (p.ftype != FS_FTYPE_DIR) // Libdir wasn't a directory!
				{
					fs_error (server, reply_port, net, stn, 0xA8, "Bad library directory.");
					active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
				}
					
				internal_handle = fs_open_interlock(server, p.unixpath, 1, active[server][usercount].userid);

				if ((active[server][usercount].lib = fs_allocate_user_dir_channel(server, usercount, internal_handle)) == 0) // Can't allocate
				{
					fs_error (server, reply_port, net, stn, 0xDE, "Library dir channel ?");
					//fs_close_dir_handle(server, internal_handle);
					fs_close_interlock(server, internal_handle, 1);
					fs_close_interlock(server, active[server][usercount].fhandles[active[server][usercount].root].handle, 1);
					fs_close_interlock(server, active[server][usercount].fhandles[active[server][usercount].current].handle, 1);
					fs_deallocate_user_dir_channel(server, usercount, active[server][usercount].root);	
					fs_deallocate_user_dir_channel(server, usercount, active[server][usercount].current);	
					active[server][usercount].net = 0; active[server][usercount].stn = 0; return;
				}

				fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, active[server][usercount].lib, internal_handle);
				strcpy(active[server][usercount].fhandles[active[server][usercount].lib].acornfullpath, p.acornfullpath);
				fs_store_tail_path(active[server][usercount].fhandles[active[server][usercount].lib].acorntailpath, p.acornfullpath);
				active[server][usercount].fhandles[active[server][usercount].lib].mode = 1;

				strncpy((char * ) active[server][usercount].lib_dir, (const char * ) p.path_from_root, 255);
				if (p.npath == 0)
					strcpy((char * ) active[server][usercount].lib_dir_tail, (const char * ) "$         ");
				else
					sprintf(active[server][usercount].lib_dir_tail, "%-80s", p.path[p.npath-1]); // WAS 10

				fs_debug (0, 1, "            from %3d.%3d Login as %s, index %d, id %d, disc %d, URD %s, CWD %s, LIB %s, priv 0x%02x", net, stn, username, usercount, active[server][usercount].userid, active[server][usercount].current_disc, home, home, lib, active[server][usercount].priv);

				// Tell the station
			
				reply.p.ptype = ECONET_AUN_DATA;
				reply.p.port = reply_port;
				reply.p.ctrl = 0x80;
				reply.p.pad = 0x00;
				//reply.p.seq = (fs_stations[server].seq += 4);
				reply.p.seq = get_local_seq(fs_stations[server].net, fs_stations[server].stn);
				reply.p.data[0] = 0x05;
				reply.p.data[1] = 0x00;
				reply.p.data[2] = FS_MULHANDLE(active[server][usercount].root);
				reply.p.data[3] = FS_MULHANDLE(active[server][usercount].current);
				reply.p.data[4] = FS_MULHANDLE(active[server][usercount].lib);
				reply.p.data[5] = active[server][usercount].bootopt;
				
				fs_aun_send(&reply, server, 6, net, stn);
			}
		}

	}
	else
	{
		fs_debug (0, 1, "            from %3d.%3d Login attempt - username '%s' - Unknown user", net, stn, username);
		fs_error(server, reply_port, net, stn, 0xBC, "User not known");
	}

}

void fs_read_user_env(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned int active_id)
{

	struct __econet_packet_udp r;
	int replylen = 0, count, termfound;
	unsigned short disclen;

	fs_debug (0, 2, "%12sfrom %3d.%3d Read user environment - current user handle %d, current lib handle %d", "", net, stn, active[server][active_id].current, active[server][active_id].lib);

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;

	r.p.data[replylen++] = 0;
	r.p.data[replylen++] = 0;

	// If either current or library handle is invalid, barf massively.

	//fs_debug (0, 2, "Current.is_dir = %d, handle = %d, Lib.is_dir = %d, handle = %d\n", active[server][active_id].fhandles[active[server][active_id].current].is_dir, active[server][active_id].fhandles[active[server][active_id].current].handle, active[server][active_id].fhandles[active[server][active_id].lib].is_dir, active[server][active_id].fhandles[active[server][active_id].lib].handle);

	if (!(active[server][active_id].fhandles[active[server][active_id].current].is_dir) ||
	    !(active[server][active_id].fhandles[active[server][active_id].lib].is_dir) ||
	    (active[server][active_id].fhandles[active[server][active_id].current].handle == -1) ||
	    (active[server][active_id].fhandles[active[server][active_id].lib].handle == -1))
	{
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
		return;
	}

	disclen = r.p.data[replylen++] = 16; // strlen(fs_discs[server][active[server][active_id].disc].name);

	sprintf (&(r.p.data[replylen]), "%-16s", fs_discs[server][active[server][active_id].current_disc].name);

	replylen += disclen;

	memcpy(&(r.p.data[replylen]), &(active[server][active_id].fhandles[active[server][active_id].current].acorntailpath), 10);
	termfound = 0;
	for (count = 0; count < 10; count++)
		if (termfound || r.p.data[replylen+count] == 0) 
		{
			r.p.data[replylen+count] = ' ';
			termfound = 1;
		}

	//snprintf (&(r.p.data[replylen]), 10, "%-10s", active[server][active_id].fhandles[active[server][active_id].current].acorntailpath);
	//sprintf (&(r.p.data[replylen]), "%-10s", active[server][active_id].current_dir_tail);
	replylen += 10;

	memcpy(&(r.p.data[replylen]), &(active[server][active_id].fhandles[active[server][active_id].lib].acorntailpath), 10);
	termfound = 0;
	for (count = 0; count < 10; count++)
		if (termfound || r.p.data[replylen+count] == 0)
		{
			r.p.data[replylen+count] = ' ';
			termfound = 1;
		}

	//snprintf (&(r.p.data[replylen]), 10, "%-10s", active[server][active_id].fhandles[active[server][active_id].lib].acorntailpath);
	//sprintf (&(r.p.data[replylen]), "%-10s", active[server][active_id].lib_dir_tail);
	replylen += 10;

	fs_aun_send (&r, server, replylen, net, stn);
	
}

void fs_examine(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned char *data, unsigned int datalen)
{
	unsigned short relative_to, arg, start, n;
	unsigned char path[1024]; // Was 256 before long filenames
	struct path p;
	struct path_entry *e;
	struct __econet_packet_udp r;
	int replylen, replyseglen;
	unsigned short examined, dirsize;
	// Next 4 lines only used in the old non-wildcard code
	//DIR *d;
	//struct dirent *entry;
	//struct objattr attr;
	//char unixpath[1024];
	char acornpathfromroot[1024];

	relative_to = *(data+3);
	arg = (char) *(data+5);
	start = (char) *(data+6);
	n = (char) *(data+7);

	fs_copy_to_cr(path, (data + 8), 255);

	/* This next bit looks like rubbish

	if (arg == 2) // If arg = 2, it looks like the path to examine starts at data + 9 and ends with the end of the packet, not 0x0d
	{
		unsigned short p;

		strncpy(path, (data + 9), datalen - 9);
		path[datalen - 9] = '\0';	
		// But sometimes it sticks 0x0d on the end
		// So ferret it out and remove

		p = 0;
	
		while (p <= datalen - 9)
		{
			if (path[p] == 0x0d) path[p] = '\0';
			p++;
		}
		
	}

	*/

	fs_debug (0, 2, "%12sfrom %3d.%3d Examine %s relative to %d, start %d, extent %d, arg = %d", "", net, stn, path,
		relative_to, start, n, arg);

	if (!fs_normalize_path_wildcard(server, active_id, path, relative_to, &p, 1) || p.ftype == FS_FTYPE_NOTFOUND)
	{

		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;

/*

		struct __econet_packet_udp reply;
	
		reply.p.ptype = ECONET_AUN_DATA;
		reply.p.port = reply_port;
		reply.p.ctrl = 0x80;
		reply.p.data[0] = reply.p.data[1] = reply.p.data[2] = 0; // This is apparently how you flag not found on an examine...
	
		fs_aun_send(&reply, server, 2, net, stn);
		return;
*/
	}

	// Add final entry onto path_from_root (because normalize doesn't do it on a wildcard call)

	if (strlen(p.path_from_root) != 0)
		strcat(p.path_from_root, ".");
	if (p.paths != NULL)
		strcat (p.path_from_root, p.paths->acornname);

	fs_free_wildcard_list(&p); // We'll just use the first one it found, which will be in the main path struct

	if (p.ftype != FS_FTYPE_DIR)
	{
		fs_error(server, reply_port, net, stn, 0xAF, "Types don't match");
		return;
	}

	replylen = 0;

	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;

	r.p.data[replylen++] = 0;
	r.p.data[replylen++] = 0;
	
	examined = r.p.data[replylen++] = 0; // Repopulate data[2] at end
	dirsize = r.p.data[replylen++] = 0; // Dir size (but this might be wrong). Repopulate later if correct

	// Wildcard code
	strcpy(acornpathfromroot, path);
	if (strlen(acornpathfromroot) != 0) strcat(acornpathfromroot, ".");
	strcat(acornpathfromroot, "*"); // It should already have $ on it if root.

	// Wildcard renormalize - THE LONG FILENAMES MODS CAUSE THIS TO RETURN NOT FOUND ON AN EMPTY DIRECTORY
	if (!fs_normalize_path_wildcard(server, active_id, acornpathfromroot, relative_to, &p, 1)) // || p.ftype == FS_FTYPE_NOTFOUND)
	{
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;
	}

	e = p.paths;
	while (dirsize < start && (e != NULL))
	{
		if ((e->perm & FS_PERM_H) == 0 || (e->owner == active[server][active_id].userid)) // not hidden
			dirsize++;
		e = e->next;
	}

/* This is wrong. FS3 puts out 27 bytes per entry. If we put the cycle number in each time, it's 28.
	if (arg == 0) // Looks like the cycle number gets repeated in arg=0 replies
		replylen--;
*/

	/* Add a check here to make sure we don't tip over a 255 byte packet */

	switch (arg)
	{
		case 0:	replyseglen = 27; break;
		case 1: replyseglen = ECONET_MAX_FILENAME_LENGTH + 57; break;
		case 2: replyseglen = ECONET_MAX_FILENAME_LENGTH + 1; break;
		case 3: replyseglen = ECONET_MAX_FILENAME_LENGTH + 9; break;
	}

	while (examined < n && (e != NULL) && (replylen < (255-replyseglen)))
	{	
		//fs_debug (0, 3, "Examining '%s'", e->acornname);

		if ((e->perm & FS_PERM_H) == 0 || (e->owner == active[server][active_id].userid)) // not hidden or we are the owner
		{
			switch (arg)
			{
				case 0: // Machine readable format
				{

					int le_count;

					//r.p.data[replylen++] = examined; // "Cycle number";	
					snprintf(&(r.p.data[replylen]), 11, "%-10.10s", e->acornname); // 11 because the 11th byte (null) gets overwritten two lines below because we only add 10 to replylen.
					replylen += 10;

					for (le_count = 0; le_count <= 3; le_count++)
					{
						r.p.data[replylen + le_count] = ((e->ftype == FS_FTYPE_DIR ? 0 : htole32(e->load)) >> (8 * le_count)) & 0xff;
						r.p.data[replylen + 4 + le_count] = ((e->ftype == FS_FTYPE_DIR ? 0 : htole32(e->exec)) >> (8 * le_count)) & 0xff;
					}

					replylen += 8; // Skip past the load / exec that we just filled in

					r.p.data[replylen++] = fs_perm_to_acorn(server, e->perm, e->ftype);
					r.p.data[replylen++] = e->day;
					r.p.data[replylen++] = e->monthyear;

					if (fs_config[server].fs_sjfunc) // Next three bytes are ownership information - main & aux. We always set aux to 0 for now.
					{
						r.p.data[replylen++] = (e->owner & 0xff);
						r.p.data[replylen++] = ((e->owner & 0x700) >> 3);
						r.p.data[replylen++] = 0; // Aux account number	
					}
					else
					{
						r.p.data[replylen++] = e->internal & 0xff;
						r.p.data[replylen++] = (e->internal & 0xff00) >> 8;
						r.p.data[replylen++] = (e->internal & 0xff0000) >> 16;
					}

					if (e->ftype == FS_FTYPE_DIR)	e->length = 0x200; // Dir length in FS3
					r.p.data[replylen++] = e->length & 0xff;
					r.p.data[replylen++] = (e->length & 0xff00) >> 8;
					r.p.data[replylen++] = (e->length & 0xff0000) >> 16;
				} break;
				case 1: // Human readable format
				{
					unsigned char tmp[256];
					unsigned char permstring_l[10], permstring_r[10];
					unsigned char hr_fmt_string[80];
	
					sprintf(permstring_l, "%s%s%s%s",
						(e->ftype == FS_FTYPE_DIR ? "D" : e->ftype == FS_FTYPE_SPECIAL ? "S" : ""),
						((e->perm & FS_PERM_L) ? "L" : ""),
						((e->perm & FS_PERM_OWN_W) ? "W" : ""),
						((e->perm & FS_PERM_OWN_R) ? "R" : "") );

					sprintf(permstring_r, "%s%s", 
						((e->perm & FS_PERM_OTH_W) ? "W" : ""),
						((e->perm & FS_PERM_OTH_R) ? "R" : "") );

					sprintf (hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX   %%4s/%%-2s     %%02d/%%02d/%%02d %%06lX", ECONET_MAX_FILENAME_LENGTH);

					//sprintf (tmp, "%-10s %08lX %08lX   %06lX   %4s/%-2s     %02d/%02d/%02d %06lX", 
					sprintf (tmp, hr_fmt_string, 
						e->acornname,
						e->load, e->exec, e->length,
						permstring_l, permstring_r,
						fs_day_from_two_bytes(e->day, e->monthyear),
						fs_month_from_two_bytes(e->day, e->monthyear),
						fs_year_from_two_bytes(e->day, e->monthyear),
						e->internal
						);
						
					strcpy((char * ) &(r.p.data[replylen]), (const char * ) tmp);
					replylen += strlen(tmp);
					r.p.data[replylen++] = '\0';

				} break;
				case 2: // 10 character filename format (short)
				{
					unsigned char hr_fmt_string[20];

					sprintf(hr_fmt_string, "%%-%d.%ds", ECONET_MAX_FILENAME_LENGTH, ECONET_MAX_FILENAME_LENGTH);

					//r.p.data[replylen++] = 0x0a;
					r.p.data[replylen++] = ECONET_MAX_FILENAME_LENGTH;
					//sprintf((char *) &(r.p.data[replylen]), "%-10.10s", e->acornname);
					sprintf((char *) &(r.p.data[replylen]), hr_fmt_string, e->acornname);
					//replylen += 10;
					replylen += ECONET_MAX_FILENAME_LENGTH;

				} break;
				case 3: // 10 character filename format (long) - this can only do 10 characters according to the spec, but FS4 exceeds this, and it causes problems with RISC OS but Acorn didn't seem that bothered...!
				{
					char tmp[256];
					char permstring_l[10], permstring_r[10];
					//unsigned char hr_fmt_string[20];

					sprintf(permstring_l, "%s%s%s%s",
						(e->ftype == FS_FTYPE_DIR ? "D" : e->ftype == FS_FTYPE_SPECIAL ? "S" : ""),
						((e->perm & FS_PERM_L) ? "L" : ""),
						((e->perm & FS_PERM_OWN_W) ? "W" : ""),
						((e->perm & FS_PERM_OWN_R) ? "R" : "") );

					sprintf(permstring_r, "%s%s", 
						((e->perm & FS_PERM_OTH_W) ? "W" : ""),
						((e->perm & FS_PERM_OTH_R) ? "R" : "") );

					//sprintf (hr_fmt_string, "%%-%ds %%4s/%%-2s", ECONET_MAX_FILENAME_LENGTH);
					//sprintf (tmp, hr_fmt_string, e->acornname,

					//if (strlen(e->acornname) > 10) e->acornname[10] = 0; // Limit to 10 chars
					sprintf (tmp, "%-10s %4s/%-2s", e->acornname,
						permstring_l, permstring_r
					);
					strcpy((char * ) &(r.p.data[replylen]), (const char * ) tmp);
					//fprintf (stderr, "hr_fmt_string = '%s', tmp = '%s', r.p.data[replylen] = '%s'\n", hr_fmt_string, tmp, (char *) &(r.p.data[replylen]));
					replylen += strlen(tmp) + 1; // +1 for the 0 byte
				} break;
			}
			examined++;
			dirsize++;
		}

		e = e->next;

	}

	fs_free_wildcard_list(&p);

// OLD non-wildcard code
/*

	if (!(d = opendir(p.unixpath)))
	{
		fs_error(server, reply_port, net, stn, 0xA8, "Broken dir");
		return;
	}

	// Skip to start entry

	while ((dirsize < start) && (entry = readdir(d)))
	{
		// Ignore special files
		if ((strlen(entry->d_name) <= 10) && (strcmp(entry->d_name, ".")) && (strcmp(entry->d_name, "..")) && strcasecmp(entry->d_name, "lost+found"))
		{
			strcpy((char * ) unixpath, (const char * ) p.unixpath);
			strcat(unixpath, "/");
			strcat(unixpath, entry->d_name);	

			fs_read_xattr(unixpath, &attr);

			if ((attr.perm & FS_PERM_H) == 0 || (attr.owner == active[server][active_id].userid)) // not hidden
				dirsize++;
		}
	}


	while ((examined < n) && (entry = readdir(d)))
	{
		struct path file;
		char acorn_name[11];
		char fullpath[1024];

		if ((strlen(entry->d_name) <= 10) && (strcmp(entry->d_name, ".")) && (strcmp(entry->d_name, "..")) && strcasecmp(entry->d_name, "lost+found"))
		{
			strncpy ((char * ) acorn_name, (const char * ) entry->d_name, 10);
			fs_unix_to_acorn(acorn_name); // Starts in unix format; this puts it into acorn format, as the variable name suggests.
	
			sprintf(fullpath, ":%s.%s%s%s", p.discname, p.path_from_root, (p.npath > 0) ? "." : "", acorn_name);

			if (!fs_normalize_path(server, active_id, fullpath, -1, &file))
			{
				fs_error(server, reply_port, net, stn, 0xA8, "Broken dir");
				closedir(d);
				return;
			}

			if ((file.perm & FS_PERM_H) == 0 || (file.owner == active[server][active_id].userid)) // not hidden or we are the owner
			{
				switch (arg)
				{
					case 0: // Machine readable format
					{
						r.p.data[replylen] = htole32(file.load); replylen += 4;
						r.p.data[replylen] = htole32(file.exec); replylen += 4;
						r.p.data[replylen++] = file.perm;
						r.p.data[replylen++] = file.day;
						r.p.data[replylen++] = file.monthyear;
						r.p.data[replylen++] = file.internal & 0xff;
						r.p.data[replylen++] = (file.internal & 0xff00) >> 8;
						r.p.data[replylen++] = (file.internal & 0xff0000) >> 16;
						r.p.data[replylen++] = file.length & 0xff;
						r.p.data[replylen++] = (file.length & 0xff00) >> 8;
						r.p.data[replylen++] = (file.length & 0xff0000) >> 16;
					} break;
					case 1: // Human readable format
					{
						unsigned char tmp[256];
						unsigned char permstring_l[10], permstring_r[10];
		
						sprintf(permstring_l, "%s%s%s%s",
							(file.ftype == FS_FTYPE_DIR ? "D" : file.ftype == FS_FTYPE_SPECIAL ? "S" : ""),
							((file.perm & FS_PERM_L) ? "L" : ""),
							((file.perm & FS_PERM_OWN_W) ? "W" : ""),
							((file.perm & FS_PERM_OWN_R) ? "R" : "") );

						sprintf(permstring_r, "%s%s", 
							((file.perm & FS_PERM_OTH_W) ? "W" : ""),
							((file.perm & FS_PERM_OTH_R) ? "R" : "") );

						sprintf (tmp, "%-10s %08lX %08lX   %06lX   %4s/%-2s     %02d/%02d/%02d %06lX", (file.npath == 0) ? (char *) "$" : (char *) file.path[file.npath - 1],
							file.load, file.exec, file.length,
							permstring_l, permstring_r,
							file.day, file.monthyear & 0x0f, ((file.monthyear & 0xf0) >> 4) + 81,
							file.internal
							);
							
						strcpy((char * ) &(r.p.data[replylen]), (const char * ) tmp);
						replylen += strlen(tmp);
						r.p.data[replylen++] = '\0';

					} break;
					case 2: // 10 character filename format (short)
					{
						r.p.data[replylen++] = 0x0a;
						sprintf((char *) &(r.p.data[replylen]), "%-10s", (file.npath == 0) ? (char *) "$" : (char *) file.path[file.npath - 1]);
						replylen += 10;

					} break;
					case 3: // 10 character filename format (long)
					{
						char tmp[256];
						char permstring_l[10], permstring_r[10];

						sprintf(permstring_l, "%s%s%s%s",
							(file.ftype == FS_FTYPE_DIR ? "D" : file.ftype == FS_FTYPE_SPECIAL ? "S" : ""),
							((file.perm & FS_PERM_L) ? "L" : ""),
							((file.perm & FS_PERM_OWN_W) ? "W" : ""),
							((file.perm & FS_PERM_OWN_R) ? "R" : "") );

						sprintf(permstring_r, "%s%s", 
							((file.perm & FS_PERM_OTH_W) ? "W" : ""),
							((file.perm & FS_PERM_OTH_R) ? "R" : "") );

						sprintf (tmp, "%-10s %4s/%-2s", (file.npath == 0) ? (char *) "$" : (char *) file.path[file.npath - 1],
							permstring_l, permstring_r
						);
						strcpy((char * ) &(r.p.data[replylen]), (const char * ) tmp);
						replylen += strlen(tmp) + 1; // +1 for the 0 byte
					} break;
				}
				examined++;
				dirsize++;
			}

		}

	}

	while ((entry = readdir(d))) // Count any remaining entries
	{

		if ((strcmp(entry->d_name, ".")) && (strcmp(entry->d_name, "..")))
		{
			strcpy((char * ) unixpath, (const char * ) p.unixpath);
			strcat(unixpath, "/");
			strcat(unixpath, entry->d_name);	
			fs_read_xattr(unixpath, &attr);

			if ((attr.perm & FS_PERM_H) == 0) // not hidden
				dirsize++;
		}
	}
*/	
	r.p.data[replylen++] = 0x80;
	r.p.data[2] = (examined & 0xff);
	r.p.data[3] = (dirsize & 0xff); // Can't work out how L3 is calculating this number

/* OLD non-wildcard code
	closedir (d);
*/

	fs_aun_send(&r, server, replylen, net, stn);

}

void fs_set_object_info(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned char *data, unsigned int datalen)
{

	unsigned short relative_to;

	struct __econet_packet_udp r;

	unsigned short command;

	char path[1024];

	unsigned short filenameposition;
		
	struct path p;

	command = *(data+5);
	relative_to = *(data+3);

	if (command == 0x40 && !(fs_config[server].fs_sjfunc))
	{
		fs_error(server, reply_port, net, stn, 0xff, "MDFS Unsupported");
		return;
	}

	switch (command)
	{
		case 1: filenameposition = 15; break;
		case 4: filenameposition = 7; break;
		case 2: // Fall through
		case 3: filenameposition = 10; break;
		case 5: filenameposition = 8; break;
		case 0x40: filenameposition = 16; *(data+datalen) = 0x0d; break; // Artificially terminate the filename on a 0x40 call - clients don't seem to
		default:
			fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
			return;
			break;
	}

	fs_copy_to_cr(path, (data+filenameposition), 1023);

	if (command != 4)
		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d", "", net, stn, path, relative_to == active[server][active_id].root ? "Root" : relative_to == active[server][active_id].lib ? "Library" : "Current", command);
	else
		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d, attribute &%02X", "", net, stn, path, relative_to == active[server][active_id].root ? "Root" : relative_to == active[server][active_id].lib ? "Library" : "Current", command, (*(data + 6)));
	
	if (!fs_normalize_path(server, active_id, path, relative_to, &p) || p.ftype == FS_FTYPE_NOTFOUND)
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	else if (((active[server][active_id].priv & FS_PRIV_SYSTEM) == 0) && 
			(p.owner != active[server][active_id].userid) &&
			(p.parent_owner != active[server][active_id].userid)
		)
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
	else if (command != 1 && command != 4 && (p.perm & FS_PERM_L)) // Locked
	{
		fs_error(server, reply_port, net, stn, 0xC3, "Locked");
	}
	else
	{
		struct objattr attr;
	
		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = reply_port;
		r.p.ctrl = 0x80;
		r.p.data[0] = r.p.data[1] = 0;

		fs_read_xattr(p.unixpath, &attr, server);

		switch (command)
		{
			case 1: // Set Load, Exec & Attributes
			
				attr.load = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				attr.exec = (*(data+10)) + (*(data+11) << 8) + (*(data+12) << 16) + (*(data+13) << 24);
				// We need to make sure our bitwise stuff corresponds with Acorns before we do this...
				attr.perm = fs_perm_from_acorn(server, *(data+14)) | ((*(data+14) & 0x0c) == 0) ? (FS_PERM_OWN_W | FS_PERM_OWN_R) : 0;
				break;
			
			case 2: // Set load address
				attr.load = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				break;

			case 3: // Set exec address
				attr.exec = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				break;
	
			case 4: // Set attributes only
				// Need to convert acorn to PiFS
				attr.perm = fs_perm_from_acorn(server, *(data+6)) | (((*(data+6) & 0x0c) == 0) ? (FS_PERM_OWN_W | FS_PERM_OWN_R) : 0);
				break;

			case 5: // Set file date
				{
					// There should be, in *(data+6, 7) a two byte date.
					// We'll implement this later
					// No - Linux has no means of changing the creation date - we might need to look at putting this in xattrs / dotfiles!
				}
				break;
			case 0x40: // MDFS set update, create date & time
				{
					// TODO: Implement this.
					// Nothing for now
				}

			// No default needed - we caught it above
		}

		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d, writing to path %s, owner %04X, perm %02X, load %08X, exec %08X, homeof %04X", "", net, stn, path, relative_to == active[server][active_id].root ? "Root" : relative_to == active[server][active_id].lib ? "Library" : "Current", command, p.unixpath, attr.owner, attr.perm, attr.load, attr.exec, attr.homeof);
		fs_write_xattr(p.unixpath, attr.owner, attr.perm, attr.load, attr.exec, attr.homeof, server);

		// If we get here, we need to send the reply

		fs_aun_send(&r, server, 2, net, stn);

	}
}

int fs_scandir_regex(const struct dirent *d)
{

	return (((strcasecmp(d->d_name, "lost+found") == 0) || (regexec(&r_wildcard, d->d_name, 0, NULL, 0) != 0)) ? 0 : 1); // regexec returns 0 on match, so we need to return 0 (no match) if it returns other than 0.

}

// Frees up malloc'd dirent entries from scandir
void fs_free_dirent(struct dirent **list, int entries)
{

	while (entries--)
		free(list[entries]);

	free(list);

}

// Counts number of Acorn-compatible entries in unixpath.
// Returns the number found, or -1 for failure

short fs_get_acorn_entries(int server, int active_id, char *unixpath)
{

	int entries;
	char regex[1024];
	struct dirent **list;

	if (fs_config[server].fs_infcolon)
		sprintf(regex, "^(%s{1,%d})", FSDOTREGEX, ECONET_MAX_FILENAME_LENGTH);
	else
		sprintf(regex, "^(%s{1,%d})", FSREGEX, ECONET_MAX_FILENAME_LENGTH);

	if (regcomp(&r_wildcard, regex, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) // We go extended expression, case insensitive and we aren't bothered about finding *where* the matches are in the string
		return -1; // Regex failure!

	entries = scandir(unixpath, &list, fs_scandir_regex, fs_alphacasesort);

	if (entries == -1) // Failure
		return -1;

	fs_free_dirent(list, entries); // De-malloc everything

	regfree (&r_wildcard);

	return entries;

}

void fs_get_object_info(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned char *data, unsigned int datalen)
{

	unsigned short replylen = 0, relative_to;

	struct __econet_packet_udp r;

	unsigned short command;
	

	unsigned short norm_return;
	char path[1024];
		
	struct path p;

	command = *(data+5);
	relative_to = *(data+3);

	memset(r.p.data, 0, 30);
	r.p.port = reply_port;
	r.p.ctrl = 0;
	r.p.ptype = ECONET_AUN_DATA;

	// Use replylen as a temporary counter

	while (replylen < 1024 && *(data+(command != 3 ? 6 : 10)+replylen) != 0x0d)
	{
		path[replylen] = *(data+(command != 3 ? 6 : 10)+replylen);
		replylen++;
	}

	path[replylen] = '\0'; // Null terminate instead of 0x0d in the packet

	fs_debug (0, 2, "%12sfrom %3d.%3d Get Object Info %s relative to %02X, command %d", "", net, stn, path, relative_to, command);

	norm_return = fs_normalize_path_wildcard(server, active_id, path, relative_to, &p, 1);

	fs_free_wildcard_list(&p); // Not interested in anything but first entry, which will be in main struct

	if (!norm_return && (p.error != FS_PATH_ERR_NODIR))
	{
		fs_error(server, reply_port, net, stn, 0xcc, "Bad filename");
		return;
	}

	if ((!norm_return && p.error == FS_PATH_ERR_NODIR) || (/* norm_return && */ p.ftype == FS_FTYPE_NOTFOUND))
	{
		struct __econet_packet_udp reply;
	
		reply.p.ptype = ECONET_AUN_DATA;
		reply.p.port = reply_port;
		reply.p.ctrl = 0x80;
		reply.p.data[0] = reply.p.data[1] = 0; // This is apparently how you flag not found on an examine...
		if (command == 6) // Longer error block
		{
			fs_error(server, reply_port, net, stn, 0xd6, "Not found");
		}
		else
		{
			reply.p.data[2] = 0; // not found.
			fs_aun_send(&reply, server, 3, net, stn); // This will return a single byte of &00, which from the MDFS spec means 'not found' for arg = 1-5. 6 returns a hard error it seems.
		}
		return;

	}

	replylen = 0; // Reset after temporary use above

	r.p.data[replylen++] = 0;
	r.p.data[replylen++] = 0;
	r.p.data[replylen++] = p.ftype;

	if (command == 2 || command == 5)
	{
		r.p.data[replylen++] = (p.load & 0xff);
		r.p.data[replylen++] = (p.load & 0xff00) >> 8;
		r.p.data[replylen++] = (p.load & 0xff0000) >> 16;
		r.p.data[replylen++] = (p.load & 0xff000000) >> 24;
		r.p.data[replylen++] = (p.exec & 0xff);
		r.p.data[replylen++] = (p.exec & 0xff00) >> 8;
		r.p.data[replylen++] = (p.exec & 0xff0000) >> 16;
		r.p.data[replylen++] = (p.exec & 0xff000000) >> 24;
	}

	if (command == 3 || command == 5)
	{
		r.p.data[replylen++] = (p.length & 0xff);
		r.p.data[replylen++] = (p.length & 0xff00) >> 8;
		r.p.data[replylen++] = (p.length & 0xff0000) >> 16;
	}

	if (command == 4 || command == 5)
		r.p.data[replylen++] = fs_perm_to_acorn(server, p.perm, p.ftype);

	if (command == 1 || command == 5)
	{
		r.p.data[replylen++] = p.day;
		r.p.data[replylen++] = p.monthyear;
	}

	if (/* command == 4 || */ command == 5) // arg 4 doesn't request owner
		r.p.data[replylen++] = (active[server][active_id].userid == p.owner) ? 0x00 : 0xff; 

	if (command == 6)
	{
		
		// unsigned char hr_fmt_string[10];

		if (p.ftype != FS_FTYPE_DIR)
		{
			fs_error(server, reply_port, net, stn, 0xAF, "Types don't match");
			return;
		}

		r.p.data[replylen++] = 0; // Undefined on this command
		//r.p.data[replylen++] = 10; // Dir name length
		//r.p.data[replylen++] = ECONET_MAX_FILENAME_LENGTH; // Dir name length - 20231230 This is meant to be 0!
		r.p.data[replylen++] = 0; // Undefined on this command

		memset ((char *) &(r.p.data[replylen]), 32, ECONET_MAX_FILENAME_LENGTH); // Pre-fill with spaces in case this is the root dir
	
		if (p.npath == 0) // Root
		{
			//strncpy((char * ) &(r.p.data[replylen]), (const char * ) "$         ", 11);
			r.p.data[replylen] = '$';
			r.p.data[replylen+ECONET_MAX_FILENAME_LENGTH+1] = '\0';
		}
		else
		{
			unsigned char	shortname[11];

			memcpy(shortname, p.acornname, 10);
			shortname[10] = '\0';

			// sprintf (hr_fmt_string, "%%-%ds", ECONET_MAX_FILENAME_LENGTH); // This format can only take a maximum of 10 chars (FS Op 18 arg 6)
			snprintf(&(r.p.data[replylen]), 11, "%-10s", (const char * ) shortname);
			//snprintf(&(r.p.data[replylen]), ECONET_MAX_FILENAME_LENGTH+1, hr_fmt_string, (const char * ) p.acornname);
		}

		replylen += 10;
		//replylen += ECONET_MAX_FILENAME_LENGTH;

		r.p.data[replylen++] = (active[server][active_id].userid == p.owner) ? 0x00 : 0xff; 

		r.p.data[replylen++] = fs_get_acorn_entries(server, active_id, p.unixpath); // Number of directory entries

	}

	if (command == 64) // SJ Research function
	{

		if (!(fs_config[server].fs_sjfunc))
		{
			fs_error(server, reply_port, net, stn, 0xff, "SJR Not enabled");
			return;
		}

		// Create date. (File type done for all replies above)
		r.p.data[replylen++] = p.c_day;
		r.p.data[replylen++] = p.c_monthyear;
		r.p.data[replylen++] = p.c_hour;
		r.p.data[replylen++] = p.c_min;
		r.p.data[replylen++] = p.c_sec;

		// Modification date / time
		r.p.data[replylen++] = p.day;
		r.p.data[replylen++] = p.monthyear;
		r.p.data[replylen++] = p.hour;
		r.p.data[replylen++] = p.min;
		r.p.data[replylen++] = p.sec;

	}

	fs_aun_send(&r, server, replylen, net, stn);
		
}

// Save file
void fs_save(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned char *data, int datalen, unsigned char rx_ctrl)
{

	unsigned char incoming_port, ack_port;
	unsigned long load, exec, length;
	unsigned char create_only;
	char filename[1024];

	struct __econet_packet_udp r;

	create_only = (*(data+1) == 0x1d ? 1 : 0); // Function 29 just creates a file of the requisite length - no data transfer phase.
	ack_port = *(data+2);	
	
	// Anyone know what the bytes at data+3, 4 are?

	fs_copy_to_cr(filename, data+16, 1023);

	load = 	(*(data+5)) + ((*(data+6)) << 8) + ((*(data+7)) << 16) + ((*(data+8)) << 24);

	exec = 	(*(data+9)) + ((*(data+10)) << 8) + ((*(data+11)) << 16) + ((*(data+12)) << 24);
	
	length = (*(data+13)) + ((*(data+14)) << 8) + ((*(data+15)) << 16);

	fs_debug (0, 1, "%12sfrom %3d.%3d %s %s %08lx %08lx %06lx", "", net, stn, (create_only ? "CREATE" : "SAVE"), filename, load, exec, length);

	if (create_only || (incoming_port = fs_find_bulk_port(server)))
	{
		struct path p;

		if (fs_normalize_path(server, active_id, filename, active[server][active_id].current, &p))
		{
			// Path found
	
/* This is an error. PERM_L just stops you deleting it.
			if (p.perm & FS_PERM_L) // Locked - cannot write
			{
				fs_error(server, reply_port, net, stn, 0xC3, "Locked");
			}
			else */
			if (p.ftype != FS_FTYPE_FILE && p.ftype != FS_FTYPE_NOTFOUND) // Not a file!
				fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			else
			{
				if (	((p.ftype != FS_FTYPE_NOTFOUND) && (p.my_perm & FS_PERM_OWN_W)) || 
					(
						p.ftype == FS_FTYPE_NOTFOUND && 
						(	(	(p.parent_perm & FS_PERM_OWN_W) && 
								(
									(p.parent_owner == active[server][active_id].userid) || (active[server][active_id].priv & FS_PRIV_SYSTEM)
								)
							) ||
							(p.parent_perm & FS_PERM_OTH_W)
						)
					)
				)
				{
					short internal_handle;

					// Can write to it one way or another
		
					// Use interlock function here
					internal_handle = fs_open_interlock(server, p.unixpath, 3, active[server][active_id].userid);

					if (internal_handle == -3)
						fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
					else if (internal_handle == -2)
						fs_error(server, reply_port, net, stn, 0xc2, "Already open"); // Interlock failure
					else if (internal_handle == -1)
						fs_error(server, reply_port, net, stn, 0xFF, "FS Error"); // File didn't open when it should
					else
					{
						fs_write_xattr(p.unixpath, active[server][active_id].userid, FS_PERM_OWN_R | FS_PERM_OWN_W, load, exec, 0, server);  // homeof = 0 because it's a file

						r.p.port = reply_port;
						r.p.ctrl = rx_ctrl; // Copy from request
						r.p.ptype = ECONET_AUN_DATA;
			
						r.p.data[0] = r.p.data[1] = 0;
						r.p.data[2] = incoming_port;
						r.p.data[3] = (1280 & 0xff); // maximum tx size
						r.p.data[4] = (1280 & 0xff00) >> 8;
				
						if (!create_only) fs_aun_send (&r, server, 5, net, stn);
						else
						{
							// Write 'length' bytes of garbage to the file (probably nulls)

							ftruncate(fileno(fs_files[server][internal_handle].handle), length);
						}
						
						if (create_only || length == 0)
						{

							// Send a closing ACK

							struct tm t; 
							struct stat s;
							unsigned char day, monthyear;

							day = monthyear = 0;

							if (!stat((const char * ) p.unixpath, &s))
							{
								localtime_r(&(s.st_mtime), &t);
								fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(monthyear), &(day));
								//day = t.tm_mday;
								//monthyear = (((t.tm_year - 81 - 40) & 0x0f) << 4) | ((t.tm_mon+1) & 0x0f);	
							}	
								
							fs_close_interlock(server, internal_handle, 3);
							r.p.port = reply_port;
							r.p.ctrl = rx_ctrl;
							r.p.ptype = ECONET_AUN_DATA;
							r.p.data[0] = r.p.data[1] = 0;
							r.p.data[2] = FS_PERM_OWN_R | FS_PERM_OWN_W;
							r.p.data[3] = day;
							r.p.data[4] = monthyear;

							fs_aun_send (&r, server, 5, net, stn);
						}
						else
						{
							fs_bulk_ports[server][incoming_port].handle = internal_handle;
							fs_bulk_ports[server][incoming_port].net = net;
							fs_bulk_ports[server][incoming_port].stn = stn;
							fs_bulk_ports[server][incoming_port].ack_port = ack_port;
							fs_bulk_ports[server][incoming_port].length = length;
							fs_bulk_ports[server][incoming_port].received = 0; // Initialize
							fs_bulk_ports[server][incoming_port].reply_port = reply_port;
							fs_bulk_ports[server][incoming_port].rx_ctrl = rx_ctrl;
							fs_bulk_ports[server][incoming_port].mode = 3;
							fs_bulk_ports[server][incoming_port].user_handle = 0; // Rogue for no user handle, because never hand out user handle 0. This stops the bulk transfer routine trying to increment a cursor on a user handle which doesn't exist.
							strncpy(fs_bulk_ports[server][incoming_port].acornname, p.acornname, 12);
							fs_bulk_ports[server][incoming_port].last_receive = (unsigned long long) time(NULL);
						}
					}
				}
				else fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");


			}

		}
		else fs_error(server, reply_port, net, stn, 0xCC, "Bad path");
	}
	else
		fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
	
	
}

// Change ownership
void fs_free(int server, unsigned short reply_port, unsigned char net, unsigned char stn, int active_id, unsigned char *data, int datalen)
{

	struct __econet_packet_udp r;
	unsigned char path[1024];
	unsigned short disc;
	unsigned char discname[17], tmp[17];

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;
	r.p.data[0] = r.p.data[1] = 0;

	fs_copy_to_cr(tmp, data+5, 16);
	snprintf((char * ) discname, 17, "%-16s", (const char * ) tmp);

	fs_debug (0, 2, "%12sfrom %3d.%3d Read free space on %s", "", net, stn, discname);

	disc = 0;
	while (disc < ECONET_MAX_FS_DISCS)
	{
		char realname[20];
		snprintf(realname, 17, "%-16s", (const char * ) fs_discs[server][disc].name);

		if (!strcasecmp((const char *) discname, (const char *) realname))
		{	
			struct statvfs s;

			snprintf((char * ) path, 1024, "%s/%1d%s",(const char * ) fs_stations[server].directory, disc, (const char * ) fs_discs[server][disc].name);
	
			if (!statvfs((const char * ) path, &s))
			{
				unsigned long long f; // free space
				unsigned long long e; // extent of filesystem

				f = (s.f_bsize >> 8) * s.f_bavail;
				e = (s.f_bsize >> 8) * s.f_blocks;

				// This is well dodgy and probably no use unless you put the filestore on a smaller filing system

				if (f > 0xffffff) f = 0x7fffff;

				r.p.data[2] = (f % 256) & 0xff;
				r.p.data[3] = ((f >> 8) % 256) & 0xff;
				r.p.data[4] = ((f >> 16) % 256) & 0xff;

				if (e > 0xffffff) e = 0x7fffff;

				r.p.data[5] = (e % 256) & 0xff;
				r.p.data[6] = ((e >> 8) % 256) & 0xff;
				r.p.data[7] = ((e >> 16) % 256) & 0xff;

				fs_aun_send(&r, server, 8, net, stn);
				return;

			}
			else fs_error(server, reply_port, net, stn, 0xFF, "FS Error");	
		}
		disc++;
	}
	
	fs_error(server, reply_port, net, stn, 0xFF, "No such disc");

	
}
// Return error specifying who owns a file
void fs_owner(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	struct path p;
	unsigned char path[256];
	unsigned char result[30];
	unsigned char username[11];
	unsigned short ptr_file, ptr;

	fs_copy_to_cr(path, command, 1023);

	fs_debug (0, 1, "%12sfrom %3d.%3d *OWNER %s", "", net, stn, path);

	ptr = 0;

	while (*(command + ptr) == ' ' && ptr < strlen((const char *) command))
		ptr++;

	if (ptr == strlen((const char *) command))
		fs_error(server, reply_port, net, stn, 0xFE, "Bad command");

	ptr_file = ptr;

	while (*(command + ptr) != ' ' && ptr < strlen((const char *) command))
		ptr++;

	*(command + ptr) = '\0';

	strncpy((char * ) path, (const char * ) &(command[ptr_file]), 255);

	if (!fs_normalize_path(server, active_id, path, active[server][active_id].current, &p) || p.ftype == FS_FTYPE_NOTFOUND)
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	else
	{
		if (!((active[server][active_id].priv & FS_PRIV_SYSTEM) || (p.owner == active[server][active_id].userid) || (p.parent_owner == active[server][active_id].userid))) // Not system user, and doesn't own parent directory
		{
			fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			return;
		}

		snprintf(username, 11, "%-10s", users[server][p.owner].username);
		snprintf(result, 30, "Owner: %-10s %04d", username, p.owner);

		fs_error(server, reply_port, net, stn, 0xFF, result);		

	}
}

// Change ownership
void fs_chown(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	struct path p;
	unsigned char path[256];
	unsigned char username[20];
	unsigned short ptr_file, ptr_owner, ptr;
	int userid;

	fs_copy_to_cr(path, command, 255); // Command no longer 0x0d terminated

	fs_debug (0, 1, "%12sfrom %3d.%3d *CHOWN %s", "", net, stn, path);

	userid = active[server][active_id].userid;

	ptr = 0;

	// Skip whitespace (not necessary with new command parse, but does no harm)

	while (*(command + ptr) == ' ' && ptr < strlen((const char *) command))
		ptr++;

	if (ptr == strlen((const char *) command))
		fs_error(server, reply_port, net, stn, 0xFE, "Bad command");

	ptr_file = ptr;

	// Skip the filename
	while (*(command + ptr) != ' ' && ptr < strlen((const char *) command))
		ptr++;

	if (ptr == strlen((const char *) command)) // No user specified - assume us
		ptr_owner = 0;
	else
	{
		int orig_length;

		orig_length = strlen(command);

		// Null terminate the filename
		*(command + ptr) = '\0';

		ptr++;

		// Skip more whitespace
		while (*(command + ptr) == ' ' && ptr < orig_length)
			ptr++;
		if (ptr == strlen((const char *) command)) // No user specified
			ptr_owner = 0;
		else	ptr_owner = ptr;

		while (*(command + ptr) != ' ' && ptr < orig_length)
			ptr++; // Skip past owner name

		if (ptr < orig_length)
			command[ptr] = '\0'; // Null terminate the username
	}

	strncpy((char * ) path, (const char * ) &(command[ptr_file]), 255);

	snprintf((char * ) username, 11, "%-10s", (ptr_owner ? (const char * ) &(command[ptr_owner]) : (const char * ) users[server][userid].username));
	
	username[10] = '\0';
	
	fs_debug (0, 1, "%12sfrom %3d.%3d Change ownership on %s to '%s'", "", net, stn, path, (char *) (ptr_owner ? (char *) username : (char *) "self"));

	if ((!(active[server][active_id].priv & FS_PRIV_SYSTEM)) && (ptr_owner != 0)) // Ordinary user tring to change ownership to someone other than themselves
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}

	if (!fs_normalize_path(server, active_id, path, active[server][active_id].current, &p) || p.ftype == FS_FTYPE_NOTFOUND)
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	else
	{
		short newid, found;
		newid = 0;
		found = 0;
		
		if (ptr_owner == 0) 
		{
			newid = userid;
			found = 1;
		}

		while (newid < ECONET_MAX_FS_USERS && !found)
		{
			if (!strncasecmp((const char *) users[server][newid].username, (const char *) username, 10))
			{
				found = 1;
				break;
			}
			else newid++;
		}

		if (!found)
		{
			fs_error(server, reply_port, net, stn, 0xBC, "No such user");
			return;
		}

		// Now check we have permission

		if (p.perm & FS_PERM_L) // Locked
		{
			fs_error(server, reply_port, net, stn, 0xC3, "Locked");
			return;
		}

		if (
			!(active[server][active_id].priv & FS_PRIV_SYSTEM) &&
			(p.parent_owner == userid && !(p.parent_perm & FS_PERM_OWN_W)) &&
			!(p.owner == userid && (p.perm & FS_PERM_OWN_W))
		   ) // Not system user, no write access to parent directory
		{
			fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			return;
		}

		// normalize_path will have put the attributes in its attr struct - change & write to disc
		p.attr.owner = newid;

		fs_write_xattr(p.unixpath, p.attr.owner, p.attr.perm, p.attr.load, p.attr.exec, p.attr.homeof, server);

		fs_reply_success(server, reply_port, net, stn, 0, 0);
		
	}
}

// Is a file open for reading or writing?
// This is the Econet locking mechanism.
// If >0 readers, can't open for writing.
// If a writer, can't open for reading.
// Supply the request type 1 for reading, 2 for writing (or deleting, renaming, etc.), 3 for writing and trucate
// Returns -3 for too many files, -1 for file didn't exist when it should or can't open, or internal handle for OK. This will also attempt to open the file 
// -2 = interlock failure
// The path is a unix path - we look it up in the tables of file handles
short fs_open_interlock(int server, unsigned char *path, unsigned short mode, unsigned short userid)
{

	unsigned short count;

	fs_debug (0, 2, "%12sInterlock on server %d attempting to open path %s, mode %d, userid %d", "", server, path, mode, userid);

	count = 0;

	while (count < ECONET_MAX_FS_FILES)
	{
		if (fs_files[server][count].handle && !strcmp(fs_files[server][count].name, path)) // Handle check ensures this is an active entry
		{
			if (mode >= 2) // We want write
				return -2; // If there is an active entry, someone must be reading or writing, so we can't write.
			else
				if (fs_files[server][count].writers == 0) // We can open this existing handle for reading
				{
					fs_files[server][count].readers++;
					fs_debug (0, 2, "%12sInterlock opened internal dup handle %d, mode %d. Readers = %d, Writers = %d, path %s", "", count, mode, fs_files[server][count].readers, fs_files[server][count].writers, fs_files[server][count].name);
					return count; // Return the index into fs_files
				}
				else // We can't open for reading because someone else has it open for writing
					return -2;
		}
		else 	count++;
	}

	// If we've got here, then there is no existing handle for *path. Create one

	count = 0;

	while (count  < ECONET_MAX_FS_FILES)
	{
		if (fs_files[server][count].handle == NULL) // Empty descriptor
		{
			fs_files[server][count].handle = fopen(path, (mode == 1 ? "r" : (mode == 2 ? "r+" : "w+"))); // These correspond to OPENIN, OPENUP and OPENOUT. OPENUP can only be used if the file exists, so this line fails if it doesn't. Whereas w+ == OPENOUT, which can create a file.

			if (!fs_files[server][count].handle)
				return -1; // Failure
	
			strcpy(fs_files[server][count].name, path);
			if (mode == 1)	fs_files[server][count].readers = 1;
			else		fs_files[server][count].writers = 1;

			if (mode == 3) // Take ownereship on OPENOUT
				fs_write_xattr(path, userid, FS_PERM_OWN_W | FS_PERM_OWN_R, 0, 0, 0, server);
	
			fs_debug (0, 2, "%12sInterlock opened internal handle %d, mode %d. Readers = %d, Writers = %d, path %s", "", count, mode, fs_files[server][count].readers, fs_files[server][count].writers, fs_files[server][count].name);
			return count;
		}
		else count++;
	}

	// If we got here, then we couldn't find a spare descriptor - return 0

	return 0;

}

// Reduces the reader/writer count by 1 and, if both are 0, closes the file handle
void fs_close_interlock(int server, unsigned short index, unsigned short mode)
{
	if (mode == 1) // Reader close
		fs_files[server][index].readers--;
	else	fs_files[server][index].writers--;

	fs_debug (0, 2, "%12sInterlock close internal handle %d, mode %d. Readers now = %d, Writers now = %d, path %s", "", index, mode, fs_files[server][index].readers, fs_files[server][index].writers, fs_files[server][index].name);

	if (fs_files[server][index].readers <= 0 && fs_files[server][index].writers <= 0)
	{
		fs_debug (0, 2, "%12sInterlock closing internal handle %d in operating system", "", index);
		fclose(fs_files[server][index].handle);
		fs_files[server][index].handle = NULL; // Flag unused
	}

}

// Count how many existing directory entries in a directory
unsigned int fs_count_dir_entries(char *path)
{

	unsigned int count = 0;
	DIR *d;
	struct dirent *entry;

	d = opendir((const char *) path);

	if (!d) return 0;

	while ((entry = readdir(d)))
		if (entry->d_name[0] != '.') count++;

	return count;	

}

// Copy file(s)
void fs_copy(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	char source[1024], destination[1024];
	struct path p_src, p_dst;
	struct path_entry *e;
	unsigned short to_copy, all_files;

	fs_debug (0, 1, "%12sfrom %3d.%3d COPY %s", "", net, stn, command);

	if (sscanf(command, "%s %s", source, destination) != 2)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
		return;
	}

	if (!fs_normalize_path_wildcard(server, active_id, source, active[server][active_id].current, &p_src, 1))
	{
		fs_error(server, reply_port, net, stn, 0xDC, "Not found");
		fs_free_wildcard_list(&p_src);
		return;
	}
	
	all_files = 0;
	to_copy = 0;

	// Check they're all files

	e = p_src.paths;

	while (e != NULL)
	{
		if (e->ftype == FS_FTYPE_FILE && (users[server][active[server][active_id].userid].priv == FS_PRIV_SYSTEM || e->my_perm & FS_PERM_OWN_R)) all_files++;
		to_copy++;
		e = e->next;
	}

	if (all_files != to_copy) // Not all files! Error
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Source must be all files");
		fs_free_wildcard_list(&p_src);
		return;
	}

	// Make sure destination is a directory (unless only one file to copy)

	if (!fs_normalize_path(server, active_id, destination, active[server][active_id].current, &p_dst))
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad destination");
		fs_free_wildcard_list(&p_src);
		return;
	}

	if (p_dst.ftype != FS_FTYPE_DIR && to_copy > 1) // Can't copy > 1 file into something not a directory
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Destination not a dir");
		fs_free_wildcard_list(&p_src);
		return;
	}

	e = p_src.paths; // Copy them

	while (e != NULL)
	{

		short handle, out_handle;
		struct objattr a;
		unsigned long length, sf_return;
		off_t readpos;
		char destfile[2600];

		handle = fs_open_interlock(server, e->unixpath, 1, active[server][active_id].userid);

		//fs_debug (0, 1, "fs_open_interlock(%s) returned %d", e->unixpath, handle);

		if (handle == -3)
		{
			fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (handle == -2)
		{
			fs_error(server, reply_port, net, stn, 0xC2, "Already open");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (handle == -1)
		{
			fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
			fs_free_wildcard_list(&p_src);
			return;
		}

		fs_read_xattr(e->unixpath, &a, server);

		if (p_dst.ftype == FS_FTYPE_DIR)
			sprintf(destfile, "%s/%s", p_dst.unixpath, e->unixfname);
		else
			strcpy(destfile, p_dst.unixpath); 

		out_handle = fs_open_interlock(server, destfile, 3, active[server][active_id].userid);

		//fs_debug (0, 1, "fs_open_interlock(%s) returned %d", destfile, out_handle);

		if (out_handle == -3)
		{
			fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (out_handle == -2) // Should never happen
		{
			fs_error(server, reply_port, net, stn, 0xC2, "Already open");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (out_handle == -1)
		{
			fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
			fs_free_wildcard_list(&p_src);
			return;
		}

		fseek(fs_files[server][handle].handle, 0, SEEK_END);
		length = ftell(fs_files[server][handle].handle);

		fs_debug (0, 1, "%12sfrom %3d.%3d Copying %s to %s, length %06lX", "", net, stn, e->unixpath, destfile, length);

		readpos = 0; // Start at the start

		while (readpos < length)
		{
			if ((sf_return = sendfile(fileno(fs_files[server][out_handle].handle),
				fileno(fs_files[server][handle].handle),
				&readpos, 
				length)) == -1) // Error!
			{
				fs_close_interlock(server, handle, 1);
				fs_close_interlock(server, out_handle, 3);
				fs_free_wildcard_list(&p_src);
				fs_error(server, reply_port, net, stn, 0xFF, "FS Error in copy");
				return;
			}

			readpos += sf_return;
		}

		fs_write_xattr(destfile, active[server][active_id].userid, a.perm, a.load, a.exec, a.homeof, server);
		fs_close_interlock(server, handle, 1);
		fs_close_interlock(server, out_handle, 3);

		e = e->next;
	}

	fs_free_wildcard_list(&p_src);
	fs_reply_ok(server, reply_port, net, stn);

}

// System command - create symbolic link (e.g. "duplicate" library)
void fs_link(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	char source[1024], destination[1024];
	struct path p_src, p_dst;

	fs_debug (0, 1, "%12sfrom %3d.%3d LINK %s", "", net, stn, command);
	if (sscanf(command, "%s %s", source, destination) != 2)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
		return;
	}

	if (!fs_normalize_path(server, active_id, source, active[server][active_id].current, &p_src) || (p_src.ftype == FS_FTYPE_NOTFOUND))
	{
		fs_error(server, reply_port, net, stn, 0xDC, "Not found");
		fs_free_wildcard_list(&p_src);
		return;
	}
	
	if (!fs_normalize_path(server, active_id, destination, active[server][active_id].current, &p_dst))
	{
		fs_error(server, reply_port, net, stn, 0xDC, "Bad destination path");
		fs_free_wildcard_list(&p_src);
		fs_free_wildcard_list(&p_dst);
		return;
	}
	
	//fs_debug (0, 1, "Calling symlink(%s, %s)", p_src.unixpath, p_dst.unixpath);

	if (symlink(p_src.unixpath, p_dst.unixpath) == -1)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Cannot create link");
		fs_free_wildcard_list(&p_src);
		fs_free_wildcard_list(&p_dst);
		return;
	}

	fs_write_xattr(p_src.unixpath, p_src.owner, p_src.perm | FS_PERM_L, p_src.load, p_src.exec, p_src.homeof, server); // Lock the file. If you remove the file to which there are symlinks, stat goes bonkers and the FS crashes. So lock the source file so the user has to think about it!! (Obviously this will show as a locked linked file too, but hey ho)

	fs_free_wildcard_list(&p_src);
	fs_free_wildcard_list(&p_dst);

	fs_reply_ok(server, reply_port, net, stn);

}

// System command to remove a symlink
void fs_unlink(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	char link[1024];
	struct stat s;
	struct path p;

	fs_debug (0, 1, "%12sfrom %3d.%3d UNLINK %s", "", net, stn, command);
	if (sscanf(command, "%s", link) != 1)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
		return;
	}

	if (!fs_normalize_path(server, active_id, link, active[server][active_id].current, &p) || (p.ftype == FS_FTYPE_NOTFOUND))
	{
		fs_error(server, reply_port, net, stn, 0xDC, "Not found");
		return;
	}
	
	// Is it a link?

	if (lstat(p.unixpath, &s) != 0) // Stat error
	{
		fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
		return;
	}

	if (S_ISLNK(s.st_mode & S_IFMT))
	{
		if (unlink(p.unixpath) != 0) // Error
		{
			fs_error(server, reply_port, net, stn, 0xFF, "Cannot remove link");
			return;
		}
	}
	else
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Not a link");
		return;
	}
		
	fs_reply_ok(server, reply_port, net, stn);

}

// Select other disc
void fs_sdisc(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	// Collect new directory handles, and only if they're all good are we going to switch discs

	int root, cur, lib;
	struct path p_root, /* p_home, */ p_lib;
	char discname[20];
	char tmppath[1024], tmppath2[1024];
	int internal_root_handle, internal_cur_handle, internal_lib_handle;
	unsigned char home_dir[100], lib_dir[100];

	struct __econet_packet_udp r;

	fs_copy_to_cr(discname, command, 19);

	root = cur = lib = -1;

	strncpy((char *) home_dir, (const char *) users[server][active[server][active_id].userid].home, 96);
	if (strchr(home_dir, ' '))
		*(strchr(home_dir, ' ')) = '\0';
	home_dir[96] = '\0';

	strncpy((char *) lib_dir, (const char *) users[server][active[server][active_id].userid].lib, 96);
	lib_dir[96] = '\0';
	if (strchr(lib_dir, ' '))
		*(strchr(lib_dir, ' ')) = '\0';

	if (strlen(home_dir) == 0)
	{
		snprintf(home_dir, 13, "$.%10s", users[server][active[server][active_id].userid].username);
		if (strchr(home_dir, ' '))
			*(strchr(home_dir, ' ')) = '\0';
	}

	if (strlen(lib_dir) == 0)
		sprintf(lib_dir, "$.Library");

	// URD first

	sprintf(tmppath, ":%s.%s", discname, home_dir);
	sprintf(tmppath2, ":%s.$", discname);

	fs_debug (0, 2, "%12sfrom %3d.%3d Change disc to %s", "", net, stn, discname);

	if (!fs_normalize_path(server, active_id, tmppath, -1, &p_root))
	{
		if (!fs_normalize_path(server, active_id, tmppath2, -1, &p_root))
		{
			fs_debug (0, 1, "%12sfrom %3d.%3d Failed to map URD %s on %s, even %s", "", net, stn, discname, tmppath, tmppath2);
			fs_error(server, reply_port, net, stn, 0xFF, "Cannot map root directory on new disc");
			return;
		}
	}

	if (p_root.ftype == FS_FTYPE_NOTFOUND && !fs_normalize_path(server, active_id, tmppath2, -1, &p_root))
	{
		fs_debug (0, 1, "%12sfrom %3d.%3d Failed to map URD on %s, even %s", "", net, stn, discname, tmppath2);
		fs_error(server, reply_port, net, stn, 0xFF, "Cannot map root directory on new disc");
		return;

	}

	if (p_root.ftype != FS_FTYPE_DIR)
	{
		fs_debug (0, 1, "%12sfrom %3d.%3d URD on %s, even %s, is not a dir!", "", net, stn, discname, tmppath2);
		fs_error(server, reply_port, net, stn, 0xFF, "Cannot map root directory on new disc");
		return;
	}

	//if ((internal_root_handle = fs_get_dir_handle(server, active_id, p_root.unixpath)) == -1)
	if ((internal_root_handle = fs_open_interlock(server, p_root.unixpath, 1, active[server][active_id].userid)) == -1)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Root directory inaccessible!");
		return;
	}

	if ((root = fs_allocate_user_dir_channel(server, active_id, internal_root_handle)) == 0) // Can't allocate handle
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Root directory channel ?");
		//fs_close_dir_handle(server, internal_root_handle);
		fs_close_interlock(server, internal_root_handle, 1);
		return;
	}

	fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, root, internal_root_handle);

	if ((internal_cur_handle = fs_open_interlock(server, p_root.unixpath, 1, active[server][active_id].userid)) == -1)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "CWD inaccessible!");
		return;
	}

	if ((cur = fs_allocate_user_dir_channel(server, active_id, internal_cur_handle)) == 0) // Can't allocate handle
	{
		fs_error(server, reply_port, net, stn, 0xFF, "CWD channel ?");
		fs_deallocate_user_dir_channel (server, active_id, root);
		fs_close_interlock(server, internal_root_handle, 1);
		fs_close_interlock(server, internal_cur_handle, 1);
		return;
	}

	fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, cur, internal_cur_handle);

	strcpy(active[server][active_id].fhandles[root].acornfullpath, p_root.acornfullpath);
	fs_store_tail_path(active[server][active_id].fhandles[root].acorntailpath, p_root.acornfullpath);
	active[server][active_id].fhandles[root].mode = 1;

	fs_debug (0, 2, "%12sfrom %3d.%3d Successfully mapped new URD - uHandle %02X, full path %s", "", net, stn, root, active[server][active_id].fhandles[root].acornfullpath);

	strcpy(active[server][active_id].fhandles[cur].acornfullpath, p_root.acornfullpath);
	fs_store_tail_path(active[server][active_id].fhandles[cur].acorntailpath, p_root.acornfullpath);
	active[server][active_id].fhandles[cur].mode = 1;

	fs_debug (0, 2, "%12sfrom %3d.%3d Successfully mapped new CWD - uHandle %02X, full path %s", "", net, stn, cur, active[server][active_id].fhandles[cur].acornfullpath);

	sprintf(tmppath, ":%s.%s", discname, lib_dir);

	// If we find library directory on new disc, use it. Otherwise leave it alone
	if (fs_normalize_path(server, active_id, tmppath, -1, &p_lib) && p_lib.ftype == FS_FTYPE_DIR)
	{

		if ((internal_lib_handle = fs_open_interlock(server, p_lib.unixpath, 1, active[server][active_id].userid)) == -1)
		{
			fs_error(server, reply_port, net, stn, 0xFF, "Library directory inaccessible!");
			fs_deallocate_user_dir_channel(server, active_id, root);
			fs_deallocate_user_dir_channel(server, active_id, cur);
			fs_close_interlock(server, internal_root_handle, 1);
			fs_close_interlock(server, internal_cur_handle, 1);
			return;
		}
	
		if ((lib = fs_allocate_user_dir_channel(server, active_id, internal_lib_handle)) == 0) // Can't allocate handle
		{
			fs_error(server, reply_port, net, stn, 0xFF, "Library directory channel ?");
			fs_deallocate_user_dir_channel(server, active_id, root);
			fs_deallocate_user_dir_channel(server, active_id, cur);
			fs_close_interlock(server, internal_root_handle, 1);
			fs_close_interlock(server, internal_cur_handle, 1);
			fs_close_interlock(server, internal_lib_handle, 1);
			return;
		}

		fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, lib, internal_lib_handle);

		strcpy(active[server][active_id].fhandles[lib].acornfullpath, p_lib.acornfullpath);
		fs_store_tail_path(active[server][active_id].fhandles[lib].acorntailpath, p_lib.acornfullpath);
		active[server][active_id].fhandles[lib].mode = 1;
		
		// Close old lib handle

		fs_close_interlock(server, active[server][active_id].fhandles[active[server][active_id].lib].handle, 1);
		fs_deallocate_user_dir_channel(server, active_id, active[server][active_id].lib);

		active[server][active_id].lib = lib;
	
		fs_debug (0, 2, "%12sfrom %3d.%3d Successfully mapped new Library - uHandle %02X, full path %s", "", net, stn, lib, active[server][active_id].fhandles[lib].acornfullpath);
	}
	else	lib = active[server][active_id].lib;


	fs_debug (0, 2, "%12sfrom %3d.%3d Attempting to deallocate handles for URD (%d), CWD (%d)", "", net, stn, active[server][active_id].root, active[server][active_id].current);
	
	fs_close_interlock(server, active[server][active_id].fhandles[active[server][active_id].root].handle, active[server][active_id].fhandles[active[server][active_id].root].mode);
	fs_deallocate_user_dir_channel(server, active_id, active[server][active_id].root);
	

	fs_close_interlock(server, active[server][active_id].fhandles[active[server][active_id].current].handle, active[server][active_id].fhandles[active[server][active_id].current].mode);
	fs_deallocate_user_dir_channel(server, active_id, active[server][active_id].current);
	
	// active[server][active_id].lib = lib; // Lib no longer changing
	active[server][active_id].current = cur;
	active[server][active_id].root = root;
	active[server][active_id].current_disc = p_root.disc;

	strncpy((char *) active[server][active_id].root_dir, (const char *) "", 11);
	strncpy((char *) active[server][active_id].root_dir_tail, (const char *) "$         ", 11);

	fs_debug (0, 2, "%12sfrom %3d.%3d New (URD, CWD) = (%s, %s)", "", net, stn, 
		active[server][active_id].fhandles[root].acorntailpath, 
		active[server][active_id].fhandles[cur].acorntailpath );

	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.data[0] = 0x06; // SDisc return, according to MDFS manual
	r.p.data[1] = 0x00;
	r.p.data[2] = FS_MULHANDLE(root);
	r.p.data[3] = FS_MULHANDLE(cur);
	r.p.data[4] = FS_MULHANDLE(lib);
	r.p.data[5] = active[server][active_id].bootopt;

	fs_aun_send(&r, server, 6, net, stn);

}

// Rename a file (i.e. move it)
void fs_rename(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, int relative_to, unsigned char *command)
{

	struct path p_from, p_to;
	unsigned char from_path[1024], to_path[1024];
	unsigned short count, found;
	unsigned short firstpath_start, firstpath_end, secondpath_start, secondpath_end;
	short handle;
	struct __econet_packet_udp r;

	count = found = 0;

	// First, find the source path

	while (!found && (count < strlen((const char *) command)))
	{
		if (*(command + count) != ' ') found = 1;
		else count++;
	}

	if (count == strlen((const char *) command))
	{
		fs_error(server, reply_port, net, stn, 0xFD, "Bad string");
		return;
	}

	firstpath_start = count;

	found = 0;

	while (!found && (count < strlen((const char *) command)))
	{
		if (*(command + count) == ' ') found = 1;
		else count++;
	}

	if (count == strlen((const char *) command)) // Ran out without finding some space separating first string from second
	{
		fs_error(server, reply_port, net, stn, 0xFD, "Bad string");
		return;
	}

	firstpath_end = count-1;

	found = 0;

	while (!found && (count < strlen((const char *) command)))
	{
		if (*(command + count) != ' ') found = 1; // Found start of second path
		else count++;
	}

	if (count == strlen((const char *) command))
	{
		fs_error(server, reply_port, net, stn, 0xFD, "Bad string");
		return;
	}

	secondpath_start = count;

	found = 0;

	while (!found && (count < strlen((const char *) command)))
	{
		if (*(command + count) == ' ') found = 1;
		else count++;
	}

	secondpath_end = count-1;

	strncpy(from_path, (command+firstpath_start), (firstpath_end - firstpath_start + 1));
	from_path[(firstpath_end - firstpath_start + 1)] = '\0';

	strncpy(to_path, (command+secondpath_start), (secondpath_end - secondpath_start + 1));
	to_path[(secondpath_end - secondpath_start + 1)] = '\0';

	fs_debug (0, 1, "%12sfrom %3d.%3d Rename from %s to %s", "", net, stn, from_path, to_path);	

	if (!fs_normalize_path(server, active_id, from_path, active[server][active_id].current, &p_from) || !fs_normalize_path(server, active_id, to_path, active[server][active_id].current, &p_to) || p_from.ftype == FS_FTYPE_NOTFOUND)
	{
		fs_error(server, reply_port, net, stn, 0xDC, "Not found");
		return;
	}

	//fs_debug (0, 1, "Rename parms: from locked: %s, from_owner %04x, from_parent_owner %04x, to_ftype %02x, to_owner %04x, to_parent_owner %04x, to_perm %02x, to_parent_perm %02x", 
			//(p_from.perm & FS_PERM_L ? "Yes" : "No"), p_from.owner, p_from.parent_owner, p_to.ftype, p_to.owner, p_to.parent_owner, p_to.perm, p_to.parent_perm);

	if (p_from.perm & FS_PERM_L) // Source locked
	{
		fs_error(server, reply_port, net, stn, 0xC3, "Entry locked");
		return;
	}
	
	if ((p_from.owner != active[server][active_id].userid) && (p_from.parent_owner != active[server][active_id].userid) && ((active[server][active_id].priv & FS_PRIV_SYSTEM) == 0))
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}

	if ((p_to.ftype != FS_FTYPE_NOTFOUND) && p_to.ftype != FS_FTYPE_DIR) // I.e. destination does exist but isn't a directory - cannot move anything on top of existing file
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Destination exists");
		return;
		// Note, we *can* move a file into a filename inside a directory (FS_FTYPE_NOTFOUND), likewise a directory, but if the destination exists it MUST be a directory
	}

	if ((p_to.ftype == FS_FTYPE_NOTFOUND) && p_to.parent_owner != active[server][active_id].userid && ((p_to.parent_perm & FS_PERM_OTH_W) == 0)) // Attempt to move to a directory we don't own and don't have write access to
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}

	if ((p_to.ftype != FS_FTYPE_NOTFOUND && p_to.owner != active[server][active_id].userid && (active[server][active_id].priv & FS_PRIV_SYSTEM) == 0)) // Destination exists (so must be dir), not owned by us, and we're not system
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}

	// Get an interlock

	if (p_from.ftype == FS_FTYPE_FILE)
	{
		handle = fs_open_interlock(server, p_from.unixpath, 2, active[server][active_id].userid);
	
		switch (handle)
		{
			case -1: // Can't open
			{
				fs_debug (0, 1, "fs_open_interlock() returned -1");
				fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
				return;
			}
			break;
			case -2: // Interlock failure
			{
				fs_error(server, reply_port, net, stn, 0xC2, "Already open");
				return;
			}
			break;
			case -3: // Too many files
			{
				fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
				return;
			}
			break;
		}

		// Release the interlock (since nothing else is going to come along and diddle with the file in the meantime

		fs_close_interlock(server, handle, 3);
	}


	// Otherwise we should be able to move it... and Unlike Econet, we *can* move across "discs"

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

	if (syscall(SYS_renameat2, 0, p_from.unixpath, 0, p_to.unixpath, RENAME_NOREPLACE)) // non-zero - failure
	{
		fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
		return;
	}

	// If the INF file exists, rename it.  Ignore errors
	char *olddot=pathname_to_dotfile(p_from.unixpath, server);
	char *newdot=pathname_to_dotfile(p_to.unixpath, server);
	rename(olddot, newdot);
	free(olddot);
	free(newdot);

	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.data[0] = r.p.data[1] = 0;

	fs_aun_send (&r, server, 2, net, stn);

}
	

// Delete a file
void fs_delete(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, int relative_to, unsigned char *command)
{

	struct path p;
	unsigned char path[1024];
	unsigned short count, found;
	short handle;

	count = found = 0;

	while (!found && (count < strlen((const char *) command)))
	{
		if (*(command+count) != ' ') found = 1;
		else count++;
	}

	fs_copy_to_cr(path, command + count, 1023);

	if (!fs_normalize_path_wildcard(server, active_id, path, relative_to, &p, 1))
		fs_error(server, reply_port, net, stn, 0xd6, "Not found");
	else
	{

		struct path_entry *e;

		e = p.paths;

		while (e != NULL) // Cycle through the entries
		{
			if (e->ftype == FS_FTYPE_FILE)
			{
				handle = fs_open_interlock(server, e->unixpath, 2, active[server][active_id].userid);
		
				if (handle < 0) // Interlock or other problem
				{
					fs_error(server, reply_port, net, stn, 0xc2, "Already open");
					fs_free_wildcard_list(&p);
					return;
				}
				else	fs_close_interlock(server, handle, 2);
			}
		
			if (e->ftype == FS_FTYPE_DIR && (fs_get_acorn_entries(server, active_id, p.unixpath) > 0))
			{
				fs_free_wildcard_list(&p);
				fs_error(server, reply_port, net, stn, 0xff, "Dir not empty");
				return;
			}
			else if (p.ftype == FS_FTYPE_NOTFOUND)
			{
				fs_free_wildcard_list(&p);
				fs_error(server, reply_port, net, stn, 0xd6, "Not found");
				return;
			}
			else if ((e->perm & FS_PERM_L))
			{
				fs_free_wildcard_list(&p);
				fs_error(server, reply_port, net, stn, 0xC3, "Entry locked");
				return;
			}
			else if (
					!(	(users[server][active[server][active_id].userid].priv & FS_PRIV_SYSTEM) || (e->owner == active[server][active_id].userid) || ((e->parent_owner == active[server][active_id].userid) && (e->parent_perm & FS_PERM_OWN_W))
				)
			)
			{
				fs_free_wildcard_list(&p);
				fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
				return;
			}
			else
			if ( 
					((e->ftype == FS_FTYPE_FILE) && unlink((const char *) e->unixpath)) ||
				((e->ftype == FS_FTYPE_DIR) && rmdir((const char *) e->unixpath))
				) // Failed
				{	fs_debug (0, 1, "%12sfrom %3d.%3d Failed to unlink %s", "", net, stn, e->unixpath);
					fs_free_wildcard_list(&p);
					fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
					return;
				}
				else
				{
					// Silently delete the INF file if it exists
					char *dotfile=pathname_to_dotfile(e->unixpath, server);
					unlink(dotfile);
					free(dotfile);
				}
		
			e = e->next;
		}

		fs_reply_success(server, reply_port, net, stn, 0, 0);
	}

}

// Create directory
void fs_cdir(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, int relative_to, unsigned char *command)
{

	struct path p;
	unsigned char path[1024];
	unsigned short count, found;

	count = found = 0;

	while (!found && (count < strlen((const char *) command)))
	{
		if (*(command+count) != ' ') found = 1;
		else count++;
	}

	fs_copy_to_cr(path, command + count, 1023);

	fs_debug (0, 1, "%12sfrom %3d.%3d CDIR %s relative to %02X (%s)", "", net, stn, path, relative_to, active[server][active_id].fhandles[relative_to].acornfullpath);

	if (!fs_normalize_path(server, active_id, path, relative_to, &p))
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	else
	{

		if (p.ftype != FS_FTYPE_NOTFOUND)
			fs_error(server, reply_port, net, stn, 0xFF, "Exists");
		else if ((p.parent_owner == active[server][active_id].userid && (p.parent_perm & FS_PERM_OWN_W)) || (users[server][active[server][active_id].userid].priv & FS_PRIV_SYSTEM)) // Must own the parent and have write access, or be system
		{
			if (!mkdir((const char *) p.unixpath, 0770))
			{
				fs_write_xattr(p.unixpath, active[server][active_id].userid, FS_PERM_OWN_W | FS_PERM_OWN_R, 0, 0, 0, server);
				fs_reply_success(server, reply_port, net, stn, 0, 0);
			}
			else	fs_error(server, reply_port, net, stn, 0xFF, "Unable to make directory");
		}
		else fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
	}
	
}

void fs_info(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	struct path p;
	struct __econet_packet_udp r;

	unsigned char path[1024];
	unsigned char relative_to;
	char reply_string[ECONET_ABS_MAX_FILENAME_LENGTH+80];

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;

	fs_copy_to_cr(path, command, 1023);

	relative_to = active[server][active_id].current;

	//r.p.data[0] = relative_to; Maybe this is a permissions thing?
	r.p.data[0] = 0x04; // Anything else and we get weird results. 0x05, for example, causes the client machine to *RUN the file immediately after getting the answer...
	r.p.data[1] = 0;

	fs_debug (0, 2, "%12sfrom %3d.%3d *INFO %s", "", net, stn, path);

	// 20240107 Commented if (!fs_normalize_path(server, active_id, path, relative_to, &p))
	if (!fs_normalize_path_wildcard(server, active_id, path, relative_to, &p, 1))
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	else
	{
		// 20240107 Added - we only want the first one
		fs_free_wildcard_list(&p);

		if (p.ftype == FS_FTYPE_NOTFOUND)
			fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		else if (p.ftype != FS_FTYPE_FILE)
			fs_error(server, reply_port, net, stn, 0xD6, "Not a file");
		else if (p.owner != active[server][active_id].userid && (p.perm & FS_PERM_H)) // Hidden file
			fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		else
		{
			unsigned char permstring[10];
			unsigned char hr_fmt_string[100];

			strcpy(permstring, "");
		
			if (p.perm & FS_PERM_L) strcat (permstring, "L");
			if (p.perm & FS_PERM_OWN_W) strcat (permstring, "W");
			if (p.perm & FS_PERM_OWN_R) strcat (permstring, "R");
			strcat (permstring, "/");
			if (p.perm & FS_PERM_OTH_W) strcat (permstring, fs_config[server].fs_mdfsinfo ? "w" : "W");
			if (p.perm & FS_PERM_OTH_R) strcat (permstring, fs_config[server].fs_mdfsinfo ? "r" : "R");

			if (fs_config[server].fs_mdfsinfo)
			{
				// Longer output
				sprintf(hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX    %%-7s   %%02d/%%02d/%%02d %%02d/%%02d/%%02d %%02d:%%02d:%%02d %%06lX%%c%%c", ECONET_MAX_FILENAME_LENGTH);
				sprintf(reply_string, hr_fmt_string, p.acornname, p.load, p.exec, p.length, permstring, 
						fs_day_from_two_bytes(p.c_day, p.c_monthyear),
						fs_month_from_two_bytes(p.c_day, p.c_monthyear),
						fs_year_from_two_bytes(p.c_day, p.c_monthyear),
						fs_day_from_two_bytes(p.day, p.monthyear),
						fs_month_from_two_bytes(p.day, p.monthyear),
						fs_year_from_two_bytes(p.day, p.monthyear),
						p.hour, p.min, p.sec,
						p.internal, 0x0d, 0x80);
			}
			else
			{
				sprintf(hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX    %%-7s   %%02d/%%02d/%%02d %%06lX%%c%%c", ECONET_MAX_FILENAME_LENGTH);
				//sprintf(reply_string, "%-10s %08lX %08lX   %06lX    %-7s   %02d/%02d/%02d %06lX%c%c",	p.path[p.npath-1], p.load, p.exec, p.length, permstring, 
				sprintf(reply_string, hr_fmt_string, p.acornname, p.load, p.exec, p.length, permstring, 
						fs_day_from_two_bytes(p.day, p.monthyear),
						fs_month_from_two_bytes(p.day, p.monthyear),
						fs_year_from_two_bytes(p.day, p.monthyear),
						p.internal, 0x0d, 0x80);
			}

			strcpy(&(r.p.data[2]), reply_string);
	
			fs_aun_send(&r, server, strlen(reply_string)+2, net, stn);
		}

	}

}


// Change permissions
void fs_access(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *command)
{

	struct path p;
	struct path_entry *e;
	unsigned char path[1024];
	unsigned char perm;
	unsigned short ptr;
	char perm_str[10];

	fs_copy_to_cr(path, command, 1023);

	fs_debug (0, 1, "%12sfrom %3d.%3d *ACCESS %s", "", net, stn, path);

	if (sscanf(command, "%s %8s", path, perm_str) != 2)
	{
		if (sscanf(command, "%s", path) == 1)
			perm = FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
		else
		{
			fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
			return;
		}	
	}
	else
	{

		perm = 0;
		ptr = 0;

		while (ptr < strlen((const char *) perm_str) && perm_str[ptr] != '/')
		{
			switch (perm_str[ptr])
			{
				case 'w': case 'W': perm |= FS_PERM_OWN_W; break;
				case 'r': case 'R': perm |= FS_PERM_OWN_R; break;
				case 'h': case 'H': perm |= FS_PERM_H; break; // Hidden from directory listings
				case 'l': case 'L': perm |= FS_PERM_L; break; // Locked
				default:
				{
					fs_error(server, reply_port, net, stn, 0xCF, "Bad attribute");
					return;
				}
			}
			ptr++;
		}

		if (ptr != strlen((const char *) perm_str))
		{
			ptr++; // Skip the '/'
	
			while (ptr < strlen((const char *) perm_str) && (perm_str[ptr] != ' ')) // Skip trailing spaces too
			{
				switch (perm_str[ptr])
				{
					case 'w': case 'W': perm |= FS_PERM_OTH_W; break;
					case 'r': case 'R': perm |= FS_PERM_OTH_R; break;
					default: 
					{
						fs_error(server, reply_port, net, stn, 0xCF, "Bad attribute");
						return;
					}
				}
				
			ptr++;
			}
		}
			

	}
			
	
	/* OLD NON-SSCANF CODE
	ptr = 0;

	while (ptr < strlen((const char *) command) && *(command+ptr) == ' ')
		ptr++;

	if (ptr == strlen((const char *) command)) // No filespec
	{
		fs_error(server, reply_port, net, stn, 0xFC, "Bad file name");
		return;
	}

	path_ptr = ptr;

	while (ptr < strlen((const char *) command) && *(command+ptr) != ' ')
		ptr++;

	if (ptr == strlen((const char *) command)) // No access string given
	{
		fs_error(server, reply_port, net, stn, 0xCF, "Bad attribute");
		return;
	}


	//fs_debug (0, 1, "Command: %s, path_ptr = %d, ptr = %d", command, path_ptr, ptr);

	strncpy((char * ) path, (const char * ) command + path_ptr, (ptr - path_ptr));

	path[ptr - path_ptr] = '\0'; // Terminate the path


	ptr++;

	while (ptr < strlen((const char *) command) && *(command+ptr) == ' ') // Skip spaces again
		ptr++;

	if (ptr == strlen((const char *) command)) // No access string given
	{
		fs_error(server, reply_port, net, stn, 0xCF, "Bad attribute");
		return;
	}

	perm = 0;

	while (ptr < strlen((const char *) command) && *(command+ptr) != '/')
	{
		switch (*(command+ptr))
		{
			case 'W': perm |= FS_PERM_OWN_W; break;
			case 'R': perm |= FS_PERM_OWN_R; break;
			case 'H': perm |= FS_PERM_H; break; // Hidden from directory listings
			case 'L': perm |= FS_PERM_L; break; // Locked
			default:
			{
				fs_error(server, reply_port, net, stn, 0xCF, "Bad attribute");
				return;
			}
		}
		ptr++;

	}

	if (ptr != strlen((const char *) command))
	{
		ptr++; // Skip the '/'

		while (ptr < strlen((const char *) command) && (*(command+ptr) != ' ')) // Skip trailing spaces too
		{
			switch (*(command+ptr))
			{
				case 'W': perm |= FS_PERM_OTH_W; break;
				case 'R': perm |= FS_PERM_OTH_R; break;
				default: 
				{
					fs_error(server, reply_port, net, stn, 0xCF, "Bad attribute");
					return;
				}
			}
			ptr++;
		}
	}
			
	*/

	// Normalize the path

	if (!fs_normalize_path_wildcard(server, active_id, path, active[server][active_id].current, &p, 1))
	{
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;
	}
	
	if (p.paths == NULL)
	{
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;
	}

	e = p.paths;

	// First, check we have permission on everything we need
	while (e != NULL)
	{
		if (e->owner == active[server][active_id].userid || (e->parent_owner == active[server][active_id].userid && (e->parent_perm & FS_PERM_OWN_W)) || (users[server][active[server][active_id].userid].priv & FS_PRIV_SYSTEM)) // Must own the file, own the parent and have write access, or be system
			e = e->next;
		else
		{
			fs_free_wildcard_list(&p); // Free up the mallocs
			fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			return;
		}
	}

	// If we get here, we have permission on everything so crack on

	e = p.paths;

	while (e != NULL)
	{
		fs_write_xattr(e->unixpath, e->owner, perm, e->load, e->exec, e->homeof, server); // 'perm' because that's the *new* permission
		e = e->next;
	
	}

	fs_free_wildcard_list(&p); // Free up the mallocs

	// Give the station the thumbs up

	fs_reply_success(server, reply_port, net, stn, 0, 0);
}

// Read discs
void fs_read_discs(int server, unsigned short reply_port, unsigned char net, unsigned char stn, int active_id, unsigned char *data, int datalen)
{

	struct __econet_packet_udp r;

	unsigned short start = *(data+5);
	unsigned short number = *(data+6);
	unsigned short delivered = 0;
	unsigned short disc_ptr = 0;
	unsigned short found = 0;
	unsigned short data_ptr = 3;

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;

	r.p.data[0] = 10;
	r.p.data[1] = 0;
	
	fs_debug (0, 2, "%12sfrom %3d.%3d Read Discs from %d (up to %d)", "", net, stn, start, number);

	/* This appears to be wrong. 'start' as delivered by NFS is not, for example, 3 for the 3rd existent disc, it's 3 for disc number 3. 
	while (disc_ptr < ECONET_MAX_FS_DISCS && found < start)
	{
		if (fs_discs[server][disc_ptr].name[0] != '\0') // Found an active disc
			found++;
		disc_ptr++;
	}
	*/

	disc_ptr = start;

	if (disc_ptr < ECONET_MAX_FS_DISCS) // See if there are any to insert
	{
		while (disc_ptr < ECONET_MAX_FS_DISCS && (delivered < number))
		{
			if (fs_discs[server][disc_ptr].name[0] != '\0')
			{
				found++;	
				snprintf((char * ) &(r.p.data[data_ptr]), 18, "%c%-16s", disc_ptr, fs_discs[server][disc_ptr].name);
				delivered++;
				data_ptr += 17;
			}
			disc_ptr++;
		}
	}

	r.p.data[2] = delivered;

	fs_aun_send(&r, server, data_ptr, net, stn);

}

// Read time
void fs_read_time(int server, unsigned short reply_port, unsigned char net, unsigned char stn, int active_id, unsigned char *data, int datalen)
{

	struct __econet_packet_udp r;

	struct tm t;
	time_t now;
	unsigned char monthyear, day;

	fs_debug (0, 2, "%12sfrom %3d.%3d Read FS time", "", net, stn);

	now = time(NULL);
	t = *localtime(&now);

	fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);
	//monthyear = (((t.tm_year - 81 - 40) & 0x0f) << 4) | ((t.tm_mon+1) & 0x0f);	
	
	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.data[0] = r.p.data[1] = 0;

	r.p.data[2] = day;
	r.p.data[3] = monthyear;
	r.p.data[4] = t.tm_hour;
	r.p.data[5] = t.tm_min;
	r.p.data[6] = t.tm_sec;

	fs_aun_send(&r, server, 7, net, stn);

}

// Read logged on users
void fs_read_logged_on_users(int server, unsigned short reply_port, unsigned char net, unsigned char stn, int active_id, unsigned char *data, int datalen)
{

	struct __econet_packet_udp r;
	unsigned short start, number;
	unsigned short found;
	unsigned short active_ptr;
	unsigned short ptr;

	start = *(data+5);
	number = *(data+6);

	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;

	r.p.data[0] = r.p.data[1] = 0;
	r.p.data[2] = 0; // 0 users found unless we alter it later

	ptr = 3;
	
	fs_debug (0, 2, "%12sfrom %3d.%3d Read logged on users", "", net, stn);

	// Get to the start entry in active[server][]

	active_ptr = 0;
	found = 0;

	while (active_ptr < ECONET_MAX_FS_USERS && found < start)
	{
		if (active[server][active_ptr].net != 0 || active[server][active_ptr].stn != 0)
			found++;
		active_ptr++;
	}

	if (active_ptr < ECONET_MAX_FS_USERS) // We've found the first one the station wants
	{
		int deliver_count = 0;

		while (active_ptr < ECONET_MAX_FS_USERS && deliver_count < number)
		{
			if (active[server][active_ptr].net != 0 || active[server][active_ptr].stn != 0)
			{
				char username[11];
				char *spaceptr;
				strncpy((char * ) username, (const char * ) users[server][active[server][active_ptr].userid].username, 10);
				spaceptr = strchr(username, ' ');
				if (spaceptr) *(spaceptr) = (char) 0x00; // Terminate early
				else username[10] = (char) 0x00; 
				found++;
				deliver_count++;
				sprintf((char * ) &(r.p.data[ptr]), "%c%c%-s%c%c", 
					active[server][active_ptr].stn, active[server][active_ptr].net,
					username, (char) 0x0d,
					((active[server][active_ptr].priv & FS_PRIV_SYSTEM) ? 1 : 0) );

				ptr += 4 + strlen(username); // 2 byte net/stn, 1 byte priv, 1 x 0x0d + the characters in the username
			}

			active_ptr++;
		}	

		r.p.data[2] = deliver_count;
	}


	fs_aun_send (&r, server, ptr, net, stn);
}

// Read user information
void fs_read_user_info(int server, unsigned short reply_port, unsigned char net, unsigned char stn, int active_id, unsigned char *data, int datalen)
{
	struct __econet_packet_udp r;
	unsigned char username[11], username_padded[15];
	unsigned short count;

	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;

	fs_copy_to_cr(username, (data+5), 10);

	snprintf (username_padded, 11, "%-10s", username);

	fs_debug (0, 2, "%12sfrom %3d.%3d Read user info for %s", "", net, stn, username);

	count = 0;

	while (count < ECONET_MAX_FS_USERS)
	{

		if ((active[server][count].stn != 0) && (!strncasecmp((const char *) username_padded, (const char *) users[server][active[server][count].userid].username, 10)))
		{

			unsigned short userid = active[server][count].userid;
			r.p.data[0] = r.p.data[1] = 0;
			if (users[server][userid].priv & FS_PRIV_SYSTEM)
				r.p.data[2] = 0x40; // This appears to be what L3 does for a privileged user
			else	r.p.data[2] = 0;

			r.p.data[3] = active[server][count].stn;
			r.p.data[4] = active[server][count].net;

			fs_aun_send(&r, server, 5, net, stn);
			break;
		
		}
		else count++;
	}
	
	if (count == ECONET_MAX_FS_USERS)
		fs_error(server, reply_port, net, stn, 0xBC, "No such user or not logged on");

}

// Read fileserver version number
void fs_read_version(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned char *data, int datalen)
{
	struct __econet_packet_udp r;
	
	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = 0x80;

	r.p.data[0] = r.p.data[1] = 0;
	sprintf((char * ) &(r.p.data[2]), "%s%c", FS_VERSION_STRING, 0x0d);

	fs_debug (0, 2, "%12sfrom %3d.%3d Read FS version", "", net, stn);

	fs_aun_send(&r, server, strlen(FS_VERSION_STRING)+3, net, stn);

}

// Read catalogue header
void fs_cat_header(int server, unsigned short reply_port, int active_id, unsigned char net, unsigned char stn, unsigned char *data, int datalen)
{
	unsigned char path[1024];
	unsigned short relative_to;
	struct path p;
	struct __econet_packet_udp r;
	
	relative_to = *(data+3);

	fs_copy_to_cr(path, data+5, 1022);

	fs_debug (0, 2, "%12sfrom %3d.%3d Read catalogue header %s", "", net, stn, path);

	if (!fs_normalize_path(server, active_id, path, relative_to, &p))
		fs_error(server, reply_port, net, stn, 0xd6, "Not found");
	else
	{
		if (p.ftype != FS_FTYPE_DIR)
			fs_error(server, reply_port, net, stn, 0xAF, "Types don't match");
		else if (p.my_perm & FS_PERM_OWN_R)
		{
			r.p.ptype = ECONET_AUN_DATA;
			r.p.port = reply_port;
			r.p.ctrl = 0x80;
			r.p.data[0] = r.p.data[1] = 0;

// MDFS manual has 10 character path, but Acorn traffic shows pad to 11! Similarly, disc name should be 15 but Acorn traffic has 16.
			sprintf((char * ) &(r.p.data[2]), "%-11s%c   %-16s%c%c", (char *) (p.npath == 0 ? "$" : (char *) p.path[p.npath-1]),
				(p.owner == active[server][active_id].userid ? 'O' : 'P'),
				fs_discs[server][active[server][active_id].current_disc].name,
				0x0d, 0x80);
	
			fs_aun_send(&r, server, 35, net, stn);	 // would be length 33 if Acorn server was within spec...
		}
		else	fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");

	}
	
}

// Load queue enque, deque functions

// load enqueue. net, stn are destinations. server parameter is to ensure queue is ordered. p & len are the packet to queue
// Length is data portion length only, so add 8 for the header on a UDP packet, 12 for AUN
// We do the malloc/free inside the enqueue/dequeue routines
// RETURNS:
// -1 Failure - malloc
// 1 Success

char fs_load_enqueue(int server, struct __econet_packet_udp *p, int len, unsigned char net, unsigned char stn, unsigned char internal_handle, unsigned char mode)
{

	struct __econet_packet_udp *u; // Packet we'll put into the queue
	struct __pq *q; // Queue entry within a host
	struct load_queue *l, *l_parent, *n; // l_ used for searching, n is a new entry if we need one

	fs_debug (0, 4, "to %3d.%3d              Enqueue packet length %04X type %d", net, stn, len, p->p.ptype);

	u = malloc(len + 8);
	memcpy(u, p, len + 8); // Copy the packet data off

	q = malloc(sizeof(struct __pq)); // Make a new packet entry

	if (!u || !q) return -1;

	//fs_debug (0, 2, "malloc() and copy succeeded");

	// First, see if there is an existing queue entry for this server to this destination, to which we will add the packet.
	// If there is, there is no need to build a new load_queue entry.

	l = fs_load_queue;
	l_parent = NULL;

	while (l && (l->server < server))
	{
		l_parent = l;
		l = l->next;
	}

	// So by here, if there were any entries at all, l points to the first one which is >= our server number.

	// Now see about the network.

	while (l && (l->server == server) && (l->net < net))
	{
		l_parent = l;
		l = l->next;
	}

	// And likewise station number. If we get here, though, either l points to first entry where l->server > server, or first entry where l->server == server BUT l->net >= l->net - or we fell off the end of the list

	while (l && (l->server == server) && (l->net == net) && (l->stn < stn))
	{
		l_parent = l;
		l = l->next;
	}

	// And similarly here, we will either have (l->server > server), or (servers equal but net >), or (servers and net equal, but stn >) or (servers and net and stn equal) or fell off end.

	//fs_debug (0, 2, "Existing queue%s found at %p", (l ? "" : " not"), l);

	if (!l || (l->server != server || l->net != net || l->stn != stn)) // No entry found - make a new one
	{

		// Make a new load queue entry

		fs_debug (0, 4, "Making new packet queue entry for this server/net/src triple ");

		n = malloc(sizeof(struct load_queue));

		if (!n)
		{
			free (u); free (q); return -1;
		}

		fs_debug (0, 4, " - at %p ", n);

		n->net = net;
		n->stn = stn;
		n->server = server;
		n->queue_type = 1; // 2 will be getbytes()
		n->mode = mode;
		n->internal_handle = internal_handle;
		n->pq_head = NULL;
		n->pq_tail = NULL;
		n->next = NULL; // Applies whether there was no list at all, or we fell off the end of it. We'll fix it below if we're inserting

		fs_debug (0, 4, " - fs_load_queue = %p, l = %p ", fs_load_queue, l);

		if (!fs_load_queue) // There was no queue at all
		{
			fs_debug (0, 4, " - as a new fs_load_queue");
			fs_load_queue = n;
		}
		else // We are inserting, possibly at the end
		{
			if (!l) // We fell off the end
			{
				fs_debug (0, 4, " - on the end of the existing queue");
				l_parent->next = n;
			}
			else // Inserting in the middle or at queue head
			{
				if (!l_parent)
				{
					n->next = fs_load_queue;
					fs_debug (0, 4, " - by inserting at queue head");
					fs_load_queue = n;
					
				}
				else
				{
					fs_debug (0, 4, " - by splice at %p", l_parent->next);
					n->next = l_parent->next; // Splice this one in
					l_parent->next = n;
				}
			}
		

		}
	}
	else // We must have found an existing queue for this server->{net,stn} traffic - just add the packet to it.
		n = l;

	q->packet = u;
	q->len = len; // Data len only
	q->next = NULL; // Always adding to end

	if (!(n->pq_head)) // No existing packet in the queue for this transaction
		n->pq_head = n->pq_tail = q;
	else // Add to end
	{
		n->pq_tail->next = q;
		n->pq_tail = q;
	}

/*
	fs_debug (0, 2, "Queue state for %d to %3d.%3d: Load queue head at %p", server, net, stn, n);
*/
	q = n->pq_head;

	while (q)
	{
		//fs_debug (0, 2, "         Packet length %04X at %p, next at %p", q->len, q, q->next);
		q = q->next;
	}

	return 1;

}

// fs_enqueue_dump - dump a load queue entry and update the table as necessary
void fs_enqueue_dump(struct load_queue *l)
{

	struct load_queue *h, *h_parent;
	struct __pq *p, *p_next;

	h = fs_load_queue;
	h_parent = NULL;

	if (l->queue_type == 1) // *LOAD operation
		fs_close_interlock(l->server, l->internal_handle, l->mode); // Mode should always be one in this instance

	while (h && (h != l))
	{
		h_parent = h;
		h = h->next;
	}

	if (!h) // not found
		return;

	// First, dump off any remaining packets
	
	p = h->pq_head;

	while (p)
	{
		p_next = p->next;
		if (p->packet) 
		{
			fs_debug (0, 4, "Freeing bulk transfer packet at %p", p->packet);
			free (p->packet); // Check it is not null, just in case...
		}
		fs_debug (0, 4, "Freeing bulk transfer queue entry at %p", p);
		free(p);
		p = p_next;

	}
	
	if (h_parent) // Mid chain, not at start
	{
		fs_debug (0, 4, "Freed structure was not at head of chain. Spliced between %p and %p", h_parent, h->next);
		h_parent->next = h->next; // Drop this one out of the chain
	}
	else
	{
		fs_debug (0, 4, "Freed structure was at head of chain. fs_load_queue now %p", h->next);
		fs_load_queue = h->next; // Drop this one off the beginning of the chain
	}

	fs_debug (0, 4, "Freeing bulk transfer transaction queue head at %p", h);

	free(h); // Free up this struct

	// Done.


}

// Go see if there is an enqueued packet to net, stn from server. If there is, send it and wait for ack.
// If not acknowledged, dump the rest of the enqueue for that destination from this server.
// If dumped or nothing left after tx, close the relevant file handle.
// Return values:
// 1 - Success
// 2 - Success at end
// 0 - Failure - No packet(!)
// -1 - No ack - dumped

char fs_load_dequeue(int server, unsigned char net, unsigned char stn)
{

	struct load_queue *l, *l_parent; // Search variable

	l = fs_load_queue;
	l_parent = NULL;

	fs_debug (0, 4, "to %3d.%3d from %3d.%3d de-queuing bulk transfer", net, stn, fs_stations[server].net, fs_stations[server].stn);

	while (l && (l->server != server || l->net != net || l->stn != stn))
	{
		l_parent = l;
		l = l->next;
	}

	if (!l) return 0; // Nothing found

	fs_debug (0, 4, "to %3d.%3d from %3d.%3d queue head found at %p", net, stn, fs_stations[server].net, fs_stations[server].stn, l);

	if (!(l->pq_head)) // There was an entry, but it had no packets in it!
	{
		// Take this one out of the chain
		if (l_parent)
			l_parent->next = l->next;
		else	fs_load_queue = l->next;

		free(l);

		return 0;
	}

	fs_debug (0, 4, "to %3d.%3d from %3d.%3d Sending packet from __pq %p, length %04X", net, stn, fs_stations[server].net, fs_stations[server].stn, l->pq_head, l->pq_head->len);


	if ((fs_aun_send(l->pq_head->packet, server, l->pq_head->len, l->net, l->stn) <= 0)) // If this fails, dump the rest of the enqueued traffic
	{
		fs_debug (0, 4, "fs_aun_send() failed in fs_load_sequeue() - dumping rest of queue");
		fs_enqueue_dump(l); // Also closes file
		return -1;

	}
	else // Tx success - just update the packet queue
	{
		struct __pq *p;

		p = l->pq_head;

		l->pq_head = l->pq_head->next;
		free(p->packet);
		free(p);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuse-after-free"
		fs_debug (0, 4, "Packet queue entry freed at %p", p);
#pragma GCC diagnostic pop

		if (!(l->pq_head)) // Ran out of packets
		{
			fs_debug (0, 4, "End of packet queue - dumping queue head at %p", l);
			l->pq_tail = NULL;
			fs_enqueue_dump(l);
			return 2;
		}

	}

	return 1; // Success - but still more packets to come
}

// Function called by the bridge when it knows there are things to dequeue
// Dumps out one packet per bulk transfer per server->{net,stn} combo each time.
#ifdef BRIDGE_V2
void fs_dequeue(int server)
#else
void fs_dequeue(void) 
#endif
{
	struct load_queue *l;

	fs_debug (0, 4, "fs_dequeue() called");
	l = fs_load_queue;

	while (l)
	{
		fs_debug (0, 4, "Dequeue from %p", l);

#ifdef BRIDGE_V2
		if (l->server == server)
			while (fs_load_dequeue(l->server, l->net, l->stn) == 1);
#else
		fs_load_dequeue(l->server, l->net, l->stn);
#endif
		l = l->next;
	}

}

// Ca#lled by the bridge to see if there is traffic
#ifdef BRIDGE_V2
short fs_dequeuable(int server)
#else
short fs_dequeuable(void)
#endif
{
	struct load_queue *l;

	unsigned short count = 0;

	l = fs_load_queue;

	while (l)
	{
#ifdef BRIDGE_V2
		if (l->server == server)
#endif
			count++;
		l = l->next;
	}

	fs_debug (0, 4, "There is%s data in the bulk transfer queue (%d entries)", (fs_load_queue ? "" : " no"), count);

#ifdef BRIDGE_V2
	if (count)
#else
	if (fs_load_queue)
#endif
		 return 1;
	
	return 0;
}

// Load file, & cope with 'Load as command'
void fs_load(int server, unsigned short reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned char *data, int datalen, unsigned short loadas, unsigned char rxctrl)
{
	unsigned char command[256];
	struct path p;
	struct __econet_packet_udp r;

	FILE *f;

	unsigned char data_port = *(data+2);

	unsigned char relative_to = *(data+3);
		
	unsigned short result;
	short internal_handle;

	fs_copy_to_cr(command, data+5, 256);

	if (loadas) // End the command at first space if there is one - BBC Bs seem to send the whole command line
	{
		int ptr;
		ptr = 0;
		while (ptr < strlen((const char *) command))
		{
			if (command[ptr] == ' ') command[ptr] = 0x00;
			ptr++;
		}
	}

	fs_debug (0, 1, "%12sfrom %3d.%3d %s %s", "", net, stn, (loadas ? "RUN" : "LOAD"), command);

	//if (!fs_normalize_path(server, active_id, command, active[server][active_id].current, &p) &&
	if (!(result = fs_normalize_path(server, active_id, command, relative_to, &p)) && !loadas) // Try and find the file first, but don't barf here if we are trying to *RUN it.
	{

/* This stops it searching the library!
		if (loadas)
			fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
		else
*/
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;
	}

	if ((!result || (p.ftype == FS_FTYPE_NOTFOUND)) && loadas && !fs_normalize_path(server, active_id, command, active[server][active_id].lib, &p))   // Either in current, or lib if loadas set
	{
/* OLD code - doesn't need to differentiate between loaas and !loadas - see the if() statement above
		if (loadas)
			fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
		else
			fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;
*/

		// Just barf
		fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
		return;
	}

	if (p.ftype != FS_FTYPE_FILE)
	{
		if (loadas)
			fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
		else
			fs_error(server, reply_port, net, stn, 0xD6, "Not found");
		return;
	}

	// Check permissions

	if (!((active[server][active_id].priv & FS_PRIV_SYSTEM) || (p.my_perm & FS_PERM_OWN_R))) // Note: my_perm has all the relevant privilege bits in the bottom 4
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}

	if ((internal_handle = fs_open_interlock(server, p.unixpath, 1, active[server][active_id].userid)) < 0)	
	{
		fs_error(server, reply_port, net, stn, 0xFE, "Already open");
		return;
	}
	
	f = fs_files[server][internal_handle].handle;

	r.p.port = reply_port;
	r.p.ctrl = rxctrl;
	r.p.ptype = ECONET_AUN_DATA;
	r.p.data[0] = r.p.data[1] = 0;

	// Send the file attributes

	r.p.data[2] = (p.load & 0xff);
	r.p.data[3] = (p.load & 0xff00) >> 8;
	r.p.data[4] = (p.load & 0xff0000) >> 16;
	r.p.data[5] = (p.load & 0xff000000) >> 24;
	r.p.data[6] = (p.exec & 0xff);
	r.p.data[7] = (p.exec & 0xff00) >> 8;
	r.p.data[8] = (p.exec & 0xff0000) >> 16;
	r.p.data[9] = (p.exec & 0xff000000) >> 24;
	r.p.data[10] = p.length & 0xff;
	r.p.data[11] = (p.length & 0xff00) >> 8;
	r.p.data[12] = (p.length & 0xff0000) >> 16;
	r.p.data[13] = p.perm;
	r.p.data[14] = p.day;
	r.p.data[15] = p.monthyear;

	if (fs_aun_send(&r, server, 16, net, stn))
	{
		// Send data burst

		int collected, enqueue_result;

		r.p.ctrl = 0x80;
		r.p.port = data_port;


		fseek (f, 0, SEEK_SET);

		while (!feof(f))
		{
			collected = fread(&(r.p.data), 1, 1280, f);
			
			if (collected > 0) enqueue_result = fs_load_enqueue(server, &r, collected, net, stn, internal_handle, 1); else enqueue_result = 0;

			if (collected < 0 || enqueue_result < 0)
			{
				fs_debug (0, 1, "Data burst enqueue failed");
				return; // Failed in some way
			}
	

		}
		
		// Send the tail end packet
	
		r.p.data[0] = r.p.data[1] = 0x00;
		r.p.port = reply_port;
		r.p.ctrl = rxctrl;

		fs_load_enqueue(server, &r, 2, net, stn, internal_handle, 1);

	}
	
	//fs_close_interlock(server, internal_handle, 1); // Now closed by the dequeuer
}

// Determine if received ctrl-byte sequence number is what we were expecting - returns non-zero if it was. 
// Since the rogue (set at file open) is 0x02, we check bottom *two* bits

unsigned char fs_check_seq(unsigned char a, unsigned char b)
{
	return ((a ^ b) & 0x03);
}

// Get byte from current cursor position
void fs_getbyte(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle, unsigned char ctrl)
{

	if (handle < 1 || handle >= FS_MAX_OPEN_FILES || active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
	else // Valid handle it appears
	{
		struct __econet_packet_udp r;
		unsigned char b; // Character read, if appropriate
		FILE *h;
		unsigned char result;
		struct stat statbuf;

		h = fs_files[server][active[server][active_id].fhandles[handle].handle].handle;

		fs_debug (0, 2, "%12sfrom %3d.%3d Get byte on channel %02x, cursor %04lX, ctrl seq is %s (stored: %02X, received: %02X)", "", net, stn, handle, active[server][active_id].fhandles[handle].cursor,
			fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl) ? "OK" : "WRONG", active[server][active_id].fhandles[handle].sequence, ctrl);

		if (active[server][active_id].fhandles[handle].is_dir) // Directory handle
		{
			r.p.ptype = ECONET_AUN_DATA;
			r.p.port = reply_port;
			r.p.ctrl = ctrl;
			r.p.data[0] = r.p.data[1] = 0;
			r.p.data[2] = 0xfe; // Always flag EOF
			r.p.data[3] = 0xc0;
		
			fs_aun_send(&r, server, 4, net, stn);
		
			return;
		}

		if (fstat(fileno(h), &statbuf)) // Non-zero = error
		{
			fs_error_ctrl(server, reply_port, net, stn, ctrl, 0xFF, "FS Error on read");
			return;
		}

		if (active[server][active_id].fhandles[handle].pasteof) // Already tried to read past EOF
		{
			fs_error_ctrl(server, reply_port, net, stn, ctrl, 0xDF, "EOF");
			return;
		}

		// Put the pointer back where we were

		clearerr(h);
		if (!fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl)) // Assume we want the previous cursor
			fseek(h, active[server][active_id].fhandles[handle].cursor_old, SEEK_SET);
		else
			fseek(h, active[server][active_id].fhandles[handle].cursor, SEEK_SET);

		active[server][active_id].fhandles[handle].cursor_old = ftell(h);

		fs_debug (0, 2, "%12sfrom %3d.%3d Get byte on channel %02x, cursor %04lX, file length = %04lX, seek to %04lX", "", net, stn, handle, active[server][active_id].fhandles[handle].cursor, ftell(h));

		b = fgetc(h);

		result = 0;

		if (ftell(h) == statbuf.st_size) result = 0x80;
		if (feof(h))
		{
			result = 0xC0; // Attempt to read past end of file
			active[server][active_id].fhandles[handle].pasteof = 1;
		}

		active[server][active_id].fhandles[handle].cursor = ftell(h);
		active[server][active_id].fhandles[handle].sequence = (ctrl & 0x01); 
	
		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = reply_port;
		r.p.ctrl = ctrl;
		r.p.data[0] = r.p.data[1] = 0;
		r.p.data[2] = (feof(h) ? 0xfe : b);
		r.p.data[3] = result;
	
		fs_aun_send(&r, server, 4, net, stn);

	}

}

void fs_putbyte(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle, unsigned char ctrl, unsigned char b)
{

	if (handle < 1 || handle >= FS_MAX_OPEN_FILES || active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
		fs_error_ctrl(server, reply_port, net, stn, ctrl, 0xDE, "Channel ?");
	else // Valid handle it appears
	{

		FILE *h;
		struct __econet_packet_udp r;

		if (active[server][active_id].fhandles[handle].mode < 2) // Not open for writing
		{
			fs_error_ctrl(server, reply_port, net, stn, ctrl, 0xc1, "Not open for update");
			return;
		}

		h = fs_files[server][active[server][active_id].fhandles[handle].handle].handle;

		{

			unsigned char buffer[2];

			buffer[0] = b;

			// Put the pointer back where we were

			clearerr(h);

			if (fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl))
				fseek(h, active[server][active_id].fhandles[handle].cursor, SEEK_SET);
			else // Duplicate. Read previous from old cursor
				fseek(h, active[server][active_id].fhandles[handle].cursor_old, SEEK_SET);

			active[server][active_id].fhandles[handle].cursor_old = ftell(h);

			fs_debug (0, 2, "%12sfrom %3d.%3d Put byte %02X on channel %02x, cursor %06lX ctrl seq is %s (stored: %02X, received: %02X)", "", net, stn, b, handle, active[server][active_id].fhandles[handle].cursor,
				fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl) ? "OK" : "WRONG", (active[server][active_id].fhandles[handle].sequence), ctrl);

			if (fwrite(buffer, 1, 1, h) != 1)
			{
				fs_error_ctrl(server, reply_port, net, stn, ctrl, 0xFF, "FS error writing to file");
				return;
			}

			fflush(h);

			// Update cursor
	
			active[server][active_id].fhandles[handle].cursor = ftell(h);
		

			fs_debug (0, 2, "%12sfrom %3d.%3d Put byte %02X on channel %02x, updated cursor %06lX", "", net, stn, b, handle, active[server][active_id].fhandles[handle].cursor);

		}
	
		active[server][active_id].fhandles[handle].sequence = (ctrl & 0x01);

		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = reply_port;
		r.p.ctrl = ctrl;
		r.p.data[0] = r.p.data[1] = 0;

		fs_aun_send(&r, server, 2, net, stn);

	}

}

// Get more than one byte from file
void fs_get_random_access_info(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle, unsigned short function)
{

	struct __econet_packet_udp r;

	if (active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
	{
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
		return;
	}

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;
	r.p.data[0] = r.p.data[1] = 0;


	switch (function) 
	{
		case 0: // Cursor position
			r.p.data[2] = (active[server][active_id].fhandles[handle].cursor & 0xff);
			r.p.data[3] = (active[server][active_id].fhandles[handle].cursor & 0xff00) >> 8;
			r.p.data[4] = (active[server][active_id].fhandles[handle].cursor & 0xff0000) >> 16;
			fs_debug (0, 2, "%12sfrom %3d.%3d Get random access info on handle %02X, function %02X - cursor %06lX - data returned %02X %02X %02X", "", net, stn, handle, function, active[server][active_id].fhandles[handle].cursor, r.p.data[2], r.p.data[3], r.p.data[4]);
			break;
		case 1: // Fall through extent / allocation - going to assume this is file size but might be wrong
		case 2:
		{
			struct stat s;

			if (fstat(fileno(fs_files[server][active[server][active_id].fhandles[handle].handle].handle), &s)) // Non-zero == error
			{
				fs_error(server, reply_port, net, stn, 0xFF, "FS error");
				return;
			}
		
			fs_debug (0, 2, "%12sfrom %3d.%3d Get random access info on handle %02X, function %02X - extent %06lX", "", net, stn, handle, function, s.st_size);

			r.p.data[2] = s.st_size & 0xff;
			r.p.data[3] = (s.st_size & 0xff00) >> 8;
			r.p.data[4] = (s.st_size & 0xff0000) >> 16;
			break;
		}
		
	}	

	fs_aun_send(&r, server, 5, net, stn);

}

// Get more than one byte from file
void fs_set_random_access_info(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle, unsigned char *data, unsigned short datalen)
{

	struct __econet_packet_udp r;
	unsigned short function;
	unsigned long value;
	unsigned long extent;
	FILE *f;
	struct stat s;

	if (active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
	{
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
		return;
	}

	f = fs_files[server][active[server][active_id].fhandles[handle].handle].handle;

	if (fstat(fileno(f), &s)) // Error
	{
		fs_error(server, reply_port, net, stn, 0xFF, "FS error");
		return;
	}

	extent = s.st_size;

	if (extent < 0) // Error
	{
		fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
		return;
	}

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;
	r.p.data[0] = r.p.data[1] = 0;

	function = *(data+6);
	value = (*(data+7)) + ((*(data+8)) << 8) + ((*(data+9)) << 16);

	switch (function)
	{
		case 0: // Set pointer
		{

			fs_debug (0, 2, "%12sfrom %3d.%3d Set file pointer on channel %02X to %06lX, current extent %06lX%s", "", net, stn, handle, value, extent, (value > extent) ? " which is beyond EOF" : "");
			if (value > extent) // Need to expand file
			{
				unsigned char buffer[4096];
				unsigned long to_write, written;
				unsigned int chunk;

				memset (&buffer, 0, 4096);
				fseek(f, 0, SEEK_END);
		
				to_write = value - extent;
	
				while (to_write > 0)
				{

					chunk = (to_write > 4096 ? 4096 : to_write);

					written = fwrite(buffer, 1, chunk, f);
					if (written != chunk)
					{
						fs_debug (0, 1, "Tried to write %d, but fwrite returned %ld", chunk, written);
						fs_error(server, reply_port, net, stn, 0xFF, "FS Error extending file");
						return;
					}
					
					fs_debug (0, 1, "%12sfrom %3d.%3d  - tried to write %06X bytes, actually wrote %06lX", "", net, stn, chunk, written);
					to_write -= written;
				}

				fflush(f);
			}

			active[server][active_id].fhandles[handle].cursor = value; // (value <= extent ? value : extent);
		
			// This didn't seem to work!
			//if (value > extent) r.p.data[1] = 0xC0;
			//if (value == extent) r.p.data[1] = 0x00;
		}
		break;
		case 1: // Set file extent
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d Set file extent on channel %02X to %06lX, current extent %06lX%s", "", net, stn, handle, value, extent, (value > extent) ? " so adding bytes to end of file" : "");
/*
			if (value > extent)
			{
				unsigned char buffer[4096];
				unsigned long to_write, written;

				memset (&buffer, 0, 4096);
				fseek(f, 0, SEEK_END);

				to_write = value - extent;

				while (to_write > 0)
				{
					written = fwrite(buffer, (to_write > 4096 ? 4096 : to_write), 1, f);
					if (written != (to_write > 4096 ? 4096 : to_write))
					{
						fs_debug (0, 1, "%12sfrom %3d.%3d Attempted to write chunk size %ld to the file, but fwrite returned %ld", "", net, stn, (to_write > 4096 ? 4096 : to_write), written);
						fs_error(server, reply_port, net, stn, 0xFF, "FS Error extending file");
						return;
					}
					to_write -= written;
				}
			}
*/
			fflush(f);

/*
			if (value < extent)
			{
*/
				fs_debug (0, 3, "%12sfrom%3d.%3d   - %s file accordingly", "", net, stn, ((value < extent) ? "truncating" : "extending"));
				if (ftruncate(fileno(f), value)) // Error if non-zero
				{
					fs_error(server, reply_port, net, stn, 0xFF, "FS Error setting extent");
					return;
				}
/*
			}
*/

		}
		break;
		default:
			fs_error(server, reply_port, net, stn, 0xFF, "FS Error - unknown function");
			return;

	}

	fs_aun_send (&r, server, 2, net, stn);
}

// Get more than one byte from file
void fs_getbytes(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle, unsigned char ctrl, unsigned char *data, unsigned short datalen)
{

	unsigned long bytes, offset;
	unsigned char txport, offsetstatus;
	long sent, length;
	unsigned short internal_handle;
	unsigned short eofreached, fserroronread;
	int received, total_received;

	unsigned char readbuffer[FS_MAX_BULK_SIZE];

	struct __econet_packet_udp r;

	txport = *(data+2);
	offsetstatus = *(data+6);
	bytes = (((*(data+7))) + ((*(data+8)) << 8) + (*(data+9) << 16));
	offset = (((*(data+10))) + ((*(data+11)) << 8) + (*(data+12) << 16));

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() %04lX from offset %04lX (%s) by user %04x on handle %02x, ctrl seq is %s (stored: %02X, received: %02X)", "", net, stn, bytes, offset, (offsetstatus ? "ignored - using current ptr" : "being used"), active[server][active_id].userid, handle,
		fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl) ? "OK" : "WRONG", active[server][active_id].fhandles[handle].sequence, ctrl);

	if (active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
	{
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
		return;
	}

	internal_handle = active[server][active_id].fhandles[handle].handle;

	if (datalen < 13)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad server request");
		return;
	}

	if (offsetstatus) // Read from current position
		offset = active[server][active_id].fhandles[handle].cursor;

	// This appears to be wrong. ANFS and EcoLink always send the fs_getbytes & fs_putbytes commands with ctrl &80
	//if (!fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl)) // Sequence number was wrong
		//offset = active[server][active_id].fhandles[handle].cursor_old; // Use cursor old even if a cursor is provided, IF the sequence number was wrong

	// Seek to end to detect end of file
	fseek(fs_files[server][internal_handle].handle, 0, SEEK_END);
	length = ftell(fs_files[server][internal_handle].handle);

	if (length == -1) // Error
	{
		char error_str[128];

		strerror_r(errno, error_str, 127);

		fs_error(server, reply_port, net, stn, 0xFF, "Cannot find file length");
		fs_debug (0, 1, "%12s from %3d.%3d fs_getbytes() on channel %d - error on finding length of file: %s", "", net, stn, handle, error_str);
		return;
	}

	if (offset >= length) // At or eyond EOF
		eofreached = 1;
	else
		eofreached = 0;

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() offset %06lX, file length %06lX, beyond EOF %s", "", net, stn, offset, length, (eofreached ? "Yes" : "No"));

	fseek(fs_files[server][internal_handle].handle, offset, SEEK_SET);
	active[server][active_id].fhandles[handle].cursor_old = offset; // Store old cursor
	active[server][active_id].fhandles[handle].cursor = offset;

	// Send acknowledge
	r.p.ptype = ECONET_AUN_DATA;
	r.p.port = reply_port;
	r.p.ctrl = ctrl; // Repeat the ctrl byte back to the station - MDFS does this
	r.p.data[0] = r.p.data[1] = 0;

	fs_aun_send(&r, server, 2, net, stn);

	fserroronread = 0;
	sent = 0;
	total_received = 0;

	while (sent < bytes)
	{
		unsigned short readlen;

		readlen = ((bytes - sent) > sizeof(readbuffer) ? sizeof(readbuffer) : (bytes - sent));

		received = fread(readbuffer, 1, readlen, fs_files[server][internal_handle].handle);

		// Use read() so we can get at errno!

		// received = read(fileno(fs_files[server][internal_handle].handle), readbuffer, readlen);

		fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() bulk transfer: bytes required %06lX, bytes already sent %06lX, buffer size %04X, ftell() = %06lX, bytes to read %06X, bytes actually read %06X", "", net, stn, bytes, sent, (unsigned short) sizeof(readbuffer), ftell(fs_files[server][internal_handle].handle), readlen, received);

		if (received != readlen) // Either FEOF or error
		{
			if (feof(fs_files[server][internal_handle].handle)) eofreached = 1;
			//if ((offset + received) >= length) eofreached = 1;
			else
			{
				//char err_string[128];

				//if (received == -1) 
				//{
					//strerror_r(errno, err_string, 127);
					//fs_debug (0, 2, "%12sfrom %3d.%3d file read returned %d, expected %d - error on read: %s", "", net, stn, received, readlen, err_string);
				//}
				//else
					fs_debug (0, 2, "%12sfrom %3d.%3d short file read returned %d, expected %d but not end of file", "", net, stn, received, readlen);
		
				if (ferror(fs_files[server][internal_handle].handle))
				{
					clearerr(fs_files[server][internal_handle].handle);
					#ifndef __NO_LIBEXPLAIN
						// explain_ferror() is not threadsafe - so it requires the global fs mutex
						fs_debug (0, 2, "%12sfrom %3d.%3d short file read returned %d, expected %d but not end of file - error flagged: %s", "", net, stn, received, readlen, explain_ferror(fs_files[server][internal_handle].handle));
					#else
						fs_debug (0, 2, "%12sfrom %3d.%3d short file read returned %d, expected %d but not end of file - error flagged: %s", "", net, stn, received, readlen, "Unknown (no libexplain)");
					#endif
				
				}
				fserroronread = 1;
			}
		}

		// Always send packets which total up to the amount of data the station requested, even if all the data is past EOF (because the station works that out from the closing packet)
		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = txport;
		r.p.ctrl = 0x80;

		if (received > 0)
			memcpy(&(r.p.data), readbuffer, received);	

		if (received < readlen) // Pad rest of data
			memset (&(r.p.data[received]), 0, readlen - received);

		// The real FS pads a short packet to the length requested, but then sends a completion message (below) indicating how many bytes were actually valid

		fs_aun_send(&r, server, readlen, net, stn);

		sent += readlen;
		total_received += received;
		
	}

	active[server][active_id].fhandles[handle].cursor += total_received; // And update the cursor
	active[server][active_id].fhandles[handle].sequence = (ctrl & 0x01); // Store this ctrl byte, whether it was right or wrong

	if (fserroronread)
		fs_error(server, reply_port, net, stn, 0xFF, "FS Error on read");
	else
	{
		// Send a completion message
	
		fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() Acknowledging %04lX tx bytes, cursor now %06lX", "", net, stn, sent, active[server][active_id].fhandles[handle].cursor);

		r.p.port = reply_port;
		//r.p.ctrl = 0x80;
		r.p.ctrl = ctrl; // Send the ctrl byte back to the station - MDFS does this on the close packet
		r.p.data[0] = r.p.data[1] = 0;
		r.p.data[2] = (eofreached ? 0x80 : 0x00);
		r.p.data[3] = (total_received & 0xff);
		r.p.data[4] = ((total_received & 0xff00) >> 8);
		r.p.data[5] = ((total_received & 0xff0000) >> 16);

		fs_aun_send(&r, server, 6, net, stn);
	}
	
}

void fs_putbytes(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle, unsigned char ctrl, unsigned char *data, unsigned short datalen)
{

	unsigned long bytes, offset, length;
	unsigned char txport, offsetstatus;
	unsigned short internal_handle;
	unsigned char incoming_port;

	struct __econet_packet_udp r;

	struct tm t; 
	unsigned char day, monthyear;
	time_t now;

	now = time(NULL);
	t = *localtime(&now);

	fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);
	//day = t.tm_mday;
	//monthyear = (((t.tm_year - 81 - 40) & 0x0f) << 4) | ((t.tm_mon+1) & 0x0f);	
								
	txport = *(data+2);
	offsetstatus = *(data+6);
	bytes = (((*(data+9)) << 16) + ((*(data+8)) << 8) + (*(data+7)));
	offset = (((*(data+12)) << 16) + ((*(data+11)) << 8) + (*(data+10)));

	if (active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
	{
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
		return;
	}

	internal_handle = active[server][active_id].fhandles[handle].handle;

	if (datalen < 13)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad server request");
		return;
	}

	fseek(fs_files[server][internal_handle].handle, 0, SEEK_END);
	length = ftell(fs_files[server][internal_handle].handle);

	if (offsetstatus) // write to current position
		offset = active[server][active_id].fhandles[handle].cursor;

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_putbytes() %06lX at offset %06lX by user %04X on handle %02d, ctrl seq is %s (stored: %02X, received: %02X)",
			"", net, stn,
			bytes, offset, active[server][active_id].userid, handle,
			fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl) ? "OK" : "WRONG (Ignored)", 
			active[server][active_id].fhandles[handle].sequence, ctrl);

	if (offset > length) // Beyond EOF
	{
		unsigned long count;

		fs_debug (0, 2, "%12s %3d.%3d fs_putbytes() Attempt to write at offset %06X beyond file end (length %06X) - padding with nulls", "", net, stn, offset, length);

		fseek(fs_files[server][internal_handle].handle, 0, SEEK_END);

		while (count++ < (offset-length))
			fputc('\0', fs_files[server][internal_handle].handle);
	}

	// This appears to be wrong. fs_putbytes() calls always turn up with ctrl &80. Maybe not so for the singular versions
	//if (!fs_check_seq(active[server][active_id].fhandles[handle].sequence, ctrl)) // If ctrl seq wrong, seek to cursor old regardless
		//offset = active[server][active_id].fhandles[handle].cursor_old;

	fseek(fs_files[server][internal_handle].handle, offset, SEEK_SET);

	// Update cursor_old
	// 20240102 Test update
	if (active[server][active_id].fhandles[handle].cursor != active[server][active_id].fhandles[handle].cursor_old)
		active[server][active_id].fhandles[handle].cursor_old = active[server][active_id].fhandles[handle].cursor;
		// OLD version active[server][active_id].fhandles[handle].cursor_old = ftell(fs_files[server][internal_handle].handle);

	// Update sequence
        active[server][active_id].fhandles[handle].sequence = (ctrl & 0x01);

	// 20240102 Update cursor to offset. If it's moved because we picked a particular start position for write, we don't seem to update it(!)
	active[server][active_id].fhandles[handle].cursor = offset;

	// We should be the only writer, so doing the seek here should be fine
	
	// Set up a bulk transfer here.

	if ((incoming_port = fs_find_bulk_port(server)))
	{
		fs_bulk_ports[server][incoming_port].handle = internal_handle;
		fs_bulk_ports[server][incoming_port].net = net;
		fs_bulk_ports[server][incoming_port].stn = stn;
		fs_bulk_ports[server][incoming_port].ack_port = txport; // Could be wrong
		fs_bulk_ports[server][incoming_port].length = bytes;
		fs_bulk_ports[server][incoming_port].received = 0; // Initialize counter
		fs_bulk_ports[server][incoming_port].reply_port = reply_port;
		fs_bulk_ports[server][incoming_port].rx_ctrl = ctrl; // Gets added to final close packet
		fs_bulk_ports[server][incoming_port].mode = 3;
		fs_bulk_ports[server][incoming_port].active_id = active_id; // So that the cursor can be updated as we receive
		fs_bulk_ports[server][incoming_port].user_handle = handle;
		fs_bulk_ports[server][incoming_port].last_receive = (unsigned long long) time(NULL);
		// Send acknowledge
		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = reply_port;
		r.p.ctrl = ctrl;
		r.p.data[0] = r.p.data[1] = 0;
		r.p.data[2] = incoming_port;
		r.p.data[3] = (fs_config[server].fs_bigchunks ? FS_MAX_BULK_SIZE : 0x500) & 0xff; // Max trf size
		r.p.data[4] = ((fs_config[server].fs_bigchunks ? FS_MAX_BULK_SIZE : 0x500) & 0xff00) >> 8; // High byte of max trf
	
		fs_aun_send(&r, server, 5, net, stn);
	}
	else	fs_error(server, reply_port, net, stn, 0xFF, "No channels available");

	if (bytes == 0) // No data expected
	{	
		fs_close_interlock(server, fs_bulk_ports[server][incoming_port].handle, 3);
		fs_bulk_ports[server][incoming_port].handle = -1; // Make the port available again
		r.p.port = reply_port;
		r.p.ctrl = ctrl;
		r.p.ptype = ECONET_AUN_DATA;
		r.p.data[0] = r.p.data[1] = 0;
		r.p.data[2] = FS_PERM_OWN_R | FS_PERM_OWN_W;
		r.p.data[3] = day;
		r.p.data[4] = monthyear;

		fs_aun_send (&r, server, 5, net, stn);
	}

}

void fs_eof(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle)
{

	unsigned char result = 0;
	struct stat	sb;

	if (handle < 1 || handle >= FS_MAX_OPEN_FILES || active[server][active_id].fhandles[handle].handle == -1) // Invalid handle
		fs_error(server, reply_port, net, stn, 0xDE, "Channel ?");
	else // Valid handle it appears
	{
		FILE *h;
		struct __econet_packet_udp r;
		long	filesize;

		h = fs_files[server][active[server][active_id].fhandles[handle].handle].handle;

		if (fstat(fileno(h), &sb))
		{
			fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
			return;
		}
			
		filesize = sb.st_size;

		// if (active[server][active_id].fhandles[handle].cursor == ftell(h))
		if (active[server][active_id].fhandles[handle].cursor == filesize)
			result = 1;

		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = reply_port;
		r.p.ctrl = 0x80;
		r.p.data[0] = r.p.data[1] = 0;
		r.p.data[2] = result;

		fs_aun_send(&r, server, 3, net, stn);
	}

}
// Close a specific user handle. Abstracted out to allow fs_close to cycle through all handles and close them when requested close handle is 0
void fs_close_handle(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle)
{

	if (active[server][active_id].fhandles[handle].handle == -1) // Handle not open
		fs_error(server, reply_port, net, stn, 222, "Channel ?");
	else
	{
		if (active[server][active_id].fhandles[handle].is_dir)
			fs_deallocate_user_dir_channel (server, active_id, handle);
		else
		{
			fs_close_interlock(server, active[server][active_id].fhandles[handle].handle, active[server][active_id].fhandles[handle].mode);	
			fs_deallocate_user_file_channel(server, active_id, handle);
		}
	}
}

void fs_close(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned short handle)
{

	unsigned short count;

	fs_debug (0, 2, "%12sfrom %3d.%3d Close handle %d", "", net, stn, handle);

	if (handle !=0 && active[server][active_id].fhandles[handle].handle == -1) // Handle not open
	{
		fs_debug (0, 4, " - unknown");
		fs_error(server, reply_port, net, stn, 222, "Channel ?");
		return;
	}

	count = 1;

	if (handle != 0)
	{
		fs_debug (0, 4, " - (%s)", active[server][active_id].fhandles[handle].acornfullpath);
		fs_close_handle(server, reply_port, net, stn, active_id, handle);
	}
	else // User wants to close everything
	{
		fs_debug (0, 4, " - closing");
		while (count < FS_MAX_OPEN_FILES)
		{	
			if (active[server][active_id].fhandles[count].handle != -1 && !(active[server][active_id].fhandles[count].is_dir)) // Close it only if it's open and not a directory handle
			{
				fs_close_handle(server, reply_port, net, stn, active_id, count);
			}
			count++;
		}
	}

	fs_reply_success(server, reply_port, net, stn, 0, 0);

}

// Open a file, with interlock
void fs_open(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int active_id, unsigned char * data, unsigned short datalen)
{

	unsigned char existingfile = *(data+5);
	unsigned char readonly = *(data+6);
	unsigned char filename[1024];
	unsigned short result;
	unsigned short count, start;
	short handle;
	struct path p;
	//struct path_entry *e;
	struct __econet_packet_udp reply;

	count = 7;
	while (*(data+count) == ' ' && count < datalen)
		count++;

	if (count == datalen)
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");

	start = count;

	while (*(data+count) != ' ' && count < datalen)
		count++;

	if (count != datalen) // space in the filename!
		*(data+count) = 0x0d; // So terminate it early

	fs_copy_to_cr(filename, data+start, 1023);

	fs_debug (0, 2, "%12sfrom %3d.%3d Open %s readonly %s, must exist? %s", "", net, stn, filename, (readonly ? "yes" : "no"), (existingfile ? "yes" : "no"));

	// If the file must exist, then we can use wildcards; else no wildcards
	// BUT we should be able to open a file for writing with wildcards in the path except the tail end
	// Then, below, if the file doesn't exist we barf if the tail has wildcards in it.
	//
	result = fs_normalize_path_wildcard(server, active_id, filename, active[server][active_id].current, &p, 1);

	// NB the wildcard normalize copies the first entry found into the &p structure itself for backward compatibility so this should be fine.
		
	//e = p.paths;

	if (!result) // The || !e was addded for wildcard version
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	}
	else if (existingfile && p.ftype == FS_FTYPE_NOTFOUND)
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xD6, "Not found");
	}
	else if (p.ftype == FS_FTYPE_NOTFOUND && (strchr(p.acornname, '*') || strchr(p.acornname, '#'))) // Cannot hand wildcard characters in the last segment of a name we might need to create - by this point, if the file had to exist and wasn't found, we'd have exited above. So by here, the file is capable of being created, so we cannot have wildcards in its name.
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xcc, "Bad filename");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && !readonly && ((p.my_perm & FS_PERM_OWN_W) == 0))
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xbd, "Insufficient access");
	}
	else if (!readonly && (p.ftype == FS_FTYPE_NOTFOUND) && 
		(	(p.parent_owner != active[server][active_id].userid && ((p.parent_perm & FS_PERM_OTH_W) == 0)) ||
			(p.parent_owner == active[server][active_id].userid && ((p.perm & FS_PERM_OWN_W) == 0))
			) // FNF and we can't write to the directory
		)
	{
		fs_debug(0,2, "%12sfrom %3d.%3d Attempt to open %s for write - p.parent_owner = %d, p.parent_perm = %02X, p.perm = %02X, userid = %d", "", net, stn, filename, p.parent_owner, p.parent_perm, p.perm, active[server][active_id].userid);
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xbd, "Insufficient access");
	}
	else
	{

		unsigned short userhandle, mode;

		// Do we have capacity to open this file?

		mode = (readonly ? 1 : existingfile ? 2 : 3);		

		userhandle = fs_allocate_user_file_channel(server, active_id);
	
		//fprintf (stderr, "%s\n", p.unixpath);

		if (userhandle)
		{

			char 	unix_segment[ECONET_MAX_FILENAME_LENGTH+3];

			// Even on a not found, normalize puts the last acorn segment in acornname
			strcpy(unix_segment, "/");
			strcat(unix_segment, p.unixfname);

			if (p.ftype == FS_FTYPE_NOTFOUND) // Opening non-existent file for write - add unix name to end of path
				strcat(p.unixpath, unix_segment);

			handle = fs_open_interlock(server, p.unixpath, (readonly ? 1 : existingfile ? 2 : 3), active[server][active_id].userid);
			//fs_debug(0, 2, "%12sfrom %3d.%3d fs_open_interlock() for %s with mode %d returned %s", "", net, stn, p.unixpath, (readonly ? 1 : existingfile ? 2: 3), handle);

			fs_free_wildcard_list(&p);
			
			if (handle == -1)  // Couldn't open a file when we think we should be able to
			{
				fs_error(server, reply_port, net, stn, 0xFF, "FS Error");
				fs_deallocate_user_file_channel(server, active_id, userhandle);
			}
			else if (handle == -2) // Interlock issue
			{
				fs_error(server, reply_port, net, stn, 0xC2, "Already open");
				fs_deallocate_user_file_channel(server, active_id, userhandle);
			}
			else if (handle == -3)
			{
				fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
				fs_deallocate_user_file_channel(server, active_id, userhandle);
			}
			else
			{	
				unsigned char	realfullpath[1024];

				// Wildcard system doesn't append final path element

				strcpy (realfullpath, p.acornfullpath);
				if (p.npath > 0)
				{
					strcat (realfullpath, ".");
					strcat (realfullpath, p.acornname); // 20231230 This line was outside the if() and it was probably adding an extra $ to a root path
				}

				fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, userhandle, handle);
				active[server][active_id].fhandles[userhandle].handle = handle;
				active[server][active_id].fhandles[userhandle].mode = mode;
				active[server][active_id].fhandles[userhandle].cursor = 0;	
				active[server][active_id].fhandles[userhandle].cursor_old = 0;	
				active[server][active_id].fhandles[userhandle].sequence = 2;	 // This is the 0-1-0-1 oscillator tracker. But sometimes a Beeb will start with &81 ctrl byte instead of &80, so we set to 2 so that the first one is guaranteed to be different
				active[server][active_id].fhandles[userhandle].pasteof = 0; // Not past EOF yet
				active[server][active_id].fhandles[userhandle].is_dir = (p.ftype == FS_FTYPE_DIR ? 1 : 0);

				//strcpy(active[server][active_id].fhandles[userhandle].acornfullpath, p.acornfullpath);
				strcpy(active[server][active_id].fhandles[userhandle].acornfullpath, realfullpath);
				// XX HERE - WAS THIS, CHANGED
				//fs_store_tail_path(active[server][active_id].fhandles[userhandle].acorntailpath, p.acornfullpath);
				fs_store_tail_path(active[server][active_id].fhandles[userhandle].acorntailpath, realfullpath);

				reply.p.ptype = ECONET_AUN_DATA;
				reply.p.port = reply_port;
				reply.p.ctrl = 0x80;
				//reply.p.data[0] = 0x07; // *DIR command code. FS3 does this. Not sure why. When debugging PanOS, L3 was not doing this!
				reply.p.data[0] = 0x00; 
				reply.p.data[1] = 0;
				reply.p.data[2] = (unsigned char) (FS_MULHANDLE(userhandle) & 0xff);
	
				fs_debug (0, 2, "%12sfrom %3d.%3d Opened handle %d (%s)", "", net, stn, userhandle, active[server][active_id].fhandles[userhandle].acornfullpath);
				fs_aun_send(&reply, server, 3, net, stn);
			}
		}
		else
		{
			fs_free_wildcard_list(&p);
			fs_error(server, reply_port, net, stn, 0xC0, "Too many open files");
		}
	}

}

// Return which printer the user has selected, or 0xff is none specific or not logged in
int8_t fs_get_user_printer(int server, unsigned char net, unsigned char stn)
{

	int active_id;
	
	active_id = fs_stn_logged_in(server, net, stn);

	if (active_id < 0)	return 0xff;

	return active[server][active_id].printer;
}

void fs_printout(int server, uint8_t reply_port, unsigned int active_id, uint8_t net, uint8_t stn, char *file, uint8_t relative_to)
{

	uint8_t				printer;
	char *				handler;
	char				unixprinter[128], acornprinter[7];
	struct path			p;
	unsigned short			result;


	//fs_debug (0, 1, "%12sfrom %3d.%3d *PRINTOUT %s", "", net, stn, file);

	result = fs_normalize_path_wildcard(server, active_id, file, relative_to, &p, 1);
	fs_free_wildcard_list(&p); // Don't need anything but the first

	if (!result)
	{
		fs_error (server, reply_port, net, stn, 0xCC, "Bad filename");
		return;
	}
	else if (p.ftype == FS_FTYPE_NOTFOUND)
	{
		fs_error (server, reply_port, net, stn, 0xD6, "Not found");
		return;
	}
	else if (p.ftype != FS_FTYPE_FILE)
	{
		fs_error (server, reply_port, net, stn, 0xFF, "Type mismatch");
		return;
	}

	printer = fs_get_user_printer(server, net, stn);
	handler = get_user_print_handler (fs_stations[server].net, fs_stations[server].stn, printer = 0xff ? 1 : printer, unixprinter, acornprinter);

	fs_debug (0, 2, "%12sfrom %3d.%3d *PRINTOUT %s (destination %s)", "", net, stn, file, acornprinter);

	if (!handler)
		fs_error (server, reply_port, net, stn, 0xFF, "Cannot print");
	else
	{
		// Copy file to temp (full unix path in p.unixpath)
		
		int	infile, tmpfile;
		char	template[80];
		uint8_t	buffer[1024];
		int	len;

		strcpy(template, "/tmp/econet.printout.XXXXXX");

		tmpfile = mkstemp(template);
		infile = open(p.unixpath, O_RDONLY);

		if (tmpfile == -1 || infile == -1)
		{
			if (tmpfile != -1) close(tmpfile);
			if (infile != -1) close(infile);

			fs_error(server, reply_port, net, stn, 0xFF, "Cannot spool file");
			return;
		}

		// Now copy the file
		
		while ((len = read(infile, buffer, 1024)) && (len != -1))
			write(tmpfile, (const void *) buffer, len);

		close(tmpfile);
		close(infile);

		if (len == -1)
		{
			unlink(template);
			fs_error(server, reply_port, net, stn, 0xFF, "Error while spooling");
		}
		else
		{
			char 	username[11];
			uint8_t	count;

			memcpy(username, &(users[server][active_id].username), 10);

			for (count = 0; count < 11; count++)
				if (username[count] == ' ' || count == 10) username[count] = '\0';

			send_printjob (handler, fs_stations[server].net, fs_stations[server].stn, net, stn, username, acornprinter, unixprinter, template);
			//fs_debug (0, 1, "%12sfrom %3d.%3d %s at %d.%d sent print job to printer %s/%s (%s)", "", fs_stations[server].net, fs_stations[server].stn, username, net, stn, acornprinter, unixprinter, template);
			fs_reply_ok(server, reply_port, net, stn);
		}

	}

}

// Handle *PRINTER from authenticated users
void fs_select_printer(int server, unsigned char reply_port, unsigned int active_id, unsigned char net, unsigned char stn, char *pname)
{

	int printerindex = 0xff;
	struct __econet_packet_udp reply;

	reply.p.ptype = ECONET_AUN_DATA;
	reply.p.port = reply_port;
	reply.p.ctrl = 0x80;
	reply.p.data[0] = reply.p.data[1] = 0;

	printerindex = get_printer(fs_stations[server].net, fs_stations[server].stn, pname);

	fs_debug (0, 1, "%12sfrom %3d.%3d Select printer %s - %s", "", net, stn, pname, (printerindex == -1) ? "UNKNOWN" : "Succeeded");

	if (printerindex == -1) // Failed
		fs_error(server, reply_port, net, stn, 0xFF, "Unknown printer");
	else
	{
		active[server][active_id].printer = printerindex;
		fs_aun_send(&reply, server, 2, net, stn);
	}

}

// Check if a user exists. Return index into users[server] if it does; -1 if not
int fs_user_exists(int server, unsigned char *username)
{
	int count;
	unsigned short found = 0;
	char username_padded[11];

	snprintf(username_padded, 11, "%-10s", username);

	count = 0;

	while (!found && count < ECONET_MAX_FS_USERS)
	{
		if (!strncasecmp((const char *) users[server][count].username, username_padded, 10) && (users[server][count].priv != FS_PRIV_INVALID))
			found = 1;
		else count++;
	}

	if (count == ECONET_MAX_FS_USERS) return -1;
	else return count;
	 
}

// Returns -1 if there are no user slots available, or the slot number if there are
short fs_find_new_user(int server)
{

	int count = 0;
	unsigned short found = 0;

	while (!found && count < ECONET_MAX_FS_USERS)
	{
		if (users[server][count].priv == FS_PRIV_INVALID)
			found = 1;
		else count++;
	}

	if (count == ECONET_MAX_FS_USERS) return -1;
	else return count;

}

// Handle incoming file / data transfers
void handle_fs_bulk_traffic(int server, unsigned char net, unsigned char stn, unsigned char port, unsigned char ctrl, unsigned char *data, unsigned int datalen)
{

	struct __econet_packet_udp r;

	// Do you know this man?

	if (		(fs_bulk_ports[server][port].handle != -1) && 
			(fs_bulk_ports[server][port].net == net) &&
			(fs_bulk_ports[server][port].stn == stn) 
	)
	{
		int writeable, remaining, old_cursor, new_cursor, new_cursor_read;

		// We can deal with this data
	
		remaining = fs_bulk_ports[server][port].length - fs_bulk_ports[server][port].received; // How much more are we expecting?

		writeable = (remaining > datalen ? datalen : remaining);
 
		if (fs_bulk_ports[server][port].user_handle != 0) // This is a putbytes transfer not a fs_save; in the latter there is no user handle. Seek to correct point in file
			fseek(fs_files[server][fs_bulk_ports[server][port].handle].handle, SEEK_SET, (old_cursor = active[server][fs_bulk_ports[server][port].active_id].fhandles[fs_bulk_ports[server][port].user_handle].cursor));

		fwrite(data, writeable, 1, fs_files[server][fs_bulk_ports[server][port].handle].handle);

		fflush(fs_files[server][fs_bulk_ports[server][port].handle].handle);
	
		fs_bulk_ports[server][port].received += datalen;

		if (fs_bulk_ports[server][port].user_handle != 0) // This is a putbytes transfer not a fs_save; in the latter there is no user handle
		{
			active[server][fs_bulk_ports[server][port].active_id].fhandles[fs_bulk_ports[server][port].user_handle].cursor += writeable;
			new_cursor = active[server][fs_bulk_ports[server][port].active_id].fhandles[fs_bulk_ports[server][port].user_handle].cursor;
			new_cursor_read = ftell(fs_files[server][fs_bulk_ports[server][port].handle].handle);
		}
	
		fs_debug (0, 2, "%12sfrom %3d.%3d Bulk transfer in on port %02X data length &%04X, expected total length &%04lX, writeable &%04X", "", net, stn, port, datalen, fs_bulk_ports[server][port].length, writeable
				);
		if (fs_bulk_ports[server][port].user_handle != 0) // Produce additional debug
			fs_debug (0, 2, "%12sfrom %3d.%3d Bulk trasfer on port %02X old cursor = %06X, new cursor in FS = %06X, new cursor from OS = %06X - %s", "", net, stn, port, old_cursor, new_cursor, new_cursor_read, (new_cursor == new_cursor_read) ? "CORRECT" : " *** ERROR ***");

		fs_bulk_ports[server][port].last_receive = (unsigned long long) time(NULL);

		if (fs_bulk_ports[server][port].received == fs_bulk_ports[server][port].length) // Finished
		{

			// Send a closing ACK

			struct tm t; 
			unsigned char day, monthyear;
			time_t now;

			now = time(NULL);
			t = *localtime(&now);

			fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);
								
			r.p.port = fs_bulk_ports[server][port].reply_port;
			r.p.ctrl = fs_bulk_ports[server][port].rx_ctrl;
			r.p.ptype = ECONET_AUN_DATA;
			r.p.data[0] = r.p.data[1] = 0;

			if (fs_bulk_ports[server][port].user_handle) // This was PutBytes, not save
			{
				r.p.data[2] = port;
				r.p.data[3] = fs_bulk_ports[server][port].received & 0xff;
				r.p.data[4] = (fs_bulk_ports[server][port].received & 0xff00) >> 8;
				r.p.data[5] = (fs_bulk_ports[server][port].received & 0xff0000) >> 16;
				fs_aun_send (&r, server, 6, net, stn);
			}
			else // Was a save
			{
				
				fs_close_interlock(server, fs_bulk_ports[server][port].handle, 3); // We don't close on a putbytes - file stays open!

				r.p.data[0] = 3; // This appears to be what FS3 does!
				r.p.data[2] = fs_perm_to_acorn(server, FS_PERM_OWN_R | FS_PERM_OWN_W, FS_FTYPE_FILE);
				r.p.data[3] = day;
				r.p.data[4] = monthyear;

				/* Per @arg's remark from the EcoIPFS - whilst the specs say pad the filename to 12 characters and terminate with &0d,
				   in fact existing servers pad to 12 characters with spaces and terminate it with a negative byte "(plus 3 bytes of
				   junk!)". So we'll try that. */

				//memset(&(r.p.data[5]), 0, 15); // 10 char filename code

				memset(&(r.p.data[5]), 32, 15); 

				//snprintf(&(r.p.data[5]), 13, "%-12s", fs_bulk_ports[server][port].acornname); // Commented out for long filenames
				{
					uint8_t counter = 0;

					while (fs_bulk_ports[server][port].acornname[counter] != 0)
					{
						r.p.data[5+counter] = fs_bulk_ports[server][port].acornname[counter];
						counter++;
					}
				}

				r.p.data[17] = 0x80;
				// And the 'junk'
				r.p.data[18] = 0x20; r.p.data[19] = 0xA9; r.p.data[20] = 0x24;

				fs_aun_send (&r, server, 21, net, stn);
				// OLD fs_aun_send (&r, server, 5, net, stn);
			}

			fs_bulk_ports[server][port].handle = -1; // Make the bulk port available again

		}
		else
		{	
			r.p.port = fs_bulk_ports[server][port].ack_port;
			r.p.ctrl = ctrl;
			r.p.ptype = ECONET_AUN_DATA;
			r.p.data[0] = r.p.data[1] = 0; // was FS_PERM_OWN_R | FS_PERM_OWN_W;
			fs_aun_send (&r, server, 2, net, stn);
		}

		

	}
	// Otherwise, er.... ignore it?
	
}

/* Garbage collect stale incoming bulk handles - This is called from the main loop in the bridge code */

void fs_garbage_collect(int server)
{

	int count; // == Bulk port number

	for (count = 1; count < 255; count++) // Start at 1 because port 0 is immediates...
	{
		if (fs_bulk_ports[server][count].handle != -1) // Operating handle
		{
			if (fs_bulk_ports[server][count].last_receive < ((unsigned long long) time(NULL) - 10)) // 10 seconds and no traffic
			{
				fs_debug (0, 2, "%12sfrom %3d.%3d Garbage collecting stale incoming bulk port %d used %lld seconds ago", "", 
					fs_bulk_ports[server][count].net, fs_bulk_ports[server][count].stn, count, ((unsigned long long) time(NULL) - fs_bulk_ports[server][count].last_receive));

				// fs_close_interlock(server, fs_bulk_ports[server][count].handle, fs_bulk_ports[server][count].mode); // Commented so that bulk transfers to ordinary files don't close the file

				if (fs_bulk_ports[server][count].active_id != 0) // No user handle = this was a SAVE operation, so if non zero we need to close the file & a user handle
				{
					fs_close_interlock(server, fs_bulk_ports[server][count].handle, fs_bulk_ports[server][count].mode);
					fs_deallocate_user_file_channel(server, fs_bulk_ports[server][count].active_id, fs_bulk_ports[server][count].user_handle);
				}

				fs_bulk_ports[server][count].handle = -1;
			}

		}

	}

}

// Find any servers this station is logged into and eject them in case the station is dynamically reallocated
void fs_eject_station(unsigned char net, unsigned char stn)
{
	int count = 0; // Fileservers

	fs_debug (0, 1, "%12s             Ejecting station %3d.%3d", "", net, stn);

	while (count < fs_count)
	{
		int user = 0;

		while (user < ECONET_MAX_FS_USERS)
		{
			if (active[count][user].net == net && active[count][user].stn == stn)
				fs_bye(count, 0, net, stn, 0); // Silent bye
			user++;

		}

		count++;

	}

}

/* Parse command line with abbreviation. 
   Command must have a minimum of 'min' characters followed either by the full command word,
   or at some stage a '.'.
   If there is a '.' then parameters can begin immediately
   If the command word is a full word, there must be at least one space after it before
   the parameters.
   
   parse - the string to be parsed
   cmd - the command word to search for
   min - minimum number of characters to match
   param_idx - returns ptr to parameters within parse for the start of parameters

   Returns 1 for match, 0 for no match
*/

uint8_t fs_parse_cmd (char *parse, char *cmd, unsigned short min, char **param_idx)
{


	uint8_t found = 0;
	char *ptr, *tmp;
	char workstr[256];

	/* Find a dot, space */

#ifdef FS_PARSE_DEBUG
	fs_debug (0, 1, "Parse debug: Looking for '%s' in '%s'   minimum length %d: ", cmd, parse, min);
#endif

	if (strlen(parse) < min) // Command cannot meet requirements
	{
#ifdef FS_PARSE_DEBUG
		fs_debug (0, 1, "Command too short to meet requirements");
#endif
		return 0;
	}

	ptr = parse+strlen(parse); // By the time this routine is called, the command is NULL terminated
	if ((tmp = strchr(parse+min, ' ')) && (ptr > tmp)) ptr = tmp;
	if ((tmp = strchr(parse+min, '.')) && (ptr > tmp)) ptr = tmp;

#ifdef FS_PARSE_DEBUG
	if (ptr) fs_debug (0, 1, "Found '%c' at position %d: ", *ptr, (unsigned int) (ptr-parse));
	else fs_debug (0, 1, "Found neither ' ', nor '.' nor end of command ");
#endif

	if (ptr) // Should always be!
	{
		strncpy(workstr, parse, 255);
		workstr[(unsigned short) (ptr-parse)] = '\0'; // Null terminate at the boundary we found

		tmp = ptr;

		if (*tmp == 0x00) *param_idx = tmp;
		else
		{
			tmp++;
			while ((*tmp != 0x0d) && (*tmp == ' '))
				tmp++;
			*param_idx = tmp;
		}

		// Now see if we have a matching string

		if (!strncasecmp(workstr, cmd, strlen(workstr))) // Found, potentially
		{
			if (strlen(workstr) == strlen(cmd)) // Full match - found
				found = 1;
			else if ((*ptr == '.') // Abbreviation
			&&	 (strlen(workstr) >= min) // Meets minimum length requirement
			)
				found = 1;

		}

#ifdef FS_PARSE_DEBUG
		if (found) fs_debug (0, 1, "Parameters at %d \n   Parameters: %s\n  Matched length %d: ", (int) (*param_idx - parse), *param_idx, strlen(workstr));
#endif
	}

#ifdef FS_PARSE_DEBUG
	fs_debug (0, 1, "Returning %d", found);
#endif

	return found;

}

void fs_write_readable_config(int server)
{

	unsigned char	configfile[1024];
	FILE		*out;
	uint8_t		count;

	sprintf(configfile, "%s/Configuration.txt", fs_stations[server].directory);

	out = fopen(configfile, "w");

	if (out)
	{
		fprintf (out, "Fileserver configuration for station %d.%d\n\n", fs_stations[server].net, fs_stations[server].stn);
		fprintf (out, "%-25s %s\n\n", "Root directory", fs_stations[server].directory);
		fprintf (out, "%-25s %d\n", "Total no. of discs", fs_stations[server].total_discs);

		for (count = 0; count < ECONET_MAX_FS_DISCS; count++)
			if (fs_discs[server][count].name[0]) fprintf (out, "Disc %2d                   %s\n", count, fs_discs[server][count].name);

		fprintf (out, "\n");

		fprintf (out, "%-25s %-3s\n", "Acorn Home semantics", (fs_config[server].fs_acorn_home ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "SJ Res'ch functions", (fs_config[server].fs_sjfunc ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "Big Chunks", (fs_config[server].fs_bigchunks ? "On" : "Off"));
		fprintf (out, "%-25s %-4s\n", "10 char pw conversion", (fs_config[server].fs_pwtenchar ? "Done" : "No"));
		fprintf (out, "%-25s %-3s\n", "Max filename length", (fs_config[server].fs_fnamelen ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "Inf files are :inf", (fs_config[server].fs_infcolon ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "> 8 file handles", (fs_config[server].fs_manyhandle ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "MDFS-style *INFO", (fs_config[server].fs_mdfsinfo ? "On" : "Off"));

		fclose(out);

	}

}

/* Handle locally arriving fileserver traffic to server #server, from net.stn, ctrl, data, etc. - port will be &99 for FS Op */
void handle_fs_traffic (int server, unsigned char net, unsigned char stn, unsigned char ctrl, unsigned char *data, unsigned int datalen)
{

	unsigned char fsop, reply_port; 
	unsigned int userid;
	int active_id;

	if (datalen < 1) 
	{
		fs_debug (0, 1, " from %3d.%3d Invalid FS Request with no data", net, stn);
		return;
	}

	reply_port = *data;
	fsop = *(data+1);

	if (fsop >= 64 && !(fs_config[server].fs_sjfunc)) // SJ Functions turned off
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Unsupported");
		return;
	}

	active_id = fs_stn_logged_in(server, net, stn);
	userid = fs_find_userid(server, net, stn);

	if (fsop != 0 && fsop != 0x0e && fsop != 0x19) // Things we can do when not logged in
	{
		if ((active_id < 0)) // Not logged in and not OSCLI (so can't be *I AM) or two opcodes which are fine for unauthenticated users
		{
			fs_error(server, reply_port, net, stn, 0xbf, "Who are you?");
			return;
		}

		if (userid < 0)
		{
			fs_error(server, reply_port, net, stn, 0xBC, "User not known");
			return;
		}
	}

	// Only do this if the FS Call actually presents file handles - some of them don't and we hadn't spotted that in earlier versions 
	
	if ((fsop != 8) && (fsop != 9)) // 8 & 9 are Getbyte / Putbyte which do not pass the usual three handles in the tx block
	{
		/* Modify the three handles that are in every packet - assuming the packet is long enough - if we are not in manyhandle mode */
	
		if (!fs_config[server].fs_manyhandle) // NFS 3 / BBC B compatible handles
		{
			if (!(fsop == 1 || fsop == 2 || (fsop == 5) || (fsop >=10 && fsop <= 11))) if (datalen >= 3) *(data+2) = FS_DIVHANDLE(*(data+2)); // Don't modify for LOAD, SAVE, RUNAS, (GETBYTE, PUTBYTE - not in this loop), GETBYTES, PUTBYTES - all of which either don't have the usual three handles in the tx block or use the URD for something else
			if (datalen >= 4) *(data+3) = FS_DIVHANDLE(*(data+3));
			if (datalen >= 5) *(data+4) = FS_DIVHANDLE(*(data+4));
		}
	
		if (active_id >= 0) // If logged in, update handles from the incoming packet
		{
			if (!(fsop == 1 || fsop == 2 || (fsop >= 8 && fsop <= 11))) active[server][active_id].root = *(data+2);
			if (datalen >= 4) active[server][active_id].current = *(data+3);
			if (datalen >= 5) active[server][active_id].lib = *(data+4);
		
			if (fsop != 0x09) // Not a putbyte
				active[server][active_id].sequence = 2; // Reset so that next putbyte will be taken to be in sequence.
		}
	}

	switch (fsop)
	{
		case 0: // OSCLI
		{
			unsigned char command[256];
			int counter;
			char *param;

			counter = 5;
			while ((*(data+counter) != 0x0d) && (counter < datalen))
			{
				command[counter-5] = *(data+counter);
				counter++;
			}
			command[counter-5] = 0;

			/* Note for TODO - parsing *LOAD / *LO. / *SAVE / *SA.:
				*LOAD <filename> <load4>
				*SAVE <filename> <start4> <end4 (or +length, can be without space after start)> [<exec4> [<reload4>]]

				*LOAD returns command code 2, return 0, load4, 1 byte 'load_addr_found' in aund - but what is it?, pathname (query termination)
				*SAVE returns command code 1, return 0, load4, exec4, length*3*, pathname (query termination)
			*/

			//if (!strncasecmp("I AM ", (const char *) command, 5)) fs_login(server, reply_port, net, stn, command + 5);
			if (fs_parse_cmd(command, "I AM", 2, &param)) fs_login(server, reply_port, net, stn, param);
			else if (fs_parse_cmd(command, "IAM", 3, &param)) fs_login(server, reply_port, net, stn, param);
			else if (fs_parse_cmd(command, "LOGIN", 4, &param)) fs_login(server, reply_port, net, stn, param);
			else if (fs_parse_cmd(command, "LOGON", 5, &param)) fs_login(server, reply_port, net, stn, param);
			//else if ((!strncasecmp("LOGIN ", (const char *) command, 6)) || (!strncasecmp("LOGON ", (const char *) command, 6))) fs_login(server, reply_port, net, stn, command + 6);
			//else if (!strncasecmp("IAM ", (const char *) command, 4)) fs_login(server, reply_port, net, stn, command + 4);
			//else if (!strncasecmp("I .", (const char *) command, 3)) fs_login(server, reply_port, net, stn, command + 3);
			else if (fs_stn_logged_in(server, net, stn) < 0)
				fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			//else if ((!strncasecmp("CAT", (const char *) command, 3)) || (!strncmp(".", (const char *) command, 1)))
			else if (fs_parse_cmd(command, "CAT", 2, &param) || fs_parse_cmd(command, ".", 1, &param))
			{

				struct __econet_packet_udp r;
				unsigned short len; // Length of path we are trying to CAT

				r.p.port = reply_port;
				r.p.ctrl = 0x80;
				r.p.ptype = ECONET_AUN_DATA;
	
				r.p.data[0] = 3; // CAT
				r.p.data[1] = 0; // Successful return
				
/*
				len = strlen(command)-1; // Drop first character (there will at least be a '.'!)
				if (*command == '.')
				{
					if (*(command+1) == ' ')
						len--; // Take one off for the space
				}
				else
				{
					len -= 3; // Adjust because this had the letters 'CAT' in it and we've already deducted one above, but there will may be be a space.
					if (*(command+3) == 0x00) // No parameters on *CAT - so nothing to copy
						len = 0;
				}
	

				if (len)
					strncpy(&(r.p.data[2]), &(command[(strlen(command) - len)]), len);

				r.p.data[len+2] = 0x0d; //Terminate string

*/
				len = strlen(param);

				strcpy(&(r.p.data[2]), param);
				r.p.data[len+2] = 0x0d; // Terminate string

				fs_aun_send (&r, server, len+3, net, stn);

			}
			else if (fs_parse_cmd(command, "LOAD", 2, &param))
			{
				uint32_t load_addr;
				char filename[ECONET_MAX_PATH_LENGTH+1];
				struct __econet_packet_udp r;

				r.p.port = reply_port;
				r.p.ctrl = 0x80;
				r.p.ptype = ECONET_AUN_DATA;
	
				r.p.data[0] = 2; // Load
				r.p.data[1] = 0; // Successful return

				load_addr = 0; // 

				r.p.data[6] = 0x00; // Load address not found - set if we do find one

				// Now check the various things which might be there
				if (sscanf(param, "%s %08x", filename, &load_addr) == 2)
					r.p.data[6] = 0xff;
				else if (sscanf(param, "%s", filename) == 1)
				{ }
				else
				{
					fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
					return;
				}			

				r.p.data[2] = (load_addr) & 0xff;
				r.p.data[3] = (load_addr >> 8) & 0xff;
				r.p.data[4] = (load_addr >> 16) & 0xff;
				r.p.data[5] = (load_addr >> 24) & 0xff;

				strcpy (&(r.p.data[7]), filename);
				r.p.data[7+strlen(filename)] = 0x0d;

				fs_aun_send (&r, server, 7 + 1 + strlen(filename), net, stn);
		
			}
			else if (fs_parse_cmd(command, "SAVE", 2, &param))
			{

				uint32_t save_addr, load_addr, exec_addr, length;
				unsigned short parsed;
				char filename[ECONET_MAX_PATH_LENGTH+1];
				struct __econet_packet_udp r;

				r.p.port = reply_port;
				r.p.ctrl = 0x80;
				r.p.ptype = ECONET_AUN_DATA;
	
				r.p.data[0] = 1; // Save
				r.p.data[1] = 0; // Successful return

				save_addr = load_addr = exec_addr = length = 0;

				if ((parsed = sscanf(param, "%s %08x +%08x %08x %08x", filename, &save_addr, &length, &exec_addr, &load_addr)) >= 3)
				{ 
					if (parsed < 4)
						exec_addr = save_addr;
					if (parsed < 5)
						load_addr = load_addr;
				}
				else if ((parsed = sscanf(param, "%s %08x %08x %08x %08x", filename, &save_addr, &length, &exec_addr, &load_addr)) >= 3) // NB not really length
				{
					length = (length - save_addr);

					if (parsed < 4)
						exec_addr = save_addr;
					if (parsed < 5)
						load_addr = load_addr;
				}
				else
				{
					fs_error(server, reply_port, net, stn, 0xff, "Bad parameters");
					return;
				}

				r.p.data[2] = (load_addr) & 0xff;
				r.p.data[3] = (load_addr >> 8) & 0xff;
				r.p.data[4] = (load_addr >> 16) & 0xff;
				r.p.data[5] = (load_addr >> 24) & 0xff;
				r.p.data[6] = (exec_addr) & 0xff;
				r.p.data[7] = (exec_addr >> 8) & 0xff;
				r.p.data[8] = (exec_addr >> 16) & 0xff;
				r.p.data[9] = (exec_addr >> 24) & 0xff;
				r.p.data[10] = (length) & 0xff;
				r.p.data[11] = (length >> 8) & 0xff;
				r.p.data[12] = (length >> 16) & 0xff;

				strcpy(&(r.p.data[13]), filename);
				r.p.data[13 + strlen(filename)] = 0x0d;

				fs_aun_send (&r, server, 13 + 1 + strlen(filename), net, stn);

			}
			//else if (!strncasecmp("BYE", (const char *) command, 3)) fs_bye(server, reply_port, net, stn, 1);
			else if (fs_parse_cmd(command, "BYE", 3, &param)) fs_bye(server, reply_port, net, stn, 1);
			//else if (!strncasecmp("SETLIB ", (const char *) command, 7))
			else if (fs_parse_cmd(command, "SETLIB", 4, &param))
			{ // Permanently set library directory
				unsigned char libdir[97], username[11], params[256];
				short uid;

				if (active[server][active_id].priv & FS_PRIV_LOCKED)
					fs_error(server, reply_port, net, stn, 0xbd, "Insufficient access");
				else
				{
					struct path p;
					//fs_copy_to_cr(params, param, 255); // There's no CR at the end of param...
					strncpy(params, param, 255);

					if ((active[server][active_id].priv & FS_PRIV_SYSTEM) && (sscanf(params, "%10s %80s", username, libdir) == 2)) // System user with optional username
					{
						if ((uid = fs_get_uid(server, username)) < 0)
						{
							fs_error(server, reply_port, net, stn, 0xFF, "No such user");
							return;
						}

						// Can't specify a disc on library set - it will search (eventually!)
						if (libdir[0] == ':')
						{
							fs_error(server, reply_port, net, stn, 0xFF, "Can't specify disc");
							return;
						}
					}
					else if (strchr(params, ' ')) // Non-privileged user attempting something with a space, or otherwise a pattern mismatch
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
						return;
					}
					else
					{
						uid = userid;
						strcpy(libdir, params);
					}	

					fs_debug (0, 1, "%12sfrom %3d.%3d SETLIB for uid %04X to %s", "", net, stn, uid, libdir);

					if (libdir[0] != '%' && fs_normalize_path(server, active_id, libdir, *(data+3), &p) && (p.ftype == FS_FTYPE_DIR) && strlen((const char *) p.path_from_root) < 94 && (p.disc == users[server][userid].home_disc))
					{
						if (strlen(p.path_from_root) > 0)
						{
							users[server][uid].lib[0] = '$';
							users[server][uid].lib[1] = '.';
							users[server][uid].lib[2] = '\0';
						}
						else	strcpy(users[server][uid].lib, "");

						strncat((char * ) users[server][uid].lib, (const char * ) p.path_from_root, 79);
						fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
						fs_reply_ok(server, reply_port, net, stn);
					}
					else if (libdir[0] == '%') // Blank off the library
					{
						strncpy((char *) users[server][uid].lib, "", 79);
						fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
						fs_reply_ok(server, reply_port, net, stn);
					}
					else	fs_error(server, reply_port, net, stn, 0xA8, "Bad library");
				}
			}
			//else if (!strncasecmp("PRINTER ", (const char *) command, 8))
			else if (fs_parse_cmd(command, "PRINTER", 6, &param))
				fs_select_printer(server, reply_port, active_id, net, stn, param);
			else if (fs_parse_cmd(command, "PRINTOUT", 6, &param))
				fs_printout(server, reply_port, active_id, net, stn, param, active[server][active_id].current);
			//else if (!strncasecmp("PASS ", (const char *) command, 5))
			else if (fs_parse_cmd(command, "PASS", 4, &param))
				fs_change_pw(server, reply_port, userid, net, stn, param);
			//else if (!strncasecmp("CHOWN ", (const char *) command, 6))
			else if (fs_parse_cmd(command, "CHOWN", 3, &param))
				fs_chown(server, reply_port, active_id, net, stn, param);
			//else if (!strncasecmp("OWNER ", (const char *) command, 6))
			else if (fs_parse_cmd(command, "OWNER", 3, &param))
				fs_owner(server, reply_port, active_id, net, stn, param);
			//else if (!strncasecmp("ACCESS ", (const char *) command, 7))
			else if (fs_parse_cmd(command, "ACCESS", 3, &param))
				fs_access(server, reply_port, active_id, net, stn, param);
			//else if (!strncasecmp("INFO ", (const char *) command, 5))
			else if (fs_parse_cmd(command, "INFO", 1, &param)) // For some reason *I. is an abbreviation for *INFO...
				fs_info(server, reply_port, active_id, net, stn, param);
			//else if (!strncasecmp("CDIR ", (const char *) command, 5))
			else if (fs_parse_cmd(command, "CDIR", 2, &param))
				fs_cdir(server, reply_port, active_id, net, stn, active[server][active_id].current, param);
			//else if (!strncasecmp("DELETE ", (const char *) command, 7))
			else if (fs_parse_cmd(command, "DELETE", 3, &param))
				fs_delete(server, reply_port, active_id, net, stn, active[server][active_id].current, param);
			//else if (!strncasecmp("RENAME ", (const char *) command, 7))
			else if (fs_parse_cmd(command, "RENAME", 3, &param))
				fs_rename(server, reply_port, active_id, net, stn, active[server][active_id].current, param);
			//else if (!strncasecmp("REN. ", (const char *) command, 5))
				//fs_rename(server, reply_port, active_id, net, stn, active[server][active_id].current, command+5);
			//else if (!strncasecmp("SDISC ", (const char *) command, 6))
			else if (fs_parse_cmd(command, "SDISC", 2, &param))
				fs_sdisc(server, reply_port, active_id, net, stn, param);
			//else if (!strncasecmp("COPY ", (const char *) command, 5))
			else if (fs_parse_cmd(command, "COPY", 2, &param))
				fs_copy(server, reply_port, active_id, net, stn, param);
			//else if (!strncasecmp("LIB ", (const char *) command, 4)) // Change library directory
			else if (fs_parse_cmd(command, "LIB", 3, &param))
			{
				int found;
				struct path p;
				unsigned short l, n_handle;
				unsigned char	dirname[1024];

				fs_debug (0, 1, "%12sfrom %3d.%3d LIB %s", "", net, stn, param);

				if (*param == '\0')	strcpy(dirname, "");
				else	
				{
					if (*param != '"') // Start quote
						strcpy(dirname, param);
					else
					{
						strcpy (dirname, param+1); // Skip opening quote
						if (dirname[strlen(dirname)-1] == '"')
							dirname[strlen(dirname)-1] = 0; // Strip closing quote
					}

				}

				if ((found = fs_normalize_path(server, active_id, dirname, *(data+3), &p)) && (p.ftype != FS_FTYPE_NOTFOUND)) // Successful path traverse
				{
					if (p.ftype != FS_FTYPE_DIR)
						fs_error(server, reply_port, net, stn, 0xAF, "Types don't match");
					/* 
					if (p.disc != active[server][active_id].current_disc)
						fs_error(server, reply_port, net, stn, 0xFF, "Not on current disc");
					*/
					else // BROKEN if (p.my_perm & FS_PERM_OWN_R)
					{	
						/* l = fs_get_dir_handle(server, active_id, p.unixpath); */
						l = fs_open_interlock(server, p.unixpath, 1, active[server][active_id].userid);
						if (l != -1) // Found
						{
							n_handle = fs_allocate_user_dir_channel(server, active_id, l);
							if (n_handle > 0)
							{
								int old;
								struct __econet_packet_udp r;

								old = active[server][active_id].lib;

								active[server][active_id].lib = n_handle;
								fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, n_handle, l);
								strncpy((char * ) active[server][active_id].lib_dir, (const char * ) p.path_from_root, 255);
								if (p.npath == 0)	strcpy((char * ) active[server][active_id].lib_dir_tail, (const char * ) "$         ");
								else			sprintf(active[server][active_id].lib_dir_tail, "%-80s", p.path[p.npath-1]); // Was 10
								
								strcpy(active[server][active_id].fhandles[n_handle].acornfullpath, p.acornfullpath);
								fs_store_tail_path(active[server][active_id].fhandles[n_handle].acorntailpath, p.acornfullpath);
								active[server][active_id].fhandles[n_handle].mode = 1;

								if (old > 0 && (old != active[server][active_id].current) && (old != active[server][active_id].lib))
								{
									fs_close_interlock(server, active[server][active_id].fhandles[old].handle, active[server][active_id].fhandles[old].mode);
									fs_deallocate_user_dir_channel(server, active_id, old);
								}

								r.p.ptype = ECONET_AUN_DATA;
								r.p.port = reply_port;
								r.p.ctrl = 0x80;
								r.p.data[0] = 0x09; // Changed directory;
								r.p.data[1] = 0x00;
								r.p.data[2] = FS_MULHANDLE(n_handle);
								fs_aun_send (&r, server, 3, net, stn);
							
							}
							else	fs_error(server, reply_port, net, stn, 0xC0, "Too many open directories");
						}
						else	fs_error(server, reply_port, net, stn, 0xD6, "Dir unreadable");
					}
					// BROKEN else	fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
				}
				else	fs_error(server, reply_port, net, stn, 0xFE, "Not found");
			}
			//else if (!strncasecmp("DIR ", (const char *) command, 4) || (!strncasecmp("DIR", (const char *) command, 3) && (*(command + 3) == 0x0d))) // Change working directory
			//else if (!strncasecmp("DIR", (const char *) command, 3) && (*(command + 3) == '\0' || *(command + 3) == ' ')) // The code above has already null terminated the command
			else if (fs_parse_cmd(command, "DIR", 3, &param) || fs_parse_cmd(command, "DIR^", 4, &param))
			{
				int found;
				struct path p;
				unsigned short l, n_handle;
				unsigned char dirname[1024];

				if (*param == '\0')	strcpy(dirname, "");
				else	
				{
					if (*param != '"') // Start quote
						strcpy(dirname, param);
					else
					{
						strcpy (dirname, param+1); // Skip opening quote
						if (dirname[strlen(dirname)-1] == '"')
							dirname[strlen(dirname)-1] = 0; // Strip closing quote
					}


				}

				if (!strncasecmp(command, "DIR^", 4))
				{
					strcpy (dirname, "^");
				}

				fs_debug (0, 1, "%12sfrom %3d.%3d DIR %s", "", net, stn, dirname);
			
				if (!strcmp(dirname, "")) // Empty string
				{
					// Go to current home
					//sprintf (dirname, ":%s.%s", fs_discs[server][active[server][active_id].home_disc].name, users[server][userid].home); // This is actual configured home, we need the current home!
					sprintf(dirname, "%s", active[server][active_id].fhandles[active[server][active_id].root].acornfullpath);
				}
					

				if ((found = fs_normalize_path(server, active_id, dirname, *(data+3), &p)) && (p.ftype != FS_FTYPE_NOTFOUND)) // Successful path traverse
				{
					if (p.ftype != FS_FTYPE_DIR)
						fs_error(server, reply_port, net, stn, 0xAF, "Types don't match");
					else // BROKEN if (p.my_perm & FS_PERM_OWN_R)
					{	
						l = fs_open_interlock(server, p.unixpath, 1, active[server][active_id].userid);
						if (l != -1) // Found
						{
							n_handle = fs_allocate_user_dir_channel(server, active_id, l);
							if (n_handle > 0)
							{
								int old;
								struct __econet_packet_udp r;
								
								old = active[server][active_id].current;
								active[server][active_id].current = n_handle;
								fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated for internal handle %d", "", net, stn, n_handle, l);
								strncpy((char * ) active[server][active_id].current_dir, (const char * ) p.path_from_root, 255);
								if (p.npath == 0)	strcpy((char * ) active[server][active_id].current_dir_tail, (const char * ) "$         ");
								else			sprintf(active[server][active_id].current_dir_tail, "%-80s", p.path[p.npath-1]); // Was 10
								
								strcpy(active[server][active_id].fhandles[n_handle].acornfullpath, p.acornfullpath);
								fs_store_tail_path(active[server][active_id].fhandles[n_handle].acorntailpath, p.acornfullpath);
								active[server][active_id].fhandles[n_handle].mode = 1;

								//if (old > 0 && (old != active[server][active_id].root) && (old != active[server][active_id].lib)) // Attempt to close the old handle if it isn't our URD
								if (old > 0)
								{
									fs_close_interlock(server, active[server][active_id].fhandles[old].handle, active[server][active_id].fhandles[old].mode);
									fs_deallocate_user_dir_channel(server, active_id, old);
								}

								active[server][active_id].current_disc = p.disc; 

								r.p.ptype = ECONET_AUN_DATA;
								r.p.port = reply_port;
								r.p.ctrl = 0x80;
								r.p.data[0] = 0x07; // Changed directory;
								r.p.data[1] = 0x00;
								r.p.data[2] = FS_MULHANDLE(n_handle);
								fs_aun_send (&r, server, 3, net, stn);
	
							
							}
							else	fs_error(server, reply_port, net, stn, 0xC0, "Too many open directories");
						}
						else	fs_error(server, reply_port, net, stn, 0xC7, "Dir unreadable");
					}
					// BROKEN else fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
				}
				else	fs_error(server, reply_port, net, stn, 0xFE, "Not found");
			}

			else if (active[server][active_id].priv & FS_PRIV_SYSTEM)
			{

				regmatch_t matches[10];

				// System commands here


				// Wonder why the regexec was commented out?
				//if (0)
				if (regexec(&fs_netconf_regex_one, command, 2, matches, 0) == 0) // Found a NETCONF
				{
					char configitem[100];
					int length;
					unsigned char operator; // The + or - on the command line
					FILE *config;
					char configfile[300];

					// temp use of length - will point to the operator character

					operator = command[matches[1].rm_so];

					length = matches[1].rm_eo - matches[1].rm_so - 1;
					configitem[length] = 0;

					while (length > 0)
					{
						configitem[length-1] = command[matches[1].rm_so + length];
						length--;
					}

					fs_debug (0, 1, "%12sfrom %3d.%3d NET CONFIG: %s -> %s", "", net, stn, configitem, (operator == '+' ? "ON" : "OFF"));

					if (!strcasecmp("ACORNHOME", configitem))
						fs_config[server].fs_acorn_home = (operator == '+' ? 1 : 0);
					else if (!strcasecmp("COLONMAP", configitem))
					{
						//char 	regex[1024];

						fs_config[server].fs_infcolon = (operator == '+' ? 1 : 0);
						/* This is wrong - r_pathname is the Acorn regex 
						regfree(&r_pathname);
						if (fs_config[fs_count].fs_infcolon)
							sprintf(regex, "^(%s{1,%d})", FSDOTREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);
						else
							sprintf(regex, "^(%s{1,%d})", FSREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);
		
						if (regcomp(&r_pathname, regex, REG_EXTENDED) != 0)
						fs_debug (1, 0, "Unable to compile regex for file and directory names.");
						*/
					}

					else if (!strcasecmp("MDFS", configitem))
						fs_config[server].fs_sjfunc = (operator == '+' ? 1 : 0);
					else if (!strcasecmp("BIGCHUNKS", configitem))
						fs_config[server].fs_bigchunks = (operator == '+' ? 1 : 0);
					else if (!strcasecmp("BIGHANDLES", configitem))
						fs_config[server].fs_manyhandle = (operator == '+' ? 1 : 0);
					else if (!strcasecmp("MDFSINFO", configitem))
						fs_config[server].fs_mdfsinfo = (operator == '+' ? 1 : 0);
					else
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Bad configuration entry name"); return;
					}
					
					sprintf(configfile, "%s/Configuration", fs_stations[server].directory);
	
					config = fopen(configfile, "w+");

					if (!config)
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Unable to write to FS Configuration"); return;
						fs_debug (0, 1, "Unable to write config file!");
					}
					else
					{
						fwrite(&(fs_config[server]), 256, 1, config);
						fclose(config);
						fs_write_readable_config(server);
					}
					
					fs_reply_ok(server, reply_port, net, stn);

				}
				else if (fs_parse_cmd(command, "FNLENGTH", 8, &param))
				{
					int new_length;
					char params[256];
					FILE *config;
					char configfile[300];

					fs_copy_to_cr(params, param, 20);
				
					if (sscanf(params, "%d", &new_length) == 1)
					{
						if (new_length >= 10 && new_length <= 80)
							ECONET_MAX_FILENAME_LENGTH = new_length;
						else
						{
							fs_error (server, reply_port, net, stn, 0xFF, "Bad maximum filename length");
							return;
						}
						sprintf(configfile, "%s/Configuration", fs_stations[server].directory);
		
						config = fopen(configfile, "w+");
	
						if (!config)
							fs_debug (0, 1, "Unable to write config file!");
						else
						{
							fwrite(&(fs_config[server]), 256, 1, config);
							fclose(config);
							fs_write_readable_config(server);
						}
						
						fs_reply_ok(server, reply_port, net, stn);

					}
					else
					{
						fs_error (server, reply_port, net, stn, 0xFF, "Bad parameter");
						return;
					}	
				}
				//else if (!strncasecmp("SETHOME ", (const char *) command, 8))
				else if (fs_parse_cmd(command, "SETHOME", 4, &param))
				{ // Permanently set home directory
					unsigned char params[256], dir[96], username[11];
					short uid;
	
					{
						struct path p;
						char homepath[300];
						struct objattr oa;

						fs_copy_to_cr(params, param, 255);

						if (sscanf(params, "%10s %80s", username, dir) == 2)
						{
							fs_debug (0, 1, "%12sfrom %3d.%3d Set Home dir for user %s to %s", "", net, stn, username, dir);
							uid = fs_get_uid(server, username);
							if (uid < 0)
							{
								fs_error(server, reply_port, net, stn, 0xFF, "No such user");
								return;
							}
						}
						else if (sscanf(params, "%80s", (unsigned char *) dir) != 1)
						{
							fs_debug (0, 1, "%12sfrom %3d.%3d Set Home dir - bad parameters %s", "", net, stn, params);
							fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
							return;
						}
						else	uid = userid;

						// Remove homeof flag from existing home directory

						if (users[server][uid].home[0]) // If there IS a home path
						{
							sprintf(homepath, ":%s.%s", fs_discs[server][users[server][uid].home_disc].name, users[server][uid].home);
							if (fs_normalize_path(server, active_id, homepath, *(data+3), &p) && (p.ftype == FS_FTYPE_DIR))
							{
								fs_read_xattr(p.unixpath, &oa, server);
								fs_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, 0, server); // Set homeof = 0
							}
						}
			
						if (!strcmp("%", dir)) // Blank it off
						{
							users[server][uid].home[0] = '\0';
							fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
							fs_reply_ok(server, reply_port, net, stn);
						}
						else if (fs_normalize_path(server, active_id, dir, *(data+3), &p) && (p.ftype == FS_FTYPE_DIR) && strlen((const char *) p.path_from_root) < 94)
						{
							if (strlen(p.path_from_root) > 0)
							{
								users[server][uid].home[0] = '$';
								users[server][uid].home[1] = '.';
								users[server][uid].home[2] = '\0';
							}
							else	strcpy(users[server][uid].home, "");
	
							strncat((char * ) users[server][uid].home, (const char * ) p.path_from_root, 79);
							users[server][uid].home_disc = p.disc;
							fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));

							// Set homeof attribute
							if (strlen(p.path_from_root)) // Don't set it on root!
							{
								fs_read_xattr(p.unixpath, &oa, server);
								fs_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, uid, server);
							}

							fs_reply_ok(server, reply_port, net, stn);
						}
						else	fs_error(server, reply_port, net, stn, 0xA8, "Bad directory");
					}
				}
				//else if (!strncasecmp("LINK ", (const char *) command, 5))
				else if (fs_parse_cmd(command, "LINK", 4, &param))
					fs_link(server, reply_port, active_id, net, stn, param);
				//else if (!strncasecmp("UNLINK ", (const char *) command, 7))
				else if (fs_parse_cmd(command, "UNLINK", 3, &param))
					fs_unlink(server, reply_port, active_id, net, stn, param);
				//else if (!strncasecmp("FLOG ", (const char *) command, 5)) // Force log user off
				else if (fs_parse_cmd(command, "FLOG", 3, &param))
				{
					char parameter[20];
					unsigned short l_net, l_stn;
					uint32_t	count;

					l_net = l_stn = 0;

					fs_copy_to_cr(parameter, param, 19);

					if (isdigit(parameter[0])) // Assume station number, possible net number too
					{
						if (sscanf(parameter, "%hd.%hd", &l_net, &l_stn) != 2)
						{
							if (sscanf(parameter, "%hd", &l_stn) != 1)
							{
								fs_error(server, reply_port, net, stn, 0xFF, "Bad station specification");
								return;
							}
							else	l_net = 0;
						}

						fs_debug (0, 1, "%12sfrom %3d.%3d Force log off station %d.%d", "", net, stn, l_net, l_stn);

						count = 0;

						while (count < ECONET_MAX_FS_USERS)
						{
							if (active[server][count].net == l_net && active[server][count].stn == l_stn)
								fs_bye(server, 0, l_net, l_stn, 0); // Silent bye
							count++;
						}
						
					}
					else // Username
					{
						uint8_t 	found = 0;
						unsigned char	paddeduser[10];

						paddeduser[10] = '\0';

						memcpy (paddeduser, parameter, strlen(parameter) > 10 ? 10 : strlen(parameter));

						count = strlen(parameter); // Pad the balance

						while (count < 10)
							paddeduser[count++] = 32;

						paddeduser[10] = '\0'; // Truncate

						fs_debug (0, 1, "%12sfrom %3d.%3d Force log off user '%s'", "", net, stn, paddeduser);
			
						// Find UserID
						
						count = 0;

						while (!found && count < fs_stations[server].total_users)
						{
							if (!memcmp(paddeduser, users[server][count].username, 10))
								found = count;
							else
								count++;
						}	

						if (!found)
							fs_error(server, reply_port, net, stn, 0xFF, "Unknown user");
						else
						{
							count = 0;
							// Look for user ID in active

							while (count < ECONET_MAX_FS_USERS)
							{
								if (active[server][count].userid == found)
									fs_bye(server, 0, active[server][count].net,
											active[server][count].stn, 0); // Silent bye
								count++;
							}
									

						}
					}

					fs_reply_ok(server, reply_port, net, stn);
				}
				//else if (!strncasecmp("NEWUSER ", (const char *) command, 8)) // Create new user
				else if (fs_parse_cmd(command, "NEWUSER", 4, &param))
				{
					unsigned char username[11];
					int ptr;
	
					fs_copy_to_cr(username, param, 10);
					
					fs_debug (0, 1, "%12sfrom %3d.%3d Create new user %s", "", net, stn, username);
	
					ptr = 0;
					while (ptr < 10 && username[ptr] != ' ')
						ptr++;
	
					if (ptr > 10)
					{
						fs_error(server,reply_port, net, stn, 0xD6, "Bad command");
						return;
					}
			
					username[ptr] = '\0';

					ptr++; // Now points to full name

					if (fs_user_exists(server, username) >= 0)
						fs_error(server, reply_port, net, stn, 0xFF, "User exists");
					else
					{
						int id;

						id = fs_find_new_user(server);
		
						if (id < 0)
							fs_error(server, reply_port, net, stn, 0xFF, "No available users");
						else
						{
							char homepath[300];

							snprintf((char * ) users[server][id].username, 11, "%-10s", username);
							snprintf((char * ) users[server][id].password, 11, "%-10s", "");
							snprintf((char * ) users[server][id].fullname, 25, "%-24s", &(username[ptr]));
							//users[server][id].home[0] = '\0';
							//users[server][id].lib[0] = '\0';
							snprintf((char * ) users[server][id].home, 97, "$.%s", username);
							snprintf((char * ) users[server][id].lib, 97, "$.%s", "Library");
							users[server][id].home_disc = 0;
							users[server][id].priv = FS_PRIV_USER;
							
							sprintf(homepath, "%s/%1x%s/%s", fs_stations[server].directory, 0, fs_discs[server][0].name, username);
							if (mkdir((const char *) homepath, 0770) != 0)
								fs_error(server, reply_port, net, stn, 0xff, "Unable to create home directory");
							else
							{
								fs_write_xattr(homepath, id, FS_PERM_OWN_W | FS_PERM_OWN_R, 0, 0, id, server); // Set home ownership. Is there a mortgage?
							
								fs_write_user(server, id, (unsigned char *) &(users[server][id]));
								if (id >= fs_stations[server].total_users) fs_stations[server].total_users = id+1;
								fs_reply_ok(server, reply_port, net, stn);
								fs_debug (0, 1, "%12sfrom %3d.%3d New User %s, id = %d, total users = %d", "", net, stn, username, id, fs_stations[server].total_users);
							
							}
							
							
						}
					}

				}
				//else if (!strncasecmp("PRIV ", (const char *) command, 5)) // Set user privilege
				else if (fs_parse_cmd(command, "PRIV", 4, &param) || fs_parse_cmd(command, "REMUSER", 4, &param))
				{
					char username[11], priv, priv_byte;

					unsigned short count;
		
					count = 0;
				
					while (count < strlen((const char *) param) && (count < 10) && param[count] != ' ')
					{
						username[count] = param[count];
						count++;
					}

					if (count == 0) // There wasn't a username
						fs_error(server, reply_port, net, stn, 0xFE, "Bad command");

					if ((command[0] == 'P') && count == strlen((const char *) param)) // THere was no space after the username and this was PRIV not REMUSER
						fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
					else
					{
						username[count] = '\0';
						count++;
						if (command[0] == 'P' && count == strlen((const char *) param)) // There was no priv character!
							fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
						else
						{
							if (command[0] == 'P')
								priv = param[count];	
							else	priv = 'D'; // This was REMUSER not PRIV, so we pick 'D' for delete

							switch (priv) {
								case 's': case 'S': // System user
									priv_byte = FS_PRIV_SYSTEM;			
									break;
								case 'u': case 'U': // Unlocked normal user
									priv_byte = FS_PRIV_USER;
									break;
								case 'l': case 'L': // Locked normal user
									priv_byte = FS_PRIV_LOCKED;
									break;
								case 'n': case 'N': // Unlocked user who cannot change password
									priv_byte = FS_PRIV_NOPASSWORDCHANGE;
									break;
								case 'd': case 'D': // Invalidate privilege - delete the user
									priv_byte = 0;
									break;
								default:
									priv_byte = 0xff;
									fs_error(server, reply_port, net, stn, 0xfe, "Bad command");
									break;
							}

							if (priv_byte != 0xff) // Valid change
							{
								unsigned short found = 0;
								count = 0;
								char username_padded[11];
			
								// Find user
		
								snprintf(username_padded, 11, "%-10s", username);
								

								while ((count < ECONET_MAX_FS_USERS) && !found)
								{
									if (!strncasecmp((const char *) users[server][count].username, username_padded, 10) && users[server][count].priv != FS_PRIV_INVALID)
									{
										users[server][count].priv = priv_byte;
										fs_write_user(server, count, (unsigned char *) &(users[server][count]));
										fs_reply_ok(server, reply_port, net, stn);
										found = 1;
									}
									count++;
								}
								
								fs_debug (0, 1, "%12sfrom %3d.%3d Attempt to change privilege for %s to %02x (%s)", "", net, stn, username, priv_byte, found ? "Success" : "Failed");
								if (count == ECONET_MAX_FS_USERS) 
								{
									fs_error(server, reply_port, net, stn, 0xbc, "User not found");
								}

							}
						}
					}
				}
				else // Unknown command
				{

					struct __econet_packet_udp r;
					unsigned short counter;
		
					r.p.port = reply_port;
					r.p.ctrl = 0x80;
					r.p.ptype = ECONET_AUN_DATA;
					r.p.data[0] = 0x08; // Unknown command
					r.p.data[1] = 0x00; // Unknown command
					counter = 0;
					while (counter < (datalen-5))
					{
						r.p.data[2+counter] = data[counter+5];
						counter++;
					}
	
					fs_aun_send(&r, server, 2+counter, net, stn);

				}
			}

			// Unknown command. 

			else 
			{
				struct __econet_packet_udp r;
				unsigned short counter;
	
				r.p.port = reply_port;
				r.p.ctrl = 0x80;
				r.p.ptype = ECONET_AUN_DATA;
				r.p.data[0] = 0x08; // Unknown command
				r.p.data[1] = 0x00; // Unknown command
				counter = 0;
				while (counter < (datalen-5))
				{
					r.p.data[2+counter] = data[counter+5];
					counter++;
				}

				fs_aun_send(&r, server, 2+counter, net, stn);

			}
				
			
		}
		break;
		case 0x01: if (fs_stn_logged_in(server, net, stn) >= 0) fs_save(server, reply_port, net, stn, active_id, data, datalen, ctrl); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?"); // Save file
			break;
		case 0x02: if (fs_stn_logged_in(server, net, stn) >= 0) fs_load(server, reply_port, net, stn, active_id, data, datalen, 0, ctrl); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?"); // Load without searching library
			break;
		case 0x03: // Examine directory
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_examine(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x04: // Catalogue header
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_cat_header(server, reply_port, active_id, net, stn, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x05: if (fs_stn_logged_in(server, net, stn) >= 0) fs_load(server, reply_port, net, stn, active_id, data, datalen, 1, ctrl); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?"); // Load with library search
			break;
		case 0x06: // Open file
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_open(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x07: // Close file
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_close(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+5))); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			// Experimentation with *Findlib reveals that the handle sought to be closed is actually at data+4 not data+5. Not sure what data+5 is then. Except that sometimes it IS in byte data+5. Maybe if it's a directory, it's in data+4 and a file is in data+5...
			//if (fs_stn_logged_in(server, net, stn) >= 0) fs_close(server, reply_port, net, stn, active_id, *(data+4)); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x08: // Get byte
			// Test harness
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_getbyte(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+2)), ctrl); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x09: // Put byte
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_putbyte(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+2)), ctrl, *(data+3)); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x0a: // Get bytes
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_getbytes(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+5)), ctrl, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x0b: // Put bytes
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_putbytes(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+5)), ctrl, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x0c: // Get Random Access Info
			fs_get_random_access_info(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+5)), *(data+6));
			break;
		case 0x0d: // Set Random Access Info
			fs_set_random_access_info(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+5)), data, datalen);
			break;
		case 0x0e: // Read disc names
			fs_read_discs(server, reply_port, net, stn, active_id, data, datalen);
			break;
		case 0x0f: // Read logged on users
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_read_logged_on_users(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x10: // Read time
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_read_time(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x11: // Read end of file status 
			//if (fs_stn_logged_in(server, net, stn) >= 0) fs_eof(server, reply_port, net, stn, active_id, *(data+2)); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_eof(server, reply_port, net, stn, active_id, FS_DIVHANDLE(*(data+5))); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?"); // this used to be data+2 for the handle, but I reckon it's really meant to be byte 5.
			break;
		case 0x12: // Read object info
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_get_object_info(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x13: // Set object info
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_set_object_info(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x14: // Delete object
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_delete(server, reply_port, active_id, net, stn, active[server][active_id].current, (data+5)); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x15: // Read user environment
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_read_user_env(server, reply_port, net, stn, active_id); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x16: // Set boot opts
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_set_bootopt(server, reply_port, userid, net, stn, data); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x17: // BYE
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_bye(server, reply_port, net, stn, 1); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x18: // Read user info
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_read_user_info(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x19: // Read FS version
			fs_read_version(server, reply_port, net, stn, data, datalen);
			break;
		case 0x1a: // Read free space
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_free(server, reply_port, net, stn, active_id, data, datalen); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x1b: // Create directory ??
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_cdir(server, reply_port, active_id, net, stn, *(data+3), (data+6)); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?");
			break;
		case 0x1c: // Set real time clock
			if ((fs_stn_logged_in(server, net, stn) >= 0) && (active[server][active_id].priv & FS_PRIV_SYSTEM))
			{
				// Silently accept but ignore
				struct __econet_packet_udp reply;

				reply.p.ptype = ECONET_AUN_DATA;
				reply.p.port = reply_port;
				reply.p.ctrl = 0x80;

				reply.p.data[0] = 0;
				reply.p.data[1] = 0;
	
				fs_aun_send (&reply, server, 2, net, stn);
			}
			else
				fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			break;
		case 0x1d: // Create file
			if (fs_stn_logged_in(server, net, stn) >= 0) fs_save(server, reply_port, net, stn, active_id, data, datalen, ctrl); else fs_error(server, reply_port, net, stn, 0xbf, "Who are you ?"); // fs_save works out whether it is handling a real save, or a 0x1d create
			break;
		// According to the excellent Arduino Filestore code, 28 is set FS clock, 29 is create file, 30 read user free space, 31 set user free space, 32 read client id, 33 read current users extended, 34 read user information extended,
		// 35 reserved, 36 "manager interface", 37 reserved.
		case 0x1e: // Read user free space - but we aren't implementing quotas at the moment
			if ((fs_stn_logged_in(server, net, stn) >= 0))
			{
				//fs_get_user_free_space(server, reply_port, active_id, net, stn, data); // data+5 has 0x0d terminated username
				struct __econet_packet_udp reply;

				reply.p.port = reply_port;
				reply.p.ctrl = 0x80;
				reply.p.ptype = ECONET_AUN_DATA;
				
				reply.p.data[0] = 0;
				reply.p.data[1] = 0;
				reply.p.data[2] = 0;
				reply.p.data[3] = 0;
				reply.p.data[4] = 0;
				reply.p.data[5] = 0x20; // 512Mb
				fs_aun_send (&reply, server, 6, net, stn);
			}
			break;
		case 0x1f: // Set user free space
			if ((fs_stn_logged_in(server, net, stn) >= 0) && (active[server][active_id].priv & FS_PRIV_SYSTEM))
			{
				//fs_set_user_free_space(server, reply_port, active_id, net, stn, data); // data+5 has little endian free space; data+9 has 0x0d terminated username
				fs_reply_success(server, reply_port, net, stn, 0, 0);
			}
			break;
		case 0x20: // Read client ID
			if (fs_stn_logged_in(server, net, stn) >= 0)
			{
				struct __econet_packet_udp reply;
				unsigned short counter;

				reply.p.port = reply_port;
				reply.p.ctrl = 0x80;
				reply.p.ptype = ECONET_AUN_DATA;
				strncpy(reply.p.data, users[server][active[server][active_id].userid].username, 10);
				counter = 0;
				while (counter < 10 && reply.p.data[counter] != ' ') counter++;
					reply.p.data[counter] = 0x0d;
				
				fs_aun_send (&reply, server, counter+1, net, stn);
			}
/* NOT YET IMPLEMENTED
		case 0x21: if (fs_stn_logged_in(server, net, stn) >= 0) fs_read_user_info_extended_multi(server, reply_port, net, stn, *(data+5), *(data+6)); break;
		case 0x22: if (fs_stn_logged_in(server, net, stn) >= 0) fs_read_user_info_extended_single(server, reply_port, net, stn, data+5); break;
		case 0x24: if ((fs_stn_logged_in(server, net, stn) >= 0) && active[server][active_id].priv & FS_PRIV_SYSTEM)
			{
				fs_manager_interface(server, reply_port, net, stn, *(data+5), data+6);
			}
			break;
*/
		case 0x40: // Read account information (SJ Only) - i.e. free space on a particular disc
			{
				if (fs_stn_logged_in(server, net, stn) >= 0)
				{

					unsigned int start, count;
				
					unsigned char disc;

					struct __econet_packet_udp reply;

					start = *(data+8) + (*(data + 9) << 8);
					count = *(data + 10) + (*(data + 11) << 8);
					disc = *(data + 12);

					reply.p.port = reply_port;
					reply.p.ctrl = 0x80;

					reply.p.ptype = ECONET_AUN_DATA;

					fs_debug (0, 1, "%12sfrom %3d.%3d SJ Read Account information from %d for %d entries on disc no. %d - Not yet implemented", "", net, stn, start, count, disc);

					// For now, return a dummy entry
			
					reply.p.data[0] = reply.p.data[1] = 0x00; // Normal OK result
					reply.p.data[2] = reply.p.data[3] = 0xff; // Next account to try
					reply.p.data[4] = 0x01; // 1 account returned
					reply.p.data[5] = 0x00; // Number of accounts returned high byte
					reply.p.data[6] = active[server][active_id].userid & 0xff;
					reply.p.data[7] = (active[server][active_id].userid & 0xff00) >> 8;
					reply.p.data[8] = reply.p.data[9] = 0xff; // Free space
			
					fs_aun_send (&reply, server, 10, net, stn);

				}
				else
					fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			}
			break;
		case 0x41: // Read/write system information (SJ Only)
			{
				// Read operations are unprivileged; write operations are privileged
				unsigned char rw_op;
				unsigned int reply_length;
	
				struct __econet_packet_udp reply;

				rw_op = *(data+5); // 0 - reset print server info; 1 - read current printer state; 2 - write current printer state; 3 - read auto printer priority; 4 - write auto printer priority ; 5 - read system msg channel; 6 - write system msg channel; 7 - read message level; 8 - set message level; 9 - read default printer; 10 - set default printer; 11 - read priv required to set time; 12 - set priv required to set time; IE ALL THE READ OPERATIONS HAVE LOW BIT SET

				reply.p.port = reply_port;
				reply.p.ctrl = 0x80;
				reply.p.ptype = ECONET_AUN_DATA;
		
				reply.p.data[0] = reply.p.data[1] = 0; // Normal OK result
				reply_length = 2;

				if (rw_op > 12 && rw_op != 15)
					fs_error(server, reply_port, net, stn, 0xff, "Unsupported");
				else if ((fs_stn_logged_in(server, net, stn) >= 0) && (rw_op & 0x01 || active[server][active_id].priv & FS_PRIV_SYSTEM))
				{
					switch (rw_op)
					{
						case 0: // Reset print server information	
						{
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Reset printer information", "", net, stn);
							// Later we might code this to put the priority things back in order etc.
							break; // Do nothing - no data in reply
						}
						case 1: // Read current state of printer
						{
							uint8_t printer;
							int account = 0;
							char pname[7], banner[24];
							uint8_t control, status;
							short user;

							printer = *(data+6) - 1; // we zero base; the spec is 1-8

							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read printer information for printer %d", "", net, stn, printer);

							if (!get_printer_info(fs_stations[server].net, fs_stations[server].stn,
								printer,
								pname, banner, &control, &status, &user))
							{
								fs_error(server, reply_port, net, stn, 0xff, "Unknown printer");
								return;
							}

							snprintf(&(reply.p.data[reply_length]), 7, "%-6.6s", pname);
							reply_length += 6;

							reply.p.data[reply_length++] = control;
	
							reply.p.data[reply_length++] = (account & 0xff);
							reply.p.data[reply_length++] = ((account & 0xff00) >> 8);

							snprintf(&(reply.p.data[reply_length]), 24, "%-s", banner);

							reply_length += strlen(banner);
							if (strlen(banner) < 23)
								reply.p.data[reply_length++] = 0x0d;

							break;

						}
						case 2: // Set current state of printer
						{

							uint8_t printer;
							char pname[7], banner[24];
							uint8_t control;
							short user;

							printer = *(data+6);
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Write printer information for printer %d", "", net, stn, printer);
							control = *(data+13);
							user = *(data+14) + (*(data+15) << 8);

							strncpy(banner, data+16, 23);	

							if (set_printer_info(fs_stations[server].net, fs_stations[server].stn,
								printer, pname, banner, control, user))
							{
								reply.p.data[reply_length++] =  0;
								reply.p.data[reply_length++] =  0;
							}
							else
							{
								fs_error(server, reply_port, net, stn, 0xff, "PS Error");
								return;
							}

						}
						// To implement - codes 1--10 except 5-8!
						case 5: // Read system message channel
						case 6: // Set system message channel (deliberate fall through)
						{
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ %s system message channel", "", net, stn, (rw_op == 5 ? "Read" : "Set"));
							if (rw_op == 5)
							{
								reply.p.data[2] = 1; // Always 1 (Parallel)
								reply_length++;
							}
		
	
							// We ignore the set request.

						} break;
						case 7: // Read current FS message level
						{
							unsigned char level = 0;

							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read system message level", "", net, stn);
#ifndef BRIDGE_V2
							if (!fs_quiet) level = 130; // "Function codes"
							if (fs_noisy) level = 150; // "All activity"
#else
							// Temporary
							level = 1;
#endif

							reply.p.data[2] = level;
							reply_length++;
						} break;
						case 8: // Set current FS message level
						{
							unsigned char level = *(data+6);
	
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Set system message level = %d", "", net, stn, level);
#ifndef BRIDGE_V2
							fs_quiet = 1; fs_noisy = 0;
							if (level > 0) fs_quiet = 0;
							if (level > 130) fs_noisy = 1;
#else
							// Do nothing for now
#endif
						
						} break;
						case 9: // Read default printer
						case 10: // Write default printer
						{

							fs_debug (0, 2, "%12sfrom %3d.%3d SJ %s system default printer", "", net, stn, (rw_op == 9 ? "Read" : "Set"));
							if (rw_op == 9) reply.p.data[reply_length++] = 1; // Always 1...
							// We always just accept the set command
						}
						case 11: // Read priv required to change system time
						{
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read privilege required to set system time", "", net, stn);
							reply.p.data[2] = 0; // Always privileged;
							reply_length++;
						} break;
						case 12: // Write priv required to change system time
						{
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Set privilege required to set system time (ignored)", "", net, stn);
							// Silently ignore - we are not going to let Econet users change the system time...
						} break;
						case 15: // Read printer info. Always return 0 printers for now
						{

							unsigned char start, number;
							uint8_t count;

							uint8_t numret = 0; // Number returned

							char pname[7], banner[24];
							uint8_t status, control;
							short account;

							number = *(data+6); start = *(data+7);
							fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read printer information, starting at %d (max %d entries)", "", net, stn, start, number);
							reply.p.data[2] = 0; reply_length++; // Number of entries

// This broke EDITPRINT							if ((start + number) > get_printer_total(fs_stations[server].net, fs_stations[server].stn)) reply.p.data[1] = 0x80; // Attempt to flag end of list (guessing here)

							for (count = start; count < (start + number); count++)
							{
								if (get_printer_info(fs_stations[server].net, fs_stations[server].stn,
									count, pname, banner, &control, &status, &account))
								{
									numret++;
									snprintf(&(reply.p.data[reply_length]), 7, "%-6.6s", pname);
									reply_length += 6;
									//reply.p.data[reply_length] = 0; // This appears to be an error
									if ((control & 0x01) == 0) reply.p.data[reply_length] = 0; // Off - the enable bit
									else reply.p.data[reply_length] = 1;
									reply_length++;
									reply.p.data[reply_length++] = 0; // Not default
									reply.p.data[reply_length++] = (control & 0x02) >> 1; // Anonymous use
									reply.p.data[reply_length++] = (control & 0x04) >> 2; // Account required;
									reply.p.data[reply_length++] = account & 0xff;
									reply.p.data[reply_length++] = (account & 0xff00) >> 8;
									reply.p.data[reply_length++] = 1; // Always say Parallel
									reply.p.data[reply_length++] = 0; // 2nd auto number
									reply.p.data[reply_length++] = 0; // reserved
									reply.p.data[reply_length++] = 0; // reserved

								}

							}
					
							reply.p.data[2] = numret;
							
							if (numret == 0) 
							{
								reply_length--; // Don't send the count. See if that sorts it out?
							}
							

						} break;
						default:
						{
							fs_error(server, reply_port, net, stn, 0xff, "Unsupported");
							return;
							break;
						}

					}	

					//fprintf (stderr, "*** GOT HERE *** Calling fs_aun_send() with server = %d, reply_length = %d, to %d.%d\n", server, reply_length, net, stn);
					fs_aun_send (&reply, server, reply_length, net, stn);
				}
				else
					fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			}
			break;
		default: // Send error
		{
			fs_debug (0, 1, "to %3d.%3d FS Error - Unknown operation 0x%02x", net, stn, fsop);
			fs_error(server, reply_port, net, stn, 0xff, "FS Error");
		}
		break;

	}
}

// Bridge V2 packet handler code

#ifdef BRIDGE_V2

/* This code has to detect bulk transfer ports.
   d is the device struct of containing this fileserver.
   p is the packet we're being asked to deal with
   length is the *data length* (not full packet length)

   The bridge itself will free the 'p' structure when we're done.

*/

void eb_handle_fs_traffic (uint8_t server, struct __econet_packet_aun *p, uint16_t length)
{

	uint8_t port;

	port = p->p.port;

	if (port == 0x99) // Ordinary FS traffic
		handle_fs_traffic (server, p->p.srcnet, p->p.srcstn, p->p.ctrl, (char *) &(p->p.data), length);
	else
		handle_fs_bulk_traffic (server, p->p.srcnet, p->p.srcstn, port, p->p.ctrl, (char *) &(p->p.data), length);

}

uint8_t fs_writedisclist (uint8_t server, unsigned char *addr)
{

	uint8_t	found = 0, count = 0;

	while (count < ECONET_MAX_FS_DISCS)
	{
		if (fs_discs[server][count].name[0]) // Found one
		{

			memcpy (addr+(found * 20), fs_discs[server][count].name, strlen(fs_discs[server][count].name));
			found++;
		}

		count++;
	}

	return ((found/2) + ((found%2 == 0) ? 0 : 1));
}
#endif
