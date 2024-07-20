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

/* Now in fs.h
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
	#include "../include/fs.h"
#endif
*/
#include "fs.h"

/*
// the ] as second character is a special location for that character - it loses its
// special meaning as 'end of character class' so you can match on it.
#define FSACORNREGEX    "[]\\(\\)\\'\\*\\#A-Za-z0-9\\+_\x81-\xfe;[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FSREGEX    "[]\\(\\)\\'\\*\\#A-Za-z0-9\\+_\x81-\xfe;:[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FSDOTREGEX "[]\\(\\)\\'\\*\\#A-Za-z0-9\\+_\x81-\xfe;\\.[\\?/\\£\\!\\@\\%\\\\\\^\\{\\}\\+\\~\\,\\=\\<\\>\\|\\-]"
#define FS_NETCONF_REGEX_ONE "^NETCONF(IG)?\\s+([\\+\\-][A-Z]+)\\s*"

#define FS_DIVHANDLE(x)	((fs_config[server].fs_manyhandle == 0) ? (  (  ((x) == 128) ? 8 : ((x) == 64) ? 7 : ((x) == 32) ? 6 : ((x) == 16) ? 5 : ((x) == 8) ? 4 : ((x) == 4) ? 3 : ((x) == 2) ? 2 : ((x) == 1) ? 1 : (x))) : (x))
#define FS_MULHANDLE(x) ((fs_config[server].fs_manyhandle != 0) ? (x) : (1 << ((x) - 1)))
*/

regex_t fs_netconf_regex_one;
short fs_netconf_regex_initialized = 0;
uint8_t fs_set_syst_bridgepriv = 0; // If set to 1 by the HP Bridge, then on initialization, each FS will enable the bridge priv on its SYST user
short fs_sevenbitbodge; // Whether to use the spare 3 bits in the day byte for extra year information
short use_xattr=1 ; // When set use filesystem extended attributes, otherwise use a dotfile
short normalize_debug = 0; // Whether we spew out loads of debug about filename normalization

struct __fs_station	*fileservers; /* Set to NULL in fs_setup() */

/* Moved to econet-fs-hpbridge-common.h */
#if 0
extern struct __eb_device * eb_find_station (uint8_t, struct __econet_packet_aun *);
extern uint8_t eb_enqueue_output (struct __eb_device *, struct __econet_packet_aun *, uint16_t, struct __eb_device *);
extern void eb_add_stats (pthread_mutex_t *, uint64_t *, uint16_t);
extern void eb_fast_priv_notify (struct __eb_device *, uint8_t, uint8_t, uint8_t);

void fs_write_readable_config(int);
#endif

// Parser
//#define FS_PARSE_DEBUG 1
uint8_t fs_parse_cmd (char *, char *, unsigned short, char **);

/* 
 * List of FSOps in our new list form
 */

struct fsop_list fsops[255]; 

regex_t r_discname, r_wildcard;

extern void eb_debug_fmt (uint8_t, uint8_t, char *, char *);
#if 0
int fs_stn_logged_in(int, unsigned char, unsigned char);
void fs_bye(int, unsigned char, unsigned char, unsigned char, unsigned short);
void fsop_build_data (struct fsop_data *, uint8_t, uint8_t, uint8_t);
#endif

#define fsop_debug	fs_debug

void fs_debug (uint8_t death, uint8_t level, char *fmt, ...)
{

	va_list 	ap;
	char		str[1024];
	char		padstr[1044];

	va_start (ap, fmt);

	vsprintf (str, fmt, ap);
	strcpy (padstr, "FS               ");
	strcat (padstr, str);
	eb_debug_fmt (death, level, "FS", padstr);

	va_end(ap);
}

void fs_debug_full (uint8_t death, uint8_t level, struct __fs_station *s, uint8_t net, uint8_t stn, char *fmt, ...)
{
	va_list 	ap;
	char		str[850];
	char		padstr[1044];

	va_start (ap, fmt);

	vsprintf (str, fmt, ap);
	sprintf (padstr, "FS       %3d.%3d from %3d.%3d %s", s->net, s->stn, net, stn, str);
	eb_debug_fmt (death, level, "FS", padstr);

	va_end(ap);
}

#if 0
void fs_get_parameters (uint8_t server, uint32_t *params, uint8_t *fnlength)
{
	struct fsop_data f;

	fsop_build_data (&f, server, 0, 0);

	fsop_get_parameters (&f, params, fnlength);
}
#endif

void fsop_get_parameters (struct __fs_station *server, uint32_t *params, uint8_t *fnlength)
{

	*fnlength = server->config->fs_fnamelen;
	*params = 0;
	*params |= (server->config->fs_default_dir_perm) << 24;
	*params |= (server->config->fs_default_file_perm) << 16;
	
	if (server->config->fs_acorn_home)	*params |= FS_CONFIG_ACORNHOME;
	if (server->config->fs_sjfunc)	*params |= FS_CONFIG_SJFUNC;
	if (server->config->fs_bigchunks)	*params |= FS_CONFIG_BIGCHUNKS;
	if (server->config->fs_infcolon)	*params |= FS_CONFIG_INFCOLON;
	if (server->config->fs_manyhandle)	*params |= FS_CONFIG_MANYHANDLE;
	if (server->config->fs_mdfsinfo)	*params |= FS_CONFIG_MDFSINFO;
	if (server->config->fs_pifsperms)	*params |= FS_CONFIG_PIFSPERMS;
	if (server->config->fs_mask_dir_wrr)	*params |= FS_CONFIG_MASKDIRWRR;
}

#if 0
void fs_set_parameters (uint8_t server, uint32_t params, uint8_t fnlength)
{
	struct fsop_data f;

	fsop_build_data (&f, server, 0, 0);

	fsop_set_parameters (&f, params, fnlength);
}

#endif

uint8_t fsop_write_server_config (struct __fs_station *s)
{
	unsigned char	configfile[512];
	FILE *		config;

	sprintf(configfile, "%s/Configuration", s->directory);

	config = fopen(configfile, "w+");

	if (!config)
	{
		fs_debug (0, 1, "Unable to write config file!");
		return 0;
	}
	else
	{
		fwrite(&s->config, 256, 1, config);
		fclose(config);
		fsop_write_readable_config(s);
		return 1;
	}
}

void fsop_set_parameters (struct __fs_station *server, uint32_t params, uint8_t fnlength)
{

	unsigned char		regex[1024];
	uint8_t			default_dir_perm, default_file_perm;

	default_dir_perm = (params & 0x00ff0000) >> 24;
	default_file_perm = (params & 0x0000ff00) >> 16;

	server->config->fs_acorn_home = (params & FS_CONFIG_ACORNHOME) ? 1 : 0;
	server->config->fs_sjfunc = (params & FS_CONFIG_SJFUNC) ? 1 : 0;
	server->config->fs_bigchunks = (params & FS_CONFIG_BIGCHUNKS) ? 1 : 0;
	server->config->fs_infcolon = (params & FS_CONFIG_INFCOLON) ? 1 : 0;
	server->config->fs_manyhandle = (params & FS_CONFIG_MANYHANDLE) ? 1 : 0;
	server->config->fs_mdfsinfo = (params & FS_CONFIG_MDFSINFO) ? 1 : 0;
	server->config->fs_pifsperms = (params & FS_CONFIG_PIFSPERMS) ? 1 : 0;
	server->config->fs_mask_dir_wrr = (params & FS_CONFIG_MASKDIRWRR) ? 1 : 0;

	if (fnlength != server->config->fs_fnamelen)
	{
		server->config->fs_fnamelen = fnlength;

		sprintf(regex, "^(%s{1,%d})", FSACORNREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);

		if (regcomp(&(server->r_pathname), regex, REG_EXTENDED) != 0)
			fs_debug (1, 0, "Unable to compile regex for file and directory names.");
	}

	server->config->fs_default_dir_perm = default_dir_perm;
	server->config->fs_default_file_perm = default_file_perm;

	fsop_write_server_config(server);

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
void fsop_make_mdfs_pw_file(struct __fs_station *s)
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
	
	while (picounter < s->total_users)
	{
		if (s->users[picounter].priv) // Active user
		{
			uint32_t	fileptr;

			// Empty the destination struct
			memset(&(mu[mucounter]), 0, sizeof(struct mdfs_user));

			fs_mdfs_copy_terminate((unsigned char *) &(mu[mucounter].username), (unsigned char *) &(s->users[picounter].username), 10);
			fs_mdfs_copy_terminate((unsigned char *) &(mu[mucounter].password), (unsigned char *) &(s->users[picounter].password), 10);

			// Boot option
			mu[mucounter].opt = s->users[picounter].bootopt;

			// Privilege
			mu[mucounter].flag = fs_pifs_to_mdfs_priv(s->users[picounter].priv);

			// UID
			mu[mucounter].uid[0] = (picounter & 0xff);
			mu[mucounter].uid[1] = (picounter & 0xff00) >> 8;

			// Set pointers for URD & LIB
			
			fileptr = fs_get_mdfs_dir_pointer (s->users[picounter].home, 0, mu[mucounter].username);
			mu[mucounter].offset_root[0] = (fileptr & 0x000000FF);
			mu[mucounter].offset_root[1] = (fileptr & 0x0000FF00) >> 8;
			mu[mucounter].offset_root[2] = (fileptr & 0x00FF0000) >> 16;

			fileptr = fs_get_mdfs_dir_pointer (s->users[picounter].lib, 1, mu[mucounter].username);
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

			total = 0;

			while (bytecount < 3)
			{
				total += ((mu[dircounter].offset_root[bytecount] << (8 * bytecount)) + (do_bytes[bytecount] << (8 * bytecount)));
				bytecount++;
			}

			mu[dircounter].offset_root[0] = (total & 0xFF);
			mu[dircounter].offset_root[1] = (total & 0xFF00) >> 8;
			mu[dircounter].offset_root[2] = (total & 0xFF0000) >> 16;
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

			total = 0;

			while (bytecount < 3)
			{
				total += ((mu[dircounter].offset_lib[bytecount] << (8 * bytecount)) + (do_bytes[bytecount] << (8 * bytecount)));
				bytecount++;
			}

			mu[dircounter].offset_lib[0] = (total & 0xFF);
			mu[dircounter].offset_lib[1] = (total & 0xFF00) >> 8;
			mu[dircounter].offset_lib[2] = (total & 0xFF0000) >> 16;
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

	strcpy(mdfs_pwfile, s->directory);
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

#if 0 
/* About to be disused */
/* 
 * fsop_build_data
 *
 * Fill in the struct fsop_data provided by 
 * populating the server data and user data 
 * for the user logged into the net & stn provided
 */

void fsop_build_data (struct fsop_data *param, uint8_t server, uint8_t net, uint8_t stn)
{

	int	active_id;

	param->net = net;
	param->stn = stn;

	active_id = fs_stn_logged_in(server, net, stn);

	param->active = (f->active_id >= 0 ? &(active[server][active_id]) : NULL);
	param->active_id = active_id;

	param->user = (f->active_id >= 0 ? &(users[server][param->active->userid]) : NULL);
	param->user_id = param->active->userid;

	param->server = &(fs_stations[server]);
	param->server_id = server;

	param->server->config = &(fs_config[server]);
	param->server->discs = &(fs_discs[server][0]);
	param->server->files = &(fs_files[server][0]);
	param->server->dirs = &(fs_dirs[server][0]);
	param->server->users = &(users[server][0]);
	param->server->enabled = fs_enabled[server];

}
#endif

// Find a disc number by name

int fsop_get_discno(struct fsop_data *f, char *discname)
{
	struct __fs_disc	*d;

	d = f->server->discs;

	while (d)
	{
		if (!strcasecmp(d->name, discname))
			return d->index;
		d = d->next;
	}

	return -1;
}

// Find username if it exists in server's userbase
int16_t fsop_get_uid(struct __fs_station *s, char *username)
{
	int16_t counter = 0;
	unsigned char padded_username[11];
	
	strcpy(padded_username, username);

	counter = strlen(padded_username);

	while (counter < 10) padded_username[counter++] = ' ';

	padded_username[counter] = '\0';

	fs_toupper(padded_username);

	counter = 0;

	while (counter < ECONET_MAX_FS_USERS && (strncasecmp(padded_username, s->users[counter].username, 10) != 0))
		counter++;

	return ((counter < ECONET_MAX_FS_USERS) ? counter : -1);
}

/*
 * Return full username in *username
 * for a given user ID.
 *
 * See fs_get_username() for this based on active ID
 */

void fsop_get_username_base (struct __fs_station *s, int userid, char *username)
{
	memcpy (username, &(s->users[userid]), 10);
}

void fsop_get_username_lock (struct __fs_active *a, char *username)
{
	pthread_mutex_lock(&(a->server->fs_mutex));
	fsop_get_username_base (a->server, a->userid, username);
	pthread_mutex_lock(&(a->server->fs_mutex));
	return;
}

// Fill character array with username for a given active_id on this server. Put NULL in
// first byte if active id is invalid
void fsop_get_active_username (struct fsop_data *f, struct __fs_active *a, char *username)
{
	fsop_get_username_base(f->server, a->userid, username);
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

void fs_copy_padded(unsigned char *dst, unsigned char *src, uint16_t maxlen)
{
	uint16_t	count;

	strncpy(dst, src, maxlen);

	*(dst + maxlen) = '\0';

	if (maxlen < ECONET_ABS_MAX_FILENAME_LENGTH)
	{
		for (count = strlen(src); count < maxlen; count++)
			*(dst+count) = ' ';
	}
}

// Convert our perm storage to Acorn / MDFS format
uint8_t fsop_perm_to_acorn(struct __fs_station *s, uint8_t fs_perm, uint8_t ftype)
{
	uint8_t r;

	r = fs_perm & FS_PERM_H; // High bit

	if (ftype == FS_FTYPE_DIR)
		r |= 0x20;

	if (fs_perm & FS_PERM_L)
		r |= 0x10;

	if (s->config->fs_sjfunc & FS_PERM_H) // SJ research Privacy bit
		r |= ((fs_perm & (FS_PERM_H)) ? 0x40 : 0);

	r |= ((fs_perm & (FS_PERM_OWN_R | FS_PERM_OWN_W)) << 2);
	r |= ((fs_perm & (FS_PERM_OTH_R | FS_PERM_OTH_W)) >> 4);
	
	if (ftype == FS_FTYPE_DIR && s->config->fs_mask_dir_wrr && ((fs_perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)) // (OTH_W) added here because we want to provide full real perms if OTH_W is set
		r &= 0xF2;  // Acorn OWN_W, OWN_R, OTH_R bits (inverse of) 

	return r;
	

}

// Convert acorn / MDFS perm to our format
uint8_t fsop_perm_from_acorn(struct __fs_station *s, uint8_t acorn_perm)
{
	uint8_t r;

	r = 0;

	// We don't try and do the Acorn WR/R mask for directories here because we don't know if it's a directory. It's done in the normalize routine instead
	// 20240520 Commented - this only applies to directories
	// if (acorn_perm == 0) r = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R; // Acorn clients seem to use &00 to mean WR/r

	if (s->config->fs_sjfunc) r |= (acorn_perm & 0x40) ? FS_PERM_H : 0; // Hidden / Private. This is MDFS only really
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
	}
	else // use top three bits of day as low three bits of year
	{
		*dday |= ((year_internal & 0x70) << 1);
		*monthyear |= ((year_internal & 0x0f) << 4);
	}

}

uint8_t fs_year_from_two_bytes(uint8_t day, uint8_t monthyear)
{

	uint8_t r;

	if (!fs_sevenbitbodge)
		r = ((((monthyear & 0xf0) >> 4) + 81) % 100);
	else
		r = ((( ((monthyear & 0xf0) >> 4) | ((day & 0xe0) >> 1) ) + 81) % 100);

	return r;

}

uint8_t fs_month_from_two_bytes(uint8_t day, uint8_t monthyear)
{
	return (monthyear & 0x0f);
}

uint8_t fs_day_from_two_bytes(uint8_t day, uint8_t monthyear)
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

/* 
 * fs_copy_terminate(unsigned char *dest, unsigned char *src, uint16_t maxlen)
 *
 * Copy a string from src to dst until we come across a space, at which
 * point we terminate it with the terminator character, up to
 * maxlen.
 *
 */

#define fsop_copy_terminate fs_copy_terminate

uint16_t fs_copy_terminate(unsigned char *dst, unsigned char *src, uint16_t maxlen, uint8_t term)
{

	uint16_t	count = 0;

	while (count < maxlen && *(src+count) != 0x20)
	{
		*(dst+count) = *(src+count);
		count++;
	}

	*(dst+(count++)) = term;

	return count;

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

	// This bit's broken
	//while (strrchr(dest, ' ')) *(strrchr(dest, ' ')) = '\0'; // Get rid of trailing spaces
	
	while ((strlen(dest) > 0) && (dest[strlen(dest)-1] == ' ')) dest[strlen(dest)-1] = '\0';

}

/* Raw sender routine for packets into the bridge */

int raw_fs_send (struct __fs_station *s, struct __econet_packet_aun *p, int len)
{

	struct __eb_device	*destdevice;

        if (p->p.dstnet == 0)    p->p.dstnet = p->p.srcnet;

	if ((destdevice = eb_find_station(2, p)))
	{
		if (destdevice->type == EB_DEF_AUN)
		{
			/* Put on AUN output queue */
			if (eb_aunpacket_to_aun_queue(s->fs_device, destdevice, p, len))
			{
        			eb_add_stats (&(s->fs_device->statsmutex), &(s->fs_device->b_out), len);
				return len;
			}
			else /* Went wrong */
			{
				eb_free(__FILE__, __LINE__, "FS", "PROBLEM: Freeing AUN packet after failed tx to AUN queue", p);
				return 0;
			}
		}
		else
		{
			/* Put it on the real destination device */
			eb_enqueue_input(destdevice, p, len);
			pthread_cond_signal(&(destdevice->qwake));
			return len;
		}
	}

        return 0;

}

/* fs_aun_send_noseq()
 *
 * Send AUN into the bridge, but don't set the sequence number
 * Used when a sender routine (typically the load queuer) wants to set its own
 * sequence number so it can track it.
 */

#if 0
/* About to be disused */
int fs_aun_send_noseq(struct __econet_packet_udp *p, int server, int len, unsigned short net, unsigned short stn)
{
	struct __econet_packet_aun a;

	memcpy(&(a.p.aun_ttype), p, len+8);
	a.p.padding = 0x00;
		
	a.p.srcnet = fs_stations[server].net;
	a.p.srcstn = fs_stations[server].stn;
	a.p.dstnet = net;
	a.p.dststn = stn;

	// Put the enqueue call here
	
	if (a.p.dstnet == 0)	a.p.dstnet = a.p.srcnet;
	eb_enqueue_output (fs_devices[server], &a, len, NULL);
	pthread_cond_signal(&(fs_devices[server]->qwake));
	eb_add_stats (&(fs_devices[server]->statsmutex), &(fs_devices[server]->b_out), len);

	return len;

}
#endif

/* Raw variant of fsop_aun_send_noseq */

int raw_fsop_aun_send_noseq(struct __econet_packet_udp *p, int len, struct __fs_station *s, uint8_t dstnet, uint8_t dststn)
{
        struct __econet_packet_aun *a;

	a = eb_malloc(__FILE__, __LINE__, "FS", "Create new AUN packet for transmission", 12+len);

        memcpy(&(a->p.aun_ttype), p, len+8);
        a->p.padding = 0x00;

        a->p.srcnet = s->net;
        a->p.srcstn = s->stn;
        a->p.dstnet = dstnet;
        a->p.dststn = dststn;


	/* Changed 20240720 to put the traffic straight on the right input queue,
	 * or onto an AUN output queue if that's where it's going */
#if 0
        eb_enqueue_output (s->fs_device, &a, len, NULL);
        pthread_cond_signal(&(s->fs_device->qwake));
#endif

	return raw_fs_send (s, a, len);

}

/* FSOP variant of fs_aun_send_noseq() */

int fsop_aun_send_noseq(struct __econet_packet_udp *p, int len, struct fsop_data *f)
{
        struct __econet_packet_aun *a;

	a = eb_malloc(__FILE__, __LINE__, "FS", "Create new AUN packet for transmission", 12+len);

        memcpy(&(a->p.aun_ttype), p, len+8);
        a->p.padding = 0x00;

        a->p.srcnet = f->server->net;
        a->p.srcstn = f->server->stn;
        a->p.dstnet = f->net;
        a->p.dststn = f->stn;

        // Put the enqueue call here

        //if (a.p.dstnet == 0)    a.p.dstnet = a.p.srcnet;
	
	/* Changed 20240720 - see comment in raw variant above */
#if 0
        eb_enqueue_output (f->server->fs_device, &a, len, NULL);
        pthread_cond_signal(&(f->server->fs_device->qwake));
        eb_add_stats (&(f->server->fs_device->statsmutex), &(f->server->fs_device->b_out), len);
#endif

        return raw_fs_send (f->server, a, len);

}

/* fs_aun_send()
 *
 * Send AUN into the bridge, but set the sequence number.
 *
 * This is the typical way of getting data out of the FS when
 * we don't care what seq number goes in the packet.
 *
 */

/* FSOP variant of fs_aun_send() */

int fsop_aun_send(struct __econet_packet_udp *p, int len, struct fsop_data *f)
{
	p->p.seq = eb_get_local_seq(f->server->fs_device);
	return fsop_aun_send_noseq(p, len, f);
}

int raw_fsop_aun_send(struct __econet_packet_udp *p, int len, struct __fs_station *s, uint8_t net, uint8_t stn)
{
	p->p.seq = eb_get_local_seq(s->fs_device);
	return raw_fsop_aun_send_noseq(p, len, s, net, stn);
}

/* Procedure to dump all FS currently open files & directories
 * to the file descriptor provided. 
 * *
 * MUST hold the FS global lock before calling
 */

void fsop_dump_handle_list(FILE *out, struct __fs_station *s)
{

	uint8_t 		found;
	struct __fs_disc	*disc;
	struct __fs_active	*active;
	struct __fs_file	*file;

	if (!s) // bad
		return;

	pthread_mutex_lock(&(s->fs_mutex));

	fprintf (out, "\n\nServer at %3d.%3d is %s\n\n", s->net, s->stn, s->enabled ? "RUNNING" : "SHUT DOWN");

	if (!s->enabled) // Nothing to do
	{
		pthread_mutex_unlock(&(s->fs_mutex));
		return;
	}

	fprintf (out, "  Root directory: %s\n\n  Total discs: %d\n\n", s->directory, s->total_discs);

	disc = s->discs;

	while (disc)
	{
		fprintf (out, "    %2d %s\n", disc->index, disc->name);
		disc = disc->next;
	}

	fprintf (out, "\n  Currently logged in users: ");

	active = s->actives;

	found = 0;

	while (active)
	{
		char	username[11];
		uint8_t	c;
		uint8_t f2;
		struct __fs_file	*d;

		memcpy (username, s->users[active->userid].username, 10);
		username[10] = 0;

		found++;
		fprintf (out, "\n\n    %04X %s %d.%d\n\n", active->userid, username, active->net, active->stn);

		d = active->fhandles[active->root].handle;
		fprintf (out, "       URD: %2d %s\n", active->root, d->name);

		d = active->fhandles[active->current].handle;
		fprintf (out, "       CWD: %2d %s\n", active->current, d->name);

		d = active->fhandles[active->lib].handle;
		fprintf (out, "       LIB: %2d %s\n", active->lib, d->name);
		
		fprintf (out, "\n       Open files & directories: ");

		f2 = 0;

		for (c = 0; c < FS_MAX_OPEN_FILES; c++)
		{
			if (active->fhandles[c].handle)
			{
				if (!f2) fprintf (out, "\n");

				fprintf (out, "\n        %2d %s", 
					c, 
					active->fhandles[c].acornfullpath
				);

				f2++;
			}

		}

		if (!f2) fprintf (out, "None");

		fprintf (out, "\n");

		active = active->next;
	}

	if (!found) fprintf (out, "None\n\n");
	else fprintf (out, "\n");

	fprintf (out, "  Server files open: ");

	file = s->files;
	found = 0;

	while (file)
	{
		if (!found) fprintf (out, "\n");

		fprintf (out, "\n    R: %3d W: %3d %s", file->readers, file->writers, file->name);

		found++;

		file = file->next;
	}

	if (!found) fprintf (out, "None");
	fprintf (out, "\n");

	pthread_mutex_unlock(&(s->fs_mutex));
	return;	

}

/* Allocate a server directory handle for a Unix filesystem path */
#if 0
struct __fs_dir * fsop_get_dir_handle(struct fsop_data *f, unsigned char *path)
{
	struct __fs_dir		*result;
	DIR 			*h;

	h = opendir((const char *) path);

	if (!h) /* Open failed */
		return NULL; 

	/* Open succeeded */

	FS_LIST_MAKENEW(struct __fs_dir, f->server->dirs, 1, result, "FS", "Allocate new FS Dir structure");

	/* Open the directory */

	strcpy(result->name, path);
	result->readers = 1; /* Initial set */
	result->handle = h;

	return result;

}

/* Close system level dir handle */

void fs_close_dir_handle(struct __fs_station *f, struct __fs_dir *d)
{
	if (!d) /* Bad handle */
		return;

	if (d->readers > 0)
		d->readers--;

	if (d->readers == 0) /* Nobody still using this */
	{
		closedir(d->handle);
		FS_LIST_SPLICEFREE(f->dirs, d, "FS", "Deallocate FS Dir structure");
	}

	return;

}
#endif

// Find a user file channel
// Gives 0 on failure
uint8_t fsop_allocate_user_file_channel(struct __fs_active *a)
{
	uint8_t count; // f is index into fs_files[server]

	count = 1; // Don't want to feed the user a directory handle 0

	while (!a->fhandles[count].handle && count < FS_MAX_OPEN_FILES)
		count++;

	if (count >= (a->server->config->fs_manyhandle ? FS_MAX_OPEN_FILES : 9)) return 0; // No handle available - if not in manyhandle mode, >= 9 is what we need because we can allocate up to and including 8

	a->fhandles[count].is_dir = 0;

	return count;

}

// Deallocate a file handle for a user
void fsop_deallocate_user_file_channel(struct __fs_active *a, uint8_t channel)
{
	// Do nothing if it's actually a directory handle

	if (a->fhandles[channel].is_dir) return;

	a->fhandles[channel].handle = NULL;
	
	return;
}

// Take a unix DIR* handle and find a slot for it in the user's data
uint8_t fsop_allocate_user_dir_channel(struct __fs_active *a, struct __fs_file *d)
{
	uint8_t count;

	count = 1; // Don't want to feed the user a directory handle 0

	while (a->fhandles[count].handle && count < FS_MAX_OPEN_FILES)
		count++;

	if (count >= (a->server->config->fs_manyhandle ? FS_MAX_OPEN_FILES : 9)) return 0; // No handle available - see comment in the user file allocator for why this is 9

	a->fhandles[count].handle = d;
	a->fhandles[count].cursor = 0;
	a->fhandles[count].cursor_old = 0;
	a->fhandles[count].mode = 1; /* Always 1 for dirs */
	a->fhandles[count].pasteof = 0; /* Irrelevant */
	a->fhandles[count].sequence = 0; /* Irrelevant */
	a->fhandles[count].is_dir = 1;

	return count;

}

// Deallocate a directory handle for a user
void fsop_deallocate_user_dir_channel(struct __fs_active *a, uint8_t channel)
{

	if (a->fhandles[channel].is_dir == 0) return; /* Not a directory! */

	if (!a->fhandles[channel].handle) return; /* Not an open handle */

	//fsop_close_dir_handle(a->server, (struct __fs_dir *) a->fhandles[channel].handle);
	fsop_close_interlock(a->server, a->fhandles[channel].handle, 1);

	a->fhandles[channel].handle = NULL; /* Signal unused */

	return;
}

// Find index into users[server] with net,stn number
struct __fs_active * fsop_find_active(struct __fs_station *s, uint8_t net, uint8_t stn)
{

	struct __fs_active *a;

	a = s->actives;

	while (a)
	{
		if (a->net == net && a->stn == stn)
			return a;
		else
			a = a->next;
	}

	return NULL;	 

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

void fsop_read_attr_from_file(unsigned char *path, struct objattr *r, struct fsop_data *f)
{
	char *dotfile=pathname_to_dotfile(path, f->server->config->fs_infcolon);
	FILE *df=fopen(dotfile,"r");
	if (df != NULL)
	{
		unsigned short owner, perm, homeof;
		unsigned long load, exec;

		homeof = 0;

		if (fscanf(df, "%hx %lx %lx %hx %hx", &owner, &load, &exec, &perm, &homeof) != 5)
			fscanf(df, "%hx %lx %lx %hx", &owner, &load, &exec, &perm);

		r->owner = owner;
		r->load = load;
		r->exec = exec;
		r->perm = perm;
		r->homeof = homeof;

		fclose(df);

	}

	free(dotfile);
	return;
}

void fs_write_attr_to_file(unsigned char *path, int owner, short perm, unsigned long load, unsigned long exec, int homeof, struct fsop_data *f)
{
	char *dotfile=pathname_to_dotfile(path, f->server->config->fs_infcolon);
	FILE *df=fopen(dotfile,"w");
	if (df != NULL)
	{
		fprintf(df, "%hx %lx %lx %hx %hx", owner, load, exec, perm, homeof);
		fclose(df);
	}
	else
		fs_debug (0, 1, "Could not open %s for writing: %s\n", path, strerror(errno));

	free(dotfile);
	return;
}

/* fs_isdir(path)
 * Return true if file in filesystem is a dir
 */

uint8_t fs_isdir(char *path)
{
	struct stat	s;
	int		r;

	r = stat(path, &s);

	if (r == -1)
		fs_debug (0, 1, "PERMS", "%12s Permissions system cannot stat %s to see if it's a directory", "", path);
	else if ((s.st_mode & S_IFMT) == S_IFDIR)
		return 1;

	return 0; // Returns 0 if stat failed or is a file.

}

void fsop_read_xattr(unsigned char *path, struct objattr *r, struct fsop_data *f)
{
	unsigned char 	attrbuf[20];
	char 		*dotfile = pathname_to_dotfile(path, f->server->config->fs_infcolon);
	int 		dotexists = access(dotfile, F_OK);

	// Default values
	r->owner=0; // syst
	r->load=0;
	r->exec=0;

	if (fs_isdir(path))
		r->perm = FS_CONF_DEFAULT_DIR_PERM(f->server);
	else	r->perm = FS_CONF_DEFAULT_FILE_PERM(f->server);

	r->homeof=0;

	free(dotfile);

	if (!use_xattr || dotexists==0)
	{
		fsop_read_attr_from_file(path, r, f);
		return;
	}

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

/*
 * Set xattr on a file/dir.
 *
 * Note that perm is uint16_t even though it is really 8 bit.
 * This is to allow the upper 8 bits (if any are set) to mean
 * "leave existing perm in place" so that we do not change
 * permissions when overwriting a file.
 */

void fsop_write_xattr(unsigned char *path, uint16_t owner, uint16_t perm, uint32_t load, uint32_t exec, uint16_t homeof, struct fsop_data *f)
{
	struct objattr 		existing;
	unsigned char 		attrbuf[20];
	unsigned char 		old_owner[10];
	char 			*dotfile = pathname_to_dotfile(path, f->server->config->fs_infcolon);
	int 			dotexists = access(dotfile, F_OK);

	free(dotfile);

	fsop_read_xattr(path, &existing, f);

	if (perm & 0xff00)
		perm = existing.perm;

	if (((perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == 0) && fs_isdir(path))
		perm |= FS_CONF_DEFAULT_DIR_PERM(f->server); // imply default if dir perm given as 'no perms'
		// No equivalent for files, because can justifiably set to, e.g. "/"

	if (!use_xattr || dotexists==0)
	{
		fs_write_attr_to_file(path, owner, perm & 0xFF, load, exec, homeof, f);
		return;
	}

	sprintf((char * ) attrbuf, "%04X", owner);

	// See if owner is being changed
	//
	if (getxattr((const char *) path, "user.econet_owner", old_owner, 4) >= 0) // Attribute found
	{
		old_owner[4] = 0;
		if (strcasecmp(old_owner, attrbuf))
			fs_debug (0, 1, "Owner being changed from %s to %s on file %s", old_owner, attrbuf, path);	
	}

	if (setxattr((const char *) path, "user.econet_owner", (const void *) attrbuf, 4, 0))
		fs_debug (0, 1, "Failed to set owner on %s", path);

	sprintf((char * ) attrbuf, "%08X", load);
	if (setxattr((const char *) path, "user.econet_load", (const void *) attrbuf, 8, 0))
		fs_debug (0, 1, "Failed to set load address on %s", path);

	sprintf((char * ) attrbuf, "%08X", exec);
	if (setxattr((const char *) path, "user.econet_exec", (const void *) attrbuf, 8, 0))
		fs_debug (0, 1, "Failed to set exec address on %s: %s", path, strerror(errno));

	sprintf((char *) attrbuf, "%04X", homeof);
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
			case '(': // Fall through
			case ')': // Fall through
			case '?': // Fall through
			case '[': // Fall through
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
	return regcomp(&(r_wildcard), string, REG_EXTENDED | REG_ICASE | REG_NOSUB);
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

#define fsop_free_wildcard_list	fs_free_wildcard_list

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
 
#define fsop_get_wildcard_entries fs_get_wildcard_entries

int fs_get_wildcard_entries (struct fsop_data *f, int userid, char *haystack, char *needle, struct path_entry **head, struct path_entry **tail)
{

	unsigned short 		counter, found;
	short 			results;
	struct path_entry 	*p, *new_p;
	char 			needle_wildcard[2048];
	struct dirent 		**namelist;
	struct stat 		statbuf;
	struct objattr 		oa, oa_parent;
	struct tm 		ct;

	found = counter = 0;
	*head = *tail = p = NULL;

	fs_acorn_to_unix(needle, f->server->config->fs_infcolon);

	fs_wildcard_to_regex(needle, needle_wildcard, f->server->config->fs_infcolon);

	if (normalize_debug) fs_debug (0, 2, "fs_get_wildcard_entries() - needle = '%s', needle_wildcard = '%s'", needle, needle_wildcard);

	if (fs_compile_wildcard_regex(needle_wildcard) != 0) // Error
		return -1;

	results = scandir(haystack, &namelist, fs_scandir_filter, fs_alphacasesort);

	if (results == -1) // Error - e.g. not found, or not a directory
		return -1;

	// Convert to a path_entry chain here and assign head & tail.

	fsop_read_xattr(haystack, &oa_parent, f);
	
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
	
			/* Commented out - no glibc wrapper yet
			// And statx for birthday. Soon we'll just use statx() and not stat() as well
			
			if (statx(0, new_p->unixpath, 0, STATX_BTIME, &statxbuf) != 0) // Error
			{
				fs_debug (0, 2, "Unable to statx %s", new_p->unixpath);
				free (new_p);
				counter++;
				continue;
			}
			*/
	

			//fs_debug (0, 3, "fs_get_wildcard_entries() loop counter %d of %d - ACORN:'%s', UNIX '%s'", counter+1, results, new_p->acornname, new_p->unixfname);
	
			p = new_p; // update p
	
			fsop_read_xattr(p->unixpath, &oa, f);
	
			p->load = oa.load;
			p->exec = oa.exec;
			p->owner = oa.owner;
			p->perm = oa.perm;
			p->homeof = oa.homeof;
			p->length = statbuf.st_size;
			p->parent_owner = oa_parent.owner;
			p->parent_perm = oa_parent.perm;
	
			// Parent must be a directory, so we frig the permissions to be WR/ if we own the parent and permissions are &00 (which L3FS would let us read/write to because we own it)
			
			if ((p->parent_owner == userid) && (p->parent_perm == 0))
				p->parent_perm = FS_PERM_OWN_R | FS_PERM_OWN_W;
	
			if (f->server->users[userid].priv & FS_PRIV_SYSTEM)
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
	
			// Create time - This is bogus. ctime is not create time.
			localtime_r(&(statbuf.st_ctime), &ct);
			fs_date_to_two_bytes(ct.tm_mday, ct.tm_mon+1, ct.tm_year, &(p->c_monthyear), &(p->c_day));
			p->c_hour = ct.tm_hour;
			p->c_min = ct.tm_min;
			p->c_sec = ct.tm_sec;
	
			p->internal = statbuf.st_ino;
			strncpy(p->ownername, f->server->users[p->owner].username, 10);
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

/* First, the fsop wrapper */

int fsop_normalize_path_wildcard (struct fsop_data *f, unsigned char *received_path, short relative_to, struct path *result, unsigned short wildcard)
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
	uint8_t	special_path; // Set to 1 below if user is selecting a filename beginning %, @, &
	struct __fs_active *a;

	unsigned short homeof_found = 0; // Non-zero if we traverse a known home directory

	DIR *dir;
	short count;

	a = f->active;

	special_path = 0;

	result->npath = 0;
	result->paths = result->paths_tail = NULL;

	result->disc = -1; // Rogue so that we can tell if there was a discspec in the path

	/* Implement MDFS $DISCNAME notation */

	if (strlen(received_path) >= 2 && (*received_path == '$') && (*(received_path+1) != '.')) // Must be the MDFS notation
		*(received_path) = ':'; // Convert to Acorn

	/* Fudge the special files here if we have SYST privs */

	if (a && a->server->users[a->userid].priv & FS_PRIV_SYSTEM)
	{
		unsigned char	final_path[30];
		unsigned char 	*acorn_start_ptr;

		final_path[0] = '\0';

		if (FS_CONFIG(f->server,fs_sjfunc) && (strlen(received_path) >= 10) && !strcasecmp(received_path + strlen(received_path)-10, "%PASSWORDS"))
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
			fsop_get_disc_name(f->server, a->server->users[a->userid].home_disc, result->discname);
			result->disc = a->server->users[a->userid].home_disc;

			strcpy(result->path[0], acorn_start_ptr);
			strcpy(result->acornname, acorn_start_ptr);
			strcpy(result->path_from_root, acorn_start_ptr);
			sprintf(result->unixpath, "%s/%s", f->server->directory, final_path);
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

	
	// Implement ANFS name bodge
	
	if ( 		a
		&&	(a->server->users[a->userid].priv2 & FS_PRIV2_ANFSNAMEBODGE)
		&&	(strlen(received_path) >= 4 && *received_path >= '0' && *received_path <= '9' && *(received_path+1) == '.')
	   )
	{
		path[0] = ':';
		strcpy(&(path[1]), received_path);
	}
	else
		strcpy(path, received_path);

	/* First, fudge 'relative_to' if filename is any of &, @, %
	 */

	/* Check for the three specials, and make sure they are either followed by '.' or end of line */

	if (a && (path[0] == '&' || path[0] == '@' || path[0] == '%') && (path[1] == '\0' || path[1] == '.'))
	{

		unsigned char	temp_path[1048];

		special_path++; // Will already be 1 if this was a path below [%&@] - e.g. %.LIBRARY, this adds another one so that we skip the '.'. Otherwise we're just skipping the [%&@] because there will be a null at the end of it, which we then detect as a 0 length string in the ajuster else {} block below.

		if (path[1] == '.')
			special_path++; // Skip the .

		switch (path[0])
		{
			case '&':	relative_to = a->root; break;
			case '@':	relative_to = a->current; break;
			case '%':	relative_to = a->lib; break;
		}

		if (normalize_debug)
		{
			fs_debug (0, 1, "Special character detected '%c': User id = %d, special_path = %d, new relative_to = %d", path[0], a->userid, special_path, relative_to);
		}

		// Pretend we were given the bit after the special character

		strcpy (temp_path, (path + special_path));
		strcpy (path, temp_path);

		if (normalize_debug)
		{
			fs_debug (0, 1, "User id = %d, new relative path = '%s'", a->userid, path);
		}

	}

	if (normalize_debug) 
	{
		if (a)
			fs_debug(0,1, "path=%s, received_path=%s, relative to %d, wildcard = %d, user %d, acornfullpath = %s", path, received_path, relative_to, wildcard, a->userid, a->fhandles[relative_to].acornfullpath);
		else
			fs_debug(0,1, "path=%s, received_path=%s, relative to %d, wildcard = %d", path, received_path, relative_to, wildcard);
	}

	// If the handle we have for 'relative to' is invalid, then return directory error
	if ((relative_to > FS_MAX_OPEN_FILES) || (a && relative_to != -1 && !a->fhandles[relative_to].handle))
	{
		result->error = FS_PATH_ERR_NODIR; return 0;
	}

	// Cope with null path relative to dir on another disc
	if (strlen(path) == 0 && relative_to != -1)
		strcpy(path, a->fhandles[relative_to].acornfullpath);
	else if (relative_to != -1 && (path[0] != ':' && path[0] != '$') /* && path[0] != '&' */)
	{
		unsigned char	temp_path[2096];

		// 20240506 sprintf(path, "%s.%s", active[server][user].fhandles[relative_to].acornfullpath, received_path);
		snprintf(temp_path, 2095, "%s.%s", a->fhandles[relative_to].acornfullpath, path);
		// Copy & truncate if need be
		memcpy (path, temp_path, 1024);
		path[1025] = '\0';
	}

	if (normalize_debug && relative_to != -1) fs_debug (0, 1, "Path provided: '%s', relative to '%s'", received_path, a->fhandles[relative_to].acornfullpath);
	else if (normalize_debug) fs_debug (0, 1, "Path provided: '%s', relative to nowhere", received_path);

	// Truncate any path provided that has spaces in it
	count = 0; 
	while (count < strlen(path))
	{
		if (path[count] == 0x20) path[count] = '\0';
		count++;
	}

	memset(path_internal, 0, 1024);

	if (normalize_debug) fs_debug (0, 1, "Path after adjustment is '%s'", path);

	if (*path == ':') // Disc selection
	{

		int 	found = 0;

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

		{
			struct __fs_disc	*disc;

			disc = f->server->discs;

			while (disc && !found)
			{
				if ((!strcasecmp((const char *) disc->name, (const char *) result->discname) || ((a->server->users[a->userid].priv2 & FS_PRIV2_ANFSNAMEBODGE) && (disc->index == atoi(result->discname)))) && FS_DISC_VIS(f->server,a->userid,disc->index))
					found = 1;
				else
					disc = disc->next;
			}

			if (!found)
			{
				result->error = FS_PATH_ERR_NODISC;
				return 0; // Bad path - no such disc
			}

			result->disc = disc->index;
		}
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
			fs_debug (0, 1, "Normalize relative to handle %d, which has full acorn path %s", relative_to, a->fhandles[relative_to].acornfullpath);
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
	else // relative path given - so give it relative to the relevant handle
	{
		unsigned short fp_ptr = 0;

		if (relative_to < 1) // Relative to nowhere
			strcpy(adjusted, "");
		else
		{
			while (a->fhandles[relative_to].acornfullpath[fp_ptr] != '.') fp_ptr++;
			// Now at end of disc name
			// Skip the '.$'
			fp_ptr += 2;
			if (a->fhandles[relative_to].acornfullpath[fp_ptr] == '.') // Path longer than just :DISC.$
				fp_ptr++;
	
			if (fp_ptr < strlen(a->fhandles[relative_to].acornfullpath))
			{
				sprintf(adjusted, "%s", a->fhandles[relative_to].acornfullpath + fp_ptr);
				if (strlen(path_internal) > 0) strcat(adjusted, ".");
			}
			else	strcpy(adjusted, "");
		}

		strcat(adjusted, path_internal); 

		if (normalize_debug)
		{
			fs_debug (0, 1, "User id = %d, adjusted acorn path = %s", a->userid, adjusted);
		}
	}

	if (result->disc == -1)
	{
		result->disc = a->current_disc; // Replace the rogue if we are not selecting a specific disc
		if (normalize_debug) fs_debug (0, 1, "No disc specified, choosing current disc: %d", a->current_disc);
	}

	fsop_get_disc_name(f->server, result->disc, result->discname);

	if (normalize_debug) fs_debug (0, 1, "Disc selected = %d, %s", result->disc, result->discname);
	if (normalize_debug) fs_debug (0, 1, "path_internal = %s (len %d)", path_internal, (int) strlen(path_internal));

	sprintf (result->acornfullpath, ":%s.$", result->discname);

	if (normalize_debug) fs_debug (0, 1, "Adjusted = %s / ptr = %d / path_internal = %s", adjusted, ptr, path_internal);

	strcpy ((char * ) result->path_from_root, (const char * ) adjusted);

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
			if (regexec(&(f->server->r_pathname), adjusted + ptr, 1, matches, 0) == 0)
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

	sprintf (result->unixpath, "%s/%1d%s", f->server->directory, result->disc, result->discname);

	if ((a->server->users[a->userid].priv2 & FS_PRIV2_CHROOT) && (relative_to != -1) && (result->disc == a->server->users[a->userid].home_disc)) // CHROOT set for this user and we are not logging in / changing disc and we are on the home disc
	{
		// Add home directory unix path to result->unixpath here - NB consider making the LIB normalize on login / sdisc relative to the chrooted root - might break things otherwise.
		strcpy (result->unixpath, a->urd_unix_path); // Force $ to be home dir
	}

	if (normalize_debug) fs_debug (0, 1, "Unix dir: %s, npath = %d", result->unixpath, result->npath);

	// Iterate through each directory looking for the next part of the path in a case insensitive matter, and if any of them lack extended attributes then add them in as we go (if the thing exists!)
	// Also do the conversion from '/' in an Acorn path to ':' in a unix filename ...

	count = 0;

	// Collect root directory info
	{
		struct stat s;
		struct tm t;

		result->ftype = FS_FTYPE_DIR;
		
		sprintf(result->acornname, "%-10s", "$"); // Probably don't need to update this for >10 char filenames, all it does is put $ in the front of the path

		strcpy((char * ) result->unixfname, (const char * ) "");	 // Root dir - no name
		result->internal = s.st_ino; // Internal name = Inode number
		result->length = 0; // Probably wrong

		// Next, see if we have xattr and, if not, populate them. We do this for all paths along the way

		fsop_read_xattr(result->unixpath,&attr,f);

		if (relative_to != -1 && (a->server->users[a->userid].priv2 & FS_PRIV2_CHROOT) && (result->disc == a->server->users[a->userid].home_disc))
		{
			if (normalize_debug) fs_debug (0, 1, "chroot home directory %s for user %d and on home disc", result->unixpath, a->userid);
			result->homeof = attr.homeof;
			result->owner = result->parent_owner = attr.owner;
			result->parent_perm = result->perm = attr.perm;
			result->my_perm = (attr.owner == a->userid) ? (attr.perm & 0x0f) : ((attr.perm & 0xf0) >> 4);

			if (normalize_debug) fs_debug (0, 1, "chroot results for root dir %s for user %d are homeof=%04X, owner=%04X, parent_owner=%04X, parent_perm = %02X, perm = %02X, my_perm = %02X", result->unixpath, a->userid, result->homeof, result->owner, result->parent_owner, result->parent_perm, result->perm, result->my_perm);
		}
		else
		{
			result->owner = 0; // Always SYST if root directory not owned
			result->homeof = 0;
			result->perm = FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
			result->my_perm = FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
			// Added 20231227
			result->parent_perm = result->perm;
			result->parent_owner = result->owner;
	
			if (!(a->server->users[a->userid].priv & FS_PRIV_SYSTEM))
				result->my_perm = FS_PERM_OWN_R; // Read only my_perm for non-System users on a root directory
 
		}

		result->load = 0;
		result->exec = 0;

		fsop_write_xattr(result->unixpath, result->owner, result->perm, result->load, result->exec, result->homeof, f);

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

		if (normalize_debug) fs_debug (0, 1, "Processing wildcard path with %d elements", result->npath);

		// Re-set path_from_root bceause we'll need to update it with the real acorn names
		strcpy(result->path_from_root, "");

		while (result->npath > 0 && (count < result->npath))
		{

			strcpy(acorn_path, result->path[count]); // Preserve result->path[count] as is, otherwise fs_get_wildcard_entries will convert it to unix, which we don't want
			if (normalize_debug) fs_debug (0, 1, "Processing path element %d - %s (Acorn: %s) in directory %s", count, result->path[count], acorn_path, result->unixpath);

			num_entries = fs_get_wildcard_entries(f, a->userid, result->unixpath, // Current search dir
					acorn_path, // Current segment in Acorn format (which the function will convert)
					&(result->paths), &(result->paths_tail));

			if (normalize_debug)
			{
				fs_debug (0, 1, "Wildcard search returned %d entries (result->paths = %8p):", num_entries, result->paths);
				p = result->paths;
				while (p != NULL)
				{
					fs_debug (0, 1, "Type %02x Owner %04x Parent owner %04x Owner %10s Perm %02x Parent Perm %02x My Perm %02x Load %08lX Exec %08lX Homeof %04x Length %08lX Int name %06lX Unixpath %s Unix fname %s Acorn Name %s Date %02d/%02d/%02d",
						p->ftype, p->owner, p->parent_owner, p->ownername,
						p->perm, p->parent_perm, p->my_perm,
						p->load, p->exec, p->homeof, p->length, p->internal,
						p->unixpath, p->unixfname, p->acornname,
						fs_day_from_two_bytes(p->day, p->monthyear),
						fs_month_from_two_bytes(p->day, p->monthyear),
						fs_year_from_two_bytes(p->day, p->monthyear));
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

				fsop_read_xattr(result->unixpath, &attr, f);

				result->ftype = FS_FTYPE_NOTFOUND;
				result->perm = 0;
				result->parent_owner = attr.owner;
				result->parent_perm = attr.perm;
				
				// Copy to thing we didn't find to result->acornname so it can be reused in the caller
				strcpy (result->unixfname, acorn_path);
				strcpy (result->acornname, acorn_path);
				fs_acorn_to_unix(result->unixfname, f->server->config->fs_infcolon);

				// If we are on the last segment and the filename does not contain wildcards, we return 1 to indicate that what was 
				// searched for wasn't there so that it can be written to. Obviously if it did contain wildcards then it can't be so we
				// return 0

				if (normalize_debug) fs_debug (0, 1, "Work out whether to return 1 or 0 when nothing found: num_entries returned %d, count = %d, result->npath-1=%d, search for wildcards is %s", num_entries, count, result->npath-1, (strchr(result->path[count], '*') == NULL && strchr(result->path[count], '#') == NULL) ? "in vain" : "successful");
				if ((count == result->npath-1) && (num_entries != -1) // Soft error if on last path entry unless we got an error from the wildcard search
					// && ((strchr(result->path[count], '*') == NULL) && (strchr(result->path[count], '#') == NULL))
				) // Only give a hard fail if we are not in last path segment
					return 1;

				if (normalize_debug) fs_debug (0, 1, "Signal a hard fail");
				result->error = FS_PATH_ERR_NODIR;
				return 0; // If not on last segment, this is a hard fail.
			}
				
			// Always copy the first entry into the main struction because we always want it.
			// Unless on last segment (when we want to leave all the path entries available to be freed by the caller)
			// we free them up here.

			// So there's at least one entry, and it should be at *paths

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

			if (f->server->config->fs_acorn_home && homeof_found)
			{
				struct path_entry *h;

				result->owner = homeof_found;
				result->my_perm = result->perm;
				h = result->paths;

				while (h)
				{
					h->owner = homeof_found;
					h->my_perm = h->perm;
					strncpy(h->ownername, f->server->users[h->owner].username, 10);
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
			{
				if ((result->ftype == FS_FTYPE_DIR) && (!(FS_PERM_EFFOWNER(a,result->owner)) && !(result->perm & FS_PERM_OTH_R)))
				{
					// Hard fail
					result->error = FS_PATH_ERR_NODIR;
					result->ftype = FS_FTYPE_NOTFOUND;
					return 0;
				}

				fs_free_wildcard_list(result);
			}

			count++;
		}

		if (normalize_debug) fs_debug (0, 1, "Returning full acorn path (wildcard - last path element to be added by caller) %s with my_perm = %02X, unix_path = %s", result->acornfullpath, result->my_perm, result->unixpath);

		return 1;
	}

	// This is the non-wildcard code

	/* If in chroot mode, set initial value of local variable parent_owner to owner of current dir because otherwise it is initialized to 0 (for root dir) */

	if (FS_UINFO(a).priv2 & FS_PRIV2_CHROOT)
		parent_owner = result->parent_owner; // Set above correctly in chroot mode.

	if (normalize_debug) fs_debug (0, 1, "non-wildcard initial results for root dir %s for user %d are homeof=%04X, owner=%04X, parent_owner=%04X, parent_perm = %02X, perm = %02X, my_perm = %02X", result->unixpath, FS_ACTIVE_UID(a), result->homeof, result->owner, result->parent_owner, result->parent_perm, result->perm, result->my_perm);

	while ((result->npath > 0) && count < result->npath)
	{
		char path_segment[ECONET_ABS_MAX_FILENAME_LENGTH+10]; // used to store the converted name (/ -> :)
		struct stat s;
		// OLD char attrbuf[20];
		unsigned short r_counter;
		unsigned short owner, perm;

		found = 0;

		if (normalize_debug) fs_debug (0, 1, "Loop %d - Examining %s", count, result->unixpath);

		// Convert pathname so that / -> :

		r_counter = 0; 

		while (result->path[count][r_counter] != '\0' && r_counter < ECONET_MAX_FILENAME_LENGTH)
		{
			if (result->path[count][r_counter] == '/')
				path_segment[r_counter] = (FS_CONFIG(f->server,fs_infcolon) ? '.' : ':');
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

		if (normalize_debug) fs_debug (0, 1, "Loop %d - Calling fs_check_dir(..., %s, ...)", count, path_segment);

		// If path_segment is found in dir, then it puts the unix name for that file in unix_segment
		found = fs_check_dir (dir, path_segment, unix_segment);

		closedir(dir);

		// Obtain permissions on dir - see if we can read it

		fsop_read_xattr(result->unixpath, &attr, f);
		owner = attr.owner;
		perm = attr.perm;

		if (homeof_found == 0 && FS_CONFIG(f->server,fs_acorn_home) && attr.homeof != 0)
			homeof_found = attr.homeof;

		if (homeof_found)
			owner = homeof_found;
		
		// Fudge parent perm if we own the object and permissions = &00
		if ((FS_ACTIVE_UID(a) == attr.owner) && ((attr.perm & ~FS_PERM_L) == 0))
			perm = attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R;
		
		if (count == result->npath - 1) // Last segment
			result->parent_perm = perm;

		if (!	( 
				(FS_UINFO(a).priv & FS_PRIV_SYSTEM)
			||	(FS_ACTIVE_UID(a) == owner) // Owner can always read own directory irrespective of permissions(!)
			||	(perm & FS_PERM_OTH_R) // Others can read the directory
			)
			&& !found) 
		{
			if (normalize_debug) fs_debug (0, 1, "This user cannot read dir %s", result->unixpath);
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
							unix_segment[r_counter] = (FS_CONFIG(f->server,fs_infcolon) ? '.' : ':');
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
					if (normalize_debug) fs_debug (0, 1, "Non-Wildcard file (%s, unix %s) not found in dir %s - returning unixpath %s, acornname %s, parent_owner %04X", path_segment, unix_segment, result->unixpath, result->unixpath, result->acornname, result->parent_owner);
					return 1;
				}
				else	
				{
					result->error = FS_PATH_ERR_NODIR;
					return 0; // Fatal not found
				}
			}
		}

		if (normalize_debug) fs_debug (0, 1, "Found path segment %s in unix world = %s", path_segment, unix_segment);
		strcat(result->unixpath, "/");
		strcat(result->unixpath, unix_segment);

		// Add it to full acorn path
		strcat(result->acornfullpath, ".");
		strcat(result->acornfullpath, path_segment);

		if (normalize_debug) fs_debug (0, 1, "Attempting to stat %s", result->unixpath);

		if (!stat(result->unixpath, &s)) // Successful stat
		{

			//int owner;
			char dirname[1024];

			if (normalize_debug) fs_debug (0, 1, "stat(%s) succeeded", result->unixpath);
			if (!S_ISDIR(s.st_mode) && (count < (result->npath - 1))) // stat() follows symlinks so the first bit works across links; the second condition is because we only insist on directories for that part of the path except the last element, which might legitimately be FILE or DIR
			{
				result->ftype = FS_FTYPE_NOTFOUND; // Because something we encountered before end of path could not be a directory
				return 1;
			}

			if (normalize_debug) fs_debug (0, 1, "Non-leaf node %s is%s a directory", result->unixpath, (S_ISDIR(s.st_mode) ? "" : " NOT"));
			if ((S_ISDIR(s.st_mode) == 0) && (S_ISREG(s.st_mode) == 0)) // Soemthing is wrong
			{
				result->error = FS_PATH_ERR_TYPE;
				return 0; // Should either be file or directory - not block device etc.
			}

			if (normalize_debug) fs_debug (0, 1, "Proceeding to look at attributes on %s", result->unixpath);
			// Next, set internal name from inode number

			result->internal = s.st_ino; // Internal name = Inode number

			// Next, see if we have xattr and, if not, populate them. We do this for all paths along the way

			strcpy ((char * ) dirname, (const char * ) result->unixpath);
			// Need to add / for setxattr
			if (S_ISDIR(s.st_mode))	strcat(dirname, "/");

			fsop_read_xattr(dirname, &attr, f);

			if (normalize_debug) fs_debug (0, 1, "fsop_read_xattr yielded: Owner %04X, Load %08lX, Exec %08lX, Home Of %04X, Perm %02X", attr.owner, attr.load, attr.exec, attr.homeof, attr.perm);

			// If it's a directory with 0 permissions and we own it, set permissions to RW/

			if (normalize_debug) fs_debug (0, 1, "Looking to see if this user (id %04X) is the owner (%04X), if this is a dir and if perms (%02X) are &00", a->userid, attr.owner, attr.perm);

			if ((FS_ACTIVE_UID(a) == attr.owner) && S_ISDIR(s.st_mode) && ((attr.perm & ~FS_PERM_L) == 0))
			{
				if (normalize_debug) fs_debug (0, 1, "Is a directory owned by the user with perm = 0 - setting permissions to WR/");
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


			if (homeof_found == 0 && FS_CONFIG(f->server,fs_acorn_home) && attr.homeof != 0)
				homeof_found = attr.homeof;

			if (homeof_found)
				result->owner = result->attr.owner = homeof_found;
		
			result->parent_owner = parent_owner;

			parent_owner = result->owner; // Ready for next loop

			if (normalize_debug) fs_debug (0, 1, "Setting parent_owner = %04x, this object owned by %04x", result->parent_owner, result->owner);

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

				if (FS_ACTIVE_SYST(a))
					result->my_perm = 0xff;
				else if (FS_ACTIVE_UID(a) != result->owner)
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

	strncpy((char * ) result->ownername, (const char *) f->server->users[result->owner].username, 10); // Populate readable owner name
	result->ownername[10] = '\0';

	return 1; // Success

}

// The old format, non-wildcard function, for backward compat
// Will ultimately need modifying to copy the first entry in the found list into the 
// path structure and then free all the path entries that have been found.

/* First an fsop wrapper */

int fsop_normalize_path(struct fsop_data *f, unsigned char *path, short relative_to, struct path *result)
{
	return fsop_normalize_path_wildcard(f, path, relative_to, result, 0);
}


/*
 * fs_exists()
 *
 * Check whether a given acorn path on a given server for a given active_id
 * exists. Return one of the FS_FTYPE_* constants, or 0 for not exist
 *
 */

uint8_t fsop_exists(struct fsop_data *f, unsigned char *path)
{

	struct path 	p;
	uint8_t		fsnp;

	fsnp = fsop_normalize_path(f, path, -1, &p);

	//fprintf (stderr, "fs_normalize_path for %s returned %d, result->ftype = %d\n", path, fsnp, p.ftype);
	if (fsnp == 0 || p.ftype == FS_FTYPE_NOTFOUND)
		return FS_FTYPE_NOTFOUND;
	else
		return p.ftype;

}

void fsop_write_user(struct __fs_station *s, int user, unsigned char *d) // Writes the 256 bytes at d to the user's record in the relevant password file
{

	/* MMAPed now
	char pwfile[1024];
	FILE *h;


	sprintf (pwfile, "%s/Passwords", f->server->directory);

	if ((h = fopen(pwfile, "r+")))
	{
		if (fseek(h, (256 * user), SEEK_SET))
			fs_debug (0, 1, "Attempt to write beyond end of user file\n");
		else if (fwrite(d, 256, 1, h) != 1)
				fs_debug (0, 1, "Error writing to password file\n");

		fclose(h);
	}
	else fs_debug (0, 0, "Error opening password file - %s\n", strerror(errno));
	*/

	memcpy(&(s->users[user]), d, 256);
}

// Clear the SYST password on a given FS (used from the *FAST handler in the bridge)
uint8_t fsop_clear_syst_pw(struct __fs_station *server)
{

	int	count;
	uint8_t	ret = 0;

	pthread_mutex_lock(&(server->fs_mutex));

	for (count = 0; count < ECONET_MAX_FS_USERS; count++)
	{
		if (!strncmp(server->users[count].username, "SYST      ", 10))
		{
			memset(server->users[count].password, 32, 10);
			ret = 1;
		}
	}

	pthread_mutex_unlock(&(server->fs_mutex));

	return ret;
}

// Tell the bridge if a particular FS is active

uint8_t fsop_is_enabled(struct __fs_station *s)
{
	uint8_t	ret;

	pthread_mutex_lock(&(s->fs_mutex));
	ret = s->enabled;
	pthread_mutex_unlock(&(s->fs_mutex));

	return ret;
}

/*
 * fsop_initialize()
 *
 * Creates a new server struct and initializes it, but
 * leaves the server disabled.
 *
 * Returns the __fs_station struct pointer back to the
 * HPB.
 *
 * Sets up the thread locks etc.
 *
 * This function is called by the config reader in the HPB
 * when it wants to get a server instantiated.
 *
 */

struct __fs_station * fsop_initialize(struct __eb_device *device, char *directory)
{
	
	DIR *d;
	struct dirent *entry;

	FILE *passwd;
	char passwordfile[280], passwordfilecopy[300];
	int length;
	char regex[256];
	
	struct __fs_station *server;

	FS_LIST_MAKENEW(struct __fs_station, fileservers, 1, server, "FS", "Initialize new server struct");
        server->net = device->net;
        server->stn = device->local.stn;
        strcpy (server->directory, directory);
        server->config = NULL;
        server->discs = NULL;
        server->files = NULL;
        server->actives = NULL;
        server->users = NULL;
        server->enabled = 0;
        server->fs_load_queue = NULL;
        server->fs_device = device;
        server->fs_workqueue = NULL;
	server->peeks = NULL;
        /* Don't touch next, prev - they'll be initialized by the list management macros */

        /* Don't do anything with fs_thread - fsop_run() sets that up */

	fs_debug (0, 2, "Attempting to initialize server on %d.%d at directory %s", server->net, server->stn, server->directory);

	// Ensure serverparam begins with /
	if (*directory != '/')
	{
		FS_LIST_SPLICEFREE(fileservers,server,"FS","Destroy FS struct on failed init");

		fs_debug (0, 1, "Bad directory name %s", directory);
		return NULL;
	}

	// If there is a file in this directory called "auto_inf" then we
	// automatically turn on "-x" mode.  This should work transparently
	// for any filesystem that isn't currently inf'd 'cos reads will
	// get the xattr and writes will create a new inf file
	
	char *autoinf=malloc(strlen(server->directory)+15);
	strcpy(autoinf,server->directory);
	strcat(autoinf,"/auto_inf");

	if (access(autoinf, F_OK) == 0)
	{
		fs_debug (0, 1, "Automatically turned on -x mode because of %s", autoinf);
		use_xattr = 0;
	}

	free(autoinf);

	if (!fs_netconf_regex_initialized)
	{
		if (regcomp(&fs_netconf_regex_one, FS_NETCONF_REGEX_ONE, REG_EXTENDED | REG_ICASE) != 0)
			fs_debug (1, 0, "Unable to compile netconf regex.");
		fs_netconf_regex_initialized = 1;
	}

	d = opendir(server->directory);

	if (!d)
		fs_debug(1, 1, "Unable to open root directory %s", server->directory);
	else
	{

		FILE * cfgfile;

		server->config = eb_malloc(__FILE__, __LINE__, "FS", "Allocate FS config struct", sizeof(struct __fs_config));
		memset(server->config, 0, sizeof(struct __fs_config));

		// Set up some defaults in case we are writing a new file
		server->config->fs_acorn_home = 0;
		server->config->fs_sjfunc = 1;
		server->config->fs_pwtenchar = 1;
		server->config->fs_fnamelen = FS_DEFAULT_NAMELEN;
		server->config->fs_mask_dir_wrr = 1;
		
		FS_CONF_DEFAULT_DIR_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;
		FS_CONF_DEFAULT_FILE_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R;

		sprintf(passwordfile, "%s/Configuration", server->directory);
		cfgfile = fopen(passwordfile, "r+");

		if (!cfgfile) // Config file not present
		{
			if ((cfgfile = fopen(passwordfile, "w+")))
				fwrite(server->config, 256, 1, cfgfile);
			else fs_debug (0, 1, "Unable to write configuration file at %s - not initializing", passwordfile);

			fsop_write_readable_config(server);
		}
		else
		{
			int configlen;

			fseek(cfgfile, 0, SEEK_END);
			configlen = ftell(cfgfile);
			rewind(cfgfile);

			if (configlen != 256)
				fs_debug (0, 1, "Configuration file is incorrect length!");
			else
			{
				fread (server->config, 256, 1, cfgfile);
				fs_debug (0, 2, "Configuration file loaded");
			}

			// Install some defaults if they need setting
			if (FS_CONF_DEFAULT_DIR_PERM(server) == 0x00) 
				FS_CONF_DEFAULT_DIR_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;

			if (FS_CONF_DEFAULT_FILE_PERM(server) == 0x00)
				FS_CONF_DEFAULT_FILE_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R; // NB OTH_R added here for backward compatibility. If this is a server where this default was unconfigured, we configure it to match what PiFS v2.0 did

			rewind(cfgfile);

			// Write copy in case we've updated it
			fwrite(server->config, 256, 1, cfgfile);
			
			fsop_write_readable_config(server);
		}

		if (FS_CONFIG(server,fs_fnamelen) < 10 || FS_CONFIG(server,fs_fnamelen) > ECONET_ABS_MAX_FILENAME_LENGTH)
			server->config->fs_fnamelen = 10;

		// Filename regex compile moved here so we know how long the filenames are. We set this to maximum length because
		// the normalize routine sifts out maximum length for each individual server and there is only one regex compiled
		// because the scandir filter uses it, and that routine cannot take a server number as a parameter.

		sprintf(regex, "^(%s{1,%d})", FSACORNREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);

		if (regcomp(&(server->r_pathname), regex, REG_EXTENDED) != 0)
			fs_debug (1, 0, "Unable to compile regex for file and directory names.");

		// Load / Create password file

		sprintf(passwordfile, "%s/Passwords", server->directory);
	
		passwd = fopen(passwordfile, "r+");
		
		if (!passwd)
		{
			struct __fs_user	u;

			fs_debug (0, 1, "No password file - initializing %s with SYST", passwordfile);
			memset (&u, 0, sizeof(u));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow="
			sprintf (u.username, "%-10.10s", "SYST");
			sprintf (u.password, "%-10.10s", "");
			sprintf (u.fullname, "%-24.24s", "System User"); 
			u.priv = FS_PRIV_SYSTEM;
			u.priv2 = FS_PRIV2_BRIDGE; /* Automatically add bridge privileges to new SYST user */
			u.bootopt = 0;
			sprintf (u.home, "%-80.80s", "$");
			sprintf (u.lib, "%-80.80s", "$.Library");
#pragma GCC diagnostic pop
			u.home_disc = 0;
			u.year = u.month = u.day = u.hour = u.min = u.sec = 0; // Last login time
			if ((passwd = fopen(passwordfile, "w+")))
				fwrite(&(u), 256, 1, passwd);
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

				if ((length / 256) != ECONET_MAX_FS_USERS) // Old pw file that hasn't been padded
				{
					struct __fs_user u;
					fseek(passwd, 0, SEEK_END);
					memset(&u, 0, sizeof(u));
					fwrite(&u, 256, ECONET_MAX_FS_USERS - (length / 256), passwd);
				}

				fseek(passwd, 0, SEEK_END);
				length = ftell(passwd);
				
				fs_debug (0, 2, "Password file read - %d user(s)", (length / 256));
				server->users = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(passwd), 0);
				if (server->users == MAP_FAILED)
					fs_debug (1, 0, "Cannot mmap() password file (%s)", strerror(errno));

				server->total_users = (length / 256);
				server->total_discs = 0;
		
				if (server->config->fs_pwtenchar == 0) // Shuffle full name field along 5 characters and blank out the 5 spaces
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
					
					for (u = 0; u < server->total_users; u++)
					{
						char old_realname[30];
						// Move real name 5 bytes further on (but our struct has been updated, so it's actually 5 bytes earlier than the struct suggests! And copy it, less 5 bytes

						memcpy (old_realname, &(server->users[u].password[6]), 30);
						memcpy (server->users[u].fullname, old_realname, 25);
						memset (&(server->users[u].password[6]), 32, 5);

					}

					server->config->fs_pwtenchar = 1;

					rewind(cfgfile);
					fwrite (server->config, 256, 1, cfgfile);
					rewind(cfgfile);

					fs_debug (0, 1, "Updated password file for 10 character passwords, and backed up password file to %s", passwordfilecopy);
				}

				fclose (cfgfile);

				// Make MDFS password file

				if (server->config->fs_sjfunc)
					fsop_make_mdfs_pw_file(server); // Causing problems in the directory build

				// Now load up the discs. These are named 0XXX, 1XXX ... FXXXX for discs 0-15
				while ((entry = readdir(d)) && discs_found < ECONET_MAX_FS_DISCS)
				{

					struct 	stat statbuf;
					char	fullname[1024];

					sprintf(fullname, "%s/%s", server->directory, entry->d_name);

					if (((entry->d_name[0] >= '0' && entry->d_name[0] <= '9') || (entry->d_name[0] >= 'A' && entry->d_name[0] <= 'F')) && (entry->d_type == DT_DIR || (entry->d_type == DT_LNK && (stat(fullname, &statbuf) == 0) && (S_ISDIR(statbuf.st_mode)))) && (strlen((const char *) entry->d_name) <= 17)) // Found a disc. Length 17 = index character + 16 name; we ignore directories which are longer than that because the disc name will be too long
					{
						uint8_t index, count;
						struct __fs_disc	*d;

						FS_LIST_MAKENEW(struct __fs_disc,server->discs,0,d,"FS","Create disc structure");
						
						if (entry->d_name[0] > '9') 
							index = (uint8_t) ((entry->d_name[0]) - ('A' - 10));
						else
							index = (uint8_t) (entry->d_name[0] - '0');
	
						d->index = index;

						count = 0;

						while (count < 16 && (entry->d_name[count+1] != 0))
						{
							d->name[count] = entry->d_name[1+count];	
							count++;
						}

						d->name[count] = 0;
					
						fs_debug (0, 2, "Initialized disc name %s (%d)", d->name, index);

						server->total_discs++;
	
					}
				}
				
				closedir(d);
		
				if (server->total_discs > 0)
				{
					// Load / Initialize groups file here - TODO
					unsigned char groupfile[1024];
					FILE *group;

					sprintf(groupfile, "%s/Groups", server->directory);
	
					group = fopen(groupfile, "r+");

					if (!group) // Doesn't exist - create it
					{

						struct __fs_group g;

						memset (&g, 0, sizeof(g));

						fs_debug (0, 1, "No group file at %s - initializing", groupfile);

						if ((group = fopen(groupfile, "w+")))
							fwrite(&g, sizeof(struct __fs_group), 256, group);

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
							server->groups = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(group), 0);
							server->total_groups = length;
							server->enabled = 0;
						}

						fclose(group);
					}
					else fs_debug (0, 1, "Server failed to initialize - cannot initialize or find Groups file!");

					// (If there was still no group file here, fs_count won't increment and we don't initialize)
				}
				else fs_debug (0, 1, "Server failed to find any discs!");
			}
			fclose(passwd);
	
		}
		
	}
	
	/* If told to, set bridge priv on SYST user */

	if (fs_set_syst_bridgepriv)
	{
		int	userid;

		if ((userid = fsop_get_uid(server, "SYST")) >= 0)
			server->users[userid].priv2 |= FS_PRIV2_BRIDGE;
	}

        if (pthread_mutex_init(&server->fs_mutex, NULL) == -1)
        {
                FS_LIST_SPLICEFREE(fileservers, server, "FS", "Free fileserver control structure after failed mutex init");
                return NULL;
        }

        if (pthread_mutex_init(&server->fs_mpeek_mutex, NULL) == -1)
        {
                FS_LIST_SPLICEFREE(fileservers, server, "FS", "Free fileserver control structure after failed mpeek mutex init");
                return NULL;
        }

        if (pthread_cond_init(&server->fs_condition, NULL) == -1)
        {
                FS_LIST_SPLICEFREE(fileservers, server, "FS", "Free fileserver control structure after failed cond init");
                return NULL;
        }

        /* Don't do anything with fs_thread - fsop_run() sets that up */

	fs_debug (0, 2, "Server at %s successfully initialized on station %d.%d", server->directory, server->net, server->stn);

	fsop_write_readable_config(server);

	return server;
}

/* 
 * fsop_shutdown()
 *
 * Designed to be called from within the main FS thread. 
 *
 * This kicks all users off, and cleans up the server
 * struct so that nothing remains allocated within it.
 *
 * Then returns. The calling thread will then exit.
 *
 * To start the FS up again, call fs_initialize. That
 * (re) creates the thread with the server disabled.
 *
 * Then at some stage call fs_run, which sets enabled
 * to true and wakes the thread up.
 *
 * This function must be called with the fs_mutex
 * lock held.
 *
 */

void fsop_shutdown (struct __fs_station *s)
{
	struct __fs_active	*a, *n;
	struct __fs_disc 	*disc;
	struct load_queue	*l;
	struct __fs_bulk_port	*bulk;
	struct __eb_packetqueue *pq;

	// Flag server inactive
	
	s->enabled = 0;

	eb_port_deallocate(s->fs_device, 0x99); 

	a = s->actives;

	while (a)
	{
		n = a->next;

		fsop_bye_internal(a, 0, 0);

		a = n;
	}

	if (s->actives) /* This should not have anything in it! */
		fs_debug (0, 1, "Server at %d.%d was left with one or more active users after shutdown!", s->net, s->stn);

	if (s->files) /* This should not have anything in it after everyone has been logged off! */
		fs_debug (0, 1, "Server at %d.%d was left with one or more open files after shutdown!", s->net, s->stn);

	/* Unmap users and groups */

	if (s->users)
		munmap(s->users, 256 * s->total_users); 

	if (s->groups)
		munmap(s->groups, 10 * s->total_groups);

	s->users = NULL;
	s->groups = NULL;

	/* Free any discs we found */

	disc = s->discs;

	while (disc)
	{
		struct __fs_disc *n;

		n = disc->next;
		eb_free (__FILE__, __LINE__, "FS", "Free disc struct", disc);
		disc = n;
	}

	s->discs = NULL;

	/* Free the config struct */

	eb_free (__FILE__, __LINE__, "FS", "Free config struct", s->config);

	/* Dump the various queues, if there's anything on them */

	l = s->fs_load_queue;

	while (l)
	{
		struct load_queue *ln;
		struct __pq *packetq, *packetq_next;

		ln = l->next;	

		fs_debug (0, 3, "FS", "Server at %3d.%3d cleaning up load_queue at %p on shutdown", s->net, s->stn, l);
		packetq = l->pq_head;

		while (packetq)
		{
			packetq_next = packetq->next;

			fs_debug (0, 3, "FS", "Server at %3d.%3d freeing packetq entry at %p on load_queue at %p on shutdown", s->net, s->stn, packetq, l);
			eb_free(__FILE__, __LINE__, "FS", "Free packet queue entry on shutdown", packetq);

			packetq = packetq_next;
		}

		eb_free(__FILE__, __LINE__, "FS", "Free load queue entry at %p on shutdown", l);

		l = ln;
	}

	s->fs_load_queue = NULL;

	/* Next clean up the bulk ports */

	bulk = s->bulkports;

	while (bulk)
	{
		struct __fs_bulk_port *bn;

		bn = bulk->next;

		eb_port_deallocate(s->fs_device, bulk->bulkport);

		fs_debug (0, 3, "FS", "Server at %3d.%3d freeing bulk port entry at %p on shutdown", s->net, s->stn, bulk);

		bulk = bn;

	}

	s->bulkports = NULL;

	/* Next clean up the work queue */

	pq = s->fs_workqueue;

	while (pq)
	{
		struct __eb_packetqueue	*pqn;

		pqn = pq->n;

		fs_debug (0, 3, "FS", "Server at %3d.%3d freeing work queue entry at %p on shutdown", s->net, s->stn, pq);

		eb_free(__FILE__, __LINE__, "FS", "Free packet on FS workqueue on shutdown", pq->p);
		eb_free(__FILE__, __LINE__, "FS", "Free packet queue entry on work queue on shutdown", pq);

		pq = pqn;

	}

	s->fs_workqueue = NULL;

	fs_debug (0, 1, "Server at %d.%d has shut down", s->net, s->stn);

	return;

}

// Used when we must be able to specify a ctrl byte

void fsop_error_ctrl(struct fsop_data *f, uint8_t ctrl, uint8_t error, char *msg)
{

        struct __econet_packet_udp reply;

        reply.p.port = FSOP_REPLY_PORT;
        reply.p.ctrl = ctrl;
        reply.p.ptype = ECONET_AUN_DATA;
        reply.p.data[0] = 0x00;
        reply.p.data[1] = error;
        memcpy (&(reply.p.data[2]), msg, strlen((const char *) msg));
        reply.p.data[2+strlen(msg)] = 0x0d;

        // 8 = UDP Econet header, 2 = 0 and then error code, rest is message + 0x0d
        fsop_aun_send (&reply, 2+(strlen(msg))+1, f);

}

// Used when we don't need to send a particular control byte back
//
void fsop_error(struct fsop_data * f, uint8_t error, char *msg)
{
	fsop_error_ctrl(f, 0x80, error, msg);
}

/*
 * Signal OK completion to station.
 *
 * Wonder why this cannot just do fs_reply_success (..., 0, 0) ?
 *
 * Answer: looks like it can be.
 *
 * And then this can be fs_reply_ok_with_data (and a data len of 0)
 *
 * And fs_reply_success can have fs_reply_success_with_data and we'll use that instead of
 * fs_reply_success_with_data
 *
 */

/* Variant of fs_reply_ok for use with fsop_data struct */
void fsop_reply_ok(struct fsop_data * f)
{

	fsop_reply_success(f, 0, 0);

}

void fsop_reply_success(struct fsop_data *f, uint8_t cmd, uint8_t code)
{
	FS_REPLY_DATA(0x80);

        reply.p.port = FSOP_REPLY_PORT;
        reply.p.seq = eb_get_local_seq(f->server->fs_device);
	reply.p.data[0] = cmd;
	reply.p.data[1] = code;

        fsop_aun_send (&reply, 2, f);
}

/*
 * fsop_reply_ok_with_data
 *
 * Send OK reply with data portion
 *
 * Will eventually streamline this into fs_reply_ok and fs_reply_success
 *
 */

void fsop_reply_ok_with_data(struct fsop_data *f, uint8_t *data, uint16_t datalen)
{

	FS_REPLY_DATA(0x80);

        reply.p.port = FSOP_REPLY_PORT;
        reply.p.seq = eb_get_local_seq(f->server->fs_device);
        memcpy (&(reply.p.data[2]), data, datalen);

        fsop_aun_send (&reply, 2+datalen, f);
}

#define fsop_toupper fs_toupper

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

/* "Book out" a bulk port number.
 * Calling function responsible for making the struct etc.
 */

void fsop_handle_bulk_traffic(struct __econet_packet_aun *, uint16_t, void *);

uint8_t fsop_find_bulk_port(struct __fs_station *s)
{
	return eb_port_allocate(s->fs_device, 0, fsop_handle_bulk_traffic, s);
}

/* 
 * See if a station is logged in 
 * by searching for its 'active' struct
 */

struct __fs_active * fsop_stn_logged_in(struct __fs_station *s, uint8_t net, uint8_t stn)
{

	struct __fs_active 	*a;
	uint8_t			found = 0;

	a = s->actives;

	while (a && !found)
	{
		if (a->net == (net == 0 ? s->net : net)
			&&  a->stn == stn)
			return a;
		else
			a = a->next;
	}

	return NULL; /* Not found */
}

/* Variant of fsop_stn_logged_in with locking - used by the bridge itself */

struct __fs_active * fsop_stn_logged_in_lock(struct __fs_station *s, uint8_t net, uint8_t stn)
{
	struct __fs_active	*a;

	pthread_mutex_lock (&(s->fs_mutex));
	a = fsop_stn_logged_in(s, net, stn);
	pthread_mutex_unlock (&(s->fs_mutex));

	return a;
}

void fsop_bye_internal(struct __fs_active *a, uint8_t do_reply, uint8_t reply_port)
{

	struct __econet_packet_udp	reply;
	int count;
	struct __fs_station *s; 

	fs_debug_full (0, 1, a->server, a->net, a->stn, "Bye");

	s = a->server;

	reply.p.ptype = ECONET_AUN_DATA;
	reply.p.ctrl = 0x80;
	reply.p.port = reply_port;

	// Close active files / handles
	
	count = 1;
	while (count < FS_MAX_OPEN_FILES)
	{
		if (a->fhandles[count].handle)
		{
			/* TODO: Clean up any load_queue or bulk port entries here */

			if (a->fhandles[count].is_dir) /* deallocator closes the internal handle */
				fsop_deallocate_user_dir_channel(a, count);
			else
			{
				fsop_close_interlock(a->server, a->fhandles[count].handle, a->fhandles[count].mode);
				fsop_deallocate_user_file_channel(a, count);
			}
		}
		count++;
	}

	if (do_reply) // != 0 if we need to send a reply (i.e. user initiated bye) as opposed to 0 if this is an internal cleardown of a user
	{
	
		// Active logout - remove bridge priv bit
		eb_fast_priv_notify(s->fs_device, a->net, a->stn, 0);

		raw_fsop_aun_send(&reply, 2, s, a->net, a->stn);
	}

	FS_LIST_SPLICEFREE(s->actives, a, "FS", "fsop_bye_internal() deallocate active struct");

}

#if 0
/* Moved to new structure */
void fsop_change_pw(struct fsop_data *f, uint8_t reply_port, uint16_t userid, uint8_t net, uint8_t stn, unsigned char *params)
{
	char pw_cur[11], pw_new[13], pw_old[11]; // pw_new is 13 to cope with 10 character password in quotes
	int ptr;
	int new_ptr;

	if (f->server->users[userid].priv & FS_PRIV_NOPASSWORDCHANGE)
	{
		fsop_error(f, 0xBA, "Insufficient privilege");
		return;
	}

	// Possibly replace with memcpy() ?
	strncpy((char * ) pw_cur, (const char *) f->server->users[userid].password, 10);
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
		fsop_error(f, 0xFE, "Bad command");
	else
	{

		uint8_t termination_char;

		new_ptr = 0;
		while (*(params+ptr) == ' ') ptr++; // Skip space
		//ptr++;

		// Copy new password
		while (ptr < strlen(params) && (*(params+ptr) != 0x0d) && (new_ptr < 12))
			pw_new[new_ptr++] = *(params+ptr++);

		termination_char = *(params+ptr);

		// If next character is not null and we have 10 characters then bad password

		if (new_ptr >= 10 && termination_char != 0x00) // The packet comes in with a 0x0d terminator, but the OSCLI (FSOp 0) command parser changes that to null termination
			fsop_error(f, 0xFE, "Bad new password");
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
				fsop_error(f, 0xB9, "Bad password");
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
					strncpy((char *) f->server->users[userid].password, (const char * ) blank_pw, 10);
				else
					strncpy((char *) f->server->users[userid].password, (const char * ) pw_new, 10);

				/* Should be unnecessary now - MMAPed
				fs_write_user(server, userid, (char *) &(users[server][userid]));	
				*/

				fsop_reply_success(f, 0, 0);

				strncpy((char *) username, (const char *) f->server->users[userid].username, 10);
				username[10] = 0;
				fs_debug (0, 1, "User %s changed password", username);
			}
			else	fsop_error(f, 0xB9, "Bad password");
		}
	}

}

/* 
 * FS Op 0x60 (96)
 *
 * PiBridge service call
 *
 * *(data+5) is arg
 *
 * arg = 
 * 0 - Return PiBridge build information
 * 16 - Return PiFS user ID & privilege bytes
 * 17 - Read FS configuration info (Acorndir, MDFS, MDFSINFO, Unix base directory, etc.)
 * 18 - Write FS configuration info (base directory is never writeable)
 * 19 - Shut down fileserver
 * 20 - Force logoff a user by name or ID
 *
 */

/* Moved to new structure */

void fs_pibridge (int server, uint8_t reply_port, uint16_t active_id, uint8_t net, uint8_t stn, uint8_t *data, uint16_t datalen)
{

	uint8_t 	arg;

	arg = *(data+5);

	/* Args 0 - 15 are Bridge Priv users only,
	 * Args 16- 31 are Syst only,
	 * Args 32- 64 are anyones
	 */

	if (
			(arg < 16 && !FS_ACTIVE_BRIDGE(server, active_id))
		||	(arg >= 16 && arg < 32 && !FS_ACTIVE_SYST(server, active_id))
	   )
	{
		fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call - prohibited", "", net, stn);
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}
	switch (arg)
	{

		/* BRIDGE PRIVILEGES ONLY */
		 
		/* arg 0 - Return PiBridge build information - Bridge privileged users only */

		case 0: 
		{
			char	ver[128];

			fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 0 - Get GIT version", "", net, stn);
			strcpy (ver, GIT_VERSION);
			ver[strlen(GIT_VERSION)+1] = 0x00;
			ver[strlen(GIT_VERSION)] = 0x0D;
			fs_reply_ok_with_data(server, reply_port, net, stn, ver, strlen(ver));

		} break;

		/* arg 1 - shutdown host system if binary is setuid */

		case 1:
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 1 - Pi Shutdown", "", net, stn);
			if (seteuid(0) != 0)
				fs_error(server, reply_port, net, stn, 0xFF, "Bridge not able to shut down");
			else
			{
				char *	shutdown_msg = "Bridge shutting down\x0d";

				fs_reply_ok_with_data(server, reply_port, net, stn, shutdown_msg, strlen(shutdown_msg));

				if (!fork())
				{
					usleep(5000000); // To get the reply out
					execl("/usr/sbin/shutdown", "shutdown", "-h", "now", NULL);
				}

			}
			return; // May never get here
		} break;

		/* SYSTEM PRIVILEGES ONLY */

		/* arg 16 - Return user ID & privilege bytes for username at *(data + 6... 0x0D terminated) */

		case 0x10:
		{
			uint8_t		info[4];
			int16_t		uid;
		 	unsigned char	username[11];

			fs_copy_to_cr(username, (data + 6), 10);
			uid = fs_get_uid (server, username);

			fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 16 - Get UID and priv bits for %s", "", net, stn, username);
			if (uid < 0) /* Not found */
				fs_error(server, reply_port, net, stn, 0xFF, "Unknown user");
			else
			{
				/* UID, low byte first */
				info[0] = (uid & 0xff);
				info[1] = (uid & 0xff00) >> 8;

				/* Then privilege bytes */
				info[2] = users[server][uid].priv;
				info[3] = users[server][uid].priv2;

				fs_reply_ok_with_data(server, reply_port, net, stn, info, 4);
			}

		} break;

		/* Read fileserver parameters (ACORNDIR, MDFS, MDFSINFO, etc.) */

		case 0x11: 
		{
			uint8_t	data[5];
			uint32_t params;

			fs_get_parameters (server, &params, &(data[4]));

			fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 17 - Get FS parameters (0x%04X, filename length %d)", "", net, stn, params, data[4]);

			// Shift FS params into data, LSB first

			data[0] = params & 0xff;
			data[1] = (params & 0xff00) >> 8;
			data[2] = (params & 0xff0000) >> 16;
			data[3] = (params & 0xff000000) >> 24;

			fs_reply_ok_with_data(server, reply_port, net, stn, data, 5);

		} break;

		/* Write fileserver parameters (ACORNDIR, MDFS, MDFSINFO, etc.) */

		case 0x12: 
		{
			uint32_t params;
			uint8_t fnlength;

			params = 	(*(data+6))
				+	(*(data+7) << 8)
				+	(*(data+8) << 16)
				+	(*(data+9) << 24);
			
			fnlength = *(data+10);
	
			fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 18 - Set FS parameters (0x%04X, filename length %d)", "", net, stn, params, fnlength);

			if (fnlength < 10 || fnlength > 79)
			{
				fs_error(server, reply_port, net, stn, 0xFF, "Bad filename length");
				return;
			}

			fs_set_parameters (server, params, fnlength);

		} break;

		/* Shut down fileserver */

		case 0x13:
		{
			char shutdown_msg[128];

			snprintf (shutdown_msg, 127, "Fileserver at %d.%d shutting down\x0d", fs_stations[server].net, fs_stations[server].stn);
			fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 19 - Shut down fileserver", "", net, stn);
			fs_reply_ok_with_data(server, reply_port, net, stn, shutdown_msg, strlen(shutdown_msg));
			fs_shutdown(server);

		} break;

		/* Force log user off by name (arg2 = 0) or uid (arg2 = 1) or station number (arg2 = 2) */
		case 0x14:
		{
			uint8_t		arg2;
			int16_t		uid; 
			uint8_t		l_net, l_stn;
			unsigned char	username[11];
			uint16_t	loggedoff = 0;
			uint8_t		replydata[2];
			uint16_t	count;

			arg2 = *(data+6);

			switch (arg2)
			{
				case 0: /* by username */
				{
					if (datalen < 9) /* One character username + 0x0D */
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Insufficient data");
						return;
					}

					fs_copy_to_cr (username, (data+7), 10);
					uid = fs_get_uid(server, username);

					fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 20 - Force log off by username: %s (ID 0x%04X)", "", net, stn, username, uid);
					if (uid < 0) /* Not known */
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Unknown user");
						return;
					}
				}; /* uid now has valid user number */ break;

				case 1: /* by uid */
				{
					if (datalen < 9)
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Insufficient data");
						return;
					}

					uid = (*(data + 7)) + (*(data + 8) << 8);

					if (users[server][uid].priv == 0) /* Deleted user */
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Unknown user");
						return;
					}

					fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 20 - Force log off by user id: %d", "", net, stn, uid);
				} break;

				case 2: /* by station */
				{
					if (datalen < 9)
					{
						fs_error(server, reply_port, net, stn, 0xFF, "Insufficient data");
						return;
					}

					l_net = *(data+7);
					l_stn = *(data+8);

					fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 20 - Force log off by station: %d.%d", "", net, stn, l_net, l_stn);
				} break;

				default:
				{
					fs_error(server, reply_port, net, stn, 0xFF, "Bad argument");
					return;
				}
			}

			/* Log the relevant users off & send back a count of how many */
	
			for (count = 0; count < ECONET_MAX_FS_ACTIVE; count++)
			{
				if (	(arg2 == 2 && active[server][count].net == l_net && active[server][count].stn == l_stn)
				||	(arg2 < 2 && active[server][count].userid == uid) 
				)
				{
					fs_bye(server, 0, active[server][count].net, active[server][count].stn, 0); // Silent bye
					loggedoff++;
				}
			}

			replydata[0] = loggedoff & 0xff;
			replydata[1] = (loggedoff & 0xff00) >> 8;

			fs_reply_ok_with_data(server, reply_port, net, stn, replydata, 2);

		} break;

		/* Catch undefined operations */

		default:
			fs_error(server, reply_port, net, stn, 0xFF, "Unsupported");

	}

}
// Set boot option
void fsop_set_bootopt(struct fsop_data *f, uint16_t userid, uint8_t opt)
{

	unsigned char 	username[11];
	struct __fs_active	*a;

	/* 
	 * Check if user can change boot opt
	 */

	if (!(FS_ACTIVE_SYST(f->active) && f->server->users[userid].priv2 & FS_PRIV2_FIXOPT)) 
	{
		fs_debug (0, 2, "%12sfrom %3d.%3d Set boot option %d - prohibited", "", f->net, f->stn, opt);

		fsop_error(f, 0xBD, "Insufficient access");

		return;
	}

	if (opt > 7)
	{
		fsop_error(f, 0xBD, "Bad option");
		return;
	}

	fsop_get_username_base(f->server, userid, username);

	fs_debug (0, 2, "%12sfrom %3d.%3d Set boot option %d for user %s", "", f->net, f->stn, opt, username);
	
	f->server->users[userid].bootopt = opt;

	/* change live bootopt if logged in */

	a = f->server->actives;

	while (a)
	{
		if (a->userid == userid)
			a->bootopt = opt;

		a = a->next;
	}


	/* Should be unnecessary now we are mmaped 
	fs_write_user(server, userid, (char *) &(users[server][userid]));
	*/

	fsop_reply_success(f, 0, 0);

	return;


}

/* Moved to new structure */
void fsop_login(struct fsop_data *f, unsigned char *command)
{

	char username[11];
	char password[11];

	unsigned short counter, stringptr;
	unsigned short found = 0;

	// Notify not privileged on any login attempt, successful or otherwise. It'll get set to 1 below if need be
	
	eb_fast_priv_notify(f->server->fs_device, net, stn, 0);

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

	while (counter < f->server->total_users && !found)
	{
		if (!strncasecmp(f->server->users[counter].username, username, 10) && (f->server->users[counter].priv != 0))
			found = 1;
		else
			counter++;
	}

	if (found)
	{
		if (strncasecmp((const char *) f->server->users[counter].password, password, 10))
		{
			fsop_error(f, 0xBC, "Wrong password");
			fs_debug(0, 1, "            from %3d.%3d Login attempt - username '%s' - Wrong password", f->net, f->stn, username);
		}
		else if (f->server->users[counter].priv & FS_PRIV_LOCKED)
		{
			fsop_error(f, 0xBC, "Account locked");
			fs_debug (0, 1, "           from %3d.%3d Login attempt - username '%s' - Account locked", f->net, f->stn, username);
		}
		else
		{
			FS_REPLY_DATA(0x80);

			struct __fs_active *a;

			uint8_t err;

			a = f->server->actives;

			// Is this station logged on ?

			while (a)
			{
				if ((a->net == net && a->stn == stn)) // Allows us to overwrite an existing handle if the station is already logged in
					found = 1;
				else	a = a->next;
			}

			if (a) // Log off
			{
				f->active = a;
				fsop_bye_internal(a, 0, 0); // Silent
			}

			FS_LIST_MAKENEW(struct __fs_active,f->server->actives,1,a,"FS","Login making new active struct");
			
			a->net = (net == 0 ? f->server->net : net);
			a->stn = stn;
			a->printer = 0xff; // No current printer selected
			a->userid = counter;
			a->user = &(f->server->users[counter]);
			a->bootopt = users[server][counter].bootopt;
			a->priv = f->server->users[counter].priv;
			a->userid = counter;
			a->current_disc = f->server->users[counter].home_disc; // Need to set here so that first normalize for URD works.
			a->is_32bit = 0; /* Updated later, when we've implemented MachinePeek at login */
			a->server = f->server;
			a->root = a->current = a->lib = 0; /* Rogue so things don't get closed when they aren't open */
			f->active = a;

			for (count = 0; count < FS_MAX_OPEN_FILES; count++) a->fhandles[count].handle = NULL; // Flag unused for files

			strncpy((char * ) home, (const char * ) f->server->users[counter].home, 96);
			home[96] = '\0';

			for (count = 0; count < 80; count++) if (home[count] == 0x20) home[count] = '\0'; // Remove spaces and null terminate

			if (home[0] == '\0')
			{
				sprintf(home, "$.%s", f->server->users[counter].username);
				home[80] = '\0';
				if (strchr(home, ' ')) *(strchr(home, ' ')) = '\0';
			}
			

			err = fsop_move_disc (f, a->current_disc);

			if (err != FSOP_MOVE_DISC_SUCCESS)
			{
				/* fsop_move_disc will have cleared down the handles */

				unsigned char	which[5],	error[20];
				unsigned char	errstr[40];

				switch((err & 0x0F))
				{
					case FSOP_MOVE_DISC_URD:	strcpy(which, "URD"); break;
					case FSOP_MOVE_DISC_CWD:	strcpy(which, "CWD"); break;
					case FSOP_MOVE_DISC_LIB:	strcpy(which, "LIB"); break;
				}

				switch ((err & 0xF0))
				{
					case FSOP_MOVE_DISC_NOTFOUND:	strcpy(error, "Not found"); break;
					case FSOP_MOVE_DISC_NOTDIR:	strcpy(error, "Not a directory"); break;
					case FSOP_MOVE_DISC_UNREADABLE:	strcpy(error, "Unreadable"); break;
					case FSOP_MOVE_DISC_UNMAPPABLE:	strcpy(error, "Unmappable"); break;
					case FSOP_MOVE_DISC_CHANNEL:	strcpy(error, "No available channel"); break;
					case FSOP_MOVE_DISC_INVIS:	strcpy(error, "Disc invisible to user"); break;
				}

				fs_debug (0, 1, "%12sfrom %3d.%3d Login attempt - %s %s for userid %04X", "", f->net, f->stn, which, error, a->userid);

				sprintf(errstr, "%s %s", which, error);
				fsop_error (f, 0xFF, errstr);
				FS_LIST_SPLICEFREE(f->server->actives, a, "FS", "Freeing active struct when cannot mount disc");
				return;
			}

			if (f->server->users[a->userid].priv2 & FS_PRIV2_CHROOT) // Fudge the root directory information so that $ maps to URD
			{
				char *dollar;

				sprintf(a->root_dir_tail, "$         ");
				snprintf(a->root_dir, 2600, "$.");
				fs_store_tail_path(a->fhandles[a->root].acorntailpath, "$");
				dollar = strchr(a->fhandles[a->root].acornfullpath, '$');

				*(dollar+1) = 0; // Drop everything after the '.' after the dollar sign

				strcpy(a->current_dir_tail, a->root_dir_tail);
				strcpy(a->current_dir, a->root_dir);
				fs_store_tail_path(a->fhandles[a->current].acorntailpath, "$");
				strcpy(a->fhandles[a->current].acornfullpath, a->fhandles[a->root].acornfullpath);

			}

			// Notify bridge if we have a Bridge priv user

			if (a->user->priv2 & FS_PRIV2_BRIDGE) // Bridge priv user
			{
				eb_fast_priv_notify(a->server->fs_device, f->net, f->stn, 1);
				fs_debug (0, 1, "%12sfrom %3d.%3d User %s has bridge privileges", "", f->net, f->stn, username);
			}
		
			fs_debug (0, 1, "            from %3d.%3d Login as %s, id %04X, disc %d, URD %s, CWD %s, LIB %s, priv 0x%02x", f->net, f->stn, username, a->userid, a->current_disc, a->root, a->current, a->lib, a->user->priv);

			// Tell the station
		
			reply.p.data[0] = 0x05;
			reply.p.data[2] = FS_MULHANDLE(a->root);
			reply.p.data[3] = FS_MULHANDLE(a->current);
			reply.p.data[4] = FS_MULHANDLE(a->lib);
			reply.p.data[5] = a->bootopt;
			
			fsop_aun_send(&reply, 6, f);
		}
	}
	else
	{
		fs_debug (0, 1, "            from %3d.%3d Login attempt - username '%s' - Unknown user", f->net, f->stn, username);
		fsop_error(f, 0xBC, "User not known");
	}

}

void fsop_read_user_env(struct fsop_data *f)
{

	FS_R_DATA(0x80);

	int replylen = 2, count, termfound;
	unsigned short disclen;
	unsigned char	discname[17];
	struct __fs_active	*a;

	a = f->active;

	fs_debug (0, 2, "%12sfrom %3d.%3d Read user environment - current user handle %d, current lib handle %d", "", f->net, f->stn, f->active->current, f->active->lib);

	// If either current or library handle is invalid, barf massively.

	//fs_debug (0, 2, "Current.is_dir = %d, handle = %d, Lib.is_dir = %d, handle = %d\n", active[server][active_id].fhandles[active[server][active_id].current].is_dir, active[server][active_id].fhandles[active[server][active_id].current].handle, active[server][active_id].fhandles[active[server][active_id].lib].is_dir, active[server][active_id].fhandles[active[server][active_id].lib].handle);

	if (!(a->fhandles[a->current].is_dir)
	||  !(a->fhandles[a->lib].is_dir)
	||  !(a->fhandles[a->current].handle)
	||  !(a->fhandles[a->lib].handle))
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	disclen = r.p.data[replylen++] = 16; // strlen(fs_discs[server][active[server][active_id].disc].name);

	fsop_get_disc_name(f->server, a->current_disc, discname);

	sprintf (&(r.p.data[replylen]), "%-16s", discname);

	replylen += disclen;

	memcpy(&(r.p.data[replylen]), &(a->fhandles[a->current].acorntailpath), 10);

	termfound = 0;

	for (count = 0; count < 10; count++)
		if (termfound || r.p.data[replylen+count] == 0) 
		{
			r.p.data[replylen+count] = ' ';
			termfound = 1;
		}

	replylen += 10;

	memcpy(&(r.p.data[replylen]), &(a->fhandles[a->lib].acorntailpath), 10);

	termfound = 0;

	for (count = 0; count < 10; count++)
	if (termfound || r.p.data[replylen+count] == 0)
	{
		r.p.data[replylen+count] = ' ';
		termfound = 1;
	}

	replylen += 10;

	fsop_aun_send (&r, replylen, f);
	
}

void fsop_examine(struct fsop_data *f)
{
	FS_REPLY_DATA(0x80);

	uint8_t relative_to, arg, start, n;
	unsigned char path[1024]; // Was 256 before long filenames
	struct path p;
	struct path_entry *e;
	int replylen, replyseglen;
	unsigned short examined, dirsize;
	char acornpathfromroot[1024];

	relative_to = FSOP_CWD;
	arg = FSOP_ARG;
	start = *(f->data + 6);
	n = *(f->data + 7);

	fs_copy_to_cr(path, (f->data + 8), 255);

	fs_debug (0, 2, "%12sfrom %3d.%3d Examine %s relative to %d, start %d, extent %d, arg = %d", "", f->net, f->stn, path,
		relative_to, start, n, arg);

	replylen = 2;

	examined = reply.p.data[replylen++] = 0; // Repopulate data[2] at end
	dirsize = reply.p.data[replylen++] = 0; // Dir size (but this might be wrong). Repopulate later if correct

	if (!fsop_normalize_path_wildcard(f, path, relative_to, &p, 1) || p.ftype == FS_FTYPE_NOTFOUND)
	{

		if (arg == 0)
		{
			reply.p.data[replylen++] = 0x80;
			fsop_aun_send(&reply, replylen, f);
		}
		else
			fsop_error(f, 0xD6, "Not found");
		return;

	}

	// Add final entry onto path_from_root (because normalize doesn't do it on a wildcard call)

	if (strlen(p.path_from_root) != 0)
		strcat(p.path_from_root, ".");
	if (p.paths != NULL)
		strcat (p.path_from_root, p.paths->acornname);

	fs_free_wildcard_list(&p); // We'll just use the first one it found, which will be in the main path struct

	if (p.ftype != FS_FTYPE_DIR)
	{
		fsop_error(f, 0xAF, "Types don't match");
		return;
	}


	// Wildcard code

	strcpy(acornpathfromroot, path);

	if (strlen(acornpathfromroot) != 0) strcat(acornpathfromroot, ".");

	strcat(acornpathfromroot, "*"); // It should already have $ on it if root.

	// Wildcard renormalize - THE LONG FILENAMES MODS CAUSE THIS TO RETURN NOT FOUND ON AN EMPTY DIRECTORY
	
	if (!fsop_normalize_path_wildcard(f, acornpathfromroot, relative_to, &p, 1)) // || p.ftype == FS_FTYPE_NOTFOUND)
	{
		if (arg == 0)
		{
			reply.p.data[replylen++] = 0x80;
			fsop_aun_send(&reply, replylen, f);
		}
		else
			fsop_error(f, 0xD6, "Not found");
		return;
	}

	e = p.paths;

	while (dirsize < start && (e != NULL))
	{
		if ((e->perm & FS_PERM_H) == 0 || (e->owner == f->userid)) // not hidden
			dirsize++;

		e = e->next;
	}

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
		if (FS_ACTIVE_SYST(f->active) || (e->perm & FS_PERM_H) == 0 || (e->owner == f->userid)) // not hidden or we are the owner
		{
			switch (arg)
			{
				case 0: // Machine readable format
				{

					int le_count;

					snprintf(&(reply.p.data[replylen]), 11, "%-10.10s", e->acornname); // 11 because the 11th byte (null) gets overwritten two lines below because we only add 10 to replylen.

					replylen += 10;

					for (le_count = 0; le_count <= 3; le_count++)
					{
						reply.p.data[replylen + le_count] = ((e->ftype == FS_FTYPE_DIR ? 0 : htole32(e->load)) >> (8 * le_count)) & 0xff;
						reply.p.data[replylen + 4 + le_count] = ((e->ftype == FS_FTYPE_DIR ? 0 : htole32(e->exec)) >> (8 * le_count)) & 0xff;
					}

					replylen += 8; // Skip past the load / exec that we just filled in

					reply.p.data[replylen++] = fsop_perm_to_acorn(f->server, e->perm, e->ftype);
					reply.p.data[replylen++] = e->day;
					reply.p.data[replylen++] = e->monthyear;

					if (f->server->config->fs_sjfunc) // Next three bytes are ownership information - main & aux. We always set aux to 0 for now.
					{
						reply.p.data[replylen++] = (e->owner & 0xff);
						reply.p.data[replylen++] = ((e->owner & 0x700) >> 3);
						reply.p.data[replylen++] = 0; // Aux account number	
					}
					else
					{
						reply.p.data[replylen++] = e->internal & 0xff;
						reply.p.data[replylen++] = (e->internal & 0xff00) >> 8;
						reply.p.data[replylen++] = (e->internal & 0xff0000) >> 16;
					}

					if (e->ftype == FS_FTYPE_DIR)	e->length = 0x200; // Dir length in FS3

					reply.p.data[replylen++] = e->length & 0xff;
					reply.p.data[replylen++] = (e->length & 0xff00) >> 8;
					reply.p.data[replylen++] = (e->length & 0xff0000) >> 16;

				} break;
				case 1: // Human readable format
				{
					unsigned char tmp[256];
					unsigned char permstring_l[10], permstring_r[10];
					unsigned char permstring_both[20];
					unsigned char hr_fmt_string[80];
					uint8_t		is_owner;

					is_owner = FS_PERM_EFFOWNER(f->active, e->owner);
	
					if (f->server->config->fs_mask_dir_wrr && e->ftype == FS_FTYPE_DIR && (e->perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
						e->perm &= ~(FS_ACORN_DIR_MASK);

					sprintf(permstring_l, "%s%s%s%s",
						(e->ftype == FS_FTYPE_DIR ? "D" : e->ftype == FS_FTYPE_SPECIAL ? "S" : ""),
						((e->perm & FS_PERM_L) ? "L" : ""),
						((e->perm & FS_PERM_OWN_W) ? (is_owner ? "W" : FS_CONFIG(f->server,fs_mdfsinfo) ? "w": "W") : ""),
						((e->perm & FS_PERM_OWN_R) ? (is_owner ? "R" : FS_CONFIG(f->server,fs_mdfsinfo) ? "r" : "R") : "") );

					sprintf(permstring_r, "%s%s", 
						((e->perm & FS_PERM_OTH_W) ? (FS_CONFIG(f->server,fs_mdfsinfo) ? (is_owner ? "w" : "W") : "W") : ""),
						((e->perm & FS_PERM_OTH_R) ? (FS_CONFIG(f->server,fs_mdfsinfo) ? (is_owner ? "r" : "R") : "R") : "") );

					sprintf(permstring_both, "%s/%s", permstring_l, permstring_r);

					sprintf (hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX   %%-7s     %%02d/%%02d/%%02d %%06lX", ECONET_MAX_FILENAME_LENGTH);

					sprintf (tmp, hr_fmt_string, 
						e->acornname,
						e->load, e->exec, e->length,
						permstring_both,
						fs_day_from_two_bytes(e->day, e->monthyear),
						fs_month_from_two_bytes(e->day, e->monthyear),
						fs_year_from_two_bytes(e->day, e->monthyear),
						e->internal
						);
						
					strcpy((char * ) &(reply.p.data[replylen]), (const char * ) tmp);
					replylen += strlen(tmp);
					reply.p.data[replylen++] = '\0';

				} break;

				case 2: // 10 character filename format (short)
				{
					unsigned char hr_fmt_string[20];

					sprintf(hr_fmt_string, "%%-%d.%ds", ECONET_MAX_FILENAME_LENGTH, ECONET_MAX_FILENAME_LENGTH);

					reply.p.data[replylen++] = ECONET_MAX_FILENAME_LENGTH;
					sprintf((char *) &(reply.p.data[replylen]), hr_fmt_string, e->acornname);
					replylen += ECONET_MAX_FILENAME_LENGTH;

				} break;

				case 3: // 10 character filename format (long) - this can only do 10 characters according to the spec, but FS4 exceeds this, and it causes problems with RISC OS but Acorn didn't seem that bothered...!
				{
					char tmp[256];
					char permstring_l[10], permstring_r[10];
					uint8_t		is_owner;

					is_owner = FS_PERM_EFFOWNER(f->active, e->owner);

					if (f->server->config->fs_mask_dir_wrr && e->ftype == FS_FTYPE_DIR && (e->perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
						e->perm &= ~(FS_ACORN_DIR_MASK);

					sprintf(permstring_l, "%s%s%s%s",
						(e->ftype == FS_FTYPE_DIR ? "D" : e->ftype == FS_FTYPE_SPECIAL ? "S" : ""),
						((e->perm & FS_PERM_L) ? "L" : ""),
						((e->perm & FS_PERM_OWN_W) ? (is_owner ? "W" : f->server->config->fs_mdfsinfo ? "w": "W") : ""),
						((e->perm & FS_PERM_OWN_R) ? (is_owner ? "R" : f->server->config->fs_mdfsinfo ? "r" : "R") : "") );

					sprintf(permstring_r, "%s%s", 
						((e->perm & FS_PERM_OTH_W) ? (f->server->config->fs_mdfsinfo ? (is_owner ? "w" : "W") : "W") : ""),
						((e->perm & FS_PERM_OTH_R) ? (f->server->config->fs_mdfsinfo ? (is_owner ? "r" : "R") : "R") : "") );

					sprintf (tmp, "%-10s %4s/%-2s", e->acornname,
						permstring_l, permstring_r
						);

					strcpy((char * ) &(reply.p.data[replylen]), (const char * ) tmp);
					replylen += strlen(tmp) + 1; // +1 for the 0 byte

				} break;
			}

			examined++;
			dirsize++;
		}

		e = e->next;

	}

	fs_free_wildcard_list(&p);

	reply.p.data[replylen++] = 0x80;
	reply.p.data[2] = (examined & 0xff);
	reply.p.data[3] = (dirsize & 0xff); // Can't work out how L3 is calculating this number

	fsop_aun_send(&reply, replylen, f);

}

void fsop_set_object_info(struct fsop_data *f)
{

	FS_REPLY_DATA(0x80);

	unsigned short relative_to;

	unsigned short command;

	char path[1024];

	unsigned short filenameposition;
		
	struct path p;

	struct __fs_active *a;

	unsigned char *data = f->data; // Saves changing loads of stuff from the old version
	
	a = f->active;

	command = FSOP_ARG;
	relative_to = FSOP_CWD;

	if (command == 0x40 && !(f->server->config->fs_sjfunc))
	{
		fsop_error(f, 0xff, "MDFS Unsupported");
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
			fsop_error(f, 0xFF, "FS Error");
			return;
			break;
	}

	fs_copy_to_cr(path, (f->data+filenameposition), 1023);

	if (command != 4)
		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d", "", f->net, f->stn, path, relative_to == a->root ? "Root" : relative_to == a->lib ? "Library" : "Current", command);
	else
		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d, attribute &%02X", "", f->net, f->stn, path, relative_to == a->root ? "Root" : relative_to == a->lib ? "Library" : "Current", command, (*(f->data + 6)));
	
	if (!fsop_normalize_path(f, a, path, relative_to, &p) || p.ftype == FS_FTYPE_NOTFOUND)
		fsop_error(f, 0xD6, "Not found");
	else if (((!FS_ACTIVE_SYST(a))) && 
			(p.owner != a->userid) &&
			(p.parent_owner != a->userid)
		)
		fsop_error(f, 0xBD, "Insufficient access");
	else if (command != 1 && command != 4 && (p.perm & FS_PERM_L)) // Locked
	{
		fsop_error(f, 0xC3, "Entry Locked");
	}
	else
	{
		struct objattr attr;
	
		fsop_read_xattr(p.unixpath, &attr, f);

		switch (command)
		{
			case 1: // Set Load, Exec & Attributes
			
				attr.load = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				attr.exec = (*(data+10)) + (*(data+11) << 8) + (*(data+12) << 16) + (*(data+13) << 24);
				attr.perm = fsop_perm_from_acorn(f->server, *(data+14));

				// If it's a directory whose attributes we're setting, add in WR/r if no attributes are specified

				if (((*(data+14) & 0x0F) == 0))
				{
					if (p.ftype == FS_FTYPE_DIR)
						attr.perm |= FS_CONF_DEFAULT_DIR_PERM(f->server);
					else	attr.perm |= FS_CONF_DEFAULT_FILE_PERM(f->server);
				}

				// It would appear RISC PCs will send Acorn attrib &05 (r/r) when the user selects WR/r

				if ((p.ftype == FS_FTYPE_DIR)) // It would appear Owner Write and World Read are always implied on dirs from RISC OS
					attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;

				break;
			
			case 2: // Set load address
				attr.load = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				break;

			case 3: // Set exec address
				attr.exec = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				break;
	
			case 4: // Set attributes only

				attr.perm = fsop_perm_from_acorn(f->server, *(data+6));

				// If it's a directory whose attributes we're setting, add in WR/r if no attributes are specified

				if (((*(data+6) & 0x0F) == 0))
				{
					if (p.ftype == FS_FTYPE_DIR)
						attr.perm |= FS_CONF_DEFAULT_DIR_PERM(server);
					else	attr.perm |= FS_CONF_DEFAULT_FILE_PERM(server);
				}

				if ((p.ftype == FS_FTYPE_DIR)) // It would appear Owner Write and World Read are always implied on dirs from RISC OS
					attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;

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

		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d, writing to path %s, owner %04X, perm %02X, load %08X, exec %08X, homeof %04X", "", f->net, f->stn, path, relative_to == a->root ? "Root" : relative_to == a->lib ? "Library" : "Current", command, p.unixpath, attr.owner, attr.perm, attr.load, attr.exec, attr.homeof);

		fs_write_xattr(p.unixpath, attr.owner, attr.perm, attr.load, attr.exec, attr.homeof, f);

		// If we get here, we need to send the reply

		fsop_aun_send(&r, 2, f);

	}
}
#endif

int fs_scandir_regex(const struct dirent *d)
{

	return (((strcasecmp(d->d_name, "lost+found") == 0) || (strcasecmp(d->d_name, ".") == 0) || (strcasecmp(d->d_name, "..") == 0) || (strcasecmp(d->d_name, "lost+found") == 0) || (regexec(&r_wildcard, d->d_name, 0, NULL, 0) != 0)) ? 0 : 1); // regexec returns 0 on match, so we need to return 0 (no match) if it returns other than 0.

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

int16_t fsop_get_acorn_entries(struct fsop_data *f, unsigned char *unixpath)
{

	int16_t entries;

	unsigned char regex[1024];

	struct dirent **list;

	if (f->server->config->fs_infcolon)
		sprintf(regex, "^(%s{1,%d})", FSDOTREGEX, ECONET_MAX_FILENAME_LENGTH);
	else
		sprintf(regex, "^(%s{1,%d})", FSREGEX, ECONET_MAX_FILENAME_LENGTH);

	if (regcomp(&r_wildcard, regex, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) // We go extended expression, case insensitive and we aren't bothered about finding *where* the matches are in the string
		return -1; // Regex failure!

	entries = scandir(unixpath, &list, fs_scandir_regex, fs_alphacasesort);

	//fs_debug (0, 3, "%12s            fs_get_acorn_entries(%d, %d, %s) = %d", "", server, active_id, unixpath, entries);

	if (entries == -1) // Failure
		return -1;

	fs_free_dirent(list, entries); // De-malloc everything

	regfree (&r_wildcard);

	return entries;

}


#if 0
/* Moved to new infrastructure */
void fs_get_object_info(struct fsop_data *f)
{

	FS_REPLY_DATA(0x80);

	unsigned short replylen = 0, relative_to;
	unsigned short command;
	unsigned short norm_return;
	char path[1024];
	struct path p;
	unsigned char *data = f->data; /* Saves time */

	command = FSOP_ARG;
	relative_to = FSOP_CWD;

	memset(reply.p.data, 0, 30);

	// Use replylen as a temporary counter

	while (replylen < 1024 && *(data+(command != 3 ? 6 : 10)+replylen) != 0x0d)
	{
		path[replylen] = *(data+(command != 3 ? 6 : 10)+replylen);
		replylen++;
	}

	path[replylen] = '\0'; // Null terminate instead of 0x0d in the packet

	fs_debug (0, 2, "%12sfrom %3d.%3d Get Object Info %s relative to %02X, command %d", "", f->net, f->stn, path, relative_to, command);

	norm_return = fsop_normalize_path_wildcard(f, path, relative_to, &p, 1);

	fs_free_wildcard_list(&p); // Not interested in anything but first entry, which will be in main struct

	if (!norm_return && (p.error != FS_PATH_ERR_NODIR))
	{
		fsop_error(f, 0xcc, "Bad filename");
		return;
	}

	if ((!norm_return && p.error == FS_PATH_ERR_NODIR) || (/* norm_return && */ p.ftype == FS_FTYPE_NOTFOUND))
	{
		FS_REPLY_DATA(0x80);

		if (command == 6) // Longer error block
		{
			fsop_error(f, 0xd6, "Not found");
		}
		else
		{
			reply.p.data[2] = 0; // not found.
			fsop_aun_send(&reply, 3, f); // This will return a single byte of &00, which from the MDFS spec means 'not found' for arg = 1-5. 6 returns a hard error it seems.
		}
		return;

	}

	/* Prevent reading a dir we cannot read */

	if (p.ftype == FS_FTYPE_DIR && !((FS_PERM_EFFOWNER(f->active, p.owner) && (p.perm & FS_PERM_OWN_R)) || (p.perm & FS_PERM_OTH_R) || FS_ACTIVE_SYST(f->active)))
	{
		fsop_error(f, 0xbc, "Insufficient access");
		return;
	}

	replylen = 0; // Reset after temporary use above

	reply.p.data[replylen++] = 0;
	reply.p.data[replylen++] = 0;
	reply.p.data[replylen++] = p.ftype;

	if (command == 2 || command == 5 || command == 96)
	{
		reply.p.data[replylen++] = (p.load & 0xff);
		reply.p.data[replylen++] = (p.load & 0xff00) >> 8;
		reply.p.data[replylen++] = (p.load & 0xff0000) >> 16;
		reply.p.data[replylen++] = (p.load & 0xff000000) >> 24;
		reply.p.data[replylen++] = (p.exec & 0xff);
		reply.p.data[replylen++] = (p.exec & 0xff00) >> 8;
		reply.p.data[replylen++] = (p.exec & 0xff0000) >> 16;
		reply.p.data[replylen++] = (p.exec & 0xff000000) >> 24;
	}

	if (command == 3 || command == 5 || command == 96)
	{
		reply.p.data[replylen++] = (p.length & 0xff);
		reply.p.data[replylen++] = (p.length & 0xff00) >> 8;
		reply.p.data[replylen++] = (p.length & 0xff0000) >> 16;
	}

	if (command == 4 || command == 5 || command == 96)
	{
		reply.p.data[replylen++] = fsop_perm_to_acorn(f->server, p.perm, p.ftype);
	}

	if (command == 1 || command == 5 || command == 96)
	{
		reply.p.data[replylen++] = p.day;
		reply.p.data[replylen++] = p.monthyear;
	}

	if (command == 4 || command == 5 || command == 96) // arg 4 doesn't request ownership - but the RISC OS PRM says it does, so we'll put this back
		reply.p.data[replylen++] = ((FS_ACTIVE_UID(f->active) == p.owner) || FS_ACTIVE_SYST(f->active)) ? 0x00 : 0xff; 

	if (command == 6)
	{
		
		// unsigned char hr_fmt_string[10];

		if (p.ftype != FS_FTYPE_DIR)
		{
			fsop_error(f, 0xAF, "Types don't match");
			return;
		}

		reply.p.data[replylen++] = 0; // Undefined on this command
		reply.p.data[replylen++] = 10; // Dir name length - Sounds like FSOp 18cmd6 can only take 10 characters

		memset ((char *) &(reply.p.data[replylen]), 32, ECONET_MAX_FILENAME_LENGTH); // Pre-fill with spaces in case this is the root dir
	
		if (p.npath == 0) // Root
		{
			strncpy((char * ) &(reply.p.data[replylen]), (const char * ) "$         ", 11);
		}
		else
		{
			unsigned char	shortname[11];

			memcpy(shortname, p.acornname, 10);
			shortname[10] = '\0';

			snprintf(&(reply.p.data[replylen]), 11, "%-10s", (const char * ) shortname);
		}

		replylen += 10;

		reply.p.data[replylen++] = (f->userid == p.owner) ? 0x00 : 0xff; 

		reply.p.data[replylen++] = fsop_get_acorn_entries(f, p.unixpath); // Number of directory entries

	}

	if (command == 64) // SJ Research function
	{

		if (!(f->server->config->fs_sjfunc))
		{
			fsop_error(f, 0xff, "Not enabled");
			return;
		}

		// Create date. (File type done for all replies above)
		reply.p.data[replylen++] = p.c_day;
		reply.p.data[replylen++] = p.c_monthyear;
		reply.p.data[replylen++] = p.c_hour;
		reply.p.data[replylen++] = p.c_min;
		reply.p.data[replylen++] = p.c_sec;

		// Modification date / time
		reply.p.data[replylen++] = p.day;
		reply.p.data[replylen++] = p.monthyear;
		reply.p.data[replylen++] = p.hour;
		reply.p.data[replylen++] = p.min;
		reply.p.data[replylen++] = p.sec;

	}

	if (command == 65) // Not yet implemented
	{
		fsop_error(f, 0x85, "FS Error");
		return;
	}

	if (command == 96) // PiFS canonicalize object name function
	{
		memcpy(&(reply.p.data[replylen]), p.acornfullpath, strlen(p.acornfullpath));
		reply.p.data[replylen+strlen(p.acornfullpath)] = '.';
		memcpy(&(reply.p.data[replylen+strlen(p.acornfullpath)+1]), p.acornname, strlen(p.acornname));
		reply.p.data[replylen+strlen(p.acornfullpath)+strlen(p.acornname)+1] = 0x0D;
		replylen += strlen(p.acornfullpath) + 1 + strlen(p.acornname) + 1;
	}

	fsop_aun_send(&reply, replylen, f);
		
}

// Save file
void fs_save(struct fsop_data *f)
{

	FS_R_DATA(0x80);

	unsigned char 	*data = f->data; /* Just convenient - don't have to change them all to f->data! */
	unsigned char 	incoming_port, ack_port;
	uint32_t	load, exec, length;
	uint8_t 	create_only;
	char 		filename[1024];

	create_only = (*(data+1) == 0x1d ? 1 : 0); // Function 29 just creates a file of the requisite length - no data transfer phase.

	ack_port = *(data+2);	
	
	// Anyone know what the bytes at data+3, 4 are?

	fs_copy_to_cr(filename, data+16, 1023);

	load = 	(*(data+5)) + ((*(data+6)) << 8) + ((*(data+7)) << 16) + ((*(data+8)) << 24);

	exec = 	(*(data+9)) + ((*(data+10)) << 8) + ((*(data+11)) << 16) + ((*(data+12)) << 24);
	
	length = (*(data+13)) + ((*(data+14)) << 8) + ((*(data+15)) << 16);

	fs_debug (0, 1, "%12sfrom %3d.%3d %s %s %08lx %08lx %06lx", "", f->net, f->stn, (create_only ? "CREATE" : "SAVE"), filename, load, exec, length);

	if (create_only || (incoming_port = fsop_find_bulk_port(f->server)))
	{
		struct path p;

		if (fsop_normalize_path(f, filename, f->active->current, &p))
		{
			// Path found
	
			if (p.ftype == FS_FTYPE_FILE && p.perm & FS_PERM_L) // Locked - cannot write
			{
				fsop_error(f, 0xC0, "Entry Locked");
			}
			else if (p.ftype == FS_FTYPE_DIR)
				fsop_error(f, 0xFF, "Wrong object type");
			else if (p.ftype != FS_FTYPE_FILE && p.ftype != FS_FTYPE_NOTFOUND) // Not a file!
				fsop_error(f, 0xBD, "Insufficient access");
			else
			{
				if (	((p.ftype != FS_FTYPE_NOTFOUND) && (p.my_perm & FS_PERM_OWN_W)) || 
					(
						p.ftype == FS_FTYPE_NOTFOUND && 
						(	(	FS_PERM_EFFOWNER(f->active, p.parent_owner) // Owner & SYST can always write to a parent directory - at least for now - stuffs up RISC OS otherwise.
							) ||
							(p.parent_perm & FS_PERM_OTH_W)
						)
					)
					|| FS_ACTIVE_SYST(f->active)
				)
				{
					struct __fs_file 	*internal_handle;
					int8_t			err;

					// Can write to it one way or another
		
					// Use interlock function here
					internal_handle = fsop_open_interlock(f, p.unixpath, 3, &err, 0);

					if (err == -3)
						fsop_error(f, 0xC0, "Too many open files");
					else if (err == -2)
						fsop_error(f, 0xc2, "Already open"); // Interlock failure
					else if (err == -1)
						fsop_error(f, 0xFF, "FS Error"); // File didn't open when it should
					else
					{

						uint16_t perm;

						perm = FS_PERM_PRESERVE;

						if (create_only)
							perm = FS_CONF_DEFAULT_FILE_PERM(f->server);

						fs_write_xattr(p.unixpath, f->userid, perm, load, exec, 0, f);  // homeof = 0 because it's a file

						r.p.ctrl = f->ctrl; // Copy from request
						r.p.data[2] = incoming_port;
						r.p.data[3] = (1280 & 0xff); // maximum tx size
						r.p.data[4] = (1280 & 0xff00) >> 8;
				
						if (!create_only) fsop_aun_send (&r, 5, f);
						else
						{
							// Write 'length' bytes of garbage to the file (probably nulls)

							ftruncate(fileno(internal_handle->handle), length);
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
							}	
								
							fsop_close_interlock(f, internal_handle, 3);

							r.p.ctrl = f->ctrl;
							r.p.data[2] = fsop_perm_to_acorn(f->server, FS_CONF_DEFAULT_FILE_PERM(f->server), FS_FTYPE_FILE);
							r.p.data[3] = day;
							r.p.data[4] = monthyear;

							fsop_aun_send (&r, 5, f);
						}
						else
						{

							struct __fs_bulk_port	*bp;

							/* We are required to make up the struct and put it in the list */

							FS_LIST_MAKENEW(struct __fs_bulk_port,f->server->bulkports,1,bp,"FS","Allocate new bulk port structure");
							bp->bulkport = incoming_port;
							bp->handle = internal_handle;
							bp->active = f->active;
							bp->ack_port = ack_port;
							bp->length = length;
							bp->received = 0; /* Initialie */
							bp->rx_ctrl = f->ctrl;
							bp->mode = 3;
							bp->is_gbpb = 0;
							bp->user_handle = 0; // Rogue for no user handle, because never hand out user handle 0. This stops the bulk transfer routine trying to increment a cursor on a user handle which doesn't exist.
							strncpy(bp->acornname, p.acornname, 12);
							bp->last_receive = (unsigned long long) time(NULL);
						}
					}
				}
				else
		  		{
					fs_debug (0, 2, "%12sfrom %3d.%3d %s %s ftype=%02X, parent_perm=%02X, my_perm=%02X, parent_owner=%04X, uid=%04X", "", f->net, f->stn, (create_only ? "CREATE" : "SAVE"), filename, p.ftype, p.parent_perm, p.my_perm, p.parent_owner, f->userid);
				        fsop_error(f, 0xBD, "Insufficient access");
			 	}


			}

		}
		else fsop_error(f, 0xCC, "Bad path");
	}
	else
		fsop_error(f, 0xC0, "Too many open files");
	
	
}

/* Moved to new structure */
/* This is probably best moved stright to the fsop/ folder - can easily be re-written to be far shorter */

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

	if ((!(FS_ACTIVE_SYST(server, active_id))) && (ptr_owner != 0)) // Ordinary user tring to change ownership to someone other than themselves
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
			fs_error(server, reply_port, net, stn, 0xC3, "Entry Locked");
			return;
		}

		if (
			!(FS_ACTIVE_SYST(server, active_id)) &&
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
#endif

// Is a file open for reading or writing?
// This is the Econet locking mechanism.
// If >0 readers, can't open for writing.
// If a writer, can't open for reading.
// Supply the request type 1 for reading, 2 for writing (or deleting, renaming, etc.), 3 for writing and trucate
// Returns -3 for too many files, -1 for file didn't exist when it should or can't open, or internal handle for OK. This will also attempt to open the file 
// -2 = interlock failure
// The path is a unix path - we look it up in the tables of file handles
struct __fs_file * fsop_open_interlock(struct fsop_data *f, unsigned char *path, uint8_t mode, int8_t *err, uint8_t dir)
{

	struct __fs_file	*file;

	*err = 0; /* initialize */

	fs_debug_full (0, 2, f->server, f->net, f->stn, "Interlock attempting to open path %s, mode %d, userid %04X", path, mode, f->userid);

	file = f->server->files;

	while (file)
	{
		if (!strcmp(file->name, path)) // Handle check ensures this is an active entry
		{
			if (mode >= 2) // We want write
			{
				// If there is an active entry, someone must be reading or writing, so we can't write.
				
				*err = -2;
				return NULL;
			}
			else
				if (file->writers == 0) // We can open this existing handle for reading
				{
					file->readers++;
					fs_debug_full (0, 2, f->server, f->net, f->stn, "Interlock opened internal dup handle, mode %d. Readers = %d, Writers = %d, path %s", mode, file->readers, file->writers, file->name);
					return file; // Return the index into fs_files
				}
				else // We can't open for reading because someone else has it open for writing
				{
					*err = -2;
					return NULL;
				}
		}
		else 	file = file->next;
	}

	// If we've got here, then there is no existing handle for *path. Create one

	FS_LIST_MAKENEW(struct __fs_file,f->server->files,1,file,"FS","New internal file descriptor struct");

	file->handle = fopen(path, (mode == 1 ? "r" : (mode == 2 ? "r+" : "w+"))); // These correspond to OPENIN, OPENUP and OPENOUT. OPENUP can only be used if the file exists, so this line fails if it doesn't. Whereas w+ == OPENOUT, which can create a file.

	if (!file->handle) /* Can't open */
	{
		*err = -1;
		return NULL;
	}
	
	strcpy(file->name, path);

	file->readers = file->writers = 0;

	if (mode == 1)	file->readers = 1;
	else		file->writers = 1;

	if (mode == 3) // Take ownereship on OPENOUT
	{
		// 20240516 - modified - line below preserves existing permissions fs_write_xattr(path, userid, FS_PERM_OWN_W | FS_PERM_OWN_R, 0, 0, 0, server);
		fsop_write_xattr(path, f->userid, FS_PERM_PRESERVE, 0, 0, 0, f);
	}
	
	fs_debug_full (0, 2, f->server, f->net, f->stn, "Interlock opened internal handle: mode %d. Readers = %d, Writers = %d, path %s", mode, file->readers, file->writers, file->name);
	return file;

}

// Reduces the reader/writer count by 1 and, if both are 0, closes the file handle
// Note, this is different to open_interlock because it takes a server struct. 
// That's because it may be called by the load dequeuer dump function
void fsop_close_interlock(struct __fs_station *s, struct __fs_file * file, uint8_t mode)
{
	if (mode == 1) // Reader close
		file->readers--;
	else	file->writers--;

	fs_debug (0, 2, "%12s Interlock close internal handle: mode %d. Readers now = %d, Writers now = %d, path %s", "", mode, file->readers, file->writers, file->name);

	// Safety valve here - only close when both are 0, not <= 0
	// Otherwise we sometimes overclose - e.g. in the fs_garbage_collect() routine
	
	if (file->readers == 0 && file->writers == 0)
	{
		fs_debug (0, 2, "%12s Interlock closing internal handle for %s in operating system", "", file->name);
		fclose(file->handle);
		FS_LIST_SPLICEFREE(s->files,file,"FS","Freeing internal file structure");
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

#if 0
/* Moved to new structure */
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

		fsop_read_xattr(e->unixpath, &a, server);

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
	int	discno;
	int userid;
	char tmppath[1024], tmppath2[1024];
	int internal_root_handle, internal_cur_handle, internal_lib_handle;
	unsigned char home_dir[100], lib_dir[100];

	struct __econet_packet_udp r;

	fs_copy_to_cr(discname, command, 19);

	discno = fs_get_discno(server, discname);
	userid = FS_ACTIVE_UID(server, active_id);

	fprintf (stderr, "SDISC - discno %d, userid %d, visible %d\n", discno, userid, FS_DISC_VIS(server, userid, discno));

	if ((discno < 0) || !FS_DISC_VIS(server, userid, discno))
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad disc name");
		return;
	}

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

	strcpy (active[server][active_id].urd_unix_path, p_root.unixpath); // Used in order to enable chroot functionality

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

	if ((users[server][active[server][active_id].userid].priv2 & FS_PRIV2_CHROOT) && (p_root.disc == users[server][active[server][active_id].userid].home_disc)) // Fudge the root directory information so that $ maps to URD
	{
		char *dollar;

		sprintf(active[server][active_id].root_dir_tail, "$         ");
		snprintf(active[server][active_id].root_dir, 2600, "$.");
		fs_store_tail_path(active[server][active_id].fhandles[root].acorntailpath, "$");
		dollar = strchr(active[server][active_id].fhandles[root].acornfullpath, '$');

		*(dollar+1) = 0; // Drop everything after the '.' after the dollar sign

		strcpy(active[server][active_id].current_dir_tail, active[server][active_id].root_dir_tail);
		strcpy(active[server][active_id].current_dir, active[server][active_id].root_dir);
		fs_store_tail_path(active[server][active_id].fhandles[cur].acorntailpath, "$");
		strcpy(active[server][active_id].fhandles[cur].acornfullpath, active[server][active_id].fhandles[root].acornfullpath);

	}

				// Next, Library

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

	if (p_from.perm & FS_PERM_L) // Source locked
	{
		fs_error(server, reply_port, net, stn, 0xC3, "Entry Locked");
		return;
	}
	
	if ((p_from.owner != active[server][active_id].userid) && (p_from.parent_owner != active[server][active_id].userid) && (!FS_ACTIVE_SYST(server, active_id)))
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

	if ((p_to.ftype == FS_FTYPE_NOTFOUND) && p_to.parent_owner != active[server][active_id].userid && ((p_to.parent_perm & FS_PERM_OTH_W) == 0) && (!FS_ACTIVE_SYST(server, active_id))) // Attempt to move to a directory we don't own and don't have write access to
	{
		fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
		return;
	}

	if ((p_to.ftype != FS_FTYPE_NOTFOUND && p_to.owner != active[server][active_id].userid && (!FS_ACTIVE_SYST(server, active_id)))) // Destination exists (so must be dir), not owned by us, and we're not system
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

	//if (syscall(SYS_renameat2, 0, p_from.unixpath, 0, p_to.unixpath, RENAME_NOREPLACE)) // non-zero - failure
	if (syscall(SYS_renameat2, 0, p_from.unixpath, 0, p_to.unixpath, 0)) // non-zero - failure - 0 instead of NOREPLACE is fine because we catch existent destination files above - only risk is someone mucking with the filesystem within Linux, which frankly makes them their own worst enemy
	{
		fs_debug (0, 1, "%12sfrom %3d.%3d Rename from %s to %s failed (%s)", "", net, stn, p_from.unixpath, p_to.unixpath, strerror(errno));	
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

	fs_debug (0, 1, "%12sfrom %3d.%3d Delete %s", "", net, stn, path);	

	if (strlen(path) == 0)
		fs_error(server, reply_port, net, stn, 0xfe, "Bad command");
	else if (!fs_normalize_path_wildcard(server, active_id, path, relative_to, &p, 1))
		fs_error(server, reply_port, net, stn, 0xd6, "Not found");
	else if (!(p.paths))
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
				fs_error(server, reply_port, net, stn, 0xC3, "Entry Locked");
				return;
			}
			else if (
					!(	(FS_ACTIVE_SYST(server, active_id)) || (e->owner == active[server][active_id].userid) || ((e->parent_owner == active[server][active_id].userid) && (e->parent_perm & FS_PERM_OWN_W))
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
		else if ((p.parent_owner == active[server][active_id].userid && (p.parent_perm & FS_PERM_OWN_W)) || FS_ACTIVE_SYST(server, active_id)) // Must own the parent and have write access, or be system
		{
			if (!mkdir((const char *) p.unixpath, 0770))
			{
				fs_write_xattr(p.unixpath, active[server][active_id].userid, FS_CONF_DEFAULT_DIR_PERM(server), 0, 0, 0, server);
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
			uint8_t		is_owner = 0;

			is_owner = FS_PERM_EFFOWNER(server, active_id, p.owner);

			//fprintf (stderr, "%s is_owner = %d\n", p.acornname, is_owner);

			strcpy(permstring, "");
		
			if (fs_config[server].fs_mask_dir_wrr && p.ftype == FS_FTYPE_DIR && (p.perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
				p.perm &= ~(FS_ACORN_DIR_MASK);

			if (p.perm & FS_PERM_L) strcat (permstring, "L");
			if (p.perm & FS_PERM_OWN_W) strcat (permstring, (is_owner ? "W" : fs_config[server].fs_mdfsinfo ? "w" : "W"));
			if (p.perm & FS_PERM_OWN_R) strcat (permstring, (is_owner ? "R" : fs_config[server].fs_mdfsinfo ? "r" : "R"));
			strcat (permstring, "/");
			if (p.perm & FS_PERM_OTH_W) strcat (permstring, (fs_config[server].fs_mdfsinfo ? (is_owner ? "w" : "W") : "W"));
			if (p.perm & FS_PERM_OTH_R) strcat (permstring, (fs_config[server].fs_mdfsinfo ? (is_owner ? "r" : "R") : "R"));

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
		{
			// 20240520 Changed
			//perm = FS_PERM_OWN_R | FS_PERM_OWN_W | FS_PERM_OTH_R;
			strcpy (perm_str, "");
		}
		else
		{
			fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
			return;
		}	
	}

	// 20240520 Removed from main if()
	//else
	{

		perm = 0;
		ptr = 0;

		while (ptr < strlen((const char *) perm_str) && perm_str[ptr] != '/')
		{
			switch (perm_str[ptr])
			{
				case 'w': case 'W': perm |= FS_PERM_OWN_W; break;
				case 'r': case 'R': perm |= FS_PERM_OWN_R; break;
				case 'p': case 'P': perm |= FS_PERM_H; break; // Alternative to H for hidden
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
		if (e->owner == active[server][active_id].userid || (e->parent_owner == active[server][active_id].userid && (e->parent_perm & FS_PERM_OWN_W)) || FS_ACTIVE_SYST(server, active_id)) // Must own the file, own the parent and have write access, or be system
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
		uint8_t		internal_perm;

		internal_perm = perm;

		if (e->ftype == FS_FTYPE_DIR && (perm & (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R | FS_PERM_OTH_W)) == 0)
			internal_perm |= FS_CONF_DEFAULT_DIR_PERM(server);

		fs_write_xattr(e->unixpath, e->owner, internal_perm, e->load, e->exec, e->homeof, server); // 'perm' because that's the *new* permission
		e = e->next;
	
	}

	fs_free_wildcard_list(&p); // Free up the mallocs

	// Give the station the thumbs up

	fs_reply_success(server, reply_port, net, stn, 0, 0);
}

// Moved to new structure
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
	int	userid;

	r.p.port = reply_port;
	r.p.ctrl = 0x80;
	r.p.ptype = ECONET_AUN_DATA;

	r.p.data[0] = 10;
	r.p.data[1] = 0;
	
	userid = FS_ACTIVE_UID(server,active_id);

	fs_debug (0, 2, "%12sfrom %3d.%3d Read Discs from %d (up to %d)", "", net, stn, start, number);

	disc_ptr = start;

	if (disc_ptr < ECONET_MAX_FS_DISCS) // See if there are any to insert
	{
		while (disc_ptr < ECONET_MAX_FS_DISCS && (delivered < number))
		{
			if ((fs_discs[server][disc_ptr].name[0] != '\0') && FS_DISC_VIS(server,userid,disc_ptr))
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

	while (active_ptr < ECONET_MAX_FS_ACTIVE && found < start)
	{
		if ((active[server][active_ptr].net != 0 || active[server][active_ptr].stn != 0) && ((users[server][FS_ACTIVE_UID(server,active_id)].priv2 & FS_PRIV2_HIDEOTHERS) == 0 || (active[server][active_ptr].net == net && active[server][active_ptr].stn == stn)))
			found++;
		active_ptr++;
	}

	if (active_ptr < ECONET_MAX_FS_ACTIVE) // We've found the first one the station wants
	{
		int deliver_count = 0;

		while (active_ptr < ECONET_MAX_FS_ACTIVE && deliver_count < number)
		{
			if (
					(active[server][active_ptr].net != 0 || active[server][active_ptr].stn != 0)
				&&	(
						((users[server][FS_ACTIVE_UID(server,active_id)].priv2 & FS_PRIV2_HIDEOTHERS) == 0)
					||	(active[server][active_ptr].net == net && active[server][active_ptr].stn == stn)
					)
			   )
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

	while (count < ECONET_MAX_FS_ACTIVE)
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
	
	if (count == ECONET_MAX_FS_ACTIVE)
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
		else if ((p.my_perm & FS_PERM_OWN_R) || FS_ACTIVE_SYST(server,active_id))
		{
			r.p.ptype = ECONET_AUN_DATA;
			r.p.port = reply_port;
			r.p.ctrl = 0x80;
			r.p.data[0] = r.p.data[1] = 0;

// MDFS manual has 10 character path, but Acorn traffic shows pad to 11! Similarly, disc name should be 15 but Acorn traffic has 16.
			sprintf((char * ) &(r.p.data[2]), "%-11s%c   %-16s%c%c", (char *) (p.npath == 0 ? "$" : (char *) p.path[p.npath-1]),
				FS_PERM_EFFOWNER(server, active_id, p.owner) ? 'O' : 'P',
				//(p.owner == active[server][active_id].userid ? 'O' : 'P'),
				fs_discs[server][active[server][active_id].current_disc].name,
				0x0d, 0x80);
	
			fs_aun_send(&r, server, 35, net, stn);	 // would be length 33 if Acorn server was within spec...
		}
		else	fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");

	}
	
}
#endif

// Load queue enque, deque functions

// load enqueue. net, stn are destinations. server parameter is to ensure queue is ordered. p & len are the packet to queue
// Length is data portion length only, so add 8 for the header on a UDP packet, 12 for AUN
// We do the malloc/free inside the enqueue/dequeue routines
//
// server - the FS instance we are creating for
// *p - the packet to go on the queue
// len - data? length of packet
// net, stn - destination host
// internal_handle - file handle we are sending from, in case we need to close it (if this is a load operation not getbytes)
// mode - is file open for reading/writing/both - so we can close the handle properly
// seq - sequence number to trigger next dequeue when we get an ack for that sequence number - set to 0 except on first packet, because
//    the dequeuer sets the sequence number on each packet it sends. This seq is for the packet we sent to the station *before*
//    the first one in the queue. If this is non-zero, it forces the routine to create a new queue just in case the station
//    has somehow managed to do two requests at the same time...
// qtype - 1 = Load (close file at end), 2 = getbytes (leave it open)
//
// RETURNS:
// -1 Failure - malloc
// 1 Success

/* Moved to fs.h */
#if 0
#define FS_ENQUEUE_LOAD 1
#define FS_ENQUEUE_GETBYTES 2
#endif

struct load_queue * fsop_load_enqueue(struct fsop_data *f, struct __econet_packet_udp *p, uint16_t len, struct __fs_file *h, uint8_t mode, uint32_t seq, uint8_t qtype, uint16_t delay)
{

	struct __econet_packet_udp *u; // Packet we'll put into the queue
	struct __pq *q; // Queue entry within a host
	struct load_queue *l, *l_parent, *n; // l_ used for searching, n is a new entry if we need one
	struct __fs_active *a;

	a = f->active;

	fs_debug (0, 3, "to %3d.%3d              Enqueue packet length %04X type %02X", f->net, f->stn, len, p->p.ptype);

	u = malloc(len + 8);
	memcpy(u, p, len + 8); // Copy the packet data off

	q = malloc(sizeof(struct __pq)); // Make a new packet entry

	if (!u || !q) return NULL;

	//fs_debug (0, 2, "malloc() and copy succeeded");

	// First, see if there is an existing queue entry for this server to this destination, to which we will add the packet.
	// If there is, there is no need to build a new load_queue entry.

	l = f->server->fs_load_queue;
	l_parent = NULL;

	// Find a queue for destination network

	while (l && (l->active != a))
	{
		l_parent = l;
		l = l->next;
	}

	if (seq || !l || l->active != a) // No entry found - make a new one
	{

		// Make a new load queue entry

		fs_debug (0, 4, "Making new packet queue entry for this net/stn tuple");

		n = malloc(sizeof(struct load_queue));

		if (!n)
		{
			free (u); free (q); return NULL;
		}

		fs_debug (0, 4, " - at %p ", n);

		n->active = a;
		// No longer required - one queue per server: n->server = server;
		n->queue_type = qtype; // See defines above
		n->mode = mode;
		n->internal_handle = h;
		n->ack_seq_trigger = seq;
		n->last_ack_rx = time(NULL); // Now
		n->pq_head = NULL;
		n->pq_tail = NULL;
		n->server = f->server; // Upward link
		n->next = NULL; // Applies whether there was no list at all, or we fell off the end of it. We'll fix it below if we're inserting

		fs_debug (0, 3, " - new fs_load_queue = %p, l = %p ", f->server->fs_load_queue, l);

		if (!f->server->fs_load_queue) // There was no queue at all
		{
			fs_debug (0, 4, " - as a new fs_load_queue");
			f->server->fs_load_queue = n;
		}
		else // We are inserting, possibly at the end
		{
			if (!l) // We fell off the end
			{
				fs_debug (0, 3, " - on the end of the existing queue");
				l_parent->next = n;
			}
			else // Inserting in the middle or at queue head
			{
				if (!l_parent)
				{
					n->next = f->server->fs_load_queue;
					fs_debug (0, 3, " - by inserting at queue head");
					f->server->fs_load_queue = n;
					
				}
				else
				{
					fs_debug (0, 3, " - by splice at %p", l_parent->next);
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
	q->delay = delay; // Delay in ms before TX when asked
	q->server = f->server; // Upward link to server for when we transmit
	q->next = NULL; // Always adding to end

	if (!(n->pq_head)) // No existing packet in the queue for this transaction
		n->pq_head = n->pq_tail = q;
	else // Add to end
	{
		n->pq_tail->next = q;
		n->pq_tail = q;
	}

	fs_debug (0, 3, "Queue state for %3d.%3d to %3d.%3d trigger seq %08X: Load queue head at %p", f->server->net, f->server->stn, f->net, f->stn, n->ack_seq_trigger , n);
	q = n->pq_head;

	while (q)
	{
		fs_debug (0, 3, "         Packet length %04X at %p, next at %p", q->len, q, q->next);
		q = q->next;
	}

	return n;

}

// fs_enqueue_dump - dump a load queue entry and update the table as necessary
void fsop_enqueue_dump(struct load_queue *l)
{

	struct load_queue *h, *h_parent;
	struct __pq *p, *p_next;

	h = l->server->fs_load_queue;
	h_parent = NULL;

	if (l->queue_type == FS_ENQUEUE_LOAD) // *LOAD operation
		fsop_close_interlock(l->server, l->internal_handle, l->mode); // Mode should always be one in this instance

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
			fs_debug (0, 3, "Freeing bulk transfer packet at %p", p->packet);
			free (p->packet); // Check it is not null, just in case...
		}
		fs_debug (0, 3, "Freeing bulk transfer queue entry at %p", p);
		free(p);
		p = p_next;

	}
	
	/* TODO: PROBABLY CHANGE THIS TO SPLICEFREE IN THE FUTURE */

	if (h_parent) // Mid chain, not at start
	{
		fs_debug (0, 3, "Freed structure was not at head of chain. Spliced between %p and %p", h_parent, h->next);
		h_parent->next = h->next; // Drop this one out of the chain
	}
	else
	{
		fs_debug (0, 3, "Freed structure was at head of chain. fs_load_queue now %p", h->next);
		l->server->fs_load_queue = h->next; // Drop this one off the beginning of the chain
	}

	fs_debug (0, 3, "Freeing bulk transfer transaction queue head at %p", h);

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

char fsop_load_dequeue(struct __fs_station *s, uint8_t net, uint8_t stn, uint32_t seq)
{

	struct load_queue *l, *l_parent; // Search variable
	uint32_t	new_seq;
	struct __fs_active	*a;

	l = s->fs_load_queue;
	l_parent = NULL;

	fs_debug (0, 3, "to %3d.%3d from %3d.%3d bulk transfer queue head found at %p for trigger sequence %08X", net, stn, s->net, s->stn, l, (l ? l->ack_seq_trigger : 0));


	a = fsop_find_active(s, net, stn);

	if (!a) 	return 0; // This user isn't here!

	while (l && (l->active != a))
	{
		l_parent = l;
		l = l->next;
	}

	if (!l) 	return 0; // Not found

	if (!(l->pq_head)) // There was an entry, but it had no packets in it!
	{
		// Take this one out of the chain
		if (l_parent)
			l_parent->next = l->next;
		else	s->fs_load_queue = l->next;

		free(l);

		return 0;
	}

	if (l->ack_seq_trigger != seq) /* Not what we were waiting for */
		return 0;

	// Insert sequence number
	
	new_seq = eb_get_local_seq(s->fs_device);

	l->pq_head->packet->p.seq = new_seq;

	fs_debug (0, 3, "to %3d.%3d from %3d.%3d Sending packet from __pq %p, length %04X with new sequence number %08X", net, stn, s->net, s->stn, l->pq_head, l->pq_head->len, l->pq_head->packet->p.seq);

	if (l->pq_head->delay)
		usleep (1000 * l->pq_head->delay); // Usually 0, but we have a facility to delay packets because sometimes RISC OS isn't listening...(!) Usually used on first packet of a databurst

	// Send without inserting a sequence number

	if ((raw_fsop_aun_send_noseq(l->pq_head->packet, l->pq_head->len, l->server, l->active->net, l->active->stn) <= 0)) // If this fails, dump the rest of the enqueued traffic
	{
		fs_debug (0, 3, "fs_aun_send() failed in fs_load_sequeue() - dumping rest of queue");
		fsop_enqueue_dump(l); // Also closes file
		return -1;

	}
	else // Tx success - just update the packet queue
	{
		struct __pq *p;
		unsigned char		debug_str_tmp[128];

		p = l->pq_head;

		l->pq_head = l->pq_head->next;
		free(p->packet);
		sprintf (debug_str_tmp, "Packet queue entry freed at %p", p);
		free(p);

		fs_debug (0, 3, debug_str_tmp);

		if (!(l->pq_head)) // Ran out of packets
		{
			fs_debug (0, 3, "End of packet queue - dumping queue head at %p", l);
			l->pq_tail = NULL;
			fsop_enqueue_dump(l);
			return 2;
		}
		else
		{
			// Update sequence number to wait for

			l->ack_seq_trigger = new_seq;

			// Update last rx time
			
			l->last_ack_rx = time(NULL);
		}

	}

	return 1; // Success - but still more packets to come
}

#if 0
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

	uint32_t	sequence; // Used to track the seq number sent to the load enqueuer

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

	if (!((FS_ACTIVE_SYST(server, active_id)) || (p.my_perm & FS_PERM_OWN_R))) // Note: my_perm has all the relevant privilege bits in the bottom 4
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
	r.p.seq = get_local_seq(fs_stations[server].net, fs_stations[server].stn);

	sequence = r.p.seq; // Forces enqueuer to start new queue, and sets up the ack trigger for the packet we are about to send so that when that ACK turns up, we send the first packet in the queue.

	// Use the noseq variant so we can force the load_enqueue routine to start a new queue and trigger on the right sequence number.
	
	if (fs_aun_send_noseq(&r, server, 16, net, stn))
	{
		// Send data burst

		int collected, enqueue_result;

		r.p.ctrl = 0x80;
		r.p.port = data_port;


		fseek (f, 0, SEEK_SET);

		while (!feof(f))
		{
			collected = fread(&(r.p.data), 1, 1280, f);
			
			if (collected > 0) enqueue_result = fs_load_enqueue(server, &r, collected, net, stn, internal_handle, 1, sequence, FS_ENQUEUE_LOAD, 0); else enqueue_result = 0;

			if (collected < 0 || enqueue_result < 0)
			{
				fs_debug (0, 1, "Data burst enqueue failed");
				return; // Failed in some way
			}
	
			sequence = 0; // Set to 0 so that enqueuer doesn't create a new queue.

		}
		
		// Send the tail end packet
	
		r.p.data[0] = r.p.data[1] = 0x00;
		r.p.port = reply_port;
		r.p.ctrl = rxctrl;

		fs_load_enqueue(server, &r, 2, net, stn, internal_handle, 1, sequence, FS_ENQUEUE_LOAD, 0);

	}
	
}


/* This function moved to fsop_08 */
// Determine if received ctrl-byte sequence number is what we were expecting - returns non-zero if it was. 
// Since the rogue (set at file open) is 0x02, we check bottom *two* bits

uint8_t fs_check_seq(uint8_t a, uint8_t b)
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

	/* TODO. Somehow the data sent on IW's system is correct when printed during arg=0 fs_debug, but is corrupted
	 * when transmitted. So when it prints 'data returned 00 08 00', it sends '01 00 00'. Hmm. 
	 */

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

			if ((value > extent) && active[server][active_id].fhandles[handle].mode == 1) // Don't extend if read only!
			{
				fs_error(server, reply_port, net, stn, 0xB9, "Outside file");
				return;
			}

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
			active[server][active_id].fhandles[handle].pasteof = 0; // We have no longer just read the last byte of the file	
			// This didn't seem to work!
			//if (value > extent) r.p.data[1] = 0xC0;
			//if (value == extent) r.p.data[1] = 0x00;
		}
		break;
		case 1: // Set file extent
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d Set file extent on channel %02X to %06lX, current extent %06lX%s", "", net, stn, handle, value, extent, (value > extent) ? " so adding bytes to end of file" : "");

			if (active[server][active_id].fhandles[handle].mode == 1) // Read only - refuse!
			{
				fs_error(server, reply_port, net, stn, 0xC1, "File read only");
				return;
			}
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

	uint32_t	seq;

	struct __econet_packet_udp r;

	txport = *(data+2);
	offsetstatus = *(data+6);
	bytes = (((*(data+7))) + ((*(data+8)) << 8) + (*(data+9) << 16));
	offset = (((*(data+10))) + ((*(data+11)) << 8) + (*(data+12) << 16));

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() %04lX from offset %04lX (%s) by user %04x on handle %02x, ctrl seq is %s (stored: %02X, received: %02X)", "", net, stn, bytes, offset, (offsetstatus ? "ignored - using current ptr" : "being used"), f->userid, handle,
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

	// Set the sequence number so we can trigger on it
	
	seq = get_local_seq(fs_stations[server].net, fs_stations[server].stn);

	r.p.seq = seq;

	fs_aun_send_noseq(&r, server, 2, net, stn);

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

		// Now put them on a load queue
		//fs_aun_send(&r, server, readlen, net, stn);

		fs_load_enqueue(server, &(r), readlen, net, stn, internal_handle, 1, seq, FS_ENQUEUE_GETBYTES, (sent == 0) ? 0 : 0/* 275 : 100 */ ); // Interpacket delay of 200ms didn't work. 300 did. Try 250.  This is purely to cope with RISC OS cocking a deaf'un on the data burst. Probably nobody noticed in the 1990s because hard discs were so slow compared to today. And it looks like we only need it on the first databurst packet.

		seq = 0; // seq != 0 means start a new load queue, so always set to 0 here to add to same queue
		sent += readlen;
		total_received += received;
		
	}

	active[server][active_id].fhandles[handle].cursor += total_received; // And update the cursor
	active[server][active_id].fhandles[handle].sequence = (ctrl & 0x01); // Store this ctrl byte, whether it was right or wrong

	if (eofreached)	active[server][active_id].fhandles[handle].pasteof = 1; // Since we've read the end of the file, make sure getbyte() doesn't offer more data

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

		// Now goes on a load queue
		//fs_aun_send(&r, server, 6, net, stn);
		fs_load_enqueue(server, &(r), 6, net, stn, internal_handle, 1, seq, FS_ENQUEUE_GETBYTES, 0);
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
		/* LOOKS LIKE AN ERROR fs_close_interlock(server, fs_bulk_ports[server][incoming_port].handle, 3); */
		fs_bulk_ports[server][incoming_port].handle = -1; // Make the port available again
		r.p.port = reply_port;
		r.p.ctrl = ctrl;
		r.p.ptype = ECONET_AUN_DATA;
		r.p.data[0] = r.p.data[1] = 0;
		// WRONG - Why are we returning fixed permissions here?
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
				// TODO: Don't close if it's a bulk port handle? Or maybe do because on a CLOSE#0 you'd be closing anything you were trying to do a putbytes on, and *SAVE bulk transfers won't have handles...
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

	if (strlen(filename) == 0)
	{
		fs_error(server, reply_port, net, stn, 0xFF, "Bad filename");
		return;
	}

	fs_debug (0, 2, "%12sfrom %3d.%3d Open %s readonly %s, must exist? %s", "", net, stn, filename, (readonly ? "yes" : "no"), (existingfile ? "yes" : "no"));

	// If the file must exist, then we can use wildcards; else no wildcards
	// BUT we should be able to open a file for writing with wildcards in the path except the tail end
	// Then, below, if the file doesn't exist we barf if the tail has wildcards in it.
	//
	result = fs_normalize_path_wildcard(server, active_id, filename, active[server][active_id].current, &p, 1);

	//fs_debug(0,2, "%12sfrom %3d.%3d Attempt to open %s - p.parent_owner = %d, p.parent_perm = %02X, p.perm = %02X, userid = %d", "", net, stn, filename, p.parent_owner, p.parent_perm, p.perm, active[server][active_id].userid);

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
	else if ((p.ftype == FS_FTYPE_FILE) && !readonly && ((p.perm & FS_PERM_L)))
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xC3, "Entry Locked");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && !readonly && ((p.my_perm & FS_PERM_OWN_W) == 0) && !FS_ACTIVE_SYST(server, active_id))
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xbd, "Insufficient access");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && ((p.my_perm & FS_PERM_OWN_R) == 0) && !FS_ACTIVE_SYST(server, active_id))
	{
		fs_free_wildcard_list(&p);
		fs_error(server, reply_port, net, stn, 0xbd, "Insufficient access");
	}
	else if (!readonly && (p.ftype == FS_FTYPE_NOTFOUND) && !FS_ACTIVE_SYST(server, active_id) &&
		(	(p.parent_owner != active[server][active_id].userid && ((p.parent_perm & FS_PERM_OTH_W) == 0)) ||
			(p.parent_owner == active[server][active_id].userid && ((p.parent_perm & FS_PERM_OWN_W) == 0)) 
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
#endif

int8_t fsop_get_user_printer(struct __fs_active *a)
{
	uint8_t	p;

	pthread_mutex_lock(&(a->server->fs_mutex));
	p = a->printer;
	pthread_mutex_unlock(&(a->server->fs_mutex));

	return p;
}

#if 0
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
void fsop_select_printer(struct fsop_data *f, char *pname)
{

	int printerindex = 0xff;

	printerindex = get_printer(f->server->net, f->server->stn, pname);

	fs_debug (0, 1, "%12sfrom %3d.%3d Select printer %s - %s", "", f->net, f->stn, pname, (printerindex == -1) ? "UNKNOWN" : "Succeeded");

	if (printerindex == -1) // Failed
		fsop_error(f, 0xFF, "Unknown printer");
	else
	{
		f->active->printer = printerindex;
		fsop_reply_ok(f);
	}

}
#endif

// Check if a user exists. Return index into users[server] if it does; -1 if not
int fsop_user_exists(struct __fs_station *s, unsigned char *username)
{
	int count;
	unsigned short found = 0;
	char username_padded[11];

	snprintf(username_padded, 11, "%-10s", username);

	count = 0;

	while (!found && count < ECONET_MAX_FS_USERS)
	{
		if (!strncasecmp((const char *) s->users[count].username, username_padded, 10) && (s->users[count].priv != FS_PRIV_INVALID))
			found = 1;
		else count++;
	}

	if (count == ECONET_MAX_FS_USERS) return -1;
	else return count;
	 
}

// Returns -1 if there are no user slots available, or the slot number if there are
short fsop_find_new_user(struct __fs_station *s)
{

	int count = 0;
	unsigned short found = 0;

	while (!found && count < ECONET_MAX_FS_USERS)
	{
		if (s->users[count].priv == FS_PRIV_INVALID)
			found = 1;
		else count++;
	}

	if (count == ECONET_MAX_FS_USERS) return -1;
	else return count;

}

/*
 * fsop_handle_bulk_traffic()
 *
 * This is a handler routine registered with the HPB
 * when we get & register a bulk port. So it will not have
 * the fs_mutex lock held when called.
 */

void fsop_handle_bulk_traffic(struct __econet_packet_aun *p, uint16_t datalen, void *param)
{

	struct __econet_packet_udp	r;
	struct __fs_bulk_port	*bp;
	struct __fs_station 	*s = (struct __fs_station *) param;

	off_t	 writeable, remaining, old_cursor, new_cursor, new_cursor_read;
	FILE 	*h;

	r.p.ptype = ECONET_AUN_DATA;
	r.p.data[0] = r.p.data[1] = 0;

	// If the server is not enabled, return and ignore the packet
	
	pthread_mutex_lock(&(s->fs_mutex));

	if (!s->enabled)
	{
		pthread_mutex_unlock(&(s->fs_mutex));

		return;
	}

	bp = s->bulkports;

	while (bp && bp->bulkport != p->p.port)
		bp = bp->next;

	if (!bp)
	{
		pthread_mutex_unlock(&(s->fs_mutex));

		return; /* No idea what this traffic is */
	}

	// We can deal with this data
	
	remaining = bp->length - bp->received; /* How much more are we expecting ? */

	writeable = (remaining > datalen ? datalen : remaining);

	h = bp->handle->handle;

	if (bp->is_gbpb) // This is a putbytes transfer not a fs_save; in the latter there is no user handle. Seek to correct point in file
		fseek(h, SEEK_SET, (old_cursor = bp->active->fhandles[bp->user_handle].cursor));

	fwrite(p->p.data, writeable, 1, h);

	fflush(h);

	bp->received += datalen;

	if (bp->is_gbpb) // This is a putbytes transfer not a fs_save; in the latter there is no user handle
	{
		bp->active->fhandles[bp->user_handle].cursor += writeable;
		new_cursor = bp->active->fhandles[bp->user_handle].cursor;
		new_cursor_read = ftell(h);
	}

	fs_debug (0, 2, "%12sfrom %3d.%3d Bulk transfer in on port %02X data length &%04X, expected total length &%04lX, writeable &%04X", "", bp->active->net, bp->active->stn, bp->bulkport, datalen, bp->length, writeable
			);
	if (bp->is_gbpb) // Produce additional debug
		fs_debug (0, 2, "%12sfrom %3d.%3d Bulk trasfer on port %02X old cursor = %06X, new cursor in FS = %06X, new cursor from OS = %06X - %s", "", bp->active->net, bp->active->stn, bp->bulkport, old_cursor, new_cursor, new_cursor_read, (new_cursor == new_cursor_read) ? "CORRECT" : " *** ERROR ***");

	bp->last_receive = (unsigned long long) time(NULL);

	if (bp->received == bp->length) // Finished
	{

		// Send a closing ACK

		struct tm t; 
		unsigned char day, monthyear;
		time_t now;

		now = time(NULL);
		t = *localtime(&now);

		fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);
							
		r.p.port = bp->reply_port;
		r.p.ctrl = bp->rx_ctrl;
		r.p.ptype = ECONET_AUN_DATA;
		r.p.data[0] = r.p.data[1] = 0;

		// 20240404 Insert delay. Looks like some beebs aren't listening for the close packet immediately
		// after sending the last packet in a data burst and then when the bridge eventually 
		// gets to transmit it on retry, they've sent another command and everything goes one
		// packet out of sequence.

		usleep(20000); // Try 20ms to start with.

		if (bp->is_gbpb)
		{
			r.p.data[2] = bp->bulkport;
			r.p.data[3] = bp->received & 0xff;
			r.p.data[4] = (bp->received & 0xff00) >> 8;
			r.p.data[5] = (bp->received & 0xff0000) >> 16;
			r.p.seq = eb_get_local_seq(s->fs_device);
			raw_fsop_aun_send (&r, 6, s, bp->active->net, bp->active->stn);
		}
		else // Was a save
		{
			
			uint8_t counter = 0;

			fsop_close_interlock(s, bp->handle, 3); // We don't close on a putbytes - file stays open!

			r.p.data[0] = 3; // This appears to be what FS3 does!
			r.p.data[2] = fsop_perm_to_acorn(s, FS_CONF_DEFAULT_FILE_PERM(s), FS_FTYPE_FILE);
			r.p.data[3] = day;
			r.p.data[4] = monthyear;

			/* Per @arg's remark from the EcoIPFS - whilst the specs say pad the filename to 12 characters and terminate with &0d,
			   in fact existing servers pad to 12 characters with spaces and terminate it with a negative byte "(plus 3 bytes of
			   junk!)". So we'll try that. */

			memset(&(r.p.data[5]), 32, 15); 

			while (bp->acornname[counter] != 0)
			{
				r.p.data[5+counter] = bp->acornname[counter];
				counter++;
			}

			r.p.data[17] = 0x80;
			// And the 'junk'
			r.p.data[18] = 0x20; r.p.data[19] = 0xA9; r.p.data[20] = 0x24;

			raw_fsop_aun_send (&r, 21, s, bp->active->net, bp->active->stn);
		}

		FS_LIST_SPLICEFREE(s->bulkports, bp, "FS", "Freeing completed bulk port structure");

	}
	else // Send an intermediate ACK.
	{	
		r.p.port = bp->ack_port;
		r.p.ctrl = p->p.ctrl;
		raw_fsop_aun_send (&r, 2, s, bp->active->net, bp->active->stn);
	}

	pthread_mutex_unlock(&(s->fs_mutex));
}

/* Garbage collect stale incoming bulk handles - This is called from the main loop in the bridge code */

void fsop_garbage_collect(struct __fs_station *s)
{

	struct load_queue *l; // Load queue pointer
	struct __fs_bulk_port	*p; // Bulk port pointer

	p = s->bulkports;

	while (p)
	{
		struct __fs_bulk_port *n; /* N(ext) */

		n = p->next;

		if (p->last_receive < ((unsigned long long) time(NULL) - 10)) // 10s and no traffic
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d Garbage collecting stale incoming bulk port %d used %lld seconds ago", "", 
				p->active->net, p->active->stn, p->bulkport, ((unsigned long long) time(NULL) - p->last_receive));

			eb_port_deallocate(s->fs_device, p->bulkport);

			if (!(p->is_gbpb)) /* This was not GBPB but was a *SAVE */
			{
				fsop_close_interlock(s, p->handle, p->mode);
				fsop_deallocate_user_file_channel(p->active, p->user_handle);
			}
			else
			{
				fs_debug (0, 2, "%12sfrom %3d.%3d Garbage collector did not close bulk port %d because it had already closed.", "", p->active->net, p->active->stn, p->bulkport);
			}
			FS_LIST_SPLICEFREE(s->bulkports, p, "FS", "Deallocate bulk port on garbage collect");
		}

		p = n;

	}

	// Next look through our load queues and see if one has gone stale
	
	l = s->fs_load_queue;

	while (l)
	{
		struct load_queue *m;

		m = l->next;

		if (l->last_ack_rx < (time(NULL) - 10)) /* 10s time out on load dequeue */
			fsop_enqueue_dump(l);

		l = m; // Move to next, use stored value in case we dumped the queue
	}

}

// Find any servers this station is logged into and eject them in case the station is dynamically reallocated
// What's this for? Seems to kick a station off every server there is on this system
void fsop_eject_station(struct __fs_station *s, uint8_t net, uint8_t stn)
{

	struct __fs_active *a;

	a = s->actives;

	fs_debug (0, 1, "%12s             Ejecting station %3d.%3d from server at %3d.%3d", "", net, stn, a->server->net, a->server->stn);

	while (a)
	{
		if (a->stn == stn && a->net == net)
		{
			fsop_bye_internal(a, 0, 0); // Silent bye
			break;
		}

		a = a->next;
	}

}

#if 0
/* Not required in new structure */
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

#endif

void fsop_write_readable_config(struct __fs_station *s)
{

	unsigned char	configfile[1024];
	FILE		*out;

	sprintf(configfile, "%s/Configuration.txt", s->directory);

	out = fopen(configfile, "w");

	if (out)
	{
		struct __fs_disc 	*disc;

		fprintf (out, "Fileserver configuration for station %d.%d\n\n", s->net, s->stn);
		fprintf (out, "%-25s %s\n\n", "Root directory", s->directory);
		fprintf (out, "%-25s %d\n", "Total no. of discs", s->total_discs);

		disc = s->discs;

		while (disc)
		{
			fprintf (out, "Disc %2d                   %s\n", disc->index, disc->name);
			disc = disc->next;
		}

		fprintf (out, "\n");

		fprintf (out, "%-25s %-3s\n", "Acorn Home semantics", (s->config->fs_acorn_home ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "SJ Res'ch functions", (s->config->fs_sjfunc ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "Big Chunks", (s->config->fs_bigchunks ? "On" : "Off"));
		fprintf (out, "%-25s %-4s\n", "10 char pw conversion", (s->config->fs_pwtenchar ? "Done" : "No"));
		fprintf (out, "%-25s %-3s\n", "Max filename length", (s->config->fs_fnamelen ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "Inf files are :inf", (s->config->fs_infcolon ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "> 8 file handles", (s->config->fs_manyhandle ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "MDFS-style *INFO", (s->config->fs_mdfsinfo ? "On" : "Off"));
		fprintf (out, "%-25s %-3s\n", "Acornd Directory Display", (s->config->fs_mask_dir_wrr ? "On" : "Off"));

		fclose(out);

	}

}

/* Handle locally arriving fileserver traffic to server #server, from net.stn, ctrl, data, etc. - port will be &99 for FS Op */
void fsop_port99 (struct __fs_station *s, struct __econet_packet_aun *packet, uint16_t datalen)
{

	uint8_t	 	fsop;
	uint8_t		net = packet->p.srcnet, stn = packet->p.srcstn;

	struct fsop_data	fsop_param, *f; 	/* Holds data to pass to our new structured list of fsop handlers */
	struct __fs_active	*active;

	f = &fsop_param;

	// If server disabled, return without doing anything
	
	if (!s->enabled)
		return;

	if (datalen < 1) 
	{
		fs_debug (0, 1, " from %3d.%3d Invalid FS Request with no data", net, stn);
		return;
	}

	active = fsop_stn_logged_in(s, packet->p.srcnet, packet->p.srcstn);

	/* Set up 'param' */

	fsop_param.net = packet->p.srcnet;
	fsop_param.stn = packet->p.srcstn;
	fsop_param.active = active;
	fsop_param.user = active ? &(s->users[active->userid]) : NULL;
	fsop_param.userid = active ? active->userid : 0xFFFF;
	fsop_param.server = s;
	fsop_param.data = &(packet->p.data[0]);
	fsop_param.datalen = datalen - 12;
	fsop_param.port = packet->p.port;
	fsop_param.ctrl = packet->p.ctrl;
	fsop_param.seq = packet->p.seq;
	fsop_param.reply_port = *(fsop_param.data);

	fsop = *(fsop_param.data+1);

	/* Where the FS call presents us with filehandles, do DIVHANDLE on them if need be. Some FSOPs don't. */

	if ((fsop != 8) && (fsop != 9)) // 8 & 9 are Getbyte / Putbyte which do not pass the usual three handles in the tx block
        {
                /* Modify the three handles that are in every packet - assuming the packet is long enough - if we are not in manyhandle mode */

                if (!FS_CONFIG(s,fs_manyhandle)) // NFS 3 / BBC B compatible handles
                {
			// Don't modify for LOAD, SAVE, RUNAS, (GETBYTE, PUTBYTE - not in this loop), GETBYTES, PUTBYTES - all of which either don't have the usual three handles in the tx block or use the URD for something else
                        if (	!(fsop == 1 || fsop == 2 || (fsop == 5) || (fsop >=10 && fsop <= 11)) ) 
				if (datalen >= 3) *(f->data+2) = FS_DIVHANDLE(*(f->data+2)); 

                        if (datalen >= 4) *(f->data+3) = FS_DIVHANDLE(*(f->data+3));
                        if (datalen >= 5) *(f->data+4) = FS_DIVHANDLE(*(f->data+4));
                }

        }

	fsop_param.urd = *(fsop_param.data+2); // NB sometimes this isn't the root handle and is used for something else (fsop 1,2,5,10,11 we think)
	fsop_param.cwd = *(fsop_param.data+3);
	fsop_param.lib = *(fsop_param.data+4);

	/* Reset sequence number to rogue if not fsop &09 - i.e. not a putbyte operation */

	if (active && fsop != 0x09 && fsop != 0x08)
		active->sequence = 2;

	/* Handle new FSOP list */

	if (fsops[fsop].func) /* There's a registration */
	{

		if ((fsops[fsop].flags & FSOP_F_LOGGEDIN) && !fsop_param.user) // Requires log in but not logged in
			fsop_error (&fsop_param, 0xBF, "Who are you?");
		else if ((fsops[fsop].flags & FSOP_F_SYST) && !(fsop_param.user->priv & FS_PRIV_SYSTEM))
			fsop_error (&fsop_param, 0xFF, "Insufficient privilege");
		else if ((fsops[fsop].flags & FSOP_F_MDFS) && !(fsop_param.server->config->fs_sjfunc))
			fsop_error (&fsop_param, 0xFF, "Unknown operation");
		else
			(fsops[fsop].func)(&fsop_param);

		return;

	}
	else
	{
		fs_debug (0, 1, "Unsupported operation %02X", fsop);

		fsop_error(&fsop_param, 0xFF, "Unsupported operation");
		return;
	}

#if 0
	/* This bit will go when everything's in the new structure */

	if (fsop != 0 && fsop != 0x0e && fsop != 0x19) // Things we can do when not logged in
	{
		if (!active)
		{
			fsop_error(&fsop_param, 0xbf, "Who are you?");
			return;
		}
	}

	switch (fsop)
	{
		case 0: // OSCLI
		{
			unsigned char command[256];
			int counter;
			char *param;

			struct 		oscli_params p[10]; // Max params should be less than 10
			uint8_t		num_params, param_start;
			struct		fsop_00_cmd	*cmd;

			/* New structure - parse the command & params */

			if ((cmd = fsop_00_match(data+5, &param_start))) /* Yes, assignment from fsop_00_match */
			{
				num_params = fsop_00_oscli_parse(data+5, &p[0], param_start);

				if ((cmd->flags & FSOP_00_LOGGEDIN) && (!fsop_param.user))
					fsop_error (&fsop_param, 0xff, "Who are you?");
				else if ((cmd->flags & FSOP_00_SYSTEM) && !(fsop_param.user->priv & FS_PRIV_SYSTEM))
					fsop_error (&fsop_param, 0xff, "Insufficient privilege");
				else if ((cmd->flags & FSOP_00_BRIDGE) && !(fsop_param.user->priv2 & FS_PRIV2_BRIDGE))
					fsop_error (&fsop_param, 0xff, "No bridge privilege");
				else if (cmd->p_min > num_params)
				       	fsop_error (&fsop_param, 0xff, "Not enough parameters");
				else if (cmd->p_max < num_params)
					fsop_error (&fsop_param, 0xff, "Too many parameters");
				else
					(cmd->func)(&fsop_param, &p[0], num_params, param_start);

				return;
			}
			// else { barf, later }
			
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
			/* else */ if (!active)
				fsop_error(&fsop_param, 0xbf, "Who are you ?");
			else if (fs_parse_cmd(command, "CAT", 2, &param) || fs_parse_cmd(command, ".", 1, &param))
			{

				struct __econet_packet_udp r;
				unsigned short len; // Length of path we are trying to CAT

				r.p.port = reply_port;
				r.p.ctrl = 0x80;
				r.p.ptype = ECONET_AUN_DATA;
	
				r.p.data[0] = 3; // CAT
				r.p.data[1] = 0; // Successful return
				
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
			else if (fs_parse_cmd(command, "BYE", 3, &param)) fs_bye(server, reply_port, net, stn, 1);
			else if (fs_parse_cmd(command, "SETLIB", 4, &param))
			{ // Permanently set library directory
				unsigned char libdir[97], username[11], params[256];
				short uid;

				if (active->priv & FS_PRIV_LOCKED)
					fsop_error(f, 0xbd, "Insufficient access");
				else
				{
					struct path p;
					strncpy(params, param, 255);

					if ((active->priv & FS_PRIV_SYSTEM) && (sscanf(params, "%10s %80s", username, libdir) == 2)) // System user with optional username
					{
						if ((uid = fsop_get_uid(s, username)) < 0)
						{
							fsop_error(f, 0xFF, "No such user");
							return;
						}

						// Can't specify a disc on library set - it will search (eventually!)
						if (libdir[0] == ':')
						{
							fsop_error(f, 0xFF, "Can't specify disc");
							return;
						}
					}
					else if (strchr(params, ' ')) // Non-privileged user attempting something with a space, or otherwise a pattern mismatch
					{
						fsop_error(f, 0xFF, "Bad parameters");
						return;
					}
					else
					{
						uid = userid;
						strcpy(libdir, params);
					}	

					fs_debug (0, 1, "%12sfrom %3d.%3d SETLIB for uid %04X to %s", "", net, stn, uid, libdir);

					if (libdir[0] != '%' && fsop_normalize_path(f, libdir, *(data+3), &p) && (p.ftype == FS_FTYPE_DIR) && strlen((const char *) p.path_from_root) < 94 && (p.disc == f->user->home_disc))
					{
						if (strlen(p.path_from_root) > 0)
						{
							f->user->lib[0] = '$';
							f->user->lib[1] = '.';
							f->user->lib[2] = '\0';
						}
						else	strcpy(f->user->lib, "");

						strncat((char * ) f->user->lib, (const char * ) p.path_from_root, 79);
						/* No longer needed - mmaped 
						fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
						*/
						fsop_reply_ok(f);
					}
					else if (libdir[0] == '%') // Blank off the library
					{
						strncpy((char *) f->user->lib, "", 79);
						/* No longer needed - mmaped
						fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
						*/
						fsop_reply_ok(f);
					}
					else	fsop_error(f, 0xA8, "Bad library");
				}
			}
			else if (fs_parse_cmd(command, "PRINTER", 6, &param))
				fsop_select_printer(f, param);
#ifdef EB_VERSION
	#if EB_VERSION >= 0x21
			else if (fs_parse_cmd(command, "PRINTOUT", 6, &param))
				fs_printout(server, reply_port, active_id, net, stn, param, active[server][active_id].current);
	#endif
#endif
			else if (fs_parse_cmd(command, "PASS", 4, &param))
				fs_change_pw(server, reply_port, userid, net, stn, param);
			else if (fs_parse_cmd(command, "CHOWN", 3, &param) || fs_parse_cmd(command, "SETOWNER", 5, &param))
				fs_chown(server, reply_port, active_id, net, stn, param);
			else if (fs_parse_cmd(command, "OWNER", 3, &param))
				fs_owner(server, reply_port, active_id, *(data+3), net, stn, param);
			else if (fs_parse_cmd(command, "BRIDGEVER", 7, &param))
			{
				fs_error(server, reply_port, net, stn, 0xFF, "Ver " GIT_VERSION);
				return;
			}
			else if (fs_parse_cmd(command, "ACCESS", 3, &param))
				fs_access(server, reply_port, active_id, net, stn, param);
			else if (fs_parse_cmd(command, "INFO", 1, &param)) // For some reason *I. is an abbreviation for *INFO...
				fs_info(server, reply_port, active_id, net, stn, param);
			else if (fs_parse_cmd(command, "CDIR", 2, &param))
				fs_cdir(server, reply_port, active_id, net, stn, active[server][active_id].current, param);
			else if (fs_parse_cmd(command, "DELETE", 3, &param))
				fs_delete(server, reply_port, active_id, net, stn, active[server][active_id].current, param);
			else if (fs_parse_cmd(command, "RENAME", 3, &param))
				fs_rename(server, reply_port, active_id, net, stn, active[server][active_id].current, param);
			else if (fs_parse_cmd(command, "SDISC", 2, &param))
				fs_sdisc(server, reply_port, active_id, net, stn, param);
			else if (fs_parse_cmd(command, "COPY", 2, &param))
				fs_copy(server, reply_port, active_id, net, stn, param);
			else if (fs_parse_cmd(command, "LIB", 3, &param))
			{
				int 		found;
				struct path 	p;
				struct __fs_file *l;
				uint8_t		n_handle;
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

				if ((found = fsop_normalize_path(f, dirname, *(data+3), &p)) && (p.ftype != FS_FTYPE_NOTFOUND)) // Successful path traverse
				{
					if (p.ftype != FS_FTYPE_DIR)
						fsop_error(f, 0xAF, "Types don't match");
					else if (FS_PERM_EFFOWNER(f->active, p.owner) || (p.perm & FS_PERM_OTH_R)) // Owner and SYST always have read access to directories even if the perm is not set
					{	
						int8_t	err;
						/* l = fs_get_dir_handle(server, active_id, p.unixpath); */
						l = fsop_open_interlock(f, p.unixpath, 1, &err, 1);
						if (err >= 0) // Found
						{
							n_handle = fsop_allocate_user_dir_channel(f->active, l);
							if (n_handle > 0)
							{
								int old;
								struct __econet_packet_udp r;

								old = active->lib;

								active->lib = n_handle;
								fs_debug (0, 2, "%12sfrom %3d.%3d User handle %d allocated ", "", f->net, f->stn, n_handle);
								strncpy((char * ) active->lib_dir, (const char * ) p.path_from_root, 255);
								if (p.npath == 0)	strcpy((char * ) active->lib_dir_tail, (const char * ) "$         ");
								else			sprintf(active->lib_dir_tail, "%-80s", p.path[p.npath-1]); // Was 10
								
								strcpy(active->fhandles[n_handle].acornfullpath, p.acornfullpath);
								fs_store_tail_path(active->fhandles[n_handle].acorntailpath, p.acornfullpath);
								active->fhandles[n_handle].mode = 1;

								if (old > 0) // Matches what *dir does. The interlock close will not close internally if something is still using it.
								{
									fs_debug (0, 2, "%12sfrom %3d.%3d Closing old user handle %d", "", f->net, f->stn, old);
									fsop_close_interlock(f->server, old, 1);
									fsop_deallocate_user_dir_channel(f->server, old);
								}

								r.p.ptype = ECONET_AUN_DATA;
								r.p.port = reply_port;
								r.p.ctrl = 0x80;
								r.p.data[0] = 0x09; // Changed directory;
								r.p.data[1] = 0x00;
								r.p.data[2] = FS_MULHANDLE(n_handle);
								fsop_aun_send (&r, 3, f);
							
							}
							else	fsop_error(f, 0xC0, "Too many open directories");
						}
						else	fsop_error(f, 0xD6, "Dir unreadable");
					}
					else	fsop_error(f, 0xBD, "Insufficient access");
				}
				else	fsop_error(f, 0xFE, "Not found");
			}
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
					else if (FS_PERM_EFFOWNER(server, active_id, p.owner) || (p.perm & FS_PERM_OTH_R)) // Owner and SYST always have read access to directories even if the perm is not set
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
					else fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
				}
				else	fs_error(server, reply_port, net, stn, 0xFE, "Not found");
			}

			else if (active[server][active_id].priv & FS_PRIV_SYSTEM)
			{

				regmatch_t matches[10];

				// System commands here

				if (regexec(&fs_netconf_regex_one, command, 3, matches, 0) == 0) // Found a NETCONF
				{
					char configitem[100];
					int length;
					unsigned char operator; // The + or - on the command line
					FILE *config;
					char configfile[300];

					// temp use of length - will point to the operator character

					operator = command[matches[2].rm_so];

					length = matches[2].rm_eo - matches[2].rm_so - 1;
					configitem[length] = 0;

					while (length > 0)
					{
						configitem[length-1] = command[matches[2].rm_so + length];
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
					else if (!strcasecmp("ACORNDIR", configitem))
						fs_config[server].fs_mask_dir_wrr = (operator == '+' ? 1 : 0);
					else if (!strcasecmp("PIFSPERMS", configitem))
						fs_config[server].fs_pifsperms = (operator == '+' ? 1 : 0);
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
				else if (fs_parse_cmd(command, "FSDEFPERM", 6, &param))
				{
					char params[11];
					uint8_t	counter = 0, is_dir = 0, perm = 0;
					FILE *	config;
					char configfile[300];

					fs_copy_to_cr(params, param, 10);
					
					while (counter < strlen(params))
						params[counter++] &= ~(0x20);  // Make caps - but will turn '/' into 0x0f

					counter = 0;

					if ((strlen(params) >= 1) && params[0] == 'D')
					{
						is_dir = 1;
						counter++;
					}

					// Before the /
					while ((counter < strlen(params) && params[counter] != 0x0f)) // 0x0f is what ('/' & 0x20) becomes
					{

						//fprintf (stderr, "FSDEFPERMS - counter = %d, character = '%c' (%d), length = %d\n", counter, params[counter], params[counter], strlen(params));

						switch (params[counter])
						{
							case 'L': perm |= FS_PERM_L; break;
							case 'P': perm |= FS_PERM_H; break;
							case 'H': perm |= FS_PERM_H; break;
							case 'R': perm |= FS_PERM_OWN_R; break;
							case 'W': perm |= FS_PERM_OWN_W; break;
							default:
							{
								fs_error(server, reply_port, net, stn, 0xFF, "Bad attribute"); return;
							} break;
						}

						counter++;

					}

					if ((counter < strlen(params)) && params[counter] == 0x0f)	counter++; // Skip the slash

					while (counter < strlen(params))
					{
						//fprintf (stderr, "FSDEFPERMS(other) - counter = %d, character = '%c' (%d), length = %d\n", counter, params[counter], params[counter], strlen(params));

						switch (params[counter])
						{
							case 'R': perm |= FS_PERM_OTH_R; break;
							case 'W': perm |= FS_PERM_OTH_W; break;
							default:
							{
								fs_error(server, reply_port, net, stn, 0xFF, "Bad attribute"); return;
							} break;
						}

						counter++;
					}

					// Impose defaults even in setting the defaults!

					if ((perm & (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_W | FS_PERM_OTH_R)) == 0)
					{
						perm |= FS_PERM_OWN_W | FS_PERM_OWN_R;

						if (is_dir)
							perm |= FS_PERM_OTH_R;
					}

					// Set the config

					if (is_dir)
						FS_CONF_DEFAULT_DIR_PERM(server) = perm;
					else
						FS_CONF_DEFAULT_FILE_PERM(server) = perm;

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
				else if (fs_parse_cmd(command, "FNLENGTH", 8, &param) || fs_parse_cmd(command, "FSFNLENGTH", 6, &param))
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
				else if (fs_parse_cmd(command, "SETOPT", 4, &param))
				{
					unsigned char 	params[256];
					unsigned char 	username[11];
					uint8_t		new_opt;
					short		uid;

					fs_copy_to_cr(params, param, 255);

					if (sscanf(params, "%10s %1hhd", username, &new_opt) != 2)
					{
						fs_debug (0, 1, "%12sfrom %3d.%3d Set user boot option - bad parameters %s", "", net, stn, params);
						fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
						return;
					}
					else
					{
						uint8_t		fake_data[6];

						uid = fs_get_uid(server, username);
						if (uid < 0)
						{
							fs_error(server, reply_port, net, stn, 0xFF, "No such user");
							return;
						}

						fake_data[5] = new_opt;

						fs_set_bootopt(server, reply_port, uid, net, stn, fake_data);


					}
				}
				else if (fs_parse_cmd(command, "SETHOME", 4, &param))
				{ // Permanently set home directory
					unsigned char params[256], dir[96], username[11];
					short uid;
	
					{
						struct path p;
						char homepath[300];
						struct objattr oa;

						fs_copy_to_cr(params, param, 255);


						if (strchr(params, ' ') && sscanf(params, "%10s %80s", username, dir) == 2)
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
								fsop_read_xattr(p.unixpath, &oa, server);
								fsop_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, 0, server); // Set homeof = 0
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
							else	strcpy(users[server][uid].home, "$");
	
							strncat((char * ) users[server][uid].home, (const char * ) p.path_from_root, 79);
							users[server][uid].home_disc = p.disc;
							fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));

							// Set homeof attribute
							if (strlen(p.path_from_root)) // Don't set it on root!
							{
								fsop_read_xattr(p.unixpath, &oa, server);
								fsop_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, uid, server);
							}

							fs_reply_ok(server, reply_port, net, stn);
						}
						else	fs_error(server, reply_port, net, stn, 0xA8, "Bad directory");
					}
				}
				else if (fs_parse_cmd(command, "LINK", 4, &param) || fs_parse_cmd(command, "MKLINK", 4, &param))
					fs_link(server, reply_port, active_id, net, stn, param);
				else if (fs_parse_cmd(command, "UNLINK", 3, &param))
					fs_unlink(server, reply_port, active_id, net, stn, param);
				else if (fs_parse_cmd(command, "FLOG", 3, &param) || fs_parse_cmd(command, "LOGOFF", 5, &param))
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

						while (count < ECONET_MAX_FS_ACTIVE)
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

							while (count < ECONET_MAX_FS_ACTIVE)
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
				else if (fs_parse_cmd(command, "SETPASS", 4, &param))
				{
					unsigned char	username[11], password[11];
					unsigned char 	parameters[255];
					uint16_t		count, s_ptr;

					fs_copy_to_cr (parameters, param, 21);

					s_ptr = count = 0;

					while (parameters[count] == ' ' && count < strlen(parameters))
						count++;

					if (count == strlen(parameters)) // No parameters
						fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter");
					else
					{
						while (s_ptr < 10 && parameters[count] != ' ' && (count < strlen(parameters)))
						{
							username[s_ptr] = parameters[count];
							s_ptr++; count++;
						}

						while (s_ptr < 10)
							username[s_ptr++] = ' ';

						username[s_ptr] = 0;

						if (count == strlen(parameters) || parameters[count] != ' ')
							fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter");
						else
						{
							while (parameters[count] == ' ' && count < strlen(parameters))
								count++;	

							if (count == strlen(parameters))
								fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter");
							else
							{
								s_ptr = 0;

								while (s_ptr < 10 && parameters[count] != ' ' && (count < strlen(parameters)))
								{
									password[s_ptr] = parameters[count];
									s_ptr++;
									count++;
								}

								while (s_ptr < 10)
									password[s_ptr++] = ' ';

								password[s_ptr] = 0;

								if (parameters[count] != ' ' && count != strlen(parameters))
									fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter");
								else
								{
									count = 0;

									while (count < ECONET_MAX_FS_USERS && strncasecmp(users[server][count].username, username, 10))
										count++;

									if (count == ECONET_MAX_FS_USERS)
										fs_error(server, reply_port, net, stn, 0xFF, "Unknown user");
									else
									{

										memcpy(&(users[server][count].password), password, 10);
										fs_write_user(server, count, (unsigned char *) &(users[server][count]));
										fs_reply_ok(server, reply_port, net, stn);
										fs_debug (0, 1, "%12sfrom %3d.%3d *SETPASS %s %s (user ID %d)", "", net, stn, username, password, count);

									}

								}

							}

						}

					}

				}
				else if (fs_parse_cmd(command, "DISCMASK", 5, &param) || fs_parse_cmd(command, "DISKMASK", 5, &param))
				{
					char		parameters[255];
					char		username[20], discs[10];

					fs_debug (0, 1, "%12sfrom %3d.%3d *DISCMASK %s", "", net, stn, param);

					fs_copy_to_cr (parameters, param, 40);

					if (sscanf(parameters, "%10s %4s", username, discs) != 2)
						fs_error(server, reply_port, net, stn, 0xFF, "Bad parameters");
					else
					{
						int 	userid;
						//fs_debug (0, 1, "DISCMASK username '%s', discs '%s'", username, discs);

						userid = fs_get_uid(server, username);

						if (userid < 0)
							fs_error(server, reply_port, net, stn, 0xFF, "Unknown user");
						else
						{
							uint16_t	mask;

							mask = users[server][userid].discmask;

							if (!strcasecmp(discs, "ALL"))
								mask = 0xffff;
							else if (!strcasecmp(discs, "NONE"))
								mask = 0x0000;
							else
							{
								if (sscanf(discs, "%04hX", &mask) != 1)
									mask = users[server][userid].discmask;
							}

							if (mask != users[server][userid].discmask)
							{
								users[server][userid].discmask = mask;
								fs_write_user(server, userid, (unsigned char *) &(users[server][userid]));
								fs_reply_ok(server, reply_port, net, stn);
							}
							else
								fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter or mask unchanged");
						}
					}
				}
#ifdef BRIDGE_V2
				else if (fs_parse_cmd(command, "BRIDGEUSER", 7, &param))
				{
					char 		parameters[255];
					uint8_t		count, setmode;
					int		userid;

					fs_debug (0, 1, "%12sfrom %3d.%3d *BRIDGEUSER %s", "", net, stn, param);

					if (!(users[server][active[server][active_id].userid].priv2 & FS_PRIV2_BRIDGE))
						fs_error(server, reply_port, net, stn, 0xFF, "Insufficient privilege");
					else
					{
					
						fs_copy_to_cr (parameters, param, 21);

						count = 0;

						while (parameters[count] == ' ' && count < strlen(parameters))
							count++;
	
						if (count >= (strlen(parameters)-1)) // No parameters or all we have is a single character (possibly +/-) after the spaces so there cannot be any username
							fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter");
						else if (parameters[count] != '+' && parameters[count] != '-') // First character must be a + or -
							fs_error(server, reply_port, net, stn, 0xFF, "Bad parameter");
						else
						{
							setmode = 1;
							if (parameters[count] == '-') // Unset mode
								setmode = 0;

							count++;
							if ((userid = fs_get_uid(server, (char *) (&parameters[count]))) >= 0) // Found
							{
								if (userid == active[server][active_id].userid) // Cannot modify ourselves!	
									fs_error (server, reply_port, net, stn, 0xFF, "Cannot modify own bridge privilege");
								else
								{
									if (setmode)
										users[server][userid].priv2 |= FS_PRIV2_BRIDGE;
									else
										users[server][userid].priv2 &= ~(FS_PRIV2_BRIDGE);
									// Write out

									fs_write_user(server, userid, (unsigned char *) &(users[server][userid]));
									fs_reply_ok(server, reply_port, net, stn);
								}
							}
							else
								fs_error (server, reply_port, net, stn, 0xFF, "User not found");
						}
					}

				}
#endif
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

					fs_toupper(username);

					ptr++; // Now points to full name

					if (fs_user_exists(server, username) >= 0)
						fs_error(server, reply_port, net, stn, 0xFF, "User exists");
					else
					{
						int id;
						uint8_t	ftype;

						id = fs_find_new_user(server);
		
						if (id < 0)
							fs_error(server, reply_port, net, stn, 0xFF, "No available users");
						else
						{
							char homepath[300];
							char acorn_homepath[300];

							
							snprintf((char * ) users[server][id].username, 11, "%-10s", username);
							snprintf((char * ) users[server][id].password, 11, "%-10s", "");
							snprintf((char * ) users[server][id].fullname, 25, "%-24s", &(username[ptr]));
							//users[server][id].home[0] = '\0';
							//users[server][id].lib[0] = '\0';
							snprintf((char * ) users[server][id].home, 97, "$.%s", username);
							snprintf((char * ) users[server][id].lib, 97, "$.%s", "Library");
							users[server][id].home_disc = 0;
							users[server][id].priv = 0; // Inactive unless we succeed
							users[server][id].priv2 = 0; // clear priv2 byte
							
							sprintf(homepath, "%s/%1x%s/%s", fs_stations[server].directory, 0, fs_discs[server][0].name, username);
							sprintf(acorn_homepath, ":%s.$.%s", fs_discs[server][0].name, username);

							ftype = fs_exists(server, active_id, acorn_homepath);

							if (ftype == FS_FTYPE_NOTFOUND)
							{
								if (mkdir((const char *) homepath, 0770) != 0)
									fs_error(server, reply_port, net, stn, 0xff, "Unable to create home directory");
								else
									ftype = FS_FTYPE_DIR; // Successfully created the dir
							}

							if (ftype != FS_FTYPE_DIR)
							{
								fs_debug (0, 1, "%12sfrom %3d.%3d New user %s's home path exists and is not a directory - fs_exists() returned %d", "", net, stn, username, ftype);
								fs_error(server, reply_port, net, stn, 0xff, "Home path exists and is wrong type");
							}
							else
							{
								users[server][id].priv = FS_PRIV_USER;
								fs_write_xattr(homepath, id, FS_PERM_OWN_W | FS_PERM_OWN_R, 0, 0, id, server); // Set home ownership. Is there a mortgage?
							
								fs_write_user(server, id, (unsigned char *) &(users[server][id]));
								if (id >= fs_stations[server].total_users) fs_stations[server].total_users = id+1;
								fs_reply_ok(server, reply_port, net, stn);
								fs_debug (0, 1, "%12sfrom %3d.%3d New User %s, id = %d, total users = %d", "", net, stn, username, id, fs_stations[server].total_users);
							}
						}
					}

				}
				else if (fs_parse_cmd(command, "PRIV", 4, &param) || fs_parse_cmd(command, "REMUSER", 4, &param))
				{
					char username[11], priv, priv_byte, priv2_byte;
					int	uid;

					unsigned short count;
		
					count = 0;
				
					while (count < strlen((const char *) param) && (count < 10) && param[count] != ' ')
					{
						username[count] = param[count];
						count++;
					}

					if (count == 0) // There wasn't a username
						fs_error(server, reply_port, net, stn, 0xFE, "Bad command");

					command[0] &= 0xDF; // Capitalize

					if ((command[0] == 'P') && count == strlen((const char *) param)) // THere was no space after the username and this was PRIV not REMUSER
						fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
					else
					{
						uint8_t setpriv = 1; // Default is to set the relevant priv

						username[count] = '\0';
						count++;
						if (command[0] == 'P' && count == strlen((const char *) param)) // There was no priv character!
							fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
						else if (command[0] == 'P' && (param[count] == '+' || param[count] == '-') && (strlen((const char *) param) < count+2)) // using + or - notation and string not long enough
							fs_error(server, reply_port, net, stn, 0xFE, "Bad command");
						else
						{
							uid = fs_get_uid(server, username);

							if (uid < 0)
								fs_error(server, reply_port, net, stn, 0xbc, "User not found");

							if ((command[0] & 0xdf) == 'P')
								priv = param[count];	
							else	priv = 'D'; // This was REMUSER not PRIV, so we pick 'D' for delete

							if (priv == '+' || priv == '-') // New set/unset mode
							{
								if (priv == '-') setpriv = 0;
								priv = param[count+1];
							}

							priv &= 0xDF; // Capitalize

							priv2_byte = users[server][uid].priv2;

							switch (priv) {
								case 's': case 'S': // System user
									{
										if (setpriv)
											priv_byte = FS_PRIV_SYSTEM;
										else 	priv_byte = FS_PRIV_USER;
									}
									break;
								case 'u': case 'U': // Unlocked normal user
									priv_byte = FS_PRIV_USER;
									break;
								case 'l': case 'L': // Locked normal user
									{
										if (setpriv)
											priv_byte = FS_PRIV_LOCKED;
										else	priv_byte = FS_PRIV_USER;
									}
									break;
								case 'n': case 'N': // Unlocked user who cannot change password
									{
										if (setpriv)
											priv_byte = FS_PRIV_NOPASSWORDCHANGE;
										else	priv_byte = FS_PRIV_USER;
									}
									break;
								case 'd': case 'D': // Invalidate privilege - delete the user
									priv_byte = 0;
									break;
								case 'c': case 'C': // Chroot
									{
										priv_byte = users[server][uid].priv;
										if (setpriv)
											priv2_byte = users[server][uid].priv2 | FS_PRIV2_CHROOT;
										else	priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_CHROOT;
									} break;
								case 'r': case 'R': // (Normal) root
									{
										priv_byte = users[server][uid].priv;
										priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_CHROOT;
									} break;
								case 'v': case 'V': // Show all users
									{
										priv_byte = users[server][uid].priv;
										priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_HIDEOTHERS;
									} break;
								case 'h': case 'H': // Hide other users
									{
										priv_byte = users[server][uid].priv;
										if (setpriv)
											priv2_byte = users[server][uid].priv2 | FS_PRIV2_HIDEOTHERS;
										else	priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_HIDEOTHERS;
									} break;
								case 'a': case 'A': // Turn on ANFS Name Bodge
									{
										priv_byte = users[server][uid].priv;
										if (setpriv)
											priv2_byte = users[server][uid].priv2 | FS_PRIV2_ANFSNAMEBODGE;
										else	priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_ANFSNAMEBODGE;
									} break;
								case 'b': case 'B': // Turn off ANFS Name Bodge
									{
										priv_byte = users[server][uid].priv;
										priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_ANFSNAMEBODGE;
									} break;
								case 'O': // Stop user changing boot opt
									{
										priv_byte = users[server][uid].priv;
										if (setpriv)
											priv2_byte = users[server][uid].priv2 | FS_PRIV2_FIXOPT;
										else	priv2_byte = users[server][uid].priv2 & ~FS_PRIV2_FIXOPT;
									} break;
								default:
									priv_byte = 0xff;
									fs_error(server, reply_port, net, stn, 0xfe, "Bad command");
									break;
							}

							if (priv_byte != 0xff) // Valid change
							{
								users[server][uid].priv = priv_byte;
								users[server][uid].priv2 = priv2_byte;
								fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
								fs_reply_ok(server, reply_port, net, stn);
							}
						}
					}
				}
				else if (fs_parse_cmd(command, "RENUSER", 4, &param))
				{
					char username[11], new_name[11];
					int	uid;
					uint8_t	count;

					if (sscanf(param, "%10s %10s", username, new_name) == 2)
					{

						fs_toupper(username);
						uid = fs_get_uid(server, username);

						if (uid < 0)
							fs_error(server, reply_port, net, stn, 0xbc, "User not found");
						else
						{
							if (uid == active[server][active_id].userid)
								fs_error(server, reply_port, net, stn, 0xfe, "Cannot rename self while logged in");
							else
							{
								fs_toupper(new_name);

								new_name[10] = '\0';
								count = 1;
								while (new_name[count] != '\0') count++;
								while (count < 10) new_name[count++] = ' '; // Pad
								memcpy(users[server][uid].username, new_name, 10);
								fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));
	
								fs_debug (0, 1, "%12sfrom %3d.%3d Rename user %s to %s (uid %d)", "", net, stn, username, new_name, uid);
								fs_reply_ok(server, reply_port, net, stn);
							}
						}

					}
					else
						fs_error(server, reply_port, net, stn, 0xfe, "Bad command");
					
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
			if ((fs_stn_logged_in(server, net, stn) >= 0) && FS_ACTIVE_SYST(server, active_id))
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
				else if ((fs_stn_logged_in(server, net, stn) >= 0) && (rw_op & 0x01 || FS_ACTIVE_SYST(server, active_id)))
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

					fs_aun_send (&reply, server, reply_length, net, stn);
				}
				else
					fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			}
			break;
		case 0x60: // PiBridge calls
		{
			fs_pibridge(server, reply_port, active_id, net, stn, data, datalen);
		} break;
		default: // Send error
		{
			fs_debug (0, 1, "to %3d.%3d FS Error - Unknown operation 0x%02x", net, stn, fsop);
			fs_error(server, reply_port, net, stn, 0xff, "FS Error");
		}
		break;

	}
#endif
}

// Bridge V2 packet handler code

/* This code has to detect bulk transfer ports.
   d is the device struct of containing this fileserver.
   p is the packet we're being asked to deal with
   length is the *data length* (not full packet length)

   The bridge itself will free the 'p' structure when we're done.

*/

void fsop_handle_traffic (struct __econet_packet_aun *p, uint16_t length, void *param)
{

	struct __econet_packet_aun	*mypacket;
	struct __eb_packetqueue		*q, *new_q;
	struct __fs_station		*server = (struct __fs_station *) param;

	mypacket = eb_malloc(__FILE__, __LINE__, "BRIDGE", "New packet structure for FS packet", length);
	new_q = eb_malloc(__FILE__, __LINE__, "BRIDGE", "New packet structure for FS packetqueue", sizeof(struct __eb_packetqueue));

	memcpy(mypacket, p, length);

	new_q->p = mypacket;
	new_q->length = length;
	new_q->n = NULL;

	fs_debug (0, 3, "FS at %d.%d processing traffic at %p lenght %d from %d.%d", server->net, server->stn, p, length, p->p.srcnet, p->p.srcstn);

	pthread_mutex_lock(&(server->fs_mutex));

	q = server->fs_workqueue;

	while (q && q->n)
		q = q->n;

	if (!q)
		server->fs_workqueue = new_q;
	else
		q->n = new_q;

	fs_debug (0, 3, "FS at %d.%d processing traffic at %p length %d from %d.%d - now on queue (%p)", server->net, server->stn, p, length, p->p.srcnet, p->p.srcstn, server->fs_workqueue);

	pthread_mutex_unlock(&(server->fs_mutex));

	fs_debug (0, 3, "FS at %d.%d waking worker thread", server->net, server->stn);
	pthread_cond_signal(&(server->fs_condition));

	return;

}

// Used for *FAST - NB, doesn't rename the directory: the *FAST handler has to do that.

void fsop_set_disc_name (struct __fs_station *s, uint8_t disc, unsigned char *discname)
{

	char	old_dirname[1024], new_dirname[1024];
	struct __fs_disc *d;

	d = s->discs;

	while (d && d->index != disc)
		d = d->next;

	if (d)
	{
		sprintf (new_dirname, "%s/%1d%s", s->directory, disc, discname);
		sprintf (old_dirname, "%s/%1d%s", s->directory, disc, d->name);

		if (d->name[0]) // Exists - rename it
			rename (old_dirname, new_dirname);
		else // Create it
			mkdir (new_dirname, 0755);

		memcpy(&(d->name), discname, 17);
	}


	return;
}

// Used for *FAST
uint8_t	fs_get_maxdiscs()
{
	return ECONET_MAX_FS_DISCS;
}

// Used for *FAST
void fsop_get_disc_name (struct __fs_station *s, uint8_t disc, unsigned char *discname)
{
	struct __fs_disc	*d;

	d = s->discs;

	while (d && d->index != disc)
		d = d->next;

	if (d)
		memcpy(discname, &(d->name), 17);
	else
		*discname = 0;

	return;

}

// used for *VIEW
uint8_t fsop_writedisclist (struct __fs_station *s, unsigned char *addr)
{

	struct __fs_disc	*d;

	d = s->discs;

	uint8_t	found = 0;

	while (d)
	{
		memcpy (addr+(found * 20), d->name, strlen(d->name));
		found++;
	}

	return ((found/2) + ((found%2 == 0) ? 0 : 1));
}

/*
 * fs_setup
 *
 * Called by econet-hpbridge.c to get the 
 * once-off stuff set up in the fileserver
 *
 * Doesn't actually instantiate any servers, but it does NULL-off the server list
 *
 */

void fsop_setup(void)
{

	unsigned char	regex[128];

	/* Initialize list of tabled FSOP handler functions */

	fileservers = NULL;

	memset (&fsops, 0, sizeof(fsops));

	FSOP_SET (00, (FSOP_F_NONE));
	FSOP_SET (01, (FSOP_F_LOGGEDIN)); /* Save */
	FSOP_SET (02, (FSOP_F_LOGGEDIN)); /* Load */
	FSOP_SET (03, (FSOP_F_LOGGEDIN)); /* Examine */
	FSOP_SET (04, (FSOP_F_LOGGEDIN)); /* Read catalogue header */
	FSOP_SET (05, (FSOP_F_LOGGEDIN)); /* Load as command */
	FSOP_SET (06, (FSOP_F_LOGGEDIN)); /* Open file */
	FSOP_SET (07, (FSOP_F_LOGGEDIN)); /* Close handle */
	FSOP_SET (08, (FSOP_F_LOGGEDIN)); /* Get byte */
	FSOP_SET (09, (FSOP_F_LOGGEDIN)); /* Put byte */
	FSOP_SET (0a, (FSOP_F_LOGGEDIN)); /* Get bytes */
	FSOP_SET (0b, (FSOP_F_LOGGEDIN)); /* Put bytes */
	FSOP_SET (0c, (FSOP_F_LOGGEDIN)); /* Get Random Access Info 24-bit */
	FSOP_SET (0d, (FSOP_F_LOGGEDIN)); /* Set Random Access Info 24-bit */
	FSOP_SET (0e, (FSOP_F_LOGGEDIN)); /* Read disc names */
	FSOP_SET (0f, (FSOP_F_LOGGEDIN)); /* Read logged on users */
	FSOP_SET (10, (FSOP_F_NONE)); /* Read time */
	FSOP_SET (11, (FSOP_F_LOGGEDIN)); /* Read EOF status */
	FSOP_SET (12, (FSOP_F_LOGGEDIN)); /* Read object info */
	FSOP_SET (13, (FSOP_F_LOGGEDIN)); /* Set object info */
	FSOP_SET (14, (FSOP_F_LOGGEDIN)); /* Delete object(s) */
	FSOP_SET (15, (FSOP_F_LOGGEDIN)); /* Read user env */
	FSOP_SET (17, (FSOP_F_LOGGEDIN)); /* Bye */
	FSOP_SET (18, (FSOP_F_LOGGEDIN)); /* Read user information */
	FSOP_SET (19, (FSOP_F_NONE)); /* Read FS Version */
	FSOP_SET (1a, (FSOP_F_LOGGEDIN)); /* Read free space */
	FSOP_SET (1b, (FSOP_F_LOGGEDIN)); /* Create directory */
	FSOP_SET (1c, (FSOP_F_LOGGEDIN | FSOP_F_SYST)); /* Set RTC */
	FSOP_SET (1d, (FSOP_F_LOGGEDIN)); /* Create */
	FSOP_SET (1e, (FSOP_F_LOGGEDIN)); /* Read user free space */
	FSOP_SET (1f, (FSOP_F_LOGGEDIN | FSOP_F_SYST)); /* Set user free space */
	FSOP_SET (20, (FSOP_F_LOGGEDIN)); /* Read Client Information */

	/*
	 * Functions &21, &22, &24 are manager functions - not implemented (yet)
	 */

	FSOP_SET (26, (FSOP_F_LOGGEDIN)); /* 32 bit save */
	FSOP_SET (27, (FSOP_F_LOGGEDIN)); /* 32 bit create */
	FSOP_SET (28, (FSOP_F_LOGGEDIN)); /* 32 bit load */
	FSOP_SET (29, (FSOP_F_LOGGEDIN)); /* 32 bit Get Random Access Info */
	FSOP_SET (2a, (FSOP_F_LOGGEDIN)); /* 32 bit Set Random Access Info */
	FSOP_SET (2b, (FSOP_F_LOGGEDIN)); /* 32 bit Get bytes */
	FSOP_SET (2c, (FSOP_F_LOGGEDIN)); /* 32 bit Put bytes */
	FSOP_SET (40, (FSOP_F_LOGGEDIN | FSOP_F_MDFS)); /* Read SJ Information - Not yet implemented */
	FSOP_SET (41, (FSOP_F_LOGGEDIN | FSOP_F_MDFS | FSOP_F_SYST)); /* Read/write SJ SYstem information */
	FSOP_SET (60, (FSOP_F_LOGGEDIN | FSOP_F_SYST)); /* PiBridge functions */
	/* Initialize known command list */

	/* Catalogue done as a special case */
	fsop_00_addcmd(fsop_00_mkcmd(".", FSOP_00_LOGGEDIN, 0, 1, 1, fsop_00_catalogue));
	fsop_00_addcmd(fsop_00_mkcmd("CAT", FSOP_00_LOGGEDIN, 0, 1, 2, fsop_00_catalogue));

	/* Some aliases for *I AM */
	fsop_00_addcmd(fsop_00_mkcmd("IAM", FSOP_00_ANON, 1, 3, 2, fsop_00_LOGIN));
	fsop_00_addcmd(fsop_00_mkcmd("I\x80""AM", FSOP_00_ANON, 1, 3, 4, fsop_00_LOGIN));
	fsop_00_addcmd(fsop_00_mkcmd("I\x80.", FSOP_00_ANON, 1, 3, 3, fsop_00_LOGIN));
	fsop_00_addcmd(fsop_00_mkcmd("LOGON", FSOP_00_ANON, 1, 3, 4, fsop_00_LOGIN));

	/* The rest of the commands */

	FSOP_OSCLI(ACCESS, (FSOP_00_LOGGEDIN), 1, 2, 3);
	FSOP_OSCLI(BRIDGEUSER, (FSOP_00_LOGGEDIN | FSOP_00_BRIDGE), 1, 1, 7);
	FSOP_OSCLI(BRIDGEVER, (FSOP_00_LOGGEDIN | FSOP_00_BRIDGE),0,0,7);
	FSOP_OSCLI(BYE,(FSOP_00_LOGGEDIN),0,0,2);
	FSOP_OSCLI(CHOWN,(FSOP_00_ANON), 1, 2, 5);
	FSOP_OSCLI(COPY,(FSOP_00_LOGGEDIN), 1, 2, 3);
	FSOP_OSCLI(DELETE,(FSOP_00_LOGGEDIN), 1, 1, 3);
	FSOP_OSCLI(DIR,(FSOP_00_LOGGEDIN), 0, 1, 2);
	FSOP_OSCLI(DISCMASK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 5);
	FSOP_OSCLI(DISKMASK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 5);
	FSOP_OSCLI(FSCONFIG,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 2, 4);
	FSOP_OSCLI(INFO,(FSOP_00_LOGGEDIN), 1, 1, 2);
	FSOP_OSCLI(LIB,(FSOP_00_LOGGEDIN), 0, 1, 3);
	FSOP_OSCLI(LINK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(LOAD,(FSOP_00_LOGGEDIN),1,2,2);
	FSOP_OSCLI(LOGIN,(FSOP_00_ANON),1,3,4);
	FSOP_OSCLI(LOGOFF,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 1, 4);
	FSOP_OSCLI(MKLINK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(NEWUSER,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 2, 4);
	FSOP_OSCLI(OWNER,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM),1,1,3);
	FSOP_OSCLI(PASS,(FSOP_00_LOGGEDIN),2,2,2);
	FSOP_OSCLI(PRINTER,(FSOP_00_LOGGEDIN),1,1,6);
	FSOP_OSCLI(PRINTOUT,(FSOP_00_LOGGEDIN), 1, 1, 6);
	FSOP_OSCLI(PRIV,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM),1,2,3);
	FSOP_OSCLI(RENUSER,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(SAVE,(FSOP_00_LOGGEDIN), 3, 5, 2);
	FSOP_OSCLI(SDISC,(FSOP_00_LOGGEDIN), 0, 1, 3);
	FSOP_OSCLI(SETHOME,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(SETLIB,(FSOP_00_LOGGEDIN), 1, 2, 4);
	FSOP_OSCLI(SETOPT,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(SETOWNER,(FSOP_00_ANON), 1, 2, 5);
	FSOP_OSCLI(SETPASS,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(UNLINK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 1, 4);

	sprintf(regex, "^(%s{1,16})", FSREGEX);

	if (regcomp(&r_discname, regex, REG_EXTENDED) != 0)
		fs_debug (1, 0, "Unable to compile regex for disc names.");

	fs_debug (0, 1, "Fileserver infrastructure set up");

}

/* 
 * fsop_run()
 *
 * Called by the HPB when it wants to start up
 * a particular server. Returns 0 if the server
 * wouldn't start, 1 if it started successfully,
 * and -1 if the server was already enabled.
 *
 * Returns -2 if the pointer was not a server.
 *
 */

/* Quick definition - the function is below */

void *fsop_thread (void *);

int8_t fsop_run (struct __fs_station *s)
{

	int	err;
	uint8_t	port;

	if (!s)	return -2;

	/* Test to see if server already enabled */

	fs_debug (0, 1, "FS at %d.%d Attempting to enable server", s->net, s->stn);

	pthread_mutex_lock (&(s->fs_mutex));

	if (s->enabled)
	{
		fs_debug (0, 1, "FS at %d.%d Server already enabled! Not bothering to start.", s->net, s->stn);
		pthread_mutex_unlock (&(s->fs_mutex));
		return -1;
	}

	port = eb_port_allocate(s->fs_device, 0x99, fsop_handle_traffic, (void *) s);

	if (port != 0x99)
	{
		pthread_mutex_unlock (&(s->fs_mutex));
		fs_debug (1, 0, "FS at %d.%d (%s) could not start - port &99 not available", s->net, s->stn, s->directory);
		return 0;
	}

	s->enabled = 1; /* Turn it on */
	
	pthread_mutex_unlock (&(s->fs_mutex));

	/* Create the thread & detach */

	err = pthread_create(&(s->fs_thread), NULL, fsop_thread, (void *) s);

	if (err)
	{
		fs_debug (1, 0, "FS at %d.%d (%s) could not start - thread creation failed: %s", s->net, s->stn, s->directory, strerror(err));
		return 0;
	}

	pthread_detach(s->fs_thread);

	fs_debug (0, 1, "FS at %d.%d Server enabled", s->net, s->stn);

	return 1;
}

/*
 * fs_thread()
 *
 * Main fileserver thread.
 *
 * Takes mutex, initializes config, sets up discs, users, etc.
 *
 * In time, it will also
 * call the HPB function to request port &99 and
 * other ports which are fileserver-related.
 *
 * Sets enabled = 1
 *
 * Checks work queue & then does a pthread_cond_wait waiting
 * for traffic. It's timed, so that every 10 seconds it can
 * do a garbage collect as a minimum, and check to see whether
 * something changed enabled to 0, in which case it closes
 * all its handles and kicks everyone off (does fsop_shutdown()
 * essentially).
 *
 */

void *fsop_thread(void *p)
{
	struct __fs_station *s;

	s = (struct __fs_station *) p;

	pthread_mutex_lock (&(s->fs_mutex));

	fs_debug (0, 1, "FS at %d.%d (%s) running", s->net, s->stn, s->directory);

	/* Load config, initialize users (actives should be NULL anyway, either from fsop_initialize, or on fsop_shutdown),
	 * likewise files, bulkports should be null, and the load queue.
	 *
	 * Probably worth emptying the workqueue if there's anything on it (but there shouldn't be), then grab port
	 * &99 within the bridge and sit and wait for traffic.
	 *
	 * Loop round with a cond_wait 10 seconds, check for enabled going to 0 (and if so, do a clean shutdown and
	 * exit the thread), deal with any traffic on the queue, garbage collect... and then sleep again.
	 *
	 * The main HPB will need to spot MachinePeek replies destined for this machine and call the function
	 * below to register the user's machine type & NFS version.
	 */

	while (1)
	{
		struct timespec		cond_time;
		struct __eb_packetqueue	*pq, *pqnext;
		struct __fs_active	*a;

		/* At top of loop, the lock is held - either because of the cond_wait, or because we grabbed it above */

		if (!s->enabled)
		{
			/* Something wants us to shut down - so sort that out */

			fs_debug (0, 1, "FS at %d.%d (%s) shutting down on request", s->net, s->stn, s->directory);
			
			fsop_shutdown(s);

			pthread_mutex_unlock(&(s->fs_mutex));

			eb_free (__FILE__, __LINE__, "FS", "Free FS config memory", s->config);

			/* Note, don't free the __fs_station - that stays around while the bridge is running. 
			 * Otherwise we can't tell if enabled is set or not! 
			 */

			return NULL;

		}

		/* Handle work on the workqueue here - which will include ACK & NAK for load_queue traffic triggers */
		 
		pq = s->fs_workqueue;

		fs_debug (0, 4, "FS at %d.%d processing work queue at %p", s->net, s->stn, pq);

		while (pq)
		{
			pqnext = pq->n;

			a = fsop_stn_logged_in(s, pq->p->p.srcnet, pq->p->p.srcstn);

			fs_debug (0, 4, "FS at %d.%d processing work queue at %p - packet at %p length %d from %d.%d", s->net, s->stn, pq, pq->p, pq->length, pq->p->p.srcnet, pq->p->p.srcstn);

			switch (pq->p->p.aun_ttype)
			{
		   		case ECONET_AUN_NAK: // If there's an extant queue and we got a NAK matching its trigger sequence, dump the queue - the station has obviously stopped wanting our stuff
				{
					struct load_queue *l;
	
					l = s->fs_load_queue;
	
					// See if there is a matching queue
	
					while (l && a)
					{
						if (l->active == a 
						&& l->ack_seq_trigger == pq->p->p.seq
						)
						{
							/* GOT HERE */
							if (l->queue_type == FS_ENQUEUE_LOAD)
								fsop_close_interlock(s, l->internal_handle, l->mode);
	
							fsop_enqueue_dump(l);

							break;
						}
						else
							l = l->next;
	
					}
				}
				break;

				case ECONET_AUN_ACK:
				{
					fsop_load_dequeue(s, pq->p->p.srcnet, pq->p->p.srcstn, pq->p->p.seq);
				}
					break;

				case ECONET_AUN_BCAST:
				case ECONET_AUN_DATA:
					fsop_port99(s, pq->p, pq->length);
					break;
	
			}

			eb_free(__FILE__, __LINE__, "FS", "Free FS packet after processing", pq->p);
			eb_free(__FILE__, __LINE__, "FS", "Free FS packet queue entry after processing", pq);

			s->fs_workqueue = pq = pqnext;
	
		}

		/* Garbage collect here */

		fsop_garbage_collect(s);

		/* Cond wait 10 seconds */

		fs_debug (0, 4, "FS at %d.%d sleeping", s->net, s->stn);

		clock_gettime(CLOCK_REALTIME, &cond_time);
		cond_time.tv_sec += 10;
		pthread_cond_timedwait(&(s->fs_condition), &(s->fs_mutex), &cond_time);
	}

}

/*
 * fsop_register_machine()
 *
 * Called by HPB when it sees a MachinePeek reply coming to this emulated machine.
 *
 * Helps the FS to ascertain machine type at logon
 *
 */

void * fsop_register_machine(struct __fs_machine_peek_reg *p)
{
	struct __fs_machine_peek_reg	*search;

	/* We need the lock. Considered if this risked deadlock, but
	 * I don't think it does because the FS will eventually unlock this and
	 * that will free up this routine to complete and return to the HPB
	 *
	 * Plus, most such replies will arrive in the snooze period while the FS
	 * thread is waiting on the condition after sending the MachinePeek
	 * query, whilst nothing is really going on in the FS.
	 *
	 */

	fs_debug_full (0, 2, p->s, p->net, p->stn, "Registering machine type %08X", p->mtype);

	pthread_mutex_lock(&(p->s->fs_mpeek_mutex));

	search = p->s->peeks;

	/* If this station is still in the peeks list for this server,
	 * update the mytype from our info.
	 */

	while (search)
	{
		if (search->net == p->net && search->stn == p->stn)
		{
			search->mtype = p->mtype;
			break;
		}
		else
			search = search->next;
	}

	pthread_mutex_unlock(&(p->s->fs_mpeek_mutex));

	pthread_cond_signal(&(p->s->fs_condition));

	eb_free (__FILE__, __LINE__, "FS", "Freeing machine peek structure we just registered", p);

	return NULL;

}
