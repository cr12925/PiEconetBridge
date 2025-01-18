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

uint8_t fs_set_syst_bridgepriv = 0; // If set to 1 by the HP Bridge, then on initialization, each FS will enable the bridge priv on its SYST user
short fs_sevenbitbodge; // Whether to use the spare 3 bits in the day byte for extra year information
short use_xattr=1 ; // When set use filesystem extended attributes, otherwise use a dotfile
short normalize_debug = 0; // Whether we spew out loads of debug about filename normalization

//struct __fs_station	*fileservers; /* Set to NULL in fs_setup() */

// Parser
//#define FS_PARSE_DEBUG 1
uint8_t fs_parse_cmd (char *, char *, unsigned short, char **);

/* 
 * List of FSOps in our new list form
 */

struct fsop_list fsops[255]; 

regex_t r_discname, r_wildcard;

extern void eb_debug_fmt (uint8_t, uint8_t, char *, char *);

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
	if (net != 0)
		sprintf (padstr, "FS       %3d.%3d from %3d.%3d %s", s->net, s->stn, net, stn, str);
	else
		sprintf (padstr, "FS       %3d.%3d %s", s->net, s->stn, str);

	eb_debug_fmt (death, level, "FS", padstr);

	va_end(ap);
}

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
	//if (server->config->fs_manyhandle)	*params |= FS_CONFIG_MANYHANDLE;
	if (server->config->fs_mdfsinfo)	*params |= FS_CONFIG_MDFSINFO;
	if (server->config->fs_pifsperms)	*params |= FS_CONFIG_PIFSPERMS;
	if (server->config->fs_mask_dir_wrr)	*params |= FS_CONFIG_MASKDIRWRR;
}

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
	//server->config->fs_manyhandle = (params & FS_CONFIG_MANYHANDLE) ? 1 : 0;
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

	// No longer required - mmaped: fsop_write_server_config(server);

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
	username[10] = '\0';
}

void fsop_get_username_lock (struct __fs_active *a, char *username)
{
	pthread_mutex_lock(&(a->server->fs_mutex));
	fsop_get_username_base (a->server, a->userid, username);
	pthread_mutex_unlock(&(a->server->fs_mutex));
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

	memcpy(dst, src, strlen(src));
	//strncpy(dst, src, maxlen);

	*(dst + maxlen) = '\0';

	for (count = maxlen-1; count > 0; count--)
		if (*(dst + count) == '\0') *(dst + count) = ' ';

	//if (maxlen < ECONET_ABS_MAX_FILENAME_LENGTH)
	//{
		for (count = strlen(src); count < maxlen; count++)
			*(dst+count) = ' ';
	//}
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

	if (s->config->fs_sjfunc && (fs_perm & FS_PERM_H)) // SJ research Privacy bit
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
	uint8_t	m;

	m = monthyear & 0x0f;

	return (m ? m : 1);
}

uint8_t fs_day_from_two_bytes(uint8_t day, uint8_t monthyear)
{
	uint8_t d;

	d = day & 0x1f;

	return (d ? d : 1);
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

/* Translate an mtype machine type to string *
 *
 */

unsigned char * fsop_machine_type_str (uint16_t t)
{

	uint16_t	a;

	a = ((t & 0xFF00) >> 8) | ((t & 0xFF) << 8);

	switch (a)
	{
		case 0x0001: return "BBC Microcomputer"; break;
		case 0x0002: return "Acorn Atom"; break;
		case 0x0003: return "Acorn System 3 or 4"; break;
		case 0x0004: return "Acorn System 5"; break;
		case 0x0005: return "BBC Master 128"; break;
		case 0x0006: return "Acorn Electron"; break;
		case 0x0007: return "Acorn Archimedes"; break;
		case 0x0008: return "Acorn (Reserved)"; break;
		case 0x0009: return "Acorn Communicator"; break;
		case 0x000A: return "Master ET"; break;
		case 0x000B: return "Acorn Filestore"; break;
		case 0x000C: return "Master 128 Compact"; break;
		case 0x000D: return "Acorn Ecolink PC Card"; break;
		case 0x000E: return "Acorn Unix(R) workstation"; break;
		case 0x000F: return "Acorn RISC PC"; break;
		case 0x0010: return "CTL Iyonix"; break;
		case 0x0011: return "Acorn A9"; break;
		case 0x1040: return "JGH Spectrum"; break;
		case 0x1041: return "JGH Amstrad CPC"; break;
		case 0x5050: return "PB Internet Gateway"; break;
		case 0xEEEE: return "Raspbery Pi Econet Bridge"; break;
		case 0xFFF8: return "SJ GP Server"; break;
		case 0xFFF9: return "SJ 80386 Unix"; break;
		case 0xFFFA: return "SCSI Interface"; break;
		case 0xFFFB: return "SJ IBM PC Econet Interface"; break;
		case 0xFFFC: return "Nascom 2"; break;
		case 0xFFFD: return "Research Machines 480Z"; break;
		case 0xFFFE: return "SJ Fileserver"; break;
		case 0xFFFF: return "Z80 CP/M"; break;
		default: return "Unknown machine"; break;
	}

	return "Unknown machine";
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
		fprintf (out, "\n\n    %04X %s %d.%d", active->userid, username, active->net, active->stn);

		if (active->machinepeek) // I.e. non-zero
		{
			fprintf (out, " (%s version %02X.%02X)",
				fsop_machine_type_str ((active->machinepeek & 0xFFFF0000) >> 16),
				(active->machinepeek & 0xFF),
				(active->machinepeek & 0xFF00) >> 8
				);
		}

		fprintf (out, "\n    Databurst chucnk size: &%04X", active->chunk_size);

		fprintf (out, "\n\n");
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

// Find a user file channel
// Gives 0 on failure
uint8_t fsop_allocate_user_file_channel(struct __fs_active *a)
{
	uint8_t count; // f is index into fs_files[server]

	count = 1; // Don't want to feed the user a directory handle 0

	while ((a->fhandles[count].is_dir || a->fhandles[count].handle) && count < FS_MAX_OPEN_FILES)
		count++;

	if (count >= (a->manyhandles ? FS_MAX_OPEN_FILES : 9)) return 0; // No handle available - if not in manyhandle mode, >= 9 is what we need because we can allocate up to and including 8

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

	if (count >= (a->manyhandles ? FS_MAX_OPEN_FILES : 9)) return 0; // No handle available - see comment in the user file allocator for why this is 9

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

void fsop_get_create_time (unsigned char *path, uint8_t *day, uint8_t *myear, uint8_t *hour, uint8_t *min, uint8_t *sec)
{
	unsigned char	tmp[11];

	*day = *myear = *hour = *min = *sec = 0;

	if (getxattr((const char *) path, "user.econet_birth", tmp, 10) >= 0)
	{
		unsigned char	day_s[3], myear_s[3], hour_s[3], min_s[3], sec_s[3];
		memcpy(day_s, tmp, 2);
		memcpy(myear_s, &(tmp[2]), 2);
		memcpy(hour_s, &(tmp[4]), 2);
		memcpy(min_s, &(tmp[6]), 2);
		memcpy(sec_s, &(tmp[8]), 2);
		day_s[2] = myear_s[2] = hour_s[2] = min_s[2] = sec_s[2] = 0;
		*day = strtoul(day_s, 0, 16);
		*myear = strtoul(myear_s, 0, 16);
		*hour = strtoul(hour_s, 0, 10);
		*min = strtoul(min_s, 0, 10);
		*sec = strtoul(sec_s, 0, 10);
	}
}

void fsop_set_create_time (unsigned char *path, uint8_t day, uint8_t myear, uint8_t hour, uint8_t min, uint8_t sec)
{
	unsigned char	tmp[11];

	snprintf(tmp, 11, "%02X%02X%02d%02d%02d", day, myear, hour, min, sec);

	setxattr((const char *) path, "user.econet_birth", (const void *) tmp, 10, 0);

}

void fsop_set_create_time_now (unsigned char *path)
{

	struct tm t; 
	unsigned char day, monthyear;
	time_t now;

	now = time(NULL);
	t = *localtime(&now);

	fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);

	fsop_set_create_time(path, day, monthyear, t.tm_hour, t.tm_min, t.tm_sec);
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

	sprintf ((char * ) attrbuf, "%02X", (perm & 0xff));
	if (setxattr((const char *) path, "user.econet_perm", (const void *) attrbuf, 2, 0)) // Flags = 0 means create if not exist, replace if does
		fs_debug (0, 1, "Failed to set permission on %s\n", path);

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

int fs_get_wildcard_entries (struct fsop_data *f, int userid, char *haystack, char *needle, struct path_entry **head, struct path_entry **tail, uint8_t *max_fname_length)
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

	*max_fname_length = 0;

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

			uint8_t		fname_length;

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
	
			/* Track max filename length in this selection, goes back into the path structure from calling function
			 * to enable padding to be tailored.
			 */

			if ((fname_length = strlen(new_p->acornname)) > *max_fname_length)
				*max_fname_length = fname_length;

			sprintf (new_p->unixpath, "%s/%s", haystack, new_p->unixfname);
	
			if (stat(new_p->unixpath, &statbuf) != 0) // Error
			{
				fs_debug (0, 2, "Unable to stat %s", new_p->unixpath);
				if (new_p->parent)
				{
					new_p->parent->next = NULL;
					*tail = new_p->parent;
				}
				else	
					*head = *tail = NULL;

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
#if 0
			localtime_r(&(statbuf.st_ctime), &ct);
			fs_date_to_two_bytes(ct.tm_mday, ct.tm_mon+1, ct.tm_year, &(p->c_monthyear), &(p->c_day));
			p->c_hour = ct.tm_hour;
			p->c_min = ct.tm_min;
			p->c_sec = ct.tm_sec;
#endif
			fsop_get_create_time(p->unixpath, &(p->c_day), &(p->c_monthyear), &(p->c_hour), &(p->c_min), &(p->c_sec));
	
			p->internal = statbuf.st_ino;
			strncpy(p->ownername, f->server->users[p->owner].username, 10);
			p->ownername[10] = '\0';
	
		} // End of name length if() above

		counter++;
	}

#if 0
	{
		struct path_entry *p2;

		p2 = *head;

		while (p2)
		{
			fprintf (stderr, "Path entry at %p: %s unixpath, next = %p, parent = %p\n", p2, p2->unixpath, p2->next, p2->parent);
			p2 = p2->next;
		}
	}
#endif


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
	result->max_fname_length = 0; // Stores maximum filename length for display purposes

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
#if 0	
			// Create time
			localtime_r(&(s.st_ctime), &t);
			fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_monthyear), &(result->c_day));
			result->c_hour = t.tm_hour;
			result->c_min = t.tm_min;
			result->c_sec = t.tm_sec;
#endif
			fsop_get_create_time(result->unixpath, &(result->c_day), &(result->c_monthyear), &(result->c_hour), &(result->c_min), &(result->c_sec));
			
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
			int error;

			if ((error = regexec(&(f->server->r_pathname), adjusted + ptr, 1, matches, 0)) == 0)
			{
				strncpy((char * ) result->path[result->npath], (const char * ) adjusted + ptr, matches[0].rm_eo - matches[0].rm_so);
				*(result->path[result->npath++] + matches[0].rm_eo - matches[0].rm_so) = '\0';
				ptr += (matches[0].rm_eo - matches[0].rm_so);
			}
			else
			{
				unsigned char 	errstr[1024];
				regerror(error, &(f->server->r_pathname), errstr, 1024);

				result->error = FS_PATH_ERR_FORMAT;
				if (normalize_debug) fs_debug (0, 1, "Returning path format error - regex match failed matching: error string: %s, adjusted = '%s', +ptr = '%s' (len: %d)", errstr, adjusted, adjusted + ptr, strlen(adjusted + ptr));
				/*
				{
					int c;
					for (c = 0; c < strlen(adjusted + ptr); c++)
						fs_debug (0, 1, "%02d = %02X %c", c, *(adjusted + ptr+ c), *(adjusted + ptr + c));
				}
				*/
				return 0; // bad path	
			}
	
			if (ptr != strlen((const char *) adjusted) && *(adjusted + ptr) != '.') // Bad path - must have a dot next, otherwise the path element must be more than ten characters
			{
				if (normalize_debug) fs_debug (0, 1, "Returning path format error");
				result->error = FS_PATH_ERR_FORMAT;
				return 0;
			}
			else if (ptr != strlen((const char *) adjusted) && strlen((const char *) adjusted) == (ptr + 1)) // the '.' was at the end
			{
				if (normalize_debug) fs_debug (0, 1, "Returning path format error - trailing '.'");
				result->error = FS_PATH_ERR_FORMAT;
				return 0;
			}
			else 	ptr++; // Move to start of next portion of path
		}
	}

	if (ptr < strlen((const char *) adjusted))
	{
		if (normalize_debug) fs_debug (0, 1, "Returning path length error");
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

#if 0
		// Create time
		localtime_r(&(s.st_ctime), &t);
		fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_monthyear), &(result->c_day));
		result->c_hour = t.tm_hour;
		result->c_min = t.tm_min;
		result->c_sec = t.tm_sec;
#endif
		fsop_get_create_time(result->unixpath, &(result->c_day), &(result->c_monthyear), &(result->c_hour), &(result->c_min), &(result->c_sec));
		

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
					&(result->paths), &(result->paths_tail), &(result->max_fname_length));

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
#if 0
				localtime_r(&(s.st_ctime), &t);

				fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(result->c_day), &(result->c_monthyear));
				result->c_hour = t.tm_hour;
				result->c_min = t.tm_min;
				result->c_sec = t.tm_sec;
#endif
				fsop_get_create_time(result->unixpath, &(result->c_day), &(result->c_monthyear), &(result->c_hour), &(result->c_min), &(result->c_sec));

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
			result->max_fname_length = strlen(result->acornname); // Only one result, so give its length

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

	if (!s)
		return 0;

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

	server = eb_malloc(__FILE__,__LINE__,"FS","New fileserver struct", sizeof(struct __fs_station));
	//FS_LIST_MAKENEW(struct __fs_station, fileservers, 1, server, "FS", "Initialize new server struct");
        server->net = device->net;
        server->stn = device->local.stn;
        strcpy (server->directory, directory);
        server->config = NULL;
        server->discs = NULL;
        server->files = NULL;
        server->actives = NULL;
        server->users = NULL;
        server->enabled = 0;
        // server->fs_load_queue = NULL;
        server->fs_device = device;
        server->fs_workqueue = NULL;
	server->peeks = NULL;
        /* Don't touch next, prev - they'll be initialized by the list management macros */

        /* Don't do anything with fs_thread - fsop_run() sets that up */

	fs_debug_full (0, 2, server, 0, 0, "Attempting to initialize at %s", server->directory);

	// Ensure serverparam begins with /
	if (*directory != '/')
	{
		//FS_LIST_SPLICEFREE(fileservers,server,"FS","Destroy FS struct on failed init");
		eb_free(__FILE__, __LINE__, "FS","Destroy FS struct on failed init", server);

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
		fs_debug_full (0, 1, server, 0, 0, "Automatically turned on -x mode because of %s", autoinf);
		use_xattr = 0;
	}

	free(autoinf);

	d = opendir(server->directory);

	if (!d)
		fs_debug_full (1, 1, server, 0, 0, "Unable to open root directory %s", server->directory);
	else
	{

		FILE * cfgfile;
		uint8_t	setconfigdefaults = 0;
		uint16_t configlen;

		//server->config = eb_malloc(__FILE__, __LINE__, "FS", "Allocate FS config struct", sizeof(struct __fs_config));
		//memset(server->config, 0, sizeof(struct __fs_config));

		sprintf(passwordfile, "%s/Configuration", server->directory);
		cfgfile = fopen(passwordfile, "r+");

		//fs_debug (0, 1, "Configuration at %s opened", passwordfile);

		if (!cfgfile) // Config file not present
		{
			if ((cfgfile = fopen(passwordfile, "w+")))
				fwrite(server->config, 256, 1, cfgfile);
			else fs_debug_full (0, 1, server, 0, 0, "Unable to write configuration file at %s - not initializing", passwordfile);

			setconfigdefaults = 1;

			fsop_write_readable_config(server);
		}

		fseek(cfgfile, 0, SEEK_END);
		configlen = ftell(cfgfile);
		rewind(cfgfile);

		if (configlen != 256)
			fs_debug_full (1, 0, server, 0, 0, "FS Configuration file %s is incorrect length!", passwordfile);

	 	server->config = mmap(NULL, 256, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(cfgfile), 0);

		if (server->config == MAP_FAILED)
			fs_debug_full (1, 0, server, 0, 0, "Cannot mmap() FS config file %s (%s)", passwordfile, strerror(errno));
		
		fs_debug_full (0, 2, server, 0, 0, "Configuration file mapped");

		fclose(cfgfile);

		if (setconfigdefaults)
		{

			// Set up some defaults in case we are writing a new file
			server->config->fs_acorn_home = 0;
			server->config->fs_sjfunc = 1;
			server->config->fs_pwtenchar = 1;
			server->config->fs_fnamelen = FS_DEFAULT_NAMELEN;
			server->config->fs_mask_dir_wrr = 1;
			
			FS_CONF_DEFAULT_DIR_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;
			FS_CONF_DEFAULT_FILE_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R;
		}

		// Install some defaults if they need setting
		
		if (FS_CONF_DEFAULT_DIR_PERM(server) == 0x00) 
			FS_CONF_DEFAULT_DIR_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;

		if (FS_CONF_DEFAULT_FILE_PERM(server) == 0x00)
			FS_CONF_DEFAULT_FILE_PERM(server) = FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R; // NB OTH_R added here for backward compatibility. If this is a server where this default was unconfigured, we configure it to match what PiFS v2.0 did

		if (FS_CONFIG(server,fs_fnamelen) < 10 || FS_CONFIG(server,fs_fnamelen) > ECONET_ABS_MAX_FILENAME_LENGTH)
			server->config->fs_fnamelen = 10;

		// Filename regex compile moved here so we know how long the filenames are. We set this to maximum length because
		// the normalize routine sifts out maximum length for each individual server and there is only one regex compiled
		// because the scandir filter uses it, and that routine cannot take a server number as a parameter.

		sprintf(regex, "^(%s{1,%d})", FSACORNREGEX, ECONET_ABS_MAX_FILENAME_LENGTH);

		if (regcomp(&(server->r_pathname), regex, REG_EXTENDED) != 0)
			fs_debug_full (1, 0, server, 0, 0, "Unable to compile regex for file and directory names.");

		// Load / Create password file

		sprintf(passwordfile, "%s/Passwords", server->directory);
	
		passwd = fopen(passwordfile, "r+");
		
		if (!passwd)
		{
			struct __fs_user	u;

			fs_debug_full (0, 1, server, 0, 0, "No password file - initializing %s with SYST", passwordfile);
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
			else fs_debug_full (0, 1, server, 0, 0, "Unable to write password file at %s - not initializing", passwordfile);
		}

		if (passwd) // Successful file open somewhere along the line
		{
			fseek (passwd, 0, SEEK_END);
			length = ftell(passwd); // Get file size
			rewind(passwd);
	
			if ((length % 256) != 0)
				fs_debug_full (0, 1, server, 0, 0, "Password file not a multiple of 256 bytes!");
			else if ((length > (256 * ECONET_MAX_FS_USERS)))
				fs_debug_full (0, 1, server, 0, 0, "Password file too long!");
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
				
				fs_debug_full (0, 2, server, 0, 0, "Password file read - %d user(s)", (length / 256));
				server->users = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(passwd), 0);
				if (server->users == MAP_FAILED)
					fs_debug_full (1, 0, server, 0, 0, "Cannot mmap() password file (%s)", strerror(errno));

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

					/* No longer required - now mmap()ed 
					rewind(cfgfile);
					fwrite (server->config, 256, 1, cfgfile);
					rewind(cfgfile);
					*/

					fs_debug_full (0, 1, server, 0, 0, "Updated password file for 10 character passwords, and backed up password file to %s", passwordfilecopy);
				}

				/* Closed above */
				//fclose (cfgfile);

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
						struct __fs_disc	*d, *p;

						// readdir() doesn't guarantee ordering, so we need to do it ourselves

						d = eb_malloc(__FILE__, __LINE__, "FS", "New disc structure", sizeof(struct __fs_disc));
						
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
					
						/* Put d into the list at the right place */

						p = server->discs;

						while (p && p->index < index)
							p = p->next;

						if (!server->discs)
						{
							d->next = d->prev = NULL;
							server->discs = d;
						}
						else if (!p) /* Fell off end */
						{
							p = server->discs;
							while (p && p->next)
								p = p->next;
							p->next = d;
							d->prev = p;
							d->next = NULL;
						}
						else
						{
							/* Splice in before this one */
							 
							if (p->prev) /* Not at head */
							{
								d->next = p;
								d->prev = p->prev;
								p->prev = d;
								d->prev->next = d;
							}
							else /* p is head of queue */
							{
								server->discs = d;
								d->prev = NULL;
								d->next = p;
								p->prev = d;
							}
						}

						server->total_discs++;
	
					}
				}

				closedir(d);
		
				if (server->total_discs > 0)
				{
					struct __fs_disc *d;

					d = server->discs;

					while (d)
					{
						fs_debug_full (0, 2, server, 0, 0, "Initialized disc name %s (%d)", d->name, d->index);
						d = d->next;
					}

					// Load / Initialize groups file here - TODO
					unsigned char groupfile[1024];
					FILE *group;

					sprintf(groupfile, "%s/Groups", server->directory);
	
					group = fopen(groupfile, "r+");

					if (!group) // Doesn't exist - create it
					{

						struct __fs_group g;

						memset (&g, 0, sizeof(g));

						fs_debug_full (0, 1, server, 0, 0, "No group file at %s - initializing", groupfile);

						if ((group = fopen(groupfile, "w+")))
							fwrite(&g, sizeof(struct __fs_group), 256, group);

						else fs_debug_full (0, 1, server, 0, 0, "Unable to write group file at %s - not initializing", groupfile);
					}

					if (group) // Got it somehow - created or it existed
					{

						int length; 

						fseek (group, 0, SEEK_END);
						length = ftell(group); // Get file size
						rewind(group);

						if (length != 2560)
							fs_debug_full (0, 1, server, 0, 0, "Group file is wrong length / corrupt - not initializing");
						else
						{
							server->groups = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(group), 0);
							server->total_groups = length;
							server->enabled = 0;
						}

						fclose(group);
					}
					else fs_debug_full (0, 1, server, 0, 0, "Server failed to initialize - cannot initialize or find Groups file!");

					// (If there was still no group file here, fs_count won't increment and we don't initialize)
				}
				else fs_debug_full (0, 1, server, 0, 0, "Server failed to find any discs!");
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
                //FS_LIST_SPLICEFREE(fileservers, server, "FS", "Free fileserver control structure after failed mutex init");
		eb_free(__FILE__, __LINE__, "FS","Destroy FS struct on failed mutex init", server);
                return NULL;
        }

        if (pthread_mutex_init(&server->fs_mpeek_mutex, NULL) == -1)
        {
                //FS_LIST_SPLICEFREE(fileservers, server, "FS", "Free fileserver control structure after failed mpeek mutex init");
		eb_free(__FILE__, __LINE__, "FS","Destroy FS struct on failed mpeek mutex init", server);
                return NULL;
        }

        if (pthread_cond_init(&server->fs_condition, NULL) == -1)
        {
                //FS_LIST_SPLICEFREE(fileservers, server, "FS", "Free fileserver control structure after failed cond init");
		eb_free(__FILE__, __LINE__, "FS","Destroy FS struct on failed condition init", server);
                return NULL;
        }

        /* Don't do anything with fs_thread - fsop_run() sets that up */

	fs_debug_full (0, 2, server, 0, 0, "Server successfully initialized at %s", server->directory);

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
	//struct load_queue	*l;
	struct __fs_bulk_port	*bulk;
	//struct __eb_packetqueue *pq;

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
		fs_debug_full (0, 1, s, 0, 0, "Server was left with one or more active users after shutdown!");

	if (s->files) /* This should not have anything in it after everyone has been logged off! */
		fs_debug_full (0, 1, s, 0, 0, "Server was left with one or more open files after shutdown!");

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

	/* Next clean up the bulk ports */

	bulk = s->bulkports;

	while (bulk)
	{
		struct __fs_bulk_port *bn;

		bn = bulk->next;

		eb_port_deallocate(s->fs_device, bulk->bulkport);

		fs_debug_full (0, 3, s, 0, 0, "FS", "Server freeing bulk port entry at %p on shutdown", bulk);

		bulk = bn;

	}

	s->bulkports = NULL;

	/* Unmap users and groups */

	if (s->users)
		munmap(s->users, 256 * s->total_users); 

	if (s->groups)
		munmap(s->groups, 10 * s->total_groups);

	s->users = NULL;
	s->groups = NULL;

	/* Free the config struct */

	munmap(s->config, 256);

	fs_debug_full (0, 1, s, 0, 0, "             Server has shut down");

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

	int count;
	struct __fs_station *s; 
	struct __econet_packet_udp reply;
	struct __fs_active_load_queue *alq;
	struct __fs_bulk_port *bp;

	fs_debug_full (0, 1, a->server, a->net, a->stn, "Bye");

	s = a->server;

	reply.p.ptype = ECONET_AUN_DATA;
	reply.p.ctrl = 0x80;
	reply.p.port = reply_port;
	reply.p.data[0] = reply.p.data[1] = 0;

	/* Clean up any bulk ports or load queues */

	alq = a->load_queue;

	while (alq)
	{
		struct __fs_active_load_queue *n;

		n = alq->next;

		FS_LIST_SPLICEFREE(a->load_queue,alq,"FS","Free load queue entry on *BYE");

		alq = n;

		/* Note: the clean up below will actually close the files */
	}

	/* Clean up any bulk ports which are ours */
	
	bp = a->server->bulkports;

	while (bp)
	{
		struct __fs_bulk_port *n;

		n = bp->next;

		if (bp->active == a) // It's ours
		{
			eb_port_deallocate(a->server->fs_device, bp->bulkport);
			/* Routine below will close the file */
			FS_LIST_SPLICEFREE(a->server->bulkports,bp,"FS","Free bulk port structure on *BYE");
		}

		bp = n;
	}

	// Close active files / handles
	
	count = 1;
	while (count < FS_MAX_OPEN_FILES)
	{
		if (a->fhandles[count].handle)
		{
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

	fs_debug_full (0, 2, s, 0, 0, "             Interlock close internal handle: mode %d. Readers now = %d, Writers now = %d, path %s", mode, file->readers, file->writers, file->name);

	// Safety valve here - only close when both are 0, not <= 0
	// Otherwise we sometimes overclose - e.g. in the fs_garbage_collect() routine
	
	if (file->readers == 0 && file->writers == 0)
	{
		fs_debug_full (0, 2, s, 0, 0, "             Interlock closing internal handle for %s in operating system", file->name);
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

/*
 * fsop_bulk_dequeue()
 *
 * Responds to ACKs coming from client stations.
 * Checks to see if any file data needs to be sent
 * on a databurst, and (if it's at the end) sends the
 * closing packet on the databurst.
 */

void fsop_bulk_dequeue (struct __fs_station *s, uint8_t net, uint8_t stn, uint32_t seq)
{
	struct __fs_active	*a;
	struct __fs_active_load_queue	*alq;

	a = fsop_find_active(s, net == 0 ? s->net : net, stn);

	if (!a) /* No user! */
		return;

	alq = a->load_queue;

	while (alq)
	{
		if (alq->ack_seq_trigger == seq) /* Found */
			break;
		else	alq = alq->next;
	}

	if (!alq) /* No load queue found */
		return;

	/* Update last rx time */

	alq->last_ack_rx = time(NULL); /* Now */

	if (alq->sent_bytes == alq->send_bytes) /* We've sent what was asked */
	{
		struct __econet_packet_udp	*reply;

		reply = eb_malloc(__FILE__, __LINE__, "FS", "Allocate FS bulk transfer completion packet", 18); /* 18 is max size - 12 + 6 data */

		reply->p.ctrl = alq->ctrl;
		reply->p.ptype = ECONET_AUN_DATA;
		reply->p.port = alq->client_finalackport;

		reply->p.data[0] = reply->p.data[1] = 0x00;

		if (alq->queue_type == FS_ENQUEUE_LOAD)
		{
			//fs_debug_full (0, 2, s, a->net, a->stn, "About to send termination for load - __fs_file entry is %p, FILE * is %p", alq->internal_handle, alq->internal_handle->handle);
			fsop_close_interlock(s, alq->internal_handle, alq->mode);
			raw_fsop_aun_send(reply, 2, s, a->net, a->stn);
		}
		else
		{
			reply->p.data[2] = (alq->pasteof) ? 0x80 : 0x00;
			reply->p.data[3] = (alq->valid_bytes & 0xFF);
			reply->p.data[4] = (alq->valid_bytes & 0xFF00) >> 8;
			reply->p.data[5] = (alq->valid_bytes & 0xFF0000) >> 16;

			raw_fsop_aun_send(reply, 6, s, a->net, a->stn);
		}

		eb_free(__FILE__, __LINE__, "FS", "Deallocate bulk transfer completion packet after transmission", reply);

		FS_LIST_SPLICEFREE(a->load_queue, alq, "FS", "Freeing load queue struct on data burst completion");
	}
	else
	{
		/* Must still be bytes to send */

		struct __econet_packet_udp	*reply;

		uint32_t	bytes_required;
		int		bytes_read;

		bytes_required = (alq->send_bytes - alq->sent_bytes);

		if (bytes_required > alq->chunk_size)
			bytes_required = alq->chunk_size; /* Clamp to maximum client can handle */

		reply = eb_malloc(__FILE__, __LINE__, "FS", "Allocate FS bulk transfer data packet", 12 + bytes_required); 

		reply->p.port = alq->client_dataport;
		reply->p.seq = eb_get_local_seq(s->fs_device);
		reply->p.ctrl = 0x80;
		reply->p.ptype = ECONET_AUN_DATA;

		alq->ack_seq_trigger = reply->p.seq;

		if (alq->pasteof)
			bytes_read = 0;
		else
		{
			//fs_debug_full (0, 2, s, a->net, a->stn, "About to read data - __fs_file entry is %p, FILE * is %p", alq->internal_handle, alq->internal_handle->handle);
			fseek(alq->internal_handle->handle, alq->cursor, SEEK_SET);
			bytes_read = fread(&(reply->p.data), 1, bytes_required, alq->internal_handle->handle);

			if (feof(alq->internal_handle->handle))
				alq->pasteof = 1;

			if (bytes_read < 0) /* Error */
			{
				if (alq->queue_type == FS_ENQUEUE_LOAD)
					fsop_close_interlock(s, alq->internal_handle, alq->mode);

				fs_debug_full(0, 1, a->server, a->net, a->stn, "Data burst file read failed!");
				FS_LIST_SPLICEFREE(a->load_queue, alq, "FS", "Freeing load queue struct on data burst read failure");

				return;
			}
		}

		/* Send what we've got */

		alq->sent_bytes += bytes_required;
		alq->valid_bytes += bytes_read;
		alq->cursor += bytes_read;

		/* Update user cursor if this is getbytes */
		 
		if (alq->queue_type == FS_ENQUEUE_GETBYTES)
			a->fhandles[alq->user_handle].cursor = alq->cursor;

		/* the old system used to set the data area from bytes_read+1 to bytes_required to 0, but
		 * it probably doesn't matter 
		 */

		raw_fsop_aun_send_noseq(reply, bytes_required, s, a->net, a->stn);

		eb_free (__FILE__, __LINE__, "FS", "Free databurst packet after transmission", reply);
	}

	return;

}

/*
 * fsop_get_user_printer()
 *
 * Returns the current printer index for
 * a fileserver user. Used by the printserver
 * within the main HPB.
 *
 */

int8_t fsop_get_user_printer(struct __fs_active *a)
{
	uint8_t	p;

	pthread_mutex_lock(&(a->server->fs_mutex));
	p = a->printer;
	pthread_mutex_unlock(&(a->server->fs_mutex));

	return p;
}

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

void fsop_handle_bulk_traffic(struct __econet_packet_aun *p, uint16_t len, void *param)
{

	struct __econet_packet_udp	r;
	struct __fs_bulk_port	*bp;
	struct __fs_station 	*s = (struct __fs_station *) param;

	off_t	 writeable, remaining, old_cursor, new_cursor, new_cursor_read;
	FILE 	*h;
	uint16_t	datalen = (len - 12);

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

		fs_debug_full (0, 1, s, 0, 0, "Dumped traffic arriving on unknown bulk port &%02X", p->p.port);
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

	fs_debug_full (0, 2, s, bp->active->net, bp->active->stn, "Bulk transfer in on port &%02X data length &%04X, expected total length &%04lX, writeable &%04X", bp->bulkport, datalen, bp->length, writeable
			);
	if (bp->is_gbpb) // Produce additional debug
		fs_debug_full (0, 2, s, bp->active->net, bp->active->stn, "Bulk trasfer on port %02X old cursor = %06X, new cursor in FS = %06X, new cursor from OS = %06X - %s", bp->bulkport, old_cursor, new_cursor, new_cursor_read, (new_cursor == new_cursor_read) ? "CORRECT" : " *** ERROR ***");

	bp->last_receive = (unsigned long long) time(NULL);

	if (bp->received == bp->length) // Finished
	{

		// Send a closing ACK

		struct tm t; 
		unsigned char day, monthyear;
		time_t now;

		fs_debug_full (0, 2, s, bp->active->net, bp->active->stn, "Bulk transfer in on port &%02X has completed: expected total length &%04lX, received &%04lX", bp->bulkport, bp->length, bp->received);

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

		/*
		 * Deallocate the port
		 */

		eb_port_deallocate(bp->active->server->fs_device, bp->bulkport);

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

	//struct load_queue *l; // Load queue pointer
	struct __fs_bulk_port	*p; // Bulk port pointer
	struct __fs_active_load_queue	*alq; // load queue in a user active struct
	struct __fs_active	*a; // Current user traverse

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
				fs_debug_full (0, 2, s, p->active->net, p->active->stn, "Garbage collector did not close bulk port %d because it had already closed.", p->bulkport);
			}
			FS_LIST_SPLICEFREE(s->bulkports, p, "FS", "Deallocate bulk port on garbage collect");
		}

		p = n;

	}

	a = s->actives;

	while (a)
	{
		alq = a->load_queue;

		while (alq)
		{
			struct __fs_active_load_queue *n;

			n = alq->next;

			if (alq->last_ack_rx < (time(NULL) - 10)) /* 10 second timeout */
			{
				if (alq->queue_type == FS_ENQUEUE_LOAD) /* Close the handle */
				{
					fsop_close_interlock(s, alq->internal_handle, alq->mode);
					fs_debug_full (0, 1, s, a->net, a->stn, "Load operation failed - Client failed to acknowledge FS transmission");
				}
				else
					fs_debug_full (0, 1, s, a->net, a->stn, "OSGBPB operation failed - Client failed to acknowledge data on channel &%02X", alq->user_handle);
				
				FS_LIST_SPLICEFREE(a->load_queue, alq, "FS", "Freeing active load queue struct on ACK timeout from client in fsop_garbage_collect()");
				
			}

			alq = n;
		}

		a = a->next;
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

/*
 * fsop_write_readable_config()
 *
 * Writes a human readable config to
 * %root%/Configuration.txt - which can be
 * accessed by a client system user as
 * %CONFIG
 */

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

		if (active)
                {
			// Don't modify for LOAD, SAVE, RUNAS, (GETBYTE, PUTBYTE - not in this loop), GETBYTES, PUTBYTES - all of which either don't have the usual three handles in the tx block or use the URD for something else
                        if (	!(fsop == 1 || fsop == 2 || (fsop == 5) || (fsop >=10 && fsop <= 11)) ) 
				if (datalen >= 3) *(f->data+2) = FS_DIVHANDLE(active,*(f->data+2)); 

                        if (datalen >= 4) {
				*(f->data+3) = FS_DIVHANDLE(active,*(f->data+3));
				active->current = *(f->data+3); // Update so clients can open separate dirs and use them as CWD
			}

                        if (datalen >= 5) {
				*(f->data+4) = FS_DIVHANDLE(active,*(f->data+4));
				active->lib = *(f->data+4); // Update lib so client can open separate lib dirs and use them as LIB (e.g. as FindLib does)
			}
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

	pthread_mutex_lock(&(server->fs_mutex));

	fs_debug_full (0, 3, server, p->p.srcnet, p->p.srcstn,"FS processing traffic at %p lenght %d", p, length);

	q = server->fs_workqueue;

	while (q && q->n)
		q = q->n;

	if (!q)
		server->fs_workqueue = new_q;
	else
		q->n = new_q;

	fs_debug_full (0, 3, server, p->p.srcnet, p->p.srcstn,"FS processing traffic at %p length %d - now on queue (%p)", p, length, server->fs_workqueue);

	fs_debug_full (0, 3, server, p->p.srcnet, p->p.srcstn, "FS waking worker thread");

	pthread_mutex_unlock(&(server->fs_mutex));

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
		d = d->next;
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

	//fileservers = NULL;

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
	FSOP_SET (0e, (FSOP_F_NONE)); /* Read disc names */
	FSOP_SET (0f, (FSOP_F_LOGGEDIN)); /* Read logged on users */
	FSOP_SET (10, (FSOP_F_NONE)); /* Read time */
	FSOP_SET (11, (FSOP_F_LOGGEDIN)); /* Read EOF status */
	FSOP_SET (12, (FSOP_F_LOGGEDIN)); /* Read object info */
	FSOP_SET (13, (FSOP_F_LOGGEDIN)); /* Set object info */
	FSOP_SET (14, (FSOP_F_LOGGEDIN)); /* Delete object(s) */
	FSOP_SET (15, (FSOP_F_LOGGEDIN)); /* Read user env */
	FSOP_SET (16, (FSOP_F_LOGGEDIN)); /* Set Opt */
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
	FSOP_SET (2e, (FSOP_F_LOGGEDIN)); /* 32 bit Open */
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
	FSOP_OSCLI(INFO,(FSOP_00_LOGGEDIN), 1, 1, 1); /* Has to cope with stupid *i. from M128 */
	FSOP_OSCLI(LIB,(FSOP_00_LOGGEDIN), 0, 1, 3);
	FSOP_OSCLI(LINK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(LOAD,(FSOP_00_LOGGEDIN),1,2,2);
	FSOP_OSCLI(LOGIN,(FSOP_00_ANON),1,3,4);
	FSOP_OSCLI(LOGOFF,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 1, 4);
	FSOP_OSCLI(MKLINK,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 2, 2, 4);
	FSOP_OSCLI(NEWUSER,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 2, 4);
	FSOP_OSCLI(OWNER,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM),1,1,3);
	FSOP_OSCLI(PASS,(FSOP_00_LOGGEDIN),1,2,2);
	FSOP_OSCLI(PRINTER,(FSOP_00_LOGGEDIN),1,1,6);
	FSOP_OSCLI(PRINTOUT,(FSOP_00_LOGGEDIN), 1, 1, 6);
	FSOP_OSCLI(PRIV,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM),1,2,3);
	FSOP_OSCLI(RENAME,(FSOP_00_LOGGEDIN),2,2,3);
	FSOP_OSCLI(REMUSER,(FSOP_00_LOGGEDIN | FSOP_00_SYSTEM), 1, 1, 4);
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

	fs_debug_full (0, 2, s, 0, 0, "Attempting to enable server");

	pthread_mutex_lock (&(s->fs_mutex));

	if (s->enabled)
	{
		fs_debug_full (0, 1, s, 0, 0, "Server already enabled! Not bothering to start.");
		pthread_mutex_unlock (&(s->fs_mutex));
		return -1;
	}

	port = eb_port_allocate(s->fs_device, 0x99, fsop_handle_traffic, (void *) s);

	if (port != 0x99)
	{
		pthread_mutex_unlock (&(s->fs_mutex));
		fs_debug_full (1, 0, s, 0, 0, "Could not start - port &99 not available");
		return 0;
	}

	s->enabled = 1; /* Turn it on */
	
	pthread_mutex_unlock (&(s->fs_mutex));

	/* Create the thread & detach */

	err = pthread_create(&(s->fs_device->local.fs.fs_thread), NULL, fsop_thread, (void *) s);

	if (err)
	{
		fs_debug_full (1, 0, s, 0, 0, "Could not start - thread creation failed: %s", strerror(err));
		return 0;
	}

	pthread_detach(s->fs_device->local.fs.fs_thread);

	fs_debug_full (0, 2, s, 0, 0, "Server enabled");

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

	fs_debug_full (0, 1, s, 0, 0, "Server running");

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
			uint8_t	net, stn;

			net = s->net;
			stn = s->stn;

			fs_debug_full (0, 1, s, 0, 0, "             Shutting down on request");
			
			fsop_shutdown(s);

			s->fs_device->local.fs.server = NULL;

			fs_debug (0, 1, "     %3d.%3d Shut down completed", net, stn);

			// pthread_mutex_unlock(&(s->fs_mutex));

			/* Note, don't free the __fs_station - that stays around while the bridge is running. 
			 * Otherwise we can't tell if enabled is set or not! 
			 */

			pthread_exit(NULL);

		}

		/* Handle work on the workqueue here - which will include ACK & NAK for load_queue traffic triggers */
		 
		pq = s->fs_workqueue;

		fs_debug_full (0, 4, s, 0, 0, "Processing work queue at %p", pq);

		while (pq)
		{
			pqnext = pq->n;

			if (s->enabled)
			{
			
				a = fsop_stn_logged_in(s, pq->p->p.srcnet, pq->p->p.srcstn);

				fs_debug_full (0, 4, s, 0, 0, "Processing work queue at %p - packet at %p length %d from %d.%d", pq, pq->p, pq->length, pq->p->p.srcnet, pq->p->p.srcstn);

				switch (pq->p->p.aun_ttype)
				{
		   			case ECONET_AUN_NAK: // If there's an extant queue and we got a NAK matching its trigger sequence, dump the queue - the station has obviously stopped wanting our stuff
					{
#if 0
						/* Now disused */
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
#endif
						struct __fs_active_load_queue	*alq;

						alq = a->load_queue;

						while (alq)
						{
							if (alq->ack_seq_trigger == pq->p->p.seq) 
							{
								if (alq->queue_type == FS_ENQUEUE_LOAD)
									fsop_close_interlock(s, alq->internal_handle, alq->mode);

								FS_LIST_SPLICEFREE(a->load_queue, alq, "FS", "Freeing active load queue struct on NAK received");
								break;
							}
							else
								alq = alq->next;

						}
					}
					break;
	
					case ECONET_AUN_ACK:
					{
						fsop_bulk_dequeue(s, pq->p->p.srcnet, pq->p->p.srcstn, pq->p->p.seq);
					}
						break;
	
					case ECONET_AUN_BCAST:
					case ECONET_AUN_DATA:
						fsop_port99(s, pq->p, pq->length);
						break;
		
				}
	
			}

			eb_free(__FILE__, __LINE__, "FS", "Free FS packet after processing", pq->p);
			eb_free(__FILE__, __LINE__, "FS", "Free FS packet queue entry after processing", pq);

			s->fs_workqueue = pq = pqnext;
	
		}

		if (s->enabled) /* Don't sleep if we have been asked to shut down */
		{
			/* Garbage collect here */

			fsop_garbage_collect(s);

			/* Cond wait 10 seconds */

			fs_debug_full (0, 4, s, 0, 0, "Sleeping");

			clock_gettime(CLOCK_REALTIME, &cond_time);
			cond_time.tv_sec += 10;
			pthread_cond_timedwait(&(s->fs_condition), &(s->fs_mutex), &cond_time);
		}
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

	fs_debug_full (0, 3, p->s, p->net, p->stn, "Registering machine type %08X", p->mtype);

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
