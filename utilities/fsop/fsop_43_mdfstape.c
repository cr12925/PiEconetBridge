/*
  (c) 2025 Chris Royle
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

#include "../../include/fs.h"

/*
 * fsop_43_store_timet
 *
 * Takes a time_t and stores it in the 4 bytes pointed to by *out,
 * which are in the order
 *
 * acorn_dy, acorn_my, hour, min
 */

void fsop_43_store_timet (time_t in, uint8_t *out)
{
	struct tm	conv;

	localtime_r (&in, &conv);

	fs_date_to_two_bytes(conv.tm_mday, conv.tm_mon + 1, conv.tm_year, (out+1), out);
	*(out+2) = conv.tm_hour;
	*(out+3) = conv.tm_min;

}

/* 
 * fsop_43_drive_mounted
 *
 * Checks to see if a tape drive has a tape in it and
 * gives us the name if it has.
 *
 * tapename must have at least 11 characters available and have
 * been pre-allocated by the caller
 */

uint8_t fsop_43_drive_mounted (struct __fs_station *s, uint8_t drive, char *tapename)
{
	struct stat	sb;
	unsigned char	tapedrivepath[1024];

	sprintf(tapedrivepath, "%s/%s/%d", s->directory, FS_DIR_TAPEDRIVE, drive);	
	
	if (stat(tapedrivepath, &sb) == 0) // Stat success
	{
		if ((sb.st_mode & S_IFMT) == S_IFDIR)
		{
			unsigned char linkdest[300];

			if (readlink(tapedrivepath, linkdest, 290) != -1)
			{
				char * p, *slash;

				if ((p = strrchr(linkdest, '.')))
				{
					*p = 0; /* Drop the extension */
					slash = strrchr(linkdest, '/');
					if (!slash) slash = linkdest;
					slash++;
					strncpy (tapename, slash, 10);
					return 1; /* Found */
				}
				else
					fs_debug_full (0, 1, s, 0, 0, "MDFS check drive mounted - drive %d directory does not have required extension", drive);
			}
			else
				fs_debug_full (0, 1, s, 0, 0, "MDFS check drive mounted - drive %d directory can't be read", drive);
		}
		else
			fs_debug_full (0, 1, s, 0, 0, "MDFS check drive mounted - drive %d directory (%s) is not a directory", drive, tapedrivepath);
	}
	else
		fs_debug_full (0, 1, s, 0, 0, "MDFS check drive mounted - cannot stat drive %d directory", drive);

	return 0;
}

/* 
 * fsop_43_read_int
 *
 * Reads a uint32_t from the given file and returns it, or 0 if the file doesn't exist
 */

uint32_t fsop_43_read_int(char *path)
{
	uint32_t	ttime;
	FILE 	*tfile;

	tfile = fopen(path, "r");

	if (!tfile)
		ttime = 0;
	else
	{
		/* Read format time */
		fscanf(tfile, "%d", &ttime);
		fclose(tfile);
	}

	return ttime;
}

/* 
 * fsop_43_get_tapeid_block
 *
 * Returns -1 for failure (e.g. drive not mounted) - the content of *result will not be valid
 * Returns n >= 0 where there is valid data in *result, and will populate the tapeid block - n being the number of active partitions put into the tapeid structure
 *
 * result must be pre-allocated by the caller, and is a struct __fs_tapeid_block
 *
 */

int8_t fsop_43_get_tapeid_block (struct __fs_station *s, uint8_t drive, 
		struct __fs_tapeid_block *result)
{
	unsigned char	tapedrivepath[512];
	unsigned char	otherpath[1024];
	FILE		*descrfile;
	time_t		ttime;
	uint16_t	passes;
	struct dirent	**namelist;
	int		n;
	uint8_t		partition = 0;
	struct stat	sb;

	strcpy (result->identifier, "SJ Research"); // Magic identifier

	/* Is a tape mounted, and if so what's it called? */

	if (!fsop_43_drive_mounted(s, drive, result->tapename))
	{
		fs_debug_full (0, 1, s, 0, 0, "MDFS read tape ID block on drive %d failed - drive not mounted", drive);
		return -1; /* Nothing in drive */
	}

	/* termiante with 0x0d if less than 10 characters */

	if (strlen(result->tapename) < 10)
		result->tapename[strlen(result->tapename)] = 0x0D;

	sprintf (tapedrivepath, "%s/%s/%d", s->directory, FS_DIR_TAPEDRIVE, drive);

	if (stat(tapedrivepath, &sb))
	{
		fs_debug_full (0, 1, s, 0, 0, "MDFS read tape ID block on drive %d failed - cannot stat drive directory", drive);
		return -1; /* Couldn't stat! */
	}

	if ((sb.st_mode & S_IFMT) != S_IFDIR) /* not a directory - barf */
	{
		fs_debug_full (0, 1, s, 0, 0, "MDFS read tape ID block on drive %d failed - drive location is not a directory", drive);
		return -1;
	}

	sprintf (otherpath, "%s/.format_time", tapedrivepath);

	ttime = (time_t) fsop_43_read_int (otherpath);

	sprintf (otherpath, "%s/.passes", tapedrivepath);

	passes = (uint16_t) fsop_43_read_int (otherpath);

	if (passes == 0)
		result->usage = 0;
	else	result->usage = 1;	

	*((uint8_t *) &(result->passes)) = passes & 0xff;
	*((uint8_t *) &(result->passes) + 1) = (passes & 0xff00) >> 8;

	sprintf (result->description, "PiFS Virtual Tape%c", 0x0D); // Dummy for now in case there isn't a description

	sprintf (otherpath, "%s/.description", tapedrivepath);

	if ((descrfile = fopen(otherpath, "r")))
	{
		fread (result->description, 80, 1, descrfile);
		fclose (descrfile);
	}

	fsop_43_store_timet(ttime, &(result->fmt_dayyear)); 

	memset (result->reserved, 0, 20); /* Blank off the reserved setion */

	n = scandir(tapedrivepath, &namelist, NULL, NULL);

	if (n == -1)
		return 0;
	
	while (n-- && partition < 8 ) /* Yes, I know the spec says "up to 14 of these entries" but there seems to be a limit of 8 partitions... */
	{
	 	if (strlen(namelist[n]->d_name) >= 3 &&
			(
				(namelist[n]->d_name[0] == '0' && namelist[n]->d_name[1] >= '0' && namelist[n]->d_name[1] <= '9')
			||	
				(namelist[n]->d_name[1] == '0' && namelist[n]->d_name[1] >= '0' && namelist[n]->d_name[1] <= '3')
			)
		   )
		{
			uint8_t	len;

			time_t backuptime;

			//uint8_t	my_partition;

			uint32_t data_start, data_length;


			//my_partition = ((namelist[n]->d_name[0] - 48) * 10) + (namelist[n]->d_name[1] - 48);

			data_start = 524288 * partition; /* total fudge - 512Mb partitions at 512Mb intervals */
			data_length = 524288;

			/* This is one of ours */

			strcpy ((char *) &(result->content[(partition * 64) + 1]), &(namelist[n]->d_name[2])); /* Drop the partition number off the front */

			len = strlen(namelist[n]->d_name) - 2; /* Drop first two characters */

			if (len < 10)
				result->content[(64 * partition) + 1 + len] = 0x0D; /* Termiante if less than 10 char disc name */

			result->content[( 64 * partition)] = FS_TAPEID_OK;
	
			sprintf (otherpath, "%s/%s/.backup_time", tapedrivepath, namelist[n]->d_name);

			backuptime = (time_t) fsop_43_read_int(otherpath);

			fsop_43_store_timet(backuptime, &(result->content[(64 * partition) + 11]));

			result->content[(64 * partition) + 15] = (data_start * partition) & 0xff;
			result->content[(64 * partition) + 16] = ((data_start * partition) & 0xff00) >> 8;
			result->content[(64 * partition) + 17] = ((data_start * partition) & 0xff0000) >> 16;
			result->content[(64 * partition) + 18] = ((data_start * partition) & 0xff000000) >> 24;

			result->content[(64 * partition) + 19] = (data_length & 0xff); // Fudge for now - 512Mb
			result->content[(64 * partition) + 20] = (data_length & 0xff00) >> 8; // Fudge for now - 512Mb
			result->content[(64 * partition) + 21] = (data_length & 0xff0000) >> 16; // Fudge for now - 512Mb
			result->content[(64 * partition) + 22] = (data_length & 0xff000000) >> 24; // Fudge for now - 512Mb

			memset (&(result->content[(64 * partition) + 23]), 0, 8); // Blank off the error info
			memset (&(result->content[(64 * partition) + 31]), 0, 20); // Blank off the reserved info

			partition++;

		}
	}

	free (namelist);

	if (partition < 14) result->content[(64 * partition) + 1] = 0x0D; /* Flag an empty disc so we know not to send this */

	return partition; /* Returns number of valid partitions */


}

/* 
 * Copy up to 10 character tape name, terminated by 0x0D if less than
 * 10 characters, from *fromwhere to *towhere with max length maxlen
 *
 * *towhere must have space for maxlen+1 characters to accommodate 
 * null termination.
 *
 */

uint8_t fsop_43_copy_tapename(uint8_t *towhere, uint8_t *fromwhere, uint8_t maxlen)
{

	uint8_t		count = 0;

	while (*(fromwhere + count) != 0x0D && count < maxlen)
	{
		*(towhere + count) = *(fromwhere + count);
		count++;
	}

	*(towhere + count) = 0x00;

	return count;

}

/* Execute the tape handler */

uint8_t	fsop_43_tape_handler(struct __fs_station *s, char * params)
{

	char *	cmd;
	int 	res;

	cmd = eb_malloc(__FILE__, __LINE__, "FS", "Tape handler command string", strlen(s->tapehandler) + strlen(s->directory) + strlen(params) + 3);

	sprintf (cmd, "%s %s %s", s->tapehandler, s->directory, params);

	res = system(cmd);

	//fprintf (stderr, "\n\n* Executed: %s, result = %d\n\n", cmd, WEXITSTATUS(res));

	eb_free(__FILE__, __LINE__, "FS", "Free tape handler command string", cmd);

	if (res < 0)
		return 255;
	else 	return (uint8_t) WEXITSTATUS(res);

}

uint8_t fsop_43_exec_tape_handler_return(struct fsop_data *f, char * params)
{

	/* Exec the tape handler, collect the result, and either return OK with nothing else if success,
	 * or return 0xFF error code with error string termianted by 0x0D
	 */

	uint8_t	res;

	res = fsop_43_tape_handler (f->server, params);

	if (res == 0) /* Success */
		fsop_reply_ok(f);
	else
		fsop_error(f, 0xFF, fsop_43_tape_errstr(res));

	return res;
}

/* Check the tape name for illegal/unwise characters */

uint8_t fsop_43_check_tapename(char *name)
{
	uint8_t	count = 0;

	if (strlen(name) == 0 || strlen(name) > 10)
		return 0;

	for (; count < strlen(name); count++)
	{
		if (name[count] < '0')
			return 0;
		if (name[count] > '9' &&
			!(
				(name[count] >= 'A' && name[count] <= 'Z')
				||
				(name[count] >= 'a' && name[count] <= 'z')
			 )
		   )
			return 0;
	}

	return 1;

}

/* Return error string matching the error codes returned by the tapes.sh handler script */

char * fsop_43_tape_errstr(uint8_t err)
{

	switch (err)
	{
		case 0:	return "Success"; break;
		case 1: return "Bad FS directory"; break;
		case 2: return "Tape already mounted"; break;
		case 3: return "Bad tape handler command"; break;
		case 4: return "Tape not mounted"; break;
		case 5: return "Tape unavailable"; break;
		case 6: return "Drive in use / not responding"; break;
		case 7: return "Tape unavailable (in use)"; break;
		case 8: return "Tape unreadable"; break;
		case 9: return "Drive not working"; break;
		case 10: return "Internal tape error"; break;
		case 11: return "Unable to unmount, internal error"; break;
		case 12: return "Format unsuccessful"; break;
		case 13: return "Bad tape partition"; break;
		case 14: return "Drive empty"; break;
		case 15: return "Drive fault"; break;
		case 16: return "Backup failed"; break;
		case 17: return "Bad drive number"; break;
		case 18: return "Tape not found"; break;
		case 255: return "Internal tape handler error"; break;
		default: return "Unknown tape error"; break;
	}

	return "Internal error";
		
}

FSOP(43)
{

	FS_REPLY_DATA(0x80);
	FS_REPLY_COUNTER();

	uint8_t		arg;
	unsigned char	tape[11]; // MDFS limits its tape names to 10 characters

	arg = *(f->data + 5);

	// NB, whilst PiFS can handle multiple virtual tape drives, MDFS did not. So there is a PiFS call to change drive number
	// and the drive number is stored when a backup is scheduled, and when backup is queried, it queries the current
	// drive number. Default drive number is 0.

	switch (arg)
	{
		case 0: // Check if backup possible
			{
				char	cmd_string[20];

				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Check if backup possible", arg);
				snprintf (cmd_string, 19, "drivestate x %d", f->server->tapedrive); // The parameter after drivestate is ignored on this cmd
				fsop_43_exec_tape_handler_return (f, cmd_string);
			} break;
		case 1: // Read Tape ID block
			{
				int8_t partitions; // Needs to be signed to detect errors
				uint8_t	drive;
				struct __fs_tapeid_block	b;
				uint32_t block_offset, bytestoreturn;
				uint8_t	*bptr;

				block_offset = *(f->data + 6) + (*(f->data + 7) * 256); 
				bytestoreturn = *(f->data + 8) + (*(f->data + 9) * 256);

				drive = f->server->tapedrive; // Operate on currently selected drive

				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Read tape ID block (from drive %d)", arg, drive);
				partitions = fsop_43_get_tapeid_block (f->server, drive, &b);

				if (partitions < 0) /* Failed */
				{
					fsop_error (f, 0xFF, "Drive failure");
					return;
				}

				bptr = (uint8_t *) &b;
				bptr += block_offset;

				memcpy (&(reply.p.data[2]), (char *) bptr, bytestoreturn);

				fsop_aun_send (&reply, 2 + bytestoreturn, f); 

			} break;
		case 2: // Read auto backup status
			{
				if (pthread_mutex_trylock(&(f->server->fs_backup_mutex))) // Can't get lock
				{
					fsop_error (f, 0xFF, "Tape subsystem busy");
					return;
				}

				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Read backup status", arg);
				FS_CPUT16(0); // First two bytes - no error

				if (f->server->backup->when == 0) /* Nothing pending */
				{
					FS_CPUT8(0);
					FS_CPUT32(0); /* 4 bytes of nul time */
					FS_CPUT8(0); /* 5th byte of nul time */
					FS_CPUT8(0); /* No printer output */
					FS_CPUT8(0); /* No flag */
					memset(&(reply.p.data[12]), 0, 10); /* Blank tape name */
					__rcounter += 10;
					FS_CPUT8(0xFF); /* Terminator - no partitions */
				}
				else
				{
					struct tm	when;
					uint8_t		acorn_d, acorn_my, hour, min, sec, tapenamelen, counter = 0;

					localtime_r(&(f->server->backup->when), &when);
					
					fs_date_to_two_bytes(when.tm_mday, when.tm_mon + 1 , when.tm_year, &acorn_my, &acorn_d);
					hour = when.tm_hour;
					min = when.tm_min;
					sec = when.tm_sec;

					FS_CPUT8(1); /* Backup pending apparently */
					FS_CPUT8(acorn_d);
					FS_CPUT8(acorn_my);
					FS_CPUT8(hour);
					FS_CPUT8(min);
					FS_CPUT8(sec);
					FS_CPUT8(0); // No printer output
					FS_CPUT8(1); // New tape format

					tapenamelen = strlen(f->server->backup->tapename);
					strcpy(&(reply.p.data[__rcounter]), f->server->backup->tapename);

					if (tapenamelen < 10)
						reply.p.data[__rcounter + tapenamelen] = 0x0d;

					__rcounter += 10; // because we used memcpy rather than the macros

					while (counter < 8 && f->server->backup->jobs[counter].partition != 0xff)
					{
						FS_CPUT8(f->server->backup->jobs[counter].partition);
						tapenamelen = strlen(f->server->backup->jobs[counter].discname); // Re-use tapenamelen
						strcpy (&(reply.p.data[__rcounter]), f->server->backup->jobs[counter].discname);
						if (tapenamelen < 10)
							reply.p.data[__rcounter + tapenamelen] = 0x0d;
						__rcounter += 10;

						counter++;
					}

					FS_CPUT8(0xff);

				}

				fsop_aun_send(&reply, __rcounter, f);
				pthread_mutex_unlock(&(f->server->fs_backup_mutex));

			} break;
		case 3: // Write auto backup status
			{
				uint8_t		setup;

				if (pthread_mutex_trylock(&(f->server->fs_backup_mutex))) // Can't get lock
				{
					fsop_error (f, 0xFF, "Tape subsystem busy");
					return;
				}

				setup = *(f->data + 6);

				if (!setup) /* Cancel current backup */
				{
					memset (f->server->backup, 0, sizeof(struct __fs_backup));
					f->server->backup->jobs[0].partition = 0xff; // Rogue
					fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Write backup status (cancelled)", arg);
				}
				else
				{
					/* Set it up and get the tape backup thread to have a look */

					uint8_t	acorn_dy, acorn_ym;
					uint8_t	count;
					struct tm	when;

					acorn_dy = *(f->data + 7);
					acorn_ym = *(f->data + 8);
					when.tm_mday = fs_day_from_two_bytes(acorn_dy, acorn_ym);
					when.tm_mon = fs_month_from_two_bytes(acorn_dy, acorn_ym) - 1;
					when.tm_year = fs_year_from_two_bytes(acorn_dy, acorn_ym);
					when.tm_hour = *(f->data + 9);
					when.tm_min = *(f->data + 10);
					when.tm_sec = *(f->data + 11);
					when.tm_isdst = -1;

					if (when.tm_year < 1981)
						when.tm_year += 100;

					//fprintf (stderr, "\n\n** Backup time attempted to set to %d/%02d/%04d %02d:%02d:%02d\n\n", when.tm_mday, when.tm_mon, when.tm_year, when.tm_hour, when.tm_min, when.tm_sec);

					f->server->backup->when = mktime(&when);

					/* Ignore printer output and the flag  - for now, we might make an optional thing on the handler to send to the pserv.sh script in future */

					fs_copy_to_cr(f->server->backup->tapename, (f->data + 14), 10);

					count = 0;

					while (*(f->data + 24 + (11 * count)) != 0xFF && count < 8)
					{
						f->server->backup->jobs[count].partition = *(f->data + 24 + (11 * count));
						fs_copy_to_cr(f->server->backup->jobs[count].discname, (f->data + 25 + (11 * count)), 10);
						count++;
					}


					if (count != 8)
						f->server->backup->jobs[count].partition = 0xff; // Put the rogue in

					if (count == 0) /* no discs in the backup - barf */
					{
						memset(f->server->backup, 0, sizeof(struct __fs_backup));
						f->server->backup->jobs[0].partition = 0xFF;
						fsop_error (f, 0xFF, "Invalid backup - no discs specified");
						pthread_mutex_unlock(&(f->server->fs_backup_mutex));
						return;
					}

					fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Write backup status (set for %02d/%02d/%04d %02d:%02d:%02d)", arg, when.tm_mday, when.tm_mon, when.tm_year, when.tm_hour, when.tm_min, when.tm_sec);

					pthread_cond_signal(&(f->server->fs_backup_cond));
				}

				pthread_mutex_unlock(&(f->server->fs_backup_mutex));

				fsop_reply_ok(f);

			} break;
		case 4: // Read tape partition size
			{
				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Read partition sizes", arg);

				// OK header

				FS_CPUT16(0); // 2 &00 

				// Produces fudged data

				uint8_t	count = 0;

				for (; count < 8; count++)
				{
					FS_CPUT8(0); // Means fixed
					FS_CPUT32(512 * 1024); // 512Mb 
				}

				fsop_aun_send(&reply, __rcounter, f);

			} break;
		case 16: // PiFS format tape
			{
				char	cmd_string[40];

				// Tape name at data + 6, always terminated by 0x0D
				// Copy up to max length of packet

				fs_copy_to_cr(tape, f->data+6, 10);

				fs_toupper(tape);

				if (!fsop_43_check_tapename(tape))
				{
					fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Create tape - bad tape name", "", f->net, f->stn, arg); 
					fsop_error(f, 0xFF, "Bad tape name");
					return;
				}

				fs_debug_full (0, 1, f->server, f->net, f->stn, "PiFS Tape operation %02d - Format tape", arg);

				snprintf (cmd_string, 39, "format %s", tape);
				fsop_43_exec_tape_handler_return (f, cmd_string);
			} break;
		case 17: // PiFS mount tape - tape name at data+6; operates on currently selected drive number
			{
				char	cmd_string[40];

				// Untar the relevant tape if we can find a tar. 
				// If not, it's already mounted or doesn't exist
				// Then make a symlink to the virtual tape drive directory

				fs_copy_to_cr(tape, f->data+6, 10);

				fs_toupper(tape);

				if (!fsop_43_check_tapename(tape))
				{
					fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Mount tape - bad tape name", "", f->net, f->stn, arg); 
					fsop_error(f, 0xFF, "Bad tape name");
				}

				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Mount tape %s", "", f->net, f->stn, arg, tape); 

				snprintf (cmd_string, 39, "mount %s %d", tape, f->server->tapedrive);
				fsop_43_exec_tape_handler_return (f, cmd_string);
			} break;
		case 18: // PiFS dismount current tape from drive - operates on currently selected drive number
			{
				char	cmd_string[40];

				fs_copy_to_cr(tape, f->data+6, 10);

				fs_toupper(tape);

				if (!fsop_43_check_tapename(tape))
				{
					fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Dismount tape - bad tape name", "", f->net, f->stn, arg); 
					fsop_error(f, 0xFF, "Bad tape name");
				}

				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Dismount tape %s", "", f->net, f->stn, arg, tape); 

				snprintf (cmd_string, 39, "umount %s %d", tape, f->server->tapedrive);
				fsop_43_exec_tape_handler_return (f, cmd_string);
			} break;
		case 19: // PiFS select tape drive number (at data+6)
			{
				uint8_t	tape_drive = *(f->data + 6);

				if (tape_drive < FS_MAX_TAPE_DRIVES)
				{
					fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Select drive %02d", "", f->net, f->stn, arg, tape_drive); 
					f->server->tapedrive = tape_drive;
					fsop_reply_ok(f);
				}
				else
					fsop_error (f, 0xFF, "Bad tape drive number");
			} break;
		case 20: // PiFS get tape drive number
			{
				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Get tape drive number (%02d)", "", f->net, f->stn, arg, f->server->tapedrive); 
				fsop_reply_ok_with_data(f, &(f->server->tapedrive), 1);
			} break;
		case 21: // PiFS get tape names data+6 is start index; data+7 is max number of entries to return
			// Reply is n x 10 character tape names, terminated by 0x0D if less than 10 characters long
			{
				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Get tape names (index %02d + %02d)", "", f->net, f->stn, arg, *(f->data+6), *(f->data+7)); 
				fsop_error (f, 0xFF, "Not yet implemented");
			} break;
		case 22: // Get currently mounted tape names
			// Reply is n x 10 character tape names, terminated by 0x0D if less than 10 characters long, one for each tape drive number (so we shouldn't put MAX > about 10 really...)
			{
				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Get mounted tape names", "", f->net, f->stn, arg); 
				fsop_error (f, 0xFF, "Not yet implemented");
			} break;
		default:
			{
				fs_debug_full (0, 1, f->server, f->net, f->stn, "Tape operation %02d - Unknown argument", arg);
				fsop_error (f, 0xFF, "Bad argument");
				break;
			}
	}

	return;

}

/* Code for the backup thread 
 * This works out when the next backup is, and sleeps on its condition
 * until it's time.
 * It may be woken earlier, in which case it will re-scane the job
 * to see if (i) it has been told to die pending a fileserver shutdown,
 * or (ii) if the job has been cancelled (in which case it will do an
 * indefinite sleep), or (iii) if the job time has changed (in which case
 * change its sleep pattern), or (iv) if the job time has passed in 
 * which case it's time to do a backup.
 */

void * fsop_backup_thread (void * p)
{
	struct __fs_station *s;
	time_t	next_event, now;

	s = (struct __fs_station *) p;

	fs_debug_full (0, 1, s, 0, 0, "Tape backup scheduler started");

	pthread_mutex_lock(&(s->fs_backup_mutex));

	while (1)
	{
		next_event = s->backup->when;
		now = time(NULL);

		if (next_event == 0) /* No job, indefinite sleep */
		{
			fs_debug_full (0, 1, s, 0, 0, "Tape backup scheduler has no work - sleeping");
			pthread_cond_wait(&(s->fs_backup_cond), &(s->fs_backup_mutex));
		}
		else if (next_event > now) /* Job, but it's in the future */
		{
			struct tm	until;
			struct timespec	t;

			clock_gettime(CLOCK_REALTIME, &t);
			localtime_r (&next_event, &until);

			fs_debug_full (0, 1, s, 0, 0, "Tape backup scheduler sleeping until %d/%02d/%04d %02d:%02d:%02d (%d secs)",
					until.tm_mday, until.tm_mon, until.tm_year+1900,
					until.tm_hour, until.tm_min, until.tm_sec,
					(next_event - now));

			t.tv_sec += (next_event - now);

			pthread_cond_timedwait(&(s->fs_backup_cond), &(s->fs_backup_mutex), &t);
		}

		next_event = s->backup->when;
		now = time(NULL);

		if (next_event < 0) next_event = 0;
		
		if (s->backup->die) /* FS is closing down - exit */
		{
			fs_debug_full (0, 1, s, 0, 0, "Tape backup scheduler exiting - fileserver shutting down");
			s->backup->i_have_died = 1;
			pthread_mutex_unlock (&(s->fs_backup_mutex));
			pthread_exit(NULL);
		}

		if (next_event != 0 && now > next_event)  /* Do a backup */
		{
			int count = 0; // Job list
			uint8_t	drive; // Need to find drive number

			fs_debug_full (0, 1, s, 0, 0, "Tape backup scheduler starting backup to %s", s->backup->tapename);

			for (; count < FS_MAX_TAPE_DRIVES; count++)
			{
				unsigned char	tapename[11];

				if (fsop_43_drive_mounted(s, count, tapename) && !strcasecmp(tapename, s->backup->tapename))
				{
					drive = count;
					break;
				}
			}

			if (count == FS_MAX_TAPE_DRIVES) /* Tape not found */
			{
				fs_debug_full (0, 1, s, 0, 0, "Scheduled backup to tape %s FAILED (Tape not mounted) - ABORTING",
						s->backup->tapename);
				s->backup->when = 0;
				s->backup->jobs[0].partition = 0xff;
				continue;
			}

			fs_debug_full (0, 1, s, 0, 0, "Scheduled backup - tape %s found in drive %d", s->backup->tapename, drive);

			count = 0; 

			while (count < 8 && s->backup->jobs[count].partition != 0xff)
			{
				char cmd_string[128];
				uint8_t discno; // Need to look that up for each disc
				struct __fs_disc	*d;
				uint8_t res;
				
				discno = 0xff;

				d = s->discs;

				while (d && (discno == 0xff))
				{
					if (!strcasecmp(d->name, s->backup->jobs[count].discname)) /* Found it */
						discno = d->index;
					else
						d = d->next;
				}
				
				if (discno == 0xff)
				{
					fs_debug_full (0, 1, s, 0, 0, "Scheduled backup of %s to partition %d on tape %s FAILED (Unknown disc name) - ABORTING",
							s->backup->jobs[count].discname,
							s->backup->tapename,
							s->backup->jobs[count].partition);
					s->backup->when = 0;
					s->backup->jobs[0].partition = 0xff;
					continue;
				}

				sprintf (cmd_string, "backup %s %d %d%s %d",
						s->backup->tapename,
						drive, 
						discno, 
						s->backup->jobs[count].discname,
						s->backup->jobs[count].partition);

				res = fsop_43_tape_handler(s, cmd_string);

				if (res == 0)
				{
					fs_debug_full (0, 1, s, 0, 0, "Scheduled backup of %s to partition %d on tape %s successful",
							s->backup->jobs[count].discname,
							s->backup->jobs[count].partition,
							s->backup->tapename);
				}
				else
				{
					fs_debug_full (0, 1, s, 0, 0, "Scheduled backup of %s to partition %d on tape %s FAILED (%s) - ABORTING",
							s->backup->jobs[count].discname,
							s->backup->jobs[count].partition,
							s->backup->tapename,
							fsop_43_tape_errstr(res));
					s->backup->when = 0;
					s->backup->jobs[0].partition = 0xff;
					continue;
				}
				count++;
			}
			
		}
	}


}
