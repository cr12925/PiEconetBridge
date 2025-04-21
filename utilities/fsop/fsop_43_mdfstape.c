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
				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Read tape ID block", arg);
				fsop_error(f, 0xFF, "Not yet implemented");
			} break;
		case 2: // Read auto backup status
			{
				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Read backup status", arg);
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
					struct tm	*when;
					uint8_t		acorn_d, acorn_my, hour, min, sec, tapenamelen, counter = 0;

					when = gmtime(&(f->server->backup->when));
					
					fs_date_to_two_bytes(when->tm_mday, when->tm_mon, when->tm_year, &acorn_my, &acorn_d);
					hour = when->tm_hour;
					min = when->tm_min;
					sec = when->tm_sec;

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

			} break;
		case 3: // Write auto backup status
			{
				uint8_t		setup;


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
					when.tm_mon = fs_month_from_two_bytes(acorn_dy, acorn_ym);
					when.tm_year = fs_year_from_two_bytes(acorn_dy, acorn_ym);
					when.tm_hour = *(f->data + 9);
					when.tm_min = *(f->data + 10);
					when.tm_sec = *(f->data + 11);
					when.tm_isdst = -1;

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

					fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Write backup status (set for %02d/%02d/%04d %02d:%02d:%02d)", arg, when.tm_mday, when.tm_mon, when.tm_year, when.tm_hour, when.tm_min, when.tm_sec);

					// TODO - wake up the backup scheduler!
				}

			} break;
		case 4: // Read tape partition size
			{
				fs_debug_full (0, 1, f->server, f->net, f->stn, "MDFS Tape operation %02d - Read partition sizes", arg);

				// Produces fudged data

				uint8_t	count = 0;

				for (; count < 8; count++)
				{
					FS_CPUT8(1); // Means streamer - size big enough for the amount given
					FS_CPUT32(102400); // 100Mb
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

