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

/* Preserve the tapes mounted list */

void fsop_43_store_tape_mounts(struct __fs_station *s)
{
	char	tapes_mounted_file[1024];
	FILE *	tapes_mounted;

	snprintf (tapes_mounted_file, 1022, "%s/Tapes-Mounted", s->directory);
	tapes_mounted = fopen(tapes_mounted_file, "w");
	if (tapes_mounted)
	{
		fwrite (s->tapedrives, 11, FS_MAX_TAPE_DRIVES, tapes_mounted);
		fclose (tapes_mounted);
	}

}

/* See if a given tape name is already mounted */

uint8_t fsop_43_tape_is_mounted(struct __fs_station *s, char *tapename)
{

	uint8_t		tape;

	for (tape = 0; tape < FS_MAX_TAPE_DRIVES; tape++)
	{
		if (!strcasecmp(s->tapedrives[tape], tapename))
			return 1;
	}

	return 0xFF; // Not found

}

/* 
 * fsop_43_discmount_tape
 *
 * Dismount tapename within server s.
 *
 * Causes a tar to be made (with xattrs) of the symlinked
 * directory 'tapename' within serverroot/Tapes/TAPEn/tapename
 *
 * verifies it
 *
 * and then removes the directory
 */

uint8_t fsop_43_dismount_tape(struct __fs_station *s, char *tapename)
{
	uint8_t		tape;

	tape = fsop_43_tape_is_mounted(s, tapename);

	if (tape == 0xFF) // Rogue for not mounted
		return 0;

	/* Do the re-tar here */

	/* Put the tape name in the right place */

	strncpy (s->tapedrives[s->tapedrive], tapename, 10);

	fsop_43_store_tape_mounts(s);

	return 1;
}

/*
 * fsop_43_mount_tape
 *
 * Checks to ensure nothing is already mounted in the drive,
 * and the unpacks the tar. It operates on the currently
 * selected tape drive.
 *
 */

uint8_t fsop_43_mount_tape(struct __fs_station *s, char *tapename)
{

	if (fsop_43_tape_is_mounted(s, tapename))
		return 0xFF; // Already mounted

	return 1;
}

FSOP(43)
{

	FS_REPLY_DATA(0x80);

	uint8_t		arg;
	unsigned char	tape[11]; // MDFS limits its tape names to 10 characters
	unsigned char	tape_library_path[300];
	unsigned char	tape_tar_path[320];
	unsigned char 	tape_unpack_path[320];
	unsigned char	tape_link_path[320];

	// The initialization routine will have made sure this directory exists
	sprintf (tape_library_path, "%s/Tapes/", f->server->directory);

	arg = *(f->data + 5);

	// NB, whilst PiFS can handle multiple virtual tape drives, MDFS did not. So there is a PiFS call to change drive number
	// and the drive number is stored when a backup is scheduled, and when backup is queried, it queries the current
	// drive number. Default drive number is 0.
	
	if (arg < 16 || arg > 18)
		fs_debug (0, 1, "%12sfrom %3d.%3d MDFS Tape operation %02X, %s - Not yet implemented", "", f->net, f->stn, arg, 
			arg == 0 ? "Determine whether backup possible" :
			arg == 1 ? "Read tape ID block" :
			arg == 2 ? "Read current status, auto backup" :
			arg == 3 ? "Write current status of auto backup" :
			arg == 4 ? "Read tape partition size" : 
			"Bad argument"
			);

	switch (arg)
	{
		case 16: // PiFS create tape
			{
				// Tape name at data + 6, always terminated by 0x0D
				// Copy up to max length of packet

				fs_copy_to_cr(tape, f->data+6, 10);
				if (strlen(tape) > 0)
				{
					// Sanity check tape name here. TODO.
					fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Create tape %s", "", f->net, f->stn, arg, tape); 
				}
				else
				{
					fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Create tape - bad tape name", "", f->net, f->stn, arg); 
					fsop_error(f, 0xFF, "Bad tape name");
				}
			} break;
		case 17: // PiFS mount tape - tape name at data+6; operates on currently selected drive number
			{
				// Untar the relevant tape if we can find a tar. 
				// If not, it's already mounted or doesn't exist
				// Then make a symlink to the virtual tape drive directory

				fs_copy_to_cr(tape, f->data+6, 10);
				// Sanity check tape name here. TODO.
				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Mount tape %s", "", f->net, f->stn, arg, tape); 

				fsop_error(f, 0xFF, "Not yet implemented");
			} break;
		case 18: // PiFS dismount current tape from drive - operates on currently selected drive number
			{
				fs_debug (0, 1, "%12sfrom %3d.%3d PiFS Tape operation %02X, Dismount tape in current drive (%d)", "", f->net, f->stn, arg, f->server->tapedrive); 
				// Tar up the directory (with xattrs), and remove the link to the virtual tape drive directory
				fsop_error(f, 0xFF, "Not yet implemented");
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
				fsop_error (f, 0xFF, "Bad argument");
				break;
			}
	}

	return;

}

