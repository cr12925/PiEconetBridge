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

#include "fs.h"

FSOP_00(TAPEMOUNT)
{
	uint8_t		drive;
	char		tapename[11], drivestring[11];
	char		tape_cmd_string[256];

	fsop_00_oscli_extract(f->data, p, 0, tapename, 10, param_start);

	if (num == 2)
	{
		fsop_00_oscli_extract(f->data, p, 1, drivestring, 1, param_start);
		if (drivestring[0] < '0' || drivestring[0] >= (FS_MAX_TAPE_DRIVES + '0'))
		{
			fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEMOUNT %s %s - Bad drive", tapename, drivestring);
			fsop_error(f, 0xFF, "Bad drive");
			return;
		}
		drive = atoi(drivestring);
	}
	else
		drive = f->server->tapedrive;

	fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEMOUNT %s %d", tapename, drive);

	fs_toupper(tapename);

	snprintf (tape_cmd_string, 250, "mount %s %d", tapename, drive);

	fsop_43_exec_tape_handler_return(f, tape_cmd_string);

}

FSOP_00(UNLOADTAPE)
{
	fsop_00_TAPEDISMOUNT (f, p, num, param_start);	
}

FSOP_00(TAPEDISMOUNT)
{
        uint8_t         drive;
        char            tapename[11], drivestring[11];
        char            tape_cmd_string[256];

	if (num == 1)
	{
        	fsop_00_oscli_extract(f->data, p, 0, drivestring, 10, param_start);
		if (drivestring[0] < '0' || drivestring[0] >= (FS_MAX_TAPE_DRIVES + '0'))
		{
			fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEDISMOUNT %s - Bad drive", drivestring);
			fsop_error(f, 0xFF, "Bad drive");
			return;
		}
		drive = atoi(drivestring);
	}
	else	
		drive = f->server->tapedrive;

	/* This routine needs to find the mounted tape name because the script needs it */
	 
	if (fsop_tape_get_mounted_name (f->server, drive, tapename))
	{
        	fs_toupper(tapename);

        	fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEDISMOUNT %d (mounted tape: %s)", drive, tapename);

        	snprintf (tape_cmd_string, 250, "umount %s %d", tapename, drive);

        	fsop_43_exec_tape_handler_return(f, tape_cmd_string);
	}
	else
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEDISMOUNT %s - Cannot get mounted tape name", drivestring);
		fsop_error(f, 0xFF, "Drive empty");
	}
}

FSOP_00(TAPEFORMAT)
{
        char            tapename[11];
        char            tape_cmd_string[256];

        fsop_00_oscli_extract(f->data, p, 0, tapename, 10, param_start);

        fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEFORMAT %s", tapename);

        fs_toupper(tapename);

        snprintf (tape_cmd_string, 250, "format %s", tapename);

        fsop_43_exec_tape_handler_return(f, tape_cmd_string);
	
}

FSOP_00(TAPEBACKUP)
{
	char		tapename[11], discname[20], partitionstring[5], drivestring[5];
	uint8_t		partition, drive;
	int		disc;
	char		cmd_string[1024];

	fsop_00_oscli_extract(f->data, p, 0, discname, 16, param_start);
	fsop_00_oscli_extract(f->data, p, 1, partitionstring, 4, param_start);

	fs_toupper(discname);

	if ((disc = fsop_get_discno(f, discname)) < 0)
	{
		fsop_error(f, 0xFF, "No such disc");
		return;
	}

	drive = f->server->tapedrive;

	if (num == 3) /* Drive number specified */
	{

        	fsop_00_oscli_extract(f->data, p, 2, drivestring, 2, param_start);
		if (drivestring[0] < '0' || drivestring[0] >= (FS_MAX_TAPE_DRIVES + '0'))
		{
			fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEBACKUP %s %s %d - Bad drive", discname, partitionstring, drivestring);
			fsop_error(f, 0xFF, "Bad drive");
			return;
		}
		drive = atoi(drivestring);
	}

	for (uint8_t c = 0; c < strlen(partitionstring); c++)
	{
		if (!isdigit(partitionstring[c]))
		{
			fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEBACKUP %s %s %d - Bad partition", discname, partitionstring, drive);
			fsop_error (f, 0xFF, "Bad partition");
			return;
		}
	}

	partition = atoi(partitionstring);

	if (partition > 14)
	{

		fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEBACKUP %s %d %d - Bad partition", discname, partition, drive);
		fsop_error (f, 0xFF, "Bad partition");
		return;
	}

	if (fsop_tape_get_mounted_name (f->server, drive, tapename))
	{

		snprintf (cmd_string, 1023, "backup %s %d %d%s %d", tapename, drive, disc, discname, partition);

		fsop_43_exec_tape_handler_return(f, cmd_string);
	}
	else
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEBACKUP %s %d %d - Drive error (can't identify mounted tape name)", discname, partition, drive);
		fsop_error (f, 0xFF, "Drive error");
	}

	return;
}

FSOP_00(TAPESELECT)
{
        char            drivestring[11];

        fsop_00_oscli_extract(f->data, p, 0, drivestring, 10, param_start);

	if (drivestring[0] < '0' || drivestring[0] >= (FS_MAX_TAPE_DRIVES + '0'))
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "*TAPEDISMOUNT %s - Bad drive", drivestring);
		fsop_error(f, 0xFF, "Bad drive");
	}

	f->server->tapedrive = atoi(drivestring);

	fsop_reply_ok(f);
}

FSOP_00(TAPEREPEAT)
{
	unsigned char	interval_string[20], timestring[20];
	uint32_t	interval, secs;

	fsop_00_oscli_extract(f->data, p, 0, interval_string, 19, param_start);
	
	interval = atoi(interval_string);

	if (num == 2)
		fsop_00_oscli_extract(f->data, p, 0, timestring, 19, param_start);

	if (
			(num == 1 && interval != 0)
		||	(num == 2 && interval == 0)
	   )
	{
		fsop_error (f, 0xFF, "Bad interval");
		return;
	}


	if (num == 2) { switch (timestring[0])
	{
		case 'h':
		case 'H':
			secs = 60 * 60;
			break;
		case 'd':
		case 'D':
			secs = 60 * 60 * 24;
			break;
		default:
			fsop_error (f, 0xff, "Bad time specifier");
			return;
	}
	}
	else
		secs = 0;

	f->server->backup->interval = atoi(interval_string) * secs;

	fsop_reply_ok(f);
}


