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

/* 
 * Implements 
 *
 * FSOP &06 - open file
 * FSOP &07 - close handle
 */

uint8_t fsop_close_handle(struct fsop_data *f, uint8_t handle)
{

	if (!f->active->fhandles[handle].handle) // Handle not open
		return 0;
	else
	{
		if (f->active->fhandles[handle].is_dir)
			fsop_deallocate_user_dir_channel (f->active, handle);
		else
		{
			fsop_close_interlock(f->server, f->active->fhandles[handle].handle, f->active->fhandles[handle].mode);
			fsop_deallocate_user_file_channel(FSOP_ACTIVE, handle);
		}
		return 1;
	}
}

FSOP(06)
{

	FS_REPLY_DATA(0x80);
	uint8_t		existingfile = *(f->data+5);
	uint8_t		readonly = *(f->data+6);
	unsigned char	filename[1024];
	uint8_t		result;
	uint8_t		count, start;
	struct __fs_file	*handle;
	struct path 	p;
	uint8_t		is_32bit = 0;

	if (*(f->data+1) == 0x2E)
		is_32bit = 1;

	count = 7;

	while (*(f->data+count) == ' ' && count < f->datalen)
		count++;

	if (count == f->datalen)
		fsop_error(f, 0xD6, "Not found");

	start = count;

	while (*(f->data+count) != ' ' && count < f->datalen)
		count++;

	if (count != f->datalen) // space in the filename!
		*(f->data+count) = 0x0d; // So terminate it early

	fs_copy_to_cr(filename, f->data+start, 1023);

	if (strlen(filename) == 0)
	{
		fsop_error(f, 0xFF, "Bad filename");
		return;
	}

	fs_debug_full (0, 2, f->server, f->net, f->stn, "Open%s %s readonly %s, must exist? %s", (is_32bit ? "32" : ""), filename, (readonly ? "yes" : "no"), (existingfile ? "yes" : "no"));

	// If the file must exist, then we can use wildcards; else no wildcards
	// BUT we should be able to open a file for writing with wildcards in the path except the tail end
	// Then, below, if the file doesn't exist we barf if the tail has wildcards in it.
	
	result = fsop_normalize_path_wildcard(f, filename, FSOP_CWD, &p, 1);

	if (!result) // The || !e was addded for wildcard version
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xD6, "Not found");
	}
	else if (existingfile && p.ftype == FS_FTYPE_NOTFOUND)
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xD6, "Not found");
	}
	else if (p.ftype == FS_FTYPE_NOTFOUND && (strchr(p.acornname, '*') || strchr(p.acornname, '#'))) // Cannot hand wildcard characters in the last segment of a name we might need to create - by this point, if the file had to exist and wasn't found, we'd have exited above. So by here, the file is capable of being created, so we cannot have wildcards in its name.
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xcc, "Bad filename");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && !readonly && ((p.perm & FS_PERM_L)))
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xC3, "Entry Locked");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && !readonly && ((p.my_perm & FS_PERM_OWN_W) == 0) && !FS_ACTIVE_SYST(f->active))
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xbd, "Insufficient access");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && ((p.my_perm & FS_PERM_OWN_R) == 0) && !FS_ACTIVE_SYST(f->active))
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xbd, "Insufficient access");
	}
	else if ((p.ftype == FS_FTYPE_FILE) && ((p.perm & FS_PERM_EXEC) && !FS_ACTIVE_SYST(f->active)))
	{
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xff, "Execute only");
	}
	else if (!readonly && 
			(p.ftype == FS_FTYPE_NOTFOUND) && !FS_ACTIVE_SYST(f->active)
		&&
		(       ((!(FS_PERM_EFFOWNER(f->active, p.parent_owner))) && ((p.parent_perm & FS_PERM_OTH_W) == 0)) ||
			((FS_PERM_EFFOWNER(f->active, p.parent_owner)) && ((p.parent_perm & FS_PERM_OWN_W) == 0))
			// FNF and we can't write to the directory
		)
		)
	{
		fs_debug_full (0,2, f->server, f->net, f->stn, "Attempt to open %s for write - p.parent_owner = %d, p.parent_perm = %02X, p.perm = %02X, userid = %d", filename, p.parent_owner, p.parent_perm, p.perm, f->userid);
		fs_free_wildcard_list(&p);
		fsop_error(f, 0xbd, "Insufficient access");
	}
	else
	{

		uint8_t 	userhandle, mode;

		// Do we have capacity to open this file?

		mode = (readonly ? 1 : existingfile ? 2 : 3);

		userhandle = fsop_allocate_user_file_channel(f->active);

		if (userhandle)
		{
			char    unix_segment[ECONET_MAX_FILENAME_LENGTH+3];
			int8_t	err;

			// Even on a not found, normalize puts the last acorn segment in acornname
			
			strcpy(unix_segment, "/");
			strcat(unix_segment, p.unixfname);

			if (p.ftype == FS_FTYPE_NOTFOUND) // Opening non-existent file for write - add unix name to end of path
				strcat(p.unixpath, unix_segment);

			handle = fsop_open_interlock(f, p.unixpath, (readonly ? 1 : existingfile ? 2 : 3), &err, 0);

			fs_free_wildcard_list(&p);

			if (err == -1)  // Couldn't open a file when we think we should be able to
			{
				fsop_error(f, 0xFF, "FS Error");
				fsop_deallocate_user_file_channel(f->active, userhandle);
			}
			else if (err == -2) // Interlock issue
			{
				fsop_error(f, 0xC2, "Already open");
				fsop_deallocate_user_file_channel(f->active, userhandle);
			}
			else if (err == -3)
			{
				fsop_error(f, 0xC0, "Too many open files");
				fsop_deallocate_user_file_channel(f->active, userhandle);
			}
			else
			{
				unsigned char   realfullpath[1024];
				struct __fs_active 	*a = f->active;

				// Wildcard system doesn't append final path element

				strcpy (realfullpath, p.acornfullpath);

				if (p.npath > 0)
				{
					strcat (realfullpath, ".");
					strcat (realfullpath, p.acornname); // 20231230 This line was outside the if() and it was probably adding an extra $ to a root path
				}

				// fs_debug (0, 2, "%12sfrom %3d.%3d User handle %02X allocated for %s", "", f->net, f->stn, userhandle, realfullpath);

				a->fhandles[userhandle].handle = handle;
				a->fhandles[userhandle].mode = mode;
				a->fhandles[userhandle].cursor = 0;
				a->fhandles[userhandle].cursor_old = 0;
				a->fhandles[userhandle].sequence = 2;     // This is the 0-1-0-1 oscillator tracker. But sometimes a Beeb will start with &81 ctrl byte instead of &80, so we set to 2 so that the first one is guaranteed to be different
				a->fhandles[userhandle].pasteof = 0; // Not past EOF yet
				a->fhandles[userhandle].is_dir = (p.ftype == FS_FTYPE_DIR ? 1 : 0);

				strcpy(a->fhandles[userhandle].acornfullpath, realfullpath);
				fs_store_tail_path(a->fhandles[userhandle].acorntailpath, realfullpath);

				reply.p.data[2] = (unsigned char) (FS_MULHANDLE(a, userhandle) & 0xff);

				if (is_32bit)
				{
					reply.p.data[3] = (p.ftype == FS_FTYPE_DIR ? 2 : 1);
					reply.p.data[4] = fsop_perm_to_acorn(a->server, p.perm, p.ftype);
					reply.p.data[5] = (FS_PERM_EFFOWNER(a, p.owner) ? 0 : 0xff);
					reply.p.data[6] = (p.length & 0xFF);
					reply.p.data[7] = (p.length & 0xFF00) >> 8;
					reply.p.data[8] = (p.length & 0xFF0000) >> 16;
					reply.p.data[9] = (p.length & 0xFF000000) >> 24;
					memcpy(&(reply.p.data[10]), &(reply.p.data[6]), 4);
				}

				fs_debug_full (0, 2, f->server, f->net, f->stn, "Opened handle %02X (%s)", userhandle, a->fhandles[userhandle].acornfullpath);
				fsop_aun_send(&reply, (is_32bit ? 14 : 3), f);
			}
		}
		else
		{
			fs_free_wildcard_list(&p);
			fsop_error(f, 0xC0, "Too many open files");
		}
	}


	return;

}

FSOP(07)
{

	uint8_t 	count;
	uint8_t		handle = FS_DIVHANDLE(f->active,*(f->data+5));
	struct __fs_active	*a = f->active;

	if (handle > FS_MAX_OPEN_FILES || (handle != 0 && !a->fhandles[handle].handle))
	{
		fs_debug_full (0, 2, f->server, f->net, f->stn, "Attempt to close bad/unknown handle &%02X", handle);
		fsop_error(f, 222, "Channel ?");
		return;
	}

	if (handle != 0)
	{
		fs_debug_full (0, 2, f->server, f->net, f->stn, "Close handle &%02X (%s)", handle, a->fhandles[handle].acornfullpath);
		fsop_close_handle(f, handle);
	}
	else // User wants to close everything
	{

		count = 1;

		while (count < FS_MAX_OPEN_FILES)
		{
			if (a->fhandles[count].handle && !(a->fhandles[count].is_dir)) // Close it only if it's open and not a directory handle
			{
				fs_debug_full (0, 2, f->server, f->net, f->stn, "Close handle &%02X (%s)", count, a->fhandles[count].acornfullpath);
				fsop_close_handle(f, count);
			}
			count++;
		}
	}

	fsop_reply_ok(f);

	return;

}

FSOP(2e)
{
	fsop_06(f); /* 24-bit version figures out 32-bit functioning */
}
