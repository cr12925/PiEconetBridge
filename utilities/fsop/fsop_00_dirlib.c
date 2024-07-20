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
 * Implements *DIR, *LIB
 */

void	fsop_00_dirlib_internal(struct fsop_data *f, uint8_t *user_handle, unsigned char *dirname, uint8_t is_dir)
{

	struct path		p;
	unsigned char		my_dirname[256];
	struct __fs_file	*n;
	int8_t			err;
	uint8_t			handle;
	int			found;

	if (*(dirname) == '"' && *(dirname + strlen(dirname) - 1) == '"') /* Need to de-quote */
	{
		unsigned char		n[256];

		strcpy (n, &(dirname[1]));

		n[strlen(n)-1] = '\0';

		strcpy (my_dirname, n);
	}

	found = fsop_normalize_path_wildcard(f, dirname, FSOP_CWD, &p, 1);

	fs_free_wildcard_list(&p); /* We don't need the other possible wildcard matches... */

	if (!found || p.ftype == FS_FTYPE_NOTFOUND)
		fsop_error(f, 0xFE, "Not found");
	else if (p.ftype != FS_FTYPE_DIR)
		fsop_error(f, 0xAF, "Types don't match");
	else if (!FS_PERM_EFFOWNER(f->active, p.owner) && !(p.perm & FS_PERM_OTH_R))
		fsop_error(f, 0xBD, "Insufficient access");
	else
	{
		
		/* Close old handle */

		fs_debug_full (0, 2, f->server, f->net, f->stn, "Closing old %s handle %d", is_dir ? "CWD" : "LIB", *user_handle);

		// 20240720 - deallocate user dir channel also does close interlock
		//fsop_close_interlock(f->server, f->active->fhandles[*user_handle].handle, 1);
		fsop_deallocate_user_dir_channel(f->active, *user_handle);

		/* Open the new dir */

		if (!(n = fsop_open_interlock(f, p.unixpath, 1, &err, 1)))
			fsop_error(f, 0xC7, "Dir unreadable");
		else if (!(handle = fsop_allocate_user_dir_channel(f->active, n)))
		{
			fsop_close_interlock(f->server, n, 1);
			fsop_error(f, 0xC0, "Too many open directories");
		}
		else /* Successful open */
		{
			char		new_dir[256];
			char		tail[ECONET_MAX_PATH_LENGTH];
			FS_REPLY_DATA(0x80);

			strncpy(new_dir, (const char *) p.acornfullpath, 255);

			/* normalize wildcard doesn't add tail path */
			strcat(new_dir, ".");
			strcat(new_dir, p.acornname);

			fs_store_tail_path(tail, new_dir);
			
			strcpy (f->active->fhandles[handle].acornfullpath, new_dir);
			strcpy (f->active->fhandles[handle].acorntailpath, tail);

			*user_handle = handle;

			fs_debug_full (0, 2, f->server, f->net, f->stn, "User handle %d allocated for new %s (%s)", handle, is_dir ? "CWD" : "LIB", new_dir);

			if (is_dir)
			{
				strncpy((char *) f->active->current_dir, (const char *) new_dir, 255);
				strcpy(f->active->current_dir_tail, tail);
				f->active->current_disc = p.disc;
				reply.p.data[0] = 0x07; /* CWD change */
				reply.p.data[2] = FS_MULHANDLE(handle);
			}
			else
			{

				strncpy((char *) f->active->lib_dir, (const char *) new_dir, 255);
				strcpy(f->active->lib_dir_tail, tail);
				reply.p.data[0] = 0x09; /* LIB change */
				reply.p.data[2] = FS_MULHANDLE(handle);
			}

			fsop_aun_send(&reply, 3, f);

		}

	}

}

FSOP_00(DIR)
{

	unsigned char	dirname[256];

	if (num == 0) /* No directory given - pick our home dir */
		strcpy(dirname, "$.Library"); /* Normalize routine will fix this up */
	else
		FSOP_EXTRACT(f,0,dirname,255);

	fs_debug (0, 1, "%12sfrom %3d.%3d DIR %s", "", f->net, f->stn, dirname);

	fsop_00_dirlib_internal(f, &(f->active->current), dirname, 1);

}

FSOP_00(LIB)
{
	unsigned char	dirname[256];

	if (num == 0) /* No directory given - pick our home dir */
		strcpy(dirname, "$.Library"); /* Normalize routine will fix this up */
	else
		FSOP_EXTRACT(f,0,dirname,255);

	fs_debug (0, 1, "%12sfrom %3d.%3d LIB %s", "", f->net, f->stn, dirname);

	fsop_00_dirlib_internal(f, &(f->active->lib), dirname, 0);

}

