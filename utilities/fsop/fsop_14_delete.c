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
 * Implements FSOP 0x14 (delete object)
 * and *DELETE <fsp>
 *
 * The internal function returns either:
 * >= 0 number of files deleted
 * < 0 an error:
 * -1 Bad path
 * -2 Not found
 * -3 Entry locked
 * -4 Directory not empty
 * -5 Insufficient access
 * -6 Already open
 * -7 FS Error
 */

int fsop_delete_internal (struct fsop_data *f, unsigned char *path, uint8_t relative_to)
{

	struct path 		p;
	struct path_entry 	*e;
	uint16_t		count;
	struct __fs_file	*handle;
	int8_t			err;

	if (strlen(path) == 0)
		return -1;

	/* Normalize */

	if (!fsop_normalize_path_wildcard(f, path, relative_to, &p, 1) || !(p.paths))
		return -2; /* Not found */

	/* Deal with what we found */
	e = p.paths;

	count = 0;

	while (e)
	{
		if (e->ftype == FS_FTYPE_FILE)
		{
			handle = fsop_open_interlock(f, e->unixpath, 2, &err, 0);

			if (err < 0) // Interlock or other problem
			{
				fs_free_wildcard_list(&p);
				return -6;
			}
			else    fsop_close_interlock(f->server, handle, 2);
		}

		if (e->ftype == FS_FTYPE_DIR && (fsop_get_acorn_entries(f, p.unixpath) > 0))
		{
			fs_free_wildcard_list(&p);
			return -4;
		}
		else if (p.ftype == FS_FTYPE_NOTFOUND)
		{
			fs_free_wildcard_list(&p);
			return -2;
		}
		else if ((e->perm & FS_PERM_L))
		{
			fs_free_wildcard_list(&p);
			return -3;
		}
		else if (
				!( FS_PERM_EFFOWNER(f->active,e->owner) || ((e->parent_owner == f->userid) && (e->parent_perm & FS_PERM_OWN_W))
			)
		)
		{
			fs_free_wildcard_list(&p);
			return -5;
		}
		else
		if (
				((e->ftype == FS_FTYPE_FILE) && unlink((const char *) e->unixpath)) ||
			((e->ftype == FS_FTYPE_DIR) && rmdir((const char *) e->unixpath))
			) // Failed
			{       
				fs_free_wildcard_list(&p);
				return -7;
			}
			else
			{
				// Silently delete the INF file if it exists
				char *dotfile=pathname_to_dotfile(e->unixpath, FS_CONFIG(f->server,fs_infcolon));
				count++;
				unlink(dotfile);
				free(dotfile);
			}

		e = e->next;
	}

	return count;

}

void fsop_do_delete(struct fsop_data *f, unsigned char *path, uint8_t relative_to)
{

	int 	e;

	e = fsop_delete_internal(f,path,FSOP_CWD);

	if (e >= 0)
		fsop_reply_ok(f);
	else
	{
		switch (e * -1)
		{
			case 1: fsop_error(f, 0xFF, "Bad path"); break;
			case 2: fsop_error(f, 0xD6, "Not found"); break;
			case 3: fsop_error(f, 0xC3, "Entry Locked"); break;
			case 4: fsop_error(f, 0xFF, "Dir not empty"); break;
			case 5: fsop_error(f, 0xBD, "Insufficient access"); break;
			case 6: fsop_error(f, 0xC2, "Already open"); break;
			default: fsop_error(f, 0xFF, "FS Error"); break;
		}
	}

}

FSOP(14)
{

	unsigned char	path[1024];
	uint8_t		path_start;

	path_start = 5;

	while (path_start < f->datalen && *(f->data + path_start) == ' ')
		path_start++;

	fs_copy_to_cr(path, (f->data + path_start), 1023);

	fsop_do_delete(f, path, FSOP_CWD);

	return;

}

FSOP_00(DELETE)
{
	unsigned char	path[256];

	fsop_00_oscli_extract(f->data, p, 0, path, 255, param_start);

	fsop_do_delete(f, path, FSOP_CWD);

}

