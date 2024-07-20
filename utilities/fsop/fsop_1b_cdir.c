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

int fsop_cdir_internal(struct fsop_data *f, unsigned char *path, uint8_t relative_to)
{

	struct path 		p;

	if (strlen(path) == 0)
		return -1;

	/* Normalize */

	if (fsop_normalize_path(f, path, relative_to, &p) && p.ftype != FS_FTYPE_NOTFOUND)
		return -2; /* Not found */

	if (!FS_PERM_EFFOWNER(f->active, p.parent_owner)) /* No rights in the parent directory */
		return -5; /* Insufficient access */

	if (!mkdir((const char *) p.unixpath, 0770))
	{
		fsop_write_xattr(p.unixpath, f->userid, FS_CONF_DEFAULT_DIR_PERM(f->server), 0, 0, 0, f);
		return 0;
	}

	return 1;

}

void fsop_do_cdir(struct fsop_data *f, unsigned char *path, uint8_t relative_to)
{

	int 	e;

	e = fsop_cdir_internal(f,path,FSOP_CWD);

	if (e >= 0)
		fsop_reply_ok(f);
	else
	{
		switch (e * -1)
		{
			case 1: fsop_error(f, 0xFF, "Bad path"); break;
			case 2: fsop_error(f, 0xFF, "Exists"); break;
			default: fsop_error(f, 0xFF, "FS Error"); break;
		}
	}

}

FSOP(1b)
{

	unsigned char	path[1024];
	uint8_t		path_start;

	path_start = 5;

	while (path_start < f->datalen && *(f->data + path_start) == ' ')
		path_start++;

	fs_copy_to_cr(path, (f->data + path_start), 1023);

	fsop_do_cdir(f, path, FSOP_CWD);

	return;

}

FSOP_00(CDIR)
{
	unsigned char	path[256];

	fsop_00_oscli_extract(f->data, p, 0, path, 255, param_start);

	fsop_do_cdir(f, path, FSOP_CWD);

}

