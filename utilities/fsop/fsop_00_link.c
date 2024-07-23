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
 * Implements *LINK <source-fsp> <linked-fsp>
 *
 */

/* Manually defined because this is used for both *. and *CAT */

FSOP_00(LINK)
{
	fsop_00_MKLINK(f, p, num, param_start);
}

FSOP_00(MKLINK)
{
	char source[256], destination[256];
	struct path p_src, p_dst;

	fsop_00_oscli_extract(f->data, p, 0, source, 127, param_start);
	fsop_00_oscli_extract(f->data, p, 1, destination, 127, param_start);

	fs_debug (0, 1, "%12sfrom %3d.%3d LINK %s %s", "", f->net, f->stn, source, destination);

	if (!fsop_normalize_path(f, source, f->active->current, &p_src) || (p_src.ftype == FS_FTYPE_NOTFOUND))
	{
		fsop_error(f, 0xDC, "Not found");
		fs_free_wildcard_list(&p_src);
		return;
	}

	if (!fsop_normalize_path(f, destination, f->active->current, &p_dst) || (p_src.ftype == FS_FTYPE_NOTFOUND))
	{
		fsop_error(f, 0xDC, "Bad destination path");
		fs_free_wildcard_list(&p_src);
		fs_free_wildcard_list(&p_dst);
		return;
	}

	if (symlink(p_src.unixpath, p_dst.unixpath) == -1)
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "Unable to link %s to %s", p_src.unixpath, p_dst.unixpath);
		fsop_error(f, 0xFF, "Cannot create link");
		fs_free_wildcard_list(&p_src);
		fs_free_wildcard_list(&p_dst);
		return;
	}

	fsop_write_xattr(p_src.unixpath, p_src.owner, p_src.perm | FS_PERM_L, p_src.load, p_src.exec, p_src.homeof, f); // Lock the file. If you remove the file to which there are symlinks, stat goes bonkers and the FS crashes. So lock the source file so the user has to think about it!! (Obviously this will show as a locked linked file too, but hey ho)

	fs_free_wildcard_list(&p_src);
	fs_free_wildcard_list(&p_dst);

	fsop_reply_ok(f);
}

FSOP_00(UNLINK)
{
	char link[256];
	struct stat s;
	struct path pu;

	fsop_00_oscli_extract(f->data, p, 0, link, 254, param_start);

	fs_debug (0, 1, "%12sfrom %3d.%3d UNLINK %s", "", f->net, f->stn, link);

	if (!fsop_normalize_path(f, link, f->active->current, &pu) || (pu.ftype == FS_FTYPE_NOTFOUND))
	{
		fsop_error(f, 0xDC, "Not found");
		return;
	}

	// Is it a link?

	if (lstat(pu.unixpath, &s) != 0) // Stat error
	{
		fsop_error(f, 0xFF, "FS Error");
		return;
	}

	if (S_ISLNK(s.st_mode & S_IFMT))
	{
		if (unlink(pu.unixpath) != 0) // Error
		{
			fsop_error(f, 0xFF, "Cannot remove link");
			return;
		}
	}
	else
	{
		fsop_error(f, 0xFF, "Not a link");
		return;
	}
       
	fsop_reply_ok(f);	

}
