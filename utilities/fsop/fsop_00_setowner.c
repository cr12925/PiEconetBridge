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
 * *SETOWNER - change ownership on a file.
 *
 * *SETOWNER <fsp> (<user>)
 *
 * If <user> is included, then if the user is not the calling user
 * the user must have SYST privileges
 *
 */

FSOP_00(SETOWNER)
{

	struct path pn;
	unsigned char path[256];
	unsigned char username[11];
	uint16_t	userid;

	fsop_00_oscli_extract(f->data, p, 0, path, 240, param_start);

	if (num > 1)
	{
		fsop_00_oscli_extract(f->data, p, 1, username, 10, param_start);
		if ((userid = fsop_get_uid(f->server, username)) == -1)
		{
			fsop_error(f, 0xFF, "Unknown user");
			return;
		}
		if ((userid != f->userid) && (!FS_ACTIVE_SYST(f->active)))
		{
			fsop_error(f, 0xBD, "Insufficient access");
			return;
		}
	}
	else
		userid = f->userid;

	if (num > 1)
		fs_debug (0, 1, "%12sfrom %3d.%3d *SETOWNER %s %s (uid %d)", "", f->net, f->stn, path, username, userid);
	else
		fs_debug (0, 1, "%12sfrom %3d.%3d *SETOWNER %s", "", f->net, f->stn, path);

	if (!fsop_normalize_path(f, path, f->cwd, &pn) || pn.ftype == FS_FTYPE_NOTFOUND)
		fsop_error(f, 0xD6, "Not found");
	else if (pn.perm & FS_PERM_L)
		fsop_error(f, 0xC3, "Entry Locked");
	else if (pn.parent_owner == userid || FS_ACTIVE_SYST(f->active))
	{
		pn.attr.owner = userid;
		fsop_write_xattr(pn.unixpath, pn.attr.owner, pn.attr.perm, pn.attr.load, pn.attr.exec, pn.attr.homeof, f);
		fsop_reply_success(f, 0, 0);
	}

	return;

}

FSOP_00(CHOWN)
{
	fsop_00_SETOWNER(f, p, num, param_start);
}
