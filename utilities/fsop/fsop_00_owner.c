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

/* Generate error which reveals name & ID of file/dir owner. NB won't work on
 * RISC OS because it doesn't keep its CWD up to date!
 *
 * This version doesn't check for SYST because the command parser does it.
 */

FSOP_00(OWNER)
{

	struct path pn;
	unsigned char path[256];
	unsigned char result[30];
	unsigned char username[11];

	fsop_00_oscli_extract(f->data + 5, p, 1, path, 240);

	fs_debug (0, 1, "%12sfrom %3d.%3d *OWNER %s", "", f->net, f->stn, path);

	if (!fsop_normalize_path(f, path, f->cwd, &pn) || pn.ftype == FS_FTYPE_NOTFOUND)
		fsop_error(f, 0xD6, "Not found");
	else
	{
		snprintf(username, 11, "%-10s", f->server->users[pn.owner].username);
		snprintf(result, 30, "Owner: %-10s %04X", username, pn.owner);

		fsop_error(f, 0xFF, result);
	}

	return;

}

