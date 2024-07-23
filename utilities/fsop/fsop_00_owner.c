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
	uint32_t	mtype;
	uint16_t	hw;

	mtype = f->active->machinepeek;

	hw = ((mtype & 0xFF000000) >> 24) | ((mtype & 0x00FF0000) >> 8);

	if (hw > 0x000C || hw == 0x0007 || hw == 0x0008 || hw == 0x0009 || hw == 0x000B)
	{
		fsop_error (f, 0xFF, "Not supported on this platform");
		return;
	}

	fsop_00_oscli_extract(f->data, p, 0, path, 240, param_start);

	fs_debug_full (0, 1, f->server, f->net, f->stn, "*OWNER %s from type", path);

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

