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
 * Implements *DISCMASK and *DISKMASK
 *
 */


FSOP_00(DISCMASK)
{
	char	    	username[20], discs[10];
	int16_t		userid;
	uint16_t	mask;

	FSOP_EXTRACT(f, 0, username, 10);
	FSOP_EXTRACT(f, 1, discs, 9);

	fs_debug (0, 1, "%12sfrom %3d.%3d *DISCMASK %s %s", "", f->net, f->stn, username, discs);

	userid = fsop_get_uid(f->server, username);

	if (userid < 0)
	{
		fsop_error (f, 0xFF, "Unknown user");
		return;
	}

	mask = f->user->discmask;

	if (!strcasecmp(discs, "ALL"))
		mask = 0xffff;
	else if (!strcasecmp(discs, "NONE"))
		mask = 0x0000;
	else
	{
		if (sscanf(discs, "%04hX", &mask) != 1)
		{
			fsop_error(f, 0xFF, "Bad disk mask");
			return;
		}
	}

	if (mask != f->server->users[userid].discmask)
	{
		f->server->users[userid].discmask = mask;
		fsop_reply_ok(f);
	}
	else
		fsop_error(f, 0xFF, "Bad parameter or mask unchanged");

}

FSOP_00(DISKMASK)
{
	fsop_00_DISCMASK(f, p, num, param_start);
}
