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

/* Note: All this does is return the path element of the command
 * with result code 3 so that ATOM computers then know what to do.
 * Essentially, we're just a parser for the ATOM.
 */

/* Manually defined because this is used for both *. and *CAT */

void fsop_00_catalogue(struct fsop_data *f, struct oscli_params *p, uint8_t num, uint8_t param_start)
{

	FS_REPLY_DATA(0x80);

	unsigned char	path[256];

	//fprintf (stderr, "fsop_00_catalogue: num = %d, param_start = %d, f->data+5 = %s\n", num, param_start, f->data+5);

	reply.p.data[0] = 0x03; /* *CAT */

	if (num > 1)
		fsop_error(f, 0xFF, "Too many parameters");
	else if (num == 1)
		fsop_00_oscli_extract(f->data, p, 0, path, 240, param_start);
	else	strcpy (path, "");

	fs_debug (0, 1, "%12sfrom %3d.%3d *CAT %s (path length %d)", "", f->net, f->stn, path, strlen(path));

	strncpy(&(reply.p.data[2]), path, strlen(path));
	reply.p.data[2+strlen(path)] = 0x0D; /* CR terminator */

	fsop_aun_send (&reply, 3+strlen(path), f);

	return;

}

