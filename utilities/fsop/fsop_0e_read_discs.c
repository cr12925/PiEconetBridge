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

FSOP(0e)
{

	FS_R_DATA(0x80);

	uint8_t		start = FSOP_ARG;
	uint8_t		number = *(f->data+6);
	uint8_t		delivered = 0;
	struct __fs_disc	*disc;
	uint8_t		data_ptr = 3;
	uint8_t		counted;

	r.p.data[0] = 10;

	fs_debug (0, 2, "%12sfrom %3d.%3d Read Discs from %d (up to %d)", "", f->net, f->stn, start, number);

	disc = f->server->discs;
	counted = 0;

	/* Now copy discs to the reply, if there are any */

	while (disc && delivered < number)
	{
		if (FS_DISC_VIS(f->server, f->userid, disc->index) && (disc->index >= start))
		{
				snprintf((char *) &(r.p.data[data_ptr]), 18, "%c%-16s", disc->index, disc->name);
				delivered++;
				data_ptr += 17;
		}

		disc = disc->next;
	}

	r.p.data[2] = delivered;

	fsop_aun_send(&r, data_ptr, f);

	return;

}

