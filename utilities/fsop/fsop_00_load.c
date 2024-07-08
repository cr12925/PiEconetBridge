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

/* Parser for *LOAD for ATOMs that can't do it themselves */

FSOP_00(LOAD)
{

	FS_REPLY_DATA(0x80);

	unsigned char path[256];
	uint32_t	load = 0;
	unsigned char load_string[10];

	strcpy(load_string, "");

	fsop_00_oscli_extract(f->data, p, 0, path, 240, param_start);

	if (num == 2) /* We have a load address as well */
	{
		uint8_t		count = 0;
		uint8_t		c;

		fsop_00_oscli_extract(f->data, p, 1, load_string, 8, param_start);

		while (count < 8 && count < strlen(load_string))
		{
			c = load_string[count];

			if (c >= '0' && c <= '9')
				c -= '0';
			else if (c >= 'A' && c <= 'F')
				c = c - 'A' + 10;
			else if (c >= 'a' && c <= 'f')
				c = c - 'a' + 10;
			else
			{
				fsop_error (f, 0xFF, "Bad load address");
				return;
			}

			load = (load << 4) + (c);

			count++;
		}

	}

	fs_debug (0, 1, "%12sfrom %3d.%3d *LOAD %s %s (0x%08X)", "", f->net, f->stn, path, load_string, load);

	reply.p.data[0] = 0x02; /* Load */
	reply.p.data[2] = (load) & 0xff;
	reply.p.data[3] = (load >> 8) & 0xff;
	reply.p.data[4] = (load >> 16) & 0xff;
	reply.p.data[5] = (load >> 24) & 0xff;

	reply.p.data[6] = (num == 2) ? 0xff : 0x00; /* 0xff means we had a load address to use */

	strcpy(&(reply.p.data[7]), path);
	reply.p.data[7+strlen(path)] = 0x0D;

	fsop_aun_send (&reply, 7 + 1 + strlen(path), f);

	return;

}

