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

#include "../../include/fs.h"

FSOP(40)
{

	FS_REPLY_DATA(0x80);

	unsigned int start, count;

	unsigned char disc;

	uint32_t	space;

	start = *(f->data+8) + (*(f->data + 9) << 8);
	count = *(f->data + 10) + (*(f->data + 11) << 8);
	disc = *(f->data + 12);

	fs_debug (0, 1, "%12sfrom %3d.%3d SJ Read Account information from %d for %d entries on disc no. %d", "", f->net, f->stn, start, count, disc);

	space = f->user->quota_free[0] +
		(f->user->quota_free[1] << 8) +
		(f->user->quota_free[2] << 16) +
		(f->user->quota_free[3] << 24);

	space /= 1024; // Kilobytes
	if (space > 65536) space=65536; /* Reply packet only has 2 bytes */

	// For now, return a dummy entry

	reply.p.data[2] = reply.p.data[3] = 0xff; // Next account to try
	reply.p.data[4] = 0x01; // 1 account returned
	reply.p.data[5] = 0x00; // Number of accounts returned high byte
	reply.p.data[6] = f->userid & 0xff;
	reply.p.data[7] = (f->userid & 0xff00) >> 8;
	reply.p.data[8] = (space & 0xff);
	reply.p.data[9] = (space & 0xff00) >> 8;

	fsop_send(10);
	
	return;

}

