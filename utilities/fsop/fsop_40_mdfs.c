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
	FS_REPLY_COUNTER();

	unsigned int start, count;

	uint8_t	done;
	uint32_t	nextaccount;

	unsigned char disc;

	uint32_t	space;

	start = *(f->data+6) + (*(f->data + 7) << 8);
	count = *(f->data + 8) + (*(f->data + 9) << 8);
	disc = *(f->data + 10); /* We ignore this - quotas are global */

	fs_debug (0, 1, "%12sfrom %3d.%3d SJ Read Account information from %d for %d entries on disc no. %d", "", f->net, f->stn, start, count, disc);

	if (!FS_ACTIVE_SYST(f->active))
	{
		start = f->userid;
		count = 1;
	}

	done = 0;
	nextaccount = start;

	FS_CPUT16(0); // OK Reply
	FS_CPUT16(0); // Next account to try - placeholder
	FS_CPUT16(0); // Number of accounts returned - placeholder

	while ((done < count) && (nextaccount <= 65535))
	{
		if (f->server->users[nextaccount].priv == 0) /* Not in use */
		{
			nextaccount++;
			continue;
		}

		space = f->server->users[nextaccount].quota_free[0] +
			(f->server->users[nextaccount].quota_free[1] << 8) +
			(f->server->users[nextaccount].quota_free[2] << 16) +
			(f->server->users[nextaccount].quota_free[3] << 24);
	
		space /= 1024; // Kilobytes
		if (space > 65536) space=65536; /* Reply packet only has 2 bytes */
	
		FS_CPUT16(nextaccount);
		FS_CPUT16(space);

		done++;
		nextaccount++;
	}
	
	while (nextaccount < 65535 && (f->server->users[nextaccount].priv == 0))
		nextaccount++; // Find next used entry, or return 0xFFFF

	reply.p.data[2] = (nextaccount & 0xff);
	reply.p.data[3] = (nextaccount & 0xff00) >> 8; // Next account to try
	reply.p.data[4] = (done & 0xff); // Accounts returned, low byte
	reply.p.data[5] = (done & 0xff00) >> 8; // Number of accounts returned high byte

	FS_CSEND();
	
	return;

}

