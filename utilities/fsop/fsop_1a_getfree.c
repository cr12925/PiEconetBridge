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

FSOP(1a)
{

	FS_REPLY_DATA(0x80); // Sets up as a data packet, ctrl byte as specified, to the reply port, with first two data bytes 0

	struct __fs_disc	*disc;
	uint8_t 	path[1024];
	unsigned char	discname[17];

	fs_copy_to_cr(discname, f->data+5, 16);

	fs_debug_full (0, 2, f->server, f->net, f->stn, "Read free space on %s", discname);

	disc = f->server->discs;

	while (disc)
	{
		if (!strcasecmp((const char *) discname, (const char *) disc->name))
		{
			struct statvfs s;

			snprintf((char * ) path, 1024, "%s/%1d%s",(const char * ) f->server->directory, disc->index, (const char *) disc->name);

			if (!statvfs((const char * ) path, &s))
			{
				unsigned long long fr; // free space
				unsigned long long e; // extent of filesystem

				fr = (s.f_bsize >> 8) * s.f_bavail;
				e = (s.f_bsize >> 8) * s.f_blocks;

				// This is well dodgy and probably no use unless you put the filestore on a smaller filing system

				if (fr > 0xffffff) fr = 0x7fffff;

				reply.p.data[2] = (fr % 256) & 0xff;
				reply.p.data[3] = ((fr >> 8) % 256) & 0xff;
				reply.p.data[4] = ((fr >> 16) % 256) & 0xff;

				if (e > 0xffffff) e = 0x7fffff;

				reply.p.data[5] = ((e-fr) % 256) & 0xff;
				reply.p.data[6] = (((e-fr) >> 8) % 256) & 0xff;
				reply.p.data[7] = (((e-fr) >> 16) % 256) & 0xff;

				fsop_send(8);

				return;

			}
			else fsop_error(f, 0xFF, "FS Error");
		}

		disc = disc->next;
	}

	fsop_error(f, 0xFF, "No such disc");


	return;

}

