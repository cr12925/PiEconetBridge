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

FSOP(18)
{

	FS_REPLY_DATA(0x80);

	unsigned char	username[11], username_padded[11];
	uint16_t	count;

	/* 
	 * Extract the username the caller wants to know above
	 */

	fs_copy_to_cr(username, (f->data + 5), 10);
	snprintf (username_padded, 11, "%-10s", username);

        fs_debug (0, 2, "%12sfrom %3d.%3d Read user info for %s", "", f->net, f->stn, username);

	/* Look for it in the active list */

        count = 0;

        while (count < ECONET_MAX_FS_ACTIVE)
        {

                if ((f->server->actives[count].stn != 0) && (!strncasecmp((const char *) username_padded, (const char *) f->server->users[f->server->actives[count].userid].username, 10)))
                {

                        unsigned short userid = f->server->actives[count].userid;
                        reply.p.data[0] = reply.p.data[1] = 0;
                        if (f->server->users[userid].priv & FS_PRIV_SYSTEM)
                                reply.p.data[2] = 0x40; // This appears to be what L3 does for a privileged user
                        else    reply.p.data[2] = 0;

                        reply.p.data[3] = f->server->actives[count].stn;
                        reply.p.data[4] = f->server->actives[count].net;

			//fprintf (stderr, "Found at %d.%d, priv %d\n", reply.p.data[4], reply.p.data[3], reply.p.data[2]);
                        fsop_aun_send(&reply, 5, f);
			return;
                }
                else count++;
        }

        if (count == ECONET_MAX_FS_ACTIVE)
                fsop_error(f, 0xBC, "No such user or not logged on");

	return;

}

