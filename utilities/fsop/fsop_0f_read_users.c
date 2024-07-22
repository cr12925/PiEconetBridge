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
 * FSOP &0f - Read logged on users
 */

FSOP(0f)
{

	FS_R_DATA(0x80);

	uint8_t start, number;
	uint8_t found, ptr;
	uint8_t deliver_count;
	char	username[11];

	struct __fs_active 	*a;

	start = FSOP_ARG;
	number = *(f->data + 6);

	r.p.data[2] = 0; // 0 users found unless we alter it later

	ptr = 3;

	fs_debug_full (0, 2, f->server, f->net, f->stn, "Read logged on users %d to %d", start, number);

	// Get to the start entry in active[server][]

	found = 0;

	a = f->server->actives;

	while (a && found < start)
	{
		if (
			(f->user->priv & FS_PRIV_SYSTEM)
		||	!(f->server->users[a->userid].priv & FS_PRIV_SYSTEM) /* We aren't syst and the logged on user is */
		||	a->userid == f->userid
		||	!(f->server->users[a->userid].priv2 & FS_PRIV2_HIDEOTHERS)
		)
			found++;

		a = a->next;
	}

	deliver_count = 0;

	while (a && found < (start + number))
	{
		if (
			(f->user->priv & FS_PRIV_SYSTEM)
		||	!(f->server->users[a->userid].priv & FS_PRIV_SYSTEM) /* We aren't syst and the logged on user is */
		||	a->userid == f->userid
		||	!(f->server->users[a->userid].priv2 & FS_PRIV2_HIDEOTHERS)
		)
		{
			char *space;

			memcpy(username, f->server->users[a->userid].username, 10);
			username[10] = '\0';

			space = strchr(username, ' ');

			if (space) *space = '\0';

			found++;

			deliver_count++;

			sprintf((char * ) &(r.p.data[ptr]), "%c%c%-s%c%c",
				a->stn, a->net,
				username, (char) 0x0D,
				((f->server->users[a->userid].priv & FS_PRIV_SYSTEM) ? 1 : 0) 
			);

			ptr += 4 + strlen(username); // 2 byte net/stn, 1 byte priv, 1 x 0x0d + the characters in the username
		}

		a = a->next;

	}

	r.p.data[2] = deliver_count;

	fsop_aun_send (&r, ptr, f);

	return;

}

