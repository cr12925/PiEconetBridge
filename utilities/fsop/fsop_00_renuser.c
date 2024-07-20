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
 * Implements *RENUSER <oldusername> <newusername>
 */

FSOP_00(RENUSER)
{
	unsigned char 	username[11], new_name[11], new_padded[11];;
	int16_t     	uid;

	FSOP_EXTRACT(f,0,username,10);
	FSOP_EXTRACT(f,1,new_name,10);

	fs_copy_padded (new_padded, new_name, 10);

	uid = fsop_get_uid(f->server, username);

	if (uid < 0)
		fsop_error(f, 0xbc, "Unknown user");
	else
	{
		if (uid == f->active->userid)
			fsop_error(f, 0xfe, "Cannot rename self while logged in");
		else
		{
			fs_toupper(new_padded);

			memcpy(f->server->users[uid].username, new_name, 10);
			//fs_write_user(server, uid, (unsigned char *) &(users[server][uid]));

			fs_debug (0, 1, "%12sfrom %3d.%3d Rename user %s to %s (uid %d)", "", f->net, f->stn, username, new_padded, uid);

			fsop_reply_ok(f);
		}
	}

}

