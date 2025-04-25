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
 * &1E - Read user free space 
 * &1F - Set user free space
 *
 * Neither does anything because we don't implement quotas.
 */

FSOP(1e)
{

	uint8_t		data[4];
	uint32_t	space; // A magic figure which doesn't upset DRDOS with Econet
	unsigned char	user[11];
	int16_t		uid;

	fs_copy_to_cr(user, (f->data + 5), 10);

	if (strlen(user) == 0)
		uid = f->userid;
	else
		uid = fsop_get_uid(f->server, user);

	if (!FS_ACTIVE_SYST(f) && uid != f->userid)
	{
		fsop_error (f, 0xFF, "Insufficient privilege");
		return;
	}

	if (uid < 0)
		fsop_error (f, 0xFF, "Unknown user");
	else
	{
		space = fsop_get_user_free (&(f->server->users[uid]));

		data[0] = (space & 0x000000FF);
		data[1] = (space & 0x0000FF00) >> 8;
		data[2] = (space & 0x00FF0000) >> 16;
		data[3] = (space & 0xFF000000) >> 24;

		fsop_reply_ok_with_data(f, data, 4);
	}

	return;

}

FSOP(1f)
{

	unsigned char	user[11];
	int16_t		uid;

	if (!FS_ACTIVE_SYST(f))
	{
		fsop_error (f, 0xFF, "Insufficient privilege");
		return;
	}

	fs_copy_to_cr(user, (f->data + 9), 10);

	if (strlen(user) == 0)
		uid = f->userid;
	else
		uid = fsop_get_uid(f->server, user);

	if (uid < 0)
		fsop_error (f, 0xFF, "Unknown user");
	else
	{
		f->server->users[uid].quota_free[0] = *(f->data + 5);
		f->server->users[uid].quota_free[1] = *(f->data + 6);
		f->server->users[uid].quota_free[2] = *(f->data + 7);
		f->server->users[uid].quota_free[3] = *(f->data + 8);
		fsop_reply_ok(f);
	}

	return;

}
