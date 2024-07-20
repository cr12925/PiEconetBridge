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
 * Implements
 *
 * FSOP 0x16 - Set Boot Opts
 * *SETOPT
 */

void fsop_setopt_internal(struct fsop_data *f, uint16_t uid, uint8_t opt)
{

	struct __fs_active *a;

	f->server->users[uid].bootopt = opt;

	a = f->server->actives;

	while (a)
	{
		if (a->userid == uid)
			a->bootopt = opt;

		a = a->next;
	}

}

FSOP(16)
{

	uint8_t		opt = FSOP_ARG;

	if (f->server->users[f->userid].priv2 & FS_PRIV2_FIXOPT)
		fsop_error(f, 0xBD, "Insufficient access");

	else if (opt > 7)
		fsop_error(f, 0xBD, "Bad option");

	else
	{
		fsop_setopt_internal(f, f->userid, opt);
		fsop_reply_ok(f);
	}

	return;

}

FSOP_00(SETOPT)
{

	unsigned char	username[11];
	unsigned char	optstring[10];
	uint8_t		new_opt;
	int16_t		uid;

	FSOP_EXTRACT(f,0,username,10);
	FSOP_EXTRACT(f,1,optstring,9);

	new_opt = atoi(optstring);

	uid = fsop_get_uid(f->server, username);

	fs_debug (0, 2, "%12sfrom %3d.%3d Set boot option %d for user %s", "", f->net, f->stn, new_opt, username);

	if (uid < 0)
		fsop_error(f, 0xFF, "No such user");
	else
	{
		fsop_setopt_internal(f, uid, new_opt);
		fsop_reply_ok(f);
	}

}
