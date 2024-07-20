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
 * Implements *LOGOFF <username | station>
 *
 */


FSOP_00(LOGOFF)
{
	unsigned char 	parameter[11];
	uint8_t		l_net, l_stn;

	l_net = l_stn = 0;

	FSOP_EXTRACT(f,0,parameter,10);

	if (isdigit(parameter[0])) // Assume station number, possible net number too
	{
		struct __fs_active 	*a, *n;

		if (sscanf(parameter, "%hhd.%hhd", &l_net, &l_stn) != 2)
		{
			if (sscanf(parameter, "%hhd", &l_stn) != 1)
			{
				fsop_error(f, 0xFF, "Bad station specification");
				return;
			}
			else    l_net = f->server->net;
		}

		fs_debug (0, 1, "%12sfrom %3d.%3d Force log off station %d.%d", "", f->net, f->stn, l_net, l_stn);

		a = f->server->actives;

		while (a)
		{
			n = a->next;

			if (a->net == l_net && a->stn == l_stn)
			{
				fsop_bye_internal(a, 0, 0); /* Silent bye */
				break;
			}

			a = n;

		}

	}
	else // Username
	{
		int16_t		userid;
		struct __fs_active 	*a, *n;

		fs_debug (0, 1, "%12sfrom %3d.%3d Force log off user '%s'", "", f->net, f->stn, parameter);

		userid = fsop_get_uid (f->server, parameter);

		if (userid < 0)
		{
			fsop_error(f, 0xFF, "Unknown user");
			return;
		}

		a = f->server->actives;

		while (a)
		{
			n = a->next;

			if (a->userid == userid)
				fsop_bye_internal(a, 0, 0); /* Silent bye */

			a = n;
		}
	}

	fsop_reply_ok(f);

}

