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

void fsop_00_creditdebit_internal(struct fsop_data *f, struct oscli_params *p, uint8_t num, uint8_t param_start, int8_t posneg)
{

	char		userstr[10], amountstr[10];
	uint32_t	user, now;
	int32_t		amount;
	struct __fs_user	*u;

	fsop_00_oscli_extract(f->data, p, 0, userstr, 10, param_start);
	fsop_00_oscli_extract(f->data, p, 1, amountstr, 10, param_start);

	user = atoi(userstr);
	amount = atoi(amountstr);

	fs_debug_full (0, 1, f->server, f->net, f->stn, "FS %s user %d by %dK", (posneg < 0 ? "Debit" : "Credit"), user, amount);

	amount *= 1024;

	if (user > f->server->total_users || (f->server->users[user].priv == 0))
	{
		fsop_error (f, 0xFF, "Bad user ID");
		return;
	}

	u = &(f->server->users[user]);
	now = fsop_get_user_free(u);

	if (posneg < 0 && amount > now)
		amount = now; /* Don't go below 0 */

	amount *= (posneg < 0 ? 1 : -1); /* Because update_quota takes OFF a positive amount.. */

	fsop_update_quota(u, amount);

	fsop_reply_ok(f);
}

FSOP_00(CREDIT)
{
	fsop_00_creditdebit_internal(f, p, num, param_start, 1);
}

FSOP_00(DEBIT)
{
	fsop_00_creditdebit_internal(f, p, num, param_start, -1);
}
