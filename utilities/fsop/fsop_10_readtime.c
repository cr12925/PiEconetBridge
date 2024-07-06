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

FSOP(10)
{

	uint8_t		data[5];
	struct tm	t;
	time_t		now;
	uint8_t		monthyear, day;

        fs_debug (0, 2, "%12sfrom %3d.%3d Read FS time", "", f->net, f->stn);

        now = time(NULL);
        t = *localtime(&now);

        fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);

        data[0] = day;
        data[1] = monthyear;
        data[2] = t.tm_hour;
        data[3] = t.tm_min;
        data[4] = t.tm_sec;

	fsop_reply_ok_with_data(f, data, 5);

	return;

}

