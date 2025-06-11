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
 * Implements *PRINTER <printer>
 */

FSOP_00(PRINTER)
{
        int printerindex = 0xff;
	unsigned char	pname[7];

	FSOP_EXTRACT(f,0,pname,6);

        printerindex = get_printer(f->server->net, f->server->stn, pname);

        fs_debug (0, 1, "%12sfrom %3d.%3d Select printer %s - %s", "", f->net, f->stn, pname, (printerindex == -1) ? "UNKNOWN" : "Succeeded");

        if (printerindex == -1) // Failed
                fsop_error(f, 0xFF, "Unknown printer");
        else
        {
                f->active->printer = printerindex;
                fsop_reply_ok(f);
        }

}

