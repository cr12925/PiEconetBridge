/*
  (c) 2025 Chris Royle
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

#include "../../include/fs.h"

FSOP(43)
{

	FS_REPLY_DATA(0x80);

	uint8_t		arg;

	arg = *(f->data + 5);

	fs_debug (0, 1, "%12sfrom %3d.%3d SJ Tape operation %02X, %s - Not yet implemented", "", f->net, f->stn, arg, 
			arg == 0 ? "Determine whether backup possible" :
			arg == 1 ? "Read tape ID block" :
			arg == 2 ? "Read current status, auto backup" :
			arg == 3 ? "Write current status of auto backup" :
			arg == 4 ? "Read tape partition size" : 
			"Bad argument"
			);

	// For now, return an error
	
	fsop_error (f, 0xFF, "Not implemented");

	return;

}

