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

FSOP(42)
{

	fs_debug (0, 1, "%12sfrom %3d.%3d SJ Read encryption key - Not implemented, and it probably won't be", "", f->net, f->stn);

	// For now, return an error
	
	fsop_error (f, 0xFF, "Not implemented");

	return;

}

