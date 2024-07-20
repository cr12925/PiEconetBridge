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

	fsop_reply_ok(f);

	return;

}

FSOP(1f)
{

	fsop_reply_ok(f);

	return;

}
