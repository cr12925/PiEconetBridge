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
 * Read EOF status on handle
 */

FSOP(11)
{

	uint8_t result = 0;
	uint8_t	handle = FS_DIVHANDLE(f->active,FSOP_ARG);

	struct stat     sb;

	if (handle < 1 || handle >= FS_MAX_OPEN_FILES || !(f->active->fhandles[handle].handle))
		fsop_error(f, 0xDE, "Channel ?");

	else // Valid handle it appears
	{

		FS_R_DATA(0x80);

		FILE 	*h;
		long    filesize;
		struct __fs_file	*ptr;

		ptr = (struct __fs_file *) f->active->fhandles[handle].handle;

		h =  ptr->handle;

		if (fstat(fileno(h), &sb))
		{
			fsop_error(f, 0xFF, "FS Error");
			return;
		}

		filesize = sb.st_size;

		if (f->active->fhandles[handle].cursor == filesize)
			result = 1;

		r.p.data[2] = result;

		fsop_aun_send(&r, 3, f);
	}

	return;

}

