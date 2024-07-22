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

uint8_t fs_check_seq(uint8_t a, uint8_t b)
{
        return ((a ^ b) & 0x03);
}

FSOP(08) /* Getbyte */
{

	FS_R_DATA(0x80);
	uint8_t		handle;
	uint8_t		ctrl;
	unsigned char b; // Character read, if appropriate
	FILE *h;
	unsigned char result;
	struct stat statbuf;
	struct __fs_file *fl;
	struct __fs_active *a;

	a = f->active;
	handle = FS_DIVHANDLE(a,FSOP_URD); /* Handle appears in URD slot */
	ctrl = f->ctrl;

	if (handle < 1 || handle >= FS_MAX_OPEN_FILES || !a->fhandles[handle].handle)
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	fl = a->fhandles[handle].handle;
	h = fl->handle;

	fs_debug (0, 2, "%12sfrom %3d.%3d Get byte on channel %02x, cursor %04lX, ctrl seq is %s (stored: %02X, received: %02X)", "", f->net, f->stn, handle, a->fhandles[handle].cursor,
			fs_check_seq(a->fhandles[handle].sequence, ctrl) ? "OK" : "WRONG", a->fhandles[handle].sequence, ctrl);

	if (a->fhandles[handle].is_dir) // Directory handle
	{
		r.p.ctrl = ctrl;
		r.p.data[2] = 0xfe; // Always flag EOF
		r.p.data[3] = 0xc0;

		fsop_aun_send(&r, 4, f);

		return;
	}

	if (fstat(fileno(h), &statbuf)) // Non-zero = error
	{
		fsop_error_ctrl(f, ctrl, 0xFF, "FS Error on read");
		return;
	}

	if (a->fhandles[handle].pasteof) // Already tried to read past EOF
	{
		fsop_error_ctrl(f, ctrl, 0xDF, "EOF");
		return;
	}

	// Put the pointer back where we were

	clearerr(h);

	if (!fs_check_seq(a->sequence, ctrl)) // Assume we want the previous cursor
		fseek(h, a->fhandles[handle].cursor_old, SEEK_SET);
	else
		fseek(h, a->fhandles[handle].cursor, SEEK_SET);

	a->fhandles[handle].cursor_old = ftell(h);

	fs_debug (0, 2, "%12sfrom %3d.%3d Get byte on channel %02x, cursor %04lX, file length = %04lX, seek to %04lX", "", f->net, f->stn, handle, a->fhandles[handle].cursor, ftell(h));

	b = fgetc(h);

	result = 0;

	if (ftell(h) == statbuf.st_size) result = 0x80;

	if (feof(h))
	{
		result = 0xC0; // Attempt to read past end of file
		a->fhandles[handle].pasteof = 1;
	}

	a->fhandles[handle].cursor = ftell(h);
	a->fhandles[handle].sequence = (ctrl & 0x01);

	r.p.ctrl = ctrl;
	r.p.data[2] = (feof(h) ? 0xfe : b);
	r.p.data[3] = result;

	fsop_aun_send(&r, 4, f);

}

FSOP(09) /* Putbyte */
{
	FS_R_DATA(0x80);
	uint8_t		handle;
	uint8_t		ctrl;
	uint8_t 	b; // Character read, if appropriate
	uint8_t 	buffer[2];
	FILE 		*h;
	struct __fs_file 	*fl;
	struct __fs_active 	*a;

	a = f->active;
	handle = FS_DIVHANDLE(a,FSOP_URD); /* Handle appears in URD slot */
	ctrl = f->ctrl;
	b = FSOP_CWD; /* Byte to put appears in the CWD slot - data+3 */

	if (handle < 1 || handle >= FS_MAX_OPEN_FILES || !(fl = a->fhandles[handle].handle)) // Invalid handle
	{
		fsop_error_ctrl(f, ctrl, 0xDE, "Channel ?");
		return;
	}

	if (a->fhandles[handle].mode < 2) // Not open for writing
	{
		fsop_error_ctrl(f, ctrl, 0xc1, "Not open for update");
		return;
	}

	if (a->fhandles[handle].is_dir)
	{
		fsop_error_ctrl(f, ctrl, 0xFF, "Is a directory");
		return;
	}

	h = fl->handle;

	buffer[0] = b;

	// Put the pointer back where we were

	clearerr(h);

	if (fs_check_seq(a->fhandles[handle].sequence, ctrl))
		fseek(h, a->fhandles[handle].cursor, SEEK_SET);
	else // Duplicate. Read previous from old cursor
		fseek(h, a->fhandles[handle].cursor_old, SEEK_SET);

	a->fhandles[handle].cursor_old = ftell(h);

	fs_debug (0, 2, "%12sfrom %3d.%3d Put byte %02X on channel %02x, cursor %06lX ctrl seq is %s (stored: %02X, received: %02X)", "", f->net, f->stn, b, handle, a->fhandles[handle].cursor,
		fs_check_seq(a->fhandles[handle].sequence, ctrl) ? "OK" : "WRONG", (a->fhandles[handle].sequence), ctrl);

	if (fwrite(buffer, 1, 1, h) != 1)
	{
		fsop_error_ctrl(f, ctrl, 0xFF, "FS error writing to file");
		return;
	}

	fflush(h);

	// Update cursor

	a->fhandles[handle].cursor = ftell(h);
	a->fhandles[handle].sequence = (ctrl & 0x01);

	fs_debug (0, 2, "%12sfrom %3d.%3d Put byte %02X on channel %02x, updated cursor %06lX", "", f->net, f->stn, b, handle, a->fhandles[handle].cursor);

	r.p.ctrl = ctrl;

	fsop_aun_send(&r, 2, f);

}

