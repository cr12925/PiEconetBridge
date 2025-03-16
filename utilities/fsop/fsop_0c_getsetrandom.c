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
 * Implements FSOP...
 *
 * &0C - Get Random Access (24-bit)
 * &0D - Set Random Access (24-bit)
 * &29 - Get Random Access (32-bit)
 * &2A - Set Random Access (32-bit)
 */

FSOP(0c)
{

	FS_R_DATA(0x80);
	uint8_t		handle;
	uint8_t		function;
	struct __fs_active	*a;
	struct __fs_file	*fl;
	FILE *		h;

	a = f->active;
	handle = FS_DIVHANDLE(a,*(f->data+5));
	function = FS_DIVHANDLE(a,*(f->data+6));

	if ((handle > FS_MAX_OPEN_FILES) || !(a->fhandles[handle].handle)) // Invalid handle
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	if (a->fhandles[handle].is_dir)
	{
		fsop_error(f, 0xFF, "Is a directory");
		return;
	}

	fl = a->fhandles[handle].handle;
	h = fl->handle; /* The underlying file* handle */

	switch (function)
	{
		case 0: // Cursor position
			r.p.data[2] = (a->fhandles[handle].cursor & 0xff);
			r.p.data[3] = (a->fhandles[handle].cursor & 0xff00) >> 8;
			r.p.data[4] = (a->fhandles[handle].cursor & 0xff0000) >> 16;
			fs_debug_full (0, 2, f->server, f->net, f->stn, "Get random access info on handle %02X, function %02X - cursor %06lX - data returned %02X %02X %02X", handle, function, a->fhandles[handle].cursor, r.p.data[2], r.p.data[3], r.p.data[4]);
			break;
		case 1: // Fall through extent / allocation - going to assume this is file size but might be wrong
		case 2:
		{
			struct stat s;

			if (fstat(fileno(h), &s)) // Non-zero == error
			{
				fsop_error(f, 0xFF, "FS error");
				return;
			}

			fs_debug_full (0, 2, f->server, f->net, f->stn, "Get random access info on handle %02X, function %02X - extent %06lX", handle, function, s.st_size);

			r.p.data[2] = s.st_size & 0xff;
			r.p.data[3] = (s.st_size & 0xff00) >> 8;
			r.p.data[4] = (s.st_size & 0xff0000) >> 16;
			break;
		}
		break;
	}

	fsop_aun_send(&r, 5, f);

	return;

}

FSOP(0d)
{
	FS_R_DATA(0x80);

	uint8_t			handle;
	uint8_t			function;
	uint8_t			is_32bit;
	off_t	 		extent;
	uint32_t		value; 
	FILE 			*h;
	struct stat 		s;
	struct __fs_active	*a;
	struct __fs_file	*fl;

	a = f->active;
	is_32bit = ((*(f->data+1)) == 0x2A) ? 1 : 0;
	handle = FS_DIVHANDLE(a,FSOP_ARG);
	function = *(f->data+6);
	value = (*(f->data+7)) + ((*(f->data+8)) << 8) + ((*(f->data+9)) << 16);

	if (is_32bit)
	{
		value += (*(f->data+8)) << 24;

		// see mdfs.net. Apparently AL4FS 2.09 gives Channel? for all calls (!)
		// and NetFS 6.07/6.08 send arg & channel the wrong way round, and this can 
		// be detected and remedied using the procedure below.
		// TODO: See if the MachinePeek we do at login will reveal this.
		
		if ((handle == 0) || (function > 3))
		{
			uint8_t	t;
	
			// Swap handle & function - we've detected a broken NetFS version that has them the wrong way round.
			
			t = handle;
			handle = function;
			function = t;
		}
	}

	if (handle < 1 || (handle > FS_MAX_OPEN_FILES) || !(a->fhandles[handle].handle))
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	fl = a->fhandles[handle].handle;
	h = fl->handle;

	if (fstat(fileno(h), &s)) // Error
	{
		fsop_error(f, 0xFF, "FS error");
		return;
	}

	extent = s.st_size;

	if (extent < 0) // Error
	{
		fsop_error(f, 0xFF, "FS Error");
		return;
	}

	switch (function)
	{
		case 0: // Set pointer
		{

			fs_debug_full (0, 2, f->server, f->net, f->stn, "Set file pointer%s on channel %02X to %06lX, current extent %06lX%s", (is_32bit ? " (32 bit)" : ""), handle, value, extent, (value > extent) ? " which is beyond EOF" : "");

			if ((value > extent) && a->fhandles[handle].mode == 1) // Don't extend if read only!
			{
				fsop_error(f, 0xB9, "Outside file");
				return;
			}

			if (value > extent) // Need to expand file
			{
				unsigned char buffer[4096];
				unsigned long to_write, written;
				unsigned int chunk;

				memset (&buffer, 0, 4096);
				fseek(h, 0, SEEK_END);

				to_write = value - extent;

				while (to_write > 0)
				{

					chunk = (to_write > 4096 ? 4096 : to_write);

					written = fwrite(buffer, 1, chunk, h);
					if (written != chunk)
					{
						fs_debug (0, 1, "Tried to write %d, but fwrite returned %ld", chunk, written);
						fsop_error(f, 0xFF, "FS Error extending file");
						return;
					}
					fs_debug_full (0, 1, f->server, f->net, f->stn, "Tried to write %06X bytes, actually wrote %06lX", chunk, written);
					to_write -= written;
				}

				fflush(h);
			}

			a->fhandles[handle].cursor = value; // (value <= extent ? value : extent);
			a->fhandles[handle].pasteof = 0; // We have no longer just read the last byte of the file
		}
		break;
		case 1: // Set file extent
		{
			fs_debug_full (0, 2, f->server, f->net, f->stn, "Set file extent%s on channel %02X to %06lX, current extent %06lX%s", (is_32bit ? " (32 bit)" : ""), handle, value, extent, (value > extent) ? " so adding bytes to end of file" : "");

			if (a->fhandles[handle].mode == 1) // Read only - refuse!
			{
				fsop_error(f, 0xC1, "File read only");
				return;
			}

			fflush(h);

			fs_debug_full (0, 3, f->server, f->net, f->stn, "   - %s file accordingly", (is_32bit ? " (32 bit)" : ""), ((value < extent) ? "truncating" : "extending"));

			if (ftruncate(fileno(h), value)) // Error if non-zero
			{
				fsop_error(f, 0xFF, "FS Error setting extent");
				return;
			}
		}
		break;
		case 2:
		{
			if (is_32bit)
			{
				uint32_t	load, exec;
				struct objattr	attr;

				// Set load & execute	

				load = value; // We got that for the other calls, above.

				exec = (*(f->data+11)) + ((*(f->data+12)) << 8) + ((*(f->data+13)) << 16) + ((*(f->data+14)) << 24);

				fsop_read_xattr(a->fhandles[handle].handle->name, &attr, f);

				attr.load = load;
				attr.exec = exec;

				fsop_write_xattr(a->fhandles[handle].handle->name,
						attr.owner,
						attr.perm,
						attr.load,
						attr.exec,
						attr.homeof,
						f);
			}
			else
				fsop_error(f, 0xFF, "Bad argument");
		}
		default:
			fsop_error(f, 0xFF, "Bad argument");
			return;

	}

	fsop_aun_send (&r, 2, f);

	return;

}


FSOP(29)
{

	FS_R_DATA(0x80);
	uint8_t			handle;
	uint8_t			function;
	struct __fs_active	*a;
	struct __fs_file	*fl;
	FILE *			h;
	struct stat		s;

	a = f->active;
	handle = FS_DIVHANDLE(a,*(f->data+5));
	function = (*(f->data+6));

	// see mdfs.net. Apparently AL4FS 2.09 gives Channel? for all calls (!)
	// and NetFS 6.07/6.08 send arg & channel the wrong way round, and this can 
	// be detected and remedied using the procedure below.
	// TODO: See if the MachinePeek we do at login will reveal this.
	
	if ((handle == 0) || (function > 3))
	{
		uint8_t	t;

		// Swap handle & function - we've detected a broken NetFS version that has them the wrong way round.
		
		t = handle;
		handle = function;
		function = t;
	}

	if ((handle > FS_MAX_OPEN_FILES) || !(a->fhandles[handle].handle)) // Invalid handle
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	if (a->fhandles[handle].is_dir)
	{
		fsop_error(f, 0xFF, "Is a directory");
		return;
	}

	fl = a->fhandles[handle].handle;
	h = fl->handle; /* The underlying file* handle */

	switch (function)
	{
		case 0:
		{
			struct objattr	attr;

			if (fstat(fileno(h), &s)) // Non-zero == error
			{
				fsop_error(f, 0xFF, "FS error");
				return;
			}

			fsop_read_xattr(a->fhandles[handle].handle->name, &attr, f); // TODO - check this is right - is .name the full filesystem path in unix world?

			/* Now get xattr */

			fs_debug_full (0, 2, f->server, f->net, f->stn, "Get random access info (32 bit) on handle %02X, function %02X - cursor %08lX, size %08lX (extent is same)", handle, function, a->fhandles[handle].cursor, s.st_size);

			r.p.data[2] = (a->fhandles[handle].cursor & 0xff);
			r.p.data[3] = (a->fhandles[handle].cursor & 0xff00) >> 8;
			r.p.data[4] = (a->fhandles[handle].cursor & 0xff0000) >> 16;
			r.p.data[5] = (a->fhandles[handle].cursor & 0xff000000) >> 24;
			r.p.data[6] = (s.st_size & 0xff);
			r.p.data[7] = (s.st_size & 0xff00) >> 8;
			r.p.data[8] = (s.st_size & 0xff0000) >> 16;
			r.p.data[9] = (s.st_size & 0xff000000) >> 24;
			memcpy(&(r.p.data[10]), &(r.p.data[6]), 4); // Space allocation
			r.p.data[14] = (attr.load & 0xff);
			r.p.data[15] = (attr.load & 0xff00) >> 8;
			r.p.data[16] = (attr.load & 0xff0000) >> 16;
			r.p.data[17] = (attr.load & 0xff000000) >> 24;
			r.p.data[18] = (attr.exec & 0xff);
			r.p.data[19] = (attr.exec & 0xff00) >> 8;
			r.p.data[20] = (attr.exec & 0xff0000) >> 16;
			r.p.data[21] = (attr.exec & 0xff000000) >> 24;

		} break;
		default:
			fsop_error(f, 0xFF, "No such FS argument");

	}

	fsop_aun_send(&r, 22, f);

	return;

}

FSOP(2a)
{

	fsop_0d(f); /* The 24-bit function works out when it's in 32 bit mode */

	return;

}

