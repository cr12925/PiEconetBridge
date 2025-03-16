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
 * Implements *COPY <source-fsp> (<destination-fsp>)
 *
 * If source is a file, destination can be a file or a directory
 * If source enumerates to more than one file, destination *must* be a directory
 *
 * If destination is omitted, it will be taken as CWD.
 */

/* Manually defined because this is used for both *. and *CAT */

FSOP_00(COPY)
{

	unsigned char	source[127], destination[127];
	struct path	p_src, p_dst;
	struct path_entry	*e;
	uint16_t	to_copy = 0;

	if (num > 2)
	{
		fsop_error(f, 0xFF, "Too many parameters");
		return;
	}

	if (num == 0)
	{
		fsop_error(f, 0xFF, "Bad parameters");
		return;
	}

	fsop_00_oscli_extract(f->data, p, 0, source, 125, param_start);

	if (num == 2)
		fsop_00_oscli_extract(f->data, p, 1, destination, 125, param_start);
	else
	{
		//strcpy(destination, f->active->fhandles[f->active->current].acornfullpath);
		strcpy(destination, f->active->fhandles[f->cwd].acornfullpath);
	}

	fs_debug (0, 1, "%12sfrom %3d.%3d *COPY %s %s", "", f->net, f->stn, source, destination);

	//if (!fsop_normalize_path_wildcard(f, source, f->active->current, &p_src, 1))
	if (!fsop_normalize_path_wildcard(f, source, f->cwd, &p_src, 1))
	{
		fsop_error(f, 0xDC, "Source not found");
		fs_free_wildcard_list(&p_src);
		return;
	}

	e = p_src.paths;

	while (e)
	{
		if (e->ftype == FS_FTYPE_FILE && ((FS_PERM_EFFOWNER(f->active, e->owner) || (e->perm & FS_PERM_OTH_R))))
			to_copy++;
		e = e->next;
	}

	if (to_copy == 0)
	{
		fsop_error(f, 0xFF, "No files match source");
		fs_free_wildcard_list(&p_src);
		return;
	}

	//if (!fsop_normalize_path(f, destination, f->active->current, &p_dst))
	if (!fsop_normalize_path(f, destination, f->cwd, &p_dst))
	{
		fsop_error(f, 0xFF, "Bad destination");
		fs_free_wildcard_list(&p_src);
		return;
	}

	if (p_dst.ftype == FS_FTYPE_NOTFOUND)
	{
		fsop_error(f, 0xFF, "Destination not found");
		fs_free_wildcard_list(&p_src);
		return;
	}

	if (to_copy > 1 && p_dst.ftype != FS_FTYPE_DIR)
	{
		fsop_error(f, 0xFF, "Destination not a directory");
		fs_free_wildcard_list(&p_src);
		return;
	}

	/* Copy the files */
	
	e = p_src.paths;

	while (e != NULL)
	{

		struct __fs_file *in_handle, *out_handle;
		struct objattr a;
		unsigned long length, sf_return;
		off_t readpos;
		char destfile[2600];
		int8_t err;

		if (e->ftype != FS_FTYPE_FILE) /* Don't copy anything but files */
		{
			e = e->next;
			continue;
		}

		in_handle = fsop_open_interlock(f, e->unixpath, 1, &err, 0);

		if (err == -3)
		{
			fsop_error(f, 0xC0, "Too many open files");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (err == -2)
		{
			fsop_error(f, 0xC2, "Already open");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (err == -1)
		{
			fsop_error(f, 0xFF, "FS Error");
			fs_free_wildcard_list(&p_src);
			return;
		}

		fsop_read_xattr(e->unixpath, &a, f);

		if (p_dst.ftype == FS_FTYPE_DIR)
			sprintf(destfile, "%s/%s", p_dst.unixpath, e->unixfname);
		else
			strcpy(destfile, p_dst.unixpath);

		out_handle = fsop_open_interlock(f, destfile, 3, &err, 0);

		if (err == -3)
		{
			fsop_error(f, 0xC0, "Too many open files");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (err == -2) // Should never happen
		{
			fsop_error(f, 0xC2, "Already open");
			fs_free_wildcard_list(&p_src);
			return;
		}
		else if (err == -1)
		{
			fsop_error(f, 0xFF, "FS Error");
			fs_free_wildcard_list(&p_src);
			return;
		}

		fseek(in_handle->handle, 0, SEEK_END);
		length = ftell(in_handle->handle);

		fs_debug (0, 1, "%12sfrom %3d.%3d Copying %s to %s, length %06lX", "", f->net, f->stn, e->unixpath, destfile, length);

		readpos = 0; // Start at the start

		while (readpos < length)
		{
			if ((sf_return = sendfile(fileno(out_handle->handle),
				fileno(in_handle->handle),
				&readpos,
				length)) == -1) // Error!
			{
				fsop_close_interlock(f->server, in_handle, 1);
				fsop_close_interlock(f->server, out_handle, 3);
				fs_free_wildcard_list(&p_src);
				fsop_error(f, 0xFF, "FS Error in copy");
				return;
			}

			readpos += sf_return;
		}

		fsop_write_xattr(destfile, f->userid, a.perm, a.load, a.exec, a.homeof, f);
		fsop_close_interlock(f->server, in_handle, 1);
		fsop_close_interlock(f->server, out_handle, 3);

		e = e->next;
	}

	fs_free_wildcard_list(&p_src);

	fsop_reply_ok(f);

	return;

}

