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
 * Implements *PRINTOUT <fsp>
 */

FSOP_00(PRINTOUT)
{

	unsigned char	file[256];

	uint8_t		printer;
	unsigned char *	handler;
	unsigned char	unixprinter[128], acornprinter[7];
	struct path	pt;
	uint8_t		result;

	FSOP_EXTRACT(f,0,file,255);

	result = fsop_normalize_path_wildcard(f, file, FSOP_CWD, &pt, 1);

	fs_free_wildcard_list(&pt); // Don't need anything but the first

	if (!result)
	{
		fsop_error (f, 0xCC, "Bad filename");
		return;
	}
	else if (pt.ftype == FS_FTYPE_NOTFOUND)
	{
		fsop_error (f, 0xD6, "Not found");
		return;
	}
	else if (pt.ftype != FS_FTYPE_FILE)
	{
		fsop_error (f, 0xFF, "Type mismatch");
		return;
	}

	printer = fsop_get_user_printer(f->active);
	handler = get_user_print_handler (f->server->net, f->server->stn, printer = 0xff ? 1 : printer, unixprinter, acornprinter);

	fs_debug (0, 2, "%12sfrom %3d.%3d *PRINTOUT %s (destination %s)", "", f->net, f->stn, file, acornprinter);

	if (!handler)
		fsop_error (f, 0xFF, "Printer not available");
	else
	{
		// Copy file to temp (full unix path in p.unixpath)

		int     infile, tmpfile;
		char    template[80];
		uint8_t buffer[1024];
		int     len;

		strcpy(template, "/tmp/econet.printout.XXXXXX");

		tmpfile = mkstemp(template);
		infile = open(pt.unixpath, O_RDONLY);

		if (tmpfile == -1 || infile == -1)
		{
			if (tmpfile != -1) close(tmpfile);
			if (infile != -1) close(infile);

			fsop_error(f, 0xFF, "Cannot spool file");
			return;
		}

		// Now copy the file

		while ((len = read(infile, buffer, 1024)) && (len != -1))
			write(tmpfile, (const void *) buffer, len);

		close(tmpfile);
		close(infile);

		if (len == -1)
		{
			unlink(template);
			fsop_error(f, 0xFF, "Error while spooling");
		}
		else
		{
			char    username[11];
			uint8_t count;

			memcpy(username, &(f->server->users[f->userid].username), 10);

			for (count = 0; count < 11; count++)
				if (username[count] == ' ' || count == 10) username[count] = '\0';

			send_printjob (handler, f->server->net, f->server->stn, f->net, f->stn, username, acornprinter, unixprinter, template);

	 		fsop_reply_ok(f);
		}

	}

}

