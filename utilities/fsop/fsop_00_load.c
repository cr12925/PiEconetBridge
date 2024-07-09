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

/* Extern for hex parser */

uint8_t  fsop_00_hexparse(char *, uint8_t, uint32_t *);

/* Parser for *LOAD for ATOMs that can't do it themselves */

FSOP_00(LOAD)
{

	FS_REPLY_DATA(0x80);

	unsigned char path[256];
	uint32_t	load = 0;
	unsigned char load_string[10];

	strcpy(load_string, "");

	fsop_00_oscli_extract(f->data, p, 0, path, 240, param_start);

	if (num == 2) /* We have a load address as well */
	{
		fsop_00_oscli_extract(f->data, p, 1, load_string, 8, param_start);

		if (!fsop_00_hexparse(load_string, 8, &load))
			fsop_error (f, 0xFF, "Bad load address");
	}

	fs_debug (0, 1, "%12sfrom %3d.%3d *LOAD %s %s (0x%08X)", "", f->net, f->stn, path, load_string, load);

	reply.p.data[0] = 0x02; /* Load */
	/*
	reply.p.data[2] = (load) & 0xff;
	reply.p.data[3] = (load >> 8) & 0xff;
	reply.p.data[4] = (load >> 16) & 0xff;
	reply.p.data[5] = (load >> 24) & 0xff;
	*/

	fsop_lsb_reply (&(reply.p.data[2]), 4, load);

	reply.p.data[6] = (num == 2) ? 0xff : 0x00; /* 0xff means we had a load address to use */

	strcpy(&(reply.p.data[7]), path);
	reply.p.data[7+strlen(path)] = 0x0D;

	fsop_aun_send (&reply, 7 + 1 + strlen(path), f);

	return;

}

FSOP_00(SAVE)
{
	FS_REPLY_DATA(0x80);

	unsigned char 	path[256];
	unsigned char	save_s[10], len_s[11], exec_s[10], load_s[10];
	uint32_t	save, length, exec, load;

	reply.p.data[0] = 0x01; /* Save */

	save = length = exec = load = 0;

	fsop_00_oscli_extract(f->data, p, 0, path, 240, param_start);
	fsop_00_oscli_extract(f->data, p, 1, save_s, 8, param_start);
	fsop_00_oscli_extract(f->data, p, 2, len_s, 7, param_start); /* Length is 24 bits only, optionally with + */
	
	if (!fsop_00_hexparse(save_s, 8, &save))
	{
		fsop_error (f, 0xFF, "Bad save address");
		return;
	}

	if (len_s[0] == '+')
	{
		if (!fsop_00_hexparse(&(len_s[1]), 6, &length))
		{
			fsop_error (f, 0xFF, "Bad length");
			return;
		}
	}
	else
	{
		if (!fsop_00_hexparse(len_s, 6, &length))
		{
			fsop_error (f, 0xFF, "Bad length");
			return;
		}

		length = length - save;
	}

	if (num >= 4)
	{
		fsop_00_oscli_extract(f->data, p, 3, exec_s, 8, param_start); 
		if (!fsop_00_hexparse(exec_s, 8, &exec))
		{
			fsop_error (f, 0xFF, "Bad exec address");
			return;
		}
	}
	else	exec = save;

	if (num == 5)
	{
		fsop_00_oscli_extract(f->data, p, 4, load_s, 8, param_start); 
		if (!fsop_00_hexparse(load_s, 8, &load))
		{
			fsop_error (f, 0xFF, "Bad load address");
			return;
		}
	}
	else	load = save;

	fsop_lsb_reply (&(reply.p.data[2]), 4, load);
	fsop_lsb_reply (&(reply.p.data[6]), 4, exec);
	fsop_lsb_reply (&(reply.p.data[10]), 3, length);
	strcpy (&(reply.p.data[13]), path);
	
	fsop_aun_send (&reply, 13 + 1 + strlen(path), f);

	return;

}
