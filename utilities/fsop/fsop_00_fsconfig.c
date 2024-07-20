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

/* Implements *FSCONFIG (and its older aliases *NETCONFIG and *NETCONF) */
/* Also contains *FSDEFPERM */

FSOP_00(FSCONFIG)
{
	unsigned char	parameter[100];
	unsigned char operator; // The + or - on the command line
	char configitem[20];

	fsop_00_oscli_extract(f->data, p, 0, parameter, 99, param_start);

	if (!strcasecmp(parameter, "FNLENGTH"))
	{
		uint8_t		length;

		if (num == 2)
		{
			FSOP_EXTRACT(f, 1, parameter, 2);
			length = atoi(parameter);

			if (length < 10 || length > 80)
			{

			}
		}
		else
		{
			fsop_error(f, 0xFF, "Bad filename length");
			return;
		}

		if (!fsop_write_server_config(f->server))
			fsop_error(f, 0xFF, "Couldn't write server config");
		else
			fsop_reply_ok(f);

		return;

	}

	if (!strcasecmp(parameter, "FSDEFPERM"))
	{
		char params[11];
		uint8_t counter = 0, is_dir = 0, perm = 0;

		FSOP_EXTRACT(f,1,params,10);

		while (counter < strlen(params))
			params[counter++] &= ~(0x20);  // Make caps - but will turn '/' into 0x0f

		counter = 0;

		if ((strlen(params) >= 1) && params[0] == 'D')
		{
			is_dir = 1;
			counter++;
		}

		// Before the /
		while ((counter < strlen(params) && params[counter] != 0x0f)) // 0x0f is what ('/' & 0x20) becomes
		{

			//fprintf (stderr, "FSDEFPERMS - counter = %d, character = '%c' (%d), length = %d\n", counter, params[counter], params[counter], strlen(params));

			switch (params[counter])
			{
				case 'L': perm |= FS_PERM_L; break;
				case 'P': perm |= FS_PERM_H; break;
				case 'H': perm |= FS_PERM_H; break;
				case 'R': perm |= FS_PERM_OWN_R; break;
				case 'W': perm |= FS_PERM_OWN_W; break;
				default:
				{
					fsop_error(f, 0xFF, "Bad attribute"); return;
				} break;
			}

			counter++;

		}

		if ((counter < strlen(params)) && params[counter] == 0x0f)      counter++; // Skip the slash

		while (counter < strlen(params))
		{
			//fprintf (stderr, "FSDEFPERMS(other) - counter = %d, character = '%c' (%d), length = %d\n", counter, params[counter], params[counter], strlen(params));

			switch (params[counter])
			{
				case 'R': perm |= FS_PERM_OTH_R; break;
				case 'W': perm |= FS_PERM_OTH_W; break;
				default:
				{
					fsop_error(f, 0xFF, "Bad attribute"); return;
				} break;
			}

			counter++;
		}

		// Impose defaults even in setting the defaults!

		if ((perm & (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_W | FS_PERM_OTH_R)) == 0)
		{
			perm |= FS_PERM_OWN_W | FS_PERM_OWN_R;

			if (is_dir)
				perm |= FS_PERM_OTH_R;
		}

		// Set the config

		if (is_dir)
			FS_CONF_DEFAULT_DIR_PERM(f->server) = perm;
		else
			FS_CONF_DEFAULT_FILE_PERM(f->server) = perm;

		if (!fsop_write_server_config(f->server))
			fsop_error(f, 0xFF, "Unable to write FS Configuration");
		else
			fsop_reply_ok(f);
		
		return;

	}

	if (num > 1)
	{
		fsop_error(f, 0xFF, "Bad parameter");
		return;
	}

	operator = parameter[0];

	if (operator != '+' && operator != '-')
	{
		fsop_error(f, 0xFF, "Bad parameter");
		return;
	}

	strcpy(configitem, &(parameter[1]));

	fs_debug (0, 1, "%12sfrom %3d.%3d *FSCONFIG - %s %s", "", f->net, f->stn, configitem, (operator == '+' ? "ON" : "OFF"));

	if (!strcasecmp("ACORNHOME", configitem))
		f->server->config->fs_acorn_home = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("COLONMAP", configitem))
		f->server->config->fs_infcolon = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("MDFS", configitem))
		f->server->config->fs_sjfunc = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("BIGCHUNKS", configitem))
		f->server->config->fs_bigchunks = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("BIGHANDLES", configitem))
		f->server->config->fs_manyhandle = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("MDFSINFO", configitem))
		f->server->config->fs_mdfsinfo = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("ACORNDIR", configitem))
		f->server->config->fs_mask_dir_wrr = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("PIFSPERMS", configitem))
		f->server->config->fs_pifsperms = (operator == '+' ? 1 : 0);
	else
	{
		fsop_error(f, 0xFF, "Bad configuration entry name"); return;
	}

	if (!fsop_write_server_config(f->server))
		fsop_error(f, 0xFF, "Couldn't write server config");
	else
		fsop_reply_ok(f);
}

