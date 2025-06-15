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
/* Also contains ENABLE & DISABLE */

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
				fsop_error(f, 0xFF, "Bad filename length");
			}
			else
				f->server->config->fs_fnamelen = length;

		}
		else
		{
			fsop_error(f, 0xFF, "Bad filename length");
			return;
		}

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

	fs_debug_full (0, 1, f->server, f->net, f->stn, "*FSCONFIG - %s %s", configitem, (operator == '+' ? "ON" : "OFF"));

	if (!strcasecmp("ACORNHOME", configitem))
		f->server->config->fs_acorn_home = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("COLONMAP", configitem))
		f->server->config->fs_infcolon = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("MDFS", configitem))
		f->server->config->fs_sjfunc = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("MDFSINFO", configitem) && (FS_CONFIG(f->server,fs_sjfunc))) /* Only available in MDFS mode */
		f->server->config->fs_mdfsinfo = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("ACORNDIR", configitem))
		f->server->config->fs_mask_dir_wrr = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("PIFSPERMS", configitem))
		f->server->config->fs_pifsperms = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("DELETE", configitem) && (FS_CONFIG(f->server,fs_sjfunc)))
		f->server->config->fs_deletewildcard = (operator == '+' ? 1 : 0);
	else if (!strcasecmp("SAVE", configitem) && (FS_CONFIG(f->server,fs_sjfunc)))
		f->server->config->fs_shortsavesoff = (operator == '-' ? 1 : 0); // Default is short saves ON, so - turns that off by setting 1
	else if (!strcasecmp("LIBRARY", configitem) && (FS_CONFIG(f->server,fs_sjfunc)))
		f->server->config->fs_mdfsextsearch = (operator == '+' ? 1 : 0);
	else
	{
		fsop_error(f, 0xFF, "Bad configuration entry name"); return;
	}

	fsop_reply_ok(f);
}

/* Enable / Disable flag 
 * for a user. If two parameters AND user is syst,
 * first parameter is username. Else sets for current
 * user, and there can be 0 parameters in which case
 * it's the DELETE setting which is being altered.
 *
 * mode = 0 means disable; 1 = enable
 */

void fsop_00_enable_disable_internal(uint8_t mode, struct fsop_data *f, struct oscli_params *p, uint8_t num, uint8_t param_start)
{
	int16_t	uid;
	enum 	{ FS_ED_DELETE, FS_ED_SAVE, FS_ED_LIBRARY } option;

	uid = f->userid;

	if (num > 1) /* param 1 will be username, but we must be syst */
	{
		if (!FS_ACTIVE_SYST(f->active))
		{
			fsop_error(f, 0xBA, "Insufficient privilege");
			return;
		}
		else
		{
			unsigned char	userid[11];

			FSOP_EXTRACT(f,0,userid,10);

			uid = fsop_get_uid(f->server, userid);

			if (uid < 0)
			{
				fsop_error(f, 0xbc, "User not known");
				return;
			}
		}
	}

	if (num == 0)
		option = FS_ED_DELETE;
	else
	{
		unsigned char		optiontext[11];

		FSOP_EXTRACT(f, num-1, optiontext, 10);

		if (!strcasecmp(optiontext, "DELETE"))
			option = FS_ED_DELETE;
		else if (!strcasecmp(optiontext, "SAVE"))
			option = FS_ED_SAVE;
		else if (!strcasecmp(optiontext, "LIBRARY"))
			option = FS_ED_LIBRARY;
		else
		{
			fsop_error(f, 0xff, "Bad parameter");
			return;
		}
	}

#define FSOP_00_ENDIS(var,flag) \
					var = (mode ? \
							(var | (flag))  \
						:	(var & ~(flag)) \
						)

	switch (option)
	{
		case FS_ED_DELETE:
			{

				if (num == 2) /* SYST changing permanently for user */
				{
					FSOP_00_ENDIS(f->server->users[uid].priv, FS_PRIV_PERMENABLE);
				}
				else
				{
					FSOP_00_ENDIS(f->active->priv, FS_PRIV_PERMENABLE);
				}
			} break;
		case FS_ED_SAVE:
			{
				/* Toggle mode because this setting is inverse */
				mode ^= 1;

				if (num == 2) /* SYST changing permanently for user */
				{
					FSOP_00_ENDIS(f->server->users[uid].priv, FS_PRIV_NOSHORTSAVE);
				}
				else
				{
					FSOP_00_ENDIS(f->active->priv, FS_PRIV_NOSHORTSAVE);
				}
			} break;
		case FS_ED_LIBRARY:
			{
				if (num == 2) /* SYST changing permanently for user */
				{
					FSOP_00_ENDIS(f->server->users[uid].priv2, FS_PRIV2_LIBRARYSEARCH);
				}
				else
				{
					FSOP_00_ENDIS(f->active->priv2, FS_PRIV2_LIBRARYSEARCH);
				}

			} break;
		default:
			{
				fsop_error(f, 0xFF, "FS Error - bad enable/disable option");
				return;
			} break;

	}

	fsop_reply_ok(f);
	
}

FSOP_00(DISABLE)
{
	fsop_00_enable_disable_internal(0, f, p, num, param_start);
}

FSOP_00(ENABLE)
{
	fsop_00_enable_disable_internal(1, f, p, num, param_start);
}
