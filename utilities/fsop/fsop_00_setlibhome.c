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
 * Implements:
 *
 * *SETLIB <username> <libdir>
 * *SETHOME <username> <homedir>
 */

void	fsop_setlibhome(struct fsop_data *f, uint16_t userid, char *path, uint8_t lib)
{

	struct path	p;

	if (lib && (*path == ':')) // Cannot set drive on library
		fsop_error(f, 0xFF, "Bad library path");
	else
	{
		fs_debug (0, 1, "%12sfrom %3d.%3d SET%s for uid %04X to %s", "", f->net, f->stn, lib ? "LIB" : "HOME", userid, path);

		if (!lib && f->server->users[userid].home[0])
		{
			unsigned char	homepath[1024];
			unsigned char	homediscname[17];

			fsop_get_disc_name (f->server, f->server->users[userid].home_disc, homediscname);

			/* Setting home directory and there's an existing one. Remove the homeof flag from it */

			sprintf(homepath, ":%s.%s", homediscname, f->server->users[userid].home);

			if (fsop_normalize_path(f, homepath, FSOP_CWD, &p) && (p.ftype == FS_FTYPE_DIR))
			{
				struct objattr oa;

				fsop_read_xattr(p.unixpath, &oa, f);
				fsop_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, 0, f);
			}
		}


		if (*path != '%' && fsop_normalize_path(f, path, FSOP_CWD, &p) && (p.ftype == FS_FTYPE_DIR) && strlen((const char *) p.path_from_root) < 94 && (!lib || p.disc == f->server->users[userid].home_disc))
		{
			/* !lib || p.disc == .... is to ensure that if setting library 
			 * then the library we found was on the home disc of the user. 
			 *
			 * For setting home directory, we can change disc.
			 */

			struct objattr	oa;

			if (lib)
				strcpy(f->server->users[userid].lib, "$");
			else	strcpy(f->server->users[userid].home, "$");

			if (strlen(p.path_from_root) > 0)
			{
				if (lib)
					strcat(f->server->users[userid].lib, ".");
				else	strcat(f->server->users[userid].home, ".");
			}

			if (lib)
				strncat((char *) f->server->users[userid].lib, (const char *) p.path_from_root, 79);
			else
				strncat((char *) f->server->users[userid].home, (const char *) p.path_from_root, 79);

			if (!lib)
			{
				f->server->users[userid].home_disc = p.disc;

				/* Set up homeof */

				if (strlen(p.path_from_root)) // Don't set homeof on $ !
				{
					fsop_read_xattr(p.unixpath, &oa, f);
					fsop_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, userid, f);
				}
			}

			fsop_reply_ok(f);
		}
		else if (*path == '%') // Blank off the library
		{
			if (lib)
				strncpy((char *) f->server->users[userid].lib, "", 79);
			else
				strncpy((char *) f->server->users[userid].home, "", 79);

			fsop_reply_ok(f);
		}
		else    fsop_error(f, 0xA8, "Bad directory");
	}
}

FSOP_00(SETLIB)
{
	unsigned char	path[1024], userstr[11];
	int16_t		userid = -1;

	if (!FS_ACTIVE_SYST(f->active) && num == 2)
		fsop_error(f, 0xFF, "Bad parameters");
	if (!FS_ACTIVE_SYST(f->active) && (f->active->priv & FS_PRIV_LOCKED))
		fsop_error(f, 0xBD, "Insufficient access");
	else if (num == 2)
	{
		FSOP_EXTRACT(f,0,userstr,10);
		FSOP_EXTRACT(f,1,path,255);
		userid = fsop_get_uid(f->server, userstr);
	}
	else if (num == 1)
	{
		FSOP_EXTRACT(f,0,path,255);
		userid = f->userid;
	}

	if (userid < 0)
		fsop_error(f, 0xFF, "Unknown user");
	else
		fsop_setlibhome(f, userid, path, 1);
}

FSOP_00(SETHOME)
{
	unsigned char   path[1024], userstr[11];
	int16_t	 	userid = -1;

	/* No SYST checks needed here because the
	 * parser only lets you use SETHOME if you are
	 * SYST.
	 */

	if (num == 2)
	{
		FSOP_EXTRACT(f,0,userstr,10);
		FSOP_EXTRACT(f,1,path,255);
		userid = fsop_get_uid(f->server, userstr);
	}
	else if (num == 1)
	{
		userid = f->userid;
		FSOP_EXTRACT(f,0,path,255);
	}

	if (userid < 0)
		fsop_error (f, 0xFF, "Unknown user");
	else
		fsop_setlibhome(f, userid, path, 0);

}

