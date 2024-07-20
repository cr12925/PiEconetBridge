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

/* Implements *ACCESS */

FSOP_00(ACCESS)
{
	struct path pt;
	struct path_entry *e;
	unsigned char path[1024];
	unsigned char perm;
	unsigned short ptr;
	char perm_str[10];
	uint8_t		dirs = 0;

	if (num == 1)
		strcpy (perm_str, "");
	else
		FSOP_EXTRACT(f,1,perm_str,9);

	FSOP_EXTRACT(f,0,path,255);

	fs_debug (0, 1, "%12sfrom %3d.%3d *ACCESS %s %s", "", f->net,f->stn, path, perm_str);

	perm = 0;
	ptr = 0;

	while (ptr < strlen((const char *) perm_str) && perm_str[ptr] != '/')
	{
		switch (perm_str[ptr])
		{
			case 'w': case 'W': perm |= FS_PERM_OWN_W; break;
			case 'r': case 'R': perm |= FS_PERM_OWN_R; break;
			case 'p': case 'P': perm |= FS_PERM_H; break; // Alternative to H for hidden
			case 'h': case 'H': perm |= FS_PERM_H; break; // Hidden from directory listings
			case 'l': case 'L': perm |= FS_PERM_L; break; // Locked
			case 'e': case 'E': perm |= FS_PERM_EXEC; break; // Execute only
			case 'd': case 'D': dirs = 1; break; // Only act on directories for this change

			default:
			{
				fsop_error(f, 0xCF, "Bad attribute");
				return;
			}
		}
		ptr++;
	}

	if (ptr != strlen((const char *) perm_str))
	{
		ptr++; // Skip the '/'

		while (ptr < strlen((const char *) perm_str) && (perm_str[ptr] != ' ')) // Skip trailing spaces too
		{
			switch (perm_str[ptr])
			{
				case 'w': case 'W': perm |= FS_PERM_OTH_W; break;
				case 'r': case 'R': perm |= FS_PERM_OTH_R; break;
				default:
				{
					fsop_error(f, 0xCF, "Bad attribute");
					return;
				}
			}

		ptr++;
		}
	}

	if (dirs && (perm & FS_PERM_EXEC))
	{
		fsop_error(f, 0xCF, "Bad attribute");
		return;
	}

	// Normalize the path

	if (!fsop_normalize_path_wildcard(f, path, FSOP_CWD, &pt, 1) || (pt.paths == NULL))
	{
		fsop_error(f, 0xD6, "Not found");
		return;
	}

	e = pt.paths;

	/*
	// First, check we have permission on everything we need
	//
	while (e != NULL)
	{
		if (((dirs && e->ftype == FS_FTYPE_DIR) || (e->ftype == FS_FTYPE_FILE)) && (FS_PERM_EFFOWNER(f->active, e->owner)) || (FS_PERM_EFFOWNER(f->active, e->parent_owner)))
			e = e->next;
		else
		{
			fs_free_wildcard_list(&p); // Free up the mallocs
			fs_error(server, reply_port, net, stn, 0xBD, "Insufficient access");
			return;
		}
	}

	*/

	// If we get here, we have permission on everything so crack on

	e = pt.paths;

	while (e != NULL)
	{
		uint8_t	 internal_perm;

		internal_perm = perm;

		if (e->ftype == FS_FTYPE_DIR && (perm & (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R | FS_PERM_OTH_W)) == 0)
			internal_perm |= FS_CONF_DEFAULT_DIR_PERM(f->server);

		if (
			((dirs && e->ftype == FS_FTYPE_DIR) || (e->ftype == FS_FTYPE_FILE || e->ftype == FS_FTYPE_SPECIAL))
		&&	(FS_PERM_EFFOWNER(f->active, e->owner) || FS_PERM_EFFOWNER(f->active, e->parent_owner))
		)
			fsop_write_xattr(e->unixpath, e->owner, internal_perm, e->load, e->exec, e->homeof, f); // 'perm' because that's the *new* permission

		e = e->next;

	}

	fs_free_wildcard_list(&pt); // Free up the mallocs

	// Give the station the thumbs up

	fsop_reply_ok(f);

}

