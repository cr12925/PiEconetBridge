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
	uint8_t		ps_len;
	uint8_t		dirs = 0;

	if (num == 1)
		strcpy (perm_str, "");
	else
		FSOP_EXTRACT(f,1,perm_str,9);

	ps_len = strlen((char *) perm_str);

	FSOP_EXTRACT(f,0,path,255);

	fs_debug_full (0, 1, f->server, f->net, f->stn, "*ACCESS %s %s", path, perm_str);

	for (ptr = 0; ptr < ps_len; ptr++)
	{
		if (perm_str[ptr] >= 'a' && perm_str[ptr] <= 'z')
			perm_str[ptr] &= 0xDF; /* Capitalize */
	}

	perm = 0;
	ptr = 0;

	if (ps_len > 0 && perm_str[ptr] == 'D')
	{
		dirs = 1;
		ptr = 1;
	}
	else if (ps_len >= 2 && (perm_str[0] == '+' || perm_str[0] == '-'))
	{
		if (perm_str[1] == 'D') dirs = (perm_str[0] == '+' ? 1 : 0);
		ptr = 2;
	}

	while (ptr < ps_len && perm_str[ptr] != '/')
	{
		switch (perm_str[ptr])
		{
			case 'W': perm |= FS_PERM_OWN_W; break;
			case 'R': perm |= FS_PERM_OWN_R; break;
			case 'P': perm |= FS_PERM_H; break; // Alternative to H for hidden
			case 'H': perm |= FS_PERM_H; break; // Hidden from directory listings
			case 'L': perm |= FS_PERM_L; break; // Locked
			case 'E': perm |= FS_PERM_EXEC; break; // Execute only
			default:
			{
				fsop_error(f, 0xCF, "Bad attribute");
				return;
			}
		}
		ptr++;
	}

	if (ptr != ps_len)
	{
		ptr++; // Skip the '/'

		while ((ptr < ps_len) && (perm_str[ptr] != ' ')) // Skip trailing spaces too
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
		uint16_t	 internal_perm;

		internal_perm = perm;

		if (e->ftype == FS_FTYPE_DIR && (perm & (FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R | FS_PERM_OTH_W)) == 0)
			internal_perm |= FS_CONF_DEFAULT_DIR_PERM(f->server);
	
		//fprintf (stderr, "File %s, Type %02X, Effowner (file: %02X, parent %02X)\n", e->unixpath, e->ftype, FS_PERM_EFFOWNER(f->active, e->owner), FS_PERM_EFFOWNER(f->active, e->parent_owner));
		if (
			((dirs && e->ftype == FS_FTYPE_DIR) || (!dirs && (e->ftype == FS_FTYPE_FILE || e->ftype == FS_FTYPE_SPECIAL)) || (e == pt.paths && e->next == NULL)) /* Last clause means 'if there's just one answer' - we don't insist on a D if the only answer is a directory */
		&&	(FS_PERM_EFFOWNER(f->active, e->owner) || FS_PERM_EFFOWNER(f->active, e->parent_owner))
		)
		{
			//fprintf (stderr, "Updating attributes on %s to %02X\n", e->unixpath, internal_perm);
			fsop_write_xattr(e->unixpath, e->owner, internal_perm, e->load, e->exec, e->homeof, f); // 'perm' because that's the *new* permission
		}

		e = e->next;

	}

	fs_free_wildcard_list(&pt); // Free up the mallocs

	// Give the station the thumbs up

	fsop_reply_ok(f);

}

