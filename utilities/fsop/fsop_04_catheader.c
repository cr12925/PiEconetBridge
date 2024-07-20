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

FSOP(04)
{

	FS_R_DATA(0x80);

	unsigned char path[1024];

	unsigned char discname[17];

	struct path pt;

	fs_copy_to_cr(path, f->data + 5, 1022);

	fs_debug (0, 2, "%12sfrom %3d.%3d Read catalogue header %s", "", f->net, f->stn, path);

	if (!fsop_normalize_path(f, path, FSOP_CWD, &pt))
		fsop_error(f, 0xd6, "Not found");
	else
	{
		if (pt.ftype != FS_FTYPE_DIR)
			fsop_error(f, 0xAF, "Types don't match");
		else if ((pt.my_perm & FS_PERM_OWN_R) || FS_ACTIVE_SYST(f->active))
		{

			// MDFS manual has 10 character path, but Acorn traffic shows pad to 11! 
			// Similarly, disc name should be 15 but Acorn traffic has 16.
			
			strcpy(discname, ""); /* Just in case... */

			fsop_get_disc_name(f->server, f->active->current_disc, discname);

			sprintf((char * ) &(r.p.data[2]), "%-11s%c   %-16s%c%c", (char *) (pt.npath == 0 ? "$" : (char *) pt.path[pt.npath-1]),
				FS_PERM_EFFOWNER(f->active, pt.owner) ? 'O' : 'P',
				discname,
				0x0d, 0x80);

			fsop_aun_send(&r, 35, f);   // would be length 33 if Acorn server was within spec...
		}
		else    fsop_error(f, 0xBD, "Insufficient access");
	}

	return;

}

