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
 * Implements *RENAME <oldfsp> <newfsp>
 */

FSOP_00(RENAME)
{

	FS_REPLY_DATA(0x80);

        struct path p_from, p_to;
        unsigned char from_path[256], to_path[256];
	struct __fs_file *handle;

	fsop_00_oscli_extract(f->data, p, 0, from_path, 255, param_start);
	fsop_00_oscli_extract(f->data, p, 1, to_path, 255, param_start);

        fs_debug (0, 1, "%12sfrom %3d.%3d *RENAME %s %s", "", f->net, f->stn, from_path, to_path);

        if (!fsop_normalize_path(f, from_path, FSOP_CWD, &p_from) || !fsop_normalize_path(f,to_path, FSOP_CWD, &p_to) || p_from.ftype == FS_FTYPE_NOTFOUND)
        {
                fsop_error(f, 0xDC, "Not found");
                return;
        }

        if (p_from.perm & FS_PERM_L) // Source locked
        {
                fsop_error(f, 0xC3, "Entry Locked");
                return;
        }

        if ((!FS_PERM_EFFOWNER(f->active,p_from.owner)) && (!FS_PERM_EFFOWNER(f->active,p_from.parent_owner)) && (!FS_ACTIVE_SYST(f->active)))
        {
                fsop_error(f, 0xBD, "Insufficient access");
                return;
        }

        if ((p_to.ftype != FS_FTYPE_NOTFOUND) && p_to.ftype != FS_FTYPE_DIR) // I.e. destination does exist but isn't a directory - cannot move anything on top of existing file
        {
                fsop_error(f, 0xFF, "Destination exists");
                return;
                // Note, we *can* move a file into a filename inside a directory (FS_FTYPE_NOTFOUND), likewise a directory, but if the destination exists it MUST be a directory
        }

        if ((p_to.ftype == FS_FTYPE_NOTFOUND) && !FS_PERM_EFFOWNER(f->active,p_to.parent_owner) && ((p_to.parent_perm & FS_PERM_OTH_W) == 0)) // Attempt to move to a directory we don't own and don't have write access to
        {
                fsop_error(f, 0xBD, "Insufficient access");
                return;
        }

        if (p_to.ftype != FS_FTYPE_NOTFOUND && !FS_PERM_EFFOWNER(f->active, p_to.owner)) // Destination exists (so must be dir), not owned by us, and we're not system
        {
                fsop_error(f, 0xBD, "Insufficient access");
                return;
        }

        // Get an interlock

        if (p_from.ftype == FS_FTYPE_FILE)
        {
		int8_t	err;

                handle = fsop_open_interlock(f, p_from.unixpath, 2, &err, 0);

                switch (err)
                {
                        case -1: // Can't open
                        {
                                fs_debug (0, 1, "fs_open_interlock() returned -1");
                                fsop_error(f, 0xFF, "FS Error");
                                return;
                        }
                        break;
                        case -2: // Interlock failure
                        {
                                fsop_error(f, 0xC2, "Already open");
                                return;
                        }
                        break;
                        case -3: // Too many files
                        {
                                fsop_error(f, 0xC0, "Too many open files");
                                return;
                        }
                        break;
                }

                // Release the interlock (since nothing else is going to come along and diddle with the file in the meantime

                fsop_close_interlock(f->server, handle, 2);
        }


        // Otherwise we should be able to move it... and Unlike Econet, we *can* move across "discs"

        if (syscall(SYS_renameat2, 0, p_from.unixpath, 0, p_to.unixpath, 0)) // non-zero - failure - 0 instead of NOREPLACE is fine because we catch existent destination files above - only risk is someone mucking with the filesystem within Linux, which frankly makes them their own worst enemy
        {
                fs_debug (0, 1, "%12sfrom %3d.%3d Rename from %s to %s failed (%s)", "", f->net, f->stn, p_from.unixpath, p_to.unixpath, strerror(errno));
                fsop_error(f, 0xFF, "FS Error");
                return;
        }

        // If the INF file exists, rename it.  Ignore errors
	//
        char *olddot=pathname_to_dotfile(p_from.unixpath, FS_CONFIG(f->server,fs_infcolon));
        char *newdot=pathname_to_dotfile(p_to.unixpath, FS_CONFIG(f->server,fs_infcolon));

        rename(olddot, newdot);

        free(olddot);
        free(newdot);

        fsop_aun_send (&reply, 2, f);

}

