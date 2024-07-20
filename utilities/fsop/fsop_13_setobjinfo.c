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

/* Set Object Info */

FSOP(13)
{

	/* FS_REPLY_DATA(0x80); */

	unsigned short relative_to;

	unsigned short command;

	char path[1024];

	unsigned short filenameposition;

	struct path p;

	struct __fs_active *a;

	unsigned char *data = f->data; // Saves changing loads of stuff from the old version
	uint16_t	datalen = f->datalen;

	a = f->active;

	command = FSOP_ARG;
	relative_to = FSOP_CWD;

	if (command == 0x40 && !(f->server->config->fs_sjfunc))
	{
		fsop_error(f, 0xff, "MDFS Unsupported");
		return;
	}

	switch (command)
	{
		case 1: filenameposition = 15; break;
		case 4: filenameposition = 7; break;
		case 2: // Fall through
		case 3: filenameposition = 10; break;
		case 5: filenameposition = 8; break;
		case 0x40: filenameposition = 16; *(data+datalen) = 0x0d; break; // Artificially terminate the filename on a 0x40 call - clients don't seem to
		default:
			fsop_error(f, 0xFF, "FS Error");
			return;
			break;
	}

	fs_copy_to_cr(path, (f->data+filenameposition), 1023);

	if (command != 4)
		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d", "", f->net, f->stn, path, relative_to == a->root ? "Root" : relative_to == a->lib ? "Library" : "Current", command);
	else
		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d, attribute &%02X", "", f->net, f->stn, path, relative_to == a->root ? "Root" : relative_to == a->lib ? "Library" : "Current", command, (*(f->data + 6)));

	if (!fsop_normalize_path(f, path, relative_to, &p) || p.ftype == FS_FTYPE_NOTFOUND)
		fsop_error(f, 0xD6, "Not found");
	else if (((!FS_ACTIVE_SYST(a))) &&
			(p.owner != a->userid) &&
			(p.parent_owner != a->userid)
		)
		fsop_error(f, 0xBD, "Insufficient access");
	else if (command != 1 && command != 4 && (p.perm & FS_PERM_L)) // Locked
	{
		fsop_error(f, 0xC3, "Entry Locked");
	}
	else
	{
		struct objattr attr;

		fsop_read_xattr(p.unixpath, &attr, f);

		switch (command)
		{
			case 1: // Set Load, Exec & Attributes

				attr.load = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				attr.exec = (*(data+10)) + (*(data+11) << 8) + (*(data+12) << 16) + (*(data+13) << 24);
				attr.perm = fsop_perm_from_acorn(f->server, *(data+14));

				// If it's a directory whose attributes we're setting, add in WR/r if no attributes are specified

				if (((*(data+14) & 0x0F) == 0))
				{
					if (p.ftype == FS_FTYPE_DIR)
						attr.perm |= FS_CONF_DEFAULT_DIR_PERM(f->server);
					else    attr.perm |= FS_CONF_DEFAULT_FILE_PERM(f->server);
				}

				// It would appear RISC PCs will send Acorn attrib &05 (r/r) when the user selects WR/r

				if ((p.ftype == FS_FTYPE_DIR)) // It would appear Owner Write and World Read are always implied on dirs from RISC OS
					attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;

				break;

			case 2: // Set load address
				attr.load = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				break;

			case 3: // Set exec address
				attr.exec = (*(data+6)) + (*(data+7) << 8) + (*(data+8) << 16) + (*(data+9) << 24);
				break;

			case 4: // Set attributes only

				attr.perm = fsop_perm_from_acorn(f->server, *(data+6));

				// If it's a directory whose attributes we're setting, add in WR/r if no attributes are specified

				if (((*(data+6) & 0x0F) == 0))
				{
					if (p.ftype == FS_FTYPE_DIR)
						attr.perm |= FS_CONF_DEFAULT_DIR_PERM(f->server);
					else    attr.perm |= FS_CONF_DEFAULT_FILE_PERM(f->server);
				}

				if ((p.ftype == FS_FTYPE_DIR)) // It would appear Owner Write and World Read are always implied on dirs from RISC OS
					attr.perm |= FS_PERM_OWN_W | FS_PERM_OWN_R | FS_PERM_OTH_R;

				break;

			case 5: // Set file date
				{
					// There should be, in *(data+6, 7) a two byte date.
					// We'll implement this later
					// No - Linux has no means of changing the creation date - we might need to look at putting this in xattrs / dotfiles!
				}
				break;
			case 0x40: // MDFS set update, create date & time
				{
					// TODO: Implement this.
					// Nothing for now
				}

			// No default needed - we caught it above
		}

		fs_debug (0, 2, "%12sfrom %3d.%3d Set Object Info %s relative to %s, command %d, writing to path %s, owner %04X, perm %02X, load %08X, exec %08X, homeof %04X", "", f->net, f->stn, path, relative_to == a->root ? "Root" : relative_to == a->lib ? "Library" : "Current", command, p.unixpath, attr.owner, attr.perm, attr.load, attr.exec, attr.homeof);

		fsop_write_xattr(p.unixpath, attr.owner, attr.perm, attr.load, attr.exec, attr.homeof, f);

		// If we get here, we need to send the reply

		//fsop_aun_send(&r, 2, f);
		
		fsop_reply_ok(f);

	}

	return;

}

