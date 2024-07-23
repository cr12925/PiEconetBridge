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

/* Implements FS Read Object Info */

void fsop_12_internal (struct fsop_data *f, uint8_t is_32bit)
{

        FS_REPLY_DATA(0x80);

        unsigned short replylen = 0, relative_to;
        unsigned short command;
        unsigned short norm_return;
        char path[1024];
        struct path p;
        unsigned char *data = f->data; /* Saves time */

        command = FSOP_ARG;
        relative_to = FSOP_CWD;

        memset(reply.p.data, 0, 30);

        // Use replylen as a temporary counter

        while (replylen < 1024 && *(data+(command != 3 ? 6 : 10)+replylen) != 0x0d)
        {
                path[replylen] = *(data+(command != 3 ? 6 : 10)+replylen);
                replylen++;
        }

        path[replylen] = '\0'; // Null terminate instead of 0x0d in the packet

	if (command == 0xBC && (!strcmp(path, "") || !strcmp(path, "$$"))) /* NetFS 32 bit support probe */
	{
		fs_debug_full (0, 2, f->server, f->net, f->stn, "NetFS 32 bit support probe");
		fsop_reply_ok(f);
	}

        fs_debug_full (0, 2, f->server, f->net, f->stn, "Get Object Info '%s' relative to %02X, command %d", path, relative_to, command);

        norm_return = fsop_normalize_path_wildcard(f, path, relative_to, &p, 1);

	if (strlen(p.path_from_root) != 0)
	{
		strcat (p.path_from_root, ".");
		strcat (p.path_from_root, p.acornname);
	}

        fs_free_wildcard_list(&p); // Not interested in anything but first entry, which will be in main struct

        if (!norm_return && (p.error != FS_PATH_ERR_NODIR))
        {
                fsop_error(f, 0xcc, "Bad filename");
                return;
        }

        if ((!norm_return && p.error == FS_PATH_ERR_NODIR) || (/* norm_return && */ p.ftype == FS_FTYPE_NOTFOUND))
        {
                FS_REPLY_DATA(0x80);

                if (command == 6) // Longer error block
                {
                        fsop_error(f, 0xd6, "Not found");
                }
                else
                {
                        reply.p.data[2] = 0; // not found.
                        fsop_aun_send(&reply, 3, f); // This will return a single byte of &00, which from the MDFS spec means 'not found' for arg = 1-5. 6 returns a hard error it seems.
                }
                return;

        }

        /* Prevent reading a dir we cannot read */

        if (p.ftype == FS_FTYPE_DIR && !((FS_PERM_EFFOWNER(f->active, p.owner) && (p.perm & FS_PERM_OWN_R)) || (p.perm & FS_PERM_OTH_R) || FS_ACTIVE_SYST(f->active)))
        {
                fsop_error(f, 0xbc, "Insufficient access");
                return;
        }

        replylen = 0; // Reset after temporary use above

        reply.p.data[replylen++] = 0;
        reply.p.data[replylen++] = 0;
        reply.p.data[replylen++] = p.ftype;

	// command = 7 is a 32 bit extension which doesn't have anything especially 32 bit in it
	// command = 8 is the 32 bit version with 32 bit length
	
	if (command == 7)
	{
		// According to MDFS.NET...

		reply.p.data[replylen++] = p.disc; // Disc number
		// SIN
                reply.p.data[replylen++] = (p.internal & 0xff);
                reply.p.data[replylen++] = (p.internal & 0xff00) >> 8;
                reply.p.data[replylen++] = (p.internal & 0xff0000) >> 16;
		reply.p.data[replylen++] = p.disc; // Disc number, again
		reply.p.data[replylen++] = 1; // Server filing system number (!?)
	}
	
        if (command == 2 || command == 5 || command == 8 || command == 96)
        {
                reply.p.data[replylen++] = (p.load & 0xff);
                reply.p.data[replylen++] = (p.load & 0xff00) >> 8;
                reply.p.data[replylen++] = (p.load & 0xff0000) >> 16;
                if (command == 8) reply.p.data[replylen++] = (p.load & 0xff000000) >> 24;
                reply.p.data[replylen++] = (p.exec & 0xff);
                reply.p.data[replylen++] = (p.exec & 0xff00) >> 8;
                reply.p.data[replylen++] = (p.exec & 0xff0000) >> 16;
                if (command == 8) reply.p.data[replylen++] = (p.exec & 0xff000000) >> 24;
        }

        if (command == 3 || command == 5 || command == 8 || command == 96)
        {
                reply.p.data[replylen++] = (p.length & 0xff);
                reply.p.data[replylen++] = (p.length & 0xff00) >> 8;
                reply.p.data[replylen++] = (p.length & 0xff0000) >> 16;

		if (command == 8)
                	reply.p.data[replylen++] = (p.length & 0xff000000) >> 24;
        }

        if (command == 4 || command == 5 || command == 8 || command == 96)
        {
                reply.p.data[replylen++] = fsop_perm_to_acorn(f->server, p.perm, p.ftype);
        }

        if (command == 1 || command == 5 || command == 8 || command == 96)
        {
                reply.p.data[replylen++] = p.day;
                reply.p.data[replylen++] = p.monthyear;
        }

        if (command == 4 || command == 5 || command == 8 || command == 96) // arg 4 doesn't request ownership - but the RISC OS PRM says it does, so we'll put this back
                reply.p.data[replylen++] = (FS_PERM_EFFOWNER(f->active, p.owner) ? 0x00 : 0xFF);

        if (command == 6)
        {

                // unsigned char hr_fmt_string[10];

                if (p.ftype != FS_FTYPE_DIR)
                {
                        fsop_error(f, 0xAF, "Types don't match");
                        return;
                }

                reply.p.data[replylen++] = 0; // Undefined on this command
                reply.p.data[replylen++] = 10; // Dir name length - Sounds like FSOp 18cmd6 can only take 10 characters

                memset ((char *) &(reply.p.data[replylen]), 32, ECONET_MAX_FILENAME_LENGTH); // Pre-fill with spaces in case this is the root dir

                if (p.npath == 0) // Root
                {
                        strncpy((char * ) &(reply.p.data[replylen]), (const char * ) "$         ", 11);
                }
                else
                {
                        unsigned char   shortname[11];

                        memcpy(shortname, p.acornname, 10);
                        shortname[10] = '\0';

                        snprintf(&(reply.p.data[replylen]), 11, "%-10s", (const char * ) shortname);
                }

                replylen += 10;

                reply.p.data[replylen++] = (f->userid == p.owner) ? 0x00 : 0xff;

                reply.p.data[replylen++] = fsop_get_acorn_entries(f, p.unixpath); // Number of directory entries

        }
        if (command == 64) // SJ Research function
        {

                if (!(f->server->config->fs_sjfunc))
                {
                        fsop_error(f, 0xff, "Not enabled");
                        return;
                }

                // Create date. (File type done for all replies above)
                reply.p.data[replylen++] = p.c_day;
                reply.p.data[replylen++] = p.c_monthyear;
                reply.p.data[replylen++] = p.c_hour;
                reply.p.data[replylen++] = p.c_min;
                reply.p.data[replylen++] = p.c_sec;

                // Modification date / time
                reply.p.data[replylen++] = p.day;
                reply.p.data[replylen++] = p.monthyear;
                reply.p.data[replylen++] = p.hour;
                reply.p.data[replylen++] = p.min;
                reply.p.data[replylen++] = p.sec;

        }

        if (command == 65) // Not yet implemented
        {
                fsop_error(f, 0x85, "FS Error");
                return;
        }

        if (command == 96) // PiFS canonicalize object name function
        {
                memcpy(&(reply.p.data[replylen]), p.acornfullpath, strlen(p.acornfullpath));
                reply.p.data[replylen+strlen(p.acornfullpath)] = '.';
                memcpy(&(reply.p.data[replylen+strlen(p.acornfullpath)+1]), p.acornname, strlen(p.acornname));
                reply.p.data[replylen+strlen(p.acornfullpath)+strlen(p.acornname)+1] = 0x0D;
                replylen += strlen(p.acornfullpath) + 1 + strlen(p.acornname) + 1;
        }

        fsop_aun_send(&reply, replylen, f);

	return;

}

FSOP(12)
{
	fsop_12_internal(f, 0);
}

