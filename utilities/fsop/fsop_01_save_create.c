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
 * Implements FSOP 01 (Save) and FSOP 1D (Create)
 */

void fsop_save_internal(struct fsop_data *f, uint8_t is_32bit)
{

       FS_R_DATA(0x80);

	unsigned char   *data = f->data; /* Just convenient - don't have to change them all to f->data! */
	unsigned char   incoming_port, ack_port;
	uint32_t	load, exec, length;
	uint8_t	 create_only;
	char	    filename[1024];

	create_only = (*(data+1) == 0x1d ? 1 : 0); // Function 29 just creates a file of the requisite length - no data transfer phase.

	ack_port = *(data+2);

	// Anyone know what the bytes at data+3, 4 are?

	fs_copy_to_cr(filename, data+16 + (is_32bit ? 1 : 0), 1023); /* 1 byte further on for 32 bit call */

	load =  (*(data+5)) + ((*(data+6)) << 8) + ((*(data+7)) << 16) + ((*(data+8)) << 24);

	exec =  (*(data+9)) + ((*(data+10)) << 8) + ((*(data+11)) << 16) + ((*(data+12)) << 24);

	length = (*(data+13)) + ((*(data+14)) << 8) + ((*(data+15)) << 16);

	if (is_32bit) length += (*(data + 16) << 24);

	fs_debug_full (0, 1, f->server, f->net, f->stn, "%s%s %s %08lx %08lx %06lx", (create_only ? "CREATE" : "SAVE"), (is_32bit ? "32" : ""), filename, load, exec, length);

	incoming_port = 0; // Dummy to stop a warning

	if (create_only || (incoming_port = fsop_find_bulk_port(f->server)))
	{
		struct path p;

		if (fsop_normalize_path(f, filename, FSOP_CWD, &p))
		{
			// Path found

			if (p.ftype == FS_FTYPE_FILE && p.perm & FS_PERM_L) // Locked - cannot write
			{
				fsop_error(f, 0xC0, "Entry Locked");
			}
			else if (p.ftype == FS_FTYPE_DIR)
				fsop_error(f, 0xFF, "Wrong object type");
			else if (p.ftype != FS_FTYPE_FILE && p.ftype != FS_FTYPE_NOTFOUND) // Not a file!
				fsop_error(f, 0xBD, "Insufficient access");
			else
			{
				if (    ((p.ftype != FS_FTYPE_NOTFOUND) && (p.my_perm & FS_PERM_OWN_W)) ||
					(
						p.ftype == FS_FTYPE_NOTFOUND &&
						(       (       FS_PERM_EFFOWNER(f->active, p.parent_owner) // Owner & SYST can always write to a parent directory - at least for now - stuffs up RISC OS otherwise.
							) ||
							(p.parent_perm & FS_PERM_OTH_W)
						)
					)
					|| FS_ACTIVE_SYST(f->active)
				)
				{
					struct __fs_file	*internal_handle;
					int8_t		  err;

					// Can write to it one way or another

					// Use interlock function here
					internal_handle = fsop_open_interlock(f, p.unixpath, 3, &err, 0);
					fsop_set_create_time_now(p.unixpath);

					if (err == -3)
						fsop_error(f, 0xC0, "Too many open files");
					else if (err == -2)
						fsop_error(f, 0xc2, "Already open"); // Interlock failure
					else if (err == -1)
						fsop_error(f, 0xFF, "FS Error"); // File didn't open when it should
					else
					{

						uint16_t perm;

						perm = FS_PERM_PRESERVE;

						if (create_only)
							perm = FS_CONF_DEFAULT_FILE_PERM(f->server);

						fsop_write_xattr(p.unixpath, f->userid, perm, load, exec, 0, f);  // homeof = 0 because it's a file

						r.p.ctrl = f->ctrl; // Copy from request
						r.p.data[2] = incoming_port;
						r.p.data[3] = (1280 & 0xff); // maximum tx size
						r.p.data[4] = (1280 & 0xff00) >> 8;

						if (!create_only) fsop_aun_send (&r, 5, f);
						else
						{
							// Write 'length' bytes of garbage to the file (probably nulls)

							ftruncate(fileno(internal_handle->handle), length);
						}

						if (create_only || length == 0)
						{

							// Send a closing ACK

							struct tm t;
							struct stat s;
							unsigned char day, monthyear;
							uint8_t		fnlength;

							day = monthyear = 0;

							if (!stat((const char * ) p.unixpath, &s))
							{
								localtime_r(&(s.st_mtime), &t);
								fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &(monthyear), &(day));
							}

							fsop_close_interlock(f->server, internal_handle, 3);

							r.p.ctrl = f->ctrl;
							r.p.data[2] = fsop_perm_to_acorn(f->server, FS_CONF_DEFAULT_FILE_PERM(f->server), FS_FTYPE_FILE);
							r.p.data[3] = day;
							r.p.data[4] = monthyear;

							if (is_32bit)
							{
								fnlength = strlen(p.acornname);
								strcpy((char *) &(r.p.data[5]), p.acornname);
								r.p.data[5+fnlength] = 0x0D; // See mdfs.net
							}

							fsop_aun_send (&r, 5 + (is_32bit ? (1 + fnlength) : 0), f);
						}
						else
						{

							struct __fs_bulk_port   *bp;

							/* We are required to make up the struct and put it in the list */

							FS_LIST_MAKENEW(struct __fs_bulk_port,f->server->bulkports,1,bp,"FS","Allocate new bulk port structure");
							bp->bulkport = incoming_port;
							bp->handle = internal_handle;
							bp->active = f->active;
							bp->ack_port = ack_port;
							bp->length = length;
							bp->received = 0; /* Initialie */
							bp->rx_ctrl = f->ctrl;
							bp->reply_port = FSOP_REPLY_PORT;
							bp->mode = 3;
							bp->is_gbpb = 0;
							bp->user_handle = 0; // Rogue for no user handle, because never hand out user handle 0. This stops the bulk transfer routine trying to increment a cursor on a user handle which doesn't exist.
							bp->is_32bit = is_32bit;
							strncpy(bp->acornname, p.acornname, 12);
							bp->last_receive = (unsigned long long) time(NULL);
						}
					}
				}
				else
				{
					fs_debug_full (0, 2, f->server, f->net, f->stn, "%s%s %s ftype=%02X, parent_perm=%02X, my_perm=%02X, parent_owner=%04X, uid=%04X", (create_only ? "CREATE" : "SAVE"), (is_32bit ? "32" : ""), filename, p.ftype, p.parent_perm, p.my_perm, p.parent_owner, f->userid);
					fsop_error(f, 0xBD, "Insufficient access");
				}

			}

		}
		else fsop_error(f, 0xCC, "Bad path");
	}
	else
		fsop_error(f, 0xC0, "Too many open files");

	return;

}

FSOP(01)
{
	fsop_save_internal(f, 0);
}

FSOP(26) /* 32-bit save */
{
	fsop_save_internal(f, 1); /* Flag as 32 bit op */
}

/* 
 * 1D is create.
 *
 * The code in FSOP(01) works out which is which, just call it.
 *
 */

void fsop_1d(struct fsop_data *f)
{
	fsop_01(f);
}

void fsop_27(struct fsop_data *f)
{
	fsop_save_internal(f, 1); /* Flag as a 32 bit create */
}

