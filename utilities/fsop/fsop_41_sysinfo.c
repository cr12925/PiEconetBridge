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

/* Implements the MDFS FSOP 0x41 Read/write system info function */

FSOP(41)
{

	FS_REPLY_DATA(0x80);

	// Read operations are unprivileged; write operations are privileged
	uint8_t		rw_op;
	uint16_t	reply_length;
	uint8_t		*data = f->data; /* Cheat */
	uint8_t		net = f->net, stn = f->stn; /* Cheat */

	rw_op = FSOP_ARG; 
	// 0 - reset print server info; 1 - read current printer state; 2 - write current printer state; 3 - read auto printer priority; 4 - write auto printer priority ; 5 - read system msg channel; 6 - write system msg channel; 7 - read message level; 8 - set message level; 9 - read default printer; 10 - set default printer; 11 - read priv required to set time; 12 - set priv required to set time; IE ALL THE READ OPERATIONS HAVE LOW BIT SET

	reply_length = 2;

	if (rw_op > 12 && rw_op != 15)
		fsop_error(f, 0xff, "Unsupported");

	switch (rw_op)
	{
		case 0: // Reset print server information
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Reset printer information", "", net, stn);
			// Later we might code this to put the priority things back in order etc.
			break; // Do nothing - no data in reply
		}
		case 1: // Read current state of printer
		{
			uint8_t printer;
			int account = 0;
			char pname[7], banner[24];
			uint8_t control, status;
			short user;

			printer = *(data+6) - 1; // we zero base; the spec is 1-8

			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read printer information for printer %d", "", net, stn, printer);

			if (!get_printer_info(f->server->net, f->server->stn,
				printer,
				pname, banner, &control, &status, &user))
			{
				fsop_error(f, 0xff, "Unknown printer");
				return;
			}

			snprintf(&(reply.p.data[reply_length]), 7, "%-6.6s", pname);
			reply_length += 6;

			reply.p.data[reply_length++] = control;

			reply.p.data[reply_length++] = (account & 0xff);
			reply.p.data[reply_length++] = ((account & 0xff00) >> 8);

			snprintf(&(reply.p.data[reply_length]), 24, "%-s", banner);

			reply_length += strlen(banner);

			if (strlen(banner) < 23)
				reply.p.data[reply_length++] = 0x0d;

			break;

			}
		case 2: // Set current state of printer
		{

			uint8_t printer;
			char pname[7], banner[24];
			uint8_t control;
			short user;

			printer = *(data+6);
			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Write printer information for printer %d", "", net, stn, printer);
			control = *(data+13);
			user = *(data+14) + (*(data+15) << 8);

			strncpy(banner, data+16, 23);

			if (set_printer_info(f->server->net, f->server->stn,
				printer, pname, banner, control, user))
			{
				reply.p.data[reply_length++] =  0;
				reply.p.data[reply_length++] =  0;
			}
			else
			{
				fsop_error(f, 0xff, "PS Error");
				return;
			}

		}
		// To implement - codes 1--10 except 5-8!
		case 5: // Read system message channel
		case 6: // Set system message channel (deliberate fall through)
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d SJ %s system message channel", "", net, stn, (rw_op == 5 ? "Read" : "Set"));
			if (rw_op == 5)
			{
				reply.p.data[2] = 1; // Always 1 (Parallel)
				reply_length++;
			}

			// We ignore the set request.

		} break;
		case 7: // Read current FS message level
		{
			unsigned char level = 0;

			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read system message level", "", net, stn);

			// Temporary
			level = 1;

			reply.p.data[2] = level;
			reply_length++;
		} break;
		case 8: // Set current FS message level
		{
			unsigned char level = *(data+6);

			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Set system message level = %d", "", net, stn, level);

			// Do nothing for now

		} break;
		case 9: // Read default printer
		case 10: // Write default printer
		{

			fs_debug (0, 2, "%12sfrom %3d.%3d SJ %s system default printer", "", net, stn, (rw_op == 9 ? "Read" : "Set"));
			if (rw_op == 9) reply.p.data[reply_length++] = 1; // Always 1...

			// We always just accept the set command
		}
		case 11: // Read priv required to change system time
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read privilege required to set system time", "", net, stn);

			reply.p.data[2] = 0; // Always privileged;
			reply_length++;
		} break;
		case 12: // Write priv required to change system time
		{
			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Set privilege required to set system time (ignored)", "", net, stn);

			// Silently ignore - we are not going to let Econet users change the system time...
		} break;
		case 15: // Read printer info. Always return 0 printers for now
		{

			unsigned char start, number;
			uint8_t count;

			uint8_t numret = 0; // Number returned

			char pname[7], banner[24];
			uint8_t status, control;
			short account;

			number = *(data+6); start = *(data+7);
			fs_debug (0, 2, "%12sfrom %3d.%3d SJ Read printer information, starting at %d (max %d entries)", "", net, stn, start, number);

			reply.p.data[2] = 0; reply_length++; // Number of entries

			for (count = start; count < (start + number); count++)
			{
				if (get_printer_info(f->server->net, f->server->stn,
					count, pname, banner, &control, &status, &account))
				{

					snprintf(&(reply.p.data[reply_length]), 7, "%-6.6s", pname);
					reply_length += 6;
					if ((control & 0x01) == 0) reply.p.data[reply_length] = 0; // Off - the enable bit
					else reply.p.data[reply_length] = 1;
					reply_length++;
				}
				else
				{
					snprintf(&(reply.p.data[reply_length]), 7, "%6s", "");
					reply_length += 6;
					reply.p.data[reply_length] = 0; /* off - i.e. non-existent */
					reply_length++;
				}
					numret++;
					reply.p.data[reply_length++] = 0; // Not default
					reply.p.data[reply_length++] = (control & 0x02) >> 1; // Anonymous use
					reply.p.data[reply_length++] = (control & 0x04) >> 2; // Account required;
					reply.p.data[reply_length++] = account & 0xff;
					reply.p.data[reply_length++] = (account & 0xff00) >> 8;
					reply.p.data[reply_length++] = 1; // Always say Parallel
					reply.p.data[reply_length++] = 0; // 2nd auto number
					reply.p.data[reply_length++] = 0; // reserved
					reply.p.data[reply_length++] = 0; // reserved
			}

			reply.p.data[2] = numret;

		} break;
		default:
		{
			fsop_error(f, 0xff, "Unsupported");
			return;
			break;
		}

	}

	fsop_aun_send (&reply, reply_length, f);

}
