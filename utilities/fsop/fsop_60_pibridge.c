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
 * FS Op 0x60 (96)
 *
 * PiBridge service call
 *
 * *(data+5) is arg
 *
 * arg =
 * 0 - Return PiBridge build information
 * 16 - Return PiFS user ID & privilege bytes
 * 17 - Read FS configuration info (Acorndir, MDFS, MDFSINFO, Unix base directory, etc.)
 * 18 - Write FS configuration info (base directory is never writeable)
 * 19 - Shut down fileserver
 * 20 - Force logoff a user by name or ID
 *
 */

FSOP(60)
{


        /* Args 0 - 15 are Bridge Priv users only,
         * Args 16- 31 are Syst only,
         * Args 32- 64 are anyones
         */

        if (
                        (FSOP_ARG < 16 && !FSOP_BRIDGE)
                ||      (FSOP_ARG >= 16 && FSOP_ARG < 32 && !FSOP_SYST)
           )
        {
                fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call - prohibited", "", f->net, f->stn);
                fsop_error(f, 0xBD, "Insufficient access");
                return;
        }
        switch (FSOP_ARG)
        {

                /* BRIDGE PRIVILEGES ONLY */

                /* arg 0 - Return PiBridge build information - Bridge privileged users only */

                case 0:
                {
                        unsigned char    ver[128];

                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 0 - Get GIT version", "", FSOP_NET, FSOP_STN);
                        strcpy ((char *) ver, GIT_VERSION);
                        ver[strlen(GIT_VERSION)+1] = 0x00;
                        ver[strlen(GIT_VERSION)] = 0x0D;
                        fsop_reply_ok_with_data(f, ver, strlen((char *) ver));

                } break;

                /* arg 1 - shutdown host system if binary is setuid */

                case 1:
                {
                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 1 - Pi Shutdown", "", f->net, f->stn);
                        if (seteuid(0) != 0)
                                fsop_error(f, 0xFF, "Bridge not able to shut down");
                        else
                        {
                                char *  shutdown_msg = "Bridge shutting down\x0d";

                                fsop_reply_ok_with_data(f, (unsigned char *) shutdown_msg, strlen(shutdown_msg));

                                if (!fork())
                                {
                                        usleep(5000000); // To get the reply out
                                        execl("/usr/sbin/shutdown", "shutdown", "-h", "now", NULL);
                                }

                        }
                        return; // May never get here
                } break;

                /* SYSTEM PRIVILEGES ONLY */

                /* arg 16 - Return user ID & privilege bytes for username at *(data + 6... 0x0D terminated) */

                case 0x10:
                {
                        uint8_t         info[4];
                        int16_t         uid;
                        char   		username[11];

                        fs_copy_to_cr((unsigned char *) username, (f->data + 6), 10);
			uid = fs_get_uid(f->server_id, username);

                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 16 - Get UID and priv bits for %s", "", f->net, f->stn, username);
                        if (uid < 0) /* Not found */
                                fsop_error(f, 0xFF, "Unknown user");
                        else
                        {
                                /* UID, low byte first */
                                info[0] = (uid & 0xff);
                                info[1] = (uid & 0xff00) >> 8;

                                /* Then privilege bytes */
                                info[2] = FSOP_UINFO(uid)->priv;
                                info[3] = FSOP_UINFO(uid)->priv2;

                                fsop_reply_ok_with_data(f, info, 4);
                        }
                } break;

                /* Read fileserver parameters (ACORNDIR, MDFS, MDFSINFO, etc.) */

                case 0x11:
                {
                        uint8_t data[5];
                        uint32_t params;

                        fs_get_parameters (f->server_id, &params, &(data[4]));

                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 17 - Get FS parameters (0x%04X, filename length %d)", "", f->net, f->stn, params, data[4]);

                        // Shift FS params into data, LSB first

                        data[0] = params & 0xff;
                        data[1] = (params & 0xff00) >> 8;
                        data[2] = (params & 0xff0000) >> 16;
                        data[3] = (params & 0xff000000) >> 24;

                        fsop_reply_ok_with_data(f, data, 5);

                } break;

                /* Write fileserver parameters (ACORNDIR, MDFS, MDFSINFO, etc.) */

                case 0x12:
                {
                        uint32_t params;
                        uint8_t fnlength;

                        params =        (*(f->data+6))
                                +       (*(f->data+7) << 8)
                                +       (*(f->data+8) << 16)
                                +       (*(f->data+9) << 24);

                        fnlength = *(f->data+10);

                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 18 - Set FS parameters (0x%04X, filename length %d)", "", f->net, f->stn, params, fnlength);

                        if (fnlength < 10 || fnlength > 79)
                        {
                                fsop_error(f, 0xFF, "Bad filename length");
                                return;
                        }

                        fsop_set_parameters (f, params, fnlength);

                } break;

                /* Shut down fileserver */

                case 0x13:
                {
                        char shutdown_msg[128];

                        snprintf (shutdown_msg, 127, "Fileserver at %d.%d shutting down\x0d", f->server->net, f->server->stn);
                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 19 - Shut down fileserver", "", f->net, f->stn);
                        fsop_reply_ok_with_data(f, (unsigned char *) shutdown_msg, strlen(shutdown_msg));
                        fsop_shutdown(f);

                } break;

                /* Force log user off by name (arg2 = 0) or uid (arg2 = 1) or station number (arg2 = 2) */
                case 0x14:
                {
                        uint8_t         arg2;
                        int16_t         uid;
                        uint8_t         l_net, l_stn;
                        char   	username[11];
                        uint16_t        loggedoff = 0;
                        uint8_t         replydata[2];
                        uint16_t        count;

                        arg2 = *(f->data+6);

                        switch (arg2)
                        {
                                case 0: /* by username */
                                {
                                        if (f->datalen < 9) /* One character username + 0x0D */
                                        {
                                                fsop_error(f, 0xFF, "Insufficient data");
                                                return;
                                        }

                                        fs_copy_to_cr ((unsigned char *) username, (f->data+7), 10);
                                        uid = fs_get_uid(f->server_id, username);

                                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 20 - Force log off by username: %s (ID 0x%04X)", "", FSOP_NET, FSOP_STN, username, uid);
                                        if (uid < 0) /* Not known */
                                        {
                                                fsop_error(f, 0xFF, "Unknown user");
                                                return;
                                        }
                                }; /* uid now has valid user number */ break;

                                case 1: /* by uid */
                                {
                                        if (f->datalen < 9)
                                        {
                                                fsop_error(f, 0xFF, "Insufficient data");
                                                return;
                                        }

                                        uid = (*(f->data + 7)) + (*(f->data + 8) << 8);

                                        if (FSOP_UINFO(uid)->priv == 0) /* Deleted user */
                                        {
                                                fsop_error(f, 0xFF, "Unknown user");
                                                return;
                                        }

                                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 20 - Force log off by user id: %d", "", FSOP_NET, FSOP_STN, uid);
                                } break;

                                case 2: /* by station */
                                {
                                        if (f->datalen < 9)
                                        {
                                                fsop_error(f, 0xFF, "Insufficient data");
                                                return;
                                        }

                                        l_net = *(f->data+7);
                                        l_stn = *(f->data+8);

                                        fs_debug (0, 2, "%12sfrom %3d.%3d FS PiBridge call arg = 20 - Force log off by station: %d.%d", "", FSOP_NET, FSOP_STN, l_net, l_stn);
                                } break;

                                default:
                                {
                                        fsop_error(f, 0xFF, "Bad argument");
                                        return;
                                }
                        }

                        /* Log the relevant users off & send back a count of how many */

                        for (count = 0; count < ECONET_MAX_FS_ACTIVE; count++)
                        {
                                if (    (arg2 == 2 && f->server->active[count].net == l_net && f->server->active[count].stn == l_stn)
                                ||      (arg2 < 2 && f->server->active[count].userid == uid)
                                )
                                {
                                        fs_bye(f->server_id, 0, f->server->active[count].net, f->server->active[count].stn, 0); // Silent bye
                                        loggedoff++;
                                }
                        }

                        replydata[0] = loggedoff & 0xff;
                        replydata[1] = (loggedoff & 0xff00) >> 8;

                        fsop_reply_ok_with_data(f, replydata, 2);

                } break;

                /* Catch undefined operations */

                default:
                        fsop_error(f, 0xFF, "Unsupported");

        }


}

