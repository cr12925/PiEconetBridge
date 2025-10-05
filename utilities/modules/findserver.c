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

/* Deals with findserver requests */

#include "econet-hpbridge.h"
#include "econet-pserv.h"
#include "fs.h"

void eb_handle_findserver_traffic (struct __econet_packet_aun *p, uint16_t len, void *param)
{

	struct __eb_device * d = (struct __eb_device *) param;

	struct __eb_device_module *m;

	if (d->type != EB_DEF_LOCAL) /* Only deal with this for local servers */
		return;

	/* Data & broadcast only */

	if (p->p.aun_ttype != ECONET_AUN_DATA && p->p.aun_ttype != ECONET_AUN_BCAST)
		return;

	if (p->p.ctrl == 0x80)
	{

		char	findserver_type[9], server_type[9];
		uint8_t	my_length;
		struct __econet_packet_aun	*reply;
								
		reply = eb_malloc (__FILE__, __LINE__, "FINDSRV", "Allocate status query reply packet", 128);

		if (!reply)
			eb_debug (1, 0, "FINDSRVR", "Unable to malloc() new FindServer reply packet");

		reply->p.srcnet = d->net;
		reply->p.srcstn = d->local.stn;
		reply->p.dstnet = p->p.srcnet;
		reply->p.dststn = p->p.srcstn;
		reply->p.aun_ttype = ECONET_AUN_DATA;
		reply->p.port = 0xb1;
		reply->p.ctrl = p->p.ctrl;
		reply->p.seq = eb_get_local_seq(d);
			
		reply->p.data[0] = 0;
		reply->p.data[2] = EB_VERSION & 0xFF;
		strcpy ((char *) &(reply->p.data[12]), EB_SERVERID);
		reply->p.data[11] = strlen(EB_SERVERID);

		my_length = 12 + strlen(EB_SERVERID);

		if (reply->p.dstnet == 0)
			reply->p.dstnet = d->net;

		memset (findserver_type, 0, 9);

		memcpy (findserver_type, p->p.data, 8);

		eb_dump_packet (d, EB_PKT_DUMP_POST_O, p, len);

		eb_debug (0, 1, "FIND", "%-8s %3d.%3d FindServer request received - type '%-8s'",
			eb_type_str(d->type), d->net, d->local.stn, findserver_type);

		if (fsop_is_enabled(d->local.fs.server)) // Is fileserver
		{
			strcpy (server_type, "FILE    ");	

			if (!strcasecmp(findserver_type, "FILE    ") || !strcasecmp(findserver_type, "        "))
			{
				memcpy (&(reply->p.data[3]), server_type, 8);
				eb_raw_send (d, reply, my_length);
			}
		}

		if (d->local.ip.tunif[0]) // Non-null tunnel - IP server
		{

			strcpy (server_type, "IPGW    ");	

			if (!strcasecmp(findserver_type, "IPGW    ") || !strcasecmp(findserver_type, "        "))
			{
				memcpy (&(reply->p.data[3]), server_type, 8);
				eb_raw_send (d, reply, my_length);
			}
		}
							
		if (d->local.printers) // Print server
		{

			strcpy (server_type, "PRINT   ");	

			if (!strcasecmp(findserver_type, "PRINT   ") || !strcasecmp(findserver_type, "        "))
			{
				memcpy (&(reply->p.data[3]), server_type, 8);
				eb_raw_send (d, reply, my_length);
			}

		}

		if (d->local.teletext_active) // Teletext server
		{
			strcpy (server_type, "TELETEXT");	

			if (!strcasecmp(findserver_type, "TELETEXT") || !strcasecmp(findserver_type, "        "))
			{
				reply->p.data[1] = EB_PORT_TELETEXT_S_REPLY;
				memcpy (&(reply->p.data[3]), server_type, 8);
				eb_raw_send (d, reply, my_length);
			}

		}

		pthread_mutex_lock (&(d->local.modules_mutex));

		m = d->local.modules;

		if (!m)
			eb_debug (0, 2, "FIND", "Local    %3d.%3d No modules to reply for", d->net, d->local.stn);

		while (m)
		{
			reply->p.data[1] = 0;
			memcpy(&(reply->p.data[3]), m->module_name, 8);

			if (m->module_started)
			{
				eb_debug (0, 2, "FIND", "Local    %3d.%3d Send findserver reply for '%s' module", d->net, d->local.stn, m->module_name);
				eb_raw_send (d, reply, my_length);
			}
			else
				eb_debug (0, 2, "FIND", "Local    %3d.%3d No findserver reply for '%s' - module not started", d->net, d->local.stn, m->module_name);

			m = m->next;
		}

		pthread_mutex_unlock (&(d->local.modules_mutex));

		eb_free (__FILE__, __LINE__, "FIND", "Freeing FindServer reply packet", reply);

	}
}
