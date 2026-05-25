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

struct __eb_findserver_no_advertise {
	char	module_name[9];
	struct __eb_findserver_no_advertise *next;
};

struct __eb_findserver_config {
	struct __eb_findserver_no_advertise *no_advertise;
};

//void eb_handle_findserver_traffic (struct __econet_packet_aun *p, uint16_t len, void *param)
void eb_handle_findserver_traffic (struct __eb_device *d, struct __eb_device_module *me, struct __econet_packet_aun *p, uint16_t len)
{

	struct __eb_device_module *m;
	struct __eb_findserver_config *config = (struct __eb_findserver_config *) me->module_ws;

	if (d->type != EB_DEF_LOCAL) /* Only deal with this for local servers */
		return;

	/* Data & broadcast only */

	if (p->p.aun_ttype != ECONET_AUN_DATA && p->p.aun_ttype != ECONET_AUN_BCAST)
		return;

	if (p->p.ctrl == 0x80)
	{

		char	findserver_type[9]; // Modularized , server_type[9];
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

		eb_debug (0, 3, "FIND", "%-8s %3d.%3d FindServer request received - type '%-8s'",
			eb_type_str(d->type), d->net, d->local.stn, findserver_type);

#if 0 /* FS Modularized */
		if (fsop_is_enabled(d->local.fs.server)) // Is fileserver
		{
			strcpy (server_type, "FILE    ");	

			if (!strcasecmp(findserver_type, "FILE    ") || !strcasecmp(findserver_type, "        "))
			{
				memcpy (&(reply->p.data[3]), server_type, 8);
				eb_raw_send (d, reply, my_length);
			}
		}
#endif
#if 0	/* Printers modularized */
		if (d->local.printers) // Print server
		{

			strcpy (server_type, "PRINT   ");	

			if (!strcasecmp(findserver_type, "PRINT   ") || !strcasecmp(findserver_type, "        "))
			{
				memcpy (&(reply->p.data[3]), server_type, 8);
				eb_raw_send (d, reply, my_length);
			}

		}
#endif
		pthread_mutex_lock (&(d->local.modules_mutex));

		m = d->local.modules;

		//if (!m)
			//eb_debug (0, 2, "FIND", "Local    %3d.%3d No modules to reply for", d->net, d->local.stn);

		while (m)
		{
			struct __eb_findserver_no_advertise *na_check = config->no_advertise;
			uint8_t no_advertise = 0;

			/* Is it in our no advertise list? */

			while (na_check)
			{
				if (!strcasecmp(na_check->module_name, m->module_findserver_name)) /* In the list */
					no_advertise = 1;
				na_check = na_check->next;
			}

			if (m != me && !no_advertise) /* Don't announce findserver! (and things where our advertising is turned off */
			{

				pthread_mutex_lock (&(m->module_mutex));
	
				reply->p.data[1] = m->module_port;
	
				memcpy(&(reply->p.data[3]), m->module_findserver_name, 8);

				if (m->module_started && (!strcmp(findserver_type, "        ") || !memcmp(findserver_type, m->module_findserver_name, 8)))
				{
					eb_debug (0, 2, "FIND", "Local    %3d.%3d Send findserver reply for '%s' module", d->net, d->local.stn, m->module_name);
					if (strcmp(findserver_type, "        ")) /* If not an "any type" query, insert short delay - sometimes they are not listening... */
						usleep(100000);

					eb_raw_send (d, reply, my_length);
				}
	
				pthread_mutex_unlock (&(m->module_mutex));
			}

			m = m->next;
		}

		pthread_mutex_unlock (&(d->local.modules_mutex));

		eb_free (__FILE__, __LINE__, "FIND", "Freeing FindServer reply packet", reply);

	}
}

/* Read in the list of services we don't advertize and store it */

uint8_t findserver_init_private(struct __eb_device *d, struct __eb_device_module *m, struct json_object *j)
{
	struct json_object *noad;
	struct __eb_findserver_config *config = (struct __eb_findserver_config *) m->module_ws;
	struct __eb_findserver_no_advertise *na = NULL;
	uint16_t	length, count;

	if (!config)
	{
		eb_debug (0, 1, "FINDSRVR", "No private workspace allocated - refusing to initialize");
		return 1;
	}

	config->no_advertise = NULL; /* Initialize list */

	if (!j) /* No key in JSON */
		return 0; /* Success - no config, so nothing to not advertise */

	if (json_object_object_get_ex(j, "no-advertize", &noad) && json_object_is_type (noad, json_type_array))
	{
		length = json_object_array_length(noad);
		count = 0;

		while (count < length)
		{
			struct json_object *array_entry;

			array_entry = json_object_array_get_idx(noad, count);

			if (array_entry && json_object_is_type (array_entry, json_type_string))
			{
				na = eb_module_alloc("FINDSRVR", "New no-advertize structure", sizeof(struct __eb_findserver_no_advertise));
				if (!na)
					eb_debug (1, 0, "FINDSRVR", "Unable to allocate memory for a no-advertize struct!");
				strncpy (na->module_name, json_object_get_string(array_entry), 8);
				na->module_name[8] = '\0'; /* Force terminate, just in case */

				na->next = config->no_advertise;
				config->no_advertise = na; /* Put on front of list */
			}

			count++;
		}
	}

	return 1;
}

void findserver_cleanup(struct __eb_device *d, struct __eb_device_module *m)
{
	/* Do nothing - the no advertize list does not need freeing */
}

eb_module_funcs_def(FINDSRVR,struct __eb_findserver_config,EB_PORT_FINDSERVER,findserver_init_private,eb_handle_findserver_traffic,findserver_cleanup);

