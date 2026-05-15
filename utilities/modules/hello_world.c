/*
  (c) 2026 Chris Royle
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


#include "econet-hpbridge.h"

/* Example Pi Econet Bridge v2.2 module. Uses only a single port, and 
 * uses the template init, start, stop and exit functions from 
 * econet-hpbridge.h
 *
 * You can always make them do other things if you want, but you'll 
 * need to write your own functions 
 *  
 * This one reserves a single port, listens on it when running,
 * and sends a reply back to the port specified in first byte of
 * calling packet. The reply will contain "Hello, ", followed by
 * the contents of the incoming packet from byte 1 onwards, up
 * to a maximum of 20 bytes, or 0x0D whichever comes first.
 *
 * You can change the prefix on the reply by setting the key "msg" in JSON config on the diverted station, e.g.
 *
 * "hellow": { "msg":"My own text here, " }
 */

#define MYMODULE "HELLOW"
#define HELLOW_PORT 0xDE

/* Define our traffic handler - our start function needs it */

eb_module_handle_traffic(MYMODULE,hellow_handle_traffic);

/* Define our queue drain function because stop needs it */

eb_module_drain_queue(MYMODULE,hellow_drain_queue);

/* Define our thread function */

void hellow_processor (struct __eb_device *, struct __eb_device_module *, struct __econet_packet_aun *, uint16_t);
eb_module_thread_def(MYMODULE,hellow_thread, hellow_processor); 

/* define our exit, start & stop functions, because init needs them */

eb_module_exit_def(MYMODULE,hellow_exit,HELLOW_PORT); /* hellow_exit is the name of the function that gets defined */
eb_module_start_def(MYMODULE,hellow_start,HELLOW_PORT,hellow_thread,hellow_handle_traffic);
eb_module_stop_def(MYMODULE,hellow_stop,HELLOW_PORT,hellow_drain_queue,NULL); /* The NULL means we do not have a specific data cleanup function to call when we stop. If you do have one, it's prototype is void (func *) (struct __eb_device *, struct __eb_device_module *); */

/* Now set up our init function, which we presently do manually. This is the function you specify in the econet-hpbridge-modules.h header */

uint8_t hellow_init (void *device, struct json_object *j)
{
	struct __eb_device *d = (struct __eb_device *) device;
	struct __eb_device_module *me;
	char mytext[128]; /* Max len */
	uint8_t jsonret;

	eb_module_debug (1, MYMODULE, d, "Server initializing");

	if ((jsonret = eb_module_json_copy_string(j,"msg",mytext,127)) != 0)
	{
		/* String too long, or wasn't there */

		if (jsonret == 1) /* string too long */
			mytext[127] = 0; /* Force terminate */
		else if (jsonret == 2) /* String not there */
			strcpy(mytext, "Hello, "); /* Default */
	}

	me = eb_module_register (d, MYMODULE, NULL, strlen(mytext)+1);

	if (!me)
	{
		eb_module_debug (1, MYMODULE, d, "Server failed to initialize - module did not register");
		return 1;
	}

	strcpy (me->module_ws, mytext); /* Engineered to be correct length */

	me->module_init = hellow_init;
	me->module_start = hellow_start; /* Funcname given above in the eb_module_start_def macro */
	me->module_stop = hellow_stop; /* Funcname given above in eb_module_stop_def */
	me->module_exit = hellow_exit; /* You get the idea */
	me->module_queue = NULL; /* Empty queue */

	EB_PORT_SET (d, reserved_ports, HELLOW_PORT, NULL, NULL); /* Reserve our port so nothing else grabs it dynamically */

	return 0; /* Success */
}

/* Process a packet at p, of length len, in module me attached to device d. This will be called under lock (module_mutex)  */
/* NB - don't free the packet - the standard definition of a thread function does it for us */

void hellow_processor (struct __eb_device *d, struct __eb_device_module *me, struct __econet_packet_aun *p, uint16_t len)
{
	struct __econet_packet_aun	*reply;
	char *				mytext = (char *) me->module_ws;
	uint8_t				reply_port = p->p.data[0];

	if (p->p.aun_ttype != ECONET_AUN_DATA) return; /* We only want data */

	reply = eb_module_alloc (MYMODULE, "Reply packet", len + strlen(mytext));

	if (!reply) /* Barf! */
		return;

	reply->p.srcstn = d->local.stn; /* Us */
	reply->p.srcnet = d->net; /* Our net */
	reply->p.dststn = p->p.srcstn; /* Them */
	reply->p.dstnet = p->p.srcnet; /* Their net */
	reply->p.port = reply_port; /* Their reply port */
	reply->p.ctrl = p->p.ctrl; /* Copy theirs, just for fun */
	reply->p.aun_ttype = ECONET_AUN_DATA; /* Data packet - 4-way */

	/* Pad & sequence filled in by sender routing */

	strcpy (&(reply->p.data[0]), mytext);
	strncpy(&(reply->p.data[strlen(mytext)]), &(p->p.data[1]), len - 13);

	/* Debug */

	//eb_module_debug_params (1, MYMODULE, d, "Sent reply to %d.%d", reply->p.dstnet, reply->p.dststn);
	eb_module_debug (1, MYMODULE, d, "Sent reply");

	/* Despatch */

	eb_raw_send(d, reply, strlen(mytext) + (len - 13));
	
}
