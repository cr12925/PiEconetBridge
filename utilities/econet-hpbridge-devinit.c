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

/*
 * econet-hpbridge-devinit.c
 *
 * Contains routines used by both the JSON and old non-JSON systems to
 * instantiate devices in the bridge, and also some utility routines for,
 * for example, making firewall entry objects and putting them on 
 * firewall lists.
 */

#define _GNU_SOURCE

#include "econet-hpbridge.h"
#include "econet-pserv.h"
#include "econet-fs-hpbridge-common.h"
#include "fs.h"

/*
 * Initialize a wire network device
 */

uint8_t	eb_device_init_wire (uint8_t net, char * device)
{
	struct __eb_device      *p;
	short                   c_net, c_stn;

	p = eb_device_init (net, EB_DEF_WIRE, 0);

	if ((p->wire.device = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create wire device string", strlen(device)+1)))
		strcpy(p->wire.device, device);
	else    eb_debug (1, 0, "CONFIG", "Cannot malloc space for device name for wire network %d", net);

	gettimeofday (&(p->wire.last_tx), 0); // Reset last transmission counter

	memset (&(p->wire.divert), 0, sizeof (p->wire.divert));

	/* Initialize sequence numbers for wire machines */

	for (c_net = 0; c_net < 256; c_net++)
		for (c_stn = 0; c_stn < 256; c_stn++)
			p->wire.seq[c_net][c_stn] = 0x4000;

	ECONET_INIT_STATIONS(p->wire.stations);
	ECONET_SET_STATION((p->wire.stations), 255, 255); // Catch broadcasts

	/* Now ensure that we put this network in all the *other* wire device stations[] lists */

	eb_set_whole_wire_net (net, p);

	memset (&(p->wire.filter_in), 0, 256);
	memset (&(p->wire.filter_out), 0, 256);

	p->wire.period = p->wire.mark = 0;

	p->wire.pool = NULL;
	memset(&(p->wire.use_pool), 0, sizeof(p->wire.use_pool));

	// Initialize bridge response timers

	memset (&(p->wire.last_bridge_whatnet), 0, sizeof(p->wire.last_bridge_whatnet));
	memset (&(p->wire.last_bridge_isnet), 0, sizeof(p->wire.last_bridge_isnet));

	return 1;
}

/*
 * Initialize a trunk device (not a multitrunk or part of one)
 *
 * destination == NULL means a dynamic trunk
 * sharekey == NULL means plaintext trunk
 *
 */

uint8_t eb_device_init_singletrunk (char * destination, uint16_t local_port, uint16_t remote_port, char * sharedkey)
{

	struct __eb_device	* p;

	/* Make our struct */

	p = eb_device_init (0, EB_DEF_TRUNK, 0);

	p->trunk.local_port = local_port;
	p->trunk.head = NULL;
	p->trunk.tail = NULL;
	memset (&(p->trunk.xlate_in), 0, 256);
	memset (&(p->trunk.xlate_in), 0, 256);
	memset (&(p->trunk.filter_in), 0, 256);
	memset (&(p->trunk.filter_out), 0, 256);

	p->trunk.pool = NULL;
	memset(&(p->trunk.use_pool), 0, sizeof(p->trunk.use_pool));

	// Flag NOT part of multitrunk

	p->trunk.multitrunk_parent = NULL;

	// Initialize shared key to NULL so we can tell if it is unset
	
	p->trunk.sharedkey = NULL;

	if (!destination) // Signals dynamic trunk
	{
		p->trunk.is_dynamic = 1;
		p->trunk.remote_port = 0;
		p->trunk.hostname = NULL;
	}
	else
	{
		p->trunk.is_dynamic = 0;
		p->trunk.remote_port = remote_port;
		p->trunk.hostname = destination;
	}

	if (sharedkey) /* i.e. is a keyed trunk */
		p->trunk.sharedkey = (unsigned char *) sharedkey;
	else    p->trunk.sharedkey = NULL;

	p->next = trunks;
	trunks = p;
	
	return 1;

}

/*
 * eb_device_init_dynamic
 *
 * Set up the (soon to be legacy) 'dynamic' AUN network
 */

uint8_t eb_device_init_dynamic (uint8_t net, uint8_t flags)
{
	struct __eb_device	*p;
	uint8_t			stn;

	if (networks[net])
		eb_debug (1, 0, "CONFIG", "Cannot configure net %d as dynamic station network - network already exists", net);

	p = eb_device_init (net, EB_DEF_NULL, flags);

	for (stn = 254; stn > 0; stn--)
	{
		struct __eb_device      *r;
		struct __eb_aun_remote  *a;

		r = eb_new_local (net, stn, EB_DEF_AUN);

		p->null.divert[stn] = r;

		a = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN Host structure (in NET)", sizeof(struct __eb_aun_remote));

		if (!a) eb_debug (1, 0, "CONFIG", "Unable to malloc() for remote AUN device %d.%d", net, stn);

		r->aun = a;

		r->config = flags; // Enable autoack if requested

		// Initialize the aun struct

		a->stn = stn;
		a->port = -1; // Dynamic
		//strcpy (a->host, "");
		// r->s_addr - later
		a->eb_device = r; // Pointer to divert device
		a->is_dynamic = 1;
		a->b_in = a->b_out = 0; // Traffic stats

		if (pthread_mutex_init(&(a->statsmutex), NULL) == -1)
eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for AUN/IP exposure at %d.%d", net, stn);

		if (pthread_mutex_init(&(a->updatemutex), NULL) == -1)
eb_debug (1, 0, "CONFIG", "Cannot initialize update mutex for AUN/IP exposure at %d.%d", net, stn);

		a->last_dynamic.tv_sec = a->last_dynamic.tv_usec = 0; // Last traffic the epoch
		a->next = NULL;

		// Maintain our list of remote AUN hosts

		if (aun_remotes)	a->next = aun_remotes;
		aun_remotes = a;

		//fprintf (stderr, "AutoAck status for %d.%d is %s (matches[2] = %s)\n", r->net, a->stn, (r->config & EB_DEV_CONF_AUTOACK) ? "On" : "Off", eb_getstring(line, &matches[2]));
	}

	eb_set_whole_wire_net (net, NULL);
	
	return 1;
}

/*
 * eb_device_init_fs
 *
 * Create an FS on net.stn with root path 'rootpath'
 */

uint8_t eb_device_init_fs (uint8_t net, uint8_t stn, char *rootpath)
{
	struct __eb_device 	* existing;

	existing = eb_new_local (net, stn, EB_DEF_LOCAL); // Barfs and quits if cannot do this.

	if (!existing)  eb_debug (1, 0, "CONFIG", "Unable to create fileserver device on %d.%d", net, stn);

	if (existing->local.fs.rootpath) // Already a fileserver
		eb_debug (1, 0, "CONFIG", "Cannot create fileserver at %s - already a fileserver", rootpath);

	existing->local.fs.rootpath = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create FS rootpath string", strlen(rootpath) + 1);

	if (!(existing->local.fs.rootpath))
		eb_debug (1, 0, "CONFIG", "Unable to malloc() fileserver path %s\n", rootpath);

	existing->local.fs.b_in = existing->local.fs.b_out = 0; // Traffic stats

	if (pthread_mutex_init(&(existing->statsmutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for fileserver at %d.%d", net, stn);

	/* Put this in all wire station[] maps */

	eb_set_single_wire_host (net, stn);

	strncpy(existing->local.fs.rootpath, rootpath, strlen(rootpath));

	return 1;
}

/* 
 * eb_device_init_ps
 *
 * Create a PS on net.stn for acorn printer 'acorn' and unix printer 'unix' and user (restriction) 'user'
 */

uint8_t eb_device_init_ps (uint8_t net, uint8_t stn, char * acorn_printer, char * unix_printer, char * user)
{

	struct __eb_device 	* existing;
	struct __eb_printer	* printer, * current_printers;

	existing = eb_new_local (net, stn, EB_DEF_LOCAL);

	if (!existing)  eb_debug (1, 0, "CONFIG", "Unable to create printserver device on %d.%d", net, stn);

	printer = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create printer struct", sizeof(struct __eb_printer));

	if (!printer)   eb_debug (1, 0, "CONFIG", "Unable to malloc() for printer on %d.%d (%s)", net, stn, acorn_printer);

	printer->priority = 1;
	printer->isdefault = 1;
	strcpy (printer->acorn_name, acorn_printer);
	strcpy (printer->unix_name, unix_printer);
	printer->status = PRN_IN_READY | PRN_OUT_READY;
	printer->control = PRNCTRL_DEFAULT;
	printer->printjobs = NULL;
	strcpy (printer->handler, ""); // Null handler

	strcpy (printer->user, user); // 'user' is zero-length string if not restricted, so we just copy it
		
	/* Put this in all wire station[] maps */

	eb_set_single_wire_host (net, stn);

	current_printers = existing->local.printers;

	while (current_printers && current_printers->next)
		current_printers = current_printers->next;

	printer->next = NULL;

	if (current_printers)
		current_printers->next = printer;
	else    existing->local.printers = printer;

	return 1;

}

/*
 * eb_device_init_ps_handler
 *
 * Set the print handler script for printer 'acorn_name' on station net.stn to 'handler'
 *
 */

uint8_t eb_device_init_ps_handler (uint8_t net, uint8_t stn, char * acorn_name, char * handler)
{
	struct __eb_device	* dev;
	struct __eb_printer	* printer;

	dev = networks[net];

	if (!dev)
		eb_debug (1, 0, "CONFIG", "Cannot configure print handler on undefined station %d.%d", net, stn);

	if (dev->type != EB_DEF_WIRE && dev->type != EB_DEF_NULL)
		eb_debug (1, 0, "CONFIG", "Cannot configure print handler on station that is not a local emulator %d.%d", net, stn);

	if (dev->type == EB_DEF_WIRE)
		dev = dev->wire.divert[stn];
	else    dev = dev->null.divert[stn];

	if (dev->type != EB_DEF_LOCAL)
		eb_debug (1, 0, "CONFIG", "Cannot configure print handler on station that is not a local emulator %d.%d", net, stn);

	printer = dev->local.printers;

	while (printer && strncasecmp(printer->acorn_name, acorn_name, 6))
		printer = printer->next;

	if (!printer)
		eb_debug (1, 0, "CONFIG", "Unknown printer %s on station %d.%d - cannot set print handler", acorn_name, net, stn);

	strncpy (printer->handler, handler, 126);

	return 1;

}

/*
 * eb_device_init_ip
 *
 * Set up an IP server on net.stn with address ip_addr and mask masklen using tunnel interface tunif
 *
 */

uint8_t	eb_device_init_ip (uint8_t net, uint8_t stn, char * tunif, uint32_t ip_host, uint32_t mask_host)
{

	struct __eb_device	* existing;
	struct __eip_addr	* local;
	char			addr[16];

	snprintf (addr, 16, "%d.%d.%d.%d", 
			(ip_host & 0xff000000) >> 24,
			(ip_host & 0x00ff0000) >> 16,
			(ip_host & 0x0000ff00) >> 8,
			(ip_host & 0x000000ff));

	existing = eb_new_local (net, stn, EB_DEF_LOCAL);

	if (!existing)  eb_debug (1, 0, "CONFIG", "Unable to create IP server device on %d.%d", net, stn);

	if (existing->local.ip.tunif[0] != '\0') // Already a tunnel server
		eb_debug (1, 0, "CONFIG", "Unable to create IP gateway on %d.%d - already a gateway", net, stn);

	strcpy (existing->local.ip.tunif, tunif);
	strcpy (existing->local.ip.addr, addr);

	existing->local.ip.b_in = existing->local.ip.b_out = 0; // Traffic stats

	if (pthread_mutex_init(&(existing->statsmutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for IP server at %d.%d", net, stn);

	/* Put this in all wire station[] maps */

	eb_set_single_wire_host (net, stn);

	local = eb_malloc (__FILE__, __LINE__, "IPGW", "Local IP address structure", sizeof(struct __eip_addr));

	if (!local)
		eb_debug (1, 0, "IPGW", "Unable to malloc() IP address structure");

	local->next = NULL;
	local->arp = NULL; // No ARP entries for now
	local->ip = ip_host;
	local->mask = mask_host;
	local->ipq = NULL; // Queue of packets waiting for ARP replies

	existing->local.ip.addresses = local;
	
	return 1;

}
