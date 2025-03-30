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

uint8_t	eb_device_init_wire (uint8_t net, char * device, struct __eb_fw_chain *fw_in, struct __eb_fw_chain *fw_out)
{
	struct __eb_device      *p;
	short                   c_net, c_stn;

	p = eb_device_init (net, EB_DEF_WIRE, 0);

	if ((p->wire.device = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create wire device string", strlen(device)+1)))
		strcpy(p->wire.device, device);
	else    eb_debug (1, 0, "CONFIG", "Cannot malloc space for device name for wire network %d", net);

	p->fw_in = fw_in;
	p->fw_out = fw_out;

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

	// Resilience mode - off at this stage
	
	p->wire.resilience = 0;

	// Initialize bridge response timers

	memset (&(p->wire.last_bridge_whatnet), 0, sizeof(p->wire.last_bridge_whatnet));
	memset (&(p->wire.last_bridge_isnet), 0, sizeof(p->wire.last_bridge_isnet));

	DEVINIT_DEBUG("Created econet with net number %d", net);

	return 1;
}

/*
 * Initialize a trunk device (not a multitrunk or part of one)
 *
 * destination == NULL means a dynamic trunk
 * sharekey == NULL means plaintext trunk
 *
 */

uint8_t eb_device_init_singletrunk (char * destination, uint16_t local_port, uint16_t remote_port, char * sharedkey, struct __eb_fw_chain *fw_in, struct __eb_fw_chain *fw_out, char *name, struct __eb_device *mt_parent, int mt_type, uint32_t retry_interval)
{

	struct __eb_device	* p;

	/* Make our struct */

	p = eb_device_init (0, EB_DEF_TRUNK, 0);

	p->trunk.local_port = local_port;
	p->fw_in = fw_in;
	p->fw_out = fw_out;
	memset (&(p->trunk.xlate_in), 0, 256);
	memset (&(p->trunk.xlate_in), 0, 256);
	memset (&(p->trunk.filter_in), 0, 256);
	memset (&(p->trunk.filter_out), 0, 256);

	p->trunk.pool = NULL;
	memset(&(p->trunk.use_pool), 0, sizeof(p->trunk.use_pool));

	p->trunk.mt_parent = mt_parent; /* Set if we're part of a multitrunk; NULL passed to this function otherwise */
	p->trunk.mt_data = NULL;
	p->trunk.mt_name = name;
	p->trunk.mt_type = mt_type;
	p->trunk.mt_retry = retry_interval;

	if (pthread_mutex_init(&(p->trunk.mt_mutex), NULL) == -1)
		eb_debug (1, 0, "DEVINIT", "%-8s %5d   Cannot initialize multitrunk mutex this device.", "Trunk", p->trunk.local_port);

 	if (pthread_cond_init(&(p->trunk.mt_cond), NULL) == -1)	
		eb_debug (1, 0, "DEVINIT", "%-8s %5d   Cannot initialize multitrunk condition this device.", "Trunk", p->trunk.local_port);

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
	{
		p->trunk.sharedkey = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create trunk key string", 32);
		memset (p->trunk.sharedkey, 0, 32); /* Pad */
		strncpy ((char *) p->trunk.sharedkey, sharedkey, strlen(sharedkey) > 31 ? 31 : strlen(sharedkey));
	}
	else    p->trunk.sharedkey = NULL;

	p->next = trunks;
	trunks = p;
	
	DEVINIT_DEBUG("Created trunk on port number %d (%sdynamic) (Multitrunk parent data '%s' / %p)", p->trunk.local_port, p->trunk.is_dynamic ? "" : "not ", mt_parent ? mt_parent->multitrunk.mt_name : "",
			mt_parent);

	return 1;

}

/*
 * eb_device_init_multitrunk
 *
 * Set up a multi trunk to listen on (NULL, hostname) port X, IPV4/6/both
 */

uint8_t eb_device_init_multitrunk (char *host, char *trunkname, uint16_t port, int family, uint16_t timeout)
{
	struct __eb_device	*p;

	p = eb_device_init(0, EB_DEF_MULTITRUNK, 0);

	p->multitrunk.mt_name = strdup(trunkname);
	p->multitrunk.port = port;
	p->multitrunk.ai_family = family;
	p->multitrunk.timeout = timeout;
	if (host)
		p->multitrunk.host = strdup(host);
	else	p->multitrunk.host = NULL;

	if (multitrunks)
		p->next = multitrunks;

	multitrunks = p;

	DEVINIT_DEBUG("Created Multi-Trunk with name %s, host %s, port %d, family %d", 
			trunkname, host, port, family);

	return 1;
}

/*
 * eb_device_init_dynamic
 *
 * Set up the (soon to be legacy) 'dynamic' AUN network
 */

uint8_t eb_device_init_dynamic (uint8_t net, uint8_t flags, struct __eb_fw_chain *fw_in, struct __eb_fw_chain *fw_out)
{
	struct __eb_device	*p;
	uint8_t			stn;

	if (networks[net])
		eb_debug (1, 0, "CONFIG", "Cannot configure net %d as dynamic station network - network already exists", net);

	p = eb_device_init (net, EB_DEF_NULL, 0);

	for (stn = 254; stn > 0; stn--)
	{
		struct __eb_device      *r;
		struct __eb_aun_remote  *a;

		r = eb_new_local (net, stn, EB_DEF_AUN);

		p->null.divert[stn] = r;
		r->fw_in = fw_in;
		r->fw_out = fw_out;

		a = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN Host structure (in NET)", sizeof(struct __eb_aun_remote));

		if (!a) eb_debug (1, 0, "CONFIG", "Unable to malloc() for remote AUN device %d.%d", net, stn);

		r->aun = a;

		r->config = flags; // Enable autoack if requested

		// Initialize the aun struct

		a->stn = stn;
		a->port = -1; // Dynamic
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

	}

	eb_set_whole_wire_net (net, NULL);
	
	DEVINIT_DEBUG("Created dynamic AUN network %d (with%s Auto Ack)", net, (flags & EB_DEV_CONF_AUTOACK) ? "" : "OUT" );

	return 1;
}

/* 
 * eb_device_init_virtual
 *
 */

uint8_t eb_device_init_virtual (uint8_t net)
{

	if (networks[net])
		eb_debug (1, 0, "CONFIG", "Cannot configure net %d as new virtual network - network already exists", net);

	networks[net] = eb_device_init (net, EB_DEF_NULL, 0);

	DEVINIT_DEBUG("Created virtual network %d", net);

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

	DEVINIT_DEBUG("Created fileserver on %d.%d with path %s", net, stn, rootpath);

	return 1;
}

/* 
 * eb_device_init_ps
 *
 * Create a PS on net.stn for acorn printer 'acorn' and unix printer 'unix' and user (restriction) 'user'
 */

uint8_t eb_device_init_ps (uint8_t net, uint8_t stn, char * acorn_printer, char * unix_printer, char * user, uint8_t priority, uint8_t is_default)
{

	struct __eb_device 	* existing;
	struct __eb_printer	* printer, * current_printers;

	existing = eb_new_local (net, stn, EB_DEF_LOCAL);

	if (!existing)  eb_debug (1, 0, "CONFIG", "Unable to create printserver device on %d.%d", net, stn);

	printer = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create printer struct", sizeof(struct __eb_printer));

	if (!printer)   eb_debug (1, 0, "CONFIG", "Unable to malloc() for printer on %d.%d (%s)", net, stn, acorn_printer);

	printer->priority = priority;
	printer->isdefault = is_default;
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

	DEVINIT_DEBUG("Created print server on %d.%d with Acorn name %s, Unix printer %s", net, stn, acorn_printer, unix_printer);

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

	DEVINIT_DEBUG("Set print handler on %d.%d for Acorn name %s to %s", net, stn, acorn_name, handler);

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
	
	DEVINIT_DEBUG("Created IP server on %d.%d via interface %s with IP address %s", net, stn, tunif, addr);

	return 1;

}

/*
 * eb_device_init_pipe
 *
 */

uint8_t eb_device_init_pipe (uint8_t net, uint8_t stn, char *base, uint8_t flags)
{
	struct __eb_device	*existing;

	existing = eb_new_local (net, stn, EB_DEF_PIPE);

	if (!existing)
		eb_debug (1, 0, "CONFIG", "Unable to create Pipe server device on %d.%d", net, stn);

	existing->pipe.base = base;
	existing->config = flags;

	DEVINIT_DEBUG("Created pipe interface on %d.%d with path %s", net, stn, base);

	return 1;
}

/*
 * eb_device_init_aun_net
 *
 */

uint8_t eb_device_init_aun_host (uint8_t net, uint8_t stn, in_addr_t address, uint16_t port, uint8_t is_autoack, uint8_t printdebug, struct __eb_fw_chain *fw_in, struct __eb_fw_chain *fw_out)
{
	struct __eb_device	*d;
	struct __eb_aun_remote	*e;

	d = eb_new_local(net, stn, EB_DEF_AUN);

	if (!d)
		eb_debug (1, 0, "CONFIG", "Cannot create station %d.%d on AUN MAP - already exists", net, stn);

	e = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN remote structure", sizeof(struct __eb_aun_remote));

	if (!e)
		eb_debug (1, 0, "CONFIG", "Cannot malloc() for AUN MAPped host %d.%d", net, stn);

	e->stn = stn;

	e->port = port;

	e->addr = address;

	e->eb_device = d; // Shouldn't this be to the network structure? CHECK

	e->is_dynamic = 0;

	e->b_in = e->b_out = 0; // Traffic stats

	if (pthread_mutex_init(&(e->statsmutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for AUN/IP exposure at %d.%d", net, stn);

	if (pthread_mutex_init(&(e->updatemutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Cannot initialize update mutex for AUN/IP exposure at %d.%d", net, stn);

	e->next = aun_remotes;

	d->config = 0;

	d->config |= (is_autoack ? EB_DEV_CONF_AUTOACK : 0);

	d->aun = e;

	d->fw_in = fw_in;
	d->fw_out = fw_out;

	aun_remotes = e;

	eb_set_single_wire_host (net, stn);

	if (printdebug)
		DEVINIT_DEBUG("Created AUN map for %d.%d with base %d.%d.%d.%d", net, stn,
			(address & 0xff000000) >> 24,
			(address & 0x00ff0000) >> 16,
			(address & 0x0000ff00) >> 8,
			(address & 0x000000ff));

	return 1;
}

/*
 * eb_device_init_aun_net
 *
 */

uint8_t eb_device_init_aun_net (uint8_t net, in_addr_t base, uint8_t is_fixed, uint16_t port, uint8_t is_autoack, struct __eb_fw_chain *fw_in, struct __eb_fw_chain *fw_out)
{
	uint8_t		stncount;

	for (stncount = 1; stncount < 255; stncount++)
	{
		eb_device_init_aun_host (net, stncount, base + stncount, 
			port ?
				(is_fixed ? port : (port + stncount -1))
			:       (is_fixed ? 32768 : (10000 + (net * 256) + stncount)),
			is_autoack, 0, fw_in, fw_out); /* Trailing 0 tells this function not to print debug - otherwise we get 254 debug lines ! */
	}

	DEVINIT_DEBUG("Created AUN network map for network %d with base %d.%d.%d.%d base port %d (%sfixed, %sAutoACK)", net, 
			(base & 0xff000000) >> 24,
			(base & 0x00ff0000) >> 16,
			(base & 0x0000ff00) >> 8,
			(base & 0x000000ff),	
			port, (is_fixed ? "" : "not "), (is_autoack ? "" : "not "));
	
	return 1;
}

/*
 * eb_device_init_expose_host
 *
 */

uint8_t eb_device_init_expose_host (uint8_t net, uint8_t stn, in_addr_t s_addr, uint16_t port, uint8_t printdebug)
{

	struct __eb_device	*net_device;
	struct __eb_aun_exposure	*dev;

	if (eb_is_exposed (net, stn, 0))
		eb_debug (1, 0, "CONFIG", "Cannot expose %d.%d - already exposed", net, stn);

	net_device = eb_get_network(net);
	dev = eb_malloc (__FILE__, __LINE__, "CONFIG", "Create AUN exposure object", sizeof(struct __eb_aun_exposure));

	if (!dev)
		eb_debug (1, 0, "CONFIG", "Unable to create new exposure device for station %d.%d", net, stn);

	if (pthread_mutex_init(&(dev->exposure_mutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Cannot initialize exposure control mutex for AUN/IP exposure at %d.%d", net, stn);

	if (pthread_mutex_init(&(dev->statsmutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Cannot initialize exposure stats mutex for AUN/IP exposure at %d.%d", net, stn);

	dev->stn = stn;
	dev->net = net;
	dev->addr = s_addr;
	dev->port = port;
	dev->socket = -1; // Init
	dev->active = (net_device ? 1 : 0);

	if (dev->active)
	{
		dev->parent = (
			(net_device->type == EB_DEF_WIRE && net_device->wire.divert[stn] ? net_device->wire.divert[stn] : 
			(net_device->type == EB_DEF_NULL && net_device->null.divert[stn] ? net_device->null.divert[stn] :
			(net_device))));
		eb_debug (0, 4, "CONFIG", "EXPOSURE %3d.%3d Parent device is %p (%s)", net, stn, dev->parent, eb_type_str(dev->parent->type));

	}
	else
	{
		dev->parent = NULL;
		eb_debug (0, 4, "CONFIG", "EXPOSURE %3d.%3d Exposed but inactive (network unknown)", net, stn);
	}

	dev->next = exposures;
	exposures = dev;

	if (printdebug)
		DEVINIT_DEBUG("Created exposure for host %d.%d on %d.%d.%d.%d port %d", net, stn,
				(s_addr & 0xff000000) >> 24,
				(s_addr & 0x00ff0000) >> 16,
				(s_addr & 0x0000ff00) >> 8,
				(s_addr & 0x000000ff),
				port);

	return 1;

}

/*
 * eb_device_init_trunk_nat
 *
 */

uint8_t eb_device_init_trunk_nat (struct __eb_device	*trunk, uint8_t local_net, uint8_t distant_net)
{

	trunk->trunk.xlate_out[local_net] = distant_net;
	trunk->trunk.xlate_in[distant_net] = local_net;

	DEVINIT_DEBUG("Created trunk NAT for distant net %d to local net %d on trunk port %d", distant_net, local_net, trunk->trunk.local_port);

	return 1;
}

/* 
 * eb_device_init_set_bridge_filter
 *
 */

uint8_t eb_device_init_set_bridge_filter (struct __eb_device	*d, uint8_t net, uint8_t drop, uint8_t inbound)
{

	if (d->type == EB_DEF_WIRE)
	{
		if (inbound)
		{
			if (net)
				d->trunk.filter_in[net] = (drop ? 0xff : 0x00);
			else
				memset(&(d->trunk.filter_in), (drop ? 0xff : 0x00), sizeof(d->trunk.filter_in));
		}
		else
		{
			if (net)
				d->trunk.filter_out[net] = (drop ? 0xff : 0x00);
			else
				memset(&(d->trunk.filter_out), (drop ? 0x0ff : 0x00), sizeof(d->trunk.filter_out));
		}
	}
	else if (d->type == EB_DEF_TRUNK)
	{
		if (inbound)
		{
			if (net)
				d->wire.filter_in[net] = (drop ? 0xff : 0x00);
			else
				memset(&(d->wire.filter_in), (drop ? 0xff : 0x00), sizeof(d->trunk.filter_in));
		}
		else
		{
			if (net)
				d->wire.filter_out[net] = (drop ? 0xff : 0x00);
			else
				memset(&(d->wire.filter_out), (drop ? 0x0ff : 0x00), sizeof(d->trunk.filter_out));
		}

	}
	else return 0;	

	DEVINIT_DEBUG("Created bridge protocol announcement filter on %s %s %d %s net %d %s",
			eb_type_str(d->type),
			d->type == EB_DEF_WIRE ? "net" : "port",
			d->type == EB_DEF_WIRE ? d->net : d->trunk.local_port,
			inbound ? "inbound" : "outbound",
			net,
			drop ? "drop" : "accept");

	return 1;
}

/* 
 * eb_device_init_add_fw_to_chain
 *
 */

uint8_t eb_device_init_add_fw_to_chain (struct __eb_fw_chain **chain, uint8_t srcnet, uint8_t srcstn, uint8_t dstnet, uint8_t dststn, uint8_t port, uint8_t action)
{

	struct __eb_fw	*entry, *search;

	entry = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create firewall struct", sizeof(struct __eb_fw));

	if (!entry)
		eb_debug (1, 0, "CONFIG", "Unable to create firewall structure for filter %d.%d to %d.%d port &%02X action %s", srcnet, srcstn, dstnet, dststn, port, (action == EB_FW_ACCEPT ? "Accept" : "Reject"));

	entry->srcnet = srcnet;
	entry->srcstn = srcstn;
	entry->dstnet = dstnet;
	entry->dststn = dststn;
	entry->port = port;
	entry->action = action;
	entry->next = NULL;

	search = (*chain)->fw_chain_start;

	while (search)
	{
		if (!(search->next))
			break;
		search = search->next;
	}

	if (!search)
		(*chain)->fw_chain_start = entry;
	else
		search->next = entry; /* Put on tail */

	return 1;
}

/* 
 * eb_device_init_set_net_clock
 *
 */

uint8_t eb_device_init_set_net_clock (struct __eb_device *d, double period, double mark)
{
	/* Note: On anything but a SPI board, this sets a global net clock because there's only one interface! */

	if (period > 15.5 || period < 3)
		eb_debug (1, 0, "CONFIG", "Bad network clock period");

	if (mark > 3)
		eb_debug (1, 0, "CONFIG", "Bad network clock mark");

	if (d->type != EB_DEF_WIRE)
		eb_debug (1, 0, "CONFIG", "Cannot set network clock - not defined as Econet");

	d->wire.period = period * 4;
	d->wire.mark = mark * 4;

	DEVINIT_DEBUG("Network clock set to %lf period / %lf mark", period, mark);

	return 1;
}

/*
 * eb_device_init_set_trunk_bind_address 
 *
 * NB if trunk object is null, sets global bind address
 */

uint8_t eb_device_init_set_trunk_bind_address (struct __eb_device *d, in_addr_t s)
{

	if (!d)
		bindhost = s;
#if 0
	else
		d->trunk.bindhost = s;
#endif
		
	// Need DEVINIT_DEBUG
	
	return 1;
}	

/*
 * eb_device_init_create_pool
 * 
 */

uint8_t eb_device_init_create_pool (char *poolname, uint8_t start_net, uint8_t *nets)
{
	struct __eb_device	*p;
	uint8_t			net;

	p = eb_device_init(start_net, EB_DEF_POOL, 0);

	if (!p)
		eb_debug (1, 0, "CONFIG", "Unable to create pool named %s", poolname);

	for (net = 1; net < 255; net++)
		if (nets[net])
			eb_set_network(net, p);

	p->pool.data = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create pool data structure", sizeof(struct __eb_pool));

	if (pthread_mutex_init(&(p->pool.data->updatemutex), NULL) == -1)
		eb_debug (1, 0, "CONFIG", "Unable to initialize update mutex for pool %s", poolname);

	strcpy ((char *) p->pool.data->name, poolname);

	for (net = 0; net < 255; net++)
		p->pool.data->hosts_net[net] = NULL;

	p->pool.data->last_net = 0; // Rogue

	memcpy (&(p->pool.data->networks), nets, sizeof (uint8_t) * 255);

	p->pool.data->next = pools;
	pools = p->pool.data;

	DEVINIT_DEBUG("Created pool %s with first net %d", poolname, start_net);

	return 1;
}

/*
 * eb_device_init_set_pool_static
 *
 */

uint8_t eb_device_init_set_pool_static (struct __eb_pool *pool,
		struct __eb_device *source_device,
		uint8_t pool_net,
		uint8_t pool_stn,
		uint8_t source_net,
		uint8_t source_stn)
{

	struct __eb_pool_host	*h;
	uint8_t			err;

	if (!pool)
		eb_debug (1, 0, "CONFIG", "Cannot add static pool mapping - bad pool");

	if (!source_device)
		eb_debug (1, 0, "CONFIG", "Cannot add static pool mapping - bad source device");

	if (source_device->type != EB_DEF_WIRE && source_device->type != EB_DEF_TRUNK)
		eb_debug (1, 0, "CONFIG", "Cannot add static pool mapping - source device is neither trunk nor wire");

	/* Is there already an entry for this address in this pool ? */

	h = eb_pool_find_addr_lock (pool, source_net, source_stn, source_device);

	if (h)
		eb_debug (1, 0, "CONFIG", "Address %d.%d already mapped on %s %d to pool address %d.%d",
				source_net, source_stn,
				eb_type_str(source_device->type),
				(source_device->type == EB_DEF_TRUNK ? source_device->trunk.local_port : source_device->net),
				pool_net, pool_stn);

	/* If we get here, there was no mapping in this pool for this source,
	 * so make one.
	 */

	h = eb_find_make_pool_host (source_device, source_net, source_stn, pool_net, pool_stn, 1 /* static */, &err);

	if (!h || err) /* NULL return on error non-zero */
		eb_debug (1, 0, "CONFIG",
				"Error creating static pool entry for %d.%d on %s %d mapped to pool address %d.%d (%s)",
				source_net, source_stn,
				eb_type_str(source_device->type),
				(source_device->type == EB_DEF_TRUNK ? source_device->trunk.local_port : source_device->net),
				pool_net, pool_stn,
				eb_pool_err(err));

	DEVINIT_DEBUG("Added pool static entry in pool %s for pool host %d.%d to distant host %d.%d on %s %s %d", 
			pool->name, pool_net, pool_stn, source_net, source_stn,
			eb_type_str(source_device->type),
			source_device->type == EB_DEF_WIRE ? "net" : "local port",
			source_device->type == EB_DEF_WIRE ? source_device->net : source_device->trunk.local_port);

	return 1;
}

/* 
 * eb_device_init_set_pooled_nets
 *
 */

uint8_t eb_device_init_set_pooled_nets (struct __eb_pool *pool, struct __eb_device *source, uint8_t all_pooled, uint8_t *nets)
{
	if (!pool)
		eb_debug (1, 0, "CONFIG", "Bad pool device passed to eb_device_init_set_pooled_nets()");

	if (!source)
		eb_debug (1, 0, "CONFIG", "Bad source device passed to eb_device_init_set_pooled_nets()");

	if (source->type != EB_DEF_TRUNK && source->type != EB_DEF_WIRE)
		eb_debug (1, 0, "CONFIG", "Bad source device type passed to eb_device_init_set_pooled_nets()");

	source->all_nets_pooled = all_pooled;

	if (source->type == EB_DEF_TRUNK)
	{
		source->trunk.pool = pool;
		memcpy(&(source->trunk.use_pool), nets, sizeof(uint8_t) * 255);
	}
	else
	{
		source->wire.pool = pool;
		memcpy(&(source->trunk.use_pool), nets, sizeof(uint8_t) * 255);
	}

	DEVINIT_DEBUG("Applied pool %s on device %s %s %d",
			pool->name,
			eb_type_str(source->type),
			source->type == EB_DEF_WIRE ? "net" : "local port",
			source->type == EB_DEF_WIRE ? source->net : source->trunk.local_port);

	return 1;
}
