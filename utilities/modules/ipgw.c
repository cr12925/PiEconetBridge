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

#define _GNU_SOURCE

#include "econet-hpbridge.h"

extern char eb_tunnel_interface_list[512];

/* IP Gateway functions  */

/*
 * eb_ipgw_arp_dest(host order IP)
 * See if there is an unexpired ARP entry. If so, return net/station combo
 * for it
 */

uint16_t eb_ipgw_arp_dest(struct __eb_device *d, struct __eb_ipgw *me, uint32_t addr)
{

	struct __eip_arp 	*a = me->addresses->arp;
	struct timeval		now;

	eb_gettimeofday(&now, 0);

	while (a && (a->ip != addr) && (timediffmsec(&(a->expiry), &now) > 0))
		a = a->next;

	if (!a) return 0;

	eb_debug (0, 3, "IPGW", "%-8s %3d.%3d ARP entry found for network order host %08X",
		eb_type_str(d->type), d->net, d->local.stn, addr);

	return (a->econet);

}

/*  
 * eb_ipgw_set_arp(host order IP, net, stn)
 *
 */

void eb_ipgw_set_arp(struct __eb_device *d, struct __eb_ipgw *me, uint32_t addr, uint8_t net, uint8_t stn)
{

	struct __eip_arp	*a;
	uint8_t			found = 0;

	if (!me->addresses)
		return;

	a = me->addresses->arp;

	while (!found && a)
	{
		if (a->ip == addr)
			found = 1;
		else a = a->next;
	}

	if (!found)
	{
		a = eb_malloc(__FILE__, __LINE__, "IPGW", "New ARP entry", sizeof(struct __eip_arp));

		if (!a)
			eb_debug (1, 0, "IPGW", "Local    %3d.%3d Unable to malloc() for IPGW ARP entry", d->net, d->local.stn);

		a->next = me->addresses->arp;
		me->addresses->arp = a;
	}

	a->ip = addr;
	a->econet = (net << 8) | stn;
	eb_gettimeofday(&(a->expiry), 0);
	a->expiry.tv_sec += 600; // 5 minutes

	eb_debug (0, 3, "IPGW", "%-8s %3d.%3d ARP entry set for network order host %08X, Econet host %3d.%3d",
		eb_type_str(d->type), d->net, d->local.stn, addr, net, stn);

}

/* eb_ipgw_transmit - send packets which are sitting on our pending queue
   This is called when we've updated the arp cache
*/

uint8_t eb_ipgw_transmit (struct __eb_device *d, struct __eb_ipgw *me, uint32_t addr)
{
	// TODO. Look through d->local.ip.addresses->ipq looking for packets
 	// to transmit to this IP address. Transmit the unexpired ones, and
 	// remove both the transmitted & expired ones from the queue.

	struct __eip_ip_queue		*q, *parent;
	struct timeval			now;
	uint16_t			arp_dest;
	uint8_t				result = 0;

	if (!(arp_dest = eb_ipgw_arp_dest(d, me, addr)))
		return 0; // Something badly wrong - we've been called because there was an arp entry, but there wasn't!

	parent = NULL;
	q = me->addresses->ipq;

	eb_debug (0, 3, "IPGW", "%-8s %3d.%3d Examining transmit queue after ARP reply received for network order address %08X",
		eb_type_str(d->type), d->net, d->local.stn, addr);

	eb_gettimeofday(&now, NULL);

	while (q)
	{
		int32_t		diff;
		uint8_t		sent;

		diff = timediffmsec(&(q->expiry), &now);

		// NB expiry is set at +2s from going on queue
		
		sent = 0;

		if ((q->destination == addr) && (diff < 0))
		{

			q->p->p.dstnet = (arp_dest & 0xff00) >> 8;
			q->p->p.dststn = (arp_dest & 0xff);

			eb_raw_send (d, q->p, q->length);
			sent = 1;
			result = 1;

		}

		// If we sent the packet, or it expired, take it out of the queue
		if (diff >= 0 || sent)
		{
	
			if (parent)
				parent->next = q->next;
			else	me->addresses->ipq = q->next;
				
			
			eb_free (__FILE__, __LINE__, "IPGW", "Freeing outgoing IP packet heading to Econet after ARP reply", q->p);

			eb_free (__FILE__, __LINE__, "IPGW", "Freeing outgoing IP packet queue structure for packet heading to Econet after ARP reply", q);

			if (parent)	q = parent->next;
			else		q = me->addresses->ipq;

		}
		else	
		{
			parent = q;
			q = q->next;
		}

	}

	return result;
}

/* 
 * eb_ipgw_incoming_ip
 */

void eb_ipgw_incoming_ip(struct __eb_device *d, struct __eb_device_module *m, struct __eb_ipgw *me)
{

	struct __econet_packet_ip	incoming;
	struct __econet_packet_aun	*outgoing;
	int 				length;

	length = read(me->socket, &incoming, ECONET_MAX_PACKET_SIZE);

	pthread_mutex_lock (&m->module_mutex);
	if (!(m->module_started))
	{
		/* IPGW disabled */
		pthread_mutex_unlock (&m->module_mutex);
		eb_debug (0, 2, "IPGW", "%3d.%3d Traffic dropped - gateway not active", d->net, d->local.stn);

		return;
	}

	if (length > 0)
	{
		eb_add_stats (&(me->statsmutex), &(me->b_in), length);

		outgoing = eb_malloc (__FILE__, __LINE__, "IPGW", "Econet AUN packet for incoming IP transmission", length + 12);

		// Mark receipt
		
		eb_update_lastrx(d);

		if (outgoing)
		{
			uint16_t	arp_dest;

			memcpy (&(outgoing->p.data), &incoming, length);
			outgoing->p.aun_ttype = ECONET_AUN_DATA;
			outgoing->p.port = 0xd2;
			outgoing->p.ctrl = 0x81;
			outgoing->p.srcnet = d->net;
			outgoing->p.srcstn = d->local.stn;

			if ((arp_dest = eb_ipgw_arp_dest(d, me, incoming.destination)))
			{
				outgoing->p.dstnet = (arp_dest & 0xff00) >> 8;
				outgoing->p.dststn = (arp_dest & 0xff);

				eb_raw_send (d, outgoing, length);

				eb_free(__FILE__, __LINE__, "IPGW", "Freeing incoming IP/AUN packet after transmission on out queue", outgoing);
			}
			else // No ARP entry - send ARP query and put the packet on a queue
			{
				struct __econet_packet_aun	*arp;
				struct __eip_ip_queue		*q, *tail;

				arp = eb_malloc(__FILE__, __LINE__, "IPGW", "Outgoing Econet ARP query", 12 + 8);

				if (!arp)
					eb_debug (1, 0, "IPGW", "Unable to malloc() storage for outgoing ARP query to Econet");

#pragma GCC diagnostic ignored "-Warray-bounds"
				arp->p.srcnet = d->net;
				arp->p.srcstn = d->local.stn;
				arp->p.dstnet = 0xff;
				arp->p.dststn = 0xff;
				arp->p.aun_ttype = ECONET_AUN_BCAST;
				arp->p.port = 0xd2;
				arp->p.ctrl = 0xa1;

				*((uint32_t *)&(arp->p.data[4])) = incoming.destination;
				*((uint32_t *)&(arp->p.data[0])) = htonl(me->addresses->ip);

#pragma GCC diagnostic warning "-Warray-bounds"
				eb_raw_send (d, arp, 8);

				eb_free(__FILE__, __LINE__, "IPGW", "Freeing outgoing Econet ARP packet", arp);

				q = eb_malloc(__FILE__, __LINE__, "IPGW", "Storage structure for pending IP/Econet packet without ARP entry", sizeof(struct __eip_ip_queue));

				if (!q)
					eb_debug (1, 0, "IPGW", "Unable to malloc() storage for incoming IP packet header queue structure");

				eb_debug (0, 3, "IPGW", "%-8s %3d.%3d Queueing outbound packet to network order host %08X pending ARP",
					eb_type_str(d->type), d->net, d->local.stn, incoming.destination);

				q->p = outgoing;
				q->destination = incoming.destination;
				q->length = length;
				eb_gettimeofday(&(q->expiry), 0);
				q->expiry.tv_sec += 2;
				q->next = NULL;

				tail = me->addresses->ipq;

				while (tail && tail->next)	tail = tail->next;

				if (tail)	tail->next = q;
				else		me->addresses->ipq = q;
						
			}
		}
		else eb_debug (1, 0, "IPGW", "Local    %3d.%3d Unable to malloc() storage for incoming IP packet for transmission into the network", d->net, d->local.stn);

	}

	pthread_mutex_unlock(&(m->module_mutex));
}

/*
 * Handle IP traffic appearing on port &D2 over the Econet sphere
 */

//void eb_handle_ipgw_traffic (struct __econet_packet_aun *p, uint16_t len, void *param)
void ipgw_handle_traffic_internal (struct __eb_device *d, struct __eb_device_module *m, struct __econet_packet_aun *p, uint16_t len) /* Modularized version */
{
	uint32_t src_ip, dst_ip;
	struct __eb_ipgw *me = (struct __eb_ipgw *) m->module_ws;

	if (!(me->tunif[0])) /* No IPGW here! */
		return;

	/* Accept DATA, or BROADCAST if it's ctrl A1 (ARP request) */

	if (!((p->p.aun_ttype == ECONET_AUN_DATA) || (p->p.aun_ttype == ECONET_AUN_BCAST && p->p.ctrl == 0xA1)))
		return;
	
	if (p->p.aun_ttype == ECONET_AUN_DATA)
		eb_send_ack (d, p, ECONET_AUN_ACK);

	src_ip = *((uint32_t *) &(p->p.data[0]));
	dst_ip = *((uint32_t *) &(p->p.data[4]));

	eb_dump_packet (d, EB_PKT_DUMP_POST_O, p, len);

	switch (p->p.ctrl)
	{
		case 0xA1: // Incoming ARP request
		{
			// Well, first we can update our ARP cache since we have just discovered a station (potentially)

			eb_ipgw_set_arp (d, me, src_ip, p->p.srcnet, p->p.srcstn);

			if (ntohl(dst_ip) == me->addresses->ip)
			{
				struct __econet_packet_aun *arp_reply;

				arp_reply = eb_malloc(__FILE__, __LINE__, "IPGW", "Arp Reply", 20);

				if (!arp_reply) eb_debug (1, 0, "IPGW", "Unable to malloc() for ARP reply!");

				arp_reply->p.aun_ttype = ECONET_AUN_DATA;
				arp_reply->p.port = 0xd2;
				arp_reply->p.ctrl = 0xA2;
				arp_reply->p.srcnet = d->net;
				arp_reply->p.srcstn = d->local.stn;
				arp_reply->p.dstnet = p->p.srcnet;
				arp_reply->p.dststn = p->p.srcstn;

				memcpy(&(arp_reply->p.data[0]), &(p->p.data[4]), 4);
				memcpy(&(arp_reply->p.data[4]), &(p->p.data[0]), 4);

				eb_debug (0, 3, "IPGW", "%-8s %3d.%3d Attempting to send ARP reply to %3d.%3d for our address",
					eb_type_str(d->type), d->net, d->local.stn, arp_reply->p.dstnet, arp_reply->p.dststn);

				eb_raw_send (d, arp_reply, 8);

				/* Free it - eb_raw_send copies the packet */

				eb_free (__FILE__, __LINE__, "IPGW", "Free Arp Reply", arp_reply); 
			}

			eb_ipgw_transmit (d, me, src_ip);

		} break;

		case 0xA2: // Incoming ARP reply
		{
			eb_ipgw_set_arp (d, me, src_ip, p->p.srcnet, p->p.srcstn);
			eb_ipgw_transmit (d, me, src_ip);

		} break;
	
		case 0x81: // Incoming IP traffic
		{
			/* Set ARP just in case this is traffic to us that the client already had an ARP entry for. */
			eb_ipgw_set_arp (d, me, src_ip, p->p.srcnet, p->p.srcstn);
			write(me->socket, (char *) &(p->p.data), len);
		} break;
	}
}

/* Modularized code */

uint8_t ipgw_init_private (struct __eb_device *d, struct __eb_device_module *m, struct json_object *j)
{
	// Parse JSON config - which is an array of objects { "interface":"tun0", "ip":"1.2.3.4/24" } for example - which we store in our private data
	// Which is probably not helpful - because our private data is an interface and a list of addresses, not a list of the pair of both of them.
	
	uint16_t		icount, ilength;
	struct __eb_ipgw	*me = (struct __eb_ipgw *) m->module_ws;

	if (!j)
	{
		eb_debug (0, 1, "IPGW", "Gateway has no configuration for station %d.%d - refusing to initialize", d->net, d->local.stn);
		return 1;
	}

	icount = 0;

	ilength = json_object_array_length (j);

	if (ilength == 0) /* Malformed JSON */
	{
		eb_debug (0, 1, "IPGW", "Malformed JSON configuration for station %d.%d - if your config block is empty, please delete it.", d->net, d->local.stn);
		return 1;
	}

	while (ilength == 1 && icount == 0) /* We're only doing 1 */ 
	{
		struct json_object      *jip, *jipinterface, *jipaddress, *jautostart;
		uint8_t		 ip[4], masklen;
		uint32_t		ip_host, mask_host;
		char		    address[30];

		jip = json_object_array_get_idx (j, icount);

		if (!json_object_object_get_ex(jip, "interface", &jipinterface))
		{
			eb_debug (1, 0, m->module_name, "Malformed IP interface configuration on %d.%d index %d - no tunnel interface specified", d->net, d->local.stn, icount);
			continue;
		}

		if (!json_object_object_get_ex(jip, "ip", &jipaddress))
			eb_debug (1, 0, m->module_name, "Malformed IP interface configuration on %d.%d index %d - no ip address specified", d->net, d->local.stn, icount);

		strncpy (address, json_object_get_string(jipaddress), 29);

		/* Parse the address / mask */

		if (sscanf(address, "%hhd.%hhd.%hhd.%hhd/%hhd",
			&(ip[3]), &(ip[2]), &(ip[1]), &(ip[0]), &masklen) != 5)
			eb_debug(1, 0, m->module_name, "Bad network and/or mask for IP gateway on %d.%d index %d", d->net, d->local.stn, icount);
					
		ip_host = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];

		mask_host = 0;
	
		while (masklen-- > 0)
			mask_host = (mask_host >> 1) | 0x80000000;

		if (strlen(eb_tunnel_interface_list) == 0)
			strcat(eb_tunnel_interface_list, ":");
	
		strcat(eb_tunnel_interface_list, json_object_get_string(jipinterface));
		strcat(eb_tunnel_interface_list, ":");

		/* Finish init here */

		strcpy (me->tunif, json_object_get_string(jipinterface));
		strcpy (me->addr, address);

		me->b_in = me->b_out = 0; /* Initialize traffic counter */

		if (pthread_mutex_init(&(me->statsmutex), NULL) == -1)
			eb_debug (1, 0, m->module_name, "Unable to initialize stats mutex for IP gateway on %d.%d", d->net, d->local.stn);

		me->addresses = eb_module_alloc(m->module_name, "Local IP address structure", sizeof (struct __eip_addr));

		if (!me->addresses)
			eb_debug (1, 0, m->module_name, "Cannot allocate IP address structure for gateway on %d.%d", d->net, d->local.stn);

		me->addresses->next = NULL;
		me->addresses->arp = NULL;
		me->addresses->ip = ip_host;
		me->addresses->mask = mask_host;
		me->addresses->ipq = NULL;	

		/* If any of the entries has autostart:false, set it globally - our parameters are an array, so that will
		 * have to do!
		 */

		if (json_object_object_get_ex(jip, "autostart", &jautostart) && json_object_is_type(jautostart, json_type_boolean))
			m->module_autostart = json_object_get_boolean(jautostart);

		icount++;       
	}

	return 0;
}

/*
 * ipgw_cleanup
 *
 * Releases memory allocated by the IPGW when the service stops.
 */

void ipgw_cleanup (struct __eb_device *d, struct __eb_device_module *m)
{
	struct __eb_ipgw *me = (struct __eb_ipgw *) m->module_ws;
	struct __eip_arp *arp = me->addresses->arp;
	struct __eip_arp *arp_next = NULL;

	/* Our addresses stuff stays live because that's configuration. We're just
	 * freeing packet data and stuff.
	 *
	 * We don't close the socket, because we need to use that again, and in the
	 * basic template macros below, there's presently no startup function that 
	 * we might use to open it
	 */

	while (arp)
	{
		arp_next = arp->next;
		eb_free (__FILE__, __LINE__, "IPGW", "Free ARP entry on module shutdown", arp);
		arp = arp_next;
	}

	me->addresses->arp = NULL; /* Clear out */
}

/* We use the templates */

eb_module_funcs_def(IPGW,struct __eb_ipgw,EB_PORT_IP,ipgw_init_private,ipgw_handle_traffic_internal,ipgw_cleanup);
