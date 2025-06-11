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

#define _GNU_SOURCE

#include "econet-hpbridge.h"

/* IP Gateway functions  */

/*
 * eb_ipgw_arp_dest(host order IP)
 * See if there is an unexpired ARP entry. If so, return net/station combo
 * for it
 */

uint16_t eb_ipgw_arp_dest(struct __eb_device *d, uint32_t addr)
{

	struct __eip_arp 	*a;
	struct timeval		now;

	a = d->local.ip.addresses->arp;

	gettimeofday(&now, 0);

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

void eb_ipgw_set_arp(struct __eb_device *d, uint32_t addr, uint8_t net, uint8_t stn)
{

	struct __eip_arp	*a;
	uint8_t			found = 0;

	if (!d->local.ip.addresses)
		return; // IP not configured on this emulator

	a = d->local.ip.addresses->arp;

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

		a->next = d->local.ip.addresses->arp;
		d->local.ip.addresses->arp = a;
	}

	a->ip = addr;
	a->econet = (net << 8) | stn;
	gettimeofday(&(a->expiry), 0);
	a->expiry.tv_sec += 600; // 5 minutes

	eb_debug (0, 3, "IPGW", "%-8s %3d.%3d ARP entry set for network order host %08X, Econet host %3d.%3d",
		eb_type_str(d->type), d->net, d->local.stn, addr, net, stn);

}

/* eb_ipgw_transmit - send packets which are sitting on our pending queue
   This is called when we've updated the arp cache
*/

uint8_t eb_ipgw_transmit (struct __eb_device *d, uint32_t addr)
{
	// TODO. Look through d->local.ip.addresses->ipq looking for packets
 	// to transmit to this IP address. Transmit the unexpired ones, and
 	// remove both the transmitted & expired ones from the queue.

	struct __eip_ip_queue		*q, *parent;
	struct timeval			now;
	uint16_t			arp_dest;
	uint8_t				result = 0;

	if (!(arp_dest = eb_ipgw_arp_dest(d, addr)))
		return 0; // Something badly wrong - we've been called because there was an arp entry, but there wasn't!

	parent = NULL;
	q = d->local.ip.addresses->ipq;

	eb_debug (0, 3, "IPGW", "%-8s %3d.%3d Examining transmit queue after ARP reply received for network order address %08X",
		eb_type_str(d->type), d->net, d->local.stn, addr);

	gettimeofday(&now, NULL);

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
			else	d->local.ip.addresses->ipq = q->next;
				
			
			eb_free (__FILE__, __LINE__, "IPGW", "Freeing outgoing IP packet heading to Econet after ARP reply", q->p);

			eb_free (__FILE__, __LINE__, "IPGW", "Freeing outgoing IP packet queue structure for packet heading to Econet after ARP reply", q);

			if (parent)	q = parent->next;
			else		q = d->local.ip.addresses->ipq;

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

void eb_ipgw_incoming_ip(struct __eb_device *d)
{

	struct __econet_packet_ip	incoming;
	struct __econet_packet_aun	*outgoing;
	int 				length;

	length = read(d->local.ip.socket, &incoming, ECONET_MAX_PACKET_SIZE);

	if (length > 0)
	{
		eb_add_stats (&(d->local.ip.statsmutex), &(d->local.ip.b_in), length);

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

			if ((arp_dest = eb_ipgw_arp_dest(d, incoming.destination)))
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
				*((uint32_t *)&(arp->p.data[0])) = htonl(d->local.ip.addresses->ip);

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
				gettimeofday(&(q->expiry), 0);
				q->expiry.tv_sec += 2;
				q->next = NULL;

				tail = d->local.ip.addresses->ipq;

				while (tail && tail->next)	tail = tail->next;

				if (tail)	tail->next = q;
				else		d->local.ip.addresses->ipq = q;
						
			}
		}
		else eb_debug (1, 0, "IPGW", "Local    %3d.%3d Unable to malloc() storage for incoming IP packet for transmission into the network", d->net, d->local.stn);

	}

}

/*
 * Handle IP traffic appearing on port &D2 over the Econet sphere
 */

void eb_handle_ipgw_traffic (struct __econet_packet_aun *p, uint16_t len, void *param)
{
	struct __eb_device *d = (struct __eb_device *) param;
	uint32_t src_ip, dst_ip;

	if (!(d->local.ip.tunif[0])) /* No IPGW here! */
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

			eb_ipgw_set_arp (d, src_ip, (p->p.srcnet == 0 ? d->net : p->p.srcnet), p->p.srcstn);

			if (ntohl(dst_ip) == d->local.ip.addresses->ip)
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

				eb_raw_send (d, p, 8);

				/* Free it - eb_raw_send copies the packet */

				eb_free (__FILE__, __LINE__, "IPGW", "Free Arp Reply", arp_reply); 
			}

			eb_ipgw_transmit (d, src_ip);

		} break;

		case 0xA2: // Incoming ARP reply
		{
			eb_ipgw_set_arp (d, src_ip, (p->p.srcnet == 0 ? d->net : p->p.srcnet), p->p.srcstn);
			eb_ipgw_transmit (d, src_ip);

		} break;
	
		case 0x81: // Incoming IP traffic
		{
			write(d->local.ip.socket, (char *) &(p->p.data), len);
		} break;
	}
}
