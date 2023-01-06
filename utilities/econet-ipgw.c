/*
  (c) 2022 Chris Royle
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
	Provide gateway for IP over Econet traffic from JGH's TCP/IP ROM
*/

#define DEBUG 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <endian.h>
#include <regex.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "../include/econet-gpio-consumer.h"

//  Necessary variables for the pipe library
uint32_t seq = 0x4000; // Starting AUN sequence number

int tobridge, frombridge; // Descriptors

char pipebase[256]; // Starting path to pipe. We append 'frombridge' and 'tobridge'

extern void econet_setbase(char *);
extern int econet_openreader();
extern int econet_openwriter();
extern int aun_read (struct __econet_packet_aun *);
extern int econet_poll(int);
extern void econet_dump (struct __econet_packet_aun *, int, uint8_t);
extern int aun_send (struct __econet_packet_aun *, int);
uint8_t noisy = 1; // Packet stuff
uint8_t localnet = 0, distantnet = 0; // local net = the number associated with our local network, distantnet is the network notionally on the other side of the bridge (in Pi world, there may be several)

int tunnel_fd; // Descriptor for the tunnel interface
char tunnel[30]; // Tunnel device name

uint32_t my_ip; // My IP address - host order
uint8_t mask;

// ARP response timeout in ms
#define ARP_WAIT 2500 
// ARP timeout in seconds (5 mins)
#define ARP_TIMEOUT 600

struct __eip_arp {
	uint32_t ip; // Host order
	uint16_t econet; // net is MSB
	struct timeval expiry; // Expiry time
	struct __eip_arp *next;
};

struct __eip_addr { // Local addresses
	uint32_t ip; // Host order
	uint32_t mask; // Host order
	struct __eip_addr *next;
	struct __eip_arp *arp;
};

struct __eip_addr *addresses = NULL;

struct __econet_packet_ip {
	uint8_t vhlen;
	uint8_t stype;
	uint16_t length;
	uint16_t ident;
	uint16_t flags_fragoffset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t csum;
	uint32_t source;
	uint32_t destination;
	unsigned char rest[ECONET_MAX_PACKET_SIZE];
};

int pipeeg_aun_send(struct __econet_packet_aun *p, int len)
{
	if (noisy) econet_dump (p, len, 0);
	return aun_send (p, len+12);
}

// Open a tunnel device
int econet_opentun(char *device)
{
	struct ifreq mine;
	int handle, err;

	// First, open the main tunnel device

	if ((handle = open("/dev/net/tun", O_RDWR)) == -1) // Failed
	{
		fprintf(stderr, "Unable to open IP tunnel device\n"); 
		exit(EXIT_FAILURE);
	}

	// Clear the ifreq structure

	memset(&mine, 0, sizeof(mine));

	// Set it up to talk to the right tunnel

	mine.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(mine.ifr_name, device, IFNAMSIZ); // Ask for the tunnel we want

	// Now try and connect to the tunnel we want

	if ((err = ioctl(handle, TUNSETIFF, (void *) &mine)) == -1) // Failed
	{
		fprintf(stderr, "Unable to open %s\n", device);
		exit(EXIT_FAILURE);
	}

	// By the time we get here, our handle should be talking to the right tunnel

	tunnel_fd = handle;
	if (noisy) fprintf (stderr, "Tunnel %s opened\n", device);
	return handle;

}

struct pollresult { // Result of our poll
	uint8_t dtype; // 1 = Econet, 2 = IP
	union {
		struct __econet_packet_aun aun; // Aun Packet
		struct __econet_packet_ip ip;
		char data[ECONET_MAX_PACKET_SIZE];
	};
	int len;
};

// Poll the Econet pipe & the Tunnel, fill the relevant buffer and notify caller which one replied.
// If we only want one of them, the parameter indicates as much:
// 0 - Both
// 1 - Econet only
// 2 - IP only
//
// ms = wait time in ms
//
// *r = pointer to poll result structure for return data.
// r->dtype = 0xff means nothing returned.
//
// Return value non-zero if there is something to find.
uint8_t econet_ip_poll(uint8_t source, int ms, struct pollresult *r)
{

	struct pollfd p[2];

	p[0].events = p[1].events = POLLIN;
	p[0].revents = p[1].revents = 0;
	p[0].fd = frombridge;
	p[1].fd = tunnel_fd;

	r->dtype = 0xff; // Rogue for no data

	switch (source)
	{

		case 1:
			poll(&(p[0]), 1, ms);
			if (p[0].revents & POLLHUP) // Closed pipe on us!
			{
				fprintf(stderr, "Bridge has gone away. Exiting.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 2:
			poll(&(p[1]), 1, ms);
			break;
		default:
			poll(p, 2, ms);
			break;
	}

	if ((source < 2) && (p[0].revents & POLLIN)) // Econet data arrived
	{
		unsigned char length[2];

		read(frombridge, &length, 2);

		r->len = read(frombridge, &(r->aun), (length[1] << 8) + length[0]) - 12;
		r->dtype = 1;
		return 1;
	}

	if (source != 1 && (p[1].revents & POLLIN)) // IP data arrived
	{
/*
		char buffer[65540];
		r->len = read(tunnel_fd, buffer, 65540); // Need to ditch any excess stuff here
		r->len -= 4;
		memcpy (&(r->ip), &(buffer[4]), r->len);
*/
		r->len = read(tunnel_fd, &(r->ip), ECONET_MAX_PACKET_SIZE);
		if (DEBUG)
		{
			int c = 0;
			fprintf (stderr, "IDATA:");
			while (c < r->len && c < 20)
			{
				fprintf(stderr, " %02X %c", r->data[c],
					(r->data[c] >= 32 && r->data[c] < 125) ? r->data[c] : '.');
				c++;
			}
			fprintf (stderr, "\n");
		
			
		}

		r->dtype = 2;
		return 2;
	}

	return 0;
}

// Attempt IP ARP on the Econet
// NB Caller to ensure there is no existing ARP entry on this 
// interface for this IP!
struct __eip_arp *econet_arp(uint32_t dest_ip, struct __eip_addr *iface)
{

	struct __eip_arp *n; // New entry in case we need it
	struct __econet_packet_aun query, response; // ARP query & response
	struct pollresult r;
	uint8_t result;

	uint8_t count = 0;

	// Build the ARP query
	query.p.aun_ttype = ECONET_AUN_BCAST;
	query.p.dstnet = query.p.dststn = 0xff;
	query.p.port = 0xd2; // IP/Econet Port
	query.p.ctrl = 0xA1; // ARP Ctrl byte

	*((uint32_t *)&(query.p.data[4])) = htonl(dest_ip);
	*((uint32_t *)&(query.p.data[0])) = htonl(my_ip);

	while (count++ < 5) // Change this to timeout later
	{

		pipeeg_aun_send(&query, 8); // Send the ARP request onto the wire
		result = econet_ip_poll(1, 50, &r);

		if (result && (r.aun.p.aun_ttype = ECONET_AUN_DATA && r.aun.p.port == 0xd2 && r.aun.p.ctrl == 0xa2)
			&& (*((uint32_t *)&(r.aun.p.data[0])) == htonl(dest_ip))
			&& (*((uint32_t *)&(r.aun.p.data[4])) == htonl(my_ip))
		)  // ARP reply with correct values
		{
			n = malloc(sizeof(struct __eip_arp));
			if (n)
			{
				// This will need improving to keep the ARP entries in sorted order for speed
				n->ip = dest_ip;
				n->econet = (r.aun.p.srcnet << 8) + r.aun.p.srcstn;
				// Set timeout in here - TODO
				n->next = iface->arp;
				iface->arp = n;
				return n;
			}
			else return NULL; // Malloc failed!

		}

	}

	return NULL; // No answer

}

// Put a received packet on the IP over Econet wire, doing an ARP as
// Necessary
void econet_send_ip(struct __econet_packet_ip *ip, int len)
{
	uint32_t dest_ip;
	struct __eip_addr *ip_ptr = addresses;
	struct __econet_packet_aun p;

	// First, ensure we are comparing in host order

	dest_ip = ntohl(ip->destination);

	// Next, build an Econet AUN packet ready, just in case we find a host to send to

	p.p.aun_ttype = ECONET_AUN_DATA;
	p.p.port = 0xd2; // IP/Econet port
	p.p.ctrl = 0x81; // This might need to change - keep an eye!

	// Source filled in by bridge; Dest filled in if we find one.
	// Copy data
	memcpy(&(p.p.data), ip, len); // Everything in the data read off the tunnel goes in the data portion

	// Now see if we can find one to send to!

	if (DEBUG) fprintf (stderr, "Search our address list for %08X...", dest_ip);

	while (ip_ptr)
	{
		if (DEBUG) fprintf (stderr, "Comparing with %08X/%d...", ip_ptr->ip, ip_ptr->mask);

		if ((dest_ip & ip_ptr->mask) == (ip_ptr->ip & ip_ptr->mask)) // Match - send
		{
			struct __eip_arp *arp_ptr = ip_ptr->arp, *arp_ptr_previous = NULL;
			struct timeval now;

			if (DEBUG) fprintf (stderr, "Matched...");
			gettimeofday(&now, 0);

			// Do we have an ARP entry for the destination? If not, see if we can find one
			if (DEBUG) fprintf (stderr, "Search for ARP entry for %08X...", dest_ip);

			while (arp_ptr)
			{
/* DISABLE TIMEOUT FOR TESTING
				if ((now.tv_sec - arp_ptr->expiry.tv_sec) > ARP_TIMEOUT)
				{
					struct __eip_arp *old;

					if (DEBUG) fprintf (stderr, "timing out entry at %p...", arp_ptr);

					// Get rid of the entry
					if (arp_ptr_previous) // We are not at head of list
						arp_ptr_previous->next = arp_ptr->next;
					else	ip_ptr->arp = arp_ptr->next;
						
					old = arp_ptr;
					arp_ptr = arp_ptr->next;
					// Free it up
					free(old);
					continue; // Continue loop
				}
*/
				if (arp_ptr->ip == dest_ip) // Found - transmit
				{
					p.p.dstnet = (arp_ptr->econet & 0xff00) >> 8;
					p.p.dststn = (arp_ptr->econet & 0xff);
					if (DEBUG) fprintf (stderr, "ARP cache entry found for %3d.%3d - transmitting\n", p.p.dstnet, p.p.dststn);
					pipeeg_aun_send (&p, len);
					return;
				}
				arp_ptr_previous = arp_ptr;
				arp_ptr = arp_ptr->next;
			}	
		
			if (arp_ptr == NULL) // Not found
			{
				struct __eip_arp *new;

				// Attempt ARP on the wire. econet_arp() will arp, and if it gets a reply
				// it will put it into the ARP cache for ip_ptr and return a pointer to the
				// new entry, or NULL.
				if (DEBUG) fprintf (stderr, "Doing Econet ARP for %08X...", dest_ip);
				new = econet_arp(dest_ip, ip_ptr);
				
				if (new) // We got an entry - transmit
				{
					p.p.dstnet = (new->econet & 0xff00) >> 8;
					p.p.dststn = (new->econet & 0xff);
					if (DEBUG) fprintf (stderr, "Found at %3d.%3d - transmitting\n", p.p.dstnet, p.p.dststn);
					pipeeg_aun_send (&p, len);
					return;
				}
				
				// Otherwise dump the packet

				if (DEBUG) fprintf (stderr, "Dumped.\n");
			}

			ip_ptr = NULL; // Quit out of while loop
		}
		else
			ip_ptr = ip_ptr->next;
	}
	
	if (DEBUG) fprintf (stderr, "Network not found. Dumping packet.\n");

}

int econet_ispresent(uint8_t net, uint8_t stn)
{

	int result = 0;
	struct __econet_packet_aun p;
	int len;

	p.p.aun_ttype = ECONET_AUN_IMM;
	p.p.port = 0x00;
	p.p.ctrl = 0x88;
	p.p.dststn = stn;
	p.p.dstnet = net;
	p.p.data[0] = p.p.data[1] = p.p.data[2] = p.p.data[3] = 0;

	pipeeg_aun_send(&p, 4);

	if (econet_poll(500))
	{
		// Assume we got an answer
		result = 1;

	}
	
	return result;

}

// Main loop here
void econet_ipgw_run(void)
{

	struct __econet_packet_aun p;

	// First, we need to send something on the pipe, because it will wake the bridge up and it'll open
	// it's writer socket to us. Let's try a bridge broadcast. Also it might generate something 
	// back to us that we can display.

	p.p.dststn = p.p.dstnet = 0xff; // Broadcast destination
	// Don't bother setting the source - the bridge will fill it in
	p.p.aun_ttype = ECONET_AUN_BCAST;
	p.p.port = 0x9c; // Bridge
	p.p.ctrl = 0x82; // Ctrl - Local net query
	strncpy(p.p.data, "BRIDGE", 7);
	p.p.data[6] = 0x9c; // Reply port
	p.p.data[7] = 0; // Net being queried

	pipeeg_aun_send (&p, 8);

	if (econet_poll(1000)) // Wait 100ms for a reply to our bridge query. We might not get one, because the bridge might not be bridging to other network numbers
	{
		int len;

		len = aun_read(&p);

		if (len == 14) // Length of a bridge reply
		{
			if (noisy) econet_dump (&p, len-12, 1);
			localnet = p.p.data[0];
			if (noisy) fprintf (stderr, "Network numbers: local %d, distant %d\n", localnet, p.p.srcnet);
		}

	}
	else
		if (noisy) fprintf (stderr, "No bridge reply received (assuming single local network)\n");
	
	// Ok, listen for traffic!

	while (1)
	{
		uint8_t result;
		struct pollresult r;
		struct __econet_packet_aun p;

		result = econet_ip_poll	(0, 1000, &r); // Poll 1s for traffic from either source

		if (result == 1) // Econet traffic arrived
		{
			// "Is this an ARP I see belore me?"

			if (r.aun.p.aun_ttype == ECONET_AUN_BCAST &&
				r.aun.p.port == 0xd2 &&
				r.aun.p.ctrl == 0xa1)
			{
				struct __eip_addr *ptr = addresses;
				uint32_t src_ip, dest_ip;

				dest_ip = ntohl(*((uint32_t *) &(r.aun.p.data[4])));
				src_ip = ntohl(*((uint32_t *) &(r.aun.p.data)));

				if (noisy) fprintf(stderr, "  ARP: Who has %08x? Tell %08x", dest_ip, src_ip);

				// Is it one of ours?

				while (ptr)
				{
					if (ptr->ip == dest_ip)
					{
						fprintf (stderr, " - Responding\n", src_ip);
						// Do ARP response
						p.p.aun_ttype = ECONET_AUN_DATA;
						p.p.port = 0xd2;
						p.p.ctrl = 0xa2;
						p.p.dstnet = r.aun.p.srcnet;
						p.p.dststn = r.aun.p.srcstn;
						memcpy(&(p.p.data[4]), &(r.aun.p.data[0]), 4);
						memcpy(&(p.p.data[0]), &(r.aun.p.data[4]), 4);
						pipeeg_aun_send(&p, 8);
						// See if we have an ARP entry on this i/f for this destination
						// and insert if not.
			
						{
							struct __eip_arp *arp_ptr;
		
							arp_ptr = ptr->arp;

							while (arp_ptr)
							{
					
								if (arp_ptr->ip == src_ip) 
								{
									gettimeofday(&(arp_ptr->expiry), 0); // Reset expiry	
									// Update station just in case
									arp_ptr->econet = (r.aun.p.srcnet << 8) + r.aun.p.srcstn;
									break;
								}
								else arp_ptr = arp_ptr->next;

							}	

							if (!arp_ptr) // Insert
							{
								arp_ptr = malloc(sizeof(struct __eip_arp));
								if (!arp_ptr)
								{
									fprintf (stderr, "malloc() failed trying to allocate ARP entry\n");
									exit(EXIT_FAILURE);
								}
								arp_ptr->ip = src_ip;
								arp_ptr->econet = (r.aun.p.srcnet << 8) + r.aun.p.srcstn;
								gettimeofday(&(arp_ptr->expiry), 0);
								arp_ptr->next = ptr->arp;
								ptr->arp = arp_ptr;
							}

						}

						break;
					}
					ptr = ptr->next;
					if (!ptr) fprintf (stderr, " - Ignoring\n");
				}

			}	
			else if (r.aun.p.aun_ttype == ECONET_AUN_DATA &&
				r.aun.p.port == 0xd2 &&
				r.aun.p.ctrl == 0x81) // If it's IP data, put it off into the real world
			{
				if (noisy)
				{
					int c = 0;
					fprintf (stderr, "TO IP: len 0x%04x %08X (%02X)", r.len, r.len, sizeof(r.len));
					while (c <  20 && c < r.len)
					{
						fprintf (stderr, " %02x %c", r.aun.p.data[c], 
							(r.aun.p.data[c] >= 32 && r.aun.p.data[c] < 125) ? r.aun.p.data[c] : '.');
						c++;
					}
					fprintf (stderr, "\n");
				}
				
				write(tunnel_fd, (char *) &(r.aun.p.data), r.len);
			}

		}
		else if (result == 2) // IP traffic received
		{
			if (DEBUG) fprintf (stderr, "FR IP: len 0x%04X src=0x%08X, dst = 0x%08X\n", r.len, ntohl(r.ip.source), ntohl(r.ip.destination));

			econet_send_ip(&(r.ip), r.len);
/*
			uint32_t dest_ip;

			// Work out dest IP & write it - ARP if need be
		
			dest_ip = ntohl(r.ip.destination);
			
			// Build an econet datagram

			p.p.aun_ttype = ECONET_AUN_DATA;
			p.p.port = 0xd2;
			p.p.ctrl = 0x81;
			p.p.dst
			memcpy(&(p.p.data), &r, r.len);

			pipeeg_aun_send(&p, r.len);
*/
		}

	}

}

void main(int argc, char **argv)
{

	int opt, initialized = 0;
	uint32_t converted;
	char *slashptr;
	struct __eip_addr *addr;

	fprintf (stderr, "PiEconetBridge IP Gateway v0.1\n\n");

	while ((opt = getopt(argc, argv, "i:hn:p:qt:")) != -1)
	{
		switch (opt) {
			case 'h':
				fprintf (stderr, " \n\
Copyright (c) 2022 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
Usage: %s [options]\n\
\n\
NB: This sends all traffic other than for local IP subnet down\n\
The defined tunnel (which you need to set up beforehand with\n\
'ip tuntap'. It relies on the host's own routing table\n\
thereafter.\n\
\n\
IP address set with -i MUST match the one set on the tunnel i/f\n\
\n\
Options:\n\
\n\
\t-h\tThis help text\n\
\t-i <ip addr/masklen> - Local IP address on Econet\n\
\t-p <base path>\tBase path (excluding tobridge/frombridge) of named pipe to join\n\
\t-q\tQuiet mode - no packet dumps or other unnecessary output\n\
\t-t <ifname>\tTunnel interface name\n\
\n\
", argv[0]);
				break;
			case 'i':
				slashptr = strchr(optarg, '/');
				if (!slashptr)
				{
					fprintf (stderr, "%s lacks a '/' mask delimited.\n");
					exit(EXIT_FAILURE);
				}
	
				*(slashptr) = (char) 0;

				if (sscanf((slashptr+1), "%d", &mask) != 1)
				{
					fprintf (stderr, "Couldn't parse netmask portion.\n");
					exit(EXIT_FAILURE);
				}

				converted = inet_addr(optarg);
				if (converted == INADDR_NONE)
				{
					fprintf (stderr, "Can't parse %s as an IP address (inet_addr())\n", optarg);
					exit(EXIT_FAILURE);
				}
				my_ip = ntohl(converted);
				addr = malloc(sizeof(struct __eip_addr));
				if (addr)
				{
					int maskcount;
					addr->next = addresses;
					addresses = addr;
					addr->ip = my_ip;
					
					maskcount = 0;
					addr->mask = 0;

					while (maskcount < 32)
					{
						addr->mask = addr->mask << 1;
						addr->mask |= (maskcount < mask) ? 1 : 0;
						maskcount++;
					}
					
					addr->arp = NULL; // No ARP table yet
				}
				else
				{
					fprintf (stderr, "malloc() failed when storing IP address.\n");
					exit(EXIT_FAILURE);
				}
				initialized++;
				break;	
			case 'p':
				econet_setbase(optarg);
				initialized++;
				break;
			case 'q': // Quiet
				noisy = 0;
				break;
			case 't': // Tunnel name
				strncpy(tunnel, optarg, 30);
				initialized++;
				break;
		}
	}

	if (initialized < 3)
	{
		fprintf (stderr, "Must specify -p, -i and -t. See '%s -h' for help\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (econet_openreader())
	{

		if (econet_openwriter())
		{
			
			// Open the tunnel

			econet_opentun(tunnel);

			if (noisy)
			{
				fprintf (stderr, "FD - to bridge = %d, from bridge = %d\n", tobridge, frombridge);
				fprintf (stderr, "Tunnel name %s, FD = %d\n", tunnel, tunnel_fd);
				fprintf (stderr, "IP address %08X/%d\n", my_ip, mask);
			}

			// Empty Econet ARP table here, configure IP address.
			// Eventually we will probably be able to have > 1 IP address in case
			// we have subnets over a bridge - plan for it but don't do it yet.
			fprintf (stderr, "Awaiting traffic...\n\n");
			econet_ipgw_run();
			if (noisy) fprintf (stderr, "Exiting\n");
			exit(EXIT_SUCCESS);
		}
		else
		{
			fprintf(stderr, "\nCannot open writing pipe. Exiting.\n");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		fprintf(stderr, "Can't open reading pipe!\n");
		exit(EXIT_FAILURE);
	}	
}
