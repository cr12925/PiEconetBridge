/*
  (c) 2021 Chris Royle
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <endian.h>
#include <regex.h>
#include <time.h>
#include "../include/econet-gpio-consumer.h"
#include "../include/econet-pserv.h"

extern int fs_initialize(unsigned char, unsigned char, char *);
extern void handle_fs_traffic(int, unsigned char, unsigned char, unsigned char, unsigned char *, unsigned int);
extern void handle_fs_bulk_traffic(int, unsigned char, unsigned char, unsigned char, unsigned char, unsigned char *, unsigned int);
extern void fs_garbage_collect(int);
extern unsigned short fs_quiet;
extern int fs_sevenbitbodge;

#define ECONET_HOSTTYPE_TDIS 0x02
#define ECONET_HOSTTYPE_TWIRE 0x04
#define ECONET_HOSTTYPE_TLOCAL 0x08
#define ECONET_HOSTTYPE_TAUN 0x01

#define ECONET_SERVER_FILE 0x01
#define ECONET_SERVER_PRINT 0x02
#define ECONET_SERVER_SOCKET 0x04

// AUN Ack wait time in ms - a remote bridge will only Ack a packet going to the wire if it successfully transmits onto the wire, so this may need to be a while
#define ECONET_AUN_ACK_WAIT_TIME 300
// Delay in us before sending AUN ACK. Helps to smooth traffic flow to remote bridges - otherwise they tend to get their underwear tangled on transmit. Doesn't need to be very long.
// Note this value is MICROseconds, the wait time above is MILLIseconds
#define ECONET_AUN_ACK_DELAY 100 

#ifdef ECONET_NO_WIRE
#define DEVICE_PATH "/dev/null"
#else
#define DEVICE_PATH "/dev/econet-gpio"
#endif

int aun_send (struct __econet_packet_udp *, int, short, short, short, short);

void dump_pkt_data(unsigned char *, int, unsigned long);

struct pollfd pset[65536];
int pmax;
int econet_fd;
int seq;
int pkt_debug = 0;
int dumpmode_brief = 0;
int wire_enabled = 1;
int spoof_immediate = 1;

int start_fd = 0; // Which index number do we start looking for UDP traffic from after poll returns? We do this cyclicly so we give all stations an even chance

unsigned short numtrunks;

char cfgpath[512] = "/etc/econet-gpio/econet.cfg";

unsigned char econet_stations[8192];

// Holds data from econet.cfg file
struct econet_hosts {							// what we we need to find a beeb?
	unsigned char station;
	unsigned char network;
	struct in_addr s_addr;
	char hostname[250];
	unsigned int port;
	int listensocket; /* One socket for each thing on the Econet wire - -2 if on UDP because we don't listen "for" those, we only transmit /to/ them */
	short type;
	short servertype;
	char fs_serverparam[1024];
	char print_serverparam[1024];
	char socket_serverparam[1024];
	int pind; /* Index into pset for this host, if it has a socket */
#ifdef ECONET_64BIT
	unsigned int seq, last_imm_seq_sent; // Our local sequence number, and the last immediate sequence number sent to this host (for wire hosts) so that we acknowledge with the same immediate sequence number
	unsigned int last_seq_ack; // The last sequence number which was acknowledged to this host if it is AUN. If we have already acknoweldged a given sequence number, we *don't* attempt to re-transmit the data onto the Econet Wire, but we do acknowledge the packet again
#else	
	unsigned long seq, last_imm_seq_sent;
	unsigned int last_seq_ack; // The last sequence number which was acknowledged to this host if it is AUN. If we have already acknoweldged a given sequence number, we *don't* attempt to re-transmit the data onto the Econet Wire, but we do acknowledge the packet again
#endif
	unsigned char last_imm_ctrl, last_imm_net, last_imm_stn; // Designed to try and avoid adding high bit back on where it's an immediate transmitting a characer for *NOTIFY - net & stn are source net & stn of the last immediate going to this host
	int fileserver_index;
	struct timespec last_wire_tx;
};

struct econet_hosts network[65536]; // Hosts we know about / listen for / bridge for
short econet_ptr[256][256]; /* [net][stn] pointer into network[] array. */
short fd_ptr[65536]; /* Index is a file descriptor - yields index into network[] */

int stations; // How many entries in network[]

short ip_networklist[256]; /* Networks we know about somewhere in IP space - for bridge queries */

// Trunking stuff

#define FW_DROP 1
#define FW_ACCEPT 2

struct __fw_entry {
	unsigned short srcnet, srcstn, dstnet, dststn;
	unsigned short action;
	void *next;
};

struct __trunk {
	unsigned short dst_start, dst_end;
	struct in_addr s_addr;
	int listenport; // Local port number
	int port; // Remote port number
	int listensocket;
	struct __fw_entry *head, *tail;
	unsigned char xlate_src[256];
	char hostname[300];
};

struct __trunk trunks[256];

// The network number we report in a first bridge reply. It's the first distant network we learn about from the config
// Eventually we may listen for bridge announcements and update it from that

short nativebridgenet = 0, localnet = 0;

struct sockaddr_in src_address;

// Packet Buffers
struct __econet_packet_udp udp_pkt;
struct __econet_packet_aun aun_pkt;

// Locally Emulated machines
#ifdef ECONET_64BIT
unsigned int local_seq = 0x00004000;
#else
unsigned long local_seq = 0x00004000;
#endif

// Local Print Server state

#define MAXPRINTJOBS 10

struct printjob {
	short net, stn;
	short ctrl; // Oscillates betwen &81, &80
	short port;
	FILE *spoolfile;
};

struct printjob printjobs[MAXPRINTJOBS];

// Local bridge query status
int bridge_query = 1;

void econet_readconfig(void) 
{
	// This reads a config file in like the BeebEm One.
	// However, stations with IP address 0.0.0.0 are on the Econet wire.
	// We listen on all IP addresses with the specified port for each one.
	// Stations with real IP addresses are out on the internet (or potentially on
	// The local machine if some sort of emulator is running - e.g. BeebEm
	
	FILE *configfile;
	char linebuf[256];
	regex_t r_comment, r_entry_distant, r_entry_local, r_entry_server, r_entry_wire, r_entry_trunk, r_entry_xlate, r_entry_fw;
	regmatch_t matches[9];
	int i, count;
	short j, k;
	int networkp; // Pointer into network[] array whilst reading config. 
	
	struct hostent *h;
	struct sockaddr_in service;

	numtrunks = 0;

	pmax = 0;
	for (i=0; i < 256; i++)
		ip_networklist[i] = 0;

	configfile = fopen(cfgpath, "r");
	if (configfile == NULL)
	{
		fprintf(stderr, "Unable to open config file %s: %s\n", cfgpath, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Blank off the variables */

	for (j = 0; j < 256; j++)
		for (k = 0; k < 256; k++)
			econet_ptr[j][k] = -1;

	for (j = 0; j < 256; j++)
		trunks[j].listensocket = -1;

	networkp = 0;

	/* Compile some regular expressions */

	if (regcomp(&r_comment, "^\\s*#.*$", 0) != 0)
	{
		fprintf(stderr, "Unable to compile comment regex.\n");
		exit(EXIT_FAILURE);
	}

	/* This needs a better regex */
	if (regcomp(&r_entry_distant, "^\\s*([Aa])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([^[:space:]]+)\\s+([[:digit:]]{4,5})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile full distant station regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_local, "^\\s*[Nn]\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile full local config regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_server, "^\\s*([FfPpSs])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5})\\s+(.+)\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile server regex.\n");
		exit(EXIT_FAILURE);
	}

        if (regcomp(&r_entry_wire, "^\\s*([Ww])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5})\\s*$", REG_EXTENDED) != 0)
        {
                fprintf(stderr, "Unable to compile full wire station regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_trunk, "^\\s*([T])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5})\\s+([[:digit:]]{1,3}|[[:digit:]]{1,3}\\-[[:digit:]]{1,3})\\s+([^[:space:]]+)\\s+([[:digit:]]{4,5})\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile trunk regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_xlate, "^\\s*([X])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile network translation regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_fw, "^\\s*([Y])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+(DROP|ACCEPT)\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile network translation regex.\n");
                exit(EXIT_FAILURE);
        }

	while (!feof(configfile))
	{
		if (fgets(linebuf, 255, configfile) == NULL) break;
		linebuf[strlen(linebuf)-1] = 0x00; // Drop the linefeed

		// Blank off the server parameters

		strcpy(network[networkp].fs_serverparam, "");
		strcpy(network[networkp].print_serverparam, "");
		strcpy(network[networkp].socket_serverparam, "");

		if (regexec(&r_comment, linebuf, 0, NULL, 0) == 0)
		{ }
		else if (regexec(&r_entry_distant, linebuf, 6, matches, 0) == 0)
		{
			char 	tmp[300];
			int	ptr;
				
			/* Find our matches */
			for (count = 1; count <= 5; count++)
			{
				ptr = 0;
				while (ptr < (matches[count].rm_eo - matches[count].rm_so))
				{
					tmp[ptr] = linebuf[ptr + matches[count].rm_so];	
					ptr++;
				}
				tmp[ptr] = 0x00;
				
				switch (count)
				{
					case 1: // D (Distant, IP, Raw packets), A (Distant, IP, AUN)
						switch (tmp[0]) {
							case 'A':
							case 'a':
								network[networkp].type = ECONET_HOSTTYPE_DIS_AUN;
								break;
						}
						break;
					case 2:
						network[networkp].network = atoi(tmp);
						break;
					case 3:
						network[networkp].station = atoi(tmp);
						break;
					case 4:
						strncpy(network[networkp].hostname, tmp, 249);
						h = gethostbyname(tmp);
						if (h == NULL)
						{
							fprintf(stderr, "Cannot resolve hostname %s\n", tmp);
							exit (EXIT_FAILURE);
						}
	
						network[networkp].s_addr = *(struct in_addr *)h->h_addr;

						network[networkp].listensocket = -2; // Distant host
						
						break;
					case 5:
						network[networkp].port = atoi(tmp);
						break;		
				}
			}

			// Turn local server off
			network[networkp].servertype = 0;
			network[networkp].last_seq_ack = 0; // Tracks the last AUN data packet we acknowledged from this host.

			// Include the network in our list
			ip_networklist[network[networkp].network] = 1;
			econet_ptr[network[networkp].network][network[networkp].station] = networkp;

			// If this is a distant AUN station, put it in the station map so the kernel module does the 4-way handshake / replies to immediates
			ECONET_SET_STATION(econet_stations, network[networkp].network, network[networkp].station);

			// Next, if we haven't yet got a native bridged network (i.e. the equivalent of the opposite side of a read bridge), the set one - takes the first in the file basically 
			if (nativebridgenet == 0 && network[networkp].network != 0)
				nativebridgenet = network[networkp].network;
			
			networkp++;
		}
		else if (regexec(&r_entry_local, linebuf, 3, matches, 0) == 0)
		{
			char 	tmp[300];
			int	ptr;
				
			/* Find our matches */
			for (count = 1; count <= 1; count++)
			{
				ptr = 0;
				while (ptr < (matches[count].rm_eo - matches[count].rm_so))
				{
					tmp[ptr] = linebuf[ptr + matches[count].rm_so];	
					ptr++;
				}
				tmp[ptr] = 0x00;
				
				if (count == 1)
					localnet = atoi(tmp);
			}
		}
		else if (regexec(&r_entry_server, linebuf, 6, matches, 0) == 0)
		{
			int stn, net, port, ptr, entry;
			char servertype;
			char datastring[200];
			char tmp[300];
				
			servertype = 0;

			/* Find our matches */
			for (count = 1; count <= 5; count++)
			{
				ptr = 0;
				while (ptr < (matches[count].rm_eo - matches[count].rm_so))
				{
					tmp[ptr] = linebuf[ptr + matches[count].rm_so];	
					ptr++;
				}
				tmp[ptr] = 0x00;
				
				switch (count)
				{
					case 1: // <F>ileserver, <P>rint server
						switch (tmp[0]) {
							case 'F':
							case 'f':
								servertype = ECONET_SERVER_FILE;
								break;
							case 'P':
							case 'p':
								servertype = ECONET_SERVER_PRINT;
								break;
							case 'S':
							case 's':
								servertype = ECONET_SERVER_SOCKET;
						}
						break;
					case 2:
						net = atoi(tmp);
						//network[networkp].network = net;
						break;
					case 3:
						stn = atoi(tmp);
						//network[networkp].station = stn;
						break;
					case 4:
						port = atoi(tmp);
						//network[networkp].port = atoi(tmp);
						break;		
					case 5:
						strncpy(datastring, tmp, 199);
						break;
				}
			}

			entry = econet_ptr[net][stn]; // Existing host
			
			if (entry == -1)
			{
				network[networkp].type = ECONET_HOSTTYPE_LOCAL_AUN;
				network[networkp].servertype = servertype;
				network[networkp].seq = 0x00004000;
				network[networkp].network = net;
				network[networkp].station = stn;
				network[networkp].port = port;
			}
			else	network[entry].servertype |= servertype;

			if (servertype == ECONET_SERVER_FILE)
				strcpy(network[(entry == -1) ? networkp : entry].fs_serverparam, datastring);
			else if (servertype == ECONET_SERVER_PRINT)
				strcpy(network[(entry == -1) ? networkp : entry].print_serverparam, datastring);
			else if (servertype == ECONET_SERVER_SOCKET)
				strcpy(network[(entry == -1) ? networkp : entry].socket_serverparam, datastring);

			if (servertype & ECONET_SERVER_FILE)
			{
				int f;

				f = fs_initialize(net, stn, (char *) &datastring);
				if (f >= 0)
					network[(entry == -1 ? networkp : entry)].fileserver_index = f;
				else f = -1;
			}

                        // Set up the listener

			if (entry == -1) // Doesn't presently exist
			{
                        	if ( (network[networkp].listensocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
                        	{
                                	fprintf(stderr, "Failed to open listening socket for local emulation %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
                                	exit(EXIT_FAILURE);
                        	}
	
                        	service.sin_family = AF_INET;
                        	service.sin_addr.s_addr = INADDR_ANY;
				network[networkp].port = port;
                        	service.sin_port = htons(network[networkp].port);
	
	
                        	if (bind(network[networkp].listensocket, (struct sockaddr *) &service, sizeof(service)) != 0)
                        	{
                                	fprintf(stderr, "Failed to bind listening socket for local emulation %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
                                	exit(EXIT_FAILURE);
                        	}

                        	network[networkp].pind = pmax; // Index into pset from the network[] array

                        	fd_ptr[network[networkp].listensocket] = networkp; // Create the index to find a station from its FD

                        	pset[pmax++].fd = network[networkp].listensocket; // Fill in our poll structure

				ECONET_SET_STATION(econet_stations, net, stn); // Put it in our list of AUN bridges

				ip_networklist[net] = 0xff;
				econet_ptr[net][stn] = networkp;

				networkp++;
			}
		}
		else if (regexec(&r_entry_wire, linebuf, 5, matches, 0) == 0)
                {
                        char	tmp[300];
			int	ptr;

                        /* Find our matches */
                        for (count = 1; count <= 4; count++)
                        {
                                ptr = 0;
                                while (ptr < (matches[count].rm_eo - matches[count].rm_so))
                                {
                                        tmp[ptr] = linebuf[ptr + matches[count].rm_so];
                                        ptr++;
                                }
                                tmp[ptr] = 0x00;

                                switch (count)
                                {
                                        case 1: // W (Wire machine, listen for RAW packets), X (Wire machine, listen for AUN)
                                                switch (tmp[0]) {
                                                        case 'W':
                                                        case 'w':
                                                                network[networkp].type = ECONET_HOSTTYPE_WIRE_AUN;
                                                                break;
                                                }
                                                break;
                                        case 2:
                                                network[networkp].network = atoi(tmp);
                                                break;
                                        case 3:
                                                network[networkp].station = atoi(tmp);
                                                break;
                                        case 4:
                                                network[networkp].port = atoi(tmp);
                                                break;
                                }
                        }

                        // Stop this being a server
                        network[networkp].servertype = 0;

                        econet_ptr[network[networkp].network][network[networkp].station] = networkp;

                        // Set up the listener

                        if ( (network[networkp].listensocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
                        {
                                fprintf(stderr, "Failed to open listening socket for econet net/stn %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
                                exit(EXIT_FAILURE);
                        }

                        service.sin_family = AF_INET;
                        service.sin_addr.s_addr = INADDR_ANY;
                        service.sin_port = htons(network[networkp].port);

                        if (bind(network[networkp].listensocket, (struct sockaddr *) &service, sizeof(service)) != 0)
                        {
                                fprintf(stderr, "Failed to bind listening socket for econet net/stn %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
                                exit(EXIT_FAILURE);
                        }

                        network[networkp].pind = pmax;
			network[networkp].seq = 0x00004000;

			clock_gettime (CLOCK_MONOTONIC, &(network[networkp].last_wire_tx));
                        fd_ptr[network[networkp].listensocket] = networkp; // Create the index to find a station from its FD

                        pset[pmax++].fd = network[networkp].listensocket; // Fill in our poll structure

                        networkp++;
                }
		else if (regexec(&r_entry_trunk, linebuf, 7, matches, 0) == 0)
		{
			char tmp[300];
			int ptr;
			unsigned short trunknum, d_start, d_end, localport, port;
			char hostname[300];

			for (count = 2; count < 7; count++)
			{
				ptr = 0;
                                while (ptr < (matches[count].rm_eo - matches[count].rm_so))
                                {
                                        tmp[ptr] = linebuf[ptr + matches[count].rm_so];
                                        ptr++;
                                }
                                tmp[ptr] = 0x00;

                                switch (count)
                                {
					case 2: // Trunk number
						trunknum = atoi(tmp);
						break;
					case 3: // Local port
						localport = atoi(tmp);
						break;
					case 4: // network range
					{
						switch (sscanf(tmp, "%hd-%hd", &d_start, &d_end))
						{
							case 1:
								d_end = d_start;
								break;
							case 0: 
								fprintf(stderr, "Bad configuration line: %s\n", linebuf);

						}
					}
					case 5: // hostname
						strcpy(hostname, tmp);
						break;
					case 6: // port
						port = atoi(tmp);
						break;	
				}

			}

			trunks[trunknum].dst_start = d_start;
			trunks[trunknum].dst_end = d_end;
			trunks[trunknum].head = trunks[trunknum].tail = NULL;
			trunks[trunknum].listenport = localport;
			memset (trunks[trunknum].xlate_src, 0, sizeof(trunks[trunknum].xlate_src));

                        if ( (trunks[trunknum].listensocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
                        {
                                fprintf(stderr, "Failed to open listening socket for trunk %d: %s.", trunknum, strerror(errno));
                                exit(EXIT_FAILURE);
                        }

                        service.sin_family = AF_INET;
                        service.sin_addr.s_addr = INADDR_ANY;
                        service.sin_port = htons(localport);

                        if (bind(trunks[trunknum].listensocket, (struct sockaddr *) &service, sizeof(service)) != 0)
                        {
                                fprintf(stderr, "Failed to bind listening socket for trunk %d: %s.", trunknum, strerror(errno));
                                exit(EXIT_FAILURE);
                        }

			// Now set up distant host structure
			strcpy(trunks[trunknum].hostname, hostname);
			h = gethostbyname(hostname);
			if (h == NULL)
			{
				fprintf(stderr, "Cannot resolve hostname %s\n", hostname);
				exit (EXIT_FAILURE);
			}

			trunks[trunknum].s_addr = *(struct in_addr *)h->h_addr;

			trunks[trunknum].port = port;

			numtrunks++;

		}
		else if (regexec(&r_entry_xlate, linebuf, 5, matches, 0) == 0)
		{
			unsigned short trunknum, srcnet;
			int ptr;
			char tmp[300];

			for (count = 2; count < 5; count++)
			{
                                ptr = 0;
                                while (ptr < (matches[count].rm_eo - matches[count].rm_so))
                                {
                                        tmp[ptr] = linebuf[ptr + matches[count].rm_so];
                                        ptr++;
                                }
                                tmp[ptr] = 0x00;

                                switch (count)
                                {
					case 2:  // Trunk number
						trunknum = atoi(tmp);
						break;
					case 3: // Our side's network number
						srcnet = atoi(tmp);
						break;
					case 4: // The number we are seen as at the far end of the trunk
						trunks[trunknum].xlate_src[srcnet] = atoi(tmp);
						break;
				}

			}	
		}
		else if (regexec(&r_entry_fw, linebuf, 8, matches, 0) == 0)
		{
                        int ptr;
                        char tmp[300];

			unsigned short trunknum;

			struct __fw_entry *e;
			
			e = malloc(sizeof(struct __fw_entry));

			e->next = NULL;

                        for (count = 2; count < 8; count++)
                        {
                                ptr = 0;
                                while (ptr < (matches[count].rm_eo - matches[count].rm_so))
                                {
                                        tmp[ptr] = linebuf[ptr + matches[count].rm_so];
                                        ptr++;
                                }
                                tmp[ptr] = 0x00;

				switch (count)
				{
					case 2: // trunknum
						trunknum = atoi(tmp);
						break;
					case 3: // incoming source net
						e->srcnet = atoi(tmp);
						break;
					case 4: // incoming source stn 
						e->srcstn = atoi(tmp);
						break;
					case 5: // incoming dest net
						e->dstnet = atoi(tmp);
						break;
					case 6: // incoming dest stn
						e->dststn = atoi(tmp);
						break;
					case 7:						
						if (!strcasecmp(tmp, "DROP"))
							e->action = FW_DROP;
						else	e->action = FW_ACCEPT;

				}	

			}		

			// Update the list
			if (trunks[trunknum].head == NULL)
				trunks[trunknum].head = trunks[trunknum].tail = e;
			else
			{	
				trunks[trunknum].tail->next = e;
				trunks[trunknum].tail = e;
			}

		}
		else		
		{
			fprintf(stderr,    "Bad configuration line: %s\n", linebuf);
			exit(EXIT_FAILURE);
		}
	}

	regfree(&r_entry_wire);
	regfree(&r_entry_server);
	regfree(&r_entry_local);
	regfree(&r_entry_distant);
	regfree(&r_entry_trunk);
	regfree(&r_entry_xlate);
	regfree(&r_entry_fw);
	
	fclose(configfile);

	stations = networkp;

		
} 


void dump_pkt_data(unsigned char *a, int len, unsigned long start_index)
{
	int count;
	int packetsize = len;

	count = 0;
	while (count < packetsize)
	{
		char dbgstr[200];
		char tmpstr[200];
		int z;
		sprintf (dbgstr, "%08lx ", count + start_index);
		z = 0;
		while (z < 32)
		{
			if ((count+z) < packetsize)
			{
				sprintf(tmpstr, "%02x ", *(a+count+z)); 
				strcat(dbgstr, tmpstr);
			}
			else	strcat(dbgstr, "   ");
			z++;
		}

		z = 0;
		while (z < 32)
		{
			if ((count+z) < packetsize)
			{
				sprintf(tmpstr, "%c", (*(a+count+z) >= 32 && *(a+count+z) < 127) ? *(a+count+z) : '.');
				strcat(dbgstr, tmpstr);
			}
			z++;
		}

		fprintf(stderr, "%s\n", dbgstr);		

		count += 32;

	}
	if (start_index == 0)
		fprintf (stderr, "%08x --- END ---\n\n", packetsize);
}

void dump_udp_pkt_aun(int s, short d, struct __econet_packet_aun *a, short srcnet, short srcstn, short dstnet, short dststn)
{

	int count = 0;
	int packetsize = s;
	char ts[20];

	if (pkt_debug == 0) return;

	
	if (dumpmode_brief)
	{
		fprintf (stderr, "%3s%2s: to %3d.%3d from %3d.%3d port 0x%02x ctrl 0x%02x seq 0x%08x len 0x%04x ", (d & 2) == 0 ? "ECO": "LOC", ((d & 1) == 0) ? "->" : "<-", dstnet, dststn, srcnet, srcstn, a->p.port, a->p.ctrl, le32toh(a->p.seq), s);
		for (count = 0; count < (s < 40 ? s : 40); count++)
			fprintf (stderr, "%02x %c ", a->p.data[count], (a->p.data[count] < 32 || a->p.data[count] > 126) ? '.' : a->p.data[count]);
		fprintf (stderr, "\n");
			
	}
	else
	{
		fprintf (stderr, "%08x --- PACKET %s %s ---\n", packetsize, (d & 1) == 0 ? "FROM" : "TO", (d & 2) == 0 ? "ECONET" : "LOCAL");
		switch (a->p.aun_ttype)
		{
			case ECONET_AUN_DATA:
				strcpy(ts, "DATA");
				break;
			case ECONET_AUN_IMM:
				strcpy(ts, "IMMEDIATE");
				break;
			case ECONET_AUN_IMMREP:
				strcpy(ts, "IMMEDIATE REPLY");
				break;
			case ECONET_AUN_BCAST:
				strcpy(ts, "BROADCAST");
				break;
			case ECONET_AUN_ACK:
				strcpy(ts, "ACKNOWLEDGMENT");
				break;
			case ECONET_AUN_NAK:
				strcpy(ts, "NAK");
				break;
			default:
				strcpy(ts, "UNKNOWN");
		}

	fprintf (stderr, "         --- AUN TYPE %s\n", ts);

	if (a->p.port == 0x00 && a->p.ctrl != 0x85) /* Immediate */
		fprintf (stderr, "         IMMEDIATE\n");
	else if (a->p.port == 0x00) // Special 0x85 Immediate that's done as a 4-way
		fprintf (stderr, "         IMMEDIATE - SPECIAL 0X85\n");
	if (dststn == 0xff)
		fprintf (stderr, "         BROADCAST\n");
	else
		fprintf (stderr, "         DST Net/Stn 0x%02x/0x%02x\n", dstnet, dststn);

	fprintf (stderr, "         SRC Net/Stn 0x%02x/0x%02x\n", srcnet, srcstn);
	fprintf (stderr, "         PORT/CTRL   0x%02x/0x%02x\n", a->p.port, a->p.ctrl);
	
	dump_pkt_data((unsigned char *) &(a->p.data), s, 0);

	}

}

/* Receive from a particular UDP socket */
int udp_receive(int fd, void *a, int maxlen, struct sockaddr * restrict addr)
{
	int  r;
	socklen_t addrlen;

	addrlen = sizeof(struct sockaddr);

	r = recvfrom(fd, a, maxlen, 0, addr, (socklen_t *) &addrlen);

	if (r<0)
		fprintf (stderr, "Error %d (%s) on receiving UDP from socket %d\n", errno, strerror(errno), fd);

	return r;

}

char * econet_strtxerr(int e)
{
	switch (e)
	{
		case ECONET_TX_SUCCESS: return (char *)"No error"; 
		case EBUSY: return (char *)"Module busy";
		case ECONET_TX_JAMMED: return (char *)"Line jammed";
		case ECONET_TX_HANDSHAKEFAIL: return (char *)"Handshake failure";
		case ECONET_TX_NOCLOCK: return (char *)"No clock";
		case ECONET_TX_UNDERRUN: return (char *)"Transmit underrun";
		case ECONET_TX_TDRAFULL: return (char *)"Data register full on tx";
		case ECONET_TX_NOIRQ: return (char *)"No IRQ received to being/continue transmit";
		case ECONET_TX_NOCOPY: return (char *)"Could not copy packet from userspace";
		case ECONET_TX_NOTSTART: return (char *)"Transmission never begun";
		case ECONET_TX_COLLISION: return (char *)"Collision during transmission";
		default: return (char *)"Unknown error";
	}	

}

void aun_acknowledge (struct __econet_packet_udp *a, short srcnet, short srcstn, short dstnet, short dststn, char ptype)
{

	struct __econet_packet_udp reply;

	reply.p.ptype = ptype;
	reply.p.port = a->p.port;
	reply.p.ctrl = a->p.ctrl;
	reply.p.pad = 0x00;
	reply.p.seq = a->p.seq;

	aun_send (&reply, 8, dstnet, dststn, srcnet, srcstn);

}

void econet_handle_local_aun (struct __econet_packet_aun *a, int packlen)
{

	int s_ptr, d_ptr;

	s_ptr = econet_ptr[a->p.srcnet][a->p.srcstn];
	d_ptr = econet_ptr[a->p.dstnet][a->p.dststn];

	//fprintf (stderr, "LOCAL: type %d, to %3d.%3d from %3d.%3d port %02x ctrl %02x length %d\n", 
		//a->p.aun_ttype, a->p.dstnet, a->p.dststn, a->p.srcnet, a->p.srcstn, a->p.port, a->p.ctrl, packlen);

	if (a->p.aun_ttype == ECONET_AUN_IMM) // Immediate
	{
		if (a->p.ctrl == 0x88) // Machinepeek
		{
			a->p.aun_ttype = ECONET_AUN_IMMREP;
			//a->p.seq = (local_seq += 4);
			a->p.seq = (network[d_ptr].seq += 4);
			a->p.data[0] = ADVERTISED_MACHINETYPE & 0xff;
			a->p.data[1] = (ADVERTISED_MACHINETYPE & 0xff00) >> 8;
			a->p.data[2] = ADVERTISED_VERSION & 0xff;
			a->p.data[3] = (ADVERTISED_VERSION & 0xff00) >> 8;

			aun_send ((struct __econet_packet_udp *)&(a->p.aun_ttype), 12, a->p.dstnet, a->p.dststn, a->p.srcnet, a->p.srcstn);
		}	
	}
	else if (a->p.aun_ttype == ECONET_AUN_BCAST) // Broadcast - See if we need to do a bridge query reply
	{
		//fprintf (stderr, "Bridge query %s, port %02x, BRIDGE check %s, localnet %s\n", (bridge_query ? "on" : "off"), a->p.port, (!strncmp("BRIDGE", (const char *) a->p.data, 6) ? "match" : "not matched"), localnet ? "set" : "not set");
		if (bridge_query && (a->p.port == 0x9c) && (!strncmp("BRIDGE", (const char *) a->p.data, 6)) && localnet)
		{
			short query_net, reply_port;
			struct __econet_packet_udp reply;

			reply_port = a->p.data[6];
			query_net = a->p.data[7];
	
			if (pkt_debug)
				fprintf (stderr, "LOC  : BRIDGE     from %3d.%3d, query 0x%02x, reply port 0x%02x, query net %d\n", a->p.srcnet, a->p.srcstn, a->p.ctrl, reply_port, query_net);

			if (a->p.ctrl == 0x82 || (a->p.ctrl == 0x83 && (ip_networklist[query_net] == 0xff))) // Either a local network number query, or a query for a network in our known distant list
			{
				reply.p.ptype = ECONET_AUN_DATA;
				reply.p.port = reply_port;
				reply.p.ctrl = a->p.ctrl;
				reply.p.pad = 0x00;
				reply.p.seq = (local_seq += 4); // local_seq now used for bridge responses
				reply.p.data[0] = localnet;
				reply.p.data[1] = query_net; 
				aun_send (&reply, 10, nativebridgenet, 0, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source. 
			}
	
		}
	}
	else if (a->p.aun_ttype == ECONET_AUN_DATA) // Data packet
	{
		if ((a->p.port == 0x99) && (network[d_ptr].servertype & ECONET_SERVER_FILE) && (network[d_ptr].fileserver_index >= 0))
			handle_fs_traffic(network[d_ptr].fileserver_index, a->p.srcnet, a->p.srcstn, a->p.ctrl, a->p.data, packlen-12);
		else if ((a->p.port == 0x9f) && ((network[d_ptr].servertype) & ECONET_SERVER_PRINT) && (!strncmp((const char *)&(a->p.data), "PRINT", 5))) // Looks like only ANFS does this...
		{
			int count, found;; 
		
			count = 0; found = -1;

			// See if we can find a spare print job

			while (count < MAXPRINTJOBS && found == -1)
			{
				if (printjobs[count].net == 0 && printjobs[count].stn == 0) // Found one
					found = count;
				else	count++;
			}

			if (found != -1)
			{
				struct __econet_packet_udp reply;

				char filename[100];

				printjobs[found].stn = a->p.srcstn;
				printjobs[found].net = a->p.srcnet;
				printjobs[found].ctrl = 0x80; 
				
				reply.p.ptype = ECONET_AUN_DATA;
				reply.p.port = 0x9e;
				reply.p.ctrl = 0x80;
				reply.p.pad = 0x00;
				//reply.p.seq = (local_seq += 4);
				reply.p.seq = (network[d_ptr].seq += 4);
				reply.p.data[0] = 0x00;

				aun_send (&reply, 9, network[d_ptr].network, network[d_ptr].station, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source.

				sprintf(filename, SPOOLFILESPEC, found);

				printjobs[found].spoolfile = fopen(filename, "w");

				if (!printjobs[found].spoolfile)
				{
					printjobs[count].net = printjobs[count].stn = 0;  // Free this up - couldn't open file	
					fprintf (stderr, "Unable to open spool file for print job from station %d.%d\n", a->p.srcnet, a->p.srcstn);
				}
				else
				{
					fprintf (stderr, "PRINT: Starting spooler job for %d.%d - %s\n", a->p.srcnet, a->p.srcstn, network[d_ptr].print_serverparam);
					if (strstr(network[d_ptr].print_serverparam, "@")) // Email print job, not send to printer
					{
						fprintf(printjobs[count].spoolfile, "To: %s\n", network[d_ptr].print_serverparam);
						fprintf(printjobs[count].spoolfile, "Subject: Econet print job from station %d.%d\n\n", a->p.srcnet, a->p.srcstn);
					}
					fprintf (printjobs[count].spoolfile, PRINTHEADER, a->p.srcnet, a->p.srcstn);
				}
				
			}
			else	fprintf(stderr, "PRINT: No resources for job from %d.%d\n", network[s_ptr].network, network[s_ptr].station);

		}
		else if ((a->p.port == 0xd1) && (network[d_ptr].servertype & ECONET_SERVER_PRINT)) // Actual printing
		{
			int found = -1, count = 0;
			struct __econet_packet_udp reply;

			// First locate the printjob entry

			while (count < MAXPRINTJOBS && found == -1)
			{
				if (printjobs[count].net == a->p.srcnet && 
				    printjobs[count].stn == a->p.srcstn)
					found = count;
				else count++;
			}

			if (found == -1) // BBC B starting new job ?
			{
				char filename[100];

				count = 0;

				// Move this to a function at some stage
				while (count < MAXPRINTJOBS && found == -1)
				{
					if (printjobs[count].net == 0 && printjobs[count].stn == 0) // Found one
						found = count;
					else	count++;
				}
	
				if (found != -1)
				{

					printjobs[found].stn = a->p.srcstn;
					printjobs[found].net = a->p.srcnet;
					printjobs[found].ctrl = 0x80; 
					sprintf(filename, SPOOLFILESPEC, found);
	
					printjobs[found].spoolfile = fopen(filename, "w");
	
					if (!printjobs[found].spoolfile)
					{
						printjobs[count].net = printjobs[count].stn = 0;  // Free this up - couldn't open file	
						fprintf (stderr, "Unable to open spool file for print job from station %d.%d\n", a->p.srcnet, a->p.srcstn);
					}
					else
					{
						fprintf (stderr, "PRINT: Starting spooler job for %d.%d - %s\n", a->p.srcnet, a->p.srcstn, network[d_ptr].print_serverparam);
						if (strstr(network[d_ptr].print_serverparam, "@")) // Email print job, not send to printer
						{
							fprintf(printjobs[count].spoolfile, "To: %s\n", network[d_ptr].print_serverparam);
							fprintf(printjobs[count].spoolfile, "Subject: Econet print job from station %d.%d\n\n", a->p.srcnet, a->p.srcstn);
						}
						fprintf (printjobs[count].spoolfile, PRINTHEADER, a->p.srcnet, a->p.srcstn);
					}

				}

			}

			if (found != -1)
			{
				reply.p.ptype = ECONET_AUN_DATA;
				reply.p.port = 0xd1;
				reply.p.ctrl = printjobs[count].ctrl;
				printjobs[count].ctrl ^= 0x01;

				reply.p.pad = 0x00;
				//reply.p.seq = (local_seq += 4);
				reply.p.seq = (network[d_ptr].seq += 4);

				// The control low bit alternation is to avoid duplicated packets. Need to implement a check... TODO.

				switch (a->p.ctrl)
				{
					case 0x83: // Fall through
					case 0x82: // Print job start
					{
						reply.p.data[0] = 0x2a;
						usleep(50000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
						aun_send (&reply, 9, network[d_ptr].network, network[d_ptr].station, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source.
					}
					break;
					case 0x80: // Fall through
					case 0x81: // Print data
					{
						fwrite(&(a->p.data), packlen-12, 1, printjobs[count].spoolfile);
						reply.p.data[0] = a->p.data[0];	
						usleep(100000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
						aun_send (&reply, 9, network[d_ptr].network, network[d_ptr].station, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source.
					}
					break;
					case 0x86: // Fall through
					case 0x87: // Final packet
					{
						char command_string[2000];
						char filename_string[200];

						// There is a rogue byte on the end of the last printjob packet it would seem
						fwrite(&(a->p.data), packlen-12-1, 1, printjobs[count].spoolfile);
						fprintf(printjobs[count].spoolfile, PRINTFOOTER);
						reply.p.data[0] = a->p.data[0];	
						usleep(100000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
						aun_send (&reply, 9, network[d_ptr].network, network[d_ptr].station, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source.
						fclose(printjobs[count].spoolfile);
						sprintf(filename_string, SPOOLFILESPEC, found);
						
						if (strstr(network[d_ptr].print_serverparam, "@")) // Email address not printername
							sprintf(command_string, MAILCMDSPEC, network[d_ptr].print_serverparam, filename_string);
						else
							sprintf(command_string, PRINTCMDSPEC, network[d_ptr].print_serverparam, filename_string);

						fprintf (stderr, "PRINT: Sending print job with %s\n", command_string);
						
						if (!fork())
							execl("/bin/sh", "sh", "-c", command_string, (char *)0);

						printjobs[count].stn = printjobs[count].net = 0; // Free the resource	

						//reply.p.data[0] = a->p.data[0];	
						//aun_send (&reply, 9, network[d_ptr].network, network[d_ptr].station, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source.
					}
					break;

				}
			}
			else
				fprintf (stderr, "PRINT: Spooler not found for print request from %d.%d\n", network[s_ptr].network, network[s_ptr].station);
			
		}
		else if ((network[d_ptr].servertype & ECONET_SERVER_FILE) && (network[d_ptr].fileserver_index >= 0)) // Could be fileserver bulk transfer traffic
			handle_fs_bulk_traffic(network[d_ptr].fileserver_index, a->p.srcnet, a->p.srcstn, a->p.port, a->p.ctrl, a->p.data, packlen-12);
		else
			fprintf(stderr, "LOCAL: Unhandled traffic.\n");
	}
	else if (a->p.aun_ttype == ECONET_AUN_ACK)
	{
	}
	else
	{
		fprintf (stderr, "Ignoring AUN type %d to local station %d.%d\n", a->p.aun_ttype, network[d_ptr].network, network[d_ptr].station);
	}

}

int aun_send (struct __econet_packet_udp *p, int len, short srcnet, short srcstn, short dstnet, short dststn)
{

	int d, s, dir, result;
	struct sockaddr_in n;

	struct __econet_packet_aun w;

	// Build an internal format packet in case we need it
	w.p.srcnet = srcnet;
	w.p.srcstn = srcstn;
	w.p.dstnet = dstnet;
	w.p.dststn = dststn;
	memcpy (&(w.p.aun_ttype), p, len);

	//fprintf (stderr, "Sending AUN packet type %02x to %3d.%3d from %3d.%3d, seq = %08lx, length %d\n", w.p.aun_ttype, dstnet, dststn, srcnet, srcstn, w.p.seq, len);

	if (w.p.aun_ttype == ECONET_AUN_BCAST)
		w.p.dstnet = w.p.dststn = 0xff;
		
	d = econet_ptr[dstnet][dststn];
	s = econet_ptr[srcnet][srcstn];

/*
 * this code is connected to bridge query handling... it hasn't worked!

	if (dstnet == 255 && dststn == 255) return len; // Dump broadcasts for now.

	if (srcnet == localnet && srcstn == 0 && network[d].type & ECONET_HOSTTYPE_TWIRE) // This is a bridge query response - for now, only send to the wire and only if it came from the wire
	{
	
		int attempts, written;
		struct timespec now;

		written = -1;
		attempts = 0;
		
		dump_udp_pkt_aun(len - 8, 2, &w, srcnet, srcstn, dstnet, dststn);

		
		clock_gettime(CLOCK_MONOTONIC, &now);
		
		if ( ( ((int64_t) (now.tv_sec - network[d].last_tx_time.tv_sec) * 1000000000UL) + 
			((now.tv_sec == network[d].last_tx_time.tv_sec) ? (now.tv_nsec - network[d].last_tx_time.tv_nsec) : (1000000000UL - network[d].last_tx_time.tv_nsec) + now.tv_sec)
		) < 500000 ) // If less than 500us since last transmission to this host, delay.
		{
			//usleep(1000); // 1ms Inserted 25.07.21 to see if this cures the bulk transmission problem - maybe the server is not quite ready for BeebEm's speedy traffic?
			// 26.07.21 it wasn't. The problem was elsewhere.
		}

		// Reset last tx time for comparison next time
		clock_gettime(CLOCK_MONOTONIC, &(network[d].last_tx_time));
		while (attempts++ < 3 && written < 0)
			written = write(econet_fd, &w, len+4);
			
		if (written < 0)
		{
			int err;
			err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
			fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - %s (%02x)\n", dstnet, dststn, srcnet, srcstn, econet_strtxerr(err), err);	
		}
		if (written < (len+4) && written >= 0)
			fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - only %d of %d bytes written\n", dstnet, dststn, srcnet, srcstn, written, (len+4));	

		return written;
	}

*/

	dir = 0;

	if (network[d].type & ECONET_HOSTTYPE_TLOCAL)
		dir = 3;
 	else if (network[s].type & ECONET_HOSTTYPE_TLOCAL)
		dir = 2;
	else if (network[d].type & ECONET_HOSTTYPE_TWIRE) dir |= 1;

	if (p->p.ptype == ECONET_AUN_BCAST)
		dststn = dstnet = 0xff;

	w.p.ctrl |= 0x80;
	
	if (w.p.aun_ttype != ECONET_AUN_ACK) // Don't dump acks...
		dump_udp_pkt_aun(len - 8, dir, &w, srcnet, srcstn, dstnet, dststn);

	result = -1;

	if ( 
	     	((network[s].type & ECONET_HOSTTYPE_TAUN) == 0)  ||   // Source must be AUN
		((w.p.aun_ttype != ECONET_AUN_BCAST) && ((network[d].type & ECONET_HOSTTYPE_TAUN) == 0) ) // Destination must be AUN, or it must be a broadcast
	     ) 
	{
		fprintf (stderr, "ERROR: to %3d.%3d (type = %02x) from %3d.%3d (type = %02x) - Attempt to send AUN where one or other not AUN. Type %d\n", dstnet, dststn, network[d].type, srcnet, srcstn, network[s].type, w.p.aun_ttype);
		result = -1;
	}
	else
	{
		if (network[d].type == ECONET_HOSTTYPE_DIS_AUN)
		{

			struct pollfd ack;
			short acknowledged = 0;
			short count = 0;

			while (count < 8 && !acknowledged)
			{
				n.sin_family = AF_INET;
				n.sin_port = htons(network[d].port);
				n.sin_addr = network[d].s_addr;
			
				p->p.ctrl &= 0x7f; // Strip high bit from control - apparently that happens on UDP

				if (w.p.aun_ttype != ECONET_AUN_BCAST) // Need to work on sending broadcasts on AUN
				{
					if (w.p.aun_ttype == ECONET_AUN_IMMREP)
						p->p.seq = network[d].last_imm_seq_sent; // Override the sequence number from the kernel to match what was last sent to this host 

					result = sendto(network[s].listensocket, p, len, MSG_DONTWAIT, (struct sockaddr *)&n, sizeof(n));
				}

				// Wait for Ack here if it was a data packet
	
				if (w.p.aun_ttype == ECONET_AUN_DATA)
				{
				//	unsigned short ack_counter = 0;

						ack.fd = network[s].listensocket;
						ack.events = POLLIN;
						
						if ((poll(&ack, 1, ECONET_AUN_ACK_WAIT_TIME)) && (ack.revents & POLLIN))
						{
							struct __econet_packet_udp data;
	
							read(network[s].listensocket, &data, 100);
								
							if (data.p.ptype == ECONET_AUN_ACK && data.p.seq == w.p.seq)
								acknowledged = 1;
						}
				}
				else if (w.p.aun_ttype == ECONET_AUN_IMM && spoof_immediate == 0) // No immediate spoofing, so we might get immediates off the wire in userspace. In which case, wait to see if we get a response and put it back on the wire
				{

					ack.fd = network[s].listensocket;
					ack.events = POLLIN;

					if ((poll(&ack, 1, 250)) && (ack.revents & POLLIN))
					{
						struct __econet_packet_udp data;
						int len, attempts, written;

						len = read(network[s].listensocket, &data, 100);
			
						if (data.p.ptype == ECONET_AUN_IMMREP) // && data.p.seq == w.p.seq) At the moment, the sequence number coming back from other bridges on immedaite reply will not match. Need to fix that.
						{
							struct __econet_packet_aun ir;

							ir.p.dststn = srcstn; // Because we are replying
							ir.p.dstnet = srcnet;
							ir.p.srcstn = dststn;
							ir.p.srcnet = dstnet;
							ir.p.aun_ttype = ECONET_AUN_IMMREP;
							ir.p.port = data.p.port;
							ir.p.ctrl = data.p.ctrl | 0x80;
							ir.p.padding = 0;
							ir.p.seq = data.p.seq;
							memcpy(&(ir.p.data), data.p.data, len-8);
							
							attempts = 0;

							written = -1;

							dump_udp_pkt_aun(len - 8, dir, &ir, dstnet, dststn, srcnet, srcstn);
							while ((attempts < 3) && (written < 0))
							{
								written = write(econet_fd, &ir, 12 + (len-8));
								attempts++;	
							}	

							if (written < 0)
							{
								int err;
								err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
								fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - %s (%02x) whilst writing immediate reply\n", srcnet, srcstn, dstnet, dststn, econet_strtxerr(err), err);	
							}
							if (written < (len+4) && written >= 0)
								fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - only %d of %d bytes written whilst writing immediate reply\n", srcnet, srcstn, dstnet, dststn, written, (len + 4));	

							acknowledged = 1;
						}
					}

				}

				else	acknowledged = 1; // Fake this to get out of the loop

				count++;

			}

	
			if (!acknowledged)
			{
				fprintf(stderr, "ERROR: to %3d.%3d from %3d.%3d - No AUN acknowledment received\n", dstnet, dststn, srcnet, srcstn);
				result = 0;
			}
			else
				result = len;
		
				
		}
		else // Wire or local
		{

			int written;

			if (network[d].type == ECONET_HOSTTYPE_LOCAL_AUN || w.p.aun_ttype == ECONET_AUN_BCAST)
			{
				econet_handle_local_aun(&w, len+4);
				result =  len;
			}

			if (
				(network[d].type == ECONET_HOSTTYPE_WIRE_AUN || (w.p.aun_ttype == ECONET_AUN_BCAST && srcnet == 0)) && // Destination is wire (or it's a broadcast from something on our network number - we don't relay broadcasts from other networks, so as to avoid potential storms, and it's not right anyway)
				((network[s].type & ECONET_HOSTTYPE_TWIRE) == 0) // Source isn't wire
			)
			{
				int attempts;

				written = -1;
				attempts = 0;
				
				while (attempts++ < 3 && written < 0)
					written = write(econet_fd, &w, len+4);
					
				if (written < 0)
				{
					int err;
					err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
					fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - %s (%02x)\n", dstnet, dststn, srcnet, srcstn, econet_strtxerr(err), err);	
				}
				else if (written < (len+4) && written >= 0)
					fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - only %d of %d bytes written\n", dstnet, dststn, srcnet, srcstn, written, (len+4));	
				else
				{
					if (w.p.aun_ttype == ECONET_AUN_IMM) // Update last immediate sequence
						network[d].last_imm_seq_sent = w.p.seq;

				}
				result = (written < 5) ? 0 : written - 4; // Adjust for the fact that we add 4 bytes of addressing on the front of the packet so it knows where an AUN packet is actually going...
			}
		}
	}

	return result;


}

int main(int argc, char **argv)
{

	int s;
	int opt;
	int dump_station_table = 0;
	int new_start_fd;

	struct __econet_packet_aun rx;

	memset(&network, 0, sizeof(network));
	memset(&econet_ptr, 0xff, sizeof(econet_ptr));
	memset(&fd_ptr, 0xff, sizeof(fd_ptr));

	seq = 0x46; /* Random number */

	while ((opt = getopt(argc, argv, "bc:dfilqsh")) != -1)
	{
		switch (opt) {
			case 'b': dumpmode_brief = 1; break;
			case 'c':
				strcpy (cfgpath, optarg);
				break;
			case 'd':
				pkt_debug = 1;
				break;
			case 'f': fs_quiet = 1; break;
			case 'i': spoof_immediate = 0; break;
			case 'l': wire_enabled = 0; break;
			case 'q':
				bridge_query = 0;
				break;
			case 's': dump_station_table = 1; break;
			case '7': fs_sevenbitbodge = 0; break;
			case 'h':	
				fprintf(stderr, " \n\
Copyright (c) 2021 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
Usage: %s [options] \n\
Options:\n\
\n\
\t-b\tDo brief packet dumps\n\
\t-c\t<config path>\n\
\t-d\tTurn on packet debug (you won't see much without!)\n\
\t-f\tSilence fileserver log output\n\
\t-i\tDon't spoof immediate responses in-kernel (experimental\n\
\t-l\tLocal only - do not connect to kernel module (uses /dev/null instead)\n\
\t-q\tDisable bridge query responses (DISABLED IN CODE)\n\
\t-s\tDump station table on startup\n\
\t-7\tDisable fileserver 7 bit bodge\n\
\n\
\
", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	ECONET_INIT_STATIONS(econet_stations);
	ECONET_SET_STATION(econet_stations, 255, 255); // Put broadcasts into the AUN pool

	econet_readconfig();

	if (dump_station_table)
	{
		int s, n, p;

		fprintf (stderr, "%3s %3s %5s %5s %4s %-30s %-5s SERVER\n", "NET", "STN", "FD", "WHERE", "TYPE", "HOST", "PORT#");

		if (localnet)
			fprintf (stderr, "%3d                      LOCAL NETWORK\n", localnet);

		if (nativebridgenet)
			fprintf (stderr, "%3d                      DEFAULT FARSIDE BRIDGE NETWORK\n", nativebridgenet);

		for (n = 0; n < 256; n++)
		{
			for (s = 0; s < 256; s++)
			{
				char buffer[6];

				p = econet_ptr[n][s];
				if (p != -1) // Real entry
				{
					if (network[p].listensocket >= 0)
						snprintf(buffer, 6, "%5d", network[p].listensocket);
					else	snprintf(buffer, 6, "%5s", "     ");

					fprintf (stderr, "%3d %3d %5s %-5s %-4s %-30s %5d %c %c %c %s%s%s%s%s\n",
						network[p].network,
						network[p].station,
						buffer,
						(network[p].type & ECONET_HOSTTYPE_TDIS) ? "Dist." :
							(network[p].type & ECONET_HOSTTYPE_TWIRE) ? "Wire" : "Local",
						(network[p].type & ECONET_HOSTTYPE_TAUN ? "AUN" : "RAW"),
						(network[p].type & ECONET_HOSTTYPE_TDIS) ? network[p].hostname : "",
						network[p].port,
						((network[p].servertype & ECONET_SERVER_FILE) ? 'F' : ' '),
						((network[p].servertype & ECONET_SERVER_PRINT) ? 'P' : ' '),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? 'S' : ' '),
						((network[p].servertype & ECONET_SERVER_FILE) ? network[p].fs_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_FILE) ? " " : ""),
						((network[p].servertype & ECONET_SERVER_PRINT) ? network[p].print_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_PRINT) ? " " : ""),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? network[p].socket_serverparam : "")
					);
				}
			}
		}
			
		if (numtrunks > 0)
		{
			fprintf (stderr, "\n\nTRUNK DEFINITIONS\n");
			for (n = 0; n < 256; n++)
			{
				if (trunks[n].listensocket >= 0) // Valid entry
				{
					struct __fw_entry *e;

					fprintf (stderr, "\n%3d listening on port %5d, carrying network(s) %3d - %3d, via %s:%d\n", n, trunks[n].listenport, trunks[n].dst_start, trunks[n].dst_end, trunks[n].hostname, trunks[n].port);
					for (s = 0; s < 256; s++)
						if (trunks[n].xlate_src[s] != 0) fprintf (stderr, "    XLATE (net)  from %3d local to %3d remote\n", s, trunks[n].xlate_src[s]);

					s = 0;
					if ((e = trunks[n].head) != NULL) // There are firewall entries
					{
						while (e && (s < 10))
						{
							fprintf(stderr, "\n    FWALL %-6s from %3d.%3d   to %3d.%3d", (e->action == FW_ACCEPT ? "Accept" : "Drop"), e->srcnet, e->srcstn, e->dstnet, e->dststn);
							e = e->next;
							s++;
						}
						fprintf (stderr, "\n");
					}
					
				}

			}

			fprintf (stderr, "\n");

		}

	}

	// If in bridge query mode, we need to enable station localnet.0 so that the kernel module will deal with it
	// Otherwise our bridge query responses won't work

	if (bridge_query && localnet)
		ECONET_SET_STATION(econet_stations, nativebridgenet, 0);

	/* The open() call will do an econet_reset() in the kernel */
	if (wire_enabled)
		econet_fd = open(DEVICE_PATH, O_RDWR);
	else	econet_fd = open("/dev/null", O_RDWR);

	if (econet_fd < 0)
	{
		printf("Unable to open econet device. You may need to be root?\n");
		exit (EXIT_FAILURE);
	}

	ioctl(econet_fd, ECONETGPIO_IOC_SET_STATIONS, &econet_stations);
	if (spoof_immediate)
		ioctl(econet_fd, ECONETGPIO_IOC_IMMSPOOF, 1);
	else	ioctl(econet_fd, ECONETGPIO_IOC_IMMSPOOF, 0);
	
	pset[pmax].fd = econet_fd;

	if (pkt_debug)
		fprintf(stderr, "AUN Bridging mode enabled.\n\n");

	for (s = 0; s <= pmax; s++)
		pset[s].events = POLLIN;

	/* Wait for traffic */

	while (poll((struct pollfd *)&pset, pmax+1, -1))
	{
	
		/* Check Econet wire first */
		if (pset[pmax].revents & POLLIN)
		{

			// Collect the packet
			s = read(econet_fd, &rx, ECONET_MAX_PACKET_SIZE);

			if (s > 0) // Ding dong, traffic arriving off the wire 
			{
				if (s < 12)
					fprintf(stderr, "Runt packet length %d received off Econet wire\n", s);
	
				rx.p.seq = (network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].seq += 4);
				if (rx.p.aun_ttype == ECONET_AUN_IMMREP)
					rx.p.seq = network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].last_imm_seq_sent;
				// Fudge the AUN type on port 0 ctrl 0x85, which is done as some sort of weird special 4 way handshake with 4 data bytes on the Scout - done as "data" and the kernel module works out that the first 4 bytes in the packet go on the scout and the rest go in the 3rd packet in the 4-way
				if (rx.p.aun_ttype == ECONET_AUN_IMM && rx.p.ctrl == 0x85)
					rx.p.aun_ttype = ECONET_AUN_DATA;

				aun_send((struct __econet_packet_udp *)&(rx.raw[4]), s-4, rx.p.srcnet, rx.p.srcstn, rx.p.dstnet, rx.p.dststn); // Deals with sending to local hosts
			}
		}

		/* See if anything turned up on UDP */

		s = start_fd;
		new_start_fd = -1; // -1 rogue - means we haven't found a receipt from UDP from anywhere yet, so when we do, we'll update the start_fd to start at the next one next time round
		
		for (s = 0; s < pmax; s++) /* not the last fd - which is the econet hardware */
		{
			int realfd;
	
			realfd = (s + start_fd) % pmax; // Offset our start to "start_fd"

			if (pset[realfd].revents & POLLIN) 
			{
				/* Read packet off UDP here */
				int  r;
				short srcnet, srcstn, dstnet, dststn;

				int count;
				unsigned short from_found, to_found;

				if (new_start_fd == -1)
				{
					new_start_fd = ((realfd + 1) % pmax); // Update start_fd to start at next FD next time, clamped to within pmax, so that the first station we received from is last in line next time round
					//fprintf (stderr, "Updated start_fd to %d\n", new_start_fd);
				}

				r = udp_receive(pset[realfd].fd, (void *) &udp_pkt, sizeof(udp_pkt), (struct sockaddr * restrict) &src_address);

				if (r< 0) continue; // Debut produced in udp_receive

				/* Look up where it came from */
		
				count = 0;

				to_found = 0xffff;
				from_found = 0xffff;

				while ((from_found == 0xffff) && (count < stations))
				{

					if ( (network[count].s_addr.s_addr == src_address.sin_addr.s_addr) && 	
					     (network[count].port == ntohs(src_address.sin_port))   // This will not work if you have more than one BeebEm host on the same machine
					)
						from_found = count;
					count++;
				}

				/* Now where did was it going /to/ ? We can find that by the listening socket number */
	
				to_found = fd_ptr[pset[realfd].fd];

				if ((from_found != 0xffff) && (to_found != 0xffff))
				{
					srcnet = network[from_found].network;
					srcstn = network[from_found].station;
				
					dstnet = network[to_found].network;
					dststn = network[to_found].station;

					if ((network[from_found].type == ECONET_HOSTTYPE_DIS_AUN)
					   &&     ( (network[to_found].type == ECONET_HOSTTYPE_WIRE_AUN) || network[to_found].type == ECONET_HOSTTYPE_LOCAL_AUN))
					   // AUN packet destined for a wire or local host which has an AUN type listener
					{
						if (!((udp_pkt.p.ptype == ECONET_AUN_ACK) || 
					   		(udp_pkt.p.ptype == ECONET_AUN_NAK) ) ) // Ignore those sorts of packets - we don't care
						{
							//int written;

							if ((udp_pkt.p.ptype == ECONET_AUN_DATA) && (network[from_found].type == ECONET_HOSTTYPE_DIS_AUN)) // Only bother sending ACKs to UDP stations - We tried only acking after transmission on to the wire and it took too long
							{
								usleep(ECONET_AUN_ACK_DELAY); // sleep - may help to slow things down a bit and kill off the transmission problems at other end of a bridge
								aun_acknowledge (&udp_pkt, srcnet, srcstn, dstnet, dststn, ECONET_AUN_ACK);
							}

							if (udp_pkt.p.ptype != ECONET_AUN_DATA || udp_pkt.p.seq > network[from_found].last_seq_ack) // If this packet is not a duplicate - i.e., it wasn't the last one we acknowledged to this host, or it isn't a data packet
							{
								/* written = */ aun_send(&udp_pkt, r, srcnet, srcstn, dstnet, dststn);
								network[from_found].last_seq_ack = udp_pkt.p.seq;
							}


						}

					}
					else 
					{
						fprintf (stderr, "UDP from FD %d. Known src/dst but can't bridge - to/from index %d, %d; to_type = 0x%02x, from_type = 0x%02x\n", pset[realfd].fd, to_found, from_found, network[to_found].type, network[from_found].type);
					}
				}
				else	fprintf (stderr, "UDP packet received on FD %d; From%s found, To%s found (pointer = %08x)\n", pset[realfd].fd, ((from_found != 0xffff) ? "" : " not"), ((to_found != 0xffff) ? "" : " not"), to_found);
			}
	
		}

		if (new_start_fd != -1)
			start_fd = new_start_fd;

		// Reset our poll structure
		for (s = 0; s <= pmax; s++)
			pset[s].events = POLLIN;

		// Fileserver garbage collection

		for (s = 0; s < stations; s++)
			if (network[s].servertype & ECONET_SERVER_FILE) 
			{
//				fprintf(stderr, "   FS: Garbage collect on server %d\n", network[s].fileserver_index);
				//fs_garbage_collect(network[s].fileserver_index);
			}
	}
}

