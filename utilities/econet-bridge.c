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
#include <ctype.h>
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
extern int sks_initialize(unsigned char, unsigned char, char *);
extern void handle_fs_traffic(int, unsigned char, unsigned char, unsigned char, unsigned char *, unsigned int);
extern void sks_handle_traffic(int, unsigned char, unsigned char, unsigned char, unsigned char *, unsigned int);
extern void handle_fs_bulk_traffic(int, unsigned char, unsigned char, unsigned char, unsigned char, unsigned char *, unsigned int);
extern void fs_garbage_collect(int);
extern void fs_eject_station(unsigned char, unsigned char); // Used to get rid of an old dynamic station
extern void fs_dequeue();
extern short fs_dequeuable();
extern void sks_poll(int);
short aun_wait (int, int, unsigned char, unsigned long, short, struct __econet_packet_aun **);
extern unsigned short fs_quiet, fs_noisy;
extern short fs_sevenbitbodge;

#define ECONET_LEARNED_HOST_IDLE_TIMEOUT 3600 // 1 hour

#define ECONET_HOSTTYPE_TDIS 0x02
#define ECONET_HOSTTYPE_TWIRE 0x04
#define ECONET_HOSTTYPE_TLOCAL 0x08
#define ECONET_HOSTTYPE_TAUN 0x01

#define ECONET_SERVER_FILE 0x01
#define ECONET_SERVER_PRINT 0x02
#define ECONET_SERVER_SOCKET 0x04

// AUN Ack wait time in ms - a remote bridge will only Ack a packet going to the wire if it successfully transmits onto the wire, so this may need to be a while
#define ECONET_AUN_ACK_WAIT_TIME 200
// Delay in us before sending AUN ACK. Helps to smooth traffic flow to remote bridges - otherwise they tend to get their underwear tangled on transmit. Doesn't need to be very long.
// Note this value is MICROseconds, the wait time above is MILLIseconds
#define ECONET_AUN_ACK_DELAY 250 

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
int wired_eject = 1; // When set, and a dynamic address is allocated to an unknown AUN station, this will cause the bridge to spoof a '*bye' equivalent to fileservers it has learned about on the wired network
short learned_net = -1;

unsigned char last_net = 0, last_stn = 0;

int start_fd = 0; // Which index number do we start looking for UDP traffic from after poll returns? We do this cyclicly so we give all stations an even chance

unsigned short numtrunks;

char cfgpath[512] = "/etc/econet-gpio/econet.cfg";

char *beebmem;

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
	int fileserver_index, sks_index;
	struct timespec last_wire_tx;
	unsigned char is_dynamic; // 0 = ordinary fixed host; 1 = host which can be assigned to unknown incoming traffic
	unsigned char is_wired_fs; // 0 = not a fileserver; 1 = we have seen port &99 traffic to this host and it is on the wire, so we think it's a fileserver. This is used to spoof *bye equivalents when a station number of dynamically allocated to an unknown AUN source, so that the previous user of the same address's login cannot be re-used
	unsigned long last_transaction;
};

struct econet_hosts network[65536]; // Hosts we know about / listen for / bridge for
short econet_ptr[256][256]; /* [net][stn] pointer into network[] array. */
short fd_ptr[65536]; /* Index is a file descriptor - yields index into network[] */

struct __econet_packet_aun_cache {
	struct __econet_packet_aun *p;
	struct __econet_packet_aun_cache *next;
	unsigned int size; // Size of p, less its 4 byte header.
	struct timeval tstamp;
};

struct __econet_packet_aun_cache *cache_head, *cache_tail;

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
	regex_t r_comment, r_entry_distant, r_entry_local, r_entry_server, r_entry_wire, r_entry_trunk, r_entry_xlate, r_entry_fw, r_entry_learn;
	regmatch_t matches[9];
	int i, count;
	short j, k;
	int networkp; // Pointer into network[] array whilst reading config. 
	
	char *end;

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

        if (regcomp(&r_entry_wire, "^\\s*([Ww])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5}|AUTO)\\s*$", REG_EXTENDED) != 0)
        {
                fprintf(stderr, "Unable to compile full wire station regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_learn, "^\\s*([Ll])\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED) != 0)
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

		// Strip off any trailing whitespace - Thank you @sweh
		end = linebuf + strlen(linebuf) + 1;
		while (end >= linebuf && isspace((unsigned char) *end))
			end--;

		end[1] = '\0';

		// Skip if empty line
		if (strlen(linebuf) == 0)
			continue;

		// Blank off the server parameters

		strcpy(network[networkp].fs_serverparam, "");
		strcpy(network[networkp].print_serverparam, "");
		strcpy(network[networkp].socket_serverparam, "");
		network[networkp].is_dynamic = 0;
		network[networkp].last_transaction = 0;
		network[networkp].is_wired_fs = 0;

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
			{
				if (datastring[strlen(datastring)-1] == '/') // Strip trailing slash
					datastring[strlen(datastring)-1] = '\0';
				strcpy(network[(entry == -1) ? networkp : entry].fs_serverparam, datastring);
			}
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

			if (servertype & ECONET_SERVER_SOCKET)
			{
				int f;

				f = sks_initialize(net, stn, (char *) &datastring);
				if (f >= 0)
					network[(entry == -1 ? networkp : entry)].sks_index = f;
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
						if (!strcmp(tmp,"AUTO"))
						{
							if (network[networkp].network > 127)
							{
								fprintf(stderr, "Network must be under 128 for AUTO to work: %s\n",linebuf);
								exit(EXIT_FAILURE);
							}
                                                	network[networkp].port = 10000+network[networkp].network*256+network[networkp].station;
						}
                                                else
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
		else if (regexec(&r_entry_learn, linebuf, 3, matches, 0) == 0) // Learn. Unknown sources will get put into this network temporarily, and garbage-collected out when they have been idle for a while
		{

                        char	tmp[300];
			int	ptr;

			/* Find our match */
			ptr = 0;
			while (ptr < (matches[2].rm_eo - matches[2].rm_so))
			{
				tmp[ptr] = linebuf[ptr + matches[2].rm_so];	
				ptr++;
			}
			tmp[ptr] = 0x00;
			
			learned_net = atoi(tmp);

			if (learned_net == 0)
			{
				fprintf (stderr, "Cannot set dynamic network number to 0 because it is used on the Econet wire.\n");
				exit(EXIT_FAILURE);
			}

			for (count = 1; count < 255; count++) // Put the entire network's worth of hosts into network[] and flag as dynamic	
			{
				econet_ptr[learned_net][count] = networkp;

				network[networkp].network = learned_net;
				network[networkp].station = count;
				network[networkp].type = ECONET_HOSTTYPE_DIS_AUN;
				network[networkp].pind = 0;
				network[networkp].servertype = 0;
				network[networkp].last_seq_ack = 0; // Tracks the last AUN data packet we acknowledged from this host.
				network[networkp].listensocket = -2; // Distant - no socket
				ECONET_SET_STATION(econet_stations, network[networkp].network, network[networkp].station);

				// Include the network in our list
				ip_networklist[network[networkp].network] = 1;

			
				if (nativebridgenet == 0 && network[networkp].network != 0)
					nativebridgenet = network[networkp].network;

				network[networkp].is_dynamic = 1;
				networkp++;
			}


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

short fs_get_server_id(unsigned char net, unsigned char stn)
{
	short result = -1;

	if (network[econet_ptr[net][stn]].fileserver_index != -1)
		result = network[econet_ptr[net][stn]].fileserver_index;

	return result;
}

// Returns local/wire machine sequence number and increments it
#ifdef ECONET_64BIT
unsigned int get_local_seq(unsigned char net, unsigned char stn)
#else
unsigned long get_local_seq(unsigned char net, unsigned char stn)
#endif
{

	return (network[econet_ptr[net][stn]].seq += 4);

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
		else if (a->p.ctrl == 0x81) // Memory Peek
		{

			if (beebmem) // If we managed to load it...
			{
				unsigned int start, end;

				start = ((a->p.data[0]) + (256 * (a->p.data[1])));
				end = ((a->p.data[4]) + (256 * (a->p.data[5])));

				sprintf (beebmem + 0x7c5f, "%d", a->p.dststn);

				a->p.aun_ttype = ECONET_AUN_IMMREP;
				a->p.seq = (network[d_ptr].seq += 4);

				memcpy(&(a->p.data), (beebmem + start), end-start);

				aun_send ((struct __econet_packet_udp *)&(a->p.aun_ttype), 8 + (end - start), a->p.dstnet, a->p.dststn, a->p.srcnet, a->p.srcstn);

			}
		}
	}
	else if (a->p.aun_ttype == ECONET_AUN_BCAST) // Broadcast - See if we need to do a bridge query reply
	{
		//fprintf (stderr, "Bridge query %s, port %02x, BRIDGE check %s, localnet %s\n", (bridge_query ? "on" : "off"), a->p.port, (!strncmp("BRIDGE", (const char *) a->p.data, 6) ? "match" : "not matched"), localnet ? "set" : "not set");
		if (bridge_query && (a->p.port == 0x9c) && (!strncmp("BRIDGE", (const char *) a->p.data, 6)) && localnet && (network[econet_ptr[a->p.srcnet][a->p.srcstn]].type & ECONET_HOSTTYPE_TWIRE))
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
				reply.p.seq = (network[d_ptr].seq += 4);

				// The control low bit alternation is to avoid duplicated packets. Need to implement a check... TODO.

				switch (a->p.ctrl)
				{
					case 0x83: // Fall through
					case 0x82: // Print job start
					{
						reply.p.data[0] = 0x2a;
						// 20210815 Commented
						//usleep(50000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
						aun_send (&reply, 9, network[d_ptr].network, network[d_ptr].station, network[s_ptr].network, network[s_ptr].station); // We're replying, so we pick up the destination of the original packet as source.
					}
					break;
					case 0x80: // Fall through
					case 0x81: // Print data
					{
						fwrite(&(a->p.data), packlen-12, 1, printjobs[count].spoolfile);
						reply.p.data[0] = a->p.data[0];	
						// 20210815 Commented
						//usleep(100000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
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
						// 20210815 Commented
						//usleep(100000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
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
		else if ((a->p.port == 0xdf) && (network[d_ptr].servertype & ECONET_SERVER_SOCKET) && (network[d_ptr].sks_index >= 0))
			sks_handle_traffic(network[d_ptr].sks_index, a->p.srcnet, a->p.srcstn, a->p.ctrl, a->p.data, packlen-12);
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

	if (w.p.aun_ttype == ECONET_AUN_BCAST)
		w.p.dstnet = w.p.dststn = 0xff;
		
	d = econet_ptr[dstnet][dststn];
	s = econet_ptr[srcnet][srcstn];

	network[d].last_transaction = time(NULL);

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

/*
			if (last_net == dstnet && last_stn == dststn)
				usleep(2000); // There seems to be some sort of reception problem with BeebEm with packets in quick succession
*/

			last_net = dstnet; last_stn = dststn;

			while (count < 5 && !acknowledged)
			{
				struct __econet_packet_aun_cache *q, *q_parent;
				short found = 0;

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

				// Clear any entries from this station out of the cache - gets rid of earlier re-tx's

				q_parent = NULL;
				q = cache_head;

				while (q && !found)
				{
					if ((q->p->p.srcnet == dstnet) && (q->p->p.srcstn == dststn)) // If the station we just transmitted to has a packet in the cache, splice it out
					{
						found = 1;
						if (q != cache_head)
						{
							q_parent->next = q->next;
					
						}
						else	cache_head = q->next; // Works even if p->next is null (only one packet on queue)
						free (q->p); free(q); // free both the packet inside the queue entry, and the queue entry
					}
					else
					{
						q_parent = q;
						q = q_parent->next;
					}
				}

				// Wait for Ack here if it was a data packet
	
				if (w.p.aun_ttype == ECONET_AUN_DATA)
				{
					struct __econet_packet_aun *ack;

					ack = malloc(ECONET_MAX_PACKET_SIZE + 4);
					
					if (ack && aun_wait(d, s, ECONET_AUN_ACK, w.p.seq, ECONET_AUN_ACK_WAIT_TIME, &ack)) // Matching Ack received - everything else received went in the cache
						acknowledged = 1;
		
					free (ack);


/*
						ack.fd = network[s].listensocket;
						ack.events = POLLIN;
						
						// This needs to store up packets received that aren't the ACK for later processing. TODO. And it needs to keep receiving until the ACK_WAIT_TIME and only abandon when that expires. Problem at present is that if another station sends a packet when we wanted an ack from some other station, we'll quietly drop that other packet and we'll miss the ACK from the one we wanted!
						if ((poll(&ack, 1, ECONET_AUN_ACK_WAIT_TIME)) && (ack.revents & POLLIN))
						{
							struct __econet_packet_udp data;
	
							read(network[s].listensocket, &data, 100);
								
							// This is bad. It needs to differentiate between senders! TODO
							// Maybe a generic receiver on a given socket with a timeout which returns if it sees an ACK from a particular host with a given sequence number, and otherwise stores everything up? (Or make it more generic so that it can look for an immediate reply with a given sequence number too?) Then have a routine after aun_send has finished which dumps those incoming packets where they are supposed to go? Maybe make the poll loop pull packets off that queue in preference to the network??
							if (data.p.ptype == ECONET_AUN_ACK && data.p.seq == w.p.seq)
								acknowledged = 1;
						}
*/

				}
				else if (w.p.aun_ttype == ECONET_AUN_IMM && spoof_immediate == 0) // No immediate spoofing, so we might get immediates off the wire in userspace. In which case, wait to see if we get a response and put it back on the wire
				{

					ack.fd = network[s].listensocket; // network[s] because we want to listen on the listener for the wire host that sent the immediate request
					ack.events = POLLIN;

					if ((poll(&ack, 1, 1000)) && (ack.revents & POLLIN)) // Too long. TODO. This long because of Mode 0 screen grabs
					{
						struct __econet_packet_udp data;
						int len, attempts, written;

						len = read(network[s].listensocket, &data, ECONET_MAX_PACKET_SIZE+4);
			
						// TODO: Likewise here, if we get some other packet we ought to store it up for later processing.
						if (data.p.ptype == ECONET_AUN_IMMREP) // && data.p.seq == w.p.seq) At the moment, the sequence number coming back from other bridges on immedaite reply will not match. Need to fix that.
						{
							struct __econet_packet_aun ir;
							int err;

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

							dump_udp_pkt_aun(len - 8, 1, &ir, dstnet, dststn, srcnet, srcstn);
							while ((attempts < 2) && (written < 0))
							{
								written = write(econet_fd, &ir, 12 + (len-8));
								err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
								attempts++;	
								if (written < 0 && (err == ECONET_TX_JAMMED || err == ECONET_TX_NOCLOCK || err == ECONET_TX_NOCOPY)) // Fatal errors
									break;
							}	

							if (written < 0)
							{
								int err;
								err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
								fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - %s (%02x) after %d attempts whilst writing immediate reply\n", srcnet, srcstn, dstnet, dststn, econet_strtxerr(err), err, attempts);	
							}
							if (written < (len+4) && written >= 0)
								fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - only %d of %d bytes written whilst writing immediate reply\n", srcnet, srcstn, dstnet, dststn, written, (len + 4));	

							acknowledged = 1;
						}
					}
					else	ioctl(econet_fd, ECONETGPIO_IOC_READMODE); // Force read mode on a timeout otherwise the kernel stops listening...

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

			if ((network[d].type & ECONET_HOSTTYPE_TWIRE) && (w.p.port == 0x99) && (!(network[d].is_wired_fs))) // Fileserver traffic on a wire station
			{
				network[d].is_wired_fs = 1;
				fprintf (stderr, "  DYN:%12s             Station %d.%d identified as wired fileserver\n", "", dstnet, dststn);
			}

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
				int attempts, err;

				written = -1;
				attempts = 0;
				
				while ((attempts < 5) && (written < 0))
				{
					written = write(econet_fd, &w, len+4);
					err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
					attempts++;	
					if (written < 0 && (err == ECONET_TX_JAMMED || err == ECONET_TX_NOCLOCK || err == ECONET_TX_NOCOPY)) // Fatal errors
						break;
					if (err == ECONET_TX_COLLISION)	usleep(network[d].station * 1000);
				}	

				if (written < 0)
					fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - %s (%02x) - after %d attempts\n", dstnet, dststn, srcnet, srcstn, econet_strtxerr(err), err, attempts);	
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

unsigned long timediffmsec(struct timeval *s, struct timeval *d)
{

	return (((d->tv_sec - s->tv_sec) * 1000) + ((d->tv_usec - s->tv_usec) / 1000));

}

// Map a sockaddr to a network[] entry - used to find source station of UDP packets
// Returns 0xffff if not founD

int econet_find_source_station (struct sockaddr_in *src_address)
{

	int from_found = 0xffff;
	int count = 0;

        while ((from_found == 0xffff) && (count < stations))
        {

		if ( (network[count].s_addr.s_addr == src_address->sin_addr.s_addr) &&
             		(network[count].port == ntohs(src_address->sin_port)) &&
             		(	network[count].is_dynamic == 0 ||
                		(network[count].last_transaction > (time(NULL) - ECONET_LEARNED_HOST_IDLE_TIMEOUT))
             		)
            	   )
  	          	from_found = count;

                 count++;
        }

	return from_found;
}


// Wait up to timeout ms for a packet from station network[sptr] to station network[dptr] matching AUN type aun_type with 
// sequence number seq. If it arrives, put the packet in *p and return 1. Otherwise set *p = NULL and return 0. Any other
// traffic arriving gets put on the packet cache for later processing.
// If returns 1, caller MUST free *p after use.
// dptr is where the packet we're looking for is going to, sptr is where it must have come from

short aun_wait (int sptr, int dptr, unsigned char aun_type, unsigned long seq, short timeout, struct __econet_packet_aun **p)
{

	struct timeval start, now;
	struct __econet_packet_udp in;
	struct pollfd pwait;
	struct sockaddr addr;

	short received = 0;
	unsigned long diff;
	

	if ((network[dptr].type & (ECONET_HOSTTYPE_TWIRE | ECONET_HOSTTYPE_TLOCAL)) == 0)
		return 0; // This function only works on WIRE type destinations (and LOCAL)

	gettimeofday(&start, 0);

	gettimeofday(&now, 0);

	diff = timediffmsec(&start, &now);

	*p = NULL; // Initialize

	while ((diff < timeout) && !received)
	{
		pwait.fd = network[dptr].listensocket;
		pwait.events = POLLIN;


		if (poll(&pwait, 1, (timeout - diff)) && (pwait.revents & POLLIN))
		{
			int r;
			int net_src;

			//r = read (network[dptr].listensocket, &in, ECONET_MAX_PACKET_SIZE + 4);
			r = udp_receive (network[dptr].listensocket, &in, ECONET_MAX_PACKET_SIZE + 4, &addr);

			if (r >= 0)
			{
				struct __econet_packet_aun *c;

				net_src = econet_find_source_station((struct sockaddr_in *) &addr);
	
				if (pkt_debug) fprintf (stderr, "CACHE: to %3d.%3d from %3d.%3d AUN type %02X, seq %08lX, len %04X received ", 
					network[dptr].network, network[dptr].station,
					(net_src == 0xff ? 0:network[net_src].network), 
					(net_src == 0xff ? 0:network[net_src].station), 
					in.p.ptype, in.p.seq, r);


/*
// Temp code - recognize what we want, ditch the rest

				if ((net_src = sptr) && (in.p.ptype == aun_type) && (in.p.seq == seq)) 
				{
					if (pkt_debug && fs_noisy) fprintf (stderr, "MATCHED");

					// Found the packet we want
					received = 1;
				}
				if (pkt_debug && fs_noisy) fprintf (stderr, "\n");
*/

				if (net_src != 0xffff) // We found the source network entry
				{
	
					c = malloc (r + 4);
	
					if (!c) return 0; // Cannot malloc - barf.
	
					c->p.dststn = network[dptr].station;
					c->p.dstnet = network[dptr].network;
					c->p.srcstn = network[net_src].station;
					c->p.srcnet = network[net_src].network;
	
					memcpy(&(c->p.aun_ttype), &in, r);
	
					if ((net_src == sptr) && (in.p.ptype == aun_type) && (in.p.seq == seq)) 
					{
						if (pkt_debug) fprintf (stderr, "MATCHED");
	
						// Found the packet we want
						*p = c;
						received = 1;
					}
					else if (net_src != sptr && (in.p.ptype == ECONET_AUN_IMM || in.p.ptype == ECONET_AUN_IMMREP || in.p.ptype == ECONET_AUN_DATA)) // Put this one on the cache if it's not from the source we want (because if it's the source we were looking for, but not the packet we were looking for, it's probably a re-tx we want to jettison) (We only bother with three types of packet... the rest we can discard)
					{
						struct __econet_packet_aun_cache *entry;
	
						// Dear purists, you will not like the next two lines. They acknowledge a data packet before transmission to local or wire.
						// Since the kernel module collapses a 4-way handshake to 2-way in the other direction, so that a sending wire station
						// thinks its packet has got to its destination before the AUN packet hits the UDP stack, still less before it has been
						// acknowledged, then in *this* direction it is hardly much different to acknoweldge an incoming UDP AUN packet before
						// it has gone where it is going... The former is necessary in order to collect a whole packet before an AUN datagram
						// could even be sent, and is thus a necesary compromise for this to work at all. The latter is simply a comparable and
						// consistent compromise in the opposite direction!

						if (in.p.ptype == ECONET_AUN_DATA)
							aun_acknowledge(&in, c->p.srcnet, c->p.srcstn, c->p.dstnet, c->p.dststn, ECONET_AUN_ACK);

						entry = malloc (sizeof(struct __econet_packet_aun_cache));
	
						if (!entry)
						{
							free(c);
							return 0; 
						}
	
						entry->p = c;
						entry->next = NULL;
						entry->size = r; // Size of p less 4 bytes for the AUN header - i.e. the value we pass to aun_send to send this packet
						gettimeofday(&(entry->tstamp), 0);
	
						if (pkt_debug) fprintf (stderr, "CACHED ");
	
						if (!cache_head) // Cache is empty
						{
							if (pkt_debug) fprintf (stderr, "as first cache entry");
							cache_head = entry;
							cache_tail = entry;
						}
						else
						{
							// We only want the last packet from each source station in the cache because they retransmit stuff, so have a look and see if we can find it. If we find it, replace the existing entry - doing some free()ing along the way

							struct __econet_packet_aun_cache *q;
							short found = 0;

							q = cache_head;

							while (q && !found)
							{
								if ((q->p->p.srcnet == entry->p->p.srcnet) && (q->p->p.srcstn == entry->p->p.srcstn))
								{
									if (pkt_debug) fprintf (stderr, "by replacing packet cache entry at %p", q);
									// Free existing packet
									free (q->p);
									q->size = entry->size;
									q->p = entry->p;
									found = 1;
								}
								q = q->next;
							}

							if (!q && !found) // Source not found in cache, put it on the tail
							{
								if (pkt_debug) fprintf (stderr, "on the cache tail");
								cache_tail->next = entry;
								cache_tail = entry;
							}
						}
					}
					else if (pkt_debug) fprintf (stderr, "DISCARDED");

					if (pkt_debug) fprintf (stderr, "\n");
				}
				else if (pkt_debug) fprintf (stderr, "JETTISONED\n");
			}
			else
			{
				if (pkt_debug) fprintf (stderr, "CACHE: Network read error\n");
				return 0; // Read error
			}

		}	

		gettimeofday(&now, 0);

	        diff = timediffmsec(&start, &now);

	}

	if (!received)
		return 0;

	return 1;

}

int main(int argc, char **argv)
{

	int s;
	int opt;
	int dump_station_table = 0;
	short fs_bulk_traffic = 0;

	struct __econet_packet_aun rx;

	memset(&network, 0, sizeof(network));
	memset(&econet_ptr, 0xff, sizeof(econet_ptr));
	memset(&fd_ptr, 0xff, sizeof(fd_ptr));

	// Clear the packet cache

	cache_head = cache_tail = NULL;

	seq = 0x46; /* Random number */

	fs_sevenbitbodge = 1; // On by default

	while ((opt = getopt(argc, argv, "bc:dfilnqszh7")) != -1)
	{
		switch (opt) {
			case 'b': dumpmode_brief = 1; break;
			case 'c':
				strcpy (cfgpath, optarg);
				break;
			case 'd':
				pkt_debug = 1;
				break;
			case 'f': fs_quiet = 1; fs_noisy = 0; break;
			case 'i': spoof_immediate = 0; break;
			case 'l': wire_enabled = 0; break;
			case 'n': fs_noisy = 1; fs_quiet = 0; break;
			case 'q':
				bridge_query = 0;
				break;
			case 's': dump_station_table = 1; break;
			case 'z': wired_eject = 0; break;
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
\t-q\tDisable bridge query responses\n\
\t-s\tDump station table on startup\n\
\t-z\tDisable wired fileserver eject on dynamic allocation (see readme)\n\
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

		if (learned_net != -1)
			fprintf (stderr, "%3d                      DYNAMICALLY ALLOCATED STATION NETWORK\n", learned_net);

		if (wire_enabled)
			fprintf (stderr, "%5d                    MAXIMUM PACKET SIZE\n", ECONET_MAX_PACKET_SIZE);

		for (n = 0; n < 256; n++)
		{
			for (s = 0; s < 256; s++)
			{
				char buffer[6];

				p = econet_ptr[n][s];
				if (p != -1 && (network[p].is_dynamic == 0)) // Real entry exc. dynamic stations
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

	// Set up our fake BeebMem if available

	{

		FILE *f;

		beebmem = malloc(65536);
		
		if (beebmem && (f = fopen("BEEBMEM", "r")))
		{

			fread(beebmem, 32768, 1, f);

			fclose(f);

			// Leave a message on the Mode 7 screen

			memset(beebmem + 0x7c00, 0, 0x400);

			strcpy(beebmem + 0x7c00, "Raspberry Pi Econet Bridge");
			strcpy((beebmem + 0x7c50), "Econet station ");
			strcpy(beebmem + 0x7ca0, "Pi OS");
			strcpy(beebmem + 0x7cf0, "*");
			sprintf (beebmem + 0x7F20, "%c%cWhat do you think you're doing, Dave?", 129, 136);
			
		}
		else if (beebmem)
		{
			free(beebmem);
			beebmem = NULL;
		}
		
	}
	
	/* Wait for traffic */

	fs_bulk_traffic = fs_dequeuable();

	while (cache_head || fs_bulk_traffic || poll((struct pollfd *)&pset, pmax+(wire_enabled ? 1 : 0), -1)) // If there are packets in the cache, process them. If there's cache or bulk traffic, only poll for 10ms so that we pick up traffic quickly if it's there.
	{

		// If there is cached or fs_bulk traffic, do a poll anyway and see if there is anything to come - but make it snappy

		if (cache_head || fs_bulk_traffic)
			poll((struct pollfd *)&pset, pmax+(wire_enabled ? 1 : 0), 10);

		if (wire_enabled && pset[pmax].revents & POLLIN) // Let the wire take a back seat sometimes
		{

			int r;
			// Collect the packet
			r = read(econet_fd, &rx, ECONET_MAX_PACKET_SIZE);

			if (r > 0) // Ding dong, traffic arriving off the wire 
			{
				if (r < 12)
					fprintf(stderr, "Runt packet length %d received off Econet wire\n", r);

				rx.p.seq = (network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].seq += 4);
				if (rx.p.aun_ttype == ECONET_AUN_IMMREP)
					rx.p.seq = network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].last_imm_seq_sent;
				// Fudge the AUN type on port 0 ctrl 0x85, which is done as some sort of weird special 4 way handshake with 4 data bytes on the Scout - done as "data" and the kernel module works out that the first 4 bytes in the packet go on the scout and the rest go in the 3rd packet in the 4-way
				if (rx.p.aun_ttype == ECONET_AUN_IMM && rx.p.ctrl == 0x85)
					rx.p.aun_ttype = ECONET_AUN_DATA;

				network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].last_transaction = time(NULL);

				aun_send((struct __econet_packet_udp *)&(rx.raw[4]), r-4, rx.p.srcnet, rx.p.srcstn, rx.p.dstnet, rx.p.dststn); // Deals with sending to local hosts

			}
		}

		while (cache_head) // If packet in cache, deal with it
		{
			struct __econet_packet_aun_cache *p;
			struct timeval now;

			p = cache_head;

			cache_head = cache_head->next;

			gettimeofday(&now, 0);

			if (timediffmsec(&(p->tstamp), &now) <= 200) // If newer than 200ms
			{
				if (pkt_debug)	fprintf (stderr, "CACHE: to %3d.%3d from %3d.%3d packet type %02X length %04X RETRIEVED from cache\n", p->p->p.dstnet, p->p->p.dststn, p->p->p.srcnet, p->p->p.srcstn, p->p->p.aun_ttype, p->size);

				aun_send((struct __econet_packet_udp *)&(p->p->raw[4]), p->size, p->p->p.srcnet, p->p->p.srcstn, p->p->p.dstnet, p->p->p.dststn);
			}

			free(p->p); // Frees the cache structure entry
			free(p); // Frees the malloc on the packet

		}

		/* See if anything turned up on UDP */

		s = start_fd;
		
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

				r = udp_receive(pset[realfd].fd, (void *) &udp_pkt, sizeof(udp_pkt), (struct sockaddr * restrict) &src_address);

				if (r< 0) continue; // Debut produced in udp_receive

				/* Look up where it came from */
		
				count = 0;

				from_found = econet_find_source_station (&src_address); // 0xffff;

/*
				while ((from_found == 0xffff) && (count < stations))
				{

					if ( (network[count].s_addr.s_addr == src_address.sin_addr.s_addr) && 	
					     (network[count].port == ntohs(src_address.sin_port)) && 
						(network[count].is_dynamic == 0 || 
							(network[count].last_transaction > (time(NULL) - ECONET_LEARNED_HOST_IDLE_TIMEOUT))
						) 
					)
						from_found = count;
					count++;
				}
*/

				/* Now where did was it going /to/ ? We can find that by the listening socket number */
	
				to_found = fd_ptr[pset[realfd].fd];

				if ((from_found == 0xFFFF) && (learned_net != -1) & (to_found != 0xFFFF)) // See if we can dynamically allocate a station number to this unknown traffic source, since we know where the traffic going, and we have learning mode on, but we don't know where the traffic came *from* 
				{
					unsigned short stn_count;
					struct sockaddr_in *s;

					stn_count = 0; 
		
					s = &src_address;

/*
					fprintf (stderr, "Dynamic traffic from family %d, port %d, address %d.%d.%d.%d\n", 
						s->sin_family, ntohs(s->sin_port),
						(ntohl(s->sin_addr.s_addr) & 0xff000000) >> 24,	
						(ntohl(s->sin_addr.s_addr) & 0xff0000) >> 16,	
						(ntohl(s->sin_addr.s_addr) & 0xff00) >> 8,	
						(ntohl(s->sin_addr.s_addr) & 0xff)
					);
*/

					while (stn_count < stations && from_found == 0xFFFF)
					{
						if (network[stn_count].is_dynamic && (network[stn_count].last_transaction < (time(NULL) - ECONET_LEARNED_HOST_IDLE_TIMEOUT))) // Found a dynamic station which has idled out
						{

							struct __econet_packet_aun bye;
							int netcount;
							short attempts, written;

							memcpy(&(network[stn_count].s_addr), &(s->sin_addr), sizeof(struct sockaddr_in));
							network[stn_count].port = ntohs(src_address.sin_port);
							from_found = stn_count;
							if (pkt_debug) fprintf (stderr, "  DYN: Allocated station number %3d.%3d to incoming traffic from %d.%d.%d.%d:%d\n", network[stn_count].network, network[stn_count].station, 
								(ntohl(network[stn_count].s_addr.s_addr) & 0xff000000) >> 24,
								(ntohl(network[stn_count].s_addr.s_addr) & 0xff0000) >> 16,
								(ntohl(network[stn_count].s_addr.s_addr) & 0xff00) >> 8,
								(ntohl(network[stn_count].s_addr.s_addr) & 0xff),
								network[stn_count].port);

							// Log out from FS & SKS here as necessary : TODO SKS
							fs_eject_station(network[stn_count].network, network[stn_count].station);

							// Spoof a bye to wire FS's we've found
							bye.p.srcstn = network[stn_count].station;
							bye.p.srcnet = network[stn_count].network;
							bye.p.port = 0x99;
							bye.p.ctrl = 0x80;
							bye.p.aun_ttype = ECONET_AUN_DATA;
							bye.p.padding = 0x00;
							bye.p.seq = 0x00;
							bye.p.data[0] = 0x90; // Reply port
							bye.p.data[1] = 0x17; // End session
							bye.p.data[2] = 1; // Dummy CWD
							bye.p.data[3] = 2; // Dummy LIB
							
							if (wired_eject)
							{
								struct pollfd p;
								short preturn;
								unsigned char buffer[ECONET_MAX_PACKET_SIZE];
								
								if (pkt_debug) fprintf (stderr, "  DYN:%12s             Spoofing *bye to known wired fileservers...", "");

								for (netcount = 0; netcount < stations; netcount++)
								{
									if (network[netcount].is_wired_fs)
									{
										if (pkt_debug) fprintf (stderr, "%d.%d ",  network[netcount].network, network[netcount].station);
										bye.p.dststn = network[netcount].station;
										bye.p.dstnet = network[netcount].network;
										
										// Send the packet
										attempts = 0;
										written = -1;
	
										while (attempts++ < 5 && written < 0)
											written = write(econet_fd, &bye, 16);
			
										// Rough and ready, but ditch the next packet off the wire, in the hope it's the FS doing an ack of the bye. Should be fine unless the FS has gone away...

										p.fd=econet_fd;
										p.events = POLLIN;

										preturn = poll(&p, 1, 100);

										if (preturn == 1) // Data available
											read(econet_fd, buffer, ECONET_MAX_PACKET_SIZE);
									}
		
								}
		
								if (pkt_debug) fprintf (stderr, "\n");

							}	
							

						}

						stn_count++;
					}

				}

				if ((from_found != 0xffff) && (to_found != 0xffff))
				{
					srcnet = network[from_found].network;
					srcstn = network[from_found].station;
				
					dstnet = network[to_found].network;
					dststn = network[to_found].station;

					network[from_found].last_transaction = time(NULL);

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
								//usleep(ECONET_AUN_ACK_DELAY); // sleep - may help to slow things down a bit and kill off the transmission problems at other end of a bridge
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
				else	
					fprintf (stderr, "UDP packet received on FD %d; From%s found, To%s found (pointer = %08x)\n", pset[realfd].fd, ((from_found != 0xffff) ? "" : " not"), ((to_found != 0xffff) ? "" : " not"), to_found);
			}
	
		}

		fs_bulk_traffic = fs_dequeuable(); // In case something got put there from UDP/Wire/Local above

		if (fs_bulk_traffic)	fs_dequeue(); // Do bulk transfers out.
	
		fs_bulk_traffic = fs_dequeuable();

		start_fd = (start_fd + 1) % pmax;

		// Fileserver garbage collection

		for (s = 0; s < stations; s++)
		{
			if (network[s].servertype & ECONET_SERVER_FILE) 
			{
				if (fs_noisy) fprintf(stderr, "   FS: Garbage collect on server %d\n", network[s].fileserver_index);
				fs_garbage_collect(network[s].fileserver_index);
			}
		
			if (network[s].servertype & ECONET_SERVER_SOCKET)
				sks_poll(network[s].sks_index);
		}

		// Reset our poll structure
		for (s = 0; s <= pmax; s++)
		{
			pset[s].events = POLLIN;
			pset[s].revents = 0; // Need to re-set because we might go round the loop because of the cache not poll()
		}

	}
}

