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
#include <sys/stat.h>
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
short aun_wait (unsigned char, unsigned char, unsigned char, unsigned char, unsigned char, unsigned long, short, struct __econet_packet_aun **);
extern unsigned short fs_quiet, fs_noisy;
extern short fs_sevenbitbodge;
extern short use_xattr; // When set use filesystem extended attributes, otherwise use a dotfile

#define ECONET_LEARNED_HOST_IDLE_TIMEOUT 3600 // 1 hour
#define ECONET_BRIDGE_RESET_FREQ 300 // 300s = 5 minutes. Every 5 mins we do a full reset and re-learn

#define ECONET_HOSTTYPE_TDIS 0x02
#define ECONET_HOSTTYPE_TWIRE 0x04
#define ECONET_HOSTTYPE_TLOCAL 0x08
#define ECONET_HOSTTYPE_TNAMEDPIPE 0x10
#define ECONET_HOSTTYPE_TAUN 0x01

#define ECONET_SERVER_FILE 0x01
#define ECONET_SERVER_PRINT 0x02
#define ECONET_SERVER_SOCKET 0x04

// AUN Ack wait time in ms
#define ECONET_AUN_ACK_WAIT_TIME 400

#define DEVICE_PATH "/dev/econet-gpio"

int aun_send (struct __econet_packet_aun *, int);
unsigned short is_aun(unsigned char, unsigned char);
int trunk_xlate_fw(struct __econet_packet_aun *, int, unsigned char);
short trunk_find (unsigned char);
int aun_trunk_send (struct __econet_packet_aun *, int);
int aun_trunk_send_internal (struct __econet_packet_aun *, int, int);

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
	struct timeval last_bridge_reply;
	// These only apply to wire hosts
	unsigned char adv_in[256], adv_out[256]; // Advertised networks. _in received from other end, _out is last advert sent by us
	unsigned char filter_in[256], filter_out[256]; // Filter masks for in & out
	char named_pipe_filename[200];
};

struct econet_hosts network[65536]; // Hosts we know about / listen for / bridge for
short econet_ptr[256][256]; /* [net][stn] pointer into network[] array. */
short fd_ptr[65536]; /* Index is a file descriptor - yields index into network[] */
short trunk_fd_ptr[65536]; /* Index is a file descriptor - pointer to index in trunks[] */

struct timeval last_bridge_reset;

struct __econet_packet_aun_cache {
	struct __econet_packet_aun *p;
	struct __econet_packet_aun_cache *next;
	unsigned int size; // Size of p, less its 4 byte header.
	struct timeval tstamp;
};

struct __econet_packet_aun_cache *cache_head, *cache_tail;

int stations; // How many entries in network[]

unsigned char wire_advertizable[256]; /* AUN/IP and local networks - for replying to wire bridge queries */
unsigned char trunk_advertizable[256]; /* Networks we know about which have wire or local stations on them, since we do not advertise AUN/IP stations on trunks */

unsigned char wire_adv_out[256], wire_adv_in[256];
unsigned char wire_filter_out[256], wire_filter_in[256];

// Trunking stuff

#define FW_DROP 1
#define FW_ACCEPT 2

struct __fw_entry {
	unsigned short srcnet, srcstn, dstnet, dststn;
	unsigned short action;
	void *next;
};

struct __trunk {
	struct addrinfo *addr;
	int listenport; // Local port number
	int port; // Remote port number
	int listensocket;
	struct __fw_entry *head, *tail;
	unsigned char xlate_src[256], xlate_dst[256]; // _src is the map we apply outbound, _dst is the mirror image for inbound
	unsigned char adv_in[256], adv_out[256]; // Advertised networks. _in received from other end, _out is last advert sent by us
	unsigned char filter_in[256], filter_out[256]; // Filter masks for in & out
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

unsigned long timediffmsec(struct timeval *s, struct timeval *d)
{

	return (((d->tv_sec - s->tv_sec) * 1000) + ((d->tv_usec - s->tv_usec) / 1000));

}

void econet_readconfig(void) 
{
	// This reads a config file in like the BeebEm One.
	// However, stations with IP address 0.0.0.0 are on the Econet wire.
	// We listen on all IP addresses with the specified port for each one.
	// Stations with real IP addresses are out on the internet (or potentially on
	// The local machine if some sort of emulator is running - e.g. BeebEm
	
	FILE *configfile;
	char linebuf[256];
	regex_t r_comment, r_entry_distant, r_entry_local, r_entry_server, r_entry_wire, r_entry_trunk, r_entry_xlate, r_entry_fw, r_entry_learn, r_entry_namedpipe, r_entry_filter;
	regmatch_t matches[9];
	int count;
	short j, k;
	int networkp; // Pointer into network[] array whilst reading config. 
	
	char *end;

	struct hostent *h;
	struct sockaddr_in service;

	numtrunks = 0;

	pmax = 0;
	memset(&wire_advertizable, 0, sizeof(wire_advertizable));
	memset(&trunk_advertizable, 0, sizeof(wire_advertizable));
	memset(&wire_adv_in, 0, sizeof(wire_adv_in));
	memset(&wire_adv_out, 0, sizeof(wire_adv_out));
	memset(&wire_filter_in, 0, sizeof(wire_filter_in));
	memset(&wire_filter_out, 0, sizeof(wire_filter_out));

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
	if (regcomp(&r_entry_distant, "^\\s*([Aa]|IP)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([^[:space:]]+)\\s+([[:digit:]]{4,5})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile full distant station regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_local, "^\\s*([Nn]|LOCALNET)\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile full local config regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_server, "^\\s*([FfPpSs])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5})\\s+(.+)\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile server regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_namedpipe, "^\\s*(UNIX)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+(\\/.+)\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile named pipe regex.\n");
		exit(EXIT_FAILURE);
	}

        if (regcomp(&r_entry_wire, "^\\s*([Ww]|WIRE)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5}|AUTO)\\s*$", REG_EXTENDED) != 0)
        {
                fprintf(stderr, "Unable to compile full wire station regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_learn, "^\\s*([Ll]|LEARN|DYNAMIC)\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED) != 0)
        {
                fprintf(stderr, "Unable to compile full wire station regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_trunk, "^\\s*([T]|TRUNK)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5})\\s+([^[:space:]]+)\\s+([[:digit:]]{4,5})\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile trunk regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_xlate, "^\\s*([X]|XLATE|TRANSLATE)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile network translation regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_fw, "^\\s*([Y]|FIREWALL)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+(DROP|ACCEPT)\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile network firewall regex.\n");
                exit(EXIT_FAILURE);
        }

        if (regcomp(&r_entry_filter, "^\\s*FILTER\\s+(IN|OUT)\\s+([[:digit:]]{1,3})\\s+NET\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED | REG_ICASE) != 0)
        {
                fprintf(stderr, "Unable to compile network filter regex.\n");
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
			wire_advertizable[network[networkp].network] = 0xff;
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
			for (count = 2; count <= 2; count++)
			{
				ptr = 0;
				while (ptr < (matches[count].rm_eo - matches[count].rm_so))
				{
					tmp[ptr] = linebuf[ptr + matches[count].rm_so];	
					ptr++;
				}
				tmp[ptr] = 0x00;
				
				if (count == 2)
					localnet = atoi(tmp);

				if (localnet)
					trunk_advertizable[localnet] = 0xff;
			}
		}
		else if (regexec(&r_entry_namedpipe, linebuf, 5, matches, 0) == 0)
		{
			int stn, net, ptr, entry, mfr;
			char filename[200], tmp[300];

			for (count = 2; count <= 4; count++) // start at 2 - we know the first one is 'UNIX'
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
					case 2: net = atoi(tmp); break;
					case 3: stn = atoi(tmp); break;
					case 4: strncpy(filename, tmp, 199); break;	
				}

			}

			entry = econet_ptr[net][stn];

			if (entry != -1)
			{
				fprintf (stderr, "Cannot configure named pipe station %d.%d - station already configured some other way.\n", net, stn);
				exit(EXIT_FAILURE);
			}

			network[networkp].type = ECONET_HOSTTYPE_TNAMEDPIPE | ECONET_HOSTTYPE_TAUN;
			network[networkp].servertype = 0;
			network[networkp].seq = 0x00004000;
			network[networkp].network = net;
			network[networkp].station = stn;
			network[networkp].port = 0;
			strcpy(network[networkp].named_pipe_filename, filename);

			mfr = mkfifo(filename, 0666); // Not keen on this.

			network[networkp].listensocket = -1;

			if (mfr == -1 && (errno != EEXIST)) // mkfifo failed and it wasn't because the fifo already existed
			{
				fprintf (stderr, "Cannot initialize named pipe at %s - ignoring\n", filename);
			}
			else
				network[networkp].listensocket = open(filename, O_RDWR);

			if (network[networkp].listensocket != -1) // Open succeeded
			{
			
                        	network[networkp].pind = pmax; // Index into pset from the network[] array

                       		fd_ptr[network[networkp].listensocket] = networkp; // Create the index to find a station from its FD
	
                       		pset[pmax++].fd = network[networkp].listensocket; // Fill in our poll structure
	
				ECONET_SET_STATION(econet_stations, net, stn); // Put it in our list of AUN bridges

				if (net != 0)
				{
					wire_advertizable[net] = 0xff;
					trunk_advertizable[net] = 0xff;
				}

				econet_ptr[net][stn] = networkp;

				networkp++;
			}
			else	fprintf (stderr, "Failed to initialize named pipe for station %d.%d - passively ignoring\n", net, stn);

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

			// Set up bridge adverts
			if (network[networkp].network !=0)
			{
				wire_advertizable[network[networkp].network] = 0xff;
				trunk_advertizable[network[networkp].network] = 0xff;
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

				if (net != 0)
				{
					wire_advertizable[net] = 0xff;
					trunk_advertizable[net] = 0xff;
				}

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

			gettimeofday(&(network[networkp].last_bridge_reply),0);
			clock_gettime (CLOCK_MONOTONIC, &(network[networkp].last_wire_tx));
                        fd_ptr[network[networkp].listensocket] = networkp; // Create the index to find a station from its FD

			if (network[networkp].network != 0)
				trunk_advertizable[network[networkp].network] = 0xff;
	
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
				wire_advertizable[network[networkp].network] = 0xff;
			
				if (nativebridgenet == 0 && network[networkp].network != 0)
					nativebridgenet = network[networkp].network;

				network[networkp].is_dynamic = 1;
				networkp++;
			}


		}
		else if (regexec(&r_entry_trunk, linebuf, 6, matches, 0) == 0)
		{
			char tmp[300];
			int ptr;
			unsigned short trunknum, localport, port;
			char hostname[300], portname[6];
			struct addrinfo hints;

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
						strcpy(portname, tmp);
						break;
					case 4: // hostname
						strcpy(hostname, tmp);
						break;
					case 5: // port
						port = atoi(tmp);
						break;	
				}

			}

			trunks[trunknum].head = trunks[trunknum].tail = NULL;
			trunks[trunknum].listenport = localport;
			memset (trunks[trunknum].adv_in, 0x0, sizeof(trunks[trunknum].adv_in));
			memset (trunks[trunknum].adv_out, 0x0, sizeof(trunks[trunknum].adv_out));
			memset (trunks[trunknum].filter_in, 0x0, sizeof(trunks[trunknum].filter_in));
			memset (trunks[trunknum].filter_out, 0x0, sizeof(trunks[trunknum].filter_out));
			memset (trunks[trunknum].xlate_src, 0xff, sizeof(trunks[trunknum].xlate_src));
			memset (trunks[trunknum].xlate_dst, 0xff, sizeof(trunks[trunknum].xlate_dst));

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

			memset (&hints, 0, sizeof(hints));
			hints.ai_family=AF_INET;
			hints.ai_socktype=SOCK_DGRAM;
			hints.ai_protocol=0;
			hints.ai_flags=0;

			// Now set up distant host structure
			strcpy(trunks[trunknum].hostname, hostname);
			
			if (getaddrinfo(hostname, portname, &hints, &(trunks[trunknum].addr)))
			{
				fprintf(stderr, "Cannot resolve hostname %s\n", hostname);
				exit (EXIT_FAILURE);
			}

			trunks[trunknum].port = port;

                        pset[pmax++].fd = trunks[trunknum].listensocket; // Fill in our poll structure
			trunk_fd_ptr[trunks[trunknum].listensocket] = trunknum; // Map the Trunk FD array

			// Populate our advertizable structure
			// And set the module to listen for these distant stations

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
						trunks[trunknum].xlate_dst[atoi(tmp)] = srcnet;
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
		while (z < 16)
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
		while (z < 16)
		{
			if ((count+z) < packetsize)
			{
				sprintf(tmpstr, "%c", (*(a+count+z) >= 32 && *(a+count+z) < 127) ? *(a+count+z) : '.');
				strcat(dbgstr, tmpstr);
			}
			z++;
		}

		fprintf(stderr, "%s\n", dbgstr);		

		count += 16;

	}
	if (start_index == 0)
		fprintf (stderr, "%08x --- END ---\n", packetsize);
}

void dump_udp_pkt_aun(struct __econet_packet_aun *a, int s)
{

	int count = 0;
	int packetsize = s;
	char ts[30];
	int src, dst;
	char src_c, dst_c;

	if (pkt_debug == 0) return;

	src = econet_ptr[a->p.srcnet][a->p.srcstn];
	dst = econet_ptr[a->p.dstnet][a->p.dststn];

#define sd_sift(x,y) {\
	if ((x) == -1) \
		y = 'T'; \
	else if (network[(x)].type & ECONET_HOSTTYPE_TLOCAL)\
		y = 'L';\
	else if (network[(x)].type & ECONET_HOSTTYPE_TWIRE)\
		y = 'E';\
	else if (network[(x)].type & ECONET_HOSTTYPE_TNAMEDPIPE)\
		y = 'N';\
	else\
		y = 'A';\
	}

	sd_sift(src, src_c);
	sd_sift(dst, dst_c);
	
	if (src_c == 'E' && (a->p.dstnet == 0xff && a->p.dststn == 0xff))
		dst_c = 'B';

	if (a->p.srcstn == 0) // Bridge query reply
		src_c = 'L';

	if (dumpmode_brief)
	{
		fprintf (stderr, "%c-->%c: to %3d.%3d from %3d.%3d port 0x%02x ctrl 0x%02x seq 0x%08x len 0x%04x ", src_c, dst_c, a->p.dstnet, a->p.dststn, a->p.srcnet, a->p.srcstn, a->p.port, a->p.ctrl, le32toh(a->p.seq), s-12);
		for (count = 0; count < ((s-12) < 40 ? (s-12) : 40); count++)
			fprintf (stderr, "%02x %c ", a->p.data[count], (a->p.data[count] < 32 || a->p.data[count] > 126) ? '.' : a->p.data[count]);
		fprintf (stderr, "%s\n", (s-12) < 40 ? "" : " ...");
			
	}
	else
	{
		fprintf (stderr, "\n%08x --- PACKET %s TO %s ---\n", packetsize, (src_c == 'T' ? "TRUNK" : (src_c == 'E' ? "ECONET" : (src_c == 'L' ? "LOCAL" : "AUN"))),
			(dst_c == 'T' ? "TRUNK" : (dst_c == 'E' ? "ECONET" : (dst_c == 'L' ? "LOCAL" : "AUN"))));
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

		if (a->p.aun_ttype == ECONET_AUN_DATA && (a->p.port == 0x00) && (a->p.ctrl == 0x85))
			strcpy(ts, "IMMEDIATE - SPECIAL 0x85");

		fprintf (stderr, "         --- AUN TYPE %s\n", ts);

		if (a->p.aun_ttype != ECONET_AUN_BCAST)
			fprintf (stderr, "         DST Net/Stn 0x%02x/0x%02x\n", a->p.dstnet, a->p.dststn);

		fprintf (stderr, "         SRC Net/Stn 0x%02x/0x%02x\n", a->p.srcnet, a->p.srcstn);
		fprintf (stderr, "         PORT/CTRL   0x%02x/0x%02x\n", a->p.port, a->p.ctrl);
	
		fprintf (stderr, "         SEQ         0x%08lX\n", a->p.seq);

		dump_pkt_data((unsigned char *) &(a->p.data), s-12, 0);

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

void aun_acknowledge (struct __econet_packet_aun *a, unsigned char ptype)
{

	struct __econet_packet_aun reply;

	reply.p.aun_ttype = ptype;
	reply.p.port = a->p.port;
	reply.p.ctrl = a->p.ctrl;
	reply.p.padding = 0x00;
	reply.p.seq = a->p.seq;
	reply.p.srcnet = a->p.dstnet;
	reply.p.srcstn = a->p.dststn;
	reply.p.dstnet = a->p.srcnet;
	reply.p.dststn = a->p.srcstn;

	if (econet_ptr[reply.p.dstnet][reply.p.dststn] == -1)
		aun_trunk_send(&reply, 12);
	else
		aun_send (&reply, 12); // TODO. Need to write to the correct place here and not use aun_send.

}

// Called when we receive a &80 bridge instruction from somewhere
// Source will be set to 0 if wire (shouldn't be defining trunk 0), -1 if this is a self-initiated reset (e.g. on startup), otherwise a trunk number
// p is a pointer to the incoming reset packet, and len is its data length
// If this is self-originated, it is treated as a bridge reset (&80), otherwise it's a bridge update (&81) or reset (&80) depending on what is in *p->p.ctrl

void econet_bridge_process(struct __econet_packet_aun *p, int len, int source)
{

	short counter;
	unsigned char is_reset;
	struct __econet_packet_aun out; // Packet structure for the packets we will send out

	if (!bridge_query || !localnet) // Exit if we are not briding
		return;

	if (source == -1)
		is_reset = 1;
	else
		is_reset = (p->p.ctrl == 0x80 ? 1 : 0);

	if (pkt_debug)
	{
		fprintf (stderr, "B-->B: Receive bridge %s from %s ", (is_reset ? "reset " : "update"), (source == -1 ? "internal" : (source == 0 ? "wire" : "trunk")));

		if (source > 0) fprintf (stderr, "%d ", source);

		if (source >= 0)
		{
			fprintf (stderr, "with nets ");
			for (counter = 0; counter < len-12; counter++)
				fprintf (stderr, "%3d ", p->p.data[counter]);
		}

		fprintf (stderr, "\n");
	}

	if (is_reset)
	{

		// First the ones for the wire
	
		memset(&wire_adv_in, 0, sizeof(wire_adv_in));
		memcpy(&wire_adv_out, &wire_advertizable, sizeof(wire_advertizable));

		// Then the trunks
	
		for (counter = 1; counter < 256; counter++)
		{
			if (trunks[counter].listensocket >= 0)
			{
				memset(&(trunks[counter].adv_in), 0, sizeof(trunks[counter].adv_in));
				memset(&(trunks[counter].adv_out), 0, sizeof(trunks[counter].adv_out)); // This gets populated with local advertizables subject to nat lower down
			}
		}

		nativebridgenet = 0; 

		// If we have some networks advertizable to the wire, set our local bridge net to the first one we find that isn't the local network
		for (counter = 1; counter < 255; counter++)
		{
			if (wire_advertizable[counter] == 0xff && (counter != localnet))
			{
				nativebridgenet = counter;
				break;
			}
		}
	}
	
	// Extract the advertised packets, filtering as we go

	for (counter = 0; counter < len-12; counter++) 
	{
		if (source == 0) // Wire origin
			wire_adv_in[p->p.data[counter]] = 0xff ^ wire_filter_in[p->p.data[counter]]; // Since the filter_in entry for a network will be 0xff if we are filtering it, this will result in 0 if the network is filtered.	
		else if (source > 0) // Not wire, but not self-originated either. (If self-originated, there will be no *p to look at)
		{
			trunks[source].adv_in[p->p.data[counter]] = 0xff ^ trunks[source].filter_in[p->p.data[counter]]; // Since the filter_in entry for a network will be 0xff if we are filtering it, this will result in 0 if the network is filtered.	
			if (!nativebridgenet) // There wasn't anything we were already advertizing to the wire - so use this as our native network
				nativebridgenet = (0xff ^ trunks[source].filter_in[p->p.data[counter]]) ? counter : 0;  // If this network wasn't filtered, nativebridgenet is set to it. Otherwise 0 (which is what it was before)
		}
	}

	// Now update the outbound advertizement tables

	// Wire first - go through each trunk and pick up its inbound advert, and combine it with what we were advertizing anyway
	// Remove any networks from outbound advert that were in the inbound advert *from* the wire

	for (counter = 0; counter < 255; counter++)
	{
		if (trunks[counter].listensocket >= 0) // Active trunk
		{
			short net;
			
			for (net = 1; net < 255; net++)
				if ((trunks[counter].adv_in[net] == 0xff) && (wire_adv_in[net] != 0xff) && (wire_filter_out[net] != 0xff)) // Copy trunk adverts to wire unless either (i) the wire was advertizing those networks to us, or (ii) there was an outbound filter on the wire advertizement for this network
					wire_adv_out[net] = 0xff;
		}

	}

	// Now rebuild the econet_stations structure

	// Update for all local servers, AUN stations, and all stations in nets advertized out to the wire, together with nativebridgenet.0, and 255.255 for broadcasts
	
	ECONET_INIT_STATIONS(econet_stations);
	ECONET_SET_STATION(econet_stations, 255, 255); // Broadcast
	if (nativebridgenet)
		ECONET_SET_STATION(econet_stations, nativebridgenet, 0); // Local bridge handshakes // Can't do this without a far side network

	// First, known AUN & local stations
	for (counter = 0; counter < stations; counter++)
		if ((network[counter].type & ECONET_HOSTTYPE_TDIS) || (network[counter].type & ECONET_HOSTTYPE_TNAMEDPIPE) || (network[counter].type & ECONET_HOSTTYPE_TLOCAL)) // NB because our dynamic network is preallocated in here, this catches the dynamic net too. Also add named pipe stations in
		{
			//fprintf (stderr, "Adding station %3d.%3d\n", network[counter].network, network[counter].station);
			ECONET_SET_STATION(econet_stations, network[counter].network, network[counter].station);
		}

	// Then everything we are advertising out as a bridge (except stn 0 & 255)
	for (counter = 1; counter < 256; counter++)
	{
		unsigned char stn;
		
		if (wire_adv_out[counter] == 0xff) // Outbound advert
			for (stn = 1; stn < 255; stn++)
				ECONET_SET_STATION(econet_stations, counter, stn);
	}

	// Update the station set

	ioctl(econet_fd, ECONETGPIO_IOC_SET_STATIONS, &econet_stations);

	// Now update each trunk's outbound advert with what's come in on every other trunk, sifting out any loops (i.e. don't advertize back to a trunk that which it advertized to us). Do NAT here.
	for (counter = 0; counter < 255; counter++)
	{

		short other; // Loop counter for other trunks

		if (trunks[counter].listensocket >= 0) // Active trunk
		{
			// The wire & local stuff will already be there because we copied trunk_advertizable into it. BUT we need to do NAT on it. TODO.

			for (other = 1; other < 255; other++)
			{
				if (trunk_advertizable[other])
				{
					unsigned char xlated;

					xlated = other;

					if (trunks[counter].xlate_src[other] != 0xff)
						xlated = trunks[counter].xlate_src[other];

					trunks[counter].adv_out[xlated] = 0xff ^ trunks[counter].filter_out[xlated]; // Apply filter to translated net

				}

			}

			// Now the other trunks. Note, we filter the outbound advert here but we need do no NAT here because these are advertizements from other trunks

			for (other = 0; other < 255; other++)
			{
				if (other != counter) // Don't copy from same trunk!
				{
					if (trunks[other].listensocket >= 0)
					{
						unsigned char net;
			
						for (net = 1; net < 255; net++)
							if ((trunks[other].adv_in[net] == 0xff) && (trunks[counter].adv_in[net] != 0xff) && (trunks[counter].filter_out[net] != 0xff)) // Other trunk advertising net 'n', and it wasn't advertized to us on this trunk, advertize it out, unless it was filtered outbound
								trunks[counter].adv_out[net] = 0xff;

					}	

				}

			}
				
		}

	}

	// Now spit out a broadcast with port &9C and ctrl byte as appropriate

	// First to the wire
	if (nativebridgenet) // Can't send this unless we have *something* on the far side of local...
	{

		unsigned char net, count;

		out.p.srcnet = nativebridgenet;
		out.p.srcstn = 0;
		out.p.dstnet = out.p.dststn = 255;
		out.p.port = 0x9c;
		out.p.ctrl = (is_reset ? (source == 0 ? 0x81 : 0x80) : 0x81); // Send this as an update if the source was the wire, otherwise as an update
		out.p.aun_ttype = ECONET_AUN_BCAST;
		out.p.seq = (local_seq += 4);

		count = 0;

		if (pkt_debug) fprintf (stderr, "B-->B: Sending bridge %s to   wire    with nets ", (is_reset ? "reset " : "update"));

		for (net = 1; net < 255; net++)
			if (wire_adv_out[net] == 0xff)
			{
				out.p.data[count++] = net;
				if (pkt_debug) fprintf (stderr, "%3d ", net);
			}

		if (pkt_debug) fprintf (stderr, "\n");
		
		write (econet_fd, &out, count+12);
	}

	// Then to the trunks
	{

		unsigned char net, trunk, count;

		for (trunk = 1; trunk < 255; trunk++)
		{
			if (trunks[trunk].listensocket >= 0 && ((source == trunk && is_reset) || (source != trunk))) // Active trunk - but we only send to the source trunk if it's a reset, and the code switches that to an update
			{
		
				out.p.srcnet = localnet;	
				out.p.srcstn = 0;
				out.p.dstnet = out.p.dststn = 255;
				out.p.port = 0x9c;
				out.p.ctrl = (is_reset ? (source == trunk ? 0x81 : 0x80) : 0x81); // If it's a reset but was from this trunk, send update not reset
				out.p.aun_ttype = ECONET_AUN_BCAST;
				out.p.seq = (local_seq += 4);

				if (pkt_debug) fprintf (stderr, "B-->B: Sending bridge %s on   trunk %d with nets ", (out.p.ctrl == 0x80 ? "reset " : "update"), trunk);

				count = 0;

				for (net = 1; net < 255; net++)
					if (trunks[trunk].adv_out[net] == 0xff)
					{
						out.p.data[count++] = net;	
						if (pkt_debug) fprintf (stderr, "%3d ", net);
					}

				if (pkt_debug) fprintf (stderr, "\n");

				aun_trunk_send_internal (&out, count+12, trunk);
			}

		}

	}
}

// a contains a packet received from somwhere, packlen is it's length. source is either 0 for the wire, > 0 for a trunk number, or -1 from anywhere else

void econet_handle_local_aun (struct __econet_packet_aun *a, int packlen, int source)
{

	struct __econet_packet_aun reply;
	int s_ptr, d_ptr;

	s_ptr = econet_ptr[a->p.srcnet][a->p.srcstn];
	d_ptr = econet_ptr[a->p.dstnet][a->p.dststn];

	if (a->p.aun_ttype == ECONET_AUN_IMM) // Immediate
	{
		if (a->p.ctrl == 0x88) // Machinepeek
		{
			reply.p.srcnet = a->p.dstnet;
			reply.p.srcstn = a->p.dststn;
			reply.p.dstnet = a->p.srcnet;
			reply.p.dststn = a->p.srcstn;
			reply.p.aun_ttype = ECONET_AUN_IMMREP;
			reply.p.seq = a->p.seq;
			reply.p.port = 0;
			reply.p.ctrl = 0x88;
			reply.p.data[0] = ADVERTISED_MACHINETYPE & 0xff;
			reply.p.data[1] = (ADVERTISED_MACHINETYPE & 0xff00) >> 8;
			reply.p.data[2] = ADVERTISED_VERSION & 0xff;
			reply.p.data[3] = (ADVERTISED_VERSION & 0xff00) >> 8;

			aun_send (&reply, 16);
		}	
		else if (a->p.ctrl == 0x81 && (packlen > 16)) // Memory Peek (packlen will be 4 internal header, 8 AUN header, 4 special 0x85 bytes, and if there is nothing beyond those 16 (total) then don't bother)
		{

			if (beebmem) // If we managed to load it...
			{
				unsigned int start, end;

				start = ((a->p.data[0]) + (256 * (a->p.data[1])));
				end = ((a->p.data[4]) + (256 * (a->p.data[5])));

				sprintf (beebmem + 0x7c5f, "%d", a->p.dststn);

				reply.p.srcnet = a->p.dstnet;
				reply.p.srcstn = a->p.dststn;
				reply.p.dstnet = a->p.srcnet;
				reply.p.dststn = a->p.srcstn;
				reply.p.aun_ttype = ECONET_AUN_IMMREP;
				reply.p.port = a->p.port;
				reply.p.ctrl = a->p.ctrl;
				reply.p.seq = a->p.seq;
			
				memcpy(&(reply.p.data), (beebmem + start), end-start);

				aun_send (&reply, 12 + (end - start));

			}
		}
	}
	else if (a->p.aun_ttype == ECONET_AUN_BCAST) // Broadcast - See if we need to do a bridge query reply
	{
		//fprintf (stderr, "Bridge query %s, port %02x, BRIDGE check %s, localnet %s\n", (bridge_query ? "on" : "off"), a->p.port, (!strncmp("BRIDGE", (const char *) a->p.data, 6) ? "match" : "not matched"), localnet ? "set" : "not set");

		if (bridge_query && (a->p.port == 0x9C) && (a->p.ctrl == 0x80 || a->p.ctrl == 0x81) && (source >= 0)) // bridge reset/update broadcast
			econet_bridge_process (a, packlen, source);

		else if (bridge_query && (a->p.port == 0x9c) && (!strncmp("BRIDGE", (const char *) a->p.data, 6)) && localnet && (network[econet_ptr[a->p.srcnet][a->p.srcstn]].type & ECONET_HOSTTYPE_TWIRE))
		{
			short query_net, reply_port;
			struct timeval now;

			reply_port = a->p.data[6];
			query_net = a->p.data[7];
	
			gettimeofday(&now, 0);

			if (pkt_debug && !dumpmode_brief)
				fprintf (stderr, "LOC  : BRIDGE     from %3d.%3d, query 0x%02x, reply port 0x%02x, query net %d\n", a->p.srcnet, a->p.srcstn, a->p.ctrl, reply_port, query_net);

			if (nativebridgenet && 
				(
					(a->p.ctrl == 0x82 
					&& (timediffmsec(&(network[econet_ptr[a->p.srcnet][a->p.srcstn]].last_bridge_reply), &now) > 1000)
					) 
				|| 	(a->p.ctrl == 0x83 && (wire_advertizable[query_net] == 0xff))
				) // Either a local network number query, or a query for a network in our known distant list
			)
			{
				
				if (a->p.ctrl == 0x82)
					gettimeofday(&(network[econet_ptr[a->p.srcnet][a->p.srcstn]].last_bridge_reply),0); // Don't reply too quickly

				reply.p.srcnet = nativebridgenet;
				reply.p.srcstn = 0;
				reply.p.dstnet = a->p.srcnet;
				reply.p.dststn = a->p.srcstn;
				reply.p.aun_ttype = ECONET_AUN_DATA;
				reply.p.port = reply_port;
				//reply.p.ctrl = a->p.ctrl;
				reply.p.ctrl = 0x80;
				reply.p.padding = 0x00;
				reply.p.seq = (local_seq += 4);
				reply.p.data[0] = localnet;
				reply.p.data[1] = query_net; 
				aun_send (&reply, 14);
			}
	
		}
	}
	else if (a->p.aun_ttype == ECONET_AUN_DATA) // Data packet
	{
		if ((a->p.port == 0x99) && (network[d_ptr].servertype & ECONET_SERVER_FILE) && (network[d_ptr].fileserver_index >= 0))
			handle_fs_traffic(network[d_ptr].fileserver_index, a->p.srcnet, a->p.srcstn, a->p.ctrl, a->p.data, packlen-12);

		else if ((a->p.port == 0x9f) && ((network[d_ptr].servertype) & ECONET_SERVER_PRINT) && (!strncmp((const char *)&(a->p.data), "PRINT", 5))) // Looks like only ANFS does this... // Print server handling
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
				char filename[100];

				printjobs[found].stn = a->p.srcstn;
				printjobs[found].net = a->p.srcnet;
				printjobs[found].ctrl = 0x80; 
				
				reply.p.srcnet = a->p.dstnet;
				reply.p.srcstn = a->p.dststn;
				reply.p.dstnet = a->p.srcnet;
				reply.p.dststn = a->p.srcstn;
				reply.p.aun_ttype = ECONET_AUN_DATA;
				reply.p.port = 0x9e;
				reply.p.ctrl = 0x80;
				reply.p.seq = get_local_seq(a->p.dstnet, a->p.dststn);
				reply.p.data[0] = 0x00;

				aun_send (&reply, 13);

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
				reply.p.srcnet = a->p.dstnet;
				reply.p.srcstn = a->p.dststn;
				reply.p.dstnet = a->p.srcnet;
				reply.p.dststn = a->p.srcstn;
				reply.p.aun_ttype = ECONET_AUN_DATA;
				reply.p.port = 0xd1;
				reply.p.ctrl = printjobs[count].ctrl;
				printjobs[count].ctrl ^= 0x01;

				reply.p.seq = get_local_seq(a->p.dstnet, a->p.dststn);

				// The control low bit alternation is to avoid duplicated packets. Need to implement a check... TODO.

				switch (a->p.ctrl)
				{
					case 0x83: // Fall through
					case 0x82: // Print job start
					{
						reply.p.data[0] = 0x2a;
						// 20210815 Commented
						//usleep(50000); // Short delay - otherwise we get failed transmits for some reason - probably 4-way failures
						aun_send (&reply, 13);
					}
					break;
					case 0x80: // Fall through
					case 0x81: // Print data
					{
						fwrite(&(a->p.data), packlen-12, 1, printjobs[count].spoolfile);
						reply.p.data[0] = a->p.data[0];	
						aun_send (&reply, 13);
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

						aun_send (&reply, 13);
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

// Trunk send internal - send packet p of length len on trunk t - used once we've found which trunk we want
int aun_trunk_send_internal (struct __econet_packet_aun *p, int len, int t)
{

	int result;

	if (trunk_xlate_fw(p, t, 1) == FW_ACCEPT) // returns 0 for drop traffic (param 3 = 1 means outbound)
		result = sendto(trunks[t].listensocket, p, len, MSG_DONTWAIT, trunks[t].addr->ai_addr, trunks[t].addr->ai_addrlen); 

	return result;
}

// Send AUN format packet (including our 4 byte magic header) over a trunk. Return 0 if it hasn't worked, otherwise packet length.
// For now, the firewall is not implemented.

int aun_trunk_send(struct __econet_packet_aun *p, int len)
{

	short trunk;
	int result = 0;

	// First, see which trunk this destination might be on.

	trunk = trunk_find(p->p.dstnet);

	if (trunk >= 0)
		result = aun_trunk_send_internal(p, len, trunk);
	else	if (pkt_debug) fprintf (stderr, "TRUNK: to %3d.%3d from %3d.%3d Trunk destination not found\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);

	return result;

}

void aun_clear_cache (unsigned char net, unsigned char stn)
{

	struct __econet_packet_aun_cache *q, *q_parent;
	int found;

	q_parent = NULL;
	q = cache_head;

	found = 0;

	while (q && !found)
	{
		if ((q->p->p.srcnet == net) && (q->p->p.srcstn == stn)) // If the station we just transmitted to has a packet in the cache, splice it out
		{
			found = 1;
			if (q != cache_head)
				q_parent->next = q->next;
			else	cache_head = q->next; // Works even if p->next is null (only one packet on queue)

			free (q->p); free(q); // free both the packet inside the queue entry, and the queue entry
		}
		else
		{
			q_parent = q;
			q = q_parent->next;
		}
	}

}

// Source is only used to pass to local handler to process broadcasts so we know where they came from
int aun_send_internal (struct __econet_packet_aun *p, int len, int source)
{

	int d, s, result; // d, s are pointers into network[]; result is number of bytes written or error return
	unsigned short count; // Transmission attempt counter
	int err; // Wire transmit error number if any
	unsigned char acknowledged = 0;
	struct sockaddr_in n;
	struct __econet_packet_aun *ack;

	if (p->p.aun_ttype == ECONET_AUN_BCAST)
		p->p.dstnet = p->p.dststn = 0xff;
		
	d = econet_ptr[p->p.dstnet][p->p.dststn];
	s = econet_ptr[p->p.srcnet][p->p.srcstn];

	if (d != -1) network[d].last_transaction = time(NULL);

	p->p.ctrl |= 0x80; // In case we're going to wire or local
	
	p->p.padding = 0x00;

	if (p->p.aun_ttype != ECONET_AUN_ACK && p->p.aun_ttype != ECONET_AUN_NAK) // Don't dump acks...
		dump_udp_pkt_aun(p, len);

	result = -1;

	// Perform interlock - do not send between same type of endpoints, or between trunk<->AUN/IP, and drop any RAW traffic in bridge mode

	if ((d != -1) && (s != -1)) // Both are known particular stations - i.e. not trunk
	{
		if ((network[d].type & ECONET_HOSTTYPE_TAUN) == 0) // Raw destination - dump it
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward traffic to a raw destination.\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
		if ((network[s].type & ECONET_HOSTTYPE_TAUN) == 0) // Raw source - dump it
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward traffic from a raw source.\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
		if ((network[d].type & ~ECONET_HOSTTYPE_TAUN) == (network[s].type & ~ECONET_HOSTTYPE_TAUN)) // Same type - dump it
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward betwen stations of the same type.\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
	}
	else
	{
/* ALLOW TRUNK TO TRUNK
		if (d == -1 && s == -1 && (p->p.srcstn != 0 && p->p.srcnet != nativebridgenet) && (p->p.aun_ttype != ECONET_AUN_BCAST)) // Trunk to trunk - dump it - unless it's from our bridge query system, or a broadcast
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward.\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
*/
		if (d == -1 && (s != -1) && (network[s].type & ECONET_HOSTTYPE_TDIS)) // AUN/IP source to Trunk - dump it
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward AUN traffic to trunk\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
		if (s == -1 && (d != -1) && (network[d].type & ECONET_HOSTTYPE_TDIS)) // Trunk to AUN/IP - dump it
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward trunk traffic to AUN.\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
	}

	// If trunk destination, the trunk send routine does NAT and works out which trunk

	// Now, where's it going?

	count = 0;

	//aun_clear_cache (p->p.dstnet, p->p.dststn);

	while (count < 2 && !acknowledged)
	{
		if (d == -1 && (p->p.aun_ttype != ECONET_AUN_BCAST))
		{
			p->p.ctrl &= 0x7f; // Strip high bit from control an AUN transmission

/*
			// Restore sequence number if we are sending an immediate reply

			if (p->p.aun_ttype == ECONET_AUN_IMMREP)
				p->p.seq = network[d].last_imm_seq_sent; // Override the sequence number from the kernel to match what was last sent to this host 
*/

			result = aun_trunk_send (p, len);

			// Wait for ack / immrep here. if the traffic didn't come from another trunk - in which case the other end can deal with waiting around for replies

			if ((s != -1) && p->p.aun_ttype == ECONET_AUN_DATA) // Wait for ack
			{
				if (aun_wait(p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, ECONET_AUN_ACK, p->p.seq, ECONET_AUN_ACK_WAIT_TIME, NULL))
					acknowledged = 1;
			}
                        else if ((s != -1) && p->p.aun_ttype == ECONET_AUN_IMM) // Wait for immediate reply - see note above about why we need not check immediate_spoof here
                        {
                                int acklen;

                                if ((acklen = aun_wait(p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, ECONET_AUN_IMMREP, p->p.seq, ECONET_AUN_ACK_WAIT_TIME * 2, &ack)))
                                {
                                        acknowledged = 1;
                                        // Can only sensibly be going on the wire
                                        write (econet_fd, ack, acklen);
                                }
                                else    ioctl(econet_fd, ECONETGPIO_IOC_READMODE); // Force read mode on a timeout otherwise the kernel stops listening...

                                if (ack) free(ack);
                        }
			else acknowledged = 1; // Treat as acknowledged

		}
		else if ((network[d].type & ECONET_HOSTTYPE_TLOCAL) || p->p.aun_ttype == ECONET_AUN_BCAST) // Probably need to forward broadcasts received off the wire to AUN/IP hosts on same net, but we don't at the moment
		{
			econet_handle_local_aun(p, len, source);
			result = len;
			acknowledged = 1;
		}
		else if ((network[d].type & ECONET_HOSTTYPE_TNAMEDPIPE)) // Named pipe client
		{
			unsigned char buffer[65536];

			result = write(network[d].listensocket, p, len);
			// Do a dummy read to get rid of that traffic coming back to us
		
			read(network[d].listensocket, &buffer, len);

			acknowledged = 1;
		}
		else if (network[d].type & ECONET_HOSTTYPE_TDIS)
		{
			p->p.ctrl &= 0x7f; // Strip high bit from control an AUN transmission

			// Transmit here - TODO
			
			n.sin_family = AF_INET;
			n.sin_port = htons(network[d].port);
			n.sin_addr = network[d].s_addr;
		
			if (p->p.aun_ttype != ECONET_AUN_BCAST) // Need to work on sending broadcasts on AUN
			{

/*
				if (p->p.aun_ttype == ECONET_AUN_IMMREP)
					p->p.seq = network[d].last_imm_seq_sent; // Override the sequence number from the kernel to match what was last sent to this host 
*/

				result = sendto(network[s].listensocket, &(p->p.aun_ttype), len-4, MSG_DONTWAIT, (struct sockaddr *)&n, sizeof(n)); // Strip first four bytes off - p is now a full internal format packet, so we ditch the first four.
				
			}

			if (p->p.aun_ttype == ECONET_AUN_DATA) // Wait for ack
			{
				int t;
				if ((t = aun_wait(p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, ECONET_AUN_ACK, p->p.seq, ECONET_AUN_ACK_WAIT_TIME, NULL)))
				{
					acknowledged = 1;
				}
			}
			else if (p->p.aun_ttype == ECONET_AUN_IMM) // Wait for immediate reply - see note above about why we need not check immediate_spoof here
			{
				int acklen;

				if ((acklen = aun_wait(p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, ECONET_AUN_IMMREP, p->p.seq, ECONET_AUN_ACK_WAIT_TIME * 2, &ack)))
				{
					acknowledged = 1;
					// Can only sensibly be going on the wire
					write (econet_fd, ack, acklen);
				}
				else	ioctl(econet_fd, ECONETGPIO_IOC_READMODE); // Force read mode on a timeout otherwise the kernel stops listening...
			
				if (ack) free(ack);
			}
			else // Treat as acknowledged
				acknowledged = 1;
		}
		else if (network[d].type & ECONET_HOSTTYPE_TWIRE) // Wire
		{

			// Is it a wired fileserver we might want to know about?

			if ((network[d].type & ECONET_HOSTTYPE_TWIRE) && (p->p.port == 0x99) && (!(network[d].is_wired_fs))) // Fileserver traffic on a wire station
			{
				network[d].is_wired_fs = 1;
				fprintf (stderr, "  DYN:%12s             Station %d.%d identified as wired fileserver\n", "", p->p.dstnet, p->p.dststn);
			}

			result = write(econet_fd, p, len);
			err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);

			if (result < 0 && (err == ECONET_TX_JAMMED || err == ECONET_TX_NOCLOCK || err == ECONET_TX_NOCOPY)) // Fatal errors
				break;
			else if (result < 0)
				result = -1 * err;
			
			if (result == len) 
			{
				acknowledged = 1;

				if (p->p.aun_ttype == ECONET_AUN_IMM) // Update last immediate sequence
					network[d].last_imm_seq_sent = p->p.seq;

			}

			// Collision backoff

			if (err == ECONET_TX_COLLISION)	usleep(network[d].station * 1000);

			
		}
		else // Unknown destination type
		{
			fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d Unknown destination\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			break;
		}

		count++;
	}

	if (!acknowledged)
	{
		if ((d != -1) && (network[d].type & ECONET_HOSTTYPE_TWIRE)) // Wire destination - specific types of error
		{
			if (result < 0)
				fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - %s (%02x)\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, econet_strtxerr(err), err);	
			else if (result < len && result >= 0)
				fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - only %d of %d bytes written\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, result, len);	
		}
		else // Non-wire
		{
			fprintf(stderr, "ERROR: to %3d.%3d from %3d.%3d No %s received\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, (p->p.aun_ttype == ECONET_AUN_IMM ? "immediate reply" : "acknowledgment"));
			result = 0;
		}
	}

	return result;

}

// Stub function to wrap around aun_send_internal for compatibility with code which does not send broadcasts to be handled by the local bridge handler
int aun_send (struct __econet_packet_aun *p, int len)
{
	return aun_send_internal(p, len, -1);
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

// Find which trunk a given network is down
short trunk_find (unsigned char net)
{

	int found = 0;
	int counter = 0;

	while (!found && (counter < 256))
	{
		if ((trunks[counter].listensocket >= 0) && (trunks[counter].adv_in[net] == 0xff))
			found = 1;
		else	counter++;
	}

	return (found ? counter : -1);	

}

// Trunk address translation and firewalling
// dir = 0 means inbound on a trunk
// dir = 1 means outbound on a trunk
// Return is FW_ACCEPT; FW_DROP
int trunk_xlate_fw(struct __econet_packet_aun *p, int trunk, unsigned char dir)
{

	struct __fw_entry *fw;

	int ret = FW_ACCEPT;

	if (dir == 1) // Outbound
	{
                if ((p->p.dstnet != p->p.srcnet) && (p->p.srcnet == 0)) // If traffic coming from net 0 (as it will be until AUN devices have a "default route" system), and we are not sending to dstnet which is the same as srcnet, substitute the local network number. Note that this allows a trunk to carry net 0 from one wired econet to another.
                        p->p.srcnet = localnet;

                // Next do address translation

                if (trunks[trunk].xlate_src[p->p.srcnet] != 0xff) // Translate our network number if there is a translation entry
                        p->p.srcnet = trunks[trunk].xlate_src[p->p.srcnet];
	}
	else // Inbound - do firewalling here (no firewalling on outbound traffic)
	{

		if (trunks[trunk].xlate_dst[p->p.dstnet] != 0xff) // Translate inbound
			p->p.dstnet = trunks[trunk].xlate_dst[p->p.dstnet];

		// Convert to net 0 if it is our local network number

		if (p->p.dstnet == localnet) p->p.dstnet = 0;

		// Firewall

		fw = trunks[trunk].head;
			
		while (fw)
		{
			// Matching entry?
			if (	((fw->srcnet == 255) || (fw->srcnet == p->p.srcnet))	
			&&	((fw->srcstn == 255) || (fw->srcstn == p->p.srcstn))
			&&	((fw->dstnet == 255) || (fw->dstnet == p->p.dstnet))
			&&	((fw->dststn == 255) || (fw->dststn == p->p.dststn))
			)
			{
				ret = fw->action;
				break;
			}
			else	fw = fw->next;
		}
					
	}

	if (pkt_debug && (ret == FW_DROP)) // log it
		fprintf (stderr, "FWALL: to %3d.%3d from %3d.%3d FORBIDDEN\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
	
	return ret;

}

// Wait up to timeout ms for a packet from srcnet.srcstn to dstnet.dststn matching AUN type aun_type with 
// sequence number seq. If it arrives, put the packet in *p (if p is not null) and return packet length. Otherwise set *p = NULL and return 0. Any other
// traffic arriving gets put on the packet cache for later processing.
// If returns 1, caller MUST free *p after use.

short aun_wait (unsigned char srcnet, unsigned char srcstn, unsigned char dstnet, unsigned char dststn, unsigned char aun_type, unsigned long seq, short timeout, struct __econet_packet_aun **p)
{

	struct timeval start, now;
	struct __econet_packet_aun in; // Structure we read from the network into
	int r; // Return value from read
	struct pollfd pwait; // Poll structure for waiting for traffic
	struct sockaddr addr;
	int dptr, sptr, trunk; // Pointers into network[] and the trunk number
	int policy; // Result of firewall policy procedure
	unsigned char aun_check_dstnet;

	short received = 0;
	unsigned long diff;
	
	if (p)
		*p = NULL; // Initialize

	sptr = econet_ptr[srcnet][srcstn];
	dptr = econet_ptr[dstnet][dststn];

	trunk = 0; 

	if (sptr == -1)
		trunk = trunk_find(srcnet);

	if ((sptr == -1) && (trunk == -1)) // Source from trunk. Find it, and barf otherwise
		return 0;
	
	if (!is_aun(srcnet, srcstn)) // Shouldn't be being called - barf
	{
		fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - aun_wait() called when distant station is not AUN\n", dstnet, dststn, srcnet, srcstn);
		return 0;
	}

	aun_check_dstnet = dstnet; 

	// Do address trnslation if receiving from trunk
	if (trunk != -1)
	{
		aun_check_dstnet = trunks[trunk].xlate_dst[dstnet];
		if (aun_check_dstnet == 0xff) // No mapping
			aun_check_dstnet = dstnet; // Restore original
		if (aun_check_dstnet == localnet)
			aun_check_dstnet = 0; // net 0 in the config
	}

	if (is_aun(aun_check_dstnet, dststn)) // Shouldn't be being called if destination is AUN. Should be wire or local.
	{
		fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d - aun_wait() called when local station is AUN and we cannot relay (xlate_dstnet = %d)\n", dstnet, dststn, srcnet, srcstn, aun_check_dstnet);
		return 0;
	}

	gettimeofday(&start, 0);

	gettimeofday(&now, 0);

	diff = timediffmsec(&start, &now);

	while ((diff < timeout) && !received)
	{
		if (trunk)
			pwait.fd = trunks[trunk].listensocket;
		else
			pwait.fd = network[dptr].listensocket;

		pwait.events = POLLIN;

		if (poll(&pwait, 1, (timeout - diff)) && (pwait.revents & POLLIN))
		{
			int net_src;

			if (dptr == -1) // Trunk
				r = udp_receive(trunks[trunk].listensocket, &in, ECONET_MAX_PACKET_SIZE+4, &addr);
			else
			{
				r = udp_receive(network[dptr].listensocket, &(in.p.aun_ttype), ECONET_MAX_PACKET_SIZE, &addr);
				if (r > 0) r +=4; // Fake the extra four bytes received so it matches a trunk receipt
			}

			if (r >= 0)
			{
				if (!trunk)
				{
					net_src = econet_find_source_station((struct sockaddr_in *) &addr);
					policy = FW_ACCEPT; // Always accept inbound from configure AUN/IP hosts
				}
				else
					policy = trunk_xlate_fw(&in, trunk, 0); // 0 = Inbound

				if (pkt_debug && !dumpmode_brief) fprintf (stderr, "CACHE: to %3d.%3d from %3d.%3d AUN type %02X, seq %08lX, len %04X received ", 
					network[dptr].network, network[dptr].station,
					(trunk ? in.p.srcnet : (net_src == 0xffff ? 0:network[net_src].network)), 
					(trunk ? in.p.srcstn : (net_src == 0xffff ? 0:network[net_src].station)), 
					in.p.aun_ttype, in.p.seq, r-4);

				if ((policy == FW_ACCEPT) && (trunk || (net_src != 0xffff))) // We know where the traffic arrived from and we're prepared to accept it
				{
	
					if (!trunk) // If not from a trunk, complete the four bytes on the front of the packet
					{
						in.p.dstnet = network[dptr].network; // This is fine, because we were listening on a socket for a single destination station
						in.p.dststn = network[dptr].station;
						in.p.srcnet = network[net_src].network; // The one we found above
						in.p.srcstn = network[net_src].station;
					}
	
					// Wsa this the traffic we were looking for?

					if ((srcnet == in.p.srcnet) && (srcstn == in.p.srcstn) && (aun_check_dstnet == in.p.dstnet) && (dststn == in.p.dststn) && (in.p.aun_ttype == aun_type) && ((in.p.aun_ttype == ECONET_AUN_IMMREP) || in.p.seq == seq)) // Temp - we should make the other bridges put the right reply sequence number on immediate replies...
					{
						if (pkt_debug && !dumpmode_brief) fprintf (stderr, "MATCHED");
	
						in.p.ctrl |= 0x80; 

						// Found the packet we want
						if (p) 
						{
							*p = malloc(r);
							if (*p)
								memcpy(*p, &in, r);
							else // Barf - can't malloc
								return 0;
							dump_udp_pkt_aun(*p, r);
						}

						received = r; // Flag the match
					}
					else if (in.p.aun_ttype == ECONET_AUN_IMM || in.p.aun_ttype == ECONET_AUN_IMMREP || in.p.aun_ttype == ECONET_AUN_DATA) // Cache useful packets
					{
						struct __econet_packet_aun_cache *entry;
	
						// Dear purists, you will not like the next two lines. They acknowledge a data packet before transmission to local or wire.
						// Since the kernel module collapses a 4-way handshake to 2-way in the other direction, so that a sending wire station
						// thinks its packet has got to its destination before the AUN packet hits the UDP stack, still less before it has been
						// acknowledged, then in *this* direction it is hardly much different to acknoweldge an incoming UDP AUN packet before
						// it has gone where it is going... The former is necessary in order to collect a whole packet before an AUN datagram
						// could even be sent, and is thus a necesary compromise for this to work at all. The latter is simply a comparable and
						// consistent compromise in the opposite direction!

						if (in.p.aun_ttype == ECONET_AUN_DATA)
							aun_acknowledge(&in, ECONET_AUN_ACK);

						// By here, any necessary trunk translation / firewalling has happened, so what we put in the cache is a *translated* packet in internal form

						entry = malloc (sizeof(struct __econet_packet_aun_cache));
	
						if (!entry)
							return 0; 
	
						entry->p = malloc(r);
						if (!entry->p) // Can't malloc
						{
							free(entry);
							return 0;
						}
	
						memcpy(entry->p, &in, r); // Copy the packet

						entry->next = NULL;
						entry->size = r; // Size of p inc 4 bytes for the AUN header - i.e. the value we pass to aun_send to send the packet

						gettimeofday(&(entry->tstamp), 0);
	
						if (pkt_debug && !dumpmode_brief) fprintf (stderr, "CACHED ");
	
						if (!cache_head) // Cache is empty
						{
							if (pkt_debug && !dumpmode_brief) fprintf (stderr, "as first cache entry");
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
									if (pkt_debug && !dumpmode_brief) fprintf (stderr, "by replacing packet cache entry at %p", q);
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
								if (pkt_debug && !dumpmode_brief) fprintf (stderr, "on the cache tail");
								cache_tail->next = entry;
								cache_tail = entry;
							}
						}
					}
					else if (pkt_debug && !dumpmode_brief) fprintf (stderr, "DISCARDED");

					if (pkt_debug && !dumpmode_brief) fprintf (stderr, "\n");
				}
				else if (pkt_debug && !dumpmode_brief) fprintf (stderr, "JETTISONED\n");
			}
			else
			{
				if (pkt_debug && !dumpmode_brief) fprintf (stderr, "CACHE: Network read error\n");
					return 0; // Read error
			}

		}	

		gettimeofday(&now, 0);

	        diff = timediffmsec(&start, &now);

	}
	

	return received;

}

// Returns 1 if net.stn is either AUN/IP or trunk

unsigned short is_aun(unsigned char net, unsigned char stn)
{
	if ((econet_ptr[net][stn] == -1) || (network[econet_ptr[net][stn]].type & ECONET_HOSTTYPE_TDIS))
		return 1;
		
	return 0;
}

int main(int argc, char **argv)
{

	int s;
	int opt;
	int dump_station_table = 0;
	short fs_bulk_traffic = 0;

	unsigned short from_found, to_found; // Used to see if we know a station or not

	struct __econet_packet_aun rx;

	memset(&network, 0, sizeof(network));
	memset(&econet_ptr, 0xff, sizeof(econet_ptr));
	memset(&fd_ptr, 0xff, sizeof(fd_ptr));
	memset(&trunk_fd_ptr, 0xff, sizeof(trunk_fd_ptr));

	// Clear the packet cache

	cache_head = cache_tail = NULL;

	seq = 0x46; /* Random number */

	fs_sevenbitbodge = 1; // On by default

	while ((opt = getopt(argc, argv, "bc:dfilnqsxzh7")) != -1)
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
                        case 'x': use_xattr = 0; break;
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
\t-x\tNever use filesystem extended attributes and force use of dotfiles\n\
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

					fprintf (stderr, "%3d %3d %5s %-5s %-4s %-30s %5d %c %c %c %s%s%s%s%s%s%s\n",
						network[p].network,
						network[p].station,
						buffer,
						(network[p].type & ECONET_HOSTTYPE_TDIS) ? "Dist." :
							(network[p].type & ECONET_HOSTTYPE_TWIRE) ? "Wire" : 
							(network[p].type & ECONET_HOSTTYPE_TNAMEDPIPE) ? "Unix" : "Local",
						(network[p].type & ECONET_HOSTTYPE_TAUN ? "AUN" : "RAW"),
						(network[p].type & ECONET_HOSTTYPE_TDIS) ? network[p].hostname : "",
						(network[p].type & ECONET_HOSTTYPE_TNAMEDPIPE) ? 0 : network[p].port,
						((network[p].servertype & ECONET_SERVER_FILE) ? 'F' : ' '),
						((network[p].servertype & ECONET_SERVER_PRINT) ? 'P' : ' '),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? 'S' : ' '),
						((network[p].servertype & ECONET_SERVER_FILE) ? network[p].fs_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_FILE) ? " " : ""),
						((network[p].servertype & ECONET_SERVER_PRINT) ? network[p].print_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_PRINT) ? " " : ""),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? network[p].socket_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? " " : ""),
						((network[p].type & ECONET_HOSTTYPE_TNAMEDPIPE) ? network[p].named_pipe_filename : "")
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

					fprintf (stderr, "\n%3d listening on port %5d via %s:%d\n", n, trunks[n].listenport, trunks[n].hostname, trunks[n].port);
					for (s = 0; s < 256; s++)
						if (trunks[n].xlate_src[s] != 0xff) fprintf (stderr, "    XLATE (net)  from %3d local to %3d remote\n", s, trunks[n].xlate_src[s]);

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

	// If in bridge query mode, we need to enable station nativebridgenet.0 so that the kernel module will deal with it
	// Otherwise our bridge query responses won't work

	if (bridge_query && nativebridgenet)
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

	for (s = 0; s <= pmax; s++)
		pset[s].events = POLLIN;

	// Set up our fake BeebMem if available

	{

		FILE *f;

		beebmem = malloc(65536);
		
		if (beebmem && (f = fopen("/etc/econet-gpio/BEEBMEM", "r")))
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

			//if (pkt_debug) fprintf(stderr, "Beeb Memory loaded\n");
			
		}
		else if (beebmem)
		{
			free(beebmem);
			beebmem = NULL;
		}
		
	}
	
	if (pkt_debug)
		fprintf(stderr, "Awaiting traffic.\n\n");

	/* Wait for traffic */

	fs_bulk_traffic = fs_dequeuable();

	// Do a bridge reset - Announce our presence

	econet_bridge_process (NULL, 0, -1); // Self-initiated reset
	gettimeofday(&last_bridge_reset, 0);

	while (cache_head || fs_bulk_traffic || poll((struct pollfd *)&pset, pmax+(wire_enabled ? 1 : 0), -1)) // If there are packets in the cache, process them. If there's cache or bulk traffic, only poll for 10ms so that we pick up traffic quickly if it's there.
	{

/*
		struct timeval now;

		// See if it's time for a bridge reset

		gettimeofday(&now, 0);

		if ((timediffmsec(&last_bridge_reset, &now)/1000) > (ECONET_BRIDGE_RESET_FREQ))
		{
			econet_bridge_process (NULL, 0, -1); // Self-initiated reset
			gettimeofday(&last_bridge_reset, 0);
		}
*/

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

				rx.p.seq = get_local_seq(rx.p.srcnet, rx.p.srcstn);

				if (rx.p.aun_ttype == ECONET_AUN_IMMREP) // Fudge - assume the immediate we have received is a reply to the last one we sent. Maybe make this more intelligent.
					rx.p.seq = network[econet_ptr[rx.p.dstnet][rx.p.dststn]].last_imm_seq_sent;

				network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].last_transaction = time(NULL);

				// Fudge the AUN type on port 0 ctrl 0x85, which is done as some sort of weird special 4 way handshake with 4 data bytes on the Scout - done as "data" and the kernel module works out that the first 4 bytes in the packet go on the scout and the rest go in the 3rd packet in the 4-way

				if (rx.p.aun_ttype == ECONET_AUN_IMM && rx.p.ctrl == 0x85) // Fudge-a-rama. This deals with the fact that NFS & ANFS in fact do a 4-way handshake on immediate $85, but with 4 data bytes on the "Scout". Those four bytes are put as the first four bytes in the data packet, and a receiving bridge will strip them off, detect the ctrl byte, and do a 4-way with the 4 bytes on the Scout, and the remainder of the data in the "data" packet (packet 3/4 in the 4-way). This enables things like *remote, *view and *notify to work.
					rx.p.aun_ttype = ECONET_AUN_DATA;

				aun_send_internal (&rx, r, 0);

			}
		}

		// Next, see if there are any cache entries to deal with

		while (cache_head) // If packet in cache, deal with it
		{
			struct __econet_packet_aun_cache *p;
			struct timeval now;

			p = cache_head;

			cache_head = cache_head->next;

			gettimeofday(&now, 0);

			if (timediffmsec(&(p->tstamp), &now) <= 500) // If newer than0.5s 
			{
				if (pkt_debug && !dumpmode_brief)	fprintf (stderr, "CACHE: to %3d.%3d from %3d.%3d packet type %02X length %04X RETRIEVED from cache\n", p->p->p.dstnet, p->p->p.dststn, p->p->p.srcnet, p->p->p.srcstn, p->p->p.aun_ttype, p->size);
				aun_send(p->p, p->size);
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

			if ((pset[realfd].revents & POLLIN) && (trunk_fd_ptr[pset[realfd].fd] != -1)) // Traffic arriving on trunk
			{
				struct __econet_packet_aun p;

				int r, count, from_found = 0xffff;
				unsigned char policy;
	
				r = udp_receive (pset[realfd].fd, (void *) &p, sizeof(p), (struct sockaddr * restrict) &src_address);

				if (r < 0) continue; // Debug produced in udp_receive

				// Which peer did it turn up from?

				count = 0;

				while ((from_found == 0xffff) && (count < 256))
				{

//					fprintf (stderr, "Checking trunk %d\n", count);

					if (
// May need some ntohs or ntohl here somewhere..?? TODO
						trunks[count].listensocket >= 0 // Active trunk
					&&	((((struct sockaddr_in *) (trunks[count].addr->ai_addr))->sin_addr.s_addr) == src_address.sin_addr.s_addr) // Someone we know about
					&&	((((struct sockaddr_in *) (trunks[count].addr->ai_addr))->sin_port) == (src_address.sin_port))
					)
						from_found = count;
					else	count++;

				}

				if (from_found == 0xffff) // Traffic arrived on a trunk but either not from someone friendly, or it was but not on a network we think should be arriving on that trunk
				{
					// Dump it.
					fprintf (stderr, "TRUNK: to %3d.%3d from %3d.%3d received on trunk %04X unrecognized\n", p.p.dstnet, p.p.dststn, p.p.srcnet, p.p.srcstn, (from_found == 0xffff ? 0xffff : count));
					continue;
				}
				else if (trunks[from_found].adv_in[p.p.srcnet] != 0xff && (p.p.port != 0x9c)) // Check if this was a network we were expecting from that source, and it wasn't bridge traffic
				{
					fprintf (stderr, "FWALL: to %3d.%3d from %3d.%3d received on trunk %04X from unadvertized source network %d\n", p.p.dstnet, p.p.dststn, p.p.srcnet, p.p.srcstn, from_found, p.p.srcnet);
					continue;
				}
			

				policy = trunk_xlate_fw(&p, count, 0); // 0 = inbound translation && firewalling

				if (p.p.aun_ttype == ECONET_AUN_DATA)
					aun_acknowledge(&p, ECONET_AUN_ACK);

				if ((p.p.aun_ttype == ECONET_AUN_BCAST) && from_found != 0xffff) // Dump to local in case it's bridge stuff - but only if we knew where it came from
					econet_handle_local_aun(&p, r, from_found);

				// Note that aun_send now dumps traffic we refuse to forward so we don't need to check here

				if ((policy == FW_ACCEPT) && ((p.p.aun_ttype == ECONET_AUN_DATA) || (p.p.aun_ttype == ECONET_AUN_IMM) || (p.p.aun_ttype == ECONET_AUN_IMMREP)))
					aun_send(&p, r);
			}
			else if (pset[realfd].revents & POLLIN) // Boggo standard AUN/IP traffic from single station, or on a named pipe
			{
				/* Read packet off UDP here */
				int  r;
				struct __econet_packet_aun p;

				//int count;

				if (network[fd_ptr[pset[realfd].fd]].type & ECONET_HOSTTYPE_TNAMEDPIPE)
				{
					r = read(pset[realfd].fd, (void *) &p, sizeof(p)); // note, we read a full 12 byte AUN+ type header here
			
					if (r < 0) continue; // Something went wrong

					// The received packet will have a valid destination on it, but we will need to fille in the source

					p.p.srcnet = network[fd_ptr[pset[realfd].fd]].network;
					p.p.srcstn = network[fd_ptr[pset[realfd].fd]].station;

					network[fd_ptr[realfd]].last_transaction = time(NULL);
					
					if (p.p.aun_ttype == ECONET_AUN_DATA)
						aun_acknowledge(&p, ECONET_AUN_ACK); // Yes, I know...

					if (p.p.seq > network[fd_ptr[realfd]].last_seq_ack)
						network[fd_ptr[pset[realfd].fd]].last_seq_ack = p.p.seq;	

					if ( !( (p.p.aun_ttype == ECONET_AUN_ACK) || (p.p.aun_ttype == ECONET_AUN_NAK) ) ) // Ignore those sorts of packets - we don't care. If we're interested in them, we pick them up in aun_wait
						aun_send(&p, r); // No +4 here because we got a full sized packet to start with
				
				}
				else
				{
					// From here on is non-named pipe code
	
					r = udp_receive(pset[realfd].fd, (void *) &(p.p.aun_ttype), sizeof(p)-4, (struct sockaddr * restrict) &src_address);
	
					if (r< 0) continue; // Debug produced in udp_receive
	
					/* Look up where it came from */
	
					from_found = econet_find_source_station (&src_address); // 0xffff;
	
					/* Now where did was it going /to/ ? We can find that by the listening socket number */
		
					to_found = fd_ptr[pset[realfd].fd];
	
					if ((from_found == 0xFFFF) && (learned_net != -1) & (to_found != 0xFFFF)) // See if we can dynamically allocate a station number to this unknown traffic source, since we know where the traffic going, and we have learning mode on, but we don't know where the traffic came *from* 
					{
						unsigned short stn_count;
						struct sockaddr_in *s;
	
						stn_count = 0; 
			
						s = &src_address;
	
						while (stn_count < stations && from_found == 0xFFFF)
						{
							if (network[stn_count].is_dynamic && (network[stn_count].last_transaction < (time(NULL) - ECONET_LEARNED_HOST_IDLE_TIMEOUT))) // Found a dynamic station which has idled out
							{
	
								struct __econet_packet_aun bye;
								int netcount;
	
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
											
											aun_send(&bye, 16);
	
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
	
					if ((from_found != 0xffff) && (to_found != 0xffff)) // We know source & destination stations
					{
	
						// Complete the internal format packet
	
						p.p.srcnet = network[from_found].network;
						p.p.srcstn = network[from_found].station;
						p.p.dstnet = network[to_found].network;
						p.p.dststn = network[to_found].station;
	
						network[from_found].last_transaction = time(NULL);
						
						if (p.p.aun_ttype == ECONET_AUN_DATA)
							aun_acknowledge(&p, ECONET_AUN_ACK); // Yes, I know...
	
						if (p.p.seq > network[from_found].last_seq_ack)
							network[from_found].last_seq_ack = p.p.seq;	
	
						if ( !( (p.p.aun_ttype == ECONET_AUN_ACK) || (p.p.aun_ttype == ECONET_AUN_NAK) ) ) // Ignore those sorts of packets - we don't care. If we're interested in them, we pick them up in aun_wait
							aun_send(&p, r+4);
	
					}
					else	
						if (pkt_debug) fprintf (stderr, "ERROR: UDP packet received on FD %d; From%s found, To%s found (pointer %d)!\n", pset[realfd].fd, ((from_found != 0xffff) ? "" : " not"), ((to_found != 0xffff) ? "" : " not"), to_found);
				}
			}
		
		}
	
		fs_bulk_traffic = fs_dequeuable(); // In case something got put there from UDP/Wire/Local above

		if (fs_bulk_traffic)	fs_dequeue(); // Do bulk transfers out.
	
		fs_bulk_traffic = fs_dequeuable(); // Reset flag for next while() loop check

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

