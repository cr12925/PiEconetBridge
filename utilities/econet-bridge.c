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
#include <stdint.h>
#include <inttypes.h>
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
extern int fs_stn_logged_in(int, unsigned char, unsigned char); // Used to identify if a user is logged in
extern void fs_get_username(int, int, char *); // Returns username or null first byte into the char* array
extern short fs_dequeuable();
extern void sks_poll(int);
extern int8_t fs_get_user_printer(int, unsigned char, unsigned char);

short aun_wait (unsigned char, unsigned char, unsigned char, unsigned char, unsigned char, uint32_t, short, struct __econet_packet_aun **);
extern unsigned short fs_quiet, fs_noisy;
extern short fs_sevenbitbodge, fs_sjfunc; // 7-bit acorn date bodge, fs_sjfunc turns on MDFS-only functionality in the fileserver(s)
extern short use_xattr; // When set use filesystem extended attributes, otherwise use a dotfile
extern short normalize_debug;

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

#define DEVICE_PATH "/dev/econet-gpio"

int aun_send (struct __econet_packet_aun *, int);
unsigned short is_aun(unsigned char, unsigned char);
int trunk_xlate_fw(struct __econet_packet_aun *, int, unsigned char);
short trunk_find (unsigned char);
int aun_trunk_send (struct __econet_packet_aun *, int);
int aun_trunk_send_internal (struct __econet_packet_aun *, int, int);

void dump_pkt_data(unsigned char *, int, unsigned long);

char * econet_strtxerr(int);

struct pollfd pset[65536];
int pmax;
int econet_fd;
int seq;
int pkt_debug = 0;
int dumpmode_brief = 0;
int wire_enabled = 1;
int spoof_immediate = 0; // Changed from 1
int wired_eject = 1; // When set, and a dynamic address is allocated to an unknown AUN station, this will cause the bridge to spoof a '*bye' equivalent to fileservers it has learned about on the wired network
short learned_net = -1;
int wire_tx_errors = 0; // Count of successive errors on tx to the wire - if it gets too high, we'll do a chip reset
unsigned char last_net = 0, last_stn = 0;
char *printhandler = NULL; // Filename of generic print handling routine

int start_fd = 0; // Which index number do we start looking for UDP traffic from after poll returns? We do this cyclicly so we give all stations an even chance

unsigned short numtrunks; // Only used to determine whether to display trunk info on summary at startup

char cfgpath[512] = "/etc/econet-gpio/econet.cfg";

char *beebmem;

unsigned char econet_stations[8192];

#define ECONET_AUN_MAX_TX 10
#define ECONET_WIRE_MAX_TX 20  // Attempt to improve reliability on a busy network
// Time before we send another packet on the Econet - Query whether we should be doing this at all (looks like we don't actually use it anywhere)
#define ECONET_RETX_INTERVAL_MSEC 75
// AUN Ack wait time in ms
#define ECONET_AUN_ACK_WAIT_TIME 200
// Mandatory gap between last tx to or rx from an AUN host so that it doesn't get confused (ms)
#define ECONET_AUN_INTERPACKET_GAP 50

struct __econet_packet_aun_cache {
	struct __econet_packet_aun *p;
	struct __econet_packet_aun_cache *next;
	unsigned int size; // Size of p, less its 4 byte header.
	struct timeval tstamp; // When it went in the cache - used to expire stale packets
	unsigned short tx_count; // Initially set to 0. Increases each time there is a TX attempt. After ECONET_AUN_MAX_TX is reached, the packet gets ditched (along with everything to this host from the same source, so that we ditch any bulk transfer queues that might be lurking in the queue). ONLY RELEVANT TO WIRE STATIONS, AND NON-TRUNK AUN STATIONS. For local, we are guaranteed to transmit successfully. For AUN, the packet will get taken off the queue when an ACK or NAK arrives. For Wire, it gets taken off the queue when there is a successful transmit. For trunks, endpoint retransmission is the job of the last bridge in the chain
	// tx_count is also used to work out, based on tstamp, whether it's time for another retransmission (e.g. tx_count = 2, next transmission needs to be at tstamp+(2 x ECONET_RETX_INTERVAL_MSEC) msecs
};

// Printer status

// Input status
#define PRN_IN_READY 	0x00
#define PRN_IN_BUSY 	0x01
#define PRN_IN_JAMMED_SOFTWARE	0x02
#define PRN_IN_JAMMED_OFFLINE	0x03
#define PRN_IN_JAMMED_DISCFULL	0x04
#define PRN_IN_UNAUTHORISED	0x05
#define PRN_IN_GOINGOFFLINE	0x06
#define PRN_IN_RESERVED		0x07

// Output status (from server to printer)
#define PRN_OUT_READY	0x00
#define PRN_OUT_OFFLINE	0x08
#define PRN_OUT_JAMMED	0x10

#define PRN_STATUS_DEFAULT (PRN_IN_READY | PRN_OUT_READY)

// Printer control
#define PRNCTRL_SPOOL 0x08 // Spool to disc or direct to printer (we always spool)
#define PRNCTRL_ACCOUNT 0x04 // Account ownership required
#define PRNCTRL_ANON 0x02 // Anonymouse use allowed. We set this by default
#define PRNCTRL_ENABLE 0x01 // Printing enabled or not. We default to yes.

#define PRNCTRL_DEFAULT (PRNCTRL_SPOOL | PRNCTRL_ANON | PRNCTRL_ENABLE)

// Client to Printer server port &9f Query codes

#define PRN_QUERY_NAME	6
#define PRN_QUERY_STATUS	1

// Maximum printers per emulated server
#define MAX_PRINTERS 8

struct __printer {
	char name[7]; // printer name - max 6 characters + null
	uint8_t status; // Status bits - see defs above
	uint8_t control; // Control bits
	unsigned short user; // Only this user can use the printer
	char unixname[100]; // Unix printer name
	char banner[24]; // Banner filename. SJ has this max 23 characters
};

// Holds data from econet.cfg file
struct econet_hosts {							// what we we need to find a beeb?
// Econet net & station of this host
	unsigned char station;
	unsigned char network;

// IP Address / port data
	struct in_addr s_addr;
	char hostname[250];
	unsigned int port;
	int listensocket; /* One socket for each thing on the Econet wire - -2 if on UDP because we don't listen "for" those, we only transmit /to/ them */

// Host type information
	short type;

// Locally emulated server type(s)
	short servertype;

// File server variables
	char fs_serverparam[1024];
	int fileserver_index;

// Print server variables
	char print_serverparam[1024];
	uint8_t numprinters;
	struct __printer printers[MAX_PRINTERS]; // Defined printers. All valid up to printers[numprinters-1]
	uint8_t printer_priorities[MAX_PRINTERS]; // List of indices into printers[] to indicate auto priority - see FS 65 function 0x03, 0x04
	
// Socket server parameter
	char socket_serverparam[1024];
	int sks_index;

// PSet index
	int pind; /* Index into pset for this host, if it has a socket */

// AUN ACK / IMM tracking
	uint32_t seq, last_imm_seq_sent; // Our local sequence number, and the last immediate sequence number sent to this host (for wire hosts) so that we acknowledge with the same immediate sequence number
	uint32_t last_seq_ack; // The last sequence number which was acknowledged to this host if it is AUN. If we have already acknoweldged a given sequence number, we *don't* attempt to re-transmit the data onto the Econet Wire, but we do acknowledge the packet again
	unsigned char last_imm_ctrl, last_imm_net, last_imm_stn; // Designed to try and avoid adding high bit back on where it's an immediate transmitting a characer for *NOTIFY - net & stn are source net & stn of the last immediate going to this host
	struct timespec last_wire_tx;
	struct timeval aun_last_tx; // Last AUN tx to an AUN machine. Used to time out the ACK/IMM wait below. (The 'awaited' value.)
	struct timeval aun_last_rx; // When we received a packet from the AUN machine so we can time out the ACK / IMMREP timer on our own transmits to it
	uint32_t ackimm_seq_awaited; // Sequence number we are waiting for an ACK for (or could be Immediate reply) FROM the AUN machine
	struct __econet_packet_aun_cache *aun_head, *aun_tail; // Output queue for AUN clients, so that we can re-tx unacknowledged packets a few times
	uint32_t ackimm_seq_tosend; // Sequence number FROM the AUN machine which needs acknowledging

	unsigned char is_dynamic; // 0 = ordinary fixed host; 1 = host which can be assigned to unknown incoming traffic
	unsigned char is_wired_fs; // 0 = not a fileserver; 1 = we have seen port &99 traffic to this host and it is on the wire, so we think it's a fileserver. This is used to spoof *bye equivalents when a station number of dynamically allocated to an unknown AUN source, so that the previous user of the same address's login cannot be re-used
	unsigned long last_transaction;
	struct timeval last_bridge_reply;
// These only apply to wire hosts - Bridge announcements
	unsigned char adv_in[256], adv_out[256]; // Advertised networks. _in received from other end, _out is last advert sent by us

// Trunk variables
	unsigned char filter_in[256], filter_out[256]; // Filter masks for in & out

// Named pipe filename if this is a named pipe host
	char named_pipe_filename[200];
	int pipewritesocket; /* file descriptor for the socket we write to when this connection is a named pipe */
	int pipeudpsocket; /* Socket descriptor for inbound UDP AUN traffic to this host */

};

// Wire packet queue & priority system

struct __econet_packet_aun_cache *wire_head = NULL, *wire_tail = NULL;
short wire_prio_out_srcnet, wire_prio_out_srcstn, wire_prio_out_dstnet, wire_prio_out_dststn, wire_prio_out_auntype, wire_prio_out_port; // -1 = value unused. Used to allow a packet headed for this machine to jump the queue and go first, e.g. an immediate reply the machine is waiting for. Basically used to decide whether we put a new packet destined for this machine on the head or the tail of the queue
struct timeval wire_prio_expiry; // Time at which the priority values in the line above expire and become invalid

// Econet hosts lists & FD pointers back into the various arrays

struct econet_hosts network[65536]; // Hosts we know about / listen for / bridge for
short econet_ptr[256][256]; /* [net][stn] pointer into network[] array. */
uint16_t last_ps[256][256]; // Last print (emulated) print server used by each station. Used to re-set default printer if the station uses a new print server
uint8_t last_prn[256][256]; // Last printer index used by a station on the current print server. Gets re-set to 0 on change of PS (i.e. when a job gets sent to an emulated PS which is not the current one in last_ps).
short fd_ptr[65536]; /* Index is a file descriptor - yields index into network[] */
int pipeudpsockets[65536]; /* Array of descriptors which are actually UDP sockets receiving traffic for named pipes, so we can sift those out early */
short trunk_fd_ptr[65536]; /* Index is a file descriptor - pointer to index in trunks[] */
int stations; // How many entries in network[]
unsigned long aun_queued = 0; // Number of packets in AUN network[] entries
unsigned char queue_debug = 0; // Whether we produce verbose queueing diagnostics

struct timeval last_bridge_reset;


// Bridge control arrays
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
struct __econet_packet_aun_cache *trunk_head = NULL, *trunk_tail = NULL;

// The network number we report in a first bridge reply. It's the first distant network we learn about from the config
// Eventually we may listen for bridge announcements and update it from that

short nativebridgenet = 0, localnet = 0;

struct sockaddr_in src_address;

// Packet Buffers
struct __econet_packet_udp udp_pkt;
struct __econet_packet_aun aun_pkt;

// Locally Emulated machines
uint32_t local_seq = 0x00004000;

// Local Print Server state

#define MAXPRINTJOBS 10

struct printjob {
	short net, stn;
	//short ctrl; // Oscillates betwen &81, &80
	short port;
	unsigned char ctrlbit; // Initialized at PS logon, and then tracked
	FILE *spoolfile;
	unsigned char printer_index;
	char unixname[20];
	char username[20];
	char name[10];
};

struct printjob printjobs[MAXPRINTJOBS];

struct last_printer {
	short networkp; // Index into network[] of the last emulated print server this station used
	unsigned char printer_index; // Index into the printer list in networkp[] entry for the emulated server (not the priority number)
};

struct last_printer last_printers[256][256];

// Local bridge query status
int bridge_query = 1;

unsigned long timediffmsec(struct timeval *s, struct timeval *d)
{

	return (((d->tv_sec - s->tv_sec) * 1000) + ((d->tv_usec - s->tv_usec) / 1000));

}


#define QUEUE_HEAD 1
#define QUEUE_TAIL 2
#define QUEUE_AUTO 3

// Puts packet *p on the queue starting at *head. If headortail = QUEUE_HEAD, it will go at *head; if QUEUE_TAIL, then at *tail; if AUTO then it will decide based
// on whether the current priority settings for this host require it to be prioritised
// ptr is a pointer into the network[] array for the host in question, so we can find the priority settings
// This will COPY p from its current memory and malloc a new structure for the queue
void econet_enqueue (struct __econet_packet_aun *p, int len, unsigned char headortail)
{

	struct timeval now;
	unsigned char placeat = QUEUE_TAIL;
	struct __econet_packet_aun *p_entry;
	struct __econet_packet_aun_cache *q_entry;

	gettimeofday(&now, 0);

	if (queue_debug)	fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d len 0x%04X request  wire   enqueue mode %02X ",
		p->p.dstnet, p->p.dststn,
		p->p.srcnet, p->p.srcstn,
		len,
		headortail);

	if (headortail == QUEUE_AUTO) // See if it's prioritized
	{
		if (
			((wire_prio_out_srcnet != -1 || wire_prio_out_srcstn != -1 || wire_prio_out_dstnet != -1 || wire_prio_out_dststn != -1 || wire_prio_out_auntype != -1 || wire_prio_out_port == -1)) // Some sort of priority set
		&&	(timediffmsec(&(wire_prio_expiry), &now) < 0) // I.e. now is before expiry
		&&	(
				(wire_prio_out_srcnet == -1 || (wire_prio_out_srcnet == p->p.srcnet))
			&&	(wire_prio_out_srcstn == -1 || (wire_prio_out_srcstn == p->p.srcstn))
			&&	(wire_prio_out_dstnet == -1 || (wire_prio_out_dstnet == p->p.dstnet))
			&&	(wire_prio_out_dststn == -1 || (wire_prio_out_dststn == p->p.dststn))
			&&	(wire_prio_out_auntype == -1 || (wire_prio_out_auntype == p->p.aun_ttype))
			&&	(wire_prio_out_port == -1 || (wire_prio_out_port == p->p.port))
			)
		)
			placeat = QUEUE_HEAD;
		if (queue_debug) fprintf (stderr, "placing on %s ", (placeat == QUEUE_HEAD ? "head" : "tail"));
	
	}

	p_entry = malloc(len);
	if (!p_entry) // Malloc failed
	{
		if (queue_debug)	fprintf (stderr, ": main malloc failed!\n");
		return;
	}

	q_entry = malloc(sizeof(struct __econet_packet_aun_cache));
	if (!q_entry) // Malloc failed
	{
		if (queue_debug)	fprintf (stderr, ": packet malloc failed!\n");
		free(p_entry);
		return;
	}

	memcpy(p_entry, p, len);
	q_entry->p = p_entry;
	q_entry->size = len;
	q_entry->next = NULL;
	q_entry->tx_count = 0;
	memcpy(&(q_entry->tstamp), &now, sizeof(struct timeval));

	// Is the queue empty so it doesn't matter where we put this?
	if (wire_head == NULL)
		wire_head = wire_tail = q_entry;
	else if (placeat == QUEUE_HEAD)
	{
		q_entry->next = wire_head;
		wire_head = q_entry;
	}
	else
	{
		wire_tail->next = q_entry;
		wire_tail = q_entry;
	}

	if (queue_debug) fprintf (stderr, "- queued\n");

	return;

}

int econet_general_enqueue(struct __econet_packet_aun_cache **head, struct __econet_packet_aun_cache **tail, struct __econet_packet_aun *p, int len)
{

	struct timeval now;
	struct __econet_packet_aun *p_entry;
	struct __econet_packet_aun_cache *q_entry;

	if (queue_debug)	fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d len 0x%04X request general enqueue\n",
		p->p.dstnet, p->p.dststn,
		p->p.srcnet, p->p.srcstn,
		len);

	gettimeofday(&now, 0);
	p_entry = malloc(len);
	if (!p_entry) // Malloc failed
	{
		if (queue_debug)	fprintf (stderr, "QUEUE: main malloc failed!\n");
		return 0;
	}

	q_entry = malloc(sizeof(struct __econet_packet_aun_cache));
	if (!q_entry) // Malloc failed
	{
		if (queue_debug)	fprintf (stderr, "QUEUE: packet malloc failed!\n");
		free(p_entry);
		return 0;
	}

	memcpy(p_entry, p, len);
	q_entry->p = p_entry;
	q_entry->size = len;
	q_entry->next = NULL;
	q_entry->tx_count = 0;
	memcpy(&(q_entry->tstamp), &now, sizeof(struct timeval));

	// Is the queue empty so it doesn't matter where we put this?
	if (*head == NULL)
		*head = *tail = q_entry;
	else
	{
		(*tail)->next = q_entry;
		(*tail) = q_entry;
	}

	return 1;

}

void econet_general_dumphead(struct __econet_packet_aun_cache **head, struct __econet_packet_aun_cache **tail) // see econet_dumphead() - this is the trunk equivalent
{

	struct __econet_packet_aun_cache *q_entry;

	q_entry = *head;

	if (queue_debug) fprintf (stderr, "QUEUE: Dumping packet at queue head %p\n", *head);

	if (q_entry)
	{
		*head = (*head)->next;
		if (!(*head))
			*tail = NULL;
		free (q_entry->p);
		free (q_entry);
	}


}

// cache_pos = 0 means put this packet on the tail of the queue if it collides. 1 = put it on the head, because that's where it came from
unsigned int econet_write_wire(struct __econet_packet_aun *p, int len, int cache_pos)
{

	int err = ECONET_TX_JAMMED; // Default
	int result;

		result = write(econet_fd, p, len);
	
		err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);

		if (err == ECONET_TX_NOCLOCK || err == ECONET_TX_NOCOPY || result != len)
			return (-1 * err);

		if (err == ECONET_TX_INPROGRESS || err == ECONET_TX_DATAPROGRESS)
		{
			struct timeval start, now;

			gettimeofday(&start, 0);
			gettimeofday(&now, 0);

			// Wait for TX to complete
			err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
			while ((err == ECONET_TX_INPROGRESS || err == ECONET_TX_DATAPROGRESS) && (timediffmsec(&start, &now) < ((2 + ((len+1024) / 1024) * 41)) )) // 1Kb on the wire is < 50ms. So 30Kb is < 150ms.
			{
				gettimeofday(&now, 0);
				err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
			}

			if (err == ECONET_TX_SUCCESS)
			{
				return len;
			}

		}

	return (-1 * err);

}

int econet_write_general(struct __econet_packet_aun *p, int len)
{
	int trunk, ptr;

	trunk = trunk_find(p->p.dstnet);
	ptr = econet_ptr[p->p.dstnet][p->p.dststn];

	if (ptr != -1 || p->p.aun_ttype == ECONET_AUN_BCAST) // A station we know
	{
		// What sort of destination?
		
		if ((network[ptr].type & ECONET_HOSTTYPE_TWIRE) || (ptr == -1 && p->p.aun_ttype == ECONET_AUN_BCAST)) // WIRE, or an unknown station and it's a broadcast
			return econet_write_wire(p, len, 0); // Will eventually get rid of parameter 3!
		else if (network[ptr].type & ECONET_HOSTTYPE_TDIS) // AUN
		{
			struct sockaddr_in n;
			int sender;
			int result;

			n.sin_family = AF_INET;
			n.sin_port = htons(network[ptr].port);
			n.sin_addr = network[ptr].s_addr;

			// Since AUN hosts can't talk to trunks, we should be able to safely look up the sending host

			sender = econet_ptr[p->p.srcnet][p->p.srcstn];

			result = sendto(
				(network[sender].type & ECONET_HOSTTYPE_TNAMEDPIPE) ? network[sender].pipeudpsocket : network[sender].listensocket,  // If it's a named pipe, we don't send from listensocket, we send from pipeudpsocket
				&(p->p.aun_ttype), len-4, MSG_DONTWAIT, (struct sockaddr *)&n, sizeof(n));
			
			if (result == len-4) return len; // Because we drop the 4 header bytes off!
			else return result;

		}
		else if (network[ptr].type & ECONET_HOSTTYPE_TNAMEDPIPE) // Named Pipe
		{
			if (network[ptr].pipewritesocket != -1)
			{
				struct __econet_packet_pipe delivery;

				int r;

				delivery.length_low = len & 0xff;
				delivery.length_high = (len >> 8) & 0xff;

				memcpy (&(delivery.dststn), p, len);

				r = write(network[ptr].pipewritesocket, &delivery, len+2);

				if (r == (len+2)) return r-2;
				else return r;
			}
			else	
			{
				if (pkt_debug) fprintf (stderr, "PIPE : Pipe write socket not open\n");
				return -1; // The other end of the named pipe isn't open
			}
		}
		else
		{
			fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d Unknown destination type (0x%02x) - cannot route\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, network[ptr].type);
			return -1;
		} // NB, Local transmission handled on arrival

	}
	else if (trunk >= 0) // On a trunk
		return aun_trunk_send(p, len);
	else
	{
		fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d Cannot route\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
		return -1;
	}

}

// Get index number of printer (not priority number, but the index into network[].printers)
// Or return -1 if no such printer.

int8_t get_printer(unsigned char net, unsigned char stn, char *pname) 
{

	uint8_t printindex;
	char pnamepad[7];

	int netindex;

	netindex = econet_ptr[net][stn];

	if (netindex == -1) return -1; // Can't find that station defined locally.

	snprintf(pnamepad, 7, "%-6.6s", pname);

	printindex = 0;

	while (printindex < network[netindex].numprinters)
	{
		if (!strncasecmp(network[netindex].printers[printindex].name, pnamepad, 6))
			return printindex;
		printindex++;
	}

	return -1; // not found if we get here
}

void econet_readconfig(void) 
{
	// This reads a config file in like the BeebEm One.
	// However, stations with IP address 0.0.0.0 are on the Econet wire.
	// We listen on all IP addresses with the specified port for each one.
	// Stations with real IP addresses are out on the internet (or potentially on
	// The local machine if some sort of emulator is running - e.g. BeebEm
	
	FILE *configfile;
	char linebuf[256], basenet[20];
	regex_t r_comment, r_entry_distant, r_entry_local, r_entry_server, r_entry_wire, r_entry_trunk, r_entry_xlate, r_entry_fw, r_entry_learn, r_entry_namedpipe, r_entry_filter, r_entry_basenet, r_entry_printhandler;
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
	*basenet='\0';

// Set all the networkp entries within the last printer table to 65535.
	memset(&last_printers, 255, sizeof(last_printers));

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
	{
		trunks[j].listensocket = -1;
	}

	networkp = 0;

	/* Compile some regular expressions */

	if (regcomp(&r_comment, "^\\s*#.*$", 0) != 0)
	{
		fprintf(stderr, "Unable to compile comment regex.\n");
		exit(EXIT_FAILURE);
	}

	/* This needs a better regex */
	if (regcomp(&r_entry_printhandler, "^\\s*PRINTHANDLER\\s+(.+)\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile print handler regex.\n");		
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_distant, "^\\s*([Aa]|IP)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([^[:space:]]+)\\s+([[:digit:]]{4,5})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile full distant station regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_basenet, "^\\s*([Bb])\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile base network regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_local, "^\\s*([Nn]|LOCALNET)\\s+([[:digit:]]{1,3})\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile full local config regex.\n");
		exit(EXIT_FAILURE);
	}

	//if (regcomp(&r_entry_server, "^\\s*([FfPpSs])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5}|AUTO)\\s+(.+)\\s*$", REG_EXTENDED) != 0)
	if (regcomp(&r_entry_server, "^\\s*([FfPp])\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5}|AUTO)\\s+(.+)\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile server regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_namedpipe, "^\\s*(UNIX)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{4,5}|AUTO)\\s+(\\/.+)\\s*$", REG_EXTENDED) != 0)
	{
		fprintf(stderr, "Unable to compile named pipe regex.\n");
		exit(EXIT_FAILURE);
	}

	if (regcomp(&r_entry_wire, "^\\s*([Ww]|WIRE)\\s+([[:digit:]]{1,3})\\s+([[:digit:]]{1,3}|\\*)\\s+([[:digit:]]{4,5}|AUTO)\\s*$", REG_EXTENDED) != 0)
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
		memset(&(network[networkp].printers), 0, sizeof(network[networkp].printers));
		memset(&(network[networkp].printer_priorities), 255, sizeof(network[networkp].printer_priorities));
		network[networkp].numprinters = 0; // i.e. last index+1, so start at 0
		strcpy(network[networkp].socket_serverparam, "");
		network[networkp].is_dynamic = 0;
		network[networkp].last_transaction = 0;
		network[networkp].is_wired_fs = 0;

		if (regexec(&r_comment, linebuf, 0, NULL, 0) == 0)
		{ }
		else if (regexec(&r_entry_printhandler, linebuf, 2, matches, 0) == 0)
		{
			printhandler = malloc(sizeof(linebuf));
			if (!printhandler)
			{
				fprintf (stderr, "Error on malloc() for print handler string.\n");
				exit(EXIT_FAILURE);
			}
			strcpy(printhandler, &(linebuf[matches[1].rm_so]));
		}
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
			
			network[networkp].aun_head = network[networkp].aun_tail = NULL;
			network[networkp].aun_last_tx.tv_sec = network[networkp].aun_last_tx.tv_usec = 0;
			network[networkp].aun_last_rx.tv_sec = network[networkp].aun_last_rx.tv_usec = 0;
			network[networkp].ackimm_seq_awaited = 0; // Sequence number we're waiting to be acked / immediate replied
			network[networkp].ackimm_seq_tosend = 0; // Sequence number the host is waiting to be responded to with ACK / NAK / IMMREP

			networkp++;
		}
		else if (regexec(&r_entry_basenet, linebuf, 3, matches, 0) == 0)
		{
			char 	tmp[300];
			int	ptr;

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
					strcpy(basenet,tmp);
			}
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
		else if (regexec(&r_entry_namedpipe, linebuf, 6, matches, 0) == 0)
		{
			int stn, net, ptr, entry, mfr, port;
			char filename[200], tmp[300];
			char readerfilename[250], writerfilename[250];
			unsigned char buffer[1024];

			for (count = 2; count <= 5; count++) // start at 2 - we know the first one is 'UNIX'
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
					case 4: port = atoi(tmp); 
						if (port == 0 && !*basenet)
							fprintf (stderr, "Warning: use of AUTO mode for station %d.%d with no base network will generate a random port\n", net, stn);
						if (port == 32768 && *basenet)
							fprintf (stderr, "Warning: direct use of port 32768 for station %d.%d may prevent AUTO in base network mode from working\n", net, stn);
						break;
					case 5: strncpy(filename, tmp, 199); break;	
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
			strcpy(network[networkp].named_pipe_filename, filename);

			snprintf(readerfilename, 249, "%s.tobridge", filename);
			snprintf(writerfilename, 249, "%s.frombridge", filename);

			mfr = mkfifo(readerfilename, 0666); // Not keen on this.

			network[networkp].listensocket = -1;

			if (mfr == -1 && (errno != EEXIST)) // mkfifo failed and it wasn't because the fifo already existed
			{
				fprintf (stderr, "Cannot initialize named pipe at %s - ignoring\n", readerfilename);
			}
			else
				network[networkp].listensocket = open(readerfilename, O_RDONLY | O_NONBLOCK | O_SYNC);

			if (network[networkp].listensocket != -1) // Open succeeded
			{
			
				mfr = mkfifo(writerfilename, 0666); // Still not keen on this
				
				if (mfr == -1 && (errno != EEXIST))
				{
					fprintf (stderr, "Cannot initialize named pipe at %s - ignoring\n", writerfilename);
				}
				else
				{
					network[networkp].pipewritesocket = -1; // Rogue - we open it when we see traffic on the pipe, otherwise there's no endpoint and it won't open
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

				}
			}
			else	fprintf (stderr, "Failed to initialize named pipe for station %d.%d - passively ignoring\n", net, stn);

			// Set up the UDP listener
			if ( (network[networkp].pipeudpsocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
			{
				fprintf(stderr, "Failed to open listening socket for local emulation %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
				exit(EXIT_FAILURE);
			}

			service.sin_family = AF_INET;
			if (*basenet && port == 0)
			{
				sprintf(tmp,"%s.%d",basenet,network[networkp].station);
				service.sin_addr.s_addr = inet_addr(tmp);
				port = 32768;
			}
			else
			{
				service.sin_addr.s_addr = INADDR_ANY;
			}

			network[networkp].port = port;
			service.sin_port = htons(network[networkp].port);

			if (bind(network[networkp].pipeudpsocket, (struct sockaddr *) &service, sizeof(service)) != 0)
			{
				fprintf(stderr, "Failed to bind listening socket for named pipe %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
				exit(EXIT_FAILURE);
			}

			pset[pmax++].fd = network[networkp].pipeudpsocket; // Fill in our poll structure

			pipeudpsockets[network[networkp].pipeudpsocket] = networkp; // Mark this as a special one for UDP traffic to Named Pipes

			// Empty the pipe

			while (read(network[networkp].listensocket, buffer, 1023) > 0);

			networkp++;

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
/*
							case 'S':
							case 's':
								servertype = ECONET_SERVER_SOCKET;
*/
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
						// we cheat here; AUTO automatically will parse as "0"
						port = atoi(tmp);
						//network[networkp].port = atoi(tmp);
						if (port == 0 && !*basenet)
							fprintf (stderr, "Warning: use of AUTO mode for station %d.%d with no base network will generate a random port\n", net, stn);
						if (port == 32768 && *basenet)
							fprintf (stderr, "Warning: direct use of port 32768 for station %d.%d may prevent AUTO in base network mode from working\n", net, stn);
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
				network[networkp].numprinters = 0;
			}
			else	network[entry].servertype |= servertype;

			if (servertype == ECONET_SERVER_FILE)
			{
				if (datastring[strlen(datastring)-1] == '/') // Strip trailing slash
					datastring[strlen(datastring)-1] = '\0';
				strcpy(network[(entry == -1) ? networkp : entry].fs_serverparam, datastring);
			}
			else if (servertype == ECONET_SERVER_PRINT)
			{
				char pname[7];
				char *at;
				char *colon; // Location of divider between Unix printer name and Econet printer name
				uint8_t index;

				if (network[(entry == -1) ? networkp : entry].numprinters == MAX_PRINTERS)
				{
					fprintf (stderr, "Maximum number of printers exceeded for this emulated server.\n");
					exit(EXIT_FAILURE);
				}

				colon = strchr(datastring, ':');

				if (colon)
				{
					strncpy(pname, colon+1, 6);
					*colon = (char) '\0'; // Terminate the data string early now we have the pname
				}
				else if ((at = strchr(datastring, '@')) && (*(at+1) != (char) '\0')) // Email address and @ is not last char
					strncpy(pname, at+1, 6);
				else
					strncpy(pname, datastring, 6);

				// Convert pname to upper
				index = 0;
				while (pname[index] != (char) 0x00 && index < 7)
				{
					pname[index] = toupper(pname[index]);
					index++;
				}

				strcpy(network[(entry == -1) ? networkp : entry].print_serverparam, datastring); // Old printer code
				strcpy(network[(entry == -1) ? networkp : entry].printers[network[(entry == -1) ? networkp : entry].numprinters].unixname, datastring); // If there was a colon, then this will have terminated where the colon was
				snprintf(network[(entry == -1) ? networkp : entry].printers[network[(entry == -1) ? networkp : entry].numprinters].name, 7, "%-6.6s", pname); // copies first up to six characters and pads with spaces
				network[(entry == -1) ? networkp : entry].printers[network[(entry == -1) ? networkp : entry].numprinters].control = PRNCTRL_DEFAULT;
				network[(entry == -1) ? networkp : entry].printers[network[(entry == -1) ? networkp : entry].numprinters].status = PRN_STATUS_DEFAULT;
				strncpy(network[(entry == -1) ? networkp : entry].printers[network[(entry == -1) ? networkp : entry].numprinters].banner, "", 23);
				network[(entry == -1) ? networkp : entry].printer_priorities[network[(entry == -1) ? networkp : entry].numprinters] = network[(entry == -1) ? networkp : entry].numprinters; // Initially set the priority list to match the order in the file
				network[(entry == -1) ? networkp : entry].numprinters++;
				
			}
/*
			else if (servertype == ECONET_SERVER_SOCKET)
				strcpy(network[(entry == -1) ? networkp : entry].socket_serverparam, datastring);
*/

			if (servertype & ECONET_SERVER_FILE)
			{
				int f;

				f = fs_initialize(net, stn, (char *) &datastring);
				if (f >= 0)
					network[(entry == -1 ? networkp : entry)].fileserver_index = f;
				else f = -1;
			}

/*
			if (servertype & ECONET_SERVER_SOCKET)
			{
				int f;

				f = sks_initialize(net, stn, (char *) &datastring);
				if (f >= 0)
					network[(entry == -1 ? networkp : entry)].sks_index = f;
				else f = -1;
			}
*/
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
				if (*basenet && port == 0)
				{
					sprintf(tmp,"%s.%d",basenet,network[networkp].station);
					service.sin_addr.s_addr = inet_addr(tmp);
					port = 32768;
				}
				else
				{
					service.sin_addr.s_addr = INADDR_ANY;
				}
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
			short this_type;
			unsigned char this_stn, this_net;
			unsigned int this_port;

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
								this_type = ECONET_HOSTTYPE_WIRE_AUN;
								break;
						}
						break;
					case 2:
						this_net = atoi(tmp);
						break;
					case 3:
						// We cheat and let station 0 mean *
						this_stn = atoi(tmp);
						break;
					case 4:
						// We cheat and let port 0 mean AUTO
						this_port = atoi(tmp);
						if (this_port == 0 && this_net > 127)
						{
							fprintf(stderr, "Network must be under 128 for AUTO to work: %s\n",linebuf);
							exit(EXIT_FAILURE);
						}
						break;
				}
			}

			// Build a simple array of all defined stations on this network
			unsigned char inuse[255] = {'\0'};
			for (short i=0;i<networkp;i++)
			{
				if (network[i].network == this_net)
				inuse[network[i].station]=1;
			}

			// Now if a station has not been specificed we want to set all possible
			// unused stations, otherwise we just set the one asked
			// We can simplify the logic by using a loop in both
			// cases and just set the range accordingly.
			unsigned char stn_low=this_stn?this_stn:1, stn_high=this_stn?this_stn:254;

			for (this_stn=stn_low;this_stn<=stn_high;this_stn++)
			{
				if (inuse[this_stn])
				{
					if (!fs_quiet) fprintf(stderr, "   Skipping station %d because previously defined\n", this_stn);
					continue;
				}

				// Stop this being a server
				network[networkp].servertype = 0;

				network[networkp].port = this_port;
				if (this_port == 0 && !*basenet)
				{
					network[networkp].port = 10000+this_net*256+this_stn;
				}

				network[networkp].station = this_stn;
				network[networkp].network = this_net;
				network[networkp].type = this_type;

				econet_ptr[network[networkp].network][network[networkp].station] = networkp;

				// Set up the listener

				if ( (network[networkp].listensocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
				{
					fprintf(stderr, "Failed to open listening socket for econet net/stn %d/%d: %s.", network[networkp].network, network[networkp].station, strerror(errno));
					exit(EXIT_FAILURE);
				}

				service.sin_family = AF_INET;
				if (*basenet && network[networkp].port == 0)
				{
					sprintf(tmp,"%s.%d",basenet,network[networkp].station);
					service.sin_addr.s_addr = inet_addr(tmp);
					service.sin_port = htons(32768);
				}
				else
				{
					service.sin_addr.s_addr = INADDR_ANY;
					service.sin_port = htons(network[networkp].port);
				}

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
	regfree(&r_entry_printhandler);
	
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
uint32_t get_local_seq(unsigned char net, unsigned char stn)
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
	
	if (wire_adv_in[a->p.srcnet]) src_c = 'W';
	if (wire_adv_in[a->p.dstnet]) dst_c = 'W';

	if ((a->p.dstnet == 0xff && a->p.dststn == 0xff))
		dst_c = 'B';

	if (a->p.srcstn == 0) // Bridge query reply
		src_c = 'Z';

	if (dumpmode_brief)
	{
		fprintf (stderr, "%c-->%c: to %3d.%3d from %3d.%3d port 0x%02x ctrl 0x%02x seq 0x%08x len 0x%04x ", src_c, dst_c, a->p.dstnet, a->p.dststn, a->p.srcnet, a->p.srcstn, a->p.port, a->p.ctrl, le32toh(a->p.seq), s-12);
		for (count = 0; count < ((s-12) < 40 ? (s-12) : 40); count++)
			fprintf (stderr, "%02x %c ", a->p.data[count], (a->p.data[count] < 32 || a->p.data[count] > 126) ? '.' : a->p.data[count]);
		fprintf (stderr, "%s\n", (s-12) < 40 ? "" : " ...");
			
	}
	else
	{
		fprintf (stderr, "\n%08x --- PACKET %s TO %s ---\n", packetsize, (src_c == 'T' ? "TRUNK" : (src_c == 'E' ? "ECONET" : (src_c == 'L' ? "LOCAL" : (src_c == 'W' ? "WIRE BRIDGED" : (src_c == 'Z' ? "BRIDGE" : "AUN"))))),
			(dst_c == 'T' ? "TRUNK" : (dst_c == 'E' ? "ECONET" : (dst_c == 'L' ? "LOCAL" : (dst_c == 'W' ? "BDGED" : "AUN")))));
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
	
		//fprintf (stderr, "         SEQ         0x%08X\n", a->p.seq);
		fprintf (stderr, "         SEQ         0x%08" PRIx32 "\n", a->p.seq);

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
	switch (-1 * e)
	{
		case ECONET_TX_SUCCESS: return (char *)"No error"; 
		case ECONET_TX_BUSY: return (char *)"Module busy";
		case ECONET_TX_JAMMED: return (char *)"Line jammed";
		case ECONET_TX_HANDSHAKEFAIL: return (char *)"Handshake failure";
		case ECONET_TX_NOCLOCK: return (char *)"No clock";
		case ECONET_TX_UNDERRUN: return (char *)"Transmit underrun";
		case ECONET_TX_TDRAFULL: return (char *)"Data register full on tx";
		case ECONET_TX_NOIRQ: return (char *)"No IRQ received to being/continue transmit";
		case ECONET_TX_NOCOPY: return (char *)"Could not copy packet from userspace";
		case ECONET_TX_NOTSTART: return (char *)"Transmission never begun";
		case ECONET_TX_COLLISION: return (char *)"Collision during transmission";
		case ECONET_TX_INPROGRESS: return (char *)"Transmission in progress";
		default: return (char *)"Unknown error";
	}	

}

void aun_acknowledge (struct __econet_packet_aun *a, unsigned char ptype)
{

	struct __econet_packet_aun reply;
	int ptr;

	reply.p.aun_ttype = ptype;
	reply.p.port = a->p.port;
	reply.p.ctrl = a->p.ctrl;
	reply.p.padding = 0x00;
	reply.p.seq = a->p.seq;
	reply.p.srcnet = a->p.dstnet;
	reply.p.srcstn = a->p.dststn;
	reply.p.dstnet = a->p.srcnet;
	reply.p.dststn = a->p.srcstn;

	econet_write_general(&reply, 12);

	ptr = econet_ptr[a->p.srcnet][a->p.srcstn]; // src used here because that's the src in the packet we are acknowledging, so the src is actually the station we're sending the ack *to* - so it's that station's tracker we need to look at
		
	if (ptr != -1 && (network[ptr].type & ECONET_HOSTTYPE_TDIS) && reply.p.seq == network[ptr].ackimm_seq_tosend)
	{
		network[ptr].ackimm_seq_tosend = 0; // We have just acknowledged a packet from this machine - clear off the tracker
		if (queue_debug) fprintf (stderr, "QUEUE: Clearing ACK tracker on network[%d] - seq 0x%08X\n", ptr, network[ptr].ackimm_seq_tosend);
	}

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
				nativebridgenet = (0xff ^ trunks[source].filter_in[p->p.data[counter]]) ? p->p.data[counter] : 0;  // If this network wasn't filtered, nativebridgenet is set to it. Otherwise 0 (which is what it was before)
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
				if (trunk_advertizable[other] || wire_adv_in[other]) // Copy what's in trunk_advertizable, and what we've had from wire adverts
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
	// Unless the source *was* the wire or it was a reset. So if this was a reset, or source > 0 (because wire is 0) then spit it out
	if (nativebridgenet && (is_reset || (source > 0))) // Can't send this unless we have *something* on the far side of local...
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

		econet_write_wire (&out, count+12, 0);
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

	//fprintf (stderr, "Local handler invoked; AUN type %d len %d\n", a->p.aun_ttype, packlen);

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
	else if ((a->p.aun_ttype == ECONET_AUN_DATA || a->p.aun_ttype == ECONET_AUN_BCAST) && (a->p.port == 0x9f)) // Print server status protocol
	{

			int count;
			unsigned char querytype;
			unsigned char pname[7];

			querytype = a->p.data[6]; // 1 == status request; 6 == name request
	
			for (count = 0; count < 6; count++)
				pname[count] = a->p.data[count];
		
			pname[6] = 0; // NULL terminate

			if (pkt_debug) fprintf (stderr, "PRINT: to %3d.%3d from %3d.%3d Printer Status Query (%s) for printer %s ",
				a->p.dstnet, a->p.dststn,
				a->p.srcnet, a->p.srcstn,
				(querytype == PRN_QUERY_STATUS) ? "status" : "name",
				pname);

			for (count = 0; count < stations; count++) // Search them all in case it's a broadcast. Otherwise, only reply from the one which was addressed
			{
				if ((network[count].servertype & ECONET_SERVER_PRINT) && (a->p.aun_ttype == ECONET_AUN_BCAST || (a->p.dstnet == network[count].network && a->p.dststn == network[count].station)))
				{

					reply.p.srcnet = network[count].network;
					reply.p.srcstn = network[count].station;
					reply.p.dstnet = a->p.srcnet;
					reply.p.dststn = a->p.srcstn;
					reply.p.aun_ttype = ECONET_AUN_DATA;
					reply.p.port = 0x9e;
					reply.p.ctrl = 0x80;

					if (querytype == PRN_QUERY_STATUS) // Status enquiry
					{
						/* First need to compare the name */

						short found = 0, printer;

						if (!strncasecmp("PRINT ", (const char *) pname, 6))
						{
							found = 1;
						}
						else
							for (printer = 0; printer < network[count].numprinters; printer++)
							{
								if (!strncasecmp((const char *) network[count].printers[printer].name, (const char *) pname, 6))
									found++;	
							}
						
						if (found)
						{
							
							if (pkt_debug) fprintf (stderr, " - responding with status\n");
							reply.p.seq = get_local_seq(network[count].network, network[count].station);
							reply.p.data[0] = 0x00; // Status byte 0 = Ready
							reply.p.data[1] = 0x00; // Busy with station N (which we don't need if ready)
							reply.p.data[2] = 0x00; // Busy with network N (which we don't need if ready)
							aun_send (&reply, 15);
						}
						else if (pkt_debug) fprintf (stderr, " - not responding\n");
					}
					else if (querytype == PRN_QUERY_NAME) // Name query - we can, apparently, send multiple replies to this.
					{

						int printer = 0;

						// Loop through the printers on this station and reply. Update sequence number for each reply...

						while (printer < network[count].numprinters)
						{
							reply.p.seq = get_local_seq(network[count].network, network[count].station);
							snprintf((char * restrict) reply.p.data, 7, "%6s", network[count].printers[printer].name);
							aun_send (&reply, 18);
							if (printer == 0 && pkt_debug) fprintf (stderr, " - responded with printer list\n");
						}

					}
				}
			}

	}
	else if (a->p.aun_ttype == ECONET_AUN_BCAST) // Broadcast - See if we need to do a bridge query reply 
	{
		if (bridge_query && (a->p.port == 0x9C) && (a->p.ctrl == 0x80 || a->p.ctrl == 0x81) && (source >= 0)) // bridge reset/update broadcast
			econet_bridge_process (a, packlen, source);

		else if (bridge_query && (a->p.port == 0x9c) && (!strncmp("BRIDGE", (const char *) a->p.data, 6)) && localnet && (network[econet_ptr[a->p.srcnet][a->p.srcstn]].type & (ECONET_HOSTTYPE_TWIRE | ECONET_HOSTTYPE_TNAMEDPIPE)))
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
			else if (pkt_debug) fprintf (stderr, "LOC  : BRIDGE     from %3d.%3d - didn't bother replying.\n", a->p.srcnet, a->p.srcstn);
	
		}
		else if (a->p.port == 0x99) // Handle broadcasts to fileservers
		{

			int count;

			for (count = 0; count < stations; count++)
			{
				if ((network[count].servertype & ECONET_SERVER_FILE) && (network[count].fileserver_index >= 0))
					handle_fs_traffic(network[count].fileserver_index, a->p.srcnet, a->p.srcstn, a->p.ctrl, a->p.data, packlen-12);
			}
		}
	}
	else if (a->p.aun_ttype == ECONET_AUN_DATA) // Data packet
	{
		if ((a->p.port == 0x99) && (network[d_ptr].servertype & ECONET_SERVER_FILE) && (network[d_ptr].fileserver_index >= 0))
			handle_fs_traffic(network[d_ptr].fileserver_index, a->p.srcnet, a->p.srcstn, a->p.ctrl, a->p.data, packlen-12);

		else if ((a->p.port == 0x9f) && ((network[d_ptr].servertype) & ECONET_SERVER_PRINT)) // Looks like only ANFS does this... // Print server handling - this looks like it is just printer state query
		{
		
			char printer_selected[10];
			char *spaceptr;
			//unsigned char querytype;

			memset(printer_selected, 0, sizeof(printer_selected));

			strncpy(printer_selected, (const char *) a->p.data, 6);

			fprintf (stderr, "PRINT: to %3d.%3d from %3d.%3d Printer status enquiry %s\n", 
				a->p.dstnet, a->p.dststn, a->p.srcnet, a->p.srcstn, printer_selected);

			reply.p.srcnet = a->p.dstnet;
			reply.p.srcstn = a->p.dststn;
			reply.p.dstnet = a->p.srcnet;
			reply.p.dststn = a->p.srcstn;
			reply.p.aun_ttype = ECONET_AUN_DATA;
			reply.p.port = 0x9e;
			reply.p.ctrl = 0x80;
			reply.p.seq = get_local_seq(a->p.dstnet, a->p.dststn);
			reply.p.data[0] = 0x00; // Printer input state (Read) // We can change this when we can bar input etc.
			reply.p.data[1] = 0x00; // Printer output state (Ready) // We can change this when we can put printers offline!


			if ((spaceptr = strchr(printer_selected, ' ')))
				*spaceptr = (char) 0; // Terminate
		
			//querytype = a->p.data[6]; // TODO - Implement the different queries

			if (!strcmp(printer_selected, "PRINT"))
			{
				aun_send (&reply, 14);
			}
			else
			{
				// See if we have a matching printer
				int count = 0, found = 0;

				while (count < network[d_ptr].numprinters)
				{
					if (strlen(network[d_ptr].printers[count].name) != strlen(printer_selected))
						count++;
					else if (!strncasecmp(network[d_ptr].printers[count].name, printer_selected, strlen(printer_selected)))
						found = 1;

					else count++;
				}	

				if (found)
				{
					last_printers[a->p.srcnet][a->p.srcstn].printer_index = -1;
					reply.p.data[0] = 0xff; // Error
					aun_send (&reply, 14);
				}
				else	
				{
					reply.p.data[0] = 0xff;
					strcpy((char *) &(reply.p.data[2]), "Unkonwn printer");
					aun_send(&reply, 14 + strlen("Unknown printer") + 1);
				}
				
			}


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

			if (found == -1) // New Print Job
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
					//printjobs[found].ctrl = 0x80; 
					printjobs[found].ctrlbit = (a->p.ctrl & 0x01) ^ 0x01; // So ctrlbit stores what we are expecting
					
					sprintf(filename, SPOOLFILESPEC, found);
	
					printjobs[found].spoolfile = fopen(filename, "w");
					
					if (!printjobs[found].spoolfile)
					{
						printjobs[count].net = printjobs[count].stn = 0;  // Free this up - couldn't open file	
						fprintf (stderr, "Unable to open spool file for print job from station %d.%d\n", a->p.srcnet, a->p.srcstn);
					}
					else
					{

						unsigned char printer_index = 0xff;
						int fserver, active_id; // active_id is an internal FS index to the logged in user table

						// Which printer?

						if (network[d_ptr].servertype & ECONET_SERVER_FILE) // Is fileserver, so it might have a printer selected
							printer_index = fs_get_user_printer(network[d_ptr].fileserver_index, a->p.srcnet, a->p.srcstn);

						if (printer_index == 0xff)
							printer_index = network[d_ptr].printer_priorities[0];

						fprintf (stderr, "PRINT: Starting spooler job for %d.%d - %s (%s)\n", a->p.srcnet, a->p.srcstn, network[d_ptr].printers[printer_index].name, network[d_ptr].printers[printer_index].unixname);

						// If we are using the new external print handler, we don't do the headers internally any more. They are configured.

						strcpy(printjobs[found].name, network[d_ptr].printers[printer_index].name);

						// Are we a fileserver as well as a print server? If so, is this station logged into it?
						if (((fserver = fs_get_server_id(a->p.dstnet, a->p.dststn)) != -1) && ((active_id = fs_stn_logged_in(fserver, a->p.srcnet, a->p.srcstn)) != -1))
						{
							fs_get_username(fserver, active_id, printjobs[found].username);
							if (printjobs[found].username == 0) strcpy(printjobs[found].username, "ANONYMOUS");
							
						}
						else	strcpy(printjobs[found].username, "ANONYMOUS");

						if (!printhandler && strstr(network[d_ptr].printers[printer_index].unixname, "@")) // Email print job, not send to printer
						{
							fprintf(printjobs[count].spoolfile, "To: %s\n", network[d_ptr].printers[printer_index].unixname);
							fprintf(printjobs[count].spoolfile, "Subject: Econet print job from station %d.%d\n\n", a->p.srcnet, a->p.srcstn);
						}
						if (!printhandler) fprintf (printjobs[count].spoolfile, PRINTHEADER, a->p.srcnet, a->p.srcstn);

						strcpy (printjobs[count].unixname, network[d_ptr].printers[printer_index].unixname);
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
				reply.p.ctrl = a->p.ctrl;

				reply.p.seq = get_local_seq(a->p.dstnet, a->p.dststn);

				// The control low bit alternation is to avoid duplicated packets. Need to implement a check... TODO.

				if ((printjobs[count].ctrlbit == (a->p.ctrl & 0x01)) || ((a->p.ctrl & 0xfe) == 0x82)) // Either matches the ctrl bit, OR is 0x82 (job start)
				{
					printjobs[count].ctrlbit = (a->p.ctrl & 0x01) ^ 0x01;

					switch (a->p.ctrl & 0xfe)
					{
						case 0x82: // Print job start
						{
							reply.p.data[0] = 0x2a;
						}
						break;
						case 0x80: // Print data
						{
							fwrite(&(a->p.data), packlen-12, 1, printjobs[count].spoolfile);
							reply.p.data[0] = a->p.data[0];	
						}
						break;
						case 0x86: // Final packet
						{
							char command_string[2000];
							char filename_string[200];
	
							// There is a rogue byte on the end of the last printjob packet it would seem
							fwrite(&(a->p.data), packlen-12-1, 1, printjobs[count].spoolfile);

							if (!printhandler)	
								fprintf(printjobs[count].spoolfile, PRINTFOOTER);

							reply.p.data[0] = a->p.data[0];	
	
							fclose(printjobs[count].spoolfile);
							sprintf(filename_string, SPOOLFILESPEC, found);
							
							if (!printhandler)
							{
								if (strstr(printjobs[count].unixname, "@")) // Email address not printername
									sprintf(command_string, MAILCMDSPEC, printjobs[count].unixname, filename_string);
								else
									sprintf(command_string, PRINTCMDSPEC, printjobs[count].unixname, filename_string);
		
								fprintf (stderr, "PRINT: Sending print job with %s\n", command_string);
							
								if (!fork())
									execl("/bin/sh", "sh", "-c", command_string, (char *)0);
							}
							else
							{
								sprintf(command_string, "%s %d %d %d %d %s %s %s %s",
									printhandler,
									a->p.dstnet, a->p.dststn,
									a->p.srcnet, a->p.srcstn,
									printjobs[count].username,
									printjobs[count].unixname,
									printjobs[count].name,
									filename_string);
				
								if (pkt_debug) fprintf(stderr, "PRINT: Command string: %s\n", command_string);

								if (!fork())	execl("/bin/bash", "bash", "-c", command_string, (char *) 0);
	
							}
	
							printjobs[count].stn = printjobs[count].net = 0; // Free the resource	

						}
						break;
					}

				}

				aun_send (&reply, 13);
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
	else
		fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d Unknown destination\n", 
			p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);

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

// Source is only used to pass to local handler to process broadcasts so we know where they came from
int aun_send_internal (struct __econet_packet_aun *p, int len, int source)
{

	int d, s, result; // d, s are pointers into network[]; result is number of bytes written or error return
	int is_on_wirebridge = 0;

	//fprintf (stderr, "aun_send_internal type %d, dst = %3d.%3d, len = %d\n", p->p.aun_ttype, p->p.dstnet, p->p.dststn, len);

	if (p->p.aun_ttype == ECONET_AUN_BCAST)
		p->p.dstnet = p->p.dststn = 0xff;
		
	d = econet_ptr[p->p.dstnet][p->p.dststn];
	s = econet_ptr[p->p.srcnet][p->p.srcstn];

	// Probably need to pick up here if the destination is on a network advertised to us by a wire bridge - if so, then if the source is not on the wire as well (and not on a wire bridge either!) then we should treat it as going onto the wire. Maybe a new variable wire_bridged which we can use in the logic below. Otherwise stuff which ought to go on the wire which has come from AUN (most likely via a trunk, but it could also be a W statement) will end up heading for an unknown trunk and failing.

	if (p->p.dstnet != 0xff && wire_adv_in[p->p.dstnet] == 0xff)  // If this is a network we know is via a bridge on the wire, flag that up.
		is_on_wirebridge = 1;
	
	if (d != -1) network[d].last_transaction = time(NULL);

	p->p.ctrl |= 0x80; // In case we're going to wire or local
	
	p->p.padding = 0x00;

	//fprintf (stderr, "Got here 1\n");
	if (p->p.aun_ttype != ECONET_AUN_ACK && p->p.aun_ttype != ECONET_AUN_NAK) // Don't dump acks...
		dump_udp_pkt_aun(p, len);

	//fprintf (stderr, "Got here 2\n");
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
		if (is_on_wirebridge && source == 0) // Wire to wire
		{
			if (pkt_debug) fprintf (stderr, "ILOCK: to %3d.%3d from %3d.%3d I refuse to forward wire traffic via a wire bridge\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
			return result;
		}
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

	if (s != -1 && (p->p.aun_ttype == ECONET_AUN_DATA || p->p.aun_ttype == ECONET_AUN_IMM)) // Particular source
	{
		if (network[s].type & ECONET_HOSTTYPE_TDIS || network[s].type & ECONET_HOSTTYPE_TNAMEDPIPE) // AUN or named Pipe
		{
			gettimeofday(&(network[s].aun_last_rx), 0); // Flag the packet receipt time so we know when to expire the ACK / IMMREP timer
			network[s].ackimm_seq_tosend = p->p.seq;
		}

		if (network[s].type & ECONET_HOSTTYPE_TWIRE && p->p.aun_ttype == ECONET_AUN_IMM) // Wire host sending immediate - prioritise the reply
		{
			wire_prio_out_srcnet = p->p.dstnet;
			wire_prio_out_srcstn = p->p.dststn;
			wire_prio_out_dstnet = p->p.srcnet;
			wire_prio_out_dststn = p->p.srcstn;
			wire_prio_out_port = 0;
			wire_prio_out_auntype = ECONET_AUN_IMMREP;
		}

	}

	// Broadcasts

	if (p->p.aun_ttype == ECONET_AUN_BCAST && p->p.port != 0x9c) // We don't retransmit bridge traffic because we tinker with that elsewhere
	{

		int trunk, count;

		result = len;

		//fprintf (stderr, "Broadcast retransmission - len = %d, s = %d\n", len, s);

		// Dump it locally if it wasn't local
		if ((s != -1 && (!(network[s].type & ECONET_HOSTTYPE_TLOCAL))) || (s == -1)) // Known source and it wasn't a local emulator,  or unknown source
		{
			//fprintf (stderr, "Sending broadcast to local\n");
			econet_handle_local_aun(p, len, source);
		}

		// Now dump it to all the named pipes we can find

		for (count = 0; count < stations;  count++)
		{
			if ((network[count].type & ECONET_HOSTTYPE_TNAMEDPIPE) && (s != -1 && s != count) && (network[count].pipewritesocket != -1)) // Is a named pipe, and not the one the packe came from
			{
				struct __econet_packet_pipe delivery;

				delivery.length_low = len & 0xff;
				delivery.length_high = (len >> 8) & 0xff;
				
				memcpy(&(delivery.dststn), p, len);
				write(network[count].pipewritesocket, &delivery, len+2);
			}

		}

		// if it didn't come from the wire, put it on the wire
		if (source != 0)	
		{
			//fprintf (stderr, "Sending broadcast to wire\n");
			econet_write_wire(p, len, 0); // Was len+12
		}

		// And on every trunk it didn't come from
	
		for (trunk = 1; trunk < 256; trunk++)
		{
			if (trunks[trunk].listensocket >= 0 && trunk != source)
			{	//fprintf (stderr, "Sending broadcast to trunk %d\n", trunk);
				aun_trunk_send_internal (p, len, trunk);
			}
		}

	}

	// If trunk destination, the trunk send routine does NAT and works out which trunk

	// Now, where's it going?

	else if (p->p.aun_ttype == ECONET_AUN_BCAST || (d != -1 && (network[d].type & ECONET_HOSTTYPE_TLOCAL))) // Probably need to forward broadcasts received off the wire to AUN/IP hosts on same net, but we don't at the moment; We catch broadcasts here again because we don't process BRIDGE broadcasts above, so they need to go to the local handler
	{
		econet_handle_local_aun(p, len, source);
		// probably need to forward broadcasts to trunks / wire depending on source - TODO
		result = len;
	}
	else if (!is_on_wirebridge && d == -1) // Trunk send (we will now send broadcasts on trunks as well)
	{
		p->p.ctrl &= 0x7f; // Strip high bit from control an AUN transmission

		if (s == -1) // Trunk to trunk - straight out
			result = aun_trunk_send (p, len);
		else
		{
			econet_general_enqueue(&trunk_head, &trunk_tail, p, len);
			result = len;
		}
	}
	else if (is_on_wirebridge || network[d].type & ECONET_HOSTTYPE_TWIRE) // Wire - and we prevent material received from the wire going back onto the wire
	{
		// Is it a wired fileserver we might want to know about? To cope with wired filservers that are via wired bridges, we probably need a separate list of wired fileservers now - TODO

		if (!is_on_wirebridge && (network[d].type & ECONET_HOSTTYPE_TWIRE) && (p->p.port == 0x99) && (!(network[d].is_wired_fs))) // Fileserver traffic on a wire station
		{
			network[d].is_wired_fs = 1;
			fprintf (stderr, "  DYN:%12s             Station %d.%d identified as wired fileserver\n", "", p->p.dstnet, p->p.dststn);
		}

		// Update this even if we don't get to transmit - what's the harm?
		if (!is_on_wirebridge && p->p.aun_ttype == ECONET_AUN_IMM)
			network[d].last_imm_seq_sent = p->p.seq;

		econet_enqueue(p, len, QUEUE_AUTO);
		result = len;

	}
	else if ((network[d].type & ECONET_HOSTTYPE_TNAMEDPIPE)) // Named pipe client
	{
		if (network[d].pipewritesocket != -1)
		{
			struct __econet_packet_pipe delivery;
		
			delivery.length_low = len & 0xff;
			delivery.length_high = (len >> 8) & 0xff;
			memcpy(&(delivery.dststn), p, len);
			result = write(network[d].pipewritesocket, &delivery, len+2);
			if (result == len+2) result -= 2;
		}
		else	if (pkt_debug) fprintf (stderr, "PIPE : Pipe write socket not open\n");
	}
	else if (network[d].type & ECONET_HOSTTYPE_TDIS)
	{
		p->p.ctrl &= 0x7f; // Strip high bit from control an AUN transmission

		// We shouldn't see ACK or NAK here because they are caught on input and processed.

		if (p->p.aun_ttype != ECONET_AUN_BCAST) // Ignore broadcasts to AUN for now
		{
			if (econet_general_enqueue(&(network[d].aun_head), &(network[d].aun_tail), p, len))
			{
				result = len;
				aun_queued++;
			}
			else	result = 0;
		}
		else result = len;
	}
	else // Unknown destination type
	{
		fprintf (stderr, "ERROR: to %3d.%3d from %3d.%3d Unknown destination\n", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn);
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

// Returns 1 if net.stn is either AUN/IP or trunk (use is_on_trunk() to work out whether it's on a trunk)

unsigned short is_aun(unsigned char net, unsigned char stn)
{
	if ((econet_ptr[net][stn] == -1) || (network[econet_ptr[net][stn]].type & ECONET_HOSTTYPE_TDIS))
		return 1;
		
	return 0;
}

// Returns 1 if net.stn isn't in network[] - i.e. if it's anywhere it's on a trunk AND we can find a trunk that appears to advertise it the relevant network
static inline unsigned short is_on_trunk(unsigned char net, unsigned char stn)
{
	if (econet_ptr[net][stn] == -1) 
	{
		unsigned short count = 1;
	
		while (count < 256)
		{
			if (trunks[count].listensocket >= 0 && trunks[count].adv_in[net] == 0xff)
				return 1;
			else count++;
		}
	}
	return 0;
}


int main(int argc, char **argv)
{

	int s;
	int opt;
	int dump_station_table = 0;
	short fs_bulk_traffic = 0;
	int last_active_fd = 0;
	int poll_timeout; // Used in order to reset the chip if we send an immediate to an AUN station and it doesn't reply

	unsigned short from_found, to_found; // Used to see if we know a station or not

	struct __econet_packet_aun rx;

	memset(&network, 0, sizeof(network));
	memset(&econet_ptr, 0xff, sizeof(econet_ptr));
	memset(&fd_ptr, 0xff, sizeof(fd_ptr));
	memset(&pipeudpsockets, 0xff, sizeof(pipeudpsockets));
	memset(&trunk_fd_ptr, 0xff, sizeof(trunk_fd_ptr));
	memset(&last_ps, 0x00, sizeof(last_ps));
	memset(&last_prn, 0x00, sizeof(last_prn));

	// Clear the packet cache

	seq = 0x46; /* Random number */

	fs_sevenbitbodge = fs_sjfunc = 1; // On by default 

	while ((opt = getopt(argc, argv, "bc:dfijlnmqrsxzh7")) != -1)
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
			case 'i': spoof_immediate = 1; break;
			case 'j': fs_sjfunc = 0; break; // Turn off MDFS / SJ functionality in FS
			case 'l': wire_enabled = 0; break;
			case 'n': fs_noisy = 1; fs_quiet = 0; break;
			case 'm': normalize_debug = 1; fs_noisy = 1; fs_quiet = 0; break;
			case 'q':
				bridge_query = 0;
				break;
			case 'r': queue_debug = 1; break;
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
\t-i\tSpoof immediate responses in-kernel (will break *REMOTE, *VIEW etc.)\n\
\t-j\tTurn off SJ Research MDFS functionality in file server\n\
\t-l\tLocal only - do not connect to kernel module (uses /dev/null instead)\n\
\t-n\tTurn on noisy fileserver debugging (also turns on ordinary logging)\n\
\t-m\tTurn on FS 'normalize' debug (filename translation from Acorn to Unix) - super noisy\n\
\t-q\tDisable bridge query responses\n\
\t-r\tEnable queue debugging (only if you know what you're doing)\n\
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

					fprintf (stderr, "%3d %3d %5s %-5s %-4s %-30s %5d %c %c %c %s%s%s%s%s\n",
						network[p].network,
						network[p].station,
						buffer,
						(network[p].type & ECONET_HOSTTYPE_TDIS) ? "Dist." :
							(network[p].type & ECONET_HOSTTYPE_TWIRE) ? "Wire" : 
							(network[p].type & ECONET_HOSTTYPE_TNAMEDPIPE) ? "Unix" : "Local",
						(network[p].type & ECONET_HOSTTYPE_TAUN ? "AUN" : "RAW"),
						(network[p].type & ECONET_HOSTTYPE_TDIS) ? network[p].hostname : "",
						network[p].port,
						((network[p].servertype & ECONET_SERVER_FILE) ? 'F' : ' '),
						((network[p].servertype & ECONET_SERVER_PRINT) ? 'P' : ' '),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? 'S' : ' '),
						((network[p].servertype & ECONET_SERVER_FILE) ? network[p].fs_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_FILE) ? " " : ""),
						//((network[p].servertype & ECONET_SERVER_PRINT) ? network[p].print_serverparam : ""),
						//((network[p].servertype & ECONET_SERVER_PRINT) ? " " : ""),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? network[p].socket_serverparam : ""),
						((network[p].servertype & ECONET_SERVER_SOCKET) ? " " : ""),
						((network[p].type & ECONET_HOSTTYPE_TNAMEDPIPE) ? network[p].named_pipe_filename : "")
					);

					if (network[p].servertype & ECONET_SERVER_PRINT)
					{
						int c;

						for (c = 0; c < network[p].numprinters; c++)
							fprintf(stderr, "%64s%c %1d %s : %s\n", "", 'P', c, network[p].printers[c].name, network[p].printers[c].unixname);

					}
				}
			}
		}
			
		if (numtrunks > 0)
		{
			fprintf (stderr, "\n\nTRUNK DEFINITIONS\n");
			for (n = 1; n < 256; n++)
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

	srand(time(NULL));

   while (1) // Loop to allow reset of chip if we have an immediate timeout
   {

	poll_timeout = -1;

	while (wire_head || aun_queued || trunk_head || poll((struct pollfd *)&pset, pmax+(wire_enabled ? 1 : 0), poll_timeout)) // AUN queued packets, wire queued packets, or something arriving. The 1 is because we now have a timeout on poll() in case we need to reset the module to make sure that immediates to AUN stations which are not present doesn't cause a hang!
	{
	
		//fprintf (stderr, "DEBUG: wire_haed = %p, aun_queued = %ld, trunk_head = %p\n", wire_head, aun_queued, trunk_head);

		if (wire_head || aun_queued || trunk_head) // Do a poll just in case something turns up, but do it quickly
			poll((struct pollfd *) &pset, pmax+(wire_enabled ? 1 : 0), 10);

		if (wire_enabled && (pset[pmax].revents & POLLIN)) // Let the wire take a back seat sometimes
		{
			int r;


			// Collect the packet
			r = read(econet_fd, &rx, ECONET_MAX_PACKET_SIZE);

			if (r > 0) // Ding dong, traffic arriving off the wire  (and if it's -1, the module was busy on read - try next time)
			{
				if (r < 12)
					fprintf(stderr, "Runt packet length %d received off Econet wire\n", r);

				if (!wire_adv_in[rx.p.srcnet]) // This was not a network advertised inbound on the wire - i.e. we should have a network[] entry for it
				{
					rx.p.seq = get_local_seq(rx.p.srcnet, rx.p.srcstn);

					if (rx.p.aun_ttype == ECONET_AUN_IMMREP) // Fudge - assume the immediate we have received is a reply to the last one we sent. Maybe make this more intelligent.
						rx.p.seq = network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].last_imm_seq_sent;

					network[econet_ptr[rx.p.srcnet][rx.p.srcstn]].last_transaction = time(NULL);

				}
				else
				{
					// Need to track sequence and immediate sequence and last transaction somehow... TODO

				}

				// Fudge the AUN type on port 0 ctrl 0x85, which is done as some sort of weird special 4 way handshake with 4 data bytes on the Scout - done as "data" and the kernel module works out that the first 4 bytes in the packet go on the scout and the rest go in the 3rd packet in the 4-way

				if (rx.p.aun_ttype == ECONET_AUN_IMM && rx.p.ctrl == 0x85) // Fudge-a-rama. This deals with the fact that NFS & ANFS in fact do a 4-way handshake on immediate $85, but with 4 data bytes on the "Scout". Those four bytes are put as the first four bytes in the data packet, and a receiving bridge will strip them off, detect the ctrl byte, and do a 4-way with the 4 bytes on the Scout, and the remainder of the data in the "data" packet (packet 3/4 in the 4-way). This enables things like *remote, *view and *notify to work.
					rx.p.aun_ttype = ECONET_AUN_DATA;

				// This will be from a known wire station or a station from over a bridge, flag priority output if need be (note - there is a concurrency issue with other wire stations since they have their own priority flags. maybe change that to a global wire priority?)
				
				// Flag broadcasts incase the module isn't doing it
				if (rx.p.dstnet == 0xff && rx.p.dststn == 0xff)
					rx.p.aun_ttype = ECONET_AUN_BCAST;

				aun_send_internal (&rx, r, 0);

			}
		}

		/* See if anything turned up on UDP */

		for (s = 0; s < pmax; s++) /* not the last fd - which is the econet hardware */
		{
			int realfd;
	
			realfd = (s + start_fd) % pmax; // Offset our start to "start_fd"

			if (pset[realfd].revents & POLLIN)
				last_active_fd = realfd;

			if ((pset[realfd].revents & POLLHUP) && (network[fd_ptr[pset[realfd].fd]].type & ECONET_HOSTTYPE_TNAMEDPIPE) && (network[fd_ptr[pset[realfd].fd]].pipewritesocket != -1))
			{
				int fd, np;
				char file[250];
				unsigned char buffer[1024];

				fd = pset[realfd].fd;
				np = fd_ptr[fd];
				// Client went away - close the writer pipe
				close(network[np].pipewritesocket);
				network[np].pipewritesocket = -1;
				if (pkt_debug) fprintf (stderr, "*PIPE:                 %3d.%3d client pipe went away.\n", 
					network[np].network, network[np].station);
				// Close the reader & re-open it
				fd_ptr[network[np].listensocket] = -1;
				snprintf(file, 249, "%s.tobridge", network[np].named_pipe_filename);
				pset[realfd].fd = open (file, O_RDONLY | O_NONBLOCK);
				if (pset[realfd].fd != -1)
					fd_ptr[pset[realfd].fd] = np;
				else 	// Barf!
				{
					fprintf (stderr, "*PIPE: Reader socket for %3d.%3d went away. Quitting.\n", network[np].network, network[np].station);
					exit(EXIT_FAILURE);
				}

				network[np].listensocket = pset[realfd].fd;

				// Empty the pipe

				while (read(network[np].listensocket, buffer, 1023) > 0);
				
			}
			else if ((pset[realfd].revents & POLLIN) && (trunk_fd_ptr[pset[realfd].fd] != -1)) // Traffic arriving on trunk
			{
				struct __econet_packet_aun p;

				int r, count, from_found = 0xffff;
				unsigned char policy;
	
				r = udp_receive (pset[realfd].fd, (void *) &p, sizeof(p), (struct sockaddr * restrict) &src_address);

				if (r < 0) continue; // Debug produced in udp_receive

				// Which peer did it turn up from?

				count = 1;

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

// Disabled - use aun_send_internal
/*
				if ((p.p.aun_ttype == ECONET_AUN_BCAST) && from_found != 0xffff) // Dump to local in case it's bridge stuff - but only if we knew where it came from
					econet_handle_local_aun(&p, r, from_found);
*/
		
				if (p.p.aun_ttype == ECONET_AUN_BCAST && from_found != 0xffff)
					aun_send_internal (&p, r, from_found);

				// Note that aun_send now dumps traffic we refuse to forward so we don't need to check here

				if ((policy == FW_ACCEPT) && ((p.p.aun_ttype == ECONET_AUN_DATA) || (p.p.aun_ttype == ECONET_AUN_IMM) || (p.p.aun_ttype == ECONET_AUN_IMMREP)))
				{
					if (p.p.aun_ttype == ECONET_AUN_DATA && (econet_ptr[p.p.dstnet][p.p.dststn] != -1)) // DATA, and it's going to a known host (can't be AUN because AUN hosts don't talk to trunks) - Proxy acknowledge, even for Named Pipes
						aun_acknowledge(&p, ECONET_AUN_ACK);
					aun_send(&p, r);
				}
			}
			else if (pset[realfd].revents & POLLIN  && (pipeudpsockets[pset[realfd].fd] != -1)) // Traffic arriving on a UDP socket which is really just AUN for a named pipe client
			{
				int netptr, r, from_found = 0xffff;
				struct __econet_packet_aun p;

				r = udp_receive (pset[realfd].fd, (void *) &(p.p.aun_ttype), sizeof(p)-4, (struct sockaddr * restrict) &src_address);

				if (r < 0) continue; // Debug produced in udp_receive

				/* Look up where it came from */

				from_found = econet_find_source_station (&src_address); // 0xffff;

				netptr = pipeudpsockets[pset[realfd].fd]; // And this is where it's to
	
				p.p.dstnet = network[netptr].network;
				p.p.dststn = network[netptr].station;

				if (from_found == 0xffff)
					fprintf (stderr, "*PIPE: to %3d.%3d              traffic from unknown AUN source.\n", p.p.dstnet, p.p.dststn);
				else
				{
					p.p.srcnet = network[from_found].network;
					p.p.srcstn = network[from_found].station;

					p.p.ctrl |= 0x80; // Put the high bit back on the ctrl 

					if (network[netptr].pipewritesocket != -1) // We have a live writer socket
					{
						struct __econet_packet_pipe delivery;

						dump_udp_pkt_aun(&p, r+4);
						
						delivery.length_low = (r+4) & 0xff;
						delivery.length_high = ((r+4) >> 8) & 0xff;
						
						write (network[netptr].pipewritesocket, &delivery, r+4+2);
					}
					else
						fprintf (stderr, "*PIPE: to %3d.%3d from %3d.%3d traffic received on UDP for named pipe but pipe not connected\n", p.p.dstnet, p.p.dststn, p.p.srcnet, p.p.srcstn );
				}

			}
			else if (pset[realfd].revents & POLLIN) // Boggo standard AUN/IP traffic from single station, or on a named pipe
			{
				/* Read packet off UDP here */
				int  r;
				struct __econet_packet_aun p;

				//int count;

				if (network[fd_ptr[pset[realfd].fd]].type & ECONET_HOSTTYPE_TNAMEDPIPE)
				{

					int length;
					unsigned char c;

					length = 0;
					
					read(pset[realfd].fd, &c, 1);
					length = c;
					read(pset[realfd].fd, &c, 1);
					length += (c << 8);

					r = read(pset[realfd].fd, &(p.raw), length);

					if (r < 0) continue; // Something went wrong

					// The received packet will have a valid destination on it, but we will need to fill in the source

					p.p.srcnet = network[fd_ptr[pset[realfd].fd]].network;
					p.p.srcstn = network[fd_ptr[pset[realfd].fd]].station;

					network[fd_ptr[realfd]].last_transaction = time(NULL);
					
					// If the pipewritesocket is not open, open it because we've received traffic

					if (network[fd_ptr[pset[realfd].fd]].pipewritesocket == -1)
					{
						char writerfilename[250];
		
						snprintf(writerfilename, 249, "%s.frombridge", network[fd_ptr[pset[realfd].fd]].named_pipe_filename);

						network[fd_ptr[pset[realfd].fd]].pipewritesocket = open(writerfilename, O_WRONLY | O_NONBLOCK | O_SYNC);
						if (pkt_debug) fprintf (stderr, "*PIPE: to %3d.%3d from %3d.%3d traffic caused write pipe to open (normal) - fd %d\n", p.p.dstnet, p.p.dststn, p.p.srcnet, p.p.srcstn, network[fd_ptr[pset[realfd].fd]].pipewritesocket);
					}

					/* This sends ACK & NAK that might arise from the named pipe - they can ignore it if they want */
					aun_send(&p, r); // Send ACK & NAK as well because that's handled properly now.

				}
				else
				{

					// This is all UDP receiver code - AUN only (trunks dealt with above)
	
					r = udp_receive(pset[realfd].fd, (void *) &(p.p.aun_ttype), sizeof(p)-4, (struct sockaddr * restrict) &src_address);
	
					if (r< 0) continue; // Debug produced in udp_receive
	
					/* Look up where it came from */
	
					from_found = econet_find_source_station (&src_address); // 0xffff;
	
					/* Now where did was it going /to/ ? We can find that by the listening socket number */
		
					to_found = fd_ptr[pset[realfd].fd];
	
					/* TODO - If this is an ACK for something we sent, check it against ackimm_seq_awaited */

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
									if (pkt_debug) fprintf (stderr, "  DYN:%12s             Spoofing *bye to known wired fileservers...", "");
	
									for (netcount = 0; netcount < stations; netcount++)
									{
										if (network[netcount].is_wired_fs)
										{
											if (pkt_debug) fprintf (stderr, "%d.%d ",  network[netcount].network, network[netcount].station);
											bye.p.dststn = network[netcount].station;
											bye.p.dstnet = network[netcount].network;
											
											aun_send(&bye, 16);
										}
			
									}
			
									if (pkt_debug) fprintf (stderr, "\n");
	
								}	
								
	
							}
	
							stn_count++;
						}
	
					}
	
					if ((from_found != 0xffff) && (to_found != 0xffff)) // We know source & destination stations (necessary because this is AUN traffic, so it can't be going to a trunk!)
					{
	
						// Complete the internal format packet
	
						p.p.srcnet = network[from_found].network;
						p.p.srcstn = network[from_found].station;
						p.p.dstnet = network[to_found].network;
						p.p.dststn = network[to_found].station;
	
						network[from_found].last_transaction = time(NULL);
						
						if (p.p.aun_ttype == ECONET_AUN_ACK || p.p.aun_ttype == ECONET_AUN_IMMREP || p.p.aun_ttype == ECONET_AUN_NAK)
						{
							if (p.p.aun_ttype == ECONET_AUN_NAK)
							{
								if (queue_debug) fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d len 0x%04X seq 0x%08X NAK received!\n",
									p.p.srcnet, p.p.srcstn, p.p.dstnet, p.p.dststn, r+4, p.p.seq);
							}
							else if (p.p.seq == network[from_found].ackimm_seq_awaited) // Found the ACK or IMMREP sequence this host was supposed to produce
							{
								if (queue_debug) fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d len 0x%04X seq 0x%08X found ack/imm rep which was awaited\n",
									p.p.srcnet, p.p.srcstn, p.p.dstnet, p.p.dststn, r+4, p.p.seq);

								network[from_found].ackimm_seq_awaited = 0;
								network[from_found].aun_last_tx.tv_sec = network[from_found].aun_last_rx.tv_usec = 0;
			
								poll_timeout = -1;  // Go back to normal timeout if we find the packet we want

								// And dump the packet off the head if it's the same sequence
	
								if (network[from_found].aun_head && p.p.seq == network[from_found].aun_head->p->p.seq)
									econet_general_dumphead (&(network[from_found].aun_head), &(network[from_found].aun_tail));

							}
						}

						/* Put it on the queue using AUN_SEND() */
						if ((network[to_found].type & ECONET_HOSTTYPE_TNAMEDPIPE) || (!( (p.p.aun_ttype == ECONET_AUN_ACK) || (p.p.aun_ttype == ECONET_AUN_NAK) ))) // Ignore those sorts of packets unless going to named pipe. (I.e. if going to local emulation or wire, we drop them)
							aun_send(&p, r+4);
/* DISABLED. We now acknowledge all incoming AUN data because otherwise we get too rapid retransmits on a busy Econet wire 
						if (p.p.aun_ttype == ECONET_AUN_DATA && (network[to_found].type & ECONET_HOSTTYPE_TNAMEDPIPE || network[to_found].type & ECONET_HOSTTYPE_TLOCAL)) // If AUN was sending to local or named pipe, we'll do the ACK (wire and trunk do their own)
*/
						if (p.p.aun_ttype == ECONET_AUN_DATA)
							aun_acknowledge(&p, ECONET_AUN_ACK);
	
					}
					else	
						if (pkt_debug) fprintf (stderr, "ERROR: UDP packet received on FD %d; From%s found, To%s found (pointer %d)!\n", pset[realfd].fd, ((from_found != 0xffff) ? "" : " not"), ((to_found != 0xffff) ? "" : " not"), to_found);
				}
			}
		
		}
	
		fs_bulk_traffic = fs_dequeuable(); // In case something got put there from UDP/Wire/Local above

		if (fs_bulk_traffic)	fs_dequeue(); // Do bulk transfers out.
	
		fs_bulk_traffic = fs_dequeuable(); // Reset flag for next while() loop check


		// Now see if we have queues to empty

		// First the wire

		if (wire_head) // On successful TX, we'll send an ACK if the source was AUN or trunk & dump the packet off the queue. Unsuccessful tx, we'll increment the tx counter. We dump packets that are more than 2s old or have had 10 tx attempts
		{
			struct timeval now;

			gettimeofday(&now, 0);

			if (queue_debug) fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d len 0x%04X retrieved from wire queue (tx count %02d) ", 
				wire_head->p->p.dstnet,
				wire_head->p->p.dststn,
				wire_head->p->p.srcnet,
				wire_head->p->p.srcstn,
				wire_head->size,
				wire_head->tx_count);

			if (wire_head->tx_count++ < ECONET_WIRE_MAX_TX) // we'll have a go at transmitting
			{
				int err;

				if (econet_write_wire(wire_head->p, wire_head->size, 0) == wire_head->size || (ioctl(econet_fd, ECONETGPIO_IOC_TXERR) == 0)) // successful tx
				{
					if (queue_debug) fprintf (stderr, "Sent ");
					if (is_aun(wire_head->p->p.srcnet, wire_head->p->p.srcstn) && wire_head->p->p.aun_ttype == ECONET_AUN_DATA) // Send ACK if we've just successfully sent a DATA packet and the sender is AUN
					{
/* Disabled because we ack an AUN on receipt now to avoid rapid retransmits from BeebEm
						if (queue_debug) fprintf (stderr, " AUN ack sent ");
						aun_acknowledge(wire_head->p, ECONET_AUN_ACK);	
*/
					}
					if (queue_debug) fprintf (stderr, "\n");
					econet_general_dumphead(&wire_head, &wire_tail);
					wire_tx_errors = 0;
				}
				else 
				{
					err = ioctl(econet_fd, ECONETGPIO_IOC_TXERR);
					if (err == ECONET_TX_HANDSHAKEFAIL) // Receiver not present
						econet_general_dumphead(&wire_head, &wire_tail);

					/* Inserted because on *REMOTE traffic where the remoted station is talking to the server, we tend to get lots of module busy for some reason, so we'll pretend they didn't happen. */

					if (err == ECONET_TX_BUSY) wire_head->tx_count--;

					if (wire_tx_errors++ > 300)
						ioctl(econet_fd, ECONETGPIO_IOC_READMODE);

					if (queue_debug) fprintf (stderr, "TX FAIL - %s (0x%02X)\n", econet_strtxerr(-1 * err), err);
				}
			}
			else	
			{
				if (queue_debug) fprintf (stderr, "DUMPED - old or tx count exceeded\n");
/*
				if (wire_head->tx_count >= ECONET_WIRE_MAX_TX) // Reset the chip just in case
					ioctl(econet_fd, ECONETGPIO_IOC_READMODE);
*/

				econet_general_dumphead(&wire_head, &wire_tail);
				
			}
	

		}

		// AUN traffic
	
		if (aun_queued)
		{
			int count;

			//if (queue_debug) fprintf (stderr, "QUEUE: Attempting to find AUN output entries\n");

			for (count = 0; count < stations; count++)
			{
				if ((network[count].type & ECONET_HOSTTYPE_TDIS) && (network[count].aun_head)) // This is an AUN host and it has queued packets
				{
					struct timeval now;
					long tdiff; // , rx_tdiff;

					gettimeofday(&now, 0);

					tdiff = timediffmsec(&(network[count].aun_last_tx), &now);
					//rx_tdiff = timediffmsec(&(network[count].aun_last_rx), &now); // Used so that when we want to transmit, it is not too close to the last received packet from this host, because it seems to cause problems

					//if (queue_debug) fprintf (stderr, "QUEUE: Examining queue on AUN host at network[%d]\n", count);

					// First, if there is a sequence number this host is waiting for an ACK on and this packet is not an IMMREP with that sequence number, don't send anything - just move on, unless it's timed out.

					if ((network[count].ackimm_seq_tosend) && (timediffmsec(&(network[count].aun_last_rx), &now) > 2000)) // Ditch the last RX / Seq tracker
					{
						if (queue_debug) fprintf (stderr, "QUEUE: Last receipt from station > 2s ago - dumping ACK tracker (seq %08X) for packets to network[%d]\n", network[count].ackimm_seq_tosend, count);
						network[count].aun_last_rx.tv_sec = network[count].aun_last_rx.tv_usec = 0;
						network[count].ackimm_seq_tosend = 0;
					}

					if (network[count].ackimm_seq_tosend && (network[count].aun_head->p->p.aun_ttype != ECONET_AUN_IMMREP || network[count].aun_head->p->p.seq != network[count].ackimm_seq_tosend)) // If this host is waiting for an IMM REP, and this one either isn't one of those, or isn't the right sequence number, then ignore it.
					{
						//if (queue_debug) fprintf (stderr, "QUEUE: network[%d] expecting sequence 0x%08X but this wasn't it\n", count, network[count].ackimm_seq_tosend);
						continue; // Next host please!
					}

					// Similarly, if we haven't had an ACK from this host for something we needed, then don't send anything
		
					if (network[count].ackimm_seq_awaited) // If we are waiting for an ACK or IMMREP *from* this host, don't send it anything unless we need to re-tx a data packet
					{
						if (tdiff > 0 && tdiff < ECONET_AUN_ACK_WAIT_TIME)
						{
							if (queue_debug) fprintf (stderr, "QUEUE: network[%d] hasn't yet acked sequence 0x%08X - skipping\n", count, network[count].ackimm_seq_awaited);
							continue;
						}

						// else drop through and let it retransmit if necessary
					}

					// If we are sending, then send it, increase tx_count and if it went OK then drop it off the queue and decrement the counter.

					if (network[count].aun_head) // This might have broken things && (network[count].ackimm_seq_awaited == 0 || network[count].ackimm_seq_awaited == network[count].aun_head->p->p.seq)) // If we have a queue for this host and either we aren't waiting for a particular ACK to come back OR the one we ARE waiting for matches the packet on the queue head so that we might need to retransmit it...
					{
						if (queue_debug) fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d len 0x%04X type 0x%02X seq 0x%08X retrieved from network[%d] queue (tx count %02X) (tdiff = %ld)", 
							network[count].aun_head->p->p.dstnet,
							network[count].aun_head->p->p.dststn,
							network[count].aun_head->p->p.srcnet,
							network[count].aun_head->p->p.srcstn,
							network[count].aun_head->size,
							network[count].aun_head->p->p.aun_ttype,
							network[count].aun_head->p->p.seq,
							count, network[count].aun_head->tx_count, tdiff);

						if (network[count].aun_head->tx_count++ > ECONET_AUN_MAX_TX) // Dump
						{

							if (queue_debug) fprintf (stderr, " - dumped (too many retries)\n");
							/* Next two lines commented because if we dump the head packet on the queue, the comparison in the if statement below is meaningless */
							//econet_general_dumphead(&(network[count].aun_head), &(network[count].aun_tail));
							//aun_queued--;
							// Clear the ACK wait if it was this packet
							if (network[count].aun_head && network[count].ackimm_seq_awaited == network[count].aun_head->p->p.seq)	
							{
								network[count].aun_last_tx.tv_sec = network[count].aun_last_tx.tv_usec = 0;
								network[count].ackimm_seq_awaited = 0;
								// And dump the rest of the queue because it probably won't respond
								while (network[count].aun_head)
								{
									struct __econet_packet_aun_cache *p;

									p = network[count].aun_head->next;
									free (network[count].aun_head->p); // Free the packet
									free (network[count].aun_head); // And the structure itself
									network[count].aun_head = p;
									aun_queued--;
								}

								network[count].aun_head = network[count].aun_tail = NULL; // Reset
							}

						}
						else if (network[count].ackimm_seq_awaited && (network[count].ackimm_seq_awaited != network[count].aun_head->p->p.seq) && tdiff > 0 && tdiff < ECONET_AUN_ACK_WAIT_TIME) // Waiting for an ACK from this host and this wasn't it and we haven't waited long enough yet and the packet on the head of the queue is not the same one, so not to be retransmitted (the timeout check is done above!)
						{
							if (queue_debug) fprintf (stderr, "\n");
							continue;
						}
						else if ( 	
/*
								(
								((tdiff > ECONET_AUN_INTERPACKET_GAP) && (rx_tdiff > ECONET_AUN_INTERPACKET_GAP)) || (usleep(ECONET_AUN_INTERPACKET_GAP * 1000))
								) && 
*/
							econet_write_general(network[count].aun_head->p, network[count].aun_head->size) == network[count].aun_head->size
						)
						{
							if (queue_debug) fprintf (stderr, " - sent ");
							if (network[count].aun_head->p->p.aun_ttype == ECONET_AUN_DATA || network[count].aun_head->p->p.aun_ttype == ECONET_AUN_IMM)
							{
								if (queue_debug) fprintf (stderr, " - tracking seq for ack from AUN ");
								network[count].ackimm_seq_awaited = network[count].aun_head->p->p.seq; // This is the Ack we are waiting for before we send anything else
								gettimeofday(&(network[count].aun_last_tx), 0);
					
								if (network[count].aun_head->p->p.aun_ttype == ECONET_AUN_IMM) // If we just sent an immediate to an AUN host, set the poll_timeout
									poll_timeout = 500;
							}

							// If this was the priority packet, clear ackimm_seq_tosend
							if (network[count].aun_head->p->p.seq == network[count].ackimm_seq_tosend)
							{
								if (queue_debug) fprintf (stderr, " - found seq the AUN machine was awaiting ");
								network[count].ackimm_seq_tosend = 0; // Blank off
							}

							// Dump the queue entry if we don't need to retransmit it
							if (network[count].aun_head->p->p.aun_ttype != ECONET_AUN_DATA)
							{
								if (queue_debug) fprintf (stderr, " - dumping from queue (not a data packet we might re-tx) ");
								econet_general_dumphead(&(network[count].aun_head), &(network[count].aun_tail));
								aun_queued--;
							}

							// If we are more than the ACK time since transmitting a packet we were waiting on an ACK for, and that packet isn't on the queue head, then ditch the 'awaited' tracker because it's not going to come
							if (tdiff > ECONET_AUN_ACK_WAIT_TIME && ((!network[count].aun_head) || (network[count].ackimm_seq_awaited != network[count].aun_head->p->p.seq)))
							{
								network[count].aun_last_tx.tv_sec = network[count].aun_last_tx.tv_usec = 0;
								network[count].ackimm_seq_awaited = 0;
							}

							if (queue_debug) fprintf (stderr, "\n");
						}
						else if (queue_debug) fprintf (stderr, "FAILED\n");

					}

				}

			}

		}

		// Then trunks - One packet at a time for now. Maybe more sophisticated later

		if (trunk_head)
		{
			struct timeval now;

			if (queue_debug) fprintf (stderr, "QUEUE: to %3d.%3d from %3d.%3d length 0x%04X retrieved from trunk queue\n", 
				trunk_head->p->p.dstnet,
				trunk_head->p->p.dststn,
				trunk_head->p->p.srcnet,
				trunk_head->p->p.srcstn,
				trunk_head->size);

			gettimeofday(&now, 0);

			if (timediffmsec(&(trunk_head->tstamp), &now) < 2000) // Dump traffic older than 2s
				aun_trunk_send(trunk_head->p, trunk_head->size);

			// We're going to dump it either way - if the send didn't work, we don't want to hold the trunk up

			econet_general_dumphead(&trunk_head, &trunk_tail);
		}

		// Fileserver garbage collection

		for (s = 0; s < stations; s++)
		{
			if (network[s].servertype & ECONET_SERVER_FILE) 
			{
				//if (fs_noisy) fprintf(stderr, "   FS: Garbage collect on server %d\n", network[s].fileserver_index);
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
		
		start_fd = last_active_fd;
	}


	ioctl(econet_fd, ECONETGPIO_IOC_READMODE); // Reset the module - we have got here because an Immediate to AUN went unresponded to, so the chip will not be in read mode any more.

   }
}

// Printer information functions for the fileserver (but we have all the variables...)
uint8_t get_printer_info(unsigned char net, unsigned char stn, uint8_t printer, char *pname, char *banner, uint8_t *control, uint8_t *status, short *user)
{

	int p; // network pointer

	p = econet_ptr[net][stn]; // Look up the network entry

	*control = *status = *user = 0; // Initialize
	snprintf(banner, 24, "%23s", "");
	snprintf(pname, 7, "%6s", "");  // Puts a null in pname[0]

	if (p == -1) // Unknown station
		return 0; // So will return empty data

	if (!(network[p].servertype & ECONET_SERVER_PRINT)) // not a print server at all
		return 0; 

	if (network[p].numprinters < printer) // Unknown printer index
		return 0;

	snprintf(pname, 7, "%6.6s", network[p].printers[printer].name);
	snprintf(banner, 24, "%23.23s", network[p].printers[printer].banner);
	*control = network[p].printers[printer].control;
	*status = network[p].printers[printer].status;
	*user = network[p].printers[printer].user;

	return 1;

}

uint8_t set_printer_info(unsigned char net, unsigned char stn, uint8_t printer, char *pname, char *banner, uint8_t control, ushort user)
{

	int p; // network pointer

	p = econet_ptr[net][stn]; // Look up the network entry

	if ((p == -1) || (!(network[p].servertype & ECONET_SERVER_PRINT)) || (network[p].numprinters < printer)) // See logic in get_printer_info()
		return 0;

	snprintf(network[p].printers[printer].name, 7, "%6.6s", pname);
	snprintf(network[p].printers[printer].banner, 24, "%23.23s", banner);
	network[p].printers[printer].control = control;
	network[p].printers[printer].user = user;

	return 1;
}

uint8_t get_printer_total(unsigned char net, unsigned char stn)
{

	int p; // network pointer

	p = econet_ptr[net][stn]; // Look up the network entry

	if ((p == -1) || (!(network[p].servertype & ECONET_SERVER_PRINT))) // See logic in get_printer_info()
		return 0;

	return network[p].numprinters;

}
