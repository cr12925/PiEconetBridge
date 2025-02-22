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

#ifndef __ECONETBRIDGE_H__
#define __ECONETBRIDGE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
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
#include <pthread.h>
#include <stdarg.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <termios.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "econet-gpio-consumer.h"

#define DEVINIT_DEBUG(_fmt, ...) if (dumpconfig) eb_debug (0, 0, "CONFIG", "%-16s " _fmt, "Core", __VA_ARGS__)

// Server version number advertised
#define EB_VERSION	0x22 // i.e. 2.2
#define EB_SERVERID	"Pi HP Bridge"

#define EB_TRUNK 	0x01
#define EB_WIRE 	0x02
#define EB_PIPE		0x04
#define EB_LOCAL	0x08
#define EB_AUN		0x10
#define EB_NULL		0x20
#define EB_MULTITRUNK	0x40
#define EB_POOL		0x80

#define EB_ADV_SHIFT	0
#define EB_TYPE_SHIFT	8
#define EB_ADV_MASK	((EB_TRUNK | EB_WIRE | EB_PIPE | EB_LOCAL | EB_AUN | EB_POOL) << EB_ADV_SHIFT)
#define EB_ADV_ALL	((EB_TRUNK | EB_WIRE | EB_PIPE | EB_LOCAL | EB_POOL) << EB_ADV_SHIFT) // We never do bridging with AUN stations. They should know where things are.
#define EB_ADV_NONE	0x00

/* The lower bits of these definitions are actually not used. They were planned
 * to help the bridge protocol (trunks, wires) decide what to advertise, but
 * in the end we just do it from the networks table
 *
 * But I've maintained the definitions as they originally were because they're
 * used for comparison purposes and it means I don't need to check if 
 * something will break!
 */
#define EB_DEF_TRUNK	((EB_TRUNK << EB_TYPE_SHIFT) | EB_ADV_ALL)
#define EB_DEF_WIRE	((EB_WIRE << EB_TYPE_SHIFT) | EB_ADV_ALL)
#define EB_DEF_PIPE	((EB_PIPE << EB_TYPE_SHIFT) | EB_ADV_NONE) // Only the Null driver gets advertised, not the host
#define EB_DEF_LOCAL	((EB_LOCAL << EB_TYPE_SHIFT) | EB_ADV_NONE) // Ditto Pipe
#define EB_DEF_AUN	((EB_AUN << EB_TYPE_SHIFT) | EB_ADV_ALL) // Ditto Pipe
#define EB_DEF_NULL	((EB_NULL << EB_TYPE_SHIFT) | EB_ADV_ALL)
#define EB_DEF_MULTITRUNK	((EB_MULTITRUNK << EB_TYPE_SHIFT) | EB_ADV_ALL)	
#define EB_DEF_POOL	((EB_POOL << EB_TYPE_SHIFT) | EB_ADV_ALL)

#define EB_DEV_CONF_DIRECT	0x01	// Passes all traffic, unqueued, unmolested (including ACK, NAK) to the destination. Otherwise deals with ACK, NAK itself.
#define EB_DEV_CONF_AUTOACK	0x02	// When data traffic received from this station (usually AUN) send it an ACK immediately and don't bother tracking what actually got delivered or where from


/* 
 * Bridge protocol defines.
 *
 * These are port & ctrl values
 *
 */

#define BRIDGE_PORT	0x9C
#define BRIDGE_RESET	0x80
#define BRIDGE_UPDATE	0x81
#define BRIDGE_WHATNET	0x82
#define BRIDGE_ISNET	0x83

/*
 * The following are part of the HPB's bridge system
 * but NOT part of Acorn or SJ's world.
 *
 */

#define ECONET_TRACE_PORT		0x9B	// Port number used for HPB traceroute functionality
#define ECONET_BRIDGE_KEEPALIVE_CTRL	0xD0	// Ctrl byte used for trunk keepalive packets
#define ECONET_BRIDGE_LOOP_PROBE	0xCF	// Used to for loop probes to see if we need to shut a device down

struct __eb_packetqueue {
	struct __econet_packet_aun 	*p;
	struct timeval 			last_tx; // Last transmission attempt on an input queue (i.e. sending to the destination driver); on an output queue this is when the packet got put on the queue - used to time it out and dump the rest of the queue if need be
	uint8_t 			tx; // Number of transmission attempts
	uint8_t				errors; // Number of transmission errors
	uint8_t				notlistening; // Number of not listening errors (subset of 'errors')
	uint16_t			length; // Length of packet including 12 byte header
	struct __eb_packetqueue 	*n; // Next or null.
};

struct __eb_outq { // Definition of outbound queue from device (i.e. going from the device to the outside world). NB on queue entry per destination (net,stn)
	struct __eb_packetqueue *p;
	struct __eb_device	*destdevice; // Pointer to __eb_device for the device this is headed to
	uint16_t	destcombo;
	uint8_t		is_aun_output; // Used so we can skip queues which aren't going to AUN, if we're doing a retransmit run
	struct __eb_outq *next;
};

#define EB_FW_ACCEPT 0x01
#define EB_FW_REJECT 0x02
#define EB_FW_CHAIN  0x04 /* Pass to another chain */
//#define EB_FW_DEFAULT EB_FW_ACCEPT

/* Firewall entry. */
struct __eb_fw { // Firewall entry - any value which is &FF is the wildcard
	uint8_t srcnet, srcstn, dstnet, dststn;
	uint8_t port;
	uint8_t action;
	struct __eb_fw *next;
};

/* Firewall chain names */

struct __eb_fw_chain {
	unsigned char *		fw_chain_name;
	uint8_t			fw_default; /* One of the EB_FW_{ACCEPT,REJECT} values for the default result if nothing matches */
	struct __eb_fw		*fw_chain_start;
	struct __eb_fw_chain	*next;
};

/* Define a printjob
*/

struct __eb_printjob {
	uint8_t		net, stn; // Who started it
	uint8_t		ctrlbit; // Oscillating sequence tracker
	FILE		*spoolfile; // What it sounds like
	char		spoolfilename[128]; // What it sounds like
	char		username[10];
	struct __eb_printjob	*next, *parent;
};

/* Define a printer associated with a virtual station
*/

struct __eb_printer { // Struct used to hold printer definitions on local emulation stations
	uint8_t		priority; // SJ Printer priority
	uint8_t		isdefault; // 1 if this a default printer pool member
	char		acorn_name[7]; // Acorn printer name
	char		unix_name[128]; // Unix printer name
	char		handler[256]; // Print handler path
	uint8_t		status; // SJ Status
	uint8_t		control; // SJ Control
	char		user[10]; // Only this user can use this printer
	struct __eb_printjob	*printjobs; // NULL means none.

	struct __eb_printer	*next;
};


/* Locally emulated filstore
*/

struct __eb_fileserver { // Struct used to hold data defining a locally emulated fileserver
	char 		*rootpath; // Full pathname to directory holding password file & directories for emulated disks
	struct __fs_station	*server; // Pointer to __fs_station struct created on initialization - NULL if not initialized
	pthread_t	fs_thread; // FS thread - attempt to stop core dumps when thread exits
	pthread_mutex_t	statsmutex; // Lock on the stats values - they are written to and read by different threads
	uint64_t	b_in, b_out; // Traffic stats
};

/* Locally emulated IP gateway
*/

struct __eb_ipgw {
	char	tunif[10];
	char	addr[20];
	int	socket; // Connection to tunnel
	struct __eip_addr *addresses;
	uint64_t	b_in, b_out; // Traffic stats
	pthread_mutex_t	statsmutex; // Lock on the stats values - they are written to and read by different threads
	// More stuff here - host order IP etc.
};

#define EB_EXP_INACTIVE		0
#define EB_EXP_PERMANENT	1
#define EB_EXP_TRANSIENT	2

/* This structure defines an AUN exposure of an internal host. E.g. if we choose to expose host 4.65 (which
   might be bridged over a wired econet, for example, or might be over a trunk, or whatever, there will
   be one of these structures, and there will be a thread listening for traffic on it and 
   passing it back to the relevant driver.
*/
struct __eb_aun_exposure {
	uint8_t			stn; // Station number. (Net number found in driver struct.)
	uint8_t			net; // Network number. (In case we are exposing a distant station.)
	int			socket; // Socket we listen on for this station
	in_addr_t		addr; // Local address of hostname of exposure
	int			port; // Local port we are listening on
	uint8_t			active; // 0 = inactive; 1 = permanently active (exposed host is permanently defined); 2 = temporarily active (exposed host is known over a bridge and may be removed) - see #defines above
	pthread_mutex_t		statsmutex; // Lock on the stats values - they are written to and read by different threads
	uint64_t		b_in, b_out; // Interface exposure state
	pthread_mutex_t		exposure_mutex; // Used when the socket int is being updated by the starter thread, or when the active flag is being altered/read
	pthread_t		me; // Thread structure for this exposure
	struct __eb_device	*parent; // Parent device which is exposed by this exposure
	struct __eb_aun_exposure	*next; // Next in list
};

/* __eb_aun_remote - Defines a chain of remote AUN stations we talk to. They are ordered by s_addr in some way.
   We keep a list here, separately, so we can find where traffic originated.
   The device driver struct can have a pointer to /one/ of these creations which can be used as a divert,
   and hence the station number entry.
   But these can be standalone and not used as a divert at all. If so, eb_device = NULL in this struct.
   If this is being used as a divert, eb_device points to the network device struct for the network
   in question.
*/
struct __eb_aun_remote {
	uint8_t		stn; // Station number
	int		port; // Port number on remote host
	in_addr_t	addr; // Socket info for remote end - Used to look up where traffic came from
	struct __eb_device	*eb_device; // Pointer to eb_device struct if this is a divert.
	pthread_mutex_t	statsmutex; // Lock on the stats values - they are written to and read by different threads
	pthread_mutex_t updatemutex; // Lock when reading or updating
	uint64_t	b_in, b_out; // Traffic stats
	uint8_t		is_dynamic; // 1 = Available for dynamic use.
	struct timeval	last_dynamic; // Last time we saw traffic on a dynamic host. If > 1 hour, dump it & reuse. Set to 0 on init so they get used.
	struct __eb_aun_remote	*next;
};

/* __eb_pool_host
 *
 * Used to store information about a single host translation in the pool
 */

struct __eb_pool_host {
	pthread_mutex_t		statsmutex; // Lock on stats
	uint64_t		b_in, b_out; // Save for traffic to unallocated stations in the pool, these should always match
	// No updatemutex - if the pool is locked, so are all the hosts within it
	// Hence why all the search / create functions require the mutex on the pool
	uint8_t			is_static; // Don't time it out if static
	struct timeval		last_traffic; // Last time we saw traffic. Used to reallocate non-static entries if stale.
	struct __eb_device	*source; // Source device - e.g. a trunk, a wire. NULL means this is an inactive entry.
	struct __eb_pool	*pool; // The pool this is a member of
	uint8_t			s_net, s_stn; // Net & station as seen at the distant end (i.e. via *source).
	uint8_t			net, stn; // Station number within the pool net.
	struct __eb_pool_host	*next_net; // Linked list. next_net points to next structure in the pool net
	struct __eb_pool_host	*prev_net; // Linked list, upward pointers - so we can splice things out 
};

/* __eb_pool
 *
 * Used to implement many to few nat down trunks and econets so as to allow large-scale joining of networks together
 *
 * POOL is a type of device, and its entry in the __eb_device union is simply a pointer to one of these. 
 * The point is that pool nets will go in networks[] but all of the entries which pertain to the same pool
 * will end up sharing data in this struct.
 */

struct __eb_pool {
	pthread_mutex_t		updatemutex; // Lock when reading or updating this struct.
	unsigned char		name[11]; // Text name of pool
	uint8_t			networks[255]; // Which nets are in this pool. Net 0 can never be in here - always a real number
	uint8_t			last_net; // Last network number from which we allocated a dynamic host - we round-robin them so that the __eb_pool_host lists stay somewhere near balanced
	struct __eb_pool_host	*hosts_net[255]; // Done by network number. Ditto net 0. (Linked list per device is in the device struct)
	struct __eb_pool	*next; // In master pools list, below
};

/* __eb_notify
 *
 * Struct for holding incoming notify characters for local stations
 *
 */

struct __eb_notify {
	uint8_t			net, stn; // Source of characters
	time_t			last_rx; // Last reception - used to work out when to display
	unsigned char		msg[256];
	uint8_t			len; // Length of msg[] to save strlen() calls
	struct __eb_notify	*next;
};

/* __eb_device

   Holds common and per-driver information about devices on which we might send/receive packets.
   
   AUN, PIPE and LOCAL only exist in host form, and can only exist as what are known of as 
   'diverts' - i.e. a station which exists in the network number serviced by another
   driver, but which is not on that driver's actual device. Examples include:

   A locally emulated fileserver in net 1, where net 1 is actually an Econet wire.
   All AUN stations. These exist as diverts in the NULL driver.
   A local pipe client in an otherwise unused network, e.g. 6, So if the pipe station is 6.250,
   there will be a NULL network 6 (which can thereby be advertised) with a divert for station
   250, containing a pointer to the __eb_device structure for the pipe host.

*/

// Port handler function

typedef void (*port_func) (struct __econet_packet_aun *, uint16_t, void *);

struct __eb_device { // Structure holding information about a "physical" device to which we might send packets to / receive packets from.


	uint8_t			net; // Network number of this device
	uint16_t		type; // EB_DEF_TRUNK, WIRE, etc.
	pthread_t		listen; // Reader thread - e.g. the one reading from /dev/econet-gpio, or from an AUN listener socket
	pthread_t		me; // Main despatcher thread
	pthread_mutex_t		qmutex_in, qmutex_out; // Mutex to local the queues on this device
	pthread_cond_t		qwake; // Condition which wakes us up when we might need to manage the queues
	struct __eb_outq	*out; // Queue leaving this device to outside world, separate queues per destination
	struct __eb_packetqueue	*in; // Inbound queue (all one list)
	struct __econet_pcaket_aun	*priority; // Not implemented yet. Will have 12 bits malloc()'d at startup and contains the pattern we are looking for as a packet to prioritize to top of input queue. Will be used both for immediates and for spotting ACKs when in the proposed new 'resilience' mode
	struct __eb_packetqueue	*device_input; // Traffic arriving from the device itself (e.g. off the wire, from a pipe)
	pthread_mutex_t		device_input_mutex; // Locks device_input queue
	uint8_t 		p_net, p_stn; // Priority net, stn - if an immediate arrives from outside world from this net, stn, put it on head of inbound queue
	uint32_t		p_seq; // Priority sequence number
	pthread_mutex_t		priority_mutex; // Locks the priority variables above, read & write
	uint8_t			config; // Config bits - EB_DEV_CONF_XXX
	pthread_mutex_t		statsmutex; // Lock on the stats values - they are written to and read by different threads
	uint64_t		b_in, b_out; // Traffic stats
	struct __eb_aun_exposure	*exposures; // Pointer to start of this net in the AUN exposure list
	struct __eb_outq	*aun_out_head, *aun_out_tail; // AUN output queues for this device
	pthread_mutex_t		aun_out_mutex; // Lock on AUN output queues (above)
	pthread_cond_t		aun_out_cond; // Condition for AUN sender thread
	pthread_t		aun_out_thread; // Thread which sends AUN traffic out
	struct __eb_device	*self; // Pointer to own struct in case of need
	struct pollfd		p_reset; // The fresh pollfd structure used by device listeners. Saves recreating it every time
	
	pthread_mutex_t		updatemutex; // Only really used to lock pool information, but probably ought to be used for other things as well, like the station maps on a wire (but then they might only be changed in one thread...)

	// Timeouts
	time_t			last_rx; // Last reception on this device - used to time out dead trunks and dynamic AUN stations (when I've written that bit!)

	/* Bridge protocol-related material */

	pthread_cond_t		bridge_update_cond; // Used to wake up the bridge updater (only used on Wire/Trunk devices)
	pthread_t		bridge_update_thread; // Bridge update thread (NB: Resets handled in main broadcast handler now)
	pthread_t		bridge_update_thread2; // 2nd Bridge update thread (NB: Resets handled in main broadcast handler now)
	pthread_mutex_t		bridge_update_lock; // Required for the condition above to work.
	pthread_cond_t		bridge_reset_cond; // Ditto for bridge resetter
	pthread_t		bridge_reset_thread; // Ditto for bridge resetter
	pthread_mutex_t		bridge_reset_lock; // Ditto for bridge resetter
	uint8_t			all_nets_pooled; // Used to work out whether not to forward resets on this device (only relevant for wire or trunk)

	/* Firewall per device - available with JSON config */

	struct __eb_fw_chain		*fw_in, *fw_out; /* 'in' is for traffic going TO the device (e.g. being sent to a fileserver, pipe, econet, or trunk - i.e. going away from the bridge), 'out' is stuff emanating out of the device (i.e. arriving on a pipe, from a fileserver, off an econet, arriving on a trunk) */

	// Per device type information
	union {

		struct { // A trunk will simply receive traffic and pass it straight to one of the other drivers for the network concerned, after doing NAT and firewalling

			// General parameters
			int 		socket;
			pthread_mutex_t	mt_mutex; // Locks mt_client - which is NULL if we are an inactive multitrunk client. And that structure also containts our pipe2() pair.
			pthread_cond_t	mt_cond;
			uint8_t		mt_addr_flags; // Can be used to set IPV6_ONLY
			// Probably need a struct mt_client *mt_client; here so that we know where our sockets & things are in multitrunk world

			char 		*hostname;
			struct addrinfo	*remote_host; // updated by mt_client / mt_server when we're a multitrunk
			int 		local_port, remote_port; // For UDP trunks only
			int		is_dynamic; // 0 = fixed other end; 1 = dynamic other end

			// Encryption parameters
			unsigned char	*sharedkey; // PSK for SHA hash on authenticated trunks
			EVP_CIPHER_CTX	*ctx_enc, *ctx_dec; // Encryption control
			unsigned char	iv[EVP_MAX_IV_LENGTH];
#define TRUNK_CIPHER_ALG 0
#define TRUNK_CIPHER_IV 1
#define TRUNK_CIPHER_DATA (TRUNK_CIPHER_IV + EVP_MAX_IV_LENGTH)
#define TRUNK_CIPHER_TOTAL (TRUNK_CIPHER_DATA + (((ECONET_MAX_PACKET_SIZE + 12 + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE))
			uint8_t		cipherpacket[TRUNK_CIPHER_TOTAL];
			int		encrypted_length;	
			AES_KEY		aes_key; // Key converted to AES-usable format

			// Pool nat config
			uint8_t			use_pool[255];
			struct __eb_pool	*pool;

			uint8_t 	xlate_in[256], xlate_out[256]; // Network number translation. _in translates a source network when the trunk receives traffic (and translates bridge advertised network numbers); _out translates a destination network when the trunk sends traffic.  Set up when config is read.
			uint8_t		filter_in[256], filter_out[256]; // Networks we ignore (i.e. we ditch traffic, and we ignore/don't send adverts)
	
			// If part of multitrunk // If NULL then not part of multi-trunk

			struct __eb_device	*mt_parent;

			
			// Keepalive thread
			
			pthread_t	keepalive_thread;

		} trunk;

		struct {
			char		*mt_name;
			uint16_t	port; // Port number
			char 		* host; // NULL if all interfaces
			int		ai_family; // AF_INET, AF_INET6, AF_UNSPEC
			uint16_t	listenqueue; // listen queue length
			enum		{ MT_CLIENT = 1, MT_SERVER = 2} mt_type;

		} multitrunk;

		struct { // Network on a real econet wire via a bridge board
			int		socket; // Socket for Wire device we are talking to
			char 		*device; // Path to device we need to try and open (supports multiple adapters now - in theory!)
			struct timeval	last_tx; // Last transmission on this device - used to insert interpacket gap
			uint32_t	seq[256][256]; // Sequence numbers for wire stations. Used to track sequence numbers for wire stations. Local & Pipe are expected to do their own.
			uint8_t		last_imm_dest_net, last_imm_dest_stn; // Last wire station an immediate was sent to from somewhere that wasn't on the wire
			uint32_t	last_imm_seq; // Sequence number of the last immediate sent to the wire from somewhere else. If we get an immediate reply from the net/stn in the line above, then put the matching sequence number in the reply
			uint8_t		stations[8192]; // Station map for module
			uint8_t		stations_initial[8192]; // Used to re-initialize on a bridge reset
			uint8_t		stations_update_rq; // 1 = Please update the station set from stations[]
			pthread_mutex_t	stations_lock;
			struct __eb_device	*divert[255]; // Pointers to diverted stations. E.g. if station 1.254 on the wire is actually a local station, this will point to its __eb_device
			uint8_t		filter_in[256], filter_out[256]; // Networks we ignore (i.e. we ditch traffic, and we ignore/don't send adverts)
			uint8_t		period, mark; // clock speed. 0 = not set by user.
			struct timeval	last_bridge_whatnet[256]; // This and the corresponding _isnet array tell us when we last successfully sent a reply to such a query to a station on this wire.
			struct timeval  last_bridge_isnet[256];

			// Pool nat config
			uint8_t			use_pool[255];
			struct __eb_pool	*pool;

		} wire;

		struct { // A local emulation connected by named pipe
			char		*base; // Base filename (full path) to pipe
			int		skt_read, skt_write; // Sockets to read from or write to the pipe
			uint8_t		stn; // Station number
			uint32_t	seq; // Sequence number
			pthread_mutex_t	code_mutex; // Must acquire this lock before calling local code
		} pipe;

		struct { // A locally emulated server
			uint8_t			stn; // Station number
			struct __eb_printer 	*printers;	
			char			*print_handler; // Full path to printer handler script
			struct __eb_fileserver	fs; // Not a pointer, this one
			struct __eb_ipgw	ip; // Not a pointer, this one
			uint32_t		seq; // AUN sequence number
			pthread_mutex_t		ports_mutex; // Locks ports[]
			uint32_t		ports[8]; // Ports in use by devices attached to this local server
			uint32_t		reserved_ports[8]; // Ports we cannot just obtain on a non-zero port request
			port_func		port_funcs[256]; // Function handlers for each port
			void			*port_param[256]; // Pointer to parameter data registered when the port was seized (e.g. for an FS, it's the __fs_sstation struct)
			uint8_t			last_port; // Last port we allocated
			// Stuff to handle *FAST to a local host
			uint8_t			fastbit; // Oscillates 0, 1 on transmissions from the *FAST handler
			uint8_t			fast_priv_stns[8192]; // Bitmap of stations who have logged into this FS with the Bridge privilege bit (cleared on *BYE by the FS - means that if the FS gets shut down, we can still tell this was a privileged station)
			uint8_t			fast_input_ctrl; // Ditto on receiption
			uint8_t			fast_client_net, fast_client_stn; // Current client
			pthread_t		fast_handler; // Thread that is operating the *FAST handler
			pthread_t		fast_io_handler; // Thread that mediates IO between despatcher and the fast handler
			pthread_mutex_t		fast_io_mutex; // Governs access to the input/output variables below
			int			fast_to_despatch[2], fast_to_handler[2]; // Socketpairs
			uint8_t			fast_thread_alive; // despatcher sets to 0; *FAST thread sets to 1 - so we can tell it's ready
			uint8_t			fast_reset; // Set to 1 when we get a new connection
			uint8_t			fast_client_ready; // Set to 1 when client indicates it will receive more output to display - happens when we get the USRPROC call. If there is output, we send it. If not, this will get set to 1 so that the fast handler knows it can send it instead
			pthread_cond_t		fast_wake;
			struct __eb_notify	*notify; // List of stuff received via *notify to a local server
			pthread_mutex_t		notify_mutex; // Mutex to lock the notify list
			pthread_t		notify_thread; // Notify watcher thread for this device
		} local;

		struct __eb_aun_remote *aun; // Address of struct in the list of remote AUN stations, kept in order of s_addr

		struct { // Null driver - has diverts only. Exists so that the network gets advertized
			struct __eb_device	*divert[255]; // Pointers to diverted stations. E.g. if station 1.254 on the wire is actually a local station, this will point to its __eb_device. On the NULL device, this means we have a virtual network that we might advertise to trunks etc., but there is no real device - just some (not necessarily all stations which exist as diverts.
		} null;

		struct { // Pool
			struct __eb_pool	*data;
		} pool;
	};
	
	struct __eb_device	*next; // Linked list. Used to maintain the chain in *devices, except trunks, where it's a pointer to the next trunk in 'trunks' because whilst a trunk will appear in networks[], it doesn't have a network number of its own.

};

#define EB_PORT_SET(device,list,port,func,param)	{ device->local.list[((port) / 32)] |= (1 << (port & 0x01f));  device->local.port_funcs[(port)]=func; device->local.port_param[(port)]=param; }
#define EB_PORT_CLR(device,list,port)	device->local.list[((port) / 32)] &= ~(1 << ((port) & 0x01f))
#define EB_PORT_ISSET(device,list,port)	((device->local.list[(port)/32] & (1 << (port & 0x01f))) != 0)

uint8_t	eb_port_allocate(struct __eb_device *, uint8_t, port_func, void*);
void eb_port_deallocate(struct __eb_device *, uint8_t);

/* __eb_imm_clear struct
 * 
 * Passed to a thread which waits for a period (defined as 1 second) to 
 * see if a priority packet has arrived on the device identified
 * in the struct. If it has, do nothing. If it hasn't, put the wire
 * back into read mode, otherwise it gets stuck waiting for an imm rep
 * to transmit which is never coming.
 * 
 */

struct __eb_imm_clear {
	struct __eb_device	*wire_device;
	pthread_t		me;
	uint8_t			p_net, p_stn;
	uint32_t		p_seq;
};

/* Note on bridge updates / operation.

   - WhatNet received on a device simply replies with __eb_device.net as being local. It will not reply if there is only
     one active network number, because it will not have a 'far side' network number to respond from. So the routine will
     first look to see if the current network is the only active on. It does that by searching networks[] for something
     non-NULL and advertisable on the device in question, but which is not a pointer to itself.

   - IsNet does likewise, but looks for a particular network in networks[] and doesn't bother responding if it's not
     known.

   - Reset just clears networks[] to NULL and rebuilds it from the device list.

   - Bridge advert then does this:
     - Looks at the networks being advertized. Translates the net numbers if on a trunk device.
     - For each, look at networks[] and see if we already know about the network. If we do, overwrite it. Successive overwrites likely to prevent loops.
     - If there is already a network[] entry for the network (as translated), and it's a locally defined network (i.e. the number matches __eb_device.net), then don't overwrite.
     - To point a newly learned network anywhere, the source must be a trunk type. Put its pointer in networks[].
     - Then for all devices apart from the source device, send a bridge advert containing everything advertisable on that kind of device, but excluding any network whose
       networks[] pointer is the device itself (avoid loops)

*/

/* Configuration information for the bridge
*/

struct __eb_config {
	uint8_t		debug_level; // 0 = off, 1 = Brief; 2 = Full
	FILE *		debug_output; // Where to send debug output
	pthread_mutex_t	debug_mutex; // Lock this before spitting out debug
	struct timeval	start; // Abs time the bridge started - for debug otuput
	uint16_t	aun_retx_interval; // Milliseconds
	uint16_t	aun_max_retries; // Maximum number of retries before we get ACK / IMMREP from distant station
	uint16_t	wire_retx_interval; // Milliseconds
	uint16_t	wire_max_retries; // Maximum number of times we'll try sending a packet on an Econet wire
	uint16_t	wire_max_notlistening; // Max number of 4-way not listenings to ignore (to cope with RISC OS not listening when it should be sometimes - e.g. during data bursts
	uint16_t	wire_interpacket_gap; // Minimum time between transmissions on the wire. Tries to avoid some not listening errors
	uint8_t		aun_nak_tolerance; // How many AUN NAKs we will tolerate from remote AUN before we dump the packet. Used to appease RiscOS, which sometimes isn't listening when it should be
	uint16_t	packet_timeout; // Milliseconds - max time a packet can sit on an out queue before we dump it and everything behind it for same destination - this will also be the maximum time a device scheduler waits on its condition
	uint16_t	max_pkt_dump_bytes; // Number of data bytes to dump on a packet dump
	uint8_t		pkt_dump_opts; // Bitmap for input/output pre/post nat
	uint8_t		local_only; // Open /dev/null instead of econet devices
	uint8_t		malloc_debug; // Whether we display malloc/free debug
	uint16_t	wire_imm_wait; // How long the system will wait for an immediate reply to arrive for transmission on an Econet wire before it resets the associated ADLC to read mode. (Otherwise it gets stuck in flag fill and the state machine goes a bit haywire.)
	uint32_t	dynamic_expiry; // Time in minutes to expire a dynamic AUN station
	uint16_t	stats_port; // TCP port number for stats connections
	uint16_t	fs_stats_port; // TCP port number for FS stats connections
	uint16_t	flashtime; // Time in ms that we turn an LED off when there's activity
	uint8_t		led_blink_on; // Set to 1 and the LEDs will blink ON for activity, not OFF
	uint8_t		leds_off; // Set to 1 and the userspace code will turn the LEDs off and leave them off
	uint8_t		trunk_keepalive_interval; // Seconds between trunk keepalive packets
	uint8_t		trunk_dead_interval; // Seconds after which trunk considered dead (bridge reset) if no traffic received
	uint8_t		trunk_keepalive_ctrl; // Ctrl byte used for trunk keepalive packets
	uint16_t	pool_dead_interval; // Seconds before a pool host will be treated as stale
	uint8_t		trunk_reset_qty; // Number of Bridge reset copies to send on UDP trunks
	uint8_t		trunk_update_qty; // Number of Bridge update copies to send on UDP trunks
	uint8_t		wire_reset_qty; // Number of bridge reset copies to send on Econet wires
	uint8_t		wire_update_qty; // Number of bridge update copies to send on Econet wires
	uint32_t		wire_bridge_query_interval; // Gap between successive IsNet or WhatNet responses to a given station on the wire (ms)
	uint8_t		wire_extralogs; // Turn extra kernel logging on to dmesg
	uint8_t		pool_reset_forward; // (Default is to) stop bridge forwarding bridge resets received from trunks & wires where all networks are pooled. (Reply updates still sent)
	uint8_t		bridge_loop_detect; // (Default is to) periodically send broadcast packets with port &9C port &CF with a random number in them to see if they come back. If they come back, we'll ignore traffic on that trunk except a reset, and after a reset we send another loop detect probe
	uint8_t		nokeepalivedebug; // Stops the bridge logging trunk keepalives (or at least anything on port &9C, ctrl &D0)
	uint8_t		nobridgeannouncedebug; // Stops bridge logging bridge reset/updates - anything withn port 9C including keepalives
};

/* Global debug vars */
#define EB_PKT_DUMP_PRE_I	0x01
#define EB_PKT_DUMP_POST_I	0x02
#define EB_PKT_DUMP_PRE_O	0x04
#define EB_PKT_DUMP_POST_O	0x08
#define EB_PKT_DUMP_INPUT_MASK	0x03
#define EB_PKT_DUMP_OUTPUT_MASK	0x0C
#define EB_PKT_DUMP_DUMPED	0x10

#define	EB_CONFIG_AUN_RETX	(config.aun_retx_interval)
#define EB_CONFIG_AUN_RETRIES	(config.aun_max_retries)
#define EB_CONFIG_WIRE_RETX	(config.wire_retx_interval)
#define EB_CONFIG_WIRE_RETRIES	(config.wire_max_retries)
#define EB_CONFIG_WIRE_MAX_NOTLISTENING (config.wire_max_notlistening)
#define EB_CONFIG_WIRE_INTERPACKETGAP	(config.wire_interpacket_gap)
#define EB_CONFIG_WIRE_IMM_WAIT	(config.wire_imm_wait)
#define EB_START_SEC		(config.start.tv_sec)
#define EB_START_USEC		(config.start.tv_usec)
#define EB_DEBUG_MUTEX		(config.debug_mutex)
#define EB_DEBUG_LEVEL		(config.debug_level)
#define EB_DEBUG_OUTPUT		(config.debug_output)
#define EB_DEBUG_MALLOC		(config.malloc_debug)
#define EB_CONFIG_PKT_EXPIRY	(config.packet_timeout)
#define EB_CONFIG_WIRE_RETIRES	(config.wire_max_retires)
#define EB_CONFIG_WIRE_RETX	(config.wire_retx_interval)
#define EB_CONFIG_AUN_RETRIES	(config.aun_max_retries)
#define EB_CONFIG_AUN_RETX	(config.aun_retx_interval)
#define EB_CONFIG_AUN_NAKTOLERANCE	(config.aun_nak_tolerance)
#define EB_CONFIG_PKT_DUMP_OPTS	(config.pkt_dump_opts)
#define EB_CONFIG_MAX_DUMP_BYTES	(config.max_pkt_dump_bytes)
#define EB_CONFIG_LOCAL		(config.local_only)
#define EB_CONFIG_DYNAMIC_EXPIRY	(config.dynamic_expiry)
#define EB_CONFIG_STATS_PORT	(config.stats_port)
#define EB_CONFIG_FS_STATS_PORT	(config.fs_stats_port)
#define EB_CONFIG_FLASHTIME	(config.flashtime)
#define EB_CONFIG_BLINK_ON	(config.led_blink_on)
#define EB_CONFIG_LEDS_OFF	(config.leds_off)
#define EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL	(config.trunk_keepalive_interval)
#define EB_CONFIG_TRUNK_DEAD_INTERVAL		(config.trunk_dead_interval)
#define EB_CONFIG_TRUNK_KEEPALIVE_CTRL		(config.trunk_keepalive_ctrl)
#define EB_CONFIG_POOL_DEAD_INTERVAL	(config.pool_dead_interval)
#define EB_CONFIG_TRUNK_RESET_QTY	(config.trunk_reset_qty)
#define EB_CONFIG_TRUNK_UPDATE_QTY	(config.trunk_update_qty)
#define EB_CONFIG_WIRE_RESET_QTY	(config.wire_reset_qty)
#define EB_CONFIG_WIRE_UPDATE_QTY	(config.wire_update_qty)
#define EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL	(config.wire_bridge_query_interval)
#define EB_CONFIG_EXTRALOGS	(config.wire_extralogs)
#define EB_CONFIG_NOKEEPALIVEDEBUG	(config.nokeepalivedebug)
#define EB_CONFIG_POOL_RESET_FWD	(config.pool_reset_forward)
#define EB_CONFIG_BRIDGE_LOOP_DETECT	(config.bridge_loop_detect)
#define EB_CONFIG_NOBRIDGEANNOUNCEDEBUG	(config.nobridgeannouncedebug)

// Printer status

// Input status
#define PRN_IN_READY    0x00
#define PRN_IN_BUSY     0x01
#define PRN_IN_JAMMED_SOFTWARE  0x02
#define PRN_IN_JAMMED_OFFLINE   0x03
#define PRN_IN_JAMMED_DISCFULL  0x04
#define PRN_IN_UNAUTHORISED     0x05
#define PRN_IN_GOINGOFFLINE     0x06
#define PRN_IN_RESERVED         0x07

// Output status (from server to printer)
#define PRN_OUT_READY   0x00
#define PRN_OUT_OFFLINE 0x08
#define PRN_OUT_JAMMED  0x10

#define PRN_STATUS_DEFAULT (PRN_IN_READY | PRN_OUT_READY)

// Printer control
#define PRNCTRL_SPOOL 0x08 // Spool to disc or direct to printer (we always spool)
#define PRNCTRL_ACCOUNT 0x04 // Account ownership required
#define PRNCTRL_ANON 0x02 // Anonymouse use allowed. We set this by default
#define PRNCTRL_ENABLE 0x01 // Printing enabled or not. We default to yes.

#define PRNCTRL_DEFAULT (PRNCTRL_SPOOL | PRNCTRL_ANON | PRNCTRL_ENABLE)

// Client to Printer server port &9f Query codes

#define PRN_QUERY_NAME  	6
#define PRN_QUERY_STATUS        1

// Printer spool file template

#define PRN_SPOOL_TEMPLATE	"/tmp/econet.printjob.XXXXXX"
#define PRN_DEFAULT_HANDLER	"/etc/econet-gpio/pserv.sh"
// Config file regexps

#define EB_CFG_COMMENT "^\\s*#.*$"
#define EB_CFG_EMPTY "^\\s*$"
#define EB_CFG_WIRE "^\\s*WIRE\\s+NET\\s+([[:digit:]]{1,3})\\s+ON\\s+DEVICE\\s+(/.+)\\s*$"
#define EB_CFG_TRUNK "^\\s*TRUNK\\s+ON\\s+PORT\\s+([[:digit:]]{1,5})\\s+TO\\s+([a-z0-9\\-\\.]{4,128}\\:[[:digit:]]{2,5}|DYNAMIC)\\s+KEY\\s+([0-9a-z]{16,32})\\s*$"
#define EB_CFG_TRUNK_PLAINTEXT "^\\s*TRUNK\\s+ON\\s+PORT\\s+([[:digit:]]{1,5})\\s+TO\\s+([a-z0-9\\-\\.]{4,128}\\:[[:digit:]]{2,5})\\s*$"
#define EB_CFG_DYNAMIC "^\\s*DYNAMIC\\s+([[:digit:]]{1,3})\\s+(AUTOACK|NONE)\\s*$"
#define EB_CFG_FILESERVER "^\\s*FILESERVER\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+PATH\\s+(/.+)\\s*$"
#define EB_CFG_PRINTSERVER "^\\s*PRINTSERVER\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+([a-z0-9]{1,6})\\s+USING\\s+([a-z0-9@_\\-\\.]{1,128})\\s*$"
#define EB_CFG_PRINTSERVER_WITHUSER "^\\s*PRINTSERVER\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+([a-z0-9]{1,6})\\s+USING\\s+([a-z0-9@_\\-\\.]{1,128})\\s+ONLY\\s+FOR\\s+([a-z0-9]{1,6})\\s*$"
#define EB_CFG_PRINTHANDLER "^\\s*PRINTHANDLER\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+([0-9a-z]{1,6})\\s+IS\\s+(/.+)\\s*$"
#define EB_CFG_IPSERVER "^\\s*IPSERVER\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+DEVICE\\s+(.+)\\s+USING\\s+IP\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\/[[:digit:]]{1,2})\\s*$"
#define EB_CFG_PIPESERVER "^\\s*PIPESERVER\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+PATH\\s+(/.+)\\s+(PASSTHRU|NONE)\\s*$"
#define EB_CFG_AUNMAP "^\\s*AUN\\s+MAP\\s+NET\\s+([[:digit:]]{1,3})\\s+ON\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+PORT\\s+(FIXED|SEQ)\\s+([[:digit:]]{2,5}|AUTO)\\s+(AUTOACK|NONE)\\s*$"
#define EB_CFG_AUNHOST "^\\s*AUN\\s+MAP\\s+HOST\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+ON\\s+([a-z0-9\\-\\.]+)\\s+PORT\\s+([[:digit:]]{2,5}|AUTO)\\s+(AUTOACK|NONE)\\s*$"
#define EB_CFG_EXPOSE_NET "^\\s*EXPOSE\\s+NET\\s+([[:digit:]]{1,3})\\s+ON\\s+(\\*|[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+PORT\\s+(FIXED|SEQ)\\s+([[:digit:]]{2,5}|AUTO)\\s*$"
#define EB_CFG_EXPOSE_HOST "^\\s*EXPOSE\\s+HOST\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+ON\\s+PORT\\s+(.+\\:[[:digit:]]{2,5}|AUTO)\\s*$"
#define EB_CFG_TRUNK_NAT "^\\s*TRUNK\\s+PORT\\s+([[:digit:]]{2,5})\\s+XLATE\\s+DISTANT\\s+NET\\s+([[:digit:]]{1,3})\\s+TO\\s+LOCAL\\s+NET\\s+([[:digit:]]{1,3})\\s*$"
#define EB_CFG_BRIDGE_NET_FILTER "^\\s*BRIDGE\\s+(DROP|ALLOW)\\s+NET\\s+(\\*|[[:digit:]]{1,3})\\s+(INBOUND|OUTBOUND)\\s+ON\\s+(WIRE\\s+NET\\s+[[:digit:]]{1,3}|TRUNK\\s+PORT\\s+[[:digit:]]{2,5})\\s*$"
#define EB_CFG_BRIDGE_TRAFFIC_FILTER "^\\s*BRIDGE\\s+(DROP|ALLOW)\\s+TRAFFIC\\s+BETWEEN\\s+(\\*|[[:digit:]]{1,3})\\.(\\*|[[:digit:]]{1,3})\\s+AND\\s+(\\*|[[:digit:]]{1,3})\\.(\\*|[[:digit:]]{1,3})\\s*$"
#define EB_CFG_CLOCK "^\\s*SET\\s+NETWORK\\s+CLOCK\\s+ON\\s+NET\\s+([[:digit:]]{1,3})\\s+PERIOD\\s+(([3-9]|1[0-5])(\\.(25|50?|75))?)\\s+MARK\\s+([123](\\.(25|50?|75))?)\\s*$"
#define EB_CFG_BINDTO "^\\s*TRUNK\\s+BIND\\s+TO\\s+(.+)\\s*$"
// Pool system
#define EB_CFG_NEW_POOL "^\\s*POOL\\s+([A-Z0-9]{1,10})\\s+NETS\\s+([0-9\\,]+)\\s*$"
#define EB_CFG_STATIC_POOL_TRUNK "^\\s*POOL\\s+STATIC\\s+([A-Z0-9]{1,10})\\s+FROM\\s+(TRUNK)\\s+PORT\\s+([[:digit:]]{2,5})\\s+STATION\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+TO\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s*$"
#define EB_CFG_STATIC_POOL_WIRE "^\\s*POOL\\s+STATIC\\s+([A-Z0-9]{1,10})\\s+FROM\\s+(WIRE)\\s+NET\\s+([[:digit:]]{1,3})\\s+STATION\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s+TO\\s+([[:digit:]]{1,3}\\.[[:digit:]]{1,3})\\s*$"
#define EB_CFG_NET_POOL_TRUNK "^\\s*(TRUNK)\\s+PORT\\s+([[:digit:]]{2,5})\\s+USE\\s+POOL\\s+([A-Z0-9]{1,10})\\s+FOR\\s+NETS\\s+([0-9\\,]+|\\*)\\s*$"
#define EB_CFG_NET_POOL_WIRE "^\\s*(WIRE)\\s+NET\\s+([[:digit:]]{1,3})\\s+USE\\s+POOL\\s+([A-Z0-9]{1,10})\\s+FOR\\s+NETS\\s+([0-9\\,]+|\\*)\\s*$"

// IP/Econet structs

// ARP response timeout in ms
#define ARP_WAIT 2500
// ARP timeout in seconds (5 mins)
#define ARP_TIMEOUT 600

struct __eip_arp {
	uint32_t ip; // Network order
	uint16_t econet; // net is MSB
	struct timeval expiry; // Expiry time
	struct __eip_arp *next;
};

struct __eip_ip_queue { // Packets waiting for ARP entries
	struct __econet_packet_aun 	*p; // IP Packet received from Ethernet
	uint16_t			length; // Of IP packet
	uint32_t			destination;
	struct timeval			expiry;
	struct __eip_ip_queue		*next;
};

struct __eip_addr { // Local addresses
	uint32_t ip; // Host order
	uint32_t mask; // Host order
	struct __eip_arp *arp;
	struct __eip_ip_queue *ipq;
	struct __eip_addr *next;
};

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

#endif


/* Externs for the FS */
extern struct __eb_device * eb_find_station (uint8_t, struct __econet_packet_aun *);
extern uint8_t eb_aunpacket_to_aun_queue(struct __eb_device *, struct __eb_device *, struct __econet_packet_aun *, uint16_t);
extern uint8_t eb_enqueue_input (struct __eb_device *, struct __econet_packet_aun *, uint16_t);

/* Debug externs */
extern void eb_debug_fmt (uint8_t, uint8_t, char *, char *);
void eb_debug (uint8_t, uint8_t, char *, char *, ...);

/* externs within econet-hpbridge.c used by ...devinit.c */

extern struct __eb_device * eb_device_init (uint8_t, uint16_t, uint8_t);
extern struct __eb_device * eb_new_local (uint8_t, uint8_t, uint16_t);
extern void eb_set_whole_wire_net (uint8_t, struct __eb_device *);
extern void eb_set_single_wire_host (uint8_t, uint8_t);
extern void * eb_malloc (char *, int line, char *, char *, size_t);
extern struct __eb_device * eb_get_network(uint8_t);
extern char * eb_type_str (uint16_t);
extern struct __eb_aun_exposure * eb_is_exposed (uint8_t, uint8_t, uint8_t);
extern void eb_set_network (uint8_t, struct __eb_device *);
extern struct __eb_pool_host *eb_pool_find_addr_lock (struct __eb_pool *, uint8_t, uint8_t, struct __eb_device *);
extern struct __eb_pool_host *eb_find_make_pool_host (struct __eb_device *, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t *);
extern char * eb_pool_err(uint8_t);

/* Globals in econet-hpbridge.c used by ...devinit.c */

extern struct __eb_device 	* trunks;
extern struct __eb_device	* multitrunks;
extern struct __eb_device	* networks[];
extern struct __eb_aun_remote	* aun_remotes;
extern struct __eb_aun_exposure	* exposures;
extern in_addr_t		bindhost;
extern struct __eb_pool		* pools;
extern struct __eb_fw_chain	* fw_chains;

extern uint8_t	dumpconfig;

/* externs within econet-hpbridge-devinit.c */

extern uint8_t	eb_device_init_wire (uint8_t, char *, struct __eb_fw_chain *, struct __eb_fw_chain *);
extern uint8_t	eb_device_init_virtual (uint8_t);
extern uint8_t	eb_device_init_singletrunk (char *, uint16_t, uint16_t, char *, struct __eb_fw_chain *, struct __eb_fw_chain *);
extern uint8_t	eb_device_init_multitrunk (char *, char *, uint16_t, int, uint8_t);
extern uint8_t 	eb_device_init_dynamic (uint8_t, uint8_t, struct __eb_fw_chain *, struct __eb_fw_chain *);
extern uint8_t	eb_device_init_fs (uint8_t, uint8_t, char *);
extern uint8_t	eb_device_init_ps (uint8_t, uint8_t, char *, char *, char *, uint8_t, uint8_t);
extern uint8_t 	eb_device_init_ps_handler (uint8_t, uint8_t, char *, char *);
extern uint8_t	eb_device_init_ip (uint8_t, uint8_t, char *, uint32_t, uint32_t);
extern uint8_t	eb_device_init_pipe (uint8_t, uint8_t, char *, uint8_t);
extern uint8_t	eb_device_init_aun_host (uint8_t, uint8_t, in_addr_t, uint16_t, uint8_t, uint8_t, struct __eb_fw_chain *, struct __eb_fw_chain *);
extern uint8_t	eb_device_init_aun_net (uint8_t, in_addr_t, uint8_t, uint16_t, uint8_t, struct __eb_fw_chain *, struct __eb_fw_chain *);
extern uint8_t	eb_device_init_expose_host (uint8_t, uint8_t, in_addr_t, uint16_t, uint8_t);
extern uint8_t	eb_device_init_trunk_nat (struct __eb_device *, uint8_t, uint8_t);
extern uint8_t	eb_device_init_set_bridge_filter (struct __eb_device *, uint8_t, uint8_t, uint8_t);
extern uint8_t	eb_device_init_add_fw_to_chain (struct __eb_fw_chain **, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);
extern uint8_t	eb_device_init_set_net_clock (struct __eb_device *, double, double);
extern uint8_t	eb_device_init_set_trunk_bind_address (struct __eb_device *, in_addr_t);
extern uint8_t	eb_device_init_create_pool (char *, uint8_t, uint8_t *);
extern uint8_t	eb_device_init_set_pool_static (struct __eb_pool *, struct __eb_device *, uint8_t, uint8_t, uint8_t, uint8_t);
extern uint8_t	eb_device_init_set_pooled_nets (struct __eb_pool *, struct __eb_device *, uint8_t, uint8_t *);

/* Multitrunk */

extern void * eb_multitrunk_server_device (void *);
extern void * eb_multitrunk_client_device (void *);

/* JSON */

uint8_t eb_readconfig_json(char *);

/* Thread management */

extern uint16_t		threads_started, threads_ready;

extern pthread_mutex_t		threadcount_mutex; // Locks the thread counter

#define eb_thread_started() { pthread_mutex_lock(&threadcount_mutex); threads_started++; pthread_mutex_unlock(&threadcount_mutex); }
#define eb_thread_ready() { pthread_mutex_lock(&threadcount_mutex); threads_ready++; pthread_mutex_unlock(&threadcount_mutex); }
