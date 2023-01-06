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

#define _GNU_SOURCE

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
#include "../include/econet-gpio-consumer.h"
#include "../include/econet-pserv.h"
#include "../include/econet-hpbridge.h"


extern int h_errno;

extern int fs_initialize(struct __eb_device *, unsigned char, unsigned char, char *);
extern int fs_stn_logged_in(int, uint8_t, uint8_t);
extern int fs_get_username(int, int, char *username);
extern int fs_get_user_printer(int, uint8_t, uint8_t);
extern int fs_load_dequeue(int, uint8_t, uint8_t);
extern void eb_handle_fs_traffic(uint16_t, struct __econet_packet_aun *, uint16_t);
extern void eb_handle_ps_traffic(struct __eb_device *, struct __econet_packet_aun *, uint16_t);
extern void eb_handle_ip_traffic(struct __eb_device *, struct __econet_packet_aun *, uint16_t);
extern void fs_eject_station(unsigned char, unsigned char); // Used to get rid of an old dynamic station
extern short fs_dequeuable(int);
extern void fs_dequeue(int);
extern void fs_garbage_collect(int);

extern short fs_sevenbitbodge;
extern short normalize_debug;

// Some globals

in_addr_t 	bindhost = 0; // IP to bind to if specified. Only used for trunks at the moment.

struct __eb_fw *bridge_fw; // Bridge-wide firewall policy

struct __eb_fs_list { // List of known fileservers, to whom we spoof a *BYE when a dynamic station logs in
        uint8_t net, stn;
        struct __eb_fs_list *next;
};

struct __eb_fs_list	*port99_list;
pthread_mutex_t		port99_mutex;

struct __eb_aun_remote 	*aun_remotes; // List of remote AUN stations
struct __eb_aun_exposure	*exposures; // List of exposures. Was originally in net (but not net,stn) order

struct __eb_device      *networks[255]; // One entry per network, contains pointer to network driver in question. Basically these are the only places we can reach.
struct __eb_device      *networks_initial[255]; // Used to rebuild networks[] on a bridge reset
struct __eb_device      *devices; // All devices. Used to rebuild networks[] on a bridge re-set
struct __eb_device      *trunks; // List of trunks.
uint16_t		threads_started, threads_ready;

pthread_mutex_t		threadcount_mutex; // Locks the thread counter

#define eb_thread_started() { pthread_mutex_lock(&threadcount_mutex); threads_started++; pthread_mutex_unlock(&threadcount_mutex); }
#define eb_thread_ready() { pthread_mutex_lock(&threadcount_mutex); threads_ready++; pthread_mutex_unlock(&threadcount_mutex); }
	
pthread_mutex_t         networks_update; // Must acquire before changing/reading networks[] array

pthread_mutex_t		fs_mutex, ps_mutex, ip_mutex; // Mutexes (mutices?) for ensuring only one thread talks to a FS, PS, or IPS at the same time

uint8_t eb_assume_true_aun = 0;         // If 1, will assume that if we don't have a route to network numbers 128+, then we should try addressing the AUN packet to... where? (Not implemented yet.)

struct __eb_config	config; // Holds bridge-wide config information

char	debug_path[1024]; 	// Filename to dump debug to

/* Bridge internal sequence number */

uint32_t	bridgewide_seq = 0x4000;

/* Some function defines - but not all of them because I couldn't be bothered */

uint8_t eb_enqueue_input (struct __eb_device *, struct __econet_packet_aun *, uint16_t);
void eb_set_whole_wire_net (uint8_t, struct __eb_device *);
uint8_t eb_firewall (struct __econet_packet_aun *);
void eb_reset_tables(void);
void eb_debug (uint8_t, uint8_t, char *, char *, ...);
uint32_t get_local_seq (unsigned char, unsigned char);
static void * eb_statistics (void *);

void eb_exit_cleanup(void)
{

	// Remove any IP addresses / tunnel interfaces we may have created

}

void eb_signal_handler (int signal)
{

	switch (signal)
	{

		case SIGINT:
			eb_debug (0, 0, "SIGNAL", "                 Cleaning up IP interfaces before exit...");
			eb_exit_cleanup();
			exit (EXIT_SUCCESS);
			break;
		default: // Do nothing
			break;

	}


}

/* Config file path */

char	config_path[1024];

char * econet_strstate(int s) // Convert AUN state to string
{
	switch (s)
	{
		case EA_IDLE: return (char *)"Idle";
		case EA_W_WRITESCOUT: return (char *)"Writing - sending scout";
		case EA_W_READFIRSTACK: return (char *)"Writing - reading first ack";
		case EA_W_WRITEDATA: return (char *)"Writing - sending data";
		case EA_W_READFINALACK: return (char *)"Writing - reading final ack";
		case EA_R_WRITEFIRSTACK: return (char *)"Reading - sending first ack";
		case EA_R_READDATA: return (char *)"Reading - reading data";
		case EA_R_WRITEFINALACK: return (char *)"Reading - sending final ack";
		case EA_I_WRITEREPLY: return (char *)"Immediate - writing reply";
		case EA_I_WRITEIMM: return (char *)"Immediate - sending query";
		case EA_I_READREPLY: return (char *)"Immediate - reading reply";
		case EA_I_IMMSENTTOAUN: return (char *)"Immediate - wire query sent to AUN and reply awaited";
		case EA_W_WRITEBCAST: return (char *)"Broadcast - writing packet";
		default: return (char *)"Unknown state";
	}

}

char * econet_strtxerr(int e)
{
	switch (((e < 0) ? -1 : 1)* e)
	{
		case ECONET_TX_SUCCESS: return (char *)"No error"; 
		case ECONET_TX_BUSY: return (char *)"Module busy";
		case ECONET_TX_JAMMED: return (char *)"Line jammed";
		case ECONET_TX_HANDSHAKEFAIL: return (char *)"Handshake failure";
		case ECONET_TX_NECOUTEZPAS: return (char *)"Not listening";
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

/* Stats updater
 */

void eb_add_stats(pthread_mutex_t *mutex, uint64_t *counter, uint16_t value)
{

	pthread_mutex_lock(mutex);
	*counter += value;
	pthread_mutex_unlock(mutex);

}

/* Calculate ms difference between two times 
*/

unsigned long timediffmsec(struct timeval *s, struct timeval *d)
{
	return (((d->tv_sec - s->tv_sec) * 1000) + ((d->tv_usec - s->tv_usec) / 1000));
}

/* Return a float for seconds since bridge start time
*/

float timediffstart()
{

	struct timeval 	now;

	gettimeofday (&now, 0);

	return (float) timediffmsec(&(config.start), &now) / 1000;

}

/* Return human readable device type from device type code
*/

char * eb_type_str (uint16_t type)
{

	switch ((type & 0xff00) >> 8)
	{
		case EB_WIRE: return (char *)"Wire"; break;
		case EB_TRUNK: return (char *)"Trunk"; break;
		case EB_PIPE: return (char *)"Pipe"; break;
		case EB_LOCAL: return (char *)"Local"; break;
		case EB_AUN: return (char *)"AUN"; break;
		case EB_NULL: return (char *)"Virtual"; break;
		default: return (char *)"UNKNOWN"; break;
	}

}

/* Put out a debug string to debug output, string already formatted
*/

void eb_debug_fmt (uint8_t quit, uint8_t level, char *module, char *formatted)
{

	/* If log entry is at a level we aren't displaying, quit
	*/
	if (level > EB_DEBUG_LEVEL)
		return;

	//pthread_mutex_lock(&EB_DEBUG_MUTEX);

	fprintf (EB_DEBUG_OUTPUT, "[+%15.6f] tid %7ld %-8s: %s\n", timediffstart(), syscall(SYS_gettid), module, formatted);
	//fprintf (EB_DEBUG_OUTPUT, formatted);
	//fprintf (EB_DEBUG_OUTPUT, "\n");

	//pthread_mutex_unlock(&EB_DEBUG_MUTEX);

	if (quit)
		exit (EXIT_FAILURE);
}

/* Format a varargs debug string and send it off to the debug output
*/

void eb_debug (uint8_t quit, uint8_t level, char *module, char *fmt, ...)
{

	va_list ap;
	char str[16384];

	va_start(ap, fmt);

	vsnprintf (str, 16382, fmt, ap);

	va_end(ap);

	eb_debug_fmt (quit, level, module, str);

}

/* Memory management debug
*/

static inline void eb_free (char *file, int line, char *module, char *purpose, void *ptr)
{

	if (EB_DEBUG_MALLOC)
		eb_debug (0, 2, "MEM MGT", "%-8s         %s:%d freeing %p for purpose %s", module, file, line, ptr, purpose);

	free (ptr);

}

static inline void * eb_malloc (char *file, int line, char *module, char *purpose, size_t size)
{

	void *r;

	r = malloc(size);

	if (EB_DEBUG_MALLOC)
		eb_debug (0, 2, "MEM MGT", "%-8s         %s:%d seeking malloc(%d) for purpose %s (r = %p)", module, file, line, size, purpose, r);

	return r;

}
/* gets the pointer pointed to by a network[] item. These never get free'd so they
 * will always be valid - they just might not be the entry in network[] that they
 * were when you found them
 */

struct __eb_device * eb_get_network (uint8_t net)
{

	struct __eb_device *result;

	pthread_mutex_lock (&networks_update);

	result = networks[net];

	pthread_mutex_unlock (&networks_update);

	return result;	

}


/* Updates the networks[] structure
 */

void eb_set_network (uint8_t net, struct __eb_device *dev)
{

	pthread_mutex_lock (&networks_update);

	networks[net] = dev;

	pthread_mutex_unlock (&networks_update);

}

/* Mark a station as a fileserver (wherever it may be)
 * Used for sending BYEs when we get a new dynamic station
 */

void eb_mark_fileserver (uint8_t net, uint8_t stn)
{

	struct __eb_fs_list	*f, *n;
	uint8_t			found = 0;

	pthread_mutex_lock (&port99_mutex);

	f = port99_list;

	n = eb_malloc(__FILE__, __LINE__, "FSLIST", "Create new FS list entry", sizeof(struct __eb_fs_list));

	if (!n)
		eb_debug (1, 0, "FSLIST", "Unable to malloc() new FS list entry");

	n->net = net;
	n->stn = stn;
	n->next = port99_list;

	while (!found && f)
	{
		if (f->net == net && f->stn == stn)
			found = 1;
		else	f = f->next;
	}

	if (!found)
	{
		port99_list = n;
		eb_debug (0, 2, "FSLIST", "         %3d.%3d Marked as fileserver", net, stn);
	}
	else
		eb_free(__FILE__, __LINE__, "FSLIST", "Freeing __eb_fs_list struct which wasn't ultimately used", n);

	pthread_mutex_unlock (&port99_mutex);

}

/* Dump a packet
 */

void eb_dump_packet (struct __eb_device *source, char dir, struct __econet_packet_aun *p, uint16_t datalength)
{

	char 		dumpstring[8192];

	if (!(EB_CONFIG_PKT_DUMP_OPTS & dir))
		return;

	sprintf (dumpstring, "%-8s %3d.%3d from %3d.%3d P:&%02X C:&%02X (%c) Type %3s Seq 0x%08X Length 0x%04X addr %p",
		eb_type_str(source->type),
		p->p.dstnet,
		p->p.dststn,
		p->p.srcnet,
		p->p.srcstn,
		p->p.port,
		p->p.ctrl,
		(dir == EB_PKT_DUMP_PRE_I ? 'i' :
		(dir == EB_PKT_DUMP_POST_I ? 'I' :
		(dir == EB_PKT_DUMP_PRE_O ? 'o' :
		(dir == EB_PKT_DUMP_POST_O ? 'O' : 
		(dir == EB_PKT_DUMP_DUMPED ? 'D' : 'X'))))),
		(p->p.aun_ttype == ECONET_AUN_BCAST ? "BRD" : 
			(p->p.aun_ttype == ECONET_AUN_DATA ? "DAT" :
			(p->p.aun_ttype == ECONET_AUN_IMMREP ? "IRP" :
			(p->p.aun_ttype == ECONET_AUN_IMM ? "IQU" :
			(p->p.aun_ttype == ECONET_AUN_ACK ? "ACK" :
			(p->p.aun_ttype == ECONET_AUN_NAK ? "NAK" : "UNK")
		))))),
		p->p.seq,
		datalength,
		p);

	if (EB_CONFIG_MAX_DUMP_BYTES > 0)
	{

#define PKTDUMP_BREAKS	16

		uint16_t 	count = 0;
		char		visible[PKTDUMP_BREAKS+1];

		while (count < datalength && count < EB_CONFIG_MAX_DUMP_BYTES)
		{
			char 		output[6];

			if ((count % PKTDUMP_BREAKS) == 0)
			{
				char addition[48];

				if (count != 0) strcat(dumpstring, visible);
				
				memset(&visible, 0, sizeof(visible));

				sprintf(addition, "\n%19s%08X: ", "", count);
				strcat(dumpstring, addition);
			}

			sprintf (output, "%02X ", p->p.data[count]);

			visible[count % PKTDUMP_BREAKS] = (p->p.data[count] > 32 && p->p.data[count] < 127) ? p->p.data[count] : '.';

			if (strlen(dumpstring) > 8000) 
			{
				strcat (dumpstring, "...");
				break;
			}
			else	strcat (dumpstring, output);
			
			count++;

		}

		/* Print final set of characters */

		if ((count % PKTDUMP_BREAKS) != 0)
		{
			uint8_t		diff, count2;

			diff = (PKTDUMP_BREAKS - (count % PKTDUMP_BREAKS));

			for (count2 = 0; count2 < diff; count2++)
				strcat (dumpstring, "   ");	
		}

		if (count > 0) strcat(dumpstring, visible);
		
	}

	eb_debug_fmt (0, 1, "PACKET", dumpstring);

}

struct __eb_led {
	uint8_t			led; // Use the #defines in the consumer.h - ECONETGPIO_{READ,WRITE}LED; ECONETGPIO_LED{ON,OFF}
	uint16_t		flashtime; // Flash (off) time in ms
	struct __eb_device	*device; // So we pick up the right device socket
};

/* Thread to flash an LED - takes pointer to struct eb_led as its parameter */

void * eb_flash_led (void * instructions)
{

	struct __eb_led 	*i;
	uint8_t			param;

	i = (struct __eb_led *) instructions;

	if (i->device->type != EB_DEF_WIRE) // Barf - we only do this for wire devices
		return NULL;

	param = i->led | (EB_CONFIG_BLINK_ON ? ECONETGPIO_LEDON : ECONETGPIO_LEDOFF);

	ioctl (i->device->wire.socket, ECONETGPIO_IOC_LED, param);
	
	usleep (EB_CONFIG_FLASHTIME * 1000);

	param = i->led | (EB_CONFIG_BLINK_ON ? ECONETGPIO_LEDOFF : ECONETGPIO_LEDON);

	ioctl (i->device->wire.socket, ECONETGPIO_IOC_LED, param);

	return NULL;
}

/* Initialize a new network device
*/

struct __eb_device * eb_device_init (uint8_t net, uint16_t type, uint8_t config)
{

	struct __eb_device 	*p;

	if (net && eb_get_network(net)) // Already defined
		eb_debug (1, 0, "CONFIG", "Cannot configure net %d - network already exists", net);

	// Create a new device struct for it

	if ((p = eb_malloc(__FILE__, __LINE__, "DEVINIT", "Creating __eb_device", sizeof(struct __eb_device))))
	{
		if (net) p->net = net;
		p->type = type;

		if (pthread_mutex_init(&(p->qmutex_in), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize queue mutex inbound for net %d", net);

		if (pthread_mutex_init(&(p->qmutex_out), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize queue mutex outbound for net %d", net);

		if (pthread_cond_init(&(p->qwake), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize queue wake condition for net %d", net);

		if (pthread_mutex_init(&(p->priority_mutex), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize priority mutex for net %d", net);

		p->out = NULL; // Init queues
		p->in = NULL;

		// Clear priority

		p->p_seq = p->p_net = p->p_stn = 0;

		// Clear all exposures

		p->exposures = NULL;

		p->b_in = p->b_out = 0; // Traffic stats

		if (pthread_mutex_init(&(p->statsmutex), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for net %d", net);

		p->self = p;
	
		p->next = NULL;
	}
	else	eb_debug (1, 0, "CONFIG", "Unable to malloc() device struct for network %d", net);

	if (net) // We don't do this unless we're creating a new network
	{
		if (devices)
			p->next = devices;

		devices = p;

		eb_set_network (net, p);
	}

	return p;

}

/* Create a new local server, if possible
*/

struct __eb_device * eb_new_local(uint8_t net, uint8_t stn, uint16_t newtype)
{
	struct __eb_device	*n, *existing;
	uint8_t			type;
	
	if (!(n = eb_get_network(net))) // Create a null device for this server
	{
		n = eb_device_init (net, EB_DEF_NULL, 0);
		eb_set_network(net, n);
		n->net = net;
	}				
	//else	n = eb_get_network(net);

	type = (n->type & 0xff00) >> 8;

	if (type != EB_WIRE && type != EB_NULL) /* Can't put a fileserver divert on anything but wire or null */
		eb_debug (1, 0, "CONFIG", "Cannot create %d.%d - network %d is neither wire nor null!",  net, stn, stn);

	existing = (type == EB_WIRE ? n->wire.divert[stn] : n->null.divert[stn]);

	if (newtype == EB_DEF_PIPE && existing)
		eb_debug (1, 0, "CONFIG", "Cannot create %d.%d - station exists", net, stn);

	if (existing && (existing->type != newtype))
		eb_debug (1, 0, "CONFIG", "Cannot create %d.%d - station exists and is not of the correct type", net, stn);

	if (!existing) /* Need a new device */
	{
		existing = eb_device_init (0, newtype, 0);
		if (type == EB_WIRE)
			n->wire.divert[stn] = existing;
		else	n->null.divert[stn] = existing;

		existing->net = net;

		if (newtype == EB_DEF_LOCAL)
		{
			existing->local.stn = stn;
			existing->local.printers = NULL;
			existing->local.print_handler = NULL;
			existing->local.seq = 0x4000;
			strcpy (existing->local.ip.tunif, ""); // Rogue for uninitialized
			existing->local.fs.index = -1; // Flag as unset
			strcpy(existing->local.ip.tunif, ""); // Flag as no IP gateway
		}
		else if (newtype == EB_DEF_PIPE)
		{
			existing->pipe.base = NULL;
			pthread_mutex_init(&existing->pipe.code_mutex, NULL);	
			existing->pipe.stn = stn;
			existing->pipe.skt_read = existing->pipe.skt_write = -1;
			existing->pipe.seq = 0x4000;
		}
	}

	return existing;

}

/* Find the device object for a remote AUN station.
   This is inefficient and wants fixing.

   Provide a host-ordered four byte address and port,
   and this will return a pointer to the device object if found,
   or NULL if not.
*/

struct __eb_device * eb_find_aun_remote (in_addr_t address, uint16_t port)
{
	struct __eb_device	*result = NULL;
	struct __eb_aun_remote	*search;

	search = aun_remotes;
	
	while (!result && search)
	{
		struct __eb_aun_remote	*n;

		pthread_mutex_lock (&(search->updatemutex));

		n = search->next;
			
		if (search->addr == address && search->port == port) // If dynamic & unused, then port == -1 so we'll miss it. (Though that'll probably be enumerated as 0xffff, which is good enough.)
			result = search->eb_device;

		pthread_mutex_unlock (&(search->updatemutex));

		if (!result)
			search = n;
	}

	return result;

}

/* Return the existing 'active' flag on an exposure, during mutex lock */

uint8_t eb_is_exposure_active(struct __eb_aun_exposure *e)
{

	uint8_t		result;

	pthread_mutex_lock (&(e->exposure_mutex));

	result = e->active;

	pthread_mutex_unlock (&(e->exposure_mutex));

	return result;

}

/* Set the 'active' flag on exposure under mutex lock for a whole net (this
   process only happens when there's a trunk advert, so whole net is
   convenient).
*/

void eb_set_exposures_active(uint8_t net, struct __eb_device *parent)
{
	
	struct __eb_aun_exposure 	*e;
	uint8_t				count;

	if (!parent) // Barf - should be set
	{
		eb_debug (0, 2, "EXPOSURE", "        %3d    Cannot activate exposure - net does not appear to be active", net);
		return;
	}

	count = 0;

	e = exposures;

	while (e)
	{

		pthread_mutex_lock (&(e->exposure_mutex));

		if (e->net == net && e->active == 0)
		{
			e->parent = parent;
			e->active = 2; // Temporarily active
			count++;
		}

		pthread_mutex_unlock (&(e->exposure_mutex));

		e = e->next;
	}

	if (count) eb_debug (0, 2, "EXPOSURE", "         %3d     Activated %d exposures", net, count);

}
	
/* Turn off temporary exposures on a given network
 */

void eb_set_exposures_inactive(uint8_t net)
{
	
	struct __eb_aun_exposure *e;
	uint8_t			 count;

	count = 0;

	e = exposures;

	while (e)
	{

		pthread_mutex_lock (&(e->exposure_mutex));

		if (e->net == net && e->active == 2)
		{
			e->active = 0; // Temporarily INactive
			e->parent = NULL; // Disable parent
			count++;
		}

		pthread_mutex_unlock (&(e->exposure_mutex));

		e = e->next;
	}

	if (count) eb_debug (0, 2, "EXPOSURE", "         %3d     De-activated %d exposures", net, count);
}

/* Determine whether a given econet address has an
   exposure to AUN, and (if it does) return a pointer to its
   exposure device

   If not, then returns NULL

   is_active = 1 means the exposure must be active, otherwise it can be inactive
   (This is used during configuration to check for double exposures.)
*/

struct __eb_aun_exposure * eb_is_exposed (uint8_t net, uint8_t stn, uint8_t is_active)
{

	struct __eb_device 	*master; // Master device for this net
	struct __eb_aun_exposure	*exposure; // Tracks through the exposure list on this device
	struct __eb_aun_exposure	*result;

	result = NULL;

	// Note, because the networks[] array is just pointers, it is perfectly possible (and indeed intended) 
	// that there will be multiple entries in it for a given driver. E.g. the wire driver will feature once
	// for each network that is reachable by a given wire (e.g. by way of bridging)

	// eb_debug (0, 4, "EXPOSE", "%-8s %3d.%3d Checking for AUN exposure", "", net, stn);

	master = eb_get_network(net);

	if (!master && is_active)
		eb_debug (0, 4, "EXPOSE", "%-8s %3d     Net not active - returning NULL for exposure search for station %d.%d", "", net, net, stn);
	else
	{
		exposure = exposures; // The per net device thing doesn't work when there are multiple nets on a trunk, for example.

		if (!exposure)	eb_debug (0, 4, "EXPOSE", "No exposures - returning NULL for search for %d.%d", net, stn);
		else
		{
			while (!result && exposure) // && exposure->net == net)
			{
				if ((!is_active || (eb_is_exposure_active(exposure))) && exposure->net == net && exposure->stn == stn) // Found it
					result = exposure;
				else
					exposure = exposure->next;
			}
		}
		
		if (result)
			eb_debug (0, 4, "EXPOSE", "%-8s %3d.%3d Found %s AUN exposure at %p", "", net, stn, (eb_is_exposure_active(result) ? "active" : "inactive"), result);
		else	eb_debug (0, 4, "EXPOSE", "%-8s %3d.%3d No AUN exposure found", "", net, stn);
	}

	return result;

}

/* Locate the device struct for a packet's source or destination
 * Returns pointer to struct if found; else NULL
 * dir = 1 means source, dir = 2 means destination (to be found)
 */

struct __eb_device * eb_find_station (uint8_t dir, struct __econet_packet_aun *p)
{

	struct __eb_device 	*result;
	uint8_t			net, stn;

	result = NULL;

	if (dir == 1)
	{
		net = p->p.srcnet;
		stn = p->p.srcstn;
	}
	else
	{
		net = p->p.dstnet;
		stn = p->p.dststn;
	}

	eb_debug (0, 4, "BRIDGE", "%-8s %3d.%3d Looking for station struct... eb_get_network() returns %p", "", net, stn, (result = eb_get_network(net)));

	eb_debug (0, 5, "BRIDGE", "%-8s %3d.%3d eb_get_network() result->net is %d", "", net, stn, result->net);

	if ((net != 255) && (stn != 255) && result) // Good start, this network looks like it might exist, and we aren't looking for a broadcast
	{
	
		if (stn == 0) // Bridge internal - don't look for diversions
			return result;

		eb_debug (0, 5, "BRIDGE", "%-8s %3d.%3d eb_get_network() Checking diverts", "", net, stn);

		if (result->net != net) // This is a secondary network on the same device - don't look for diverts
		{
			eb_debug (0, 4, "BRIDGE" "%-8s %3d.%3d eb_find_station() not searching diverts - net %d is different to device net %d", "", net, stn, net, result->net);
			return result;
		}

		// Now see if this is a diversion

		if (result->type == EB_DEF_NULL)
			result = result->null.divert[stn]; // Which will be NULL if the station doesn't exist
		else if (result->type == EB_DEF_WIRE && result->wire.divert[stn]) // Only if there's actually a divert on a wire
			result = result->wire.divert[stn];

	}

	eb_debug (0, 4, "BRIDGE", "%-8s %3d.%3d eb_find_station() returning %p", "", net, stn, result);

	return result;

}

/* Wire reset to read mode function
 */

static void * eb_wire_immediate_reset (void * ebic)
{
	struct __eb_imm_clear 	*values;

	// For reasons I don't follow, debug (including the one done on free) causes a segfault here

	values = (struct __eb_imm_clear *) ebic;

	//eb_debug (0, 4, "IMM-RST", "%-8s %3d     Immediate reset thread started for %d.%d seq 0x%08X", "Wire", values->wire_device->net, values->p_net, values->p_stn, values->p_seq);

	usleep (EB_CONFIG_WIRE_IMM_WAIT * 1000);

	pthread_mutex_lock (&(values->wire_device->priority_mutex));

	if (	(values->p_net == values->wire_device->p_net)
	&&	(values->p_stn == values->wire_device->p_stn)
	&&	(values->p_seq == values->wire_device->p_seq)
	) // Still the same thing waited for, so it didn't show up
	{
		//eb_debug (0, 3, "WIREIMM", "Wire     %3d     Resetting ADLC to read mode when immediate didn't show up", values->wire_device->net);
		ioctl (values->wire_device->wire.socket, ECONETGPIO_IOC_READMODE);

		values->wire_device->p_net = values->wire_device->p_stn = values->wire_device->p_seq = 0; // Reset
	}

	pthread_mutex_unlock (&(values->wire_device->priority_mutex));

	// Free structure malloc()d by the thread which started us

	//eb_free (__FILE__, __LINE__, "WIRE-IMM", "Freeing __eb_imm_clear structure", values);
	free(values);

	return NULL; // Die

}

/*
 *
 * BRIDGE PROTOCOL HANDLING ROUTINES
 *
 *
 */

/* Find a network number to use as our bridge sender address
 * (Which is supposed to be the other side network on a trad Acorn bridge,
 * so it can't be a network which is on the same device as the one
 * that needs to know a sender net (i.e. 'destnet') - so we just hunt
 * for one which is not destnet and isn't NULL either.
 */

uint8_t eb_bridge_sender_net (struct __eb_device *destnet)
{

	uint8_t			result = 0; // Rogue for none found
	uint8_t			count = 1;

	// Search for active net which is not destnet

	pthread_mutex_lock (&networks_update);

	while (count < 255 && !result)
	{
		if (networks[count] && (networks[count] != destnet) && (networks[count]->net != destnet->net))
			result = count;
		else	count++;
		
	}

	pthread_mutex_unlock (&networks_update);

	eb_debug (0, 4, "BRIDGE", "Internal         Sender net is %d for %s device net %d", result, eb_type_str(destnet->type), destnet->net);

	return result;

}

/* Bridge update internal routine - malloc's the update, builds it and sends
 * to a particular device
 */

void eb_bridge_update_single (struct __eb_device *trigger, struct __eb_device *dest, uint8_t ctrl, uint8_t sender_net)
{

	struct __econet_packet_aun	*update;
	char				debug_string[1024];
	uint8_t				data_count;

	update = eb_malloc (__FILE__, __LINE__, "BRIDGE", "Creating bridge packet", 12 + 255);

	if (!update)
		eb_debug (1, 0, "BRIDGE", "Internal     Malloc() failed creating bridge packet!");

	update->p.aun_ttype = ECONET_AUN_BCAST;
	update->p.port = 0x9C;
	update->p.ctrl = (ctrl == 0x80 ? 0x80 : 0x81);
	update->p.seq = (bridgewide_seq += 4);
	update->p.srcstn = 0;
	update->p.srcnet = sender_net;
	update->p.dstnet = 0xff;
	update->p.dststn = 0xff;
	
	strcpy (debug_string, "");

	data_count = 0;

	//if (ctrl == 0x81) // Update - collect our known nets into the data area
	{

		uint8_t			net_count;

		strcpy (debug_string, " with nets ");
	
		for (net_count = 1; net_count < 255; net_count++)
		{

			uint8_t		is_filtered = 0;

			if (dest->type == EB_DEF_WIRE)
				is_filtered = dest->wire.filter_out[net_count];
			else	is_filtered = dest->trunk.filter_out[net_count];

			if (!is_filtered && networks[net_count] && networks[net_count] != dest) // Don't send to trigger, and don't trombone
			{
				char netstr[5];

				update->p.data[data_count++] = net_count;
				snprintf (netstr, 5, "%3d ", net_count);
				strcat (debug_string, netstr);
			}
				
		}

		pthread_mutex_unlock (&networks_update);
	}

	eb_enqueue_input (dest, update, data_count);
	pthread_cond_signal (&(dest->qwake));

	if (dest->type == EB_DEF_WIRE)
		eb_debug (0, 2, "BRIDGE", "%-8s         Send bridge %s to %s net %d%s", (trigger ? eb_type_str(trigger->type) : "Internal"), (ctrl == 0x80 ? "reset" : "update"), eb_type_str(dest->type), dest->net, debug_string);
	else
	{
		if (dest->trunk.hostname)
			eb_debug (0, 2, "BRIDGE", "%-8s         Send bridge %s to Trunk on %s:%d%s", (trigger ? eb_type_str(trigger->type) : "Internal"), (ctrl == 0x80 ? "reset" : "update"), dest->trunk.hostname, dest->trunk.remote_port, debug_string);
		else
			eb_debug (0, 2, "BRIDGE", "%-8s         Send bridge %s to Trunk on %s%s", (trigger ? eb_type_str(trigger->type) : "Internal"), (ctrl == 0x80 ? "reset" : "update"), dest->trunk.serialport, debug_string);
	}

}

/* Bridge update sender 
 * Create a bridge update and send it to all devices except
 * the one serviced by trigger. Do this by iterating through
 * the device list so that we only send once to each device
 * in case the device is serving more than one network via
 * a bridge. Don't send to local, pipe, aun - no point because
 * they don't do bridge traffic.
 * 
 * Set ctrl correctly and this will send out resets instead of
 * updates. ctrl = &80 means reset, &81 is an update.
 *
 */

void eb_bridge_update (struct __eb_device *trigger, uint8_t ctrl)
{

	struct __eb_device		*dev;
	uint8_t				sender_net;

	// Send to all but trigger. If trigger is NULL, this was an internally forced reset/update - send everywhere

	dev = devices;

	while (dev)
	{

		sender_net = eb_bridge_sender_net(dev);

		if (!sender_net) // No bridge sender net available!
		{
			dev = dev->next;
			continue;
		}

		if (dev->type != EB_DEF_WIRE) // Don't send to trigger source, and only send to wire and trunk
		{
			dev = dev->next;
			continue;
		}

		if (dev == trigger && ctrl == 0x80) // Always send update if this was a reset
			eb_bridge_update_single (trigger, dev, 0x81, sender_net);
		else if (dev != trigger) // Don't send to trigger otherwise
			eb_bridge_update_single (trigger, dev, ctrl, sender_net);

		dev = dev->next;

	}

	// Then trunks

	dev = trunks;

	while (dev)
	{
		sender_net = eb_bridge_sender_net(dev);

		if (!sender_net) // No bridge sender net available!
		{
			dev = dev->next;
			continue;
		}

		if (dev == trigger && ctrl == 0x80) // Always send update if this was a reset
			eb_bridge_update_single (trigger, dev, 0x81, sender_net);
		else if (dev != trigger) // Don't send to trigger otherwise
			eb_bridge_update_single (trigger, dev, ctrl, sender_net);

		dev = dev->next;
	}
}

/* Bridge reset routine
 * Send reset to all but *trigger - by iterating through
 * the device list.
 * Then blank off our networks list (by iterating through
 * devices and only filling in the ones that match their
 * native net number, so that they then learn other
 * nets via bridge protocol.
 * Then send a bridge update on all interfaces.
 */

void eb_bridge_reset (struct __eb_device *trigger)
{

	char 	info[20];
	struct __eb_device	*dev;

	if (trigger)
		snprintf (info, 19, "net %d", trigger->net);
	else
		strcpy (info, "internal");

	eb_debug (0, 2, "BRIDGE", "%-8s         Bridge reset from %s", (trigger ? eb_type_str(trigger->type) : "Internal"), info);

	// Put our networks structure back to the start

	pthread_mutex_lock (&networks_update);

	for (uint8_t n = 1; n < 255; n++) // Reset temporarily active exposures to inactive
		if (networks[n])
			eb_set_exposures_inactive(n);

	memcpy (&networks, &networks_initial, sizeof(networks));
	pthread_mutex_unlock (&networks_update);

	eb_debug (0, 2, "BRIDGE", "%-8s         Networks list reset", (trigger ? eb_type_str(trigger->type) : "Internal"));

	// Reset station map to defaults on each wire net as well

	dev = devices;

	while (dev)
	{
		if (dev->type == EB_DEF_WIRE)
		{
			memcpy (&(dev->wire.stations), &(dev->wire.stations_initial), sizeof (dev->wire.stations));
			ioctl (dev->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(dev->wire.stations));
			eb_debug (0, 2, "BRIDGE", "%-8s         Station set reset on wire network %d", (trigger ? eb_type_str(trigger->type) : "Internal"), dev->net);
		}

		dev = dev->next;

	}

	// Send bridge reset onwards to sources other than trigger - use eb_bridge_update with correct ctrl byte

	eb_bridge_update (trigger, 0x80); // Reset

}

/* 
 * Respond to a station's WhatNet or IsNet query. Do so with
 * full packet from <farside>.0.
 */

void eb_bridge_whatis_net (struct __eb_device *source, uint8_t net, uint8_t stn, uint8_t ctrl, uint8_t reply_port, uint8_t query_net)
{
	uint8_t 			farside;
	struct __econet_packet_aun	*reply;

	reply = eb_malloc (__FILE__, __LINE__, "BRIDGE", "Creating bridge What/IsNet reply packet", 14);

	if (!reply)
	{
		eb_debug (0, 2, "BRIDGE", "%-8s %3d Failed to malloc() bridge What/IsNet reply packet", eb_type_str (source->type), source->net);
		return;
	}

	farside = eb_bridge_sender_net (source);

	if (!farside)
		return; // Barf - No farside net

	reply->p.srcstn = 0;
	reply->p.srcnet = farside;
	reply->p.dststn = stn;
	reply->p.dstnet = net;
	reply->p.aun_ttype = ECONET_AUN_DATA;
	reply->p.port = reply_port;
	reply->p.ctrl = 0x80;
	reply->p.seq = (bridgewide_seq += 4);
	reply->p.data[0] = source->net;
	reply->p.data[1] = query_net;

	if ((ctrl == 0x83 && networks[query_net] != source) || (ctrl == 0x82))
	{
		
		usleep (5 * 1000 * farside); // Delay
		eb_enqueue_input (source, reply, 2);
		pthread_cond_signal(&(source->qwake));

		eb_debug (0, 2, "BRIDGE", "%-8s %3d     What/IsNet reply from %3d.%3d to %3d.%3d", eb_type_str(source->type), source->net, farside, 0, net, stn);

	}

}

/* Broadcast redistribution
 * Used when the broadcast handler, below, needs to redistribute a broadcast.
 * At some stage in the future, we'll include a refcount somewhere so that
 * we dont' have to malloc() a new copy of the packet all the time - but for
 * now, that is unattractively what we'll do.
 */

void eb_send_broadcast (struct __eb_device *s, struct __eb_device *d, struct __econet_packet_aun *p, uint16_t length)
{

	struct __econet_packet_aun	*a;

	// Safety check - shouldn't be needed, but just in case.
	if (d->type == EB_DEF_NULL)	return; // No means of sending on NULL - NULL will only have diverts.

	if (s == d) // Don't trombone
		return;

	a = eb_malloc (__FILE__, __LINE__, "BCAST", "Create packet copy", length + 12);

	if (!a)	return;

	memcpy (a, p, length + 12);

	eb_enqueue_input (d, a, length);

}

/* eb_send_broadcast_diverted loops through the divert[] array on a device to
 * see if there are any stations that need to be sent a copy separately from
 * the main device
 */

void eb_send_broadcast_diverted (struct __eb_device *s, struct __eb_device *d, struct __econet_packet_aun *p, uint16_t length)
{

	struct __eb_device	*dev;
	uint8_t			count;
	struct __eb_aun_exposure	*e;

	e = eb_is_exposed (p->p.srcnet, p->p.srcstn, 1);

	if (d->type == EB_DEF_NULL)
	{
		for (count = 1; count < 255; count++)
			if ((dev = d->null.divert[count]))
				if ((dev->type == EB_DEF_AUN && e) || (dev->type != EB_DEF_AUN && ((dev->type != EB_DEF_PIPE) || (dev->pipe.skt_write != -1))))
					eb_send_broadcast(s, dev, p, length);
	}
	else if (d->type == EB_DEF_WIRE)
	{
		for (count = 1; count < 255; count++)
			if ((dev = d->wire.divert[count]))
				if ((dev->type == EB_DEF_AUN && e) || (dev->type != EB_DEF_AUN))
					eb_send_broadcast(s, dev, p, length);
	}

}

/* Trace handler
 *
 * Replies to source if we have a route to the destination station
 *
 * Port 0x9B is the trace port, Ctrl &82 is request, &83 is a reply
 *
 * Devices must not reply if they have no route to the destination
 *
 * Being attached to the relevant destination network is considered
 * final, because Beebs / Arcs won't actually reply to the traffic,
 * so the immediately adjacent bridge does it.
 *
 * Acorn bridges don't do this.
 *
 * If we actually have a defined station, we'll reply with info
 * about the defined station.
 *
 * Returns 1 when the packet should be forwarded on
 * Returns 0 when it shouldn't.
 * This will increment the hop count within the packet!
 */

uint8_t eb_trace_handler (struct __eb_device *source, struct __econet_packet_aun *p, uint16_t length)
{

	if (p->p.port == ECONET_TRACE_PORT && p->p.ctrl == 0x82) // We are using this for the HPB's traceroute facility. &82 means trace query. &83 is a response. Bridges do NOT respond if they have no route to the destination.
	{
		uint8_t			hop, final, net, stn;
		struct __eb_device	*route;

		hop = p->p.data[0];
		net = p->p.dstnet;
		stn = p->p.dststn;

		if (p->p.aun_ttype != ECONET_AUN_DATA) return 0; // Don't forward it, whatever it is.

		if (net == 0) return 1; 

		p->p.data[0]++;

		final = 0; // Set to 1 if we are last hop / end of the road

		if ((route = eb_get_network(net)))
		{
			struct __econet_packet_aun 	*reply;
			char				reply_diags[384];

			char				hostname[256];

			// We know this network - we'll reply, increment the hop count & forward it unless the network is local to us.

			if (route->net == net)
				final = 1;
			
			if (final)
			{
				if (route->type == EB_DEF_WIRE && route->wire.divert[stn])	route = route->wire.divert[stn];
				else if (route->type == EB_DEF_NULL && route->null.divert[stn])	route = route->null.divert[stn];
			}
				
			gethostname(hostname, 255);

			switch (route->type)
			{
				case EB_DEF_WIRE:
					snprintf(reply_diags, 383, "%s %03d via Wire on %s (%d)", hostname, net, route->wire.device, route->net); break;
				case EB_DEF_TRUNK:
					snprintf(reply_diags, 383, "%s %03d via Trunk to %s:%d", hostname, net, route->trunk.hostname, route->trunk.remote_port); break;
				case EB_DEF_NULL:
					snprintf(reply_diags, 383, "%s %03d via Local Null - undefined divert", hostname, net); break;
				case EB_DEF_LOCAL:
					snprintf(reply_diags, 383, "%s %03d.%03d via Local Emulation", hostname, net, stn); break;
				case EB_DEF_PIPE:
					snprintf(reply_diags, 383, "%s %03d.%03d via Local Pipe %s", hostname, net, stn, route->pipe.base); break;
				case EB_DEF_AUN:
				{
					if (route->aun->port == -1)
						snprintf(reply_diags, 383, "%s %03d.%03d via AUN (Inactive)", hostname, net, stn); 
					else
						snprintf(reply_diags, 383, "%s %03d.%03d via AUN at %08X:%d", hostname, net, stn, route->aun->addr, route->aun->port); 
				} break;
				default:	snprintf(reply_diags, 383, "%s %03d Unkonwn destination type", hostname, net); break;
			}

			reply = eb_malloc (__FILE__, __LINE__, "TRACE", "Allocating reply packet for a trace query", 12 + strlen(reply_diags) + 4);

			if (reply)
			{
				eb_debug (0, 2, "TRACE", "%-8s %3d.%3d Received trace request for known net %d, hop %d - %s (%s)", eb_type_str(source->type), p->p.srcnet, p->p.srcstn, net, hop + 1, reply_diags, final ? "last hop" : "intermediate hop");

				reply->p.port = ECONET_TRACE_PORT;
				reply->p.ctrl = 0x83;
				reply->p.srcstn = 0;
				reply->p.srcnet = devices->net; // First operative network number on our bridge
				reply->p.dststn = p->p.srcstn;
				reply->p.dstnet = p->p.srcnet;
				reply->p.aun_ttype = ECONET_AUN_DATA;
				reply->p.seq = 0x0004; // A proper Cornelius, that one.
				reply->p.padding = 0;
				reply->p.data[0] = hop + 1;
				reply->p.data[1] = final;
				reply->p.data[2] = net;
				reply->p.data[3] = stn;
				memcpy (&(reply->p.data[4]), reply_diags, strlen(reply_diags));
				
				eb_enqueue_input (source, reply, strlen(reply_diags) + 4);
	
				return 1;
			}

		}
		else
			eb_debug (0, 2, "TRACE", "%-8s %3d     Received trace request for unknown net %d, hop %d - not replying",	eb_type_str(source->type), net, hop);

		if (final || (hop > 20)) return 0; // Stop any potential storms

	}

	return 1; // Flag as processed. We return 0 if we don't want this traffic forwarded - to avoid storms.
}

/* Broadcast handler.
 * 
 * If it's bridge traffic (port 0x9C) then handle locally only.
 *
 * Otherwise blat it out everywhere we know about, including diverts, except where it came from
 *
 */

void eb_broadcast_handler (struct __eb_device *source, struct __econet_packet_aun *p, uint16_t length)
{

	if (p->p.port == 0x9C) // Bridge traffic
	{
		if (p->p.ctrl >= 0x82) // What/IsNet
		{
			if (!strncasecmp((char *) &(p->p.data), "BRIDGE", 6))
				eb_bridge_whatis_net (source, p->p.srcnet, p->p.srcstn, p->p.ctrl, p->p.data[6], p->p.data[7]);

		}
		else if ((p->p.ctrl & 0xFE) == 0x80) // Incoming reset or update
		{

			uint8_t		data_count;
			char		debug_string[1024];

			if (p->p.ctrl == 0x80) eb_reset_tables(); // Reset if need be

			// Go through the data and update our networks table

			strcpy (debug_string, ""); 

			pthread_mutex_lock (&networks_update);

			data_count = 0;

			while (data_count < length)
			{
				char			net_string[12];
				uint8_t			is_filtered;
				uint8_t			in_adv;

				in_adv = p->p.data[data_count];
	
				if (source->type == EB_DEF_WIRE)
					is_filtered = source->wire.filter_in[in_adv];
				else	is_filtered = source->trunk.filter_in[in_adv];

				snprintf (net_string, 5, " %3d", in_adv);

				if (is_filtered)
				{
					if (source->type == EB_DEF_WIRE)
						eb_debug (0, 2, "BRIDGE", "%-8s %3d     Ignored incoming bridge update for net %d: filtered inbound", eb_type_str(source->type), source->net, in_adv);
					else
						eb_debug (0, 2, "BRIDGE", "%-8s         Ignored incoming bridge update for net %d: filtered inbound", eb_type_str(source->type), in_adv);

					strcat (net_string, "F");
				}
				else
				{

					uint8_t		old_in_adv;

					// Do Network Translation

					old_in_adv = in_adv;

					if (source->type == EB_DEF_TRUNK)
						in_adv = (source->trunk.xlate_in[in_adv] ? source->trunk.xlate_in[in_adv] : in_adv);
	
					if (old_in_adv != in_adv)
					{
						char	trans_string[10];

						snprintf (trans_string, 8, "->%d", in_adv);
						strcat (net_string, trans_string);
					}

					if (networks[in_adv] && networks[in_adv] != source)
					{
						if (networks[in_adv]->type == EB_DEF_WIRE)
							eb_debug (0, 2, "BRIDGE", "%-8s %3d     Ignored incoming bridge update for net %d: already known on wire net %d", eb_type_str(source->type), source->net, in_adv, networks[in_adv]->net);
						else
							eb_debug (0, 2, "BRIDGE", "%-8s         Ignored incoming bridge update for net %d (%s): already known on trunk to %s:%d", eb_type_str(source->type), in_adv, (in_adv != old_in_adv ? "translated" : "untranslated"), networks[in_adv]->trunk.hostname, networks[in_adv]->trunk.remote_port);

						strcat (net_string, "I"); // Ignored
					}
					else	
					{	
						networks[in_adv] = source;
						eb_set_whole_wire_net (in_adv, source);
						eb_set_exposures_active (in_adv, source);
	
						eb_debug (0, 4, "BRIDGE", "                 Set networks[%d] to %p. Wire station sets updated.", in_adv, source);
					}
				}

				strcat(debug_string, net_string);

				data_count++;

			}
			
			pthread_mutex_unlock (&networks_update);

			if (source->type == EB_DEF_WIRE)
				eb_debug (0, 2, "BRIDGE", "Wire     %3d     Received bridge %s with %s%s", source->net, (p->p.ctrl == 0x80 ? "reset" : "update"), (strlen(debug_string) == 0 ? "no networks" : "nets"), debug_string);
			else
			{
				if (source->trunk.hostname)
					eb_debug (0, 2, "BRIDGE", "Trunk            Received bridge %s from %s:%d with %s%s", (p->p.ctrl == 0x80 ? "reset" : "update"), source->trunk.hostname, source->trunk.remote_port, (strlen(debug_string) == 0 ? "no networks" : "nets"), debug_string);
				else
					eb_debug (0, 2, "BRIDGE", "Trunk            Received bridge %s from %s with %s%s", (p->p.ctrl == 0x80 ? "reset" : "update"), source->trunk.serialport, (strlen(debug_string) == 0 ? "no networks" : "nets"), debug_string);
			}

			eb_bridge_update (source, p->p.ctrl);
	
		}
				

	}
	else
	{
		// It's going on input queues, so we have to replicate for each tx. In future will optimize with ref count in the packetqueue structure
	
		struct __eb_device		*d;

		d = devices; // We use this list because if we cycle through networks[], we may see the same network twice if it's had an inbound bridge advert that it accepted. This list has each device (WIRE, TRUNK, NULL) only once. Within WIRE & NULL, we need to look for diverts to send to as well.

		while (d)
		{
			if (d->type == EB_DEF_WIRE)
				eb_send_broadcast(source, d, p, length);

			if (d->type == EB_DEF_NULL || d->type == EB_DEF_WIRE)
				eb_send_broadcast_diverted(source, d, p, length);

			d = d->next;
		}

		// Then trunks

		d = trunks;

		while (d)
		{
			eb_send_broadcast(source, d, p, length);
			d = d->next;
		}

	}

}

/* Take a packet received from a device, put it on the device output queue, and wake up the 
   Device's transmission routine

   returns 1 for success, 0 for failure (e.g. can't find source station)
*/

uint8_t eb_enqueue_output (struct __eb_device *source, struct __econet_packet_aun *packet, uint16_t length)
{

	uint16_t 		destcombo;
	struct __eb_outq	*outq, *search, *parent;
	struct __eb_packetqueue	*packetq;
	struct __econet_packet_aun	*p;
	uint8_t			result = 1;

	// First off, if this is a broadcast then divert it to the broadcast handler - output queues do not handle
 	// Broadcast traffic. This should be OK because the broadcast handler does not attempt to re-transmit back
	// to source, so it shouldn't try and acquire the same input mutex that the sender might presently have

	if (packet->p.aun_ttype == ECONET_AUN_BCAST || packet->p.dstnet == 255 || packet->p.dststn == 255)
	{
		eb_broadcast_handler (source, packet, length);
		return 1;
	}

	// If auto-ack is on for this device, send it an ACK for data packets
	// (BeebEm repeats transmission of packets it didn't get an answer to, but it
	// does it with a different sequence number, so you get multiple different
	// packets. If we ack immediately, it's not massively good from an AUN standpoint,
	// but since the emulated BBC will think the packet has gone anyway, not much
	// harm. True AUN devices can sit and wait & retransmit.

	// Sanity check: we should never be sending to stn 0 (they're bridge devices which won't talk to us anyway)
	if (packet->p.dststn == 0)
		return 0;

	packet->p.dstnet = (packet->p.dstnet == 0 ? source->net : packet->p.dstnet);

	destcombo = (packet->p.dstnet << 8) + packet->p.dststn;

	eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d from %3d.%3d Attempting to put packet on output queue with destcombo 0x%04X", eb_type_str(source->type), packet->p.dstnet, packet->p.dststn, packet->p.srcnet, packet->p.srcstn, destcombo);

	if (!(p = eb_malloc(__FILE__, __LINE__, "Q-OUT", "Create packet structure", length+12))) // Only need data + 12 bytes
	{
		eb_debug (0, 1, "BRIDGE", "malloc(output, packet copy) for packet from %3d.%3d to %3d.%3d port &%02X ctrl &%02X length &%04X seq 0x%08lX",
			packet->p.srcnet,
			packet->p.srcstn,
			packet->p.dstnet,
			packet->p.dststn,
			packet->p.port,
			packet->p.ctrl,
			length,
			packet->p.seq
		);

		return 0; // Couldn't malloc
	}

	memcpy (p, packet, length+12);

	if (!(packetq = eb_malloc(__FILE__, __LINE__, "Q-OUT", "Create packetq structure", sizeof(struct __eb_packetqueue))))
	{
		eb_debug (0, 1, "BRIDGE", "malloc(output, packetqueue) for packet from %3d.%3d to %3d.%3d port &%02X ctrl &%02X length &%04X seq 0x%08lX",
			packet->p.srcnet,
			packet->p.srcstn,
			packet->p.dstnet,
			packet->p.dststn,
			packet->p.port,
			packet->p.ctrl,
			length,
			packet->p.seq
		);

		eb_free(__FILE__, __LINE__, "Q-OUT", "free packet after packetq malloc failed", p);
		return 0; 
	}

	packetq->p = p; 
	packetq->last_tx.tv_sec = packetq->last_tx.tv_usec = 0; // Cause immediate first transmission
	packetq->tx = 0; // Gets set to 1 when this has gone on the requisite input queue
	packetq->errors = 0; // Ditto tx
	packetq->length = length;
	packetq->n = NULL; // Initialize
	
	pthread_mutex_lock (&(source->qmutex_out));

	parent = NULL;
	search = source->out;

	eb_debug (0, 4, "QUEUE", "%-8s %3d     Attempting to find destcombo 0x%04X on outq list at %p", eb_type_str(source->type), source->net, destcombo, search);

	eb_debug (0, 4, "QUEUE", "%-8s %3d     Current outq list starts at %p", eb_type_str(source->type), source->net, search);
	while (search && search->destcombo < destcombo)
	{
		parent = search;
		search = search->next;
	}

	eb_debug (0, 4, "QUEUE", "%-8s %3d     Search for destcombo 0x%04X stopped at %p, which %s", eb_type_str(source->type), source->net, destcombo, search, (search && destcombo == search->destcombo ? "IS the outq we wanted" : "is NOT the outq we were looking for"));

	// By here, either we have NULL (which can mean no queue at all, or we fell off the end of the queue)
	// *or* if not null, then search->destcombo was >= the one we wanted

	if (!search || (search->destcombo != destcombo)) // No queue, or we fell off the end, or the one we found was not ours
	{
		outq = eb_malloc(__FILE__, __LINE__, "Q-OUT", "Create outq structure", sizeof(struct __eb_outq));
		if (outq)
		{
			outq->p = NULL; // Empty the queue for this destination
			outq->next = NULL;
			outq->destcombo = destcombo;
			outq->destdevice = NULL;

			outq->destdevice = eb_find_station (2, packet);
			
			if (!outq->destdevice) // Can't work out where we are going!
			{
				eb_debug (0, 1, "QUEUE", "%-8s %3d.%3d from %3d.%3d Seq 0x%08X Attempting to queue traffic when destination device cannot be found", eb_type_str(source->type), p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, p->p.seq);

				eb_free (__FILE__, __LINE__, "Q-OUT", "Free packet after dest device unknown", p);
				eb_free (__FILE__, __LINE__, "Q-OUT", "Free packetq after dest device unknown", packetq);
				eb_free (__FILE__, __LINE__, "Q-OUT", "Free outq after dest device unknown", outq);
				return 0;
			}

			// Splice it in
			if (search) // If we're here, we didn't find our destcombo
			{
				outq->next = search;
				if (parent)
					parent->next = outq;
				else	source->out = outq;
			}
			else // We were at queue head or fell off the end
			{
				if (parent) // We fell off the end
					parent->next = outq;
				else // There was no queue - put on head
					source->out = outq;
			}
			
		}
		else // Can't malloc
		{
			
			eb_debug (0, 1, "BRIDGE", "malloc(output, outq) for packet from %3d.%3d to %3d.%3d port &%02X ctrl &%02X length &%04X seq 0x%08lX",
				packet->p.srcnet,
				packet->p.srcstn,
				packet->p.dstnet,
				packet->p.dststn,
				packet->p.port,
				packet->p.ctrl,
				length,
				packet->p.seq
			);

			result = 0;
			eb_free (__FILE__, __LINE__, "Q-OUT", "Free packet after malloc(outq) failed", p);
			eb_free (__FILE__, __LINE__, "Q-OUT", "Free packetq after malloc(outq) failed", packetq);
		}
	}
	else	outq = search; // Because if we got here, search->destcombo must have been ours
	
	// By here, outq points to the queue structure we are adding the packet to

	if ((!outq->p)) // Ditch prioritising IMMREPs. If it's non-wire, it doesn't matter, and if we're putting AUN on output queue it will really muck the sequencing up, since AUN is transmitted from the outq || (p->p.aun_ttype == ECONET_AUN_IMMREP)) // Put this on the head of the queue if immediate reply, or no queue exists
	{
		packetq->n = outq->p;
		outq->p = packetq;
	
		eb_debug (0, 4, "QUEUE", "%-8s %3d     Enqueued packet at %p at queue head %p", eb_type_str(source->type), source->net, packetq->p, packetq);

	}
	else // outq->p is not null here (otherwise previous if() would have run)
	{
		struct __eb_packetqueue *w;

		w = outq->p;

		while (w->n) w = w->n;

		// By here, we have w as the last queue entry.

		w->n = packetq;

		eb_debug (0, 4, "QUEUE", "%-8s %3d     Enqueued packet at %p at queue tail %p", eb_type_str(source->type), source->net, packetq->p, packetq);
	}
	
	eb_debug (0, 4, "QUEUE", "%-8s %3d     Output queue waking up despatcher", eb_type_str(source->type), source->net);

	pthread_cond_signal (&(source->qwake));

	// Dump queue state in debug

	eb_debug (0, 4, "QUEUE", "%-8s %3d     Current output queue state:", eb_type_str(source->type), source->net);

	{
		unsigned short		packets;
		struct __eb_packetqueue	*p;
		struct __eb_outq	*o;

		o = source->out;

		if (!o)	eb_debug (0, 4, "QUEUE", "%-8s %3d    No output queues", eb_type_str(source->type), source->net);
		else
		{
			while (o)
			{
				packets = 0;
			
				p = o->p;
	
				while (p)
				{
					packets++;
					p = p->n;
				}

				eb_debug (0, 4, "QUEUE", "%-8s %3d     Destcombo 0x%04X, %d packets", eb_type_str(source->type), source->net, o->destcombo, packets);

				p = o->p;

				packets = 0;

				while (p)
				{
					eb_debug (0, 5, "QUEUE", "%-8s %3d        %4d packetqueue at %p, packet at %p", eb_type_str(source->type), source->net, packets, p, p->p);
					packets++;
					p = p->n;
				}

				o = o->next;
			}
		} 

	}

	eb_debug (0, 4, "QUEUE", "%-8s %3d     Output queue manager releasing mutex", eb_type_str(source->type), source->net);

	pthread_mutex_unlock (&(source->qmutex_out));
	
	return result;
}

/* Take a packet which will usually be sitting on a device's output queue (but might be an
   internal bridge broadcast that didn't originate within a device at all) and put it on
   another device's input queue. Then wake that device up.

   Note: packet must be malloc()'d by the caller and not free()'d by it because its pointer
   just gets used in this function. So internally generated traffic onto an input queue
   (typically only bridge replies) needs to have specifically malloc()'d packets.

   returns 1 for success, 0 for failure (e.g. can't find destination station, not listening)
*/

uint8_t eb_enqueue_input (struct __eb_device *dest, struct __econet_packet_aun *packet, uint16_t length)
{

	uint8_t		result = 1;
	struct __eb_packetqueue		*q;
	struct __eb_device		*source;
	// struct __eb_device		*source_parent = NULL; // Used to signal a parent device if the source is AUN. Prevents double locking the outbound queue mutex

	if (!(source = eb_find_station(1, packet)))
	{
		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound packet after source not found", packet);
		return 0;
	}

	if (dest == source) // This would be a loop
	{
		eb_debug (0, 1, "BRIDGE", "%-8s %3d.%3d from %3d.%3d LOOP PREVENTED port &%02X ctrl &%02X length &%04X seq 0x%08lX",
			eb_type_str(dest->type),
			packet->p.dstnet,
			packet->p.dststn,
			packet->p.srcnet,
			packet->p.srcstn,
			packet->p.port,
			packet->p.ctrl,
			length,
			packet->p.seq
		);

		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound packet after loop detected", packet);

		return 0;
	}

	if (eb_firewall(packet) != EB_FW_ACCEPT)
	{
		eb_debug (0, 1, "BRIDGE", "%-8s %3d.%3d from %3d.%3d PACKET FIREWALLED port &%02X ctrl &%02X length &%04X seq 0x%08lX",
			eb_type_str(dest->type),
			packet->p.dstnet,
			packet->p.dststn,
			packet->p.srcnet,
			packet->p.srcstn,
			packet->p.port,
			packet->p.ctrl,
			length,
			packet->p.seq
		);

		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound packet after packet firewalled", packet);

		return 0;
	}

	if (dest->type == EB_DEF_WIRE && (packet->p.aun_ttype == ECONET_AUN_ACK || packet->p.aun_ttype == ECONET_AUN_NAK)) // Don't queue these
	{
		
		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound ACK/NAK to wire - not queued", packet);

		return 1;

	}

	eb_dump_packet (dest, EB_PKT_DUMP_PRE_O, packet, length);

	// If we've got an IMMREP which matches our priority list on a wire device,
	// Put it on the head of the input queue, not the tail.

	if (!(q = eb_malloc(__FILE__, __LINE__, "Q-IN", "Create packetq structure", sizeof(struct __eb_packetqueue))))
	{
		eb_debug (0, 1, "BRIDGE", "malloc(input, packetqueue) for packet from %3d.%3d to %3d.%3d port &%02X ctrl &%02X length &%04X seq 0x%08lX",
			packet->p.srcnet,
			packet->p.srcstn,
			packet->p.dstnet,
			packet->p.dststn,
			packet->p.port,
			packet->p.ctrl,
			length,
			packet->p.seq
		);

		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound packet after malloc(packetq) files", packet);
		result = 0;
	}
	else
	{
		pthread_mutex_lock (&(dest->qmutex_in));

		q->p = packet;
		q->last_tx.tv_sec = q->last_tx.tv_usec = 0;
		q->tx = 0;
		q->errors = 0;
		q->n = NULL;
		q->length = length;
		
		pthread_mutex_lock (&(dest->priority_mutex));

		// Trunk NAT (outbound) here - TODO

		if (!dest->in || (dest->type == EB_DEF_WIRE && dest->p_net == packet->p.dstnet && dest->p_stn == packet->p.dststn && dest->p_seq == packet->p.seq))
		{
			q->n = dest->in;
			dest->in = q;

			dest->p_net = dest->p_stn = dest->p_seq = 0;

		}
		else // Put on tail
		{
			struct __eb_packetqueue *skip;

			skip = dest->in;

			while (skip->n)
				skip = skip->n;
		
			skip->n = q;
		}

		pthread_mutex_unlock (&(dest->priority_mutex));

		pthread_mutex_unlock (&(dest->qmutex_in));

		pthread_cond_signal (&(dest->qwake));
	}

	return result;

}

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

			eb_enqueue_output (d, q->p, q->length);
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

/* Implement the bridge firewall on a packet traversing the bridge. 
   Used by the bridge transfer routines immediately prior to eb_enqueue_input()
   Returns EB_FW_ACCEPT or EB_FW_REJECT. Defaults to the defined default.
*/

uint8_t eb_firewall (struct __econet_packet_aun *p)
{

	uint8_t		result;
	struct __eb_fw	*f;

	result = EB_FW_DEFAULT;

	f = bridge_fw;

	while (f)
	{
		// Note - the bridge firewall entries are bidirectional!

		if (	(	(f->srcstn == 0xff || f->srcstn == p->p.srcstn)
			&&	(f->srcnet == 0xff || f->srcnet == p->p.srcnet)
			&&	(f->dststn == 0xff || f->dststn == p->p.dststn)
			&&	(f->dstnet == 0xff || f->dstnet == p->p.dstnet)
			)
		||
			(	(f->srcstn == 0xff || f->srcstn == p->p.dststn)
			&&	(f->srcnet == 0xff || f->srcnet == p->p.dstnet)
			&&	(f->dststn == 0xff || f->dststn == p->p.srcstn)
			&&	(f->dstnet == 0xff || f->dstnet == p->p.srcnet)
			)
		)
		{
			result = f->action;
			break;
		}
		
		f = f->next;

	}

	return result;

}

/* Generic device listener loop
 */

static void * eb_device_listener (void * device)
{

	struct __eb_device	*d = device;	// Us
	struct pollfd		p;

	if ((d->type == EB_DEF_LOCAL && d->local.ip.tunif[0] != '\0') || d->type == EB_DEF_PIPE)
		eb_debug (0, 2, "LISTEN", "%-8s %3d.%3d Device listener started (fd %d)", eb_type_str(d->type), d->net, (d->type == EB_DEF_LOCAL ? d->local.stn : d->pipe.stn), d->p_reset.fd);
	else if (d->type == EB_DEF_TRUNK)
		eb_debug (0, 2, "LISTEN", "%-8s         Device listener started (fd %d)", eb_type_str(d->type), d->p_reset.fd);
	else if (d->type != EB_DEF_LOCAL)
		eb_debug (0, 2, "LISTEN", "%-8s %3d     Device listener started (fd %d)", eb_type_str(d->type), d->net, d->p_reset.fd);

	/* This routine simply sits and waits for incoming traffic from the
	   the device and, if it does, it locks the device's queue structure,
	   puts the packet on an output queue and wakes the main thread.
	 */

	/* PROBLEM: This needs to reset a wire to read mode if an immediate reply doesn't show up from the rest of the network
	   in a sensible time, otherwise we just block the wire */

	memcpy (&p, &(d->p_reset), sizeof(p));

	eb_thread_ready();

	// If we are a local device, we have no need of a listener unless we're an IP gateway, So unless the IP gateway is live, die.
	// We do this after signalling ready so we don't get a threadcount mismatch. (Sounds like bedding...)

	if (d->type == EB_DEF_LOCAL && d->local.ip.tunif[0] == '\0')
		return NULL;
	
	if (d->type == EB_DEF_WIRE && !strcasecmp(d->wire.device, "/dev/null")) // Don't even bother
		return NULL;

	while (poll(&p, 1, -1))
	{
		if ((p.revents & POLLHUP) && d->type == EB_DEF_PIPE && (d->pipe.skt_write != -1)) // Presumably PIPE - close writer socket
		{
			struct __eb_packetqueue 	*q, *q_next;

			close (d->pipe.skt_write);
			d->pipe.skt_write = -1;

			eb_debug (0, 1, "LISTEN", "%-8s %3d.%3d Pipe client went away - closing writer socket", "Pipe", d->net, d->pipe.stn);

			// Dump the input queue

			pthread_mutex_lock (&(d->qmutex_in));

			q = d->in;	

			while (q)
			{
				q_next = q->n;
				eb_free (__FILE__, __LINE__, "PIPE", "Freeing entire inbound queue after pipe client went away - free packet entry", q->p);
				eb_free (__FILE__, __LINE__, "PIPE", "Freeing entire inbound queue after pipe client went away - free packetq entry", q);
				q = q_next;
			}

			d->in = NULL;

			pthread_mutex_unlock (&(d->qmutex_in));	

			eb_debug (0, 3, "LISTEN", "Pipe     %3d.%3d Cleared device input queue", d->net, d->pipe.stn);

		}

		if (p.revents & POLLIN && (!(p.revents & POLLHUP))) // Traffic has arrived from the device
		{
	
			if ((d->type == EB_DEF_PIPE) && (d->pipe.skt_write == -1))
			{
				char	pipewriter[128];

				eb_debug (0, 1, "LISTEN", "Pipe     %3d.%3d Pipe client connected - opening writer socket", d->net, d->pipe.stn);

				snprintf (pipewriter, 127, "%s.frombridge", d->pipe.base);

				d->pipe.skt_write = open (pipewriter, O_WRONLY | O_NONBLOCK | O_SYNC);

				if (d->pipe.skt_write == -1)
					eb_debug (0, 1, "LISTEN", "Pipe     %3d.%3d Failed to open writer socket %s: %s", d->net, d->pipe.stn, pipewriter, strerror(errno));
			}

			pthread_cond_signal(&d->qwake);

		}

		// Reset poll structure
	
		memcpy (&p, &d->p_reset, sizeof(p));
		
	}
	
	return NULL;
}

/* AUN listener device - just receives traffic and puts it straight on the input queue of an ordinary device / divert 
 */

/* When we move to single thread per network for listening, use the first half of this function
   to set up the listeners, and then move the while (1) {} loop to a new function which:
   a) Gets passed an exposure object which is the first in the queue in the network in question.
   b) Looks forward to find all exposures in that network, and sets up a listener for each one.
   c) Puts each exposure in a 255-entry table per station.
   d) Has some means of mapping FDs to station numbers without a linear search, though that
      would do for now (that tells us the destination).

   The source check works as at present, as does everything else.

   Then start one such thread for each network, whether it has been defined or not (so we get
   listeners for the inactive exposures).

*/

void eb_setup_aun_listener_socket (void * exposure)
{

	struct __eb_aun_exposure	*e;	// This exposure
	struct addrinfo		hints;
	struct sockaddr_in	service;

	char 			portname[6];

	e = exposure;

	// TO DO - CREATE INTERFACE FOR e->addr HERE IF REQUIRED BY USER

	snprintf(portname, 6, "%d", e->port);

	memset (&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	// Set up local listener

	e->socket = socket(AF_INET, SOCK_DGRAM, 0);

	if (e->socket == -1)
		eb_debug (1, 0, "LISTEN", "%-8s         Unable to open AUN listener socket for station %d.%d on port %d (%s)", "AUN", e->net, e->stn, e->port, strerror(errno));

	service.sin_family = AF_INET;
	service.sin_addr.s_addr = htonl(e->addr);
	service.sin_port = htons(e->port);

	if (bind(e->socket, (struct sockaddr *) &service, sizeof(service)) != 0)
		eb_debug (1, 0, "LISTEN", "%-8s         Unable to bind AUN listener socket station %d.%d (%s)", "AUN", e->net, e->stn, strerror(errno));

	if (e->addr)
		eb_debug (0, 3, "LISTEN", "%-8s %3d.%3d Listener started on %d.%d.%d.%d:%d (fd %d)", "AUN", e->net, e->stn, 
			(e->addr & 0xff000000) >> 24,
			(e->addr & 0xff0000) >> 16,
			(e->addr & 0xff00) >> 8,
			(e->addr & 0xff),
			e->port,
			e->socket);
	else
		eb_debug (0, 3, "LISTEN", "%-8s %3d.%3d Listener started on *:%d (fd %d)", "AUN", e->net, e->stn, 
			e->port,
			e->socket);

	// No return - it'll kill the process if it can't listen
}

void eb_process_incoming_aun (struct __eb_aun_exposure *e)
{

		struct __econet_packet_aun	ack;
		struct __econet_packet_aun	incoming;
		int 				length;
		struct sockaddr_in		addr;
		socklen_t			addrlen;
		
		addrlen = sizeof(struct sockaddr);

		length = recvfrom(e->socket, &(incoming.p.aun_ttype), sizeof(struct __econet_packet_aun), 0, (struct sockaddr *) &addr, &addrlen);

		if (length < 0)
			eb_debug (0, 2, "LISTEN", "%-8s %3d.%3d Error %d reading on exposure socket %d (%s)", "AUN", e->net, e->stn, errno, e->socket, strerror(errno));
		else if (eb_is_exposure_active(e)) // Dump packet if exposure inactive
		{
			in_addr_t		source_address;
			uint16_t		source_port;
			struct __eb_device	*source_device;
			struct __econet_packet_aun	*input_packet;

			eb_add_stats (&(e->statsmutex), &(e->b_in), length-12); // Add data length to our stats - exposure receiving inbound traffic

			source_address = ntohl(addr.sin_addr.s_addr);	
			source_port = ntohs(addr.sin_port);
			source_device = eb_find_aun_remote(source_address, source_port);

			if (!source_device) // See if we can allocate a dynamic host
			{
	
				struct __eb_aun_remote		*station;
				uint8_t				found;
				struct timeval			now;

				// If we allocate a dynamic station, send *BYE from it to known FS (need to track them) and then set source_device to the one we allocate so the next IF statement operates
				// eb_debug (0, 2, "DYNAMIC", "%-8s          Traffic received from %s:%d - unknown source. Attempting to allocate dynamic host.", e->parent, inet_ntoa(addr.sin_addr), source_port);

				found = 0;

				station = aun_remotes;

				gettimeofday (&now, 0);

				while (station && !found)
				{
					struct __eb_aun_remote	*n;

					pthread_mutex_lock (&(station->updatemutex));

					n = station->next;

					if (station->is_dynamic && (station->port == -1 || (timediffmsec(&(station->last_dynamic), &now) > (EB_CONFIG_DYNAMIC_EXPIRY * 60 * 1000)))) // bother with this one - must be dynamic, and either no port (unused), or last used more than the timeout ago
					{

						found = 1;

						station->b_in = station->b_out = 0;

						gettimeofday(&(station->last_dynamic), 0);

						station->port = source_port;

						station->addr = source_address;
					
						eb_debug (0, 2, "DYNAMIC", "%-8s %3d.%3d Traffic received from unknown source %s:%d - Allocated dynamic host.", eb_type_str(station->eb_device->type), station->eb_device->net, station->stn, inet_ntoa(addr.sin_addr), source_port);
					}
					
					pthread_mutex_unlock (&(station->updatemutex));

					if (!found)	station = n;

					
				}

				if (found)
				{

/*
					struct __eb_fs_list	*f;
*/

					source_device = station->eb_device;

					// Send BYE packet to all known fileservers

					// (And the ones we don't know can't have had any traffic
					//  from this station address...)

/* Confuses the hell out of BeebEm. It gets answers from fileservers it wasn't talking to.

					pthread_mutex_lock(&(port99_mutex));

					f = port99_list;

					while (f)
					{
						struct __econet_packet_aun *bye;
						struct __eb_device *server;

						bye = eb_malloc(__FILE__, __LINE__, "DYNAMIC", "Allocating storage for spoofed *BYE to fileservers on dynamic station allocation", 12 + 2);
				
						if (!bye)
							eb_debug (1, 0, "DYNAMIC", "AUN      %3d.%3d Unable to malloc() spoofed *BYE to %3d.%3d!", station->eb_device->net, station->stn, f->net, f->stn);

						bye->p.aun_ttype = ECONET_AUN_DATA;
						bye->p.port = 0x99;
						bye->p.ctrl = 0x80;
						bye->p.seq = 0x0004;
						bye->p.srcnet = station->eb_device->net;
						bye->p.srcstn = station->stn;
						bye->p.dstnet = f->net;
						bye->p.dststn = f->stn;
						bye->p.data[0] = 0x01;
						bye->p.data[1] = 0x17; // Bye

						server = eb_find_station(2, bye);
					
						if (server)
						{
							eb_enqueue_input(server, bye, 14);
							eb_debug (0, 2, "DYNAMIC", "AUN      %3d.%3d Send spoof *BYE to fileserver at %3d.%3d", station->eb_device->net, station->stn, f->net, f->stn);
						}

						f = f->next;

					}
					
					pthread_mutex_unlock(&(port99_mutex));
*/ 
				}
				else
					eb_debug (0, 2, "AUN", "%-8s         Traffic received from unknown source %s:%d - Unable to allocate dynamic host.", eb_type_str(e->parent->type), inet_ntoa(addr.sin_addr), source_port);
				
			}

			if (source_device) // Known traffic
			{

				eb_add_stats(&(source_device->statsmutex), &(source_device->b_out), length-12); // Traffic stats - this is the remote device generating output

				incoming.p.dstnet = e->net;
				incoming.p.dststn = e->stn;
				incoming.p.srcnet = source_device->net;
				incoming.p.srcstn = source_device->aun->stn;
				incoming.p.ctrl |= 0x80;

				eb_dump_packet (e->parent, EB_PKT_DUMP_POST_I, &incoming, length - 8); // (Drop the header length)

				// Update the last transaction time - we do this whether dynamic or not, because it doesn't matter

				gettimeofday(&(source_device->aun->last_dynamic), 0);

				// If this is an ACK or NAK, scan the outq of the destination device and see if we need to remove a DATA packet. NB, if it's NAK and there's only been one transmission attempt, don't dump it because it might be from a RiscOS machine that has the bug where it isn't listening early enough. Then wake the despatcher up so it tries to transmit the next packet in its queue

				if (incoming.p.aun_ttype == ECONET_AUN_ACK || incoming.p.aun_ttype == ECONET_AUN_NAK)
				{
					struct __eb_device 	*my_parent;
					struct __eb_outq	*outq, *outq_parent;
					uint16_t		combo;

					my_parent = e->parent;

					combo = (incoming.p.srcnet << 8) | incoming.p.srcstn; // Source here, because we're doing this from the incoming packet

					eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d Acquiring lock for incoming search of outq for packet to %3d.%3d P:&%02X C: &%02X Length 0x%04X, combo = 0x%04X, e->parent = %p", eb_type_str(my_parent->type), incoming.p.dstnet, incoming.p.dststn, incoming.p.srcnet, incoming.p.srcstn, incoming.p.port, incoming.p.ctrl, length, combo, my_parent);

					pthread_mutex_lock (&(my_parent->qmutex_out));

					eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d Locks acquired for incoming search of outq for packet to %3d.%3d P:&%02X C: &%02X Seq: 0x%08X Length 0x%04X, combo = 0x%04X", eb_type_str(my_parent->type), incoming.p.dstnet, incoming.p.dststn, incoming.p.srcnet, incoming.p.srcstn, incoming.p.port, incoming.p.ctrl, incoming.p.seq, length, combo);

					outq_parent = NULL;
					outq = my_parent->out;

					while (outq && outq->destcombo != combo)
					{
						outq_parent = outq;
						outq = outq->next;
					}

					if (outq) // Found correct outq
					{

						struct __eb_packetqueue		*parent, *packetq;
						parent = NULL;
						packetq = outq->p;

						while (packetq && (packetq->p->p.aun_ttype != ECONET_AUN_DATA || packetq->p->p.seq != incoming.p.seq))
						{
							parent = packetq;
							packetq = packetq->n;
						}

						// If within NAK tolerance, set the last tx time to nil so we get an immediate retransmission
						if (packetq && (incoming.p.aun_ttype == ECONET_AUN_NAK && packetq->tx <= EB_CONFIG_AUN_NAKTOLERANCE))
							packetq->last_tx.tv_sec = 0;

						if (packetq && (incoming.p.aun_ttype == ECONET_AUN_ACK || (incoming.p.aun_ttype == ECONET_AUN_NAK && packetq->tx > EB_CONFIG_AUN_NAKTOLERANCE))) // Found a match - splice out
						{

							// uint8_t		port, srcstn, srcnet;
							struct __eb_packetqueue	*this, *this_parent;

							//port = incoming.p.port;
							//srcstn = incoming.p.dststn;
							//srcnet = incoming.p.dstnet;
							this = packetq;
							this_parent = parent;

/* The idea of this was to dump remaining packets from a particular source to this AUN destination if we got too many NAKs so that there wasn't a queue of traffic which was likely to be
 * NAK'd. Unfortunately, BeebEm (which is the primary thing I was testing with) doesn't seem to NAK. So if you interrupt a bulk transfer by pressing BREAK in BeebEm, the remaining 
 * bulk transfer packets on the outq just re-transmit one by one and it takes ages before the BeebEm machine can start communicating again...

							while (this)
							{
								if (port == this->p->p.port && srcstn == this->p->p.srcstn && srcnet == this->p->p.srcnet && ((this == packetq && this->p->p.seq == incoming.p.seq) || (this != packetq && incoming.p.aun_ttype == ECONET_AUN_NAK))) // Ditch it. This will always be so on the first loop. Only ditch if first in queue, or if not first in queue if it was a NAK - because we'll be over the NAK tolerance by the time we get here.
								{
*/
									if (this_parent)
										this_parent->n = this->n;
									else
										outq->p = this->n;

									eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d Packet spliced from outq to %3d.%3d P:&%02X C: &%02X Seq: 0x%08X Length 0x%04X, combo = 0x%04X", eb_type_str(my_parent->type), this->p->p.dstnet, this->p->p.dststn, this->p->p.srcnet, this->p->p.srcstn, this->p->p.port, this->p->p.ctrl, this->p->p.seq, this->length, combo);

									eb_free (__FILE__, __LINE__, "AUN-EXP", "Free packet after locating packet to splice out because of ACK/NAK", this->p);
									eb_free (__FILE__, __LINE__, "AUN-EXP", "Free packetq after locating packet to splice out because of ACK/NAK", this);

/*
									if (this_parent)
										this = this_parent->n;
									else	this = outq->p;

								}
								else // not removed - move one down the line
								{
									this_parent = this;
									this = this->n;
								}

								if (incoming.p.aun_ttype == ECONET_AUN_ACK) break; // Only do one loop if it's an ACK - we don't want to ditch everything if it was ACK not NAK!
							}
*/
						}

						if (!outq->p) // outq emptied - free it and de-splice
						{
							if (outq_parent) // This wasn't the first in the queue
								outq_parent->next = outq->next;
							else // Was the first in the queue
								my_parent->out = outq->next;
	
							eb_free (__FILE__, __LINE__, "AUN-EXP", "Free outq after locating packet to splice out because of ACK/NAK", outq);
						}
					}

					pthread_mutex_unlock (&(my_parent->qmutex_out));
		
					pthread_cond_signal (&(my_parent->qwake));


				}
	
				// Prospectively build an ACK - Don't need addressing because this is going out over AUN

				ack.p.seq	= incoming.p.seq;
				ack.p.aun_ttype	= ECONET_AUN_ACK;
				ack.p.port	= incoming.p.port;
				ack.p.ctrl	= incoming.p.ctrl;

				// Because this is going on an input queue, we need to malloc it

				input_packet = eb_malloc(__FILE__, __LINE__, "AUN", "Create incoming packet structure", length + 4); // Extra four bytes

				if (input_packet) // Only do this if the malloc succeeded
				{
					uint8_t		enqueue_result;
					struct __eb_device	*home_device; // The thing this is an exposure for

					memcpy (input_packet, &incoming, length + 4);

					home_device = eb_find_station (2, &incoming);

					enqueue_result = 0;

					if (home_device) enqueue_result = eb_enqueue_input (home_device, input_packet, length - 8); // Only give data length here

					if (!enqueue_result)
						ack.p.aun_ttype = ECONET_AUN_NAK; // NAK if we couldn't enqueue the packet

					if ((!enqueue_result) || (incoming.p.aun_ttype == ECONET_AUN_DATA && (source_device->config & EB_DEV_CONF_AUTOACK))) // NAK if we didn't manage to enqueue; ACK if other end if AUTO ACK
						sendto (e->socket, &(ack.p.aun_ttype), 8, MSG_DONTWAIT, (struct sockaddr *)&addr, (socklen_t) sizeof(struct sockaddr_in));
				}
				else	// MAY AS WELL SEND A NAK (even if not auto ack because the other end will never hear of this packet!)
				{
					ack.p.aun_ttype = ECONET_AUN_NAK;

					sendto (e->socket, &(ack.p.aun_ttype), 8, MSG_DONTWAIT, (struct sockaddr *)&addr, (socklen_t) sizeof(struct sockaddr_in));
				}
			}

		}
		else // Packet dumped because exposure inactive
		{
			eb_debug (0, 4, "QUEUE", "Exposure %3d.%3d Incoming packet received on exposure %p dropped because exposure inactive. P: &%02X C: &%02X Length 0x%04X", e->net, e->stn, e, incoming.p.port, incoming.p.ctrl, length);
		}
}

// AUN exposure listener thread for a given network
// This thread is passed the first exposure object for the network it is to serve.
// It then only opens sockets for stations on that network by looping through exposures

static void * eb_aun_listener (void * exposure)
{

	struct pollfd			pfd[255], pfd_initial[255];
	struct __eb_aun_exposure	* my_exposures[255]; // Exposure objects stored in same order as in pfd, so we can easily see which one received traffic
	struct __eb_aun_exposure	* e; // Loop through exposures

	struct __eb_device		* parent;

	uint8_t				num_fds, net, count;

	num_fds = 0; // Number of entries in pfd

	e = exposure; 

	net = e->net;

	parent = eb_get_network(net);

	// Obtain network number from device, create a list of all exposures, listen for them all, then poll them all	

	while (e)
	{
		if (e->net == net) // One we need to listen for
		{
			eb_setup_aun_listener_socket(e);

			pfd[num_fds].fd = e->socket;
			pfd[num_fds].events = POLLIN;

			/* TODO - Check here to see if the exposure should be active or inactive, and set its parent up appropriately */

			// By default, set inactive

			pthread_mutex_lock(&(e->exposure_mutex));

			e->active = 0; // If there's no parent network, can't be active.
			e->parent = NULL; // Set no parent for now

			if (parent) // Good start - our network is defined!
			{

				if (parent->type == EB_DEF_WIRE)
				{
					e->parent = parent;
					if (e->parent->wire.divert[e->stn]) // There was a wire divert
						e->parent = e->parent->wire.divert[e->stn];
				}
				else if (parent->type == EB_DEF_NULL && parent->null.divert[e->stn]) // Can only have diverts
					e->parent = e->parent->null.divert[e->stn];
				else if (parent->type == EB_DEF_TRUNK) // Existing trunk is fine, if it's come up before we started for example
					e->parent = parent;
				
				// Otherwise, leave it NULL and inactive
			}
			
			if (e->parent)	e->active = 1;

			pthread_mutex_unlock(&(e->exposure_mutex));

			my_exposures[num_fds] = e;
		
			num_fds++;

		}

		e = e->next;

	}

	eb_debug (0, 2, "AUN", "Listener %3d     Started %d AUN listeners", net, num_fds);

	// Copy pfd so we can reset it easily

	memcpy (&pfd_initial, &pfd, sizeof(pfd));

	eb_thread_ready();

	while (poll(pfd, num_fds, -1))
	{

		for (count = 0; count < num_fds; count++) // Loop through to see what talked to us
			if (pfd[count].revents & POLLIN) // Found one
				eb_process_incoming_aun(my_exposures[count]); // Does the read off the socket & processes it

		memcpy (&pfd, &pfd_initial, sizeof(pfd)); // Reset poll structure and go again
	}

	return NULL;
}

/* Generic inter-device transmission loop
 */

static void * eb_device_despatcher (void * device)
{

	struct __eb_device		*d = device;
	int 				err;
	uint8_t				count;
	struct pollfd			p;
	struct __econet_packet_aun	packet;
	int32_t				length; // Needs to be signed to catch errors on read
	int				l_socket; // The socket our device listens on
	uint8_t				aun_output_pending; // Flags when there may be aun retransmits on our output queue
	uint8_t				wire_output_pending; // Flags when there is a wire packet to retransmit
	uint8_t				new_output; // Set to 1 if we have generated new output in our own device while we processed our own input queue (e.g. ACKs, local immediate replies etc.) - causes the despatcher thread not to wait
	uint8_t				wire_null = 0; // Set to 1 if the device is /dev/null
	struct __eb_led			led_read, led_write;
	pthread_t			flash_read_thread, flash_write_thread;
	void 				*flash_read_return, *flash_write_return;
	struct __eb_imm_clear 		*imm_sleeper; // Control structure for imm_clear sleeper thread to reset ADLC if no immediate arrives

	// Initializes and starts a device.
	// Starts a separate listener thread for the device (to read packets from it)
	// Also responsible for starting all known diverts for this device if there are any
	// Where a destination is a remote AUN machine (diverted or just one we know about), this loop also does transmit / retransmit, using the exposure list

	if (d->type == EB_DEF_LOCAL || d->type == EB_DEF_PIPE)
		eb_debug (0, 2, "DESPATCH", "%-8s %3d.%3d Thread started (tid %d)", eb_type_str(d->type), d->net, 
			(d->type == EB_DEF_PIPE ? d->pipe.stn :
			(d->type == EB_DEF_LOCAL ? d->local.stn : 0)), syscall(SYS_gettid));
	else if (d->type != EB_DEF_TRUNK)
		eb_debug (0, 2, "DESPATCH", "%-8s %3d     Thread started (tid %d)", eb_type_str(d->type), d->net, syscall(SYS_gettid));
	else
		eb_debug (0, 2, "DESPATCH", "%-8s         Thread started for trunk on port %d to %s:%d (tid %d)", eb_type_str(d->type), d->trunk.local_port, d->trunk.hostname, d->trunk.remote_port, syscall(SYS_gettid));

	if (d->type == EB_DEF_WIRE && !strcasecmp("/dev/null", d->wire.device)) // Flag as a dummy wire so we don't try and receive traffic from it
		wire_null = 1;

	// Start our device listener

	if (EB_CONFIG_LOCAL && d->type == EB_DEF_WIRE)
		eb_debug (0, 1, "WIRE", "%-8s %3d     Econet device disabled", d->net);

	// Start divert devices if this is a WIRE or NULL / Virtual device

	if (d->type == EB_DEF_WIRE || d->type == EB_DEF_NULL)
	{
		eb_debug (0, 2, "DIVERT", "%-8s %3d     Starting divert devices", "", d->net);

		for (count = 1; count < 255; count++)
		{
			struct __eb_device	*divert;

			if (d->type == EB_DEF_WIRE)	divert = d->wire.divert[count];
			else				divert = d->null.divert[count];

			if (divert && (divert->type != EB_DEF_AUN))
			{
				if ((err = pthread_create (&(divert->me), NULL, eb_device_despatcher, divert)))
					eb_debug (1, 0, "DESPATCH", "Cannot start diverted device for station %d.%d: %s", d->net, count, strerror(err));
				else
					eb_debug (0, 2, "DIVERT", "%-8s %3d.%3d Started %s divert device", eb_type_str (d->type), d->net, count, eb_type_str(divert->type));
				
				pthread_detach(divert->me);
				eb_thread_started();
	
			}
		}
	}

/* OLD CODE - NOW DONE IN MAIN LOOP AFTER MOVE TO ONE-THREAD-PER-NETWORK FOR EXPOSURES

	// Start exposure listeners

	if (d->type == EB_DEF_WIRE || d->type == EB_DEF_NULL) // Only expose on base devices - Where trunks learn a network whose exposure is not yet running, they start it
	{
		e = exposures; // Trawl the whole list - something's wrong with the ordering
	
		count = 0;

		while (e)
		{

			pthread_attr_t	attrs;
			
			pthread_attr_init (&attrs);
			pthread_attr_setstacksize(&attrs, 20 * PTHREAD_STACK_MIN);

			if (e->net == d->net)
			{

				if ((err = pthread_create (&(e->me), &attrs, eb_aun_listener, e)))
					eb_debug (1, 0, "DESPATCH", "%-8s %3d.%3d Unable to start AUN listener thread (%s)", "AUN", e->net, e->stn, strerror(err));

				pthread_detach (e->me);

				eb_thread_started();

				count++;
			}

			e = e->next;
		}
	
		eb_debug (0, 2, "DESPATCH", "%-8s %3d     %s exposures, %d AUN listeners started", eb_type_str(d->type), d->net, (count > 0 ? "Has" : "Has no"), count);
	}

*/
	// Open our device, whatever it might be

	switch (d->type)
	{
		case EB_DEF_WIRE:
		{


			if (EB_CONFIG_LOCAL)
				d->wire.socket = open("/dev/null", O_RDWR);
			else
				d->wire.socket = open(d->wire.device, O_RDWR);

			if (d->wire.socket < 0) // Failed
				eb_debug (1, 0, "DESPATCH", "%-8s %3d     Cannot open device %s", "", d->net, (EB_CONFIG_LOCAL ? "/dev/null" : d->wire.device));

			// Do station setup
	
			ioctl(d->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(d->wire.stations));	
			ioctl(d->wire.socket, ECONETGPIO_IOC_READMODE); // Rest just in case...

			// Flashing the LEDs leaves them ON, signalling device active.

			led_read.led = ECONETGPIO_READLED;
			led_write.led = ECONETGPIO_WRITELED;
			led_read.device = led_write.device = d;
			led_read.flashtime = led_write.flashtime = 500;

			if (!pthread_create(&flash_read_thread, NULL, eb_flash_led, &led_read))
				pthread_join(flash_read_thread, &flash_read_return);

			if (!pthread_create(&flash_write_thread, NULL, eb_flash_led, &led_write))
				pthread_join(flash_write_thread, &flash_write_return);

			if (!EB_CONFIG_LEDS_OFF)
			{
				if (!pthread_create(&flash_read_thread, NULL, eb_flash_led, &led_read))
					pthread_join(flash_read_thread, &flash_read_return);

				if (!pthread_create(&flash_write_thread, NULL, eb_flash_led, &led_write))
					pthread_join(flash_write_thread, &flash_write_return);
			}

			if (d->wire.period) // Clock speed to set
			{
				ioctl(d->wire.socket, ECONETGPIO_IOC_NETCLOCK, (d->wire.period << 16) | d->wire.mark);
				eb_debug (0, 2, "DESPATCH", "%-8s %3d     Network clock configured", "Wire", d->net);
			}

			eb_debug (0, 2, "DESPATCH", "%-8s %3d     Econet device %s opened successfully (fd %d)", "Wire", d->net, (EB_CONFIG_LOCAL ? "/dev/null" : d->wire.device), d->wire.socket);	

		} break;

		case EB_DEF_LOCAL:
		{
			// Initialize fileserver, printerserver, ipserver, etc.

			if (d->local.fs.rootpath) // Active FS
			{
				pthread_mutex_lock (&fs_mutex);
				d->local.fs.index = fs_initialize (d, d->net, d->local.stn, d->local.fs.rootpath);
				pthread_mutex_unlock (&fs_mutex);
				eb_debug (0, 2, "FS", "                 Fileserver %d initialized at %s", d->local.fs.index, d->local.fs.rootpath);
			}

			if (d->local.ip.tunif[0] != '\0') // Active tunnel config
			{
				int 			handle, err;
				struct ifreq 		mine;

				if ((handle = open("/dev/net/tun", O_RDWR)) == -1) // Failure
					eb_debug (1, 0, "IPGW", "%-8s %3d.%3d Cannot open /dev/net/tun to start IPGW tunnel on %s", eb_type_str(d->type), d->net, d->local.stn, d->local.ip.tunif);	
				
				memset (&mine, 0, sizeof(mine));

				mine.ifr_flags = IFF_TUN | IFF_NO_PI;

				strncpy(mine.ifr_name, d->local.ip.tunif, IFNAMSIZ); // Ask for the tunnel we want

				if ((err = ioctl(handle, TUNSETIFF, (void *) &mine)) == -1) // Failure
					eb_debug (1, 0, "IPGW", "%-8s %3d.%3d Cannot select %s for IPGW", eb_type_str(d->type), d->net, d->local.stn, d->local.ip.tunif);

				eb_debug (0, 2, "IPGW", "%-8s %3d.%3d Tunnel %s opened for IPGW", eb_type_str(d->type), d->net, d->local.stn, d->local.ip.tunif);

				d->local.ip.socket = handle;
	
				
			}
			
		} break;

		case EB_DEF_PIPE:
		{

			char	readerfile[512], writerfile[512];
			int	mfr;

			snprintf (readerfile, 510, "%s.tobridge", d->pipe.base);
			snprintf (writerfile, 510, "%s.frombridge", d->pipe.base);

			if ((mfr = mkfifo(readerfile, 0666)) == -1 && (errno != EEXIST))
				eb_debug (1, 0, "DESPATCH", "%-8s %3d.%3d Cannot create reader pipe %s", "", d->net, d->pipe.stn, readerfile);
	
			if ((mfr = mkfifo(writerfile, 0666)) == -1 && (errno != EEXIST))
				eb_debug (1, 0, "DESPATCH", "%-8s %3d.%3d Cannot create writer pipe %s", "", d->net, d->pipe.stn, writerfile);
	
			d->pipe.skt_read = open(readerfile, O_RDONLY | O_NONBLOCK | O_SYNC);

			if (d->pipe.skt_read < 0) // Failed
				eb_debug (1, 0, "DESPATCH", "%-8s %3d.%3d Cannot open pipe reader socket %s", "", d->net, d->pipe.stn, readerfile);
			else
				eb_debug (0, 2, "DESPATCH", "%-8s %3d.%3d Pipe reader device %s opened", "", d->net, d->pipe.stn, readerfile);
	
			//d->pipe.skt_write = -1; // Initialize. -1 means no client. This will get opened when we receive traffic. Semantics of a pipe-connected station is that on connection it *must* send some traffic - usually a Bridge WhatNet? Query.
		} break;

		case EB_DEF_TRUNK:
		{

			if (d->trunk.hostname) // IP trunk
			{
				char 			portname[6];
				struct addrinfo		hints;
				struct sockaddr_in	service;
				int			s;
	
				snprintf(portname, 6, "%d", d->trunk.remote_port);
	
				memset (&hints, 0, sizeof(struct addrinfo));
	
				hints.ai_family = AF_INET;
				hints.ai_socktype = SOCK_DGRAM;
				hints.ai_flags = 0;
				hints.ai_protocol = 0;
	
				if ((s = getaddrinfo(d->trunk.hostname, portname, &hints, &(d->trunk.remote_host))) != 0)
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to resolve hostname %s: %s", d->trunk.hostname, gai_strerror(s));
	
				// Set up local listener
	
				d->trunk.socket = socket(AF_INET, SOCK_DGRAM, 0);
	
				if (d->trunk.socket == -1)
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to open trunk listener socket for local port %d to %s:%d", "Trunk", d->trunk.local_port, d->trunk.hostname, d->trunk.remote_port);
	
	
				service.sin_family = AF_INET;
				service.sin_addr.s_addr = htonl(bindhost); // INADDR_ANY;
				service.sin_port = htons(d->trunk.local_port);
	
				if (bind(d->trunk.socket, (struct sockaddr *) &service, sizeof(service)) != 0)
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to bind trunk listener socket for local port %d to %s:%d (%s)", "Trunk", d->trunk.local_port, d->trunk.hostname, d->trunk.remote_port, strerror(errno));
	
				eb_debug (0, 2, "DESPATCH", "%-8s         Trunk initialized between port %d and %s:%d", "Trunk", d->trunk.local_port, d->trunk.hostname, d->trunk.remote_port);
			} // else serial
			else
			{
				// Initialize termios & set up serial connection - TODO
	
				d->trunk.socket = open(d->trunk.serialport, O_RDWR);

				if (d->trunk.socket < 0)
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to open trunk serial port %s (%s)", "Serial", d->trunk.serialport, strerror(errno));

				if (tcgetattr(d->trunk.socket, &d->trunk.tty) != 0)
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to read config for trunk serial port %s (%s)", "Serial", d->trunk.serialport, strerror(errno));
	
				// Raw mode

				cfmakeraw(&(d->trunk.tty));

				// no delays...
				d->trunk.tty.c_cc[VMIN] = d->trunk.tty.c_cc[VTIME] = 0;

				// Sort out a few input flags

				d->trunk.tty.c_iflag |= IGNBRK;

				// And output

				d->trunk.tty.c_oflag &= ~(ONLCR | OCRNL | ONOCR | ONLRET);

				// And some control bits

				d->trunk.tty.c_cflag &= ~(CSTOPB);
				d->trunk.tty.c_cflag |= HUPCL | CRTSCTS | PARENB;

				cfsetspeed(&(d->trunk.tty), B9600); // Default

				switch (d->trunk.baudrate) // We only work symmetrically on here
				{
					case 3:
						cfsetspeed(&(d->trunk.tty), B300); // Default
						break;
					case 12:
						cfsetspeed(&(d->trunk.tty), B1200); // Default
						break;
					case 96:
						cfsetspeed(&(d->trunk.tty), B9600); // Default
						break;
					case 576:
						cfsetspeed(&(d->trunk.tty), B57600); // Default
						break;
					case 1152:
						cfsetspeed(&(d->trunk.tty), B115200); // Default
						break;
					case 2304:
						cfsetspeed(&(d->trunk.tty), B230400); // Default
						break;
					default:
						eb_debug (1, 0, "DESPATCH", "%-8s         Unsupported baudrate %d00 serial port %s", "Serial", d->trunk.baudrate, d->trunk.serialport);
				}			
		
				if (tcsetattr (d->trunk.socket, TCSANOW, &(d->trunk.tty)))
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to set termios for serial port %s (%s)", "Serial", d->trunk.serialport, strerror(errno));
				
				// Empty both directions

				tcflush (d->trunk.socket, TCIOFLUSH);

				// Set our receiver state and packet pointer
				
				d->trunk.num_ffs = 0; // Number of sequential FFs so far
			
				d->trunk.serialstate = TRUNK_SERIAL_IDLE;
		
				d->trunk.serialptr = 0; // Nothing in the buffer

				// Create the buffer

				d->trunk.serialbuf = eb_malloc (__FILE__, __LINE__, "DESPATCH", "Allocating input buffer for serial trunk", ECONET_MAX_PACKET_SIZE + 12);

				if (!(d->trunk.serialbuf))
					eb_debug (1, 0, "DESPATCH", "%-8s         Unable to allocate buffer memory for trunk serial port %s", "Serial", d->trunk.serialport);
		
				eb_debug (0, 2, "DESPATCH", "%-8s         Trunk port %s successfully initialized at %d00 baud", "Serial", d->trunk.serialport, d->trunk.baudrate);

			}

		} break;

		case EB_DEF_NULL:
		{
		} break; // No device 

		default:
			eb_debug (1, 0, "DESPATCH", "Unknown  %3d     Unknown driver type %04X - cannot initialize", d->net, d->type);
			break;
	}

	d->p_reset.events = POLLIN;

	switch (d->type)
	{
		case EB_DEF_WIRE:
			l_socket = d->wire.socket;
			break;
		case EB_DEF_TRUNK:
			l_socket = d->trunk.socket;
			break;
		case EB_DEF_PIPE:
			l_socket = d->pipe.skt_read;
			d->p_reset.events |= POLLHUP; // Detect client wandering off // This is probably unnecessary - looks like POLLHUP ignored in events
			break;
		case EB_DEF_LOCAL:
			l_socket = d->local.ip.socket;
			break;
	}

	d->p_reset.fd = l_socket;

	// Start our listener thread

	if ((d->type != EB_DEF_NULL))//  && d->type != EB_DEF_LOCAL))
	{
		if ((err = pthread_create (&(d->listen), NULL, eb_device_listener, d))) // NULL has nothing to listen for - its diverts do it; Local devices don't either - they are hard coded devices which inject directly into the queue & wake the despatcher thread
			eb_debug (1, 0, "DESPATCH", "Unable to start device listener thread for net %d: %s", d->net, strerror(err));
		pthread_detach(d->listen);
		eb_thread_started();
	}

	// Now do our work

	eb_thread_ready();

	// MAIN DESPATCH LOOP 

	aun_output_pending = wire_output_pending = new_output = 0;

	// This should have happened at init, but just in case it didn't

	d->out = NULL;
	d->in = NULL;

	while (1)
	{
		

		if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
			eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread loop start - new_output = %d, wire_output_pending = %d", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), new_output, wire_output_pending);
		else if (d->type == EB_DEF_TRUNK)
			eb_debug (0, 4, "DESPATCH", "%-8s         Despatcher thread loop start - new_output = %d, wire_output_pending = %d", eb_type_str(d->type), d->net, new_output, wire_output_pending);
		else
			eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread loop start - new_output = %d, wire_output_pending = %d", eb_type_str(d->type), d->net, new_output, wire_output_pending);

		if (!new_output) // If we have put some new output on our own queue, we don't wait - we have another run at it. Ditto if we've been told there's wire output still on our in queue
		{
	
			if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
				eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread acquiring qmutex_in prior to condwait", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn));
			else if (d->type == EB_DEF_TRUNK)
				eb_debug (0, 4, "DESPATCH", "%-8s         Despatcher thread acquiring qmutex_in prior to condwait", eb_type_str(d->type));
			else
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread acquiring qmutex_in prior to condwait", eb_type_str(d->type), d->net);


			pthread_mutex_lock (&(d->qmutex_in)); // Lock prior to condwait

			if ((aun_output_pending || wire_output_pending) && !(d->in && d->in->tx == 0))
			{
				struct timespec		cond_time;
				unsigned int		delay;
	
				delay = EB_CONFIG_WIRE_RETX;

				if (aun_output_pending && (!wire_output_pending || (EB_CONFIG_AUN_RETX < EB_CONFIG_WIRE_RETX)))	delay = EB_CONFIG_AUN_RETX;
				
				clock_gettime(CLOCK_REALTIME, &cond_time);
	
				if (cond_time.tv_nsec > (1000000000 - (delay * 1000000)))
					cond_time.tv_sec++;
	
				cond_time.tv_nsec = (cond_time.tv_nsec + (delay * 1000000)) % 1000000000;
	
				if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
					eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread timed condwait %d ms", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), delay);
				else
					eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread timed condwait %d ms", eb_type_str(d->type), d->net, delay);
				
				pthread_cond_timedwait(&(d->qwake), &(d->qmutex_in), &cond_time);
			}
			else if (!(d->in && d->in->tx == 0)) // No new traffic
			{
				if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
					eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread infinite condwait", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn));
				else if (d->type == EB_DEF_TRUNK)
					eb_debug (0, 4, "DESPATCH", "%-8s         Despatcher thread infinite condwait", eb_type_str(d->type));
				else
					eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread infinite condwait", eb_type_str(d->type), d->net);

				pthread_cond_wait(&(d->qwake), &(d->qmutex_in));
			}

			// We actually don't want the mutex just now, so:
	
			if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
				eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread awoken", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn));
			else
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread awoken", eb_type_str(d->type), d->net);


			pthread_mutex_unlock (&(d->qmutex_in));

		}

		new_output = 0;

		// First do a poll(0) to see if there was anything to read

		memcpy (&p, &(d->p_reset), sizeof(p));

		// To receive traffic after a poll(), must be not local, or if it is local then it's an IP gateway. Otherwise there should be no traffic arriving at all from a local, because the FS and PS put their stuff straight into the queues! // NB the while below is guarded by the if on this line, but not indented

		if (!(d->type == EB_DEF_WIRE && wire_null) && (d->type != EB_DEF_LOCAL || (d->local.ip.tunif[0] != '\0'))) while (poll(&p, 1, 0) && (p.revents & POLLIN)) // A 0-time poll() apparently works
		{

			uint8_t		packetreceived = 0; // Default state. Trunk serial receiver sets to 0 unless a whole packet has arrived

			if (d->type == EB_DEF_WIRE || (d->type == EB_DEF_TRUNK)) // Read straight to packet structure (Restrict to IP trunks)
			{

				if (!((d->type == EB_DEF_TRUNK) && !(d->trunk.hostname))) // Not a serial trunk	
				{
					length = read (l_socket, &packet, ECONET_MAX_PACKET_SIZE);
					if (length >= 12) packetreceived = 1;
				}
				else // serial trunk read procedure
				{
					packetreceived = 0; // Set this to 1 if the routine below detects end of packet

					while (!packetreceived && read(d->trunk.socket, d->trunk.serialbuf + d->trunk.serialptr, 1) > 0)
					{

						char c;

						c = *(d->trunk.serialbuf + d->trunk.serialptr);

						//fprintf (stderr, "Trunk serial ptr = %d, serial state = %02X, character read = 0x%02X\n", d->trunk.serialptr, d->trunk.serialstate, (int) c);

						if (c == 0xff)
							d->trunk.num_ffs++;
						else	d->trunk.num_ffs = 0;
					
						if (d->trunk.serialstate == TRUNK_SERIAL_IDLE && d->trunk.num_ffs == 10) // Start of packet
						{
							// Reset pointer and change state	

							d->trunk.serialptr = 0;
							d->trunk.serialstate = TRUNK_SERIAL_PACKET;
							d->trunk.num_ffs = 0;
						}
						else if (d->trunk.serialstate == TRUNK_SERIAL_PACKET && d->trunk.num_ffs == 10) // Found end of packet
						{
							packetreceived = 1;
							length = d->trunk.serialptr - 9; // serialptr starts at 0
							memcpy (&packet, d->trunk.serialbuf, length);
							d->trunk.serialptr = 0;
							d->trunk.serialstate = TRUNK_SERIAL_IDLE;
							d->trunk.num_ffs = 0;
						}
						else if (d->trunk.serialstate == TRUNK_SERIAL_9FF) // We read 9 FFs and then a 0. If this is an FF, we have zero byte insertion
						{
							if (c == 0xff)
							{
								d->trunk.serialptr--;
								*(d->trunk.serialbuf + d->trunk.serialptr) = 0xff;
								d->trunk.num_ffs = 0;
							}
							d->trunk.serialstate = TRUNK_SERIAL_PACKET;
						}
						else if (d->trunk.serialstate == TRUNK_SERIAL_PACKET && d->trunk.num_ffs == 9 && c == 0x00) // 9 FFs and this might be a zero byte insertion
						{
							d->trunk.serialstate = TRUNK_SERIAL_9FF;
							d->trunk.serialptr++;
						}
						else if (d->trunk.serialstate == TRUNK_SERIAL_PACKET) // Everything else resets num_ffs to 0
						{
							d->trunk.serialptr++;
						}
					}
				}

				if (packetreceived && (length >= 12))
				{
					eb_add_stats (&(d->statsmutex), &(d->b_out), length-12); // Interface producing outbound traffic

					if (d->type == EB_DEF_TRUNK)
					{
						packet.p.ctrl |= 0x80; // Add the top bit in - interop with bridge v2
						packet.p.srcnet = d->trunk.xlate_in[packet.p.srcnet] ? d->trunk.xlate_in[packet.p.srcnet] : packet.p.srcnet; // Inbound network translation
					}
	
					if (d->type == EB_DEF_WIRE) // Put sequence number in
					{

						// The below doesn't work - because the outbound packet will go out from 0.XX and the client will think it addressed 1.XX
						// if (packet.p.dstnet == d->net) // Local network addressed other than as 0 - correct it
							// packet.p.dstnet = 0;

						led_read.flashtime = EB_CONFIG_FLASHTIME;

						if (!EB_CONFIG_LEDS_OFF && !pthread_create(&flash_read_thread, NULL, eb_flash_led, &led_read))
							pthread_detach(flash_read_thread);

						packet.p.seq = (d->wire.seq[packet.p.srcnet][packet.p.srcstn] += 4);

						// Make the Sequence Number match if this was an immediate reply we were expecting
						if (	(packet.p.aun_ttype == ECONET_AUN_IMMREP)
						&&	(packet.p.srcnet == d->wire.last_imm_dest_net)
						&&	(packet.p.srcstn == d->wire.last_imm_dest_stn)
						)
							packet.p.seq = d->wire.last_imm_seq;


						// In all cases, if we've received *anything* off the wire, blank off those immediate trackers because either we got a reply, or we didn't and it'll never come

						d->wire.last_imm_dest_net = d->wire.last_imm_dest_stn = 0;
						d->wire.last_imm_seq = 0;
	
						pthread_mutex_lock (&(d->priority_mutex));
	
						if (packet.p.aun_ttype == ECONET_AUN_IMM) // Prioritize the reply
						{
							pthread_attr_t	attrs;
							pthread_t	sleeper;
	
							pthread_attr_init (&attrs);
							pthread_attr_setstacksize(&attrs, PTHREAD_STACK_MIN);


							d->p_net = packet.p.dstnet;
							d->p_stn = packet.p.dststn;
							d->p_seq = packet.p.seq;

							imm_sleeper = eb_malloc(__FILE__, __LINE__, "DESPATCH", "Create eb_imm_clear struct for immediate timer", sizeof(struct __eb_imm_clear));

							if (!imm_sleeper)
								eb_debug (1, 0, "DESPATCH", "Unable to malloc() immediate timer structure.");

							imm_sleeper->wire_device = d;
							imm_sleeper->p_net = d->p_net;
							imm_sleeper->p_stn = d->p_stn;
							imm_sleeper->p_seq = d->p_seq;
		
							pthread_create (&sleeper, &attrs, eb_wire_immediate_reset, imm_sleeper);
							pthread_detach (sleeper);
						}
						else
							d->p_net = d->p_stn = d->p_seq = 0; // If we've received something else on a wire, it doesn't matter if we unset this, because it means the flag fill that the ADLC has started must have ended which means it's a while since the immediate was received
			
						pthread_mutex_unlock (&(d->priority_mutex));
					}
				}
				// Otherwise ditch the runt
			}
			else if (d->type == EB_DEF_LOCAL) // Must be an IP gateway - this is tunnel interface traffic arriving (i.e. IP)
			{

				struct __econet_packet_ip	incoming;
				struct __econet_packet_aun	*outgoing;
				int 				length;

				length = read(d->local.ip.socket, &incoming, ECONET_MAX_PACKET_SIZE);

				if (length > 0)
				{
					eb_add_stats (&(d->local.ip.statsmutex), &(d->local.ip.b_in), length);
					outgoing = eb_malloc (__FILE__, __LINE__, "IPGW", "Econet AUN packet for incoming IP transmission", length + 12);
					packetreceived = 1;

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

							eb_enqueue_output (d, outgoing, length);
							new_output = 1;

							eb_free(__FILE__, __LINE__, "IPGW", "Freeing incoming IP/AUN packet after transmission on out queue", outgoing);
						}
						else // No ARP entry - send ARP query and put the packet on a queue
						{
							struct __econet_packet_aun	*arp;
							struct __eip_ip_queue		*q, *tail;

							arp = eb_malloc(__FILE__, __LINE__, "IPGW", "Outgoing Econet ARP query", 12 + 8);

							if (!arp)
								eb_debug (1, 0, "IPGW", "Unable to malloc() storage for outgoing ARP query to Econet");

							arp->p.srcnet = d->net;
							arp->p.srcstn = d->local.stn;
							arp->p.dstnet = 0xff;
							arp->p.dststn = 0xff;
							arp->p.aun_ttype = ECONET_AUN_BCAST;
							arp->p.port = 0xd2;
							arp->p.ctrl = 0xa1;

							*((uint32_t *)&(arp->p.data[4])) = incoming.destination;
							*((uint32_t *)&(arp->p.data[0])) = htonl(d->local.ip.addresses->ip);

							eb_enqueue_output (d, arp, 8);
							new_output = 1;

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
			else // Pipe, so read packet length first
			{
				int 		pipelength = 0;
				uint8_t 	c;

				read (l_socket, &c, 1); pipelength = c;
				read (l_socket, &c, 1); pipelength += c * 256;

				length = read (l_socket, &packet, pipelength);

				if (length != pipelength)
					eb_debug (0, 1, "PIPE", "Net      %3d - Incoming packet signalled as %04X long, but %04X read", d->net, pipelength, length);
				else
				{
					packetreceived = 1;

					// Insert source address

					packet.p.srcstn = d->pipe.stn;
					packet.p.srcnet = d->net;
					//packet.p.seq = (d->pipe.seq += 4); // CLient should do this... so it can track own seq
				}
			}
		
			if (packetreceived && length >= 12)	 // Should always have at the least 4 bytes of addressing and 8 bytes AUN
			{
				// Do the inbound packet dump here, before we add a network number

				eb_add_stats(&(d->statsmutex), &(d->b_out), length); // Traffic stats - local pipe producing traffic outbound to the bridge
				
				eb_dump_packet (d, EB_PKT_DUMP_PRE_I, &packet, length - 12);

				if (d->type != EB_DEF_TRUNK) // Fill in network numbers if need be
				{
					if (packet.p.srcnet == 0)	packet.p.srcnet = d->net;
					if (packet.p.dstnet == 0)	packet.p.dstnet = d->net;
				}	
	
				// Put it on an output queue here
			
				if (packet.p.aun_ttype == ECONET_AUN_BCAST) // Send to broadcast handler
					eb_broadcast_handler (d, &packet, length - 12);
				else
				{
					if (((packet.p.port == ECONET_TRACE_PORT) && eb_trace_handler (d, &packet, length - 12)) || (packet.p.port != ECONET_TRACE_PORT))
						eb_enqueue_output (d, &packet, length - 12);
				}

				// new_output = 1; // Added when output processing moved above

				eb_dump_packet (d, EB_PKT_DUMP_POST_I, &packet, length - 12);
			}
			else if (packetreceived)
			{
				if (d->type == EB_DEF_LOCAL)
					eb_debug (0, 1, "DESPATCH", "%-8s %3d.%3d Mysterious runt packet length %d arrived", eb_type_str(d->type), d->net, d->local.stn, length);
				else
					eb_debug (0, 1, "DESPATCH", "%-8s %3d     Mysterious runt packet length %d arrived", eb_type_str(d->type), d->net, length);
			}

		}

		// Then have a look at our output queues, making a note if there's AUN output pending

		wire_output_pending = aun_output_pending = 0;

		{
			struct __eb_outq	*o, *o_parent;
			struct __eb_packetqueue	*p, *pn;
			// uint8_t			processable;
			
			pthread_mutex_lock (&(d->qmutex_out));

/* This section made little or no performance difference

			o_parent = NULL;

			o = d->out;

			// Loop through output queues looking for wire traffic. If found, 
			// put it on input queues one packet per destination at a time
			// to even out performance. (If this isn't here, then what happens
			// is an entire destcombo's output queue goes on the wire input
			// queue in one hit, so that stations with higher numbered
			// station numbers end up with lower priority. When there's lots
			// of bulk transfers going on, that means that stations have to
			// really fight to get any response, and will often think they
			// have 'no reply'.)
		
			// Since the loop below will remove empty output queues etc, we
			// can skip this bit on this run. We do need to skip destination
			// devices which have gone away. (The loop below gets rid of such
			// queues for us too.)

			processable = 1; // Always do one loop through (probably 2!)

			while (o && processable)
			{

				struct __eb_packetqueue 	*this;
				struct __eb_outq		*this_o;

				if (o == d->out) // Head of queue - reset processable flag, see if it gets set on the traverse
					processable = 0; 

				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Looking at queue entry at %p - looking for wire traffic", eb_type_str(d->type), d->net, o);

				this_o = o;

				if (o->destdevice && o->destdevice->type == EB_DEF_WIRE && o->p) // NB Opposite of in the loop below - we are just looking for process-able traffic - existing destdevice of type wire with traffic on this output queue
				{

					this = o->p;

					// Take it off the queue, and free it if it was ACK or NAK that we've dropped

					o->p = this->n;

					// Move it and wake the in queue

					if ((this->p->p.aun_ttype == ECONET_AUN_ACK || this->p->p.aun_ttype == ECONET_AUN_NAK))
					{
						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Dropping packet data at %p because it is an ACK/NAK and input device %p is %s", eb_type_str(d->type), d->net, this->p, o->destdevice, eb_type_str(o->destdevice->type));
						eb_free (__FILE__, __LINE__, "Q-OUT", "Freeing packet data for ACK/NAK destined for wire destination", this->p);
					}
					else
					{
						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Moving packetqueue (%) packet at %p to destination input device %p (%s)", eb_type_str(d->type), d->net, this, this->p, o->destdevice, eb_type_str(o->destdevice->type));

						eb_enqueue_input (o->destdevice, this->p, this->length);
					}

					eb_debug (0, 4, "DESPATCH", "%-8s %3d     Freeing packetqueue at %p after move to destination input device %p (%s) (or being dropped because ACK/NAK)", eb_type_str(d->type), d->net, this, o->destdevice, eb_type_str(o->destdevice->type));
					eb_free (__FILE__, __LINE__, "Q-OUT", "Freeing packetqueue structure after transfer to wire input queue (or dropped if ACK/NAK)", this);

					if (this_o->p) // More traffic for this dest on the outq
						 processable++;
					else // Splice out this outq entry
					{
						// Splice out the parent here
			
						if (o_parent)
							o_parent->next = this_o->next;
						else	d->out = this_o->next;

						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Freeing empty outq at %p for destcombo 0x%04X after move to destination input device %p (%s)", eb_type_str(d->type), d->net, this_o, this_o->destcombo, this_o->destdevice, eb_type_str(this_o->destdevice->type));
						eb_free (__FILE__, __LINE__, "Q-OUT", "Freeing empty outq after wire traffic search", this_o);

						this_o = NULL;

						if (o_parent)
							o = o_parent->next;
						else	o = d->out;
					}
				}

				// Move to next packet


				// If the outq got spliced out above, the parent will have stayed the same and o will have been updated
				// and this_o will be NULL.

				if (this_o) // If set to NULL above, the outq was spliced, so the pointer will have been moved on for us
				{
					o_parent = this_o;
					o = this_o->next;
				}
			}

 --- END OF THE ADJUSTMENT THAT MADE LITTLE OR NO DIFFERENCE */

			o_parent = NULL;

			o = d->out;

			while (o) // Loop through our output queues
			{
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Looking at queue entry at %p", eb_type_str(d->type), d->net, o);

				if (!o->destdevice) // Destination went away - dump this queue
				{
					struct __eb_outq *n;

					eb_debug (0, 4, "DESPATCH", "%-8s %3d Output device not known - dumping this queue", eb_type_str(d->type), d->net);

					p = o->p;

					while (p)
					{
						pn = p->n;

						if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
							eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packet data at %p in packetqueue %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p->p, p);
						else
							eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing packet data at %p in packetqueue %p", eb_type_str(d->type), d->net, p->p, p);

						eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packet within packet queue - Destination device unknown", p->p);

						if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
							eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packetqueue %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p);
						else
							eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing packetqueue %p", eb_type_str(d->type), d->net, p);

						eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packetq - Destination device unknown", p);

						p = pn;
					}
					
					// If we have a parent, update it's 'next' pointer. Otherwise update d->out.

					if (o_parent)
						o_parent->next = o->next;
					else
						d->out = o->next;

					// Store away next outq in line because we're about to free this one.

					n = o->next;

					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing outq at %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), o);
					else
						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing outq at %p", eb_type_str(d->type), d->net, o);

					eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing outq when destination unknown", o);
					
					o = n; // Move to next in queue

				}
				else
				{
					if (o->p) // Traffic on output queue
					{
			
						struct __eb_packetqueue	*parent;

						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Traffic on output queue at %p", eb_type_str(d->type), d->net, o);

						p = o->p;
						parent = NULL; // Head of queue
						
						// Perhaps for Wire destinations, restrict this while loop to 1 round.
						// And flag if there's more wire traffic to go, so that we re-start
						// the loop round the output queues again until there isn't any more
						// wire traffic to send. That should intersperse things.

						while (p)
						{

							uint8_t		remove; // Whether to remove this packet - either because it's gone on an in queue, or because it was AUN and timed out
							uint8_t		packetfree; // Whether to free the packet struct. Normally we don't because it stays malloc()'d and gets passed into an input queue.

							// First, plonk in on the input queue, but only if it's not AUN (because AUN traffic goes directly from here via an exposure if there is on)

							eb_debug (0, 4, "DESPATCH", "%-8s %3d     Output queue - examining packetqueue at %p; destination device %p (%s)", eb_type_str(d->type), d->net, p, o->destdevice, eb_type_str(o->destdevice->type));

							if (p->p->p.port == 0x99 && p->p->p.aun_ttype == ECONET_AUN_DATA) // Track fileservers
								eb_mark_fileserver(p->p->p.dstnet, p->p->p.dststn);

							remove = packetfree = 0;

							if (o->destdevice->type == EB_DEF_AUN)
							{
								struct timeval	now;
								struct __eb_aun_exposure *exp;
	
								gettimeofday (&now, 0);

								eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d Last tx = %u.%u, Now = %u.%u", eb_type_str(o->destdevice->type), p->p->p.srcnet, p->p->p.srcstn, p->last_tx.tv_sec, p->last_tx.tv_usec, now.tv_sec, now.tv_usec);
								exp = eb_is_exposed (p->p->p.srcnet, p->p->p.srcstn, 1);

								if (!exp)
									packetfree = remove = 1;
		
								else if ((timediffmsec(&(p->last_tx), &now) >= EB_CONFIG_AUN_RETX) && exp && ((p->tx)++ < EB_CONFIG_AUN_RETRIES))
								{
									struct sockaddr_in	dest;

									gettimeofday (&(p->last_tx), 0);
									
									dest.sin_family	= AF_INET;
									dest.sin_port = htons(o->destdevice->aun->port);
									dest.sin_addr.s_addr = htonl(o->destdevice->aun->addr);

									p->p->p.ctrl &= 0x7f; // Strip high bit from ctrl 


									if (!((o->destdevice->config & EB_DEV_CONF_AUTOACK) && (p->p->p.aun_ttype == ECONET_AUN_ACK || p->p->p.aun_ttype == ECONET_AUN_NAK))) // Don't send ACK / NAK to AUTOACK stations because they'll already have had one
									{
										eb_dump_packet (o->destdevice, EB_PKT_DUMP_POST_O, p->p, p->length);
	
										eb_add_stats(&(o->destdevice->statsmutex), &(o->destdevice->b_in), p->length);
	
										sendto (exp->socket, &(p->p->p.aun_ttype), p->length + 8, MSG_DONTWAIT, (struct sockaddr *) &dest, sizeof(dest));
								
										if (p->p->p.aun_ttype != ECONET_AUN_DATA) // && p->p->p.aun_ttype != ECONET_AUN_IMM) // Everything else only gets a single shot tx
										{
											packetfree = remove = 1;

											if (p->n) aun_output_pending++; // We did have this as new_output = 1 at one stage, but that makes little sense. This version says there's more AUN output on the queue, so don't sleep indefinitely.
										}
										else
											aun_output_pending++; 
									}
									else	packetfree = remove = 1;

								}
								else
								{
									if (p->tx <= EB_CONFIG_AUN_RETRIES)
									{
										aun_output_pending++;

										eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d Retransmit timer for packetqueue entry %p has not expired", eb_type_str(o->destdevice->type), p->p->p.dstnet, p->p->p.dststn, p);
									}
									else
									{
										eb_dump_packet (d, EB_PKT_DUMP_DUMPED, p->p, p->length);
										packetfree = remove = 1;
									}
								}

							}
							else
							{
								// Move it and wake the in queue

								if (o->destdevice->type == EB_DEF_WIRE && (p->p->p.aun_ttype == ECONET_AUN_ACK || p->p->p.aun_ttype == ECONET_AUN_NAK))
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Dropping packetqueue at %p because it is an ACK/NAK and input device %p is %s", eb_type_str(d->type), d->net, p, o->destdevice, eb_type_str(o->destdevice->type));
								else
								{
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Moving packetqueue at %p to destination input device %p (%s)", eb_type_str(d->type), d->net, p, o->destdevice, eb_type_str(o->destdevice->type));

									eb_enqueue_input (o->destdevice, p->p, p->length);
								}

								remove = 1;
							}

							if (remove)
							{
								struct __eb_packetqueue		*n;
								// uint8_t				retry_copy, srcnet, srcstn, port;

								eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempting to splice out output packetqueue entry at %p", eb_type_str(d->type), d->net, p);

								n = p->n;

								//retry_copy = p->tx;
								//srcnet = p->p->p.srcnet;
								//srcstn = p->p->p.srcstn;
								//port = p->p->p.port;

								// Update pointer to next structure in parent
								if (parent)
									parent->n = n;
								else
									o->p = n;

								if (packetfree) // If we are dumping the entry and it hasn't gone on an input queue, we need to free the packet struct as well
								{
									if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
										eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packet data at %p in packetqueue %p within outq %p, destcombo 0x%04X", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p->p, p, o, o->destcombo);
									else
										eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing packet data at %p in packetqueue %p within outq %p, destcombo 0x%04X", eb_type_str(d->type), d->net, p->p, p, o, o->destcombo);

									eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packet data after output didn't move to input", p->p); 
								}

								if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
									eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packetqueue %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p);
								else
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing packetqueue %p", eb_type_str(d->type), d->net, p);

								eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packetq after movement to input or discard", p); // Free the packetqueue structure
	
								// Parent stays the same, p becomes what was p->n

								p = n;

								/* QUEUE DUMP SECTION FOR AUN */

								// If destination is AUN and we've exceeded max transmissions, dump any remaining outq entries from same source with same port 

/* This didn't work either for dumping an AUN queue when BeebEm gets a BREAK. Going to do paid work now.
								if (o->destdevice->type == EB_DEF_AUN && retry_copy > EB_CONFIG_AUN_RETRIES && packetfree) // Only if going to AUN, packet exceeded retries, and the code had flagged that the packet data should be freed (otherwise it must have gone somewhere, though heaven knows where)
								{
									struct __eb_packetqueue		*this, *this_n, *this_parent, *first_retained; // first_retained stores the first packetqueue we kept there on a queue dump so we can set p to it.
									
									this = p;
									this_parent = parent;
									first_retained = NULL;

									while (this)
									{
										this_n = p->n;

										if (p->p->p.srcstn == srcstn && p->p->p.srcnet == srcnet && p->p->p.port == port) // Dump this one as well
										{
											if (this_parent) // Update next pointer in parent
												this_parent->n = this_n;
											else	o->p = this_n;

											if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
												eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packet data at %p in packetqueue %p within outq %p, destcombo 0x%04X - dumping queue to AUN station", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), this->p, this, o, o->destcombo);
											else
												eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing packet data at %p in packetqueue %p within outq %p, destcombo 0x%04X - dumping queue to AUN station", eb_type_str(d->type), d->net, this->p, this, o, o->destcombo);

											eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packet data after output didn't move to input", this->p);


											if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
												 eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packetqueue %p - dumping queue to AUN station", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), this);
											else
												eb_debug (0, 4, "DESPATCH", "%-8s %3d      Despatcher thread freeing packetqueue %p - dumping queue to AUN station", eb_type_str(d->type), d->net, this);

											eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packetq after movement to input or discard", this);

											this = this_n;

										}
										else // Not dumping, move to next
										{
											if (!first_retained)	first_retained = this;
											this_parent = this;
											this = this_n;
										}
									}

									p = first_retained; // NB parent from prior to this loop/if combo will not have changed. It'll either be NULL or whatever the parent was before	

								}
								
*/


								if (!(o->p)) // Queue emptied - possibly because of routine immediately above
								{

									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Traffic queue to destcombo 0x%04X empty - freeing", eb_type_str(d->type), d->net, o->destcombo);

									if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
										eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing outq at %p after its queue emptied, parent outq at %p, next outq at %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), o, o_parent, o->next);
									else
										eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing outq at %p after its queue emptied, parent outq at %p, next outq at %p", eb_type_str(d->type), d->net, o, o_parent, o->next);

									if (o_parent)
										o_parent->next = o->next;
									else // Head of outq
										d->out = o->next;

									eb_free(__FILE__, __LINE__, "DESPATCH", "Freeing outq struct after its queue emptied", o);	
		
									if (o_parent)	o = o_parent->next;
									else		o = d->out;
								}
							}
							else
							{
								if (o->destdevice->type == EB_DEF_AUN) // One packet at a time on AUN
								{
									o_parent = o;
									o = o->next;
									p = NULL;
								}
								else
								{
									parent = p;
									p = p->n;
								}
							}

						}

					}	
					else	
					{
						o_parent = o;
						o = o->next; // Move to next output destination (done in the free procedure above if this queue was emptied)
					}

				}

			}

			eb_debug (0, 4, "DESPATCH", "%-8s %3d     Finished looking at output queues - releasing outq mutex", eb_type_str(d->type), d->net);

			pthread_mutex_unlock (&(d->qmutex_out));

		}


		// Now have a squiz at our input queue and see if there are things to send to the device...

		pthread_mutex_lock (&(d->qmutex_in));

		if (d->in) // There are input queue entries
		{
			struct __econet_packet_aun 	ack;
			struct __eb_packetqueue		*p, *parent; // Current packet being processed
			uint8_t				remove; // Whether to splice current packet off in q at end of loop
			int32_t				count;


			if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
				eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread acquiring qmutex_in for input queue traversal", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn));
			else
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread acquiring qmutex_in for input queue traversal", eb_type_str(d->type), d->net);

			count = 0;
			p = d->in;

			if (d->type == EB_DEF_LOCAL || d->type == EB_DEF_PIPE)
				eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Input queue state follows", eb_type_str(d->type),  d->net,
					(d->type == EB_DEF_LOCAL ? d->local.stn : d->pipe.stn));
			else
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Input queue state follows", eb_type_str(d->type),  d->net);

			while (p)
			{
				count++;
				if (d->type == EB_DEF_LOCAL || d->type == EB_DEF_PIPE)
					eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d %5d to %3d.%3d from %3d.%3d length 0x%04X, packetqueue @ %p", eb_type_str(d->type),  d->net,
						(d->type == EB_DEF_LOCAL ? d->local.stn : d->pipe.stn), count, p->p->p.dstnet, p->p->p.dststn, 
						p->p->p.srcnet, p->p->p.srcstn, p->length, p);
				else
					eb_debug (0, 4, "DESPATCH", "%-8s %3d     %5d to %3d.%3d from %3d.%3d length 0x%04X, packetqueue @ %p", eb_type_str(d->type),  d->net,
						count, p->p->p.dstnet, p->p->p.dststn, p->p->p.srcnet, p->p->p.srcstn, p->length,p );

				p = p->n;
			}

			// The input queuer will have put things in the right order, and stripped out ACK & NAK unless this is a 
			// Passthru device.

			p = d->in;
			parent = NULL;

			while (p)
			{
				remove = 0;
	
				ack.p.aun_ttype = ECONET_AUN_ACK; // Default; update later if not
				ack.p.dstnet = p->p->p.srcnet;
				ack.p.dststn = p->p->p.srcstn;
				ack.p.srcnet = p->p->p.dstnet;
				ack.p.srcstn = p->p->p.dststn;
				ack.p.seq = p->p->p.seq;
				ack.p.port = p->p->p.port;
				ack.p.ctrl = p->p->p.ctrl;

				if (p->p->p.port == 0x99) // Track fileservers
					eb_mark_fileserver(p->p->p.dstnet, p->p->p.dststn);

				switch (d->type)
				{
					case EB_DEF_TRUNK:
					{
						int result;
						struct __econet_packet_aun *ap;

						ap = eb_malloc(__FILE__, __LINE__, "DESPATCH", "Trunk send packet copy", p->length+12);

						if (ap) // And if !ap, just remove, below.
						{

							memcpy (ap, p->p, p->length + 12);

							ap->p.dstnet = (d->trunk.xlate_out[ap->p.dstnet] ? d->trunk.xlate_out[ap->p.dstnet] : ap->p.dstnet);

							if (d->trunk.hostname) // IP trunk
								result = sendto (d->trunk.socket, ap, p->length + 12, MSG_DONTWAIT, d->trunk.remote_host->ai_addr, d->trunk.remote_host->ai_addrlen);
							else
							{

								char	frameflag[10];
								uint16_t	counter;
								uint8_t		num_ffs;
								char		zero;

								memset (&frameflag, 0xff, 10);

								write(d->trunk.socket, frameflag, 10);

								num_ffs = 0;
							
								counter = 0;

								zero = '\0';
	
								while (counter < p->length + 12)
								{
									if (num_ffs == 9 && ap->raw[counter] == 0xff)
									{
										write(d->trunk.socket, &zero, 1);
										write(d->trunk.socket, &(ap->raw[counter]), 1);
										num_ffs = 0;
									}
									else
									{
										if (ap->raw[counter] == 0xff)	num_ffs++;
										else				num_ffs = 0;

										write(d->trunk.socket, &(ap->raw[counter]), 1);
									}
								
									counter++;
								}

								write(d->trunk.socket, frameflag, 10);

								result = p->length + 12;
							}

							eb_free (__FILE__, __LINE__, "DESPATCH", "Trunk send packet copy free", ap);
							eb_add_stats (&(d->statsmutex), &(d->b_in), p->length);

							if (result == -1)
								eb_debug (0, 1, "DESPATCH", "Trunk            Packet transmission failed to %s:%d (%s)", d->trunk.hostname, d->trunk.remote_port, strerror(errno));

							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
						}

						remove = 1;
					} break;

					case EB_DEF_WIRE:
					{

						int 		result;
						int 		err = ECONET_TX_JAMMED; // Default response
						struct timeval	start, now;
						struct __econet_packet_aun tx; // We copy the packet because it allows us not to much up the ack structure with the network address translation if there's a retransmit

						gettimeofday (&now, 0);

						memcpy (&tx, p->p, p->length + 12);

						if (tx.p.dstnet == d->net)	tx.p.dstnet = 0;
						if (tx.p.srcnet == d->net)	tx.p.srcnet = 0;

						{

							if ((p->tx)++ < EB_CONFIG_WIRE_RETRIES)
							{
								eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempting to transmit packet at pq %p, packet at %p, length 0x%04X", eb_type_str(d->type), d->net, p, p->p, p->length);

								gettimeofday(&(d->wire.last_tx), 0); // Update last transmission time

								gettimeofday(&start, 0);

								// Disagnostic dump when we were getting lots of Not Listenings!
								//if (ECONET_DEV_STATION(d->wire.stations, 5, 235))
									//eb_debug (0, 2, "BRIDGE", "5.235 in station set");
								//else	eb_debug (0, 2, "BRIDGE", "5.235 NOT IN STATION SET");
								//eb_dump_packet (d, 0xff, &tx, p->length);
								//eb_debug (0, 2, "BRIDGE", "Wire writing packet length %d", p->length + 12);
			
								led_write.flashtime = EB_CONFIG_FLASHTIME * (p->length > 4096 ? 2 : 1);

								if (!EB_CONFIG_LEDS_OFF && !pthread_create(&flash_write_thread, NULL, eb_flash_led, &led_write))
									pthread_detach(flash_write_thread);

								result = write (d->wire.socket, &tx, p->length + 12);

								eb_add_stats (&(d->statsmutex), &(d->b_in), p->length);

								err = ioctl(d->wire.socket, ECONETGPIO_IOC_TXERR);

								if (err == ECONET_TX_NOCLOCK || err == ECONET_TX_NOCOPY || err == ECONET_TX_NECOUTEZPAS) // Catches too many other errors || (result != p->length + 12))
								{
									remove = 1; // These are hard fails
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempt to transmit packet to %d.%d from %d.%d at %p FAILED (Terminal) with error 0x%02X (%s) (written: %d/%d)- attempt %d", eb_type_str(d->type), d->net, tx.p.dstnet, tx.p.dststn, tx.p.srcnet, tx.p.srcstn, p, err, econet_strtxerr(err), result, p->length + 12, p->tx);
								}
								else if (result == p->length + 12) // Only if we wrote it all correctly!
								{
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     TX started for packet at pq %p, packet at %p", eb_type_str(d->type), d->net, p, p->p);

									gettimeofday(&now, 0);

									err = ioctl(d->wire.socket, ECONETGPIO_IOC_TXERR); // Unnecessary - we've already got it, above
						
									while (
										(err == ECONET_TX_INPROGRESS || err == ECONET_TX_DATAPROGRESS)
									&&	(timediffmsec(&start, &now) < ((p->length > 4096) ? 3000 : 2500))
									)
									{
										gettimeofday(&now, 0);
										err = ioctl(d->wire.socket, ECONETGPIO_IOC_TXERR);
										//eb_debug (0, 4, "DESPATCH", "%-8s %3d     while() loop progressing for packet at pq %p, packet at %p, after %d ms err = 0x%02X", eb_type_str(d->type), d->net, p, p->p, timediffmsec(&start, &now), err);
									}
		
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     while() loop ended for packet at pq %p, packet at %p after %d ms", eb_type_str(d->type), d->net, p, p->p, timediffmsec(&start, &now));

									if (err == ECONET_TX_SUCCESS)
									{
										remove = 1;
		
	//									eb_debug (0, 1, "DEBUG", "Attempting to send ACK from %3d.%3d to %3d.%3d port &%02X seq 0x%08X", ack.p.dstnet, ack.p.dststn, ack.p.srcnet, ack.p.srcstn, ack.p.port, ack.p.seq);
	
										if (tx.p.aun_ttype == ECONET_AUN_IMM) // Record the sequence number & destination so we can match the sequence number on a reply
										{
											d->wire.last_imm_dest_net = tx.p.dstnet;
											d->wire.last_imm_dest_stn = tx.p.dststn;
											d->wire.last_imm_seq = tx.p.seq;
										}

										if (tx.p.aun_ttype == ECONET_AUN_DATA)
										{
											eb_enqueue_output (d, &ack, 0);			
											new_output = 1;
										}
		
										eb_dump_packet (d, EB_PKT_DUMP_POST_O, &tx, p->length);
					
										// This was not very effective. It caused the load to balance a bit, but there were lots of 'No reply's. if (p->n && p->n->p->p.dststn == p->p->p.dststn && p->n->p->p.dstnet == p->p->p.dstnet) usleep (10000); // Try and give someone else a chance to transmit if we have a traffic queue - 10ms

									}
									else
									{
										int aunstate;

										aunstate = ioctl(d->wire.socket, ECONETGPIO_IOC_GETAUNSTATE);

										eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempt to transmit packet to %d.%d from %d.%d at %p FAILED with error 0x%02X (%s) - attempt %d - kernel tx ptr = 0x%02X, aun_state = 0x%02X", eb_type_str(d->type), d->net, tx.p.dstnet, tx.p.dststn, tx.p.srcnet, tx.p.srcstn, p, err, econet_strtxerr(err), p->tx, (aunstate >> 16), aunstate & 0xff);
										p->errors++;	
										wire_output_pending++;

										if (p->errors > 3 && (err == ECONET_TX_NECOUTEZPAS))
											remove = 1; // Dump it - lots of errors on this
									}
								}
								else // Wrong length - try again - repeat of code above
								{
									int aunstate;

									aunstate = ioctl(d->wire.socket, ECONETGPIO_IOC_GETAUNSTATE);

									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempt to transmit packet to %d.%d from %d.%d at %p FAILED with error 0x%02X (%s) - attempt %d - kernel tx ptr = 0x%02X, aun_state = 0x%02X", eb_type_str(d->type), d->net, tx.p.dstnet, tx.p.dststn, tx.p.srcnet, tx.p.srcstn, p, err, econet_strtxerr(err), p->tx, (aunstate >> 16), aunstate & 0xff);
									p->errors++;	
									wire_output_pending++;

									if (p->errors > 3 && (err == ECONET_TX_NECOUTEZPAS))
										remove = 1; // Dump it - lots of errors on this


								}
							}
							else
							{
								remove = 1; // Dump it - too many retries
								ack.p.aun_ttype = ECONET_AUN_NAK;
								if (tx.p.aun_ttype == ECONET_AUN_DATA)
								{
									eb_enqueue_output (d, &ack, 0);
									new_output = 1;
									if (p->n)	wire_output_pending++; // There's a packet after this one
								}
							}
							
						}
						
					} break;

					case EB_DEF_LOCAL:
					{
						// Pending a better 'can I listen on this port' system, we distribute traffic
						// by port number - IPGW first, then PS, then FS gets the rest
						// Note that Bridge traffic inbound is all broadcast and is filtered at a far earlier stage

						// Always remove

						remove = 1;

						if (p->p->p.srcnet == d->net)	p->p->p.srcnet = 0;
						if (p->p->p.dstnet == d->net)	p->p->p.dstnet = 0;

						eb_add_stats (&(d->statsmutex), &(d->b_in), p->length);

						if (p->p->p.aun_ttype == ECONET_AUN_DATA)
						{
							eb_debug (0, 4, "LOCAL", "%-8s %3d.%3d from %3d.%3d attempting to send ACK from local amulator, P: &%02X, C: &%02X, Seq: 0x%08X", "Local", ack.p.dstnet, ack.p.dststn, ack.p.srcnet, ack.p.srcstn, ack.p.port, ack.p.ctrl, ack.p.seq);
							eb_enqueue_output (d, &ack, 0); // No data on this packet
							new_output = 1;
						}

						// Invite a queue for a single station if the FS has had an ACK from it
						// in case there's a load queue waiting.

/* NOt effective
						if (p->p->p.aun_ttype == ECONET_AUN_ACK && (d->local.fs.index >= 0) && fs_load_dequeue(d->local.fs.index, p->p->p.srcnet, p->p->p.srcstn))
							new_output = 1;
*/
						
						
						if (p->p->p.aun_ttype == ECONET_AUN_NAK || p->p->p.aun_ttype == ECONET_AUN_ACK) // Don't pass these to local devices
						{
			
						}
						else if (p->p->p.port == 0x00 && p->p->p.ctrl == 0x88 && p->p->p.aun_ttype == ECONET_AUN_IMM)
						{
							// Deal with machinetype queries here

							ack.p.aun_ttype = ECONET_AUN_IMMREP;
							ack.p.data[0] = ack.p.data[1] = 0xee;
							ack.p.data[2] = 2;
							ack.p.data[3] = 0;

							eb_enqueue_output (d, &ack, 4);
							new_output = 1;

						}
						else if (p->p->p.port == 0x9f) // Print server query
						{
							uint8_t		querytype;
							unsigned char	pname[7];
							uint8_t		count, found;
							struct __econet_packet_aun	*reply;
							struct __eb_printer *printer;
								
							reply = eb_malloc (__FILE__, __LINE__, "PRINTER", "Allocate status query reply packet", 18);

							if (!reply)
								eb_debug (1, 0, "PRINTER", "Unable to malloc() new printer status reply packet");

							querytype = p->p->p.data[6]; // See #defines for the types

							for (count = 0; count < 6; count++) // Copy printer name
								pname[count] = p->p->p.data[count];

							pname[6] = '\0'; // NULL terminate

							eb_debug (0, 2, "PRINTER", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s", 
								d->net, d->local.stn,
								p->p->p.srcnet, p->p->p.srcstn,	
								(querytype == PRN_QUERY_STATUS) ? "status" : "name",
								pname);

							reply->p.srcnet = d->net;
							reply->p.srcstn = d->local.stn;
							reply->p.dstnet = p->p->p.srcnet;
							reply->p.dststn = p->p->p.srcstn;
							reply->p.aun_ttype = ECONET_AUN_DATA;
							reply->p.port = 0x9e;
							reply->p.ctrl = 0x80;
							reply->p.seq = get_local_seq(d->net, d->local.stn);
							reply->p.data[0] = reply->p.data[1] = reply->p.data[2] = 0;

							if (reply->p.dstnet == 0)
								reply->p.dstnet = d->net;

							if (querytype == PRN_QUERY_STATUS)
							{
								found = 0;

								printer = d->local.printers;

								while (printer && !found)
									if (!strcasecmp(printer->acorn_name, (char *) pname) || !strcasecmp("PRINT ", (char *) pname))
										found = 1;
									else printer = printer->next;

								if (found) 
								{
									eb_enqueue_output (d, reply, 3);	
									new_output = 1;
								}
							}
							else if (querytype == PRN_QUERY_NAME)
							{
								printer = d->local.printers;

								while (printer)
								{
									snprintf ((char * restrict) &(reply->p.data[0]), 7, "%6s", printer->acorn_name);
									eb_enqueue_output (d, reply, 6);
									new_output = 1;
									printer = printer->next;
									reply->p.seq = get_local_seq(d->net, d->local.stn);
								}

							}

							eb_free (__FILE__, __LINE__, "PRINTER", "Freeing printer reply packet", reply);
						}
						else if (p->p->p.port == 0xD1) // Print server data
						{
							struct __eb_printjob	*job;
							struct __eb_printer	*printer;
							uint8_t 		found;

							printer = d->local.printers;
							found = 0;

							job = NULL;

							// First, see if this is an extant print job

							// ctrl = 0xfe/ff means new print job

							while (((p->p->p.ctrl & 0xfe) != 0x82) && !found && printer)
							{
								uint8_t		jobfound;

								jobfound = 0;
								job = printer->printjobs;

								while (!jobfound && job)
									if (job->net == p->p->p.srcnet && job->stn == p->p->p.srcstn)
										jobfound = found = 1;
									else job = job->next;

								if (!jobfound)
									printer = printer->next;
								
							}
							
							if (!job) // No job found - create a new one
							{
								char		template[128];
								int		spooldescriptor;

								strncpy (template, PRN_SPOOL_TEMPLATE, 126);

								spooldescriptor = mkstemp(template);

								if (spooldescriptor == -1)
									eb_debug (0, 1, "PRINTER", "Local    %3d.%3d Unable to make temporary print spool file for new job", d->net, d->local.stn);
								else
								{
									int		fs_activeid;
									int8_t		printerindex;
									char *		space;

									job = eb_malloc (__FILE__, __LINE__, "PRINTER", "Create new printjob", sizeof (struct __eb_printjob));

									if (!job)
										eb_debug (1, 0, "PRINTER", "Local    %3d.%3d Unable to malloc() for new printjob", d->net, d->local.stn);

									job->spoolfile = fdopen(spooldescriptor, "w");

									if (!job->spoolfile) // fdopen failed
										eb_debug (1, 0, "PRINTER", "Local    %3d.%3d Unable to obtain stream for new printjob (%s)", d->net, d->local.stn, strerror(errno));

									strncpy (job->spoolfilename, template, 126);

									job->net = p->p->p.srcnet;
									job->stn = p->p->p.srcstn;
									job->ctrlbit = (p->p->p.ctrl & 0x01) ^ 0x01; // Stores what we're expecting next time round

									fs_activeid = -1;
									printerindex = 0xff;

									if (d->local.fs.index >= 0 && (fs_activeid = fs_stn_logged_in(d->local.fs.index, (job->net == d->net ? 0 : job->net), job->stn)) != -1) // Is fileserver
									{
										fs_get_username(d->local.fs.index, fs_activeid, job->username);
										printerindex = fs_get_user_printer(d->local.fs.index, p->p->p.srcnet, p->p->p.srcstn); // Returns 0xff for not known
									}
									else	
										strcpy(job->username, "ANONYMOUS");
				
									if ((space = strchr(job->username, ' ')))
										*space = '\0';

									printer = d->local.printers;

									if (printerindex != 0xff)
										while ((printerindex-- > 0) && printer)
											printer = printer->next;	

									if (printer) // Splice this job in
									{
										job->next = printer->printjobs;
										if (job->next) job->next->parent = job;
										printer->printjobs = job;
										job->parent = NULL; // On head of queue
									}

								}
							}
					
							if (job && printer) // Only do this if there's a viable print job
							{
								struct __econet_packet_aun	*reply;

								reply = eb_malloc (__FILE__, __LINE__, "PRINTER", "Malloc() reply packet for spool data", 13);

								if (!reply)
									eb_debug (1, 0, "PRINTER", "Local    %3d.%3d Cannot malloc() print data reply packet", d->net, d->local.stn);

								reply->p.srcnet = d->net;
								reply->p.srcstn = d->local.stn;
								reply->p.dstnet = p->p->p.srcnet;
								reply->p.dststn = p->p->p.srcstn;
								reply->p.aun_ttype = ECONET_AUN_DATA;
								reply->p.port = 0xd1;
								reply->p.ctrl = p->p->p.ctrl;
								reply->p.seq = get_local_seq(d->net, d->local.stn);

								if (reply->p.dstnet == 0)
									reply->p.dstnet = d->net;

								reply->p.data[0] = p->p->p.data[0];

								if ((p->p->p.ctrl & 0x01) == job->ctrlbit)
								{

									job->ctrlbit ^= 0x01;

									fwrite (&(p->p->p.data), p->length - (((p->p->p.ctrl & 0xfe) == 0x86) ? 1 : 0), 1, job->spoolfile); // Last byte on last packet is always garbage apparently

									if ((p->p->p.ctrl & 0xfe) == 0x86) // Final packet, despatch to handler and close the printjob
									{
	
										char 	handler[128];
										char	command[512];

										if (printer->handler[0] == -'\0')
											strncpy (handler, PRN_DEFAULT_HANDLER, 126);
										else	strncpy (handler, printer->handler, 126);

	
										fclose (job->spoolfile);
		
										// Send to handler
	
										sprintf(command, "%s %d %d %d %d %s %s %s %s",
											handler,
											reply->p.srcnet,
											reply->p.srcstn,
											reply->p.dstnet,
											reply->p.dststn,
											job->username,
											printer->unix_name,
											printer->acorn_name,
											job->spoolfilename);
										
										if (!fork())
											execl ("/bin/sh", "sh", "-c", command, (char *) 0);

										eb_debug (0, 1, "PRINTER", "Local    %3d.%3d %s at %d.%d sent print job to printer %s/%s (%s)", reply->p.srcnet, reply->p.srcstn, job->username, reply->p.dstnet, reply->p.dststn, printer->acorn_name, printer->unix_name, job->spoolfilename);

										// Tidy up the structs
	
										if (job->parent)
										{
											job->parent->next = job->next;
											if (job->next)
												job->next->parent = job->parent;
										}
										else	
										{
											printer->printjobs = job->next;
											if (job->next)
												job->next->parent = NULL;
										}
										
										eb_free (__FILE__, __LINE__, "PRINTER", "Freeing completed printjob", job);
									}
								}

								eb_enqueue_output (d, reply, 1);
								new_output = 1;

							}

						}
						else if (p->p->p.port == 0xD2 && d->local.ip.tunif[0]) // IP/Econet
						{
							uint32_t src_ip, dst_ip;
						
							src_ip = *((uint32_t *) &(p->p->p.data[0]));
							dst_ip = *((uint32_t *) &(p->p->p.data[4]));

							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
							switch (p->p->p.ctrl)
							{
								case 0xA1: // Incoming ARP request
								{
									// Well, first we can update our ARP cache since we have just discovered a station (potentially)

									eb_ipgw_set_arp (d, src_ip, (p->p->p.srcnet == 0 ? d->net : p->p->p.srcnet), p->p->p.srcstn);

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
										arp_reply->p.dstnet = p->p->p.srcnet;
										arp_reply->p.dststn = p->p->p.srcstn;

										memcpy(&(arp_reply->p.data[0]), &(p->p->p.data[4]), 4);
										memcpy(&(arp_reply->p.data[4]), &(p->p->p.data[0]), 4);

										eb_debug (0, 3, "IPGW", "%-8s %3d.%3d Attempting to send ARP reply to %3d.%3d for our address",
											eb_type_str(d->type), d->net, d->local.stn, arp_reply->p.dstnet, arp_reply->p.dststn);

										eb_enqueue_output(d, arp_reply, 8);
										new_output = 1;

										eb_free(__FILE__, __LINE__, "IPGW", "Freeing ARP reply after transmission", arp_reply);
									}

									new_output = eb_ipgw_transmit (d, src_ip);

								} break;

								case 0xA2: // Incoming ARP reply
								{
									eb_ipgw_set_arp (d, src_ip, (p->p->p.srcnet == 0 ? d->net : p->p->p.srcnet), p->p->p.srcstn);
									new_output = eb_ipgw_transmit (d, src_ip);

								} break;
	
								case 0x81: // Incoming IP traffic
								{
									write(d->local.ip.socket, (char *) &(p->p->p.data), p->length);
								} break;
							}
						}
						else if (d->local.fs.index >= 0) // Must be fileserver traffic
						{

							pthread_mutex_lock(&fs_mutex);
							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
							eb_handle_fs_traffic(d->local.fs.index, p->p, p->length);

							if (fs_dequeuable(d->local.fs.index))
								fs_dequeue(d->local.fs.index); // For now. We'll adjust that to send straight out on BRIDGE_V2 later.
							fs_garbage_collect(d->local.fs.index);

							pthread_mutex_unlock(&fs_mutex);
							// Not effective fs_load_dequeue (d->local.fs.index, p->p->p.srcnet, p->p->p.srcstn); // Incase there was a load dequeue to do
							new_output = 1; // We'll guess there was a response. No harm if not
						}
						
					} break;

					case EB_DEF_PIPE:
					{
						remove = 1;

						if (p->p->p.srcnet == d->net)	p->p->p.srcnet = 0;
						if (p->p->p.dstnet == d->net)	p->p->p.dstnet = 0;

						if (p->p->p.aun_ttype == ECONET_AUN_DATA)
							eb_enqueue_output (d, &ack, 0);

						if (d->pipe.skt_write != -1) // Live writer
						{
							struct __econet_packet_pipe delivery;
							
							delivery.length_low = ((p->length + 12) & 0xff);
							delivery.length_high = (((p->length + 12) >> 8) & 0xff);
							
							memcpy (&(delivery.dststn), p->p, p->length + 12);

							write(d->pipe.skt_write, &delivery, p->length + 14); // Includes the extra two bytes
								
							eb_add_stats(&(d->statsmutex), &(d->b_in), p->length);

							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
						}
						else
							eb_debug (0, 1, "DESPATCH", "%-8s %3d.%3d Unexpected traffic to pipe whose writer socket is not open", "Pipe", d->net, d->pipe.stn);

						
						if ((!(d->config & EB_DEV_CONF_DIRECT)) && (p->p->p.aun_ttype == ECONET_AUN_DATA))
						{
							eb_enqueue_output (d, &ack, 0); // No data on this packet
							new_output = 1;
						}
					} break;

					// NB, we don't need to deal with NULL (shouldn't have an input queue)
					// Nor should we find DEF_AUN here, because all TX to them is done via exposures direct from output queue
					default: // Don't know what to do with this
					{
						if (p->p->p.aun_ttype == ECONET_AUN_DATA)
						{
							ack.p.aun_ttype = ECONET_AUN_NAK;
							eb_enqueue_output (d, &ack, 0);
							new_output = 1;
						}

						remove = 1;
					} break;
				}	
	
				// Splice out if necessary and find the next 'p'

				//eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher considering removing packet %p from input queue", eb_type_str(d->type), d->net, p);
				if (remove)
				{
					struct __eb_packetqueue 	*n;
	
					n = p->n;

					if (parent)
						parent->n = n;
					else
						d->in = n;

					eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher removing packet %p from input queue", eb_type_str(d->type), d->net, p);

					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing packet data at %p in input packetqueue %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p->p, p);
					else
						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing packet data at %p in input packetqueue %p", eb_type_str(d->type), d->net, p->p, p);

					eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packet data on removal from input queue", p->p);

					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread freeing input packetqueue %p, next is %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p, n);
					else
						eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread freeing input packetqueue %p, next is %p", eb_type_str(d->type), d->net, p, n);

					eb_free (__FILE__, __LINE__, "DESPATCH", "Freeing packetq on removal from input queue", p);

					p = n;

				}
				else
				{
					eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher left packet %p on input queue", eb_type_str(d->type), d->net, p);
					// So set p=NULL and exit the loop - don't go further down the queue!
					p = NULL;
					//parent = p;
					//p = p->n;
				}

			}

		}
		else
		{

			if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
				eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread input queue empty", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn));
			else
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread input queue empty", eb_type_str(d->type), d->net);
		}

		if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
			eb_debug (0, 4, "DESPATCH", "%-8s %3d.%3d Despatcher thread releasing qmutex_in after input queue traversal", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn));
		else
			eb_debug (0, 4, "DESPATCH", "%-8s %3d     Despatcher thread releasing qmutex_in after input queue traversal", eb_type_str(d->type), d->net);

		pthread_mutex_unlock (&(d->qmutex_in));

		// Dump output queue state

		pthread_mutex_lock (&(d->qmutex_out));

		{
			struct __eb_outq *o;
			struct __eb_packetqueue *p;

			o = d->out;

			if (o)
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Output queue dump at end of despatch loop", eb_type_str(d->type), d->net);

			while (o)
			{
				eb_debug (0, 4, "DESPATCH", "%-8s %3d     Output Queue at %p, destcombo 0x%04X", eb_type_str(d->type), d->net, o, o->destcombo);
				p = o->p;

				if (!p) eb_debug (0, 4, "DESPATCH", "%-8s %3d         No packetqueues!", eb_type_str(d->type), d->net);
				
				else
				{
					uint32_t count = 0;

					while (p)
					{
					
						eb_debug (0, 5, "DESPATCH", "%-8s %3d         Packetqueue at %p, packet at %p type 0x%02X length 0x%04X", eb_type_str(d->type), d->net, p, p->p, p->p->p.aun_ttype, p->length);
						p = p->n;
						count++;
					}

					eb_debug (0, 4, "DESPATCH", "%-8s %3d         %d packetqueue entries", eb_type_str(d->type), d->net, count);
				}

				o = o->next;

			}

		}

		pthread_mutex_unlock (&(d->qmutex_out));
	}

	return NULL;
}

/* Set a whole network of station[] values on all wire networks except the device pointed to be *src */

void eb_set_whole_wire_net (uint8_t net, struct __eb_device *src)
{

	struct __eb_device *other;

	other = devices;

	while (other)
	{
		if (other->type == EB_DEF_WIRE && other != src)
		{
			eb_debug (0, 4, "BRIDGE", "%-8s %3d     Setting station set for net %d", eb_type_str(other->type), other->net, net);
			uint8_t count; // Need to catch potential bridge 4-ways, so start at 0

			for (count = 0; count < 255; count++)
				ECONET_SET_STATION((other->wire.stations), net, count);	

			ioctl(other->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(other->wire.stations));

		}
	
		other = other->next;
	}

}

/* Put a single host in all the station[] values on all wired networks */

void eb_set_single_wire_host (uint8_t net, uint8_t stn)
{

	struct __eb_device *other;

	other = devices;

	while (other)
	{
		if (other->type == EB_DEF_WIRE)
		{
			ECONET_SET_STATION((other->wire.stations), (net == other->net) ? 0 : net, stn);	 // Listen for native net so stations can talk to it as (e.g.) 1.254 as well as 0.254 if it's on the local network (see below)

			ioctl(other->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(other->wire.stations));
		}
	
		other = other->next;
	}


}

/* Reset station[] structures in wire hosts, and the networks[] table to their initial values
   Called on a bridge reset
*/

void eb_reset_tables (void)
{

	struct __eb_device *d;

	pthread_mutex_lock (&networks_update);

	for (uint8_t n = 1; n < 255; n++)
		eb_set_exposures_inactive(n);

	memcpy (&networks, &networks_initial, sizeof(networks));

	pthread_mutex_unlock (&networks_update);

	d = devices;
	
	while (d)
	{
		if (d->type == EB_DEF_WIRE)
			memcpy (&(d->wire.stations), &(d->wire.stations_initial), sizeof (d->wire.stations));

		ioctl(d->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(d->wire.stations));
		
		d = d->next;
	}

}

/* Extract matched string from config file line
*/

char * eb_getstring (char *line, regmatch_t *m)
{

	line[m->rm_eo] = 0x00; // Null terminate the match, because we always have a space after our matches
	return (&line[m->rm_so]);

}

/* Read and execute the main bridge config
*/

int eb_readconfig(char *f)
{

	FILE 	*cfg;
	
	regex_t	r_comment,
		r_empty,
		r_wire,
		r_trunk,
		r_serialtrunk,
		r_dynamic,
		r_fileserver,
		r_printserver,
		r_printserver_user,
		r_printhandler,
		r_ipserver,
		r_pipeserver,
		r_aunmap,
		r_aunhost,
		r_exposenet,
		r_exposehost,
		r_trunk_nat,
		r_bridge_net_filter,
		r_bridge_traffic_filter,
		r_netclock,
		r_bindto;

	/* Build Regex
	*/

	if (regcomp(&r_comment, EB_CFG_COMMENT, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile comment regex");
	
	if (regcomp(&r_empty, EB_CFG_EMPTY, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile 'empty' regex");
	
	if (regcomp(&r_wire, EB_CFG_WIRE, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile wire regex");
	
	if (regcomp(&r_trunk, EB_CFG_TRUNK, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile IP trunk regex");
	
	if (regcomp(&r_serialtrunk, EB_CFG_SERIALTRUNK, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile serial trunk regex");
	
	if (regcomp(&r_dynamic, EB_CFG_DYNAMIC, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile dynamic AUN regex");
	
	if (regcomp(&r_fileserver, EB_CFG_FILESERVER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile fileserver regex");
	
	if (regcomp(&r_printserver, EB_CFG_PRINTSERVER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile printserver regex");
	
	if (regcomp(&r_printserver_user, EB_CFG_PRINTSERVER_WITHUSER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile printserver with user regex");
	
	if (regcomp(&r_printhandler, EB_CFG_PRINTHANDLER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile print handler regex");
	
	if (regcomp(&r_ipserver, EB_CFG_IPSERVER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile IP server regex");
	
	if (regcomp(&r_pipeserver, EB_CFG_PIPESERVER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile pipe server regex");
	
	if (regcomp(&r_aunmap, EB_CFG_AUNMAP, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile AUN map regex");
	
	if (regcomp(&r_aunhost, EB_CFG_AUNHOST, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile AUN host regex");
	
	if (regcomp(&r_exposenet, EB_CFG_EXPOSE_NET, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile AUN network exposure regex");
	
	if (regcomp(&r_exposehost, EB_CFG_EXPOSE_HOST, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile AUN host exposure regex");
	
	if (regcomp(&r_trunk_nat, EB_CFG_TRUNK_NAT, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile trunk NAT regex");
	
	if (regcomp(&r_bridge_net_filter, EB_CFG_BRIDGE_NET_FILTER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile bridge net filter regex");
	
	if (regcomp(&r_bridge_traffic_filter, EB_CFG_BRIDGE_TRAFFIC_FILTER, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile bridge traffic filter regex");
	
	if (regcomp(&r_netclock, EB_CFG_CLOCK, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile network clock regex");
	
	if (regcomp(&r_bindto, EB_CFG_BINDTO, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile interface bind regex");
	
	/* Open config
	*/

	cfg = fopen(f, "r");

	if (!cfg)
	{
		eb_debug (0, 0, "CONFIG", "Cannot read configuration file %s", f);
		return 0;		
	}

	while (!feof(cfg))
	{
		char		line[1024];
		regmatch_t	matches[10];
		
		if (fgets (line, 1023, cfg))
		{

			// Ditch the carriage return
			line[strlen(line)-1] = 0x00;

			if ((!regexec(&r_comment, line, 1, matches, 0)) || (!regexec(&r_empty, line, 1, matches, 0)))
			{
				// Skip
			}
			else if (!regexec(&r_wire, line, 3, matches, 0))
			{
				uint8_t			net;
				char			device[128];
				struct __eb_device	*p;
				short			c_net, c_stn;

				net = atoi(eb_getstring(line, &matches[1]));
				strncpy (device, eb_getstring(line, &matches[2]), 127);

				p = eb_device_init (net, EB_DEF_WIRE, 0);

				if ((p->wire.device = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create wire device string", strlen(device)+1)))
					strcpy(p->wire.device, device);
				else	eb_debug (1, 0, "CONFIG", "Cannot malloc space for device name for wire network %d", net);

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
				
			}
			else if (!regexec(&r_trunk, line, 3, matches, 0))
			{
				struct __eb_device	*p;
				char *			destination;
				char *			colon;

				/* Make our struct */

				p = eb_device_init (0, EB_DEF_TRUNK, 0);

				destination = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create Trunk destination host string", strlen(eb_getstring(line, &matches[2])) + 1);
				strncpy (destination, eb_getstring(line, &matches[2]), strlen(eb_getstring(line, &matches[2])) + 1);

				if (!destination)	eb_debug (1, 0, "CONFIG", "Unable to malloc() string for trunk destination %s", eb_getstring(line, &matches[2]));

				colon = strchr(destination, ':');

				if (!colon)	eb_debug (1, 0, "CONFIG", "Bad configuration line - no port specifier on trunk destination: %s", destination);
				
				*colon = '\0';

				colon++; // Now points to port

				p->trunk.local_port = atoi(eb_getstring(line, &matches[1]));
				p->trunk.remote_port = atoi(colon);
				p->trunk.hostname = destination;
				p->trunk.head = NULL;
				p->trunk.tail = NULL;
				memset (&(p->trunk.xlate_in), 0, 256);
				memset (&(p->trunk.xlate_in), 0, 256);
				memset (&(p->trunk.filter_in), 0, 256);
				memset (&(p->trunk.filter_out), 0, 256);
				
				/* Put it on our list of trunks */

				p->next = trunks; // Never sits in the devices list, because it doesn't have a network number
				trunks = p;
				
			}
/*
			else if (!regexec(&r_serialtrunk, line, 4, matches, 0))
			{

				struct __eb_device	*p;
				char *			destination;

				// Make our struct 

				p = eb_device_init (0, EB_DEF_TRUNK, 0);

				destination = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create Trunk dial string", strlen(eb_getstring(line, &matches[3])) + 1);

				if (!destination)	eb_debug (1, 0, "CONFIG", "Unable to malloc() string for trunk dialstring %s", eb_getstring(line, &matches[2]));

				strncpy (destination, eb_getstring(line, &matches[2]), strlen(eb_getstring(line, &matches[2])) + 1);

				p->trunk.local_port = 0;
				p->trunk.remote_port = 0;
				p->trunk.hostname = NULL;
				p->trunk.dialstring = destination;
				if (!strcasecmp(destination, "DIRECT"))
				{
					eb_free(__FILE__, __LINE__, "CONFIG", "Freeing trunk dial string - direct connection", destination);
					p->trunk.dialstring = NULL;
				}

				p->trunk.serialport = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create Trunk serial port storage", strlen(eb_getstring(line, &matches[1])) + 1);

				if (!(p->trunk.serialport))	eb_debug (1, 0, "CONFIG", "Unable to malloc() string for trunk serial port %s", eb_getstring(line, &matches[1]));

				strncpy (p->trunk.serialport, eb_getstring(line, &matches[1]), strlen(eb_getstring(line, &matches[1])) + 1);

				p->trunk.baudrate = atoi(eb_getstring(line, &matches[2]));

				p->trunk.head = NULL;
				p->trunk.tail = NULL;
				memset (&(p->trunk.xlate_in), 0, 256);
				memset (&(p->trunk.xlate_in), 0, 256);
				memset (&(p->trunk.filter_in), 0, 256);
				memset (&(p->trunk.filter_out), 0, 256);
				
				// Put it on our list of trunks

				p->next = trunks; // Never sits in the devices list, because it doesn't have a network number
				trunks = p;
				
			}
*/
			else if (!regexec(&r_dynamic, line, 3, matches, 0))
			{
				//printf ("Identified as dynamic - network %s flags %s\n", eb_getstring(line, &matches[1]), eb_getstring(line, &matches[2]));

				uint8_t			net;
				struct __eb_device	*p;
				uint8_t			flags = 0;
				uint8_t			stn;

				if (strcasecmp(eb_getstring(line, &matches[2]), "AUTOACK"))
					flags = EB_DEV_CONF_AUTOACK;
				
				net = atoi(eb_getstring(line, &matches[1]));

				if (networks[net])
					eb_debug (1, 0, "CONFIG", "Cannot configure net %d as dynamic station network - network already exists", net);
				
				p = eb_device_init (net, EB_DEF_NULL, flags);

				for (stn = 254; stn > 0; stn--)
				{
					struct __eb_device	*r;
					struct __eb_aun_remote	*a;
	
					//r = eb_device_init (net, EB_DEF_AUN, flags);
					r = eb_new_local (net, stn, EB_DEF_AUN);

					p->null.divert[stn] = r;

					a = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN Host structure (in NET)", sizeof(struct __eb_aun_remote));

					if (!a) eb_debug (1, 0, "CONFIG", "Unable to malloc() for remote AUN device %d.%d", net, stn);
					
					r->aun = a;

					/* Initialize the aun struct */

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

					/* Maintain our list of remote AUN hosts */

					if (aun_remotes)	a->next = aun_remotes;
					aun_remotes = a;

				}

				eb_set_whole_wire_net (net, NULL);
				
			}
			else if (!regexec(&r_fileserver, line, 3, matches, 0))
			{
				struct __eb_device	*existing;
				uint8_t			net, stn;

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for fileserver in config line %s", line);

				existing = eb_new_local (net, stn, EB_DEF_LOCAL); // Barfs and quits if cannot do this.
	
				if (!existing)	eb_debug (1, 0, "CONFIG", "Unable to create fileserver device on %d.%d", net, stn);

				if (existing->local.fs.rootpath) // Already a fileserver
					eb_debug (1, 0, "CONFIG", "Cannot create fileserver at %s - already a fileserver", eb_getstring(line, &matches[1]));

				existing->local.fs.rootpath = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create FS rootpath string", strlen(eb_getstring(line, &matches[2])) + 1);

				if (!(existing->local.fs.rootpath))
					eb_debug (1, 0, "CONFIG", "Unable to malloc() fileserver path %s\n", eb_getstring(line, &matches[2]));

				existing->local.fs.b_in = existing->local.fs.b_out = 0; // Traffic stats

				if (pthread_mutex_init(&(existing->statsmutex), NULL) == -1)
					eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for fileserver at %d.%d", net, stn);

				/* Put this in all wire station[] maps */

				eb_set_single_wire_host (net, stn);

				strncpy(existing->local.fs.rootpath, eb_getstring(line, &matches[2]), strlen(eb_getstring(line, &matches[2])) + 1);

			}
			else if (!regexec(&r_printserver, line, 4, matches, 0) || !regexec(&r_printserver_user, line, 5, matches, 0))
			{
				struct __eb_device	*existing;
				struct __eb_printer	*printer, *current_printers;
				uint8_t			net, stn;
				char			acorn_printer[7], unix_printer[128];

				strncpy (acorn_printer, eb_getstring(line, &matches[2]), 7);
				strncpy (unix_printer, eb_getstring(line, &matches[3]), 127);

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for print server in config line %s", line);

				existing = eb_new_local (net, stn, EB_DEF_LOCAL);

				if (!existing)	eb_debug (1, 0, "CONFIG", "Unable to create printserver device on %d.%d", net, stn);

				printer = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create printer struct", sizeof(struct __eb_printer));

				if (!printer)	eb_debug (1, 0, "CONFIG", "Unable to malloc() for printer on %d.%d (%s)", net, stn, acorn_printer);
				
				printer->priority = 1;
				printer->isdefault = 1;
				strcpy (printer->acorn_name, acorn_printer);
				strcpy (printer->unix_name, unix_printer);
				printer->status = PRN_IN_READY | PRN_OUT_READY;
				printer->control = PRNCTRL_DEFAULT;
				printer->printjobs = NULL;
				strcpy (printer->handler, ""); // Null handler

				/* Put this in all wire station[] maps */

				eb_set_single_wire_host (net, stn);

				if (!regexec(&r_printserver_user, line, 5, matches, 0))
					strcpy (printer->user, eb_getstring(line, &matches[4]));
				else	strcpy (printer->user, "");

				current_printers = existing->local.printers;
			
				while (current_printers && current_printers->next)
					current_printers = current_printers->next;
				
				printer->next = NULL;

				if (current_printers)
					current_printers->next = printer;
				else	existing->local.printers = printer;

			}
			else if (!regexec(&r_printhandler, line, 4, matches, 0))
			{
				uint8_t		net, stn;
				struct __eb_device	*dev;
				struct __eb_printer	*printer;

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for print handelr configuration line %s", line);

				dev = networks[net];

				if (!dev)
					eb_debug (1, 0, "CONFIG", "Cannot configure print handler on undefined station %s", eb_getstring(line, &matches[1]));

				if (dev->type != EB_DEF_WIRE && dev->type != EB_DEF_NULL)
					eb_debug (1, 0, "CONFIG", "Cannot configure print handler on station that is not a local emulator %s", eb_getstring(line, &matches[1]));

				if (dev->type == EB_DEF_WIRE)
					dev = dev->wire.divert[stn];
				else	dev = dev->null.divert[stn];

				if (dev->type != EB_DEF_LOCAL)
					eb_debug (1, 0, "CONFIG", "Cannot configure print handler on station that is not a local emulator %s", eb_getstring(line, &matches[1]));

				printer = dev->local.printers;

				while (strncasecmp(printer->acorn_name, eb_getstring(line, &matches[2]), 6) && printer)
					printer = printer->next;

				if (!printer)
					eb_debug (1, 0, "CONFIG", "Unknown printer %s on station %s - cannot set print handler", eb_getstring(line, &matches[2]), eb_getstring(line, &matches[1]));
				
				strncpy (printer->handler, eb_getstring(line, &matches[3]), 126);
				
			}
			else if (!regexec(&r_ipserver, line, 4, matches, 0))
			{
				struct __eb_device	*existing;
				char			addr[20], tunif[10];
				uint8_t			net, stn;
				struct __eip_addr	*local;
				uint8_t			ip[4];
				uint8_t			masklen;
				uint32_t		ip_host, mask_host;

				strcpy (tunif, eb_getstring(line, &matches[2]));
				strcpy (addr, eb_getstring(line, &matches[3]));

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for IP gateway in config line %s", line);

				if (sscanf(eb_getstring(line, &matches[3]), "%hhd.%hhd.%hhd.%hhd/%hhd",
					&(ip[3]), &(ip[2]), &(ip[1]), &(ip[0]), &masklen) != 5)
					eb_debug(1, 0, "CONFIG", "Bad network and/or mask for IP gateway in config line %s", line);
					
				ip_host = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];

				mask_host = 0;

				while (masklen-- > 0)
					mask_host = (mask_host >> 1) | 0x80000000;
				
				existing = eb_new_local (net, stn, EB_DEF_LOCAL);

				if (!existing)	eb_debug (1, 0, "CONFIG", "Unable to create IP server device on %d.%d", net, stn);

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

			}
			else if (!regexec(&r_pipeserver, line, 5, matches, 0))
			{

				struct __eb_device	*existing;
				uint8_t			net, stn;

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for pipe gateway in config line %s", line);

				existing = eb_new_local (net, stn, EB_DEF_PIPE);

				if (!existing)	eb_debug (1, 0, "CONFIG", "Unable to create Pipe server device on %d.%d", net, stn);

				existing->pipe.base = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create pipe base string", strlen(eb_getstring(line, &matches[2])+1));

				if (!existing->pipe.base)
					eb_debug (1, 0, "CONFIG", "Unable to malloc() for pipe filename for station %d.%d", net, stn);

				strcpy(existing->pipe.base, eb_getstring(line, &matches[2]));

				if (!strcasecmp(eb_getstring(line, &matches[3]), "passthru"))
					existing->config = EB_DEV_CONF_DIRECT;
				else	existing->config = 0;

				/* Put this in all wire station[] maps */

				eb_set_single_wire_host (net, stn);

			}
			else if (!regexec(&r_aunmap, line, 6, matches, 0))
			{

				in_addr_t	base;
				uint8_t		base_parts[4];
				uint8_t		net;
				uint8_t		stncount;
				uint16_t	port;
				uint8_t		is_fixed; // 0 = fixed port, 1 = sequential
				uint8_t		is_autoack;

				net = atoi(eb_getstring(line, &matches[1]));

				if (networks[net])
					eb_debug (1, 0, "CONFIG", "Cannot map AUN net %d - already defined as %s", net, eb_type_str(networks[net]->type));

				if (sscanf(eb_getstring(line, &matches[2]), "%hhd.%hhd.%hhd.%hhd", &base_parts[0], &base_parts[1], &base_parts[2], &base_parts[3]) != 4)
					eb_debug (1, 0, "CONFIG", "Cannot parse network address %s for AUN MAP", eb_getstring(line, &matches[2]));
				
				base = 0;

				for (uint8_t count = 0; count < 4; count++)
					base = (base << 8) | base_parts[count];

				if ((base & 0xff) != 0)
					eb_debug (1, 0, "CONFIG", "Network address %s for AUN MAP is not a network number (needs to end in 0)", eb_getstring(line, &matches[2]));

				is_fixed = 0;

				if (!strcasecmp("FIXED", eb_getstring(line, &matches[3])))
					is_fixed = 1;
			
				port = atoi(eb_getstring(line, &matches[4])); // 0 == AUTO

				is_autoack = 0;

				if (!strcasecmp("AUTOACK", eb_getstring(line, &matches[5])))
					is_autoack = 1;
		
				for (stncount = 1; stncount < 255; stncount++)
				{
					struct __eb_device 	*d;
					struct __eb_aun_remote 	*e;	

					d = eb_new_local(net, stncount, EB_DEF_AUN);

					if (!d)
						eb_debug (1, 0, "CONFIG", "Cannot create station %d.%d on AUN MAP - already exists", net, stncount);

					e = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN remote structure", sizeof(struct __eb_aun_remote));

					if (!e)
						eb_debug (1, 0, "CONFIG", "Cannot malloc() for AUN MAPped host %d.%d", net, stncount);

					e->stn = stncount;

					e->port = (port ? 
						(is_fixed ? port : (port + stncount -1))
					:	(is_fixed ? 32768 : (10000 + (net * 256) + stncount))
					);

					e->addr = base + stncount;

					e->eb_device = d; // Shouldn't this be to the network structure? CHECK

					e->is_dynamic = 0;

					e->b_in = e->b_out = 0; // Traffic stats

					if (pthread_mutex_init(&(e->statsmutex), NULL) == -1)
						eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for AUN/IP exposure at %d.%d", net, stncount);

					if (pthread_mutex_init(&(e->updatemutex), NULL) == -1)
						eb_debug (1, 0, "CONFIG", "Cannot initialize update mutex for AUN/IP exposure at %d.%d", net, stncount);

					e->next = aun_remotes;

					d->config |= (is_autoack ? EB_DEV_CONF_AUTOACK : 0);

					d->aun = e;

					aun_remotes = e;

				}

				eb_set_whole_wire_net (net, NULL);
				
			}
			else if (!regexec(&r_aunhost, line, 5, matches, 0))
			{

				struct hostent		*h;
				struct __eb_aun_remote	*e;
				struct __eb_device	*d;
				uint8_t			net, stn;

				if (sscanf(eb_getstring(line, &matches[1]), "%hhd.%hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station number %s for AUN host %s", eb_getstring(line, &matches[1]), eb_getstring(line, &matches[2]));

				h = gethostbyname2(eb_getstring(line, &matches[2]), AF_INET); // IPv4 only

				if (h)
				{
					d = eb_new_local(net, stn, EB_DEF_AUN);

					if (!d)
						eb_debug (1, 0, "CONFIG", "Can't malloc() device struct for AUN host %s", eb_getstring(line, &matches[2]));

					e = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN Remote structure", sizeof(struct __eb_aun_remote));

					if (!e)
						eb_debug (1, 0, "CONFIG", "Can't malloc() for AUN host %s", eb_getstring(line, &matches[2]));

					e->stn = stn;

					e->port = atoi(eb_getstring(line, &matches[3]));
					
					if (e->port == 0)	e->port = (10000 + (256 * net) + (stn)); // 'AUTO'

					if (!strcasecmp("AUTOACK", eb_getstring(line, &matches[4]))) // Automatic ACK
						d->config |= EB_DEV_CONF_AUTOACK;

					e->addr = ntohl(*((in_addr_t *)h->h_addr));

					e->eb_device = d; // Shouldn't this be to the network structure? CHECK

					e->is_dynamic = 0;

					e->b_in = e->b_out = 0; // Traffic stats

					if (pthread_mutex_init(&(e->statsmutex), NULL) == -1)
						eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for AUN/IP exposure at %d.%d", net, stn);

					if (pthread_mutex_init(&(e->updatemutex), NULL) == -1)
						eb_debug (1, 0, "CONFIG", "Cannot initialize update mutex for AUN/IP exposure at %d.%d", net, stn);

					e->next = aun_remotes;
					aun_remotes = e;

					d->aun = e;
					
					// The eb_new_local routine did the divert for us, on existing network if need be			

					eb_set_single_wire_host (net, stn);

				}
				else
					eb_debug (1, 0, "CONFIG", "Cannot resolve remote AUN host %s", eb_getstring(line, &matches[1]));

				//printf ("Identified as AUN Host %s, IP %s, port %s flags %s\n", eb_getstring(line, &matches[1]), eb_getstring(line, &matches[2]), eb_getstring(line, &matches[3]), eb_getstring(line, &matches[4]));
				// Refuse to map stations that are exposed to AUN
				// Put this station as a whole in the stations[] table for each wire device
				// Redirect from existing device if need be
			}
			else if (!regexec(&r_exposenet, line, 5, matches, 0))
			{
				uint8_t			net;
				struct __eb_device	*net_device;
				uint8_t			stn;
				int			port;
				char			addr[256];
				uint8_t			fixed;
				struct hostent		*h;
				in_addr_t		s_addr;
				struct __eb_aun_exposure	*dev; // Where in the chain to insert - NULL = start, anything else means 'after this one'

				net = atoi(eb_getstring(line, &matches[1]));
				if (!net)	eb_debug (1, 0, "CONFIG", "Bad network specified for exposure: config line %s", line);

				strncpy(addr, eb_getstring(line, &matches[2]), 254);

				fixed = 1; port = atoi(eb_getstring(line, &matches[4])); // Defaults

				if (!strcasecmp(eb_getstring(line, &matches[3]), "seq"))
				{
					// Sequential port number
					fixed = 0;
					if (port == 0) // Probably 'AUTO' specified in config
						port = 10000 + (net * 256);
				}
				else 
				{
					// Fixed port
					if (port == 0) // Probably 'AUTO'
						port = 32768;
				}
				
				if (strcmp(addr, "*") && !(h = gethostbyname2(addr, AF_INET))) // IPv4 Only for AUN - NB not !strcmp
					eb_debug (1, 0, "CONFIG", "Unable to resolve %s", addr);

				net_device = eb_get_network(net);

/* Commented during implementation of inactive exposures
				if (!(net_device = eb_get_network(net)))
					eb_debug (1, 0, "CONFIG", "Cannot expose network %d to AUN - network not yet configured", net);
*/

				if (!strcmp(addr, "*"))	s_addr = 0; 
				else
					s_addr = ntohl(*((in_addr_t *)h->h_addr));

				if (strcmp(addr, "*") && fixed && ((s_addr & 0xff) != 0)) // Low byte of address must be 0
					eb_debug (1, 0, "CONFIG", "Cannot expose network %d with fixed port if low byte of exposed address is non-zero: %s (%08X)", net, addr, s_addr);

				if (!strcmp(addr, "*") && fixed)
					eb_debug (1, 0, "CONFIG", "Cannot expose whole network %d on a fixed port without specifying base network ending .0", net);
				
/* COmmented during implementation of dynamic exposures

				if (net_device && ((	(net_device->type == EB_DEF_WIRE && net_device->wire.divert[stn] && net_device->wire.divert[stn]->type == EB_DEF_AUN) ||
					(net_device->type == EB_DEF_NULL && net_device->null.divert[stn] && net_device->null.divert[stn]->type == EB_DEF_AUN)	))
					eb_debug (1, 0, "CONFIG", "Cannot expose %d.%d - is a remote AUN station", net, stn);
*/

				for (stn = 254; stn > 0; stn--)	
				{
					if (eb_is_exposed (net, stn, 0)) // Barf if already exposed
						eb_debug (1, 0, "CONFIG", "Cannot expose %d.%d - already exposed", net, stn);

					// Populate

					if (fixed) s_addr = (s_addr & ~0xff) | stn;

					dev = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN Exposure structure", sizeof(struct __eb_aun_exposure));

					if (!dev) eb_debug (1, 0, "CONFIG", "Unable to create new exposure for station %d.%d", net, stn);

					if (pthread_mutex_init(&(dev->exposure_mutex), NULL) == -1)
						eb_debug (1, 0, "CONFIG", "Cannot initialize exposure control mutex for AUN/IP exposure at %d.%d", net, stn);
						
					dev->stn = stn;
					dev->net = net;
					dev->active = (net_device) ? 1 : 0; // Permanent if the network is defined; inactive otherwise
					dev->addr = s_addr;
					dev->port = port + (fixed ? 0 : stn);
					dev->socket = -1; // Init
					dev->b_in = dev->b_out = 0; // Traffic stats

					if (pthread_mutex_init(&(dev->statsmutex), NULL) == -1)
						eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for AUN/IP exposure at %d.%d", net, stn);

					if (dev->active)
					{
						dev->parent = (
							(net_device->type == EB_DEF_WIRE && net_device->wire.divert[stn] ? net_device->wire.divert[stn] :
							(net_device->type == EB_DEF_NULL && net_device->null.divert[stn] ? net_device->null.divert[stn] :
							(net_device))));
					}
					else	dev->parent = NULL;

					dev->next = exposures;
					exposures = dev;

				}
	
			}
			else if (!regexec(&r_exposehost, line, 3, matches, 0))
			{
				
				uint8_t			net, stn;
				struct __eb_device	*net_device;
				int			port;
				char			addr[256];
				in_addr_t		s_addr;
				struct hostent		*h;
				char 			*colon;
				struct __eb_aun_exposure *dev;


				if (sscanf(eb_getstring(line, &matches[1]), "%hhd.%hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station for exposure: %s", line);

				// matches2 can be either host:port or AUTO

				strcpy (addr, eb_getstring(line, &matches[2]));

				colon = strchr(addr, ':');

				if (colon) *colon = '\0';

				if (!colon)
				{
					s_addr = 0; // All interfaces
					port = atoi(addr);
					if (!port) port = (10000 + (256 * net) + stn);
				}
				else
				{
					colon++;
					if (!strcmp(addr, "*")) // All interfaces
						s_addr = 0;
					else
					{
						h = gethostbyname2(addr, AF_INET); // IPv4 only
						s_addr = ntohl(*((in_addr_t *)h->h_addr));
					}
					port = atoi(colon);
				}

				if (eb_is_exposed(net, stn, 0))
					eb_debug (1, 0, "CONFIG", "Cannot expose %d.%d - already exposed", net, stn);
					
				net_device = eb_get_network(net);

/*
				if (!(net_device = eb_get_network(net)))
					eb_debug (1, 0, "CONFIG", "Cannot expose host %d.%d to AUN - network not yet configured", net, stn);

				if (	(net_device->type == EB_DEF_WIRE && net_device->wire.divert[stn] && net_device->wire.divert[stn]->type == EB_DEF_AUN) ||
					(net_device->type == EB_DEF_NULL && net_device->null.divert[stn] && net_device->null.divert[stn]->type == EB_DEF_AUN)	)
					eb_debug (1, 0, "CONFIG", "Cannot expose %d.%d - is a remote AUN station", net, stn);

*/

				dev = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create AUN Exposure", sizeof(struct __eb_aun_exposure));

				if (!dev) eb_debug (1, 0, "CONFIG", "Unable to create new exposure device for station %d.%d", net, stn);

				if (pthread_mutex_init(&(dev->exposure_mutex), NULL) == -1)
					eb_debug (1, 0, "CONFIG", "Cannot initialize exposure control mutex for AUN/IP exposure at %d.%d", net, stn);

				if (pthread_mutex_init(&(dev->statsmutex), NULL) == -1)
					eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for AUN/IP exposure at %d.%d", net, stn);

				// Populate

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
				}
				else	dev->parent = NULL;

				if (dev->active)
					eb_debug (0, 4, "CONFIG", "EXPOSURE %3d.%3d Parent device is %p (%s)", net, stn, dev->parent, eb_type_str(dev->parent->type));
				else
					eb_debug (0, 4, "CONFIG", "EXPOSURE %3d.%3d Exposed but inactive (network unknown)", net, stn);


				dev->next = exposures;
				exposures = dev;

			}
			else if (!regexec(&r_trunk_nat, line, 4, matches, 0))
			{
				uint8_t			local_net, distant_net, found;
				uint16_t		trunk_port;
				struct __eb_device	*trunk;

				trunk_port = atoi(eb_getstring(line, &matches[1]));
				distant_net = atoi(eb_getstring(line, &matches[2]));
				local_net = atoi(eb_getstring(line, &matches[3]));

				if (!local_net || !distant_net)
					eb_debug (1, 0, "CONFIG", "Bad trunk NAT configuration %s: one or other network numbers resolves to 0.", line);

				found = 0;
				trunk = trunks;

				while (!found && trunk)
				{
					if (trunk->trunk.local_port == trunk_port)
						found = 1;
					else trunk = trunk->next;
				}
		
				if (!trunk)
					eb_debug (1, 0, "CONFIG", "Bad trunk NAT configuration %s: Trunk port number does not match a configured trunk.", line);

				trunk->trunk.xlate_out[local_net] = distant_net;
				trunk->trunk.xlate_in[distant_net] = local_net;

			}
			else if (!regexec(&r_bridge_net_filter, line, 5, matches, 0))
			{
				uint16_t	trunk_port;
				uint8_t		distant_net;
				uint8_t		drop, inbound;
				char		device[128];
				regex_t		r_wort;

				if (!strcasecmp(eb_getstring(line, &matches[1]), "DROP"))
					drop = 1;
				else	drop = 0;
				
				if (!strcasecmp(eb_getstring(line, &matches[3]), "INBOUND"))
					inbound = 1;
				else	inbound = 0;
				
				distant_net = atoi(eb_getstring(line, &matches[2]));

				strncpy (device, eb_getstring(line, &matches[4]), 126);
		
				if (regcomp(&r_wort, "(WIRE\\s+NET|TRUNK\\s+PORT)\\s+([[:digit:]]{1,5})", REG_EXTENDED | REG_ICASE) != 0)
					eb_debug (1, 0, "CONFIG", "Unable to compile wire/trunk filter regex");

				
				if (!regexec(&r_wort, device, 3, matches, 0))
				{
					trunk_port = atoi(eb_getstring(device, &matches[2]));

					if (!strcasecmp(eb_getstring(device, &matches[1]), "wire net"))
					{

						if (trunk_port && networks[trunk_port])
						{
							if (inbound)
							{
								if (distant_net)
									networks[trunk_port]->wire.filter_in[distant_net] = (drop ? 0xff : 0x00);
								else
									memset (&(networks[trunk_port]->wire.filter_in), (drop ? 0xff : 0x00), sizeof(networks[trunk_port]->wire.filter_in));
							}
							else
							{
								if (distant_net)
									networks[trunk_port]->wire.filter_out[distant_net] = (drop ? 0xff : 0x00);
								else
									memset (&(networks[trunk_port]->wire.filter_out), (drop ? 0xff : 0x00), sizeof(networks[trunk_port]->wire.filter_out));
							}
				
						}
						else
							eb_debug (1, 0, "CONFIG", "Attempt to configure bridge filter on wire net %d which is not configured", trunk_port);
							
					}
					else // Trunk
					{
						struct __eb_device 	*trunk;
						uint8_t			found;

						// Locate trunk

						found = 0;
						trunk = trunks;

						while (!found && trunk)
						{
							if (trunk->trunk.local_port == trunk_port)
								found = 1;
							else trunk = trunk->next;
						}

						if (!trunk)
							eb_debug (1, 0, "CONFIG", "Bad trunk NAT configuration %s: Trunk port number does not match a configured trunk.", line);

						if (inbound)
						{
							if (distant_net)
								trunk->trunk.filter_in[distant_net] = (drop ? 0xff : 0x00);
							else
								memset (&(trunk->trunk.filter_in), (drop ? 0xff : 0x00), sizeof(trunk->trunk.filter_in));
						}
						else
						{
							if (distant_net)
								trunk->trunk.filter_out[distant_net] = (drop ? 0xff : 0x00);
							else
								memset (&(trunk->trunk.filter_out), (drop ? 0xff : 0x00), sizeof(trunk->trunk.filter_out));
						}
						
					}
	
				}
				else	eb_debug (1, 0, "CONFIG", "Unable to work out device in line %s", line);

				regfree(&r_wort);
				
			}
			else if (!regexec(&r_bridge_traffic_filter, line, 6, matches, 0))
			{
				struct __eb_fw		*entry, *search;

				entry = eb_malloc (__FILE__, __LINE__, "CONFIG", "Create firewall struct", sizeof(struct __eb_fw));

				if (!entry)
					eb_debug (1, 0, "CONFIG", "Unable to create firewall structure for config line %s", line);

				entry->srcnet = atoi(eb_getstring(line, &matches[2]));
				entry->srcnet = (entry->srcnet ? entry->srcnet : 0xff);

				entry->srcstn = atoi(eb_getstring(line, &matches[3]));
				entry->srcstn = (entry->srcstn ? entry->srcstn : 0xff);

				entry->dstnet = atoi(eb_getstring(line, &matches[4]));
				entry->dstnet = (entry->dstnet ? entry->dstnet : 0xff);

				entry->dststn = atoi(eb_getstring(line, &matches[5]));
				entry->dststn = (entry->dststn ? entry->dststn : 0xff);

				entry->action = (!strcasecmp(eb_getstring(line, &matches[1]), "drop")) ? EB_FW_REJECT : EB_FW_ACCEPT;

				entry->next = NULL;

				search = bridge_fw;

				while (search)
					search = search->next;

				if (!search)
					bridge_fw = entry;
				else
					search->next = entry; // Put on tail

			}
			else if (!regexec(&r_netclock, line, 5, matches, 0))
			{
				double	period;
				int	mark;
				uint8_t	net;

				net = atoi(eb_getstring(line, &matches[1]));	
				period = atof(eb_getstring(line, &matches[2]));
				mark = atoi(eb_getstring(line, &matches[4]));

				if (period > 5.5 || period < 3)
					eb_debug (1, 0, "CONFIG", "Bad network clock period in line %s", line);

				if (mark > 2)
					eb_debug (1, 0, "CONFIG", "Bad network clock mark in line %s", line);

				if (!networks[net])
					eb_debug (1, 0, "CONFIG", "Cannot set network clock on net %d - network not yet defined", net);

				if (networks[net]->type != EB_DEF_WIRE)
					eb_debug (1, 0, "CONFIG", "Cannot set network clock on net %d - not defined as Econet", net);

				//fprintf (stderr, "Configuring net %d with period %f (%f) and mark %d (%d - '%s')\n", net, period, (period * 4), mark, (mark * 4), eb_getstring(line, &matches[3]));
				networks[net]->wire.period = period * 4;
				networks[net]->wire.mark = mark * 4;
					
			}
			else if (!regexec(&r_bindto, line, 2, matches, 0))
			{
				char		host[255];
				struct hostent	*h;

				strncpy (host, eb_getstring(line, &matches[1]), 254);

				h = gethostbyname2(host, AF_INET); // IPv4 only

				if (h)
				{
					bindhost = ntohl(*((in_addr_t *)h->h_addr));
				}
				else	eb_debug (1, 0, "CONFIG", "Cannot resolve IP address for host to bind to (%s) in line: %s", host, line);
			}
			else
				eb_debug (1, 0, "CONFIG", "Unrecognized configuration line: %s", line);
		}
		
	}

	fclose (cfg);

	regfree (&r_comment);
	regfree (&r_empty);
	regfree (&r_wire);
	regfree (&r_trunk);
	regfree (&r_dynamic);
	regfree (&r_fileserver);
	regfree (&r_printserver);
	regfree (&r_ipserver);
	regfree (&r_pipeserver);
	regfree (&r_aunmap);
	regfree (&r_aunhost);
	regfree (&r_exposenet);
	regfree (&r_exposehost);
	regfree (&r_trunk_nat);
	regfree (&r_bridge_net_filter);
	regfree (&r_bridge_traffic_filter);
	regfree (&r_netclock);
	regfree (&r_bindto);
	
	return 1;

}

void eb_help(char *name)
{

	fprintf (stderr, "\n\
Copyright (c) 2022 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
Usage: %s [options] \n\
Options:\n\
\n\
\t-h\t\tThis help text\n\
\n\
\t-c <path>\tUse alternative config file\n\
\t-d <path>\tSet debug file output. Will overwrite, not append\n\
\t-l\t\tDon't try to open Econet devices. IP only operation\n\
\t-n <num>\tMax data bytes in a packet dump (default 0)\n\
\t-p [iIoO]\tPacket dump - i/I: input phase, before/after NAT; o/O: output phase, likewise\n\
\t-s\t\tDump configuration at startup (repeat for extra debug)\n\
\t-z\t\tDebug Level (each occurrence increases; max 5)\n\
\n\
Queuing management options (usually need not be adjusted:\n\
\n\
--wire-max-tx n\t\tMaximum number of retransmits for wire packets (current: %d)\n\
--wire-interval n\tMinimum wait before wire retransmission of failed packet (ms) (current: %d)\n\
--wire-imm-wait n\tMaximum time (ms) to wait for an immediate reply destined for the wire (current %d)\n\
--aun-max-tx n\t\tMaximum number of retransmis for AUN packets (current: %d)\n\
--aun-interval n\tMinimum wait before AUN retransmission of unacknowledged packet (ms) (current: %d)\n\
--aun-nak-tolerance n\tNumber of AUN NAKs to tolerate before dumping packet. (Current: %d)\n\
--max-sockets n\t\tMaximum numbers of sockets that can be open (increase if system cannot do AUN listens)\n\
\t\t\t(Minimum 1. Used because sometimes RiscOS isn't listening when it should be!\n\
--flashtime n\t\tTime in ms to flash each activity LED off to show activity. (Current: %d)\n\
--led-blink-on\t\tActivity LEDs are off by default, and blink on for activity (Current: ON and blink OFF)\n\
--leds-off\t\tTurn the activity LEDs off and leave them off\n\
\n\
Statistics port control:\n\
\n\
--stats-port n\t\tTCP port number for traffic stats burst\n\
\n\
Fileserver control (global to all servers):\n\
\n\
--disable-7bitbodge\tDisable Y2K date compliance which uses an extra 3 bits for year\n\
Deep-level debugging options:\n\
\n\
--malloc-debug\t\tTurn on (very verbose) malloc()/free() debug when at loglevel 2 or above\n\
\n\
\
", name,
	EB_CONFIG_WIRE_RETRIES,
	EB_CONFIG_WIRE_RETX,
	EB_CONFIG_WIRE_IMM_WAIT,
	EB_CONFIG_AUN_RETRIES,
	EB_CONFIG_AUN_RETX,
	EB_CONFIG_AUN_NAKTOLERANCE,
	EB_CONFIG_FLASHTIME);


}

/* Main bridge
*/

int main (int argc, char **argv)
{

	int	opt;
	uint8_t	dumpconfig = 0;
	struct __eb_device *p;
	struct __eb_aun_exposure *e;
	int	optind;
	struct rlimit	max_fds;

	/* Set up some initial config
	*/

	max_fds.rlim_cur = max_fds.rlim_max = 0;

	threads_started = threads_ready = 0;

	if (pthread_mutex_init(&EB_DEBUG_MUTEX, NULL) == -1)
	{
		fprintf (stderr, "Failed to initialize even the debug mutex. Quitting.\n");
		exit (EXIT_FAILURE);
	}

	if (pthread_mutex_init(&fs_mutex, NULL) == -1)
		eb_debug (1, 0, "THREAD", "Unable to initialize fileserver mutex.");

	if (pthread_mutex_init(&ps_mutex, NULL) == -1)
		eb_debug (1, 0, "THREAD", "Unable to initialize printserver mutex.");

	if (pthread_mutex_init(&ip_mutex, NULL) == -1)
		eb_debug (1, 0, "THREAD", "Unable to initialize IP gateway mutex.");

	if (pthread_mutex_init(&threadcount_mutex, NULL) == -1)
		eb_debug (1, 0, "THREAD", "Unable to initialize threadcount mutex.");

	if (pthread_mutex_init(&port99_mutex, NULL) == -1)
		eb_debug (1, 0, "THREAD", "Unable to initialize port99 mutex.");

	EB_DEBUG_LEVEL = 0;
	gettimeofday (&(config.start), 0);
	EB_DEBUG_OUTPUT = stderr;
	EB_DEBUG_MALLOC = 0;
	EB_CONFIG_WIRE_RETX = 50;
	EB_CONFIG_AUN_RETX = 1000;  // BeebEm Seems to need quite a while - and does not like another packet turning up before it's ACKd the last one. Long timeout. If the ACK turns up, the inbound AUN listener wakes the queue anyway, so it should be fine.
	EB_CONFIG_WIRE_RETRIES = 10;
	EB_CONFIG_WIRE_IMM_WAIT = 1000; // Wait 1s before resetting ADLC from flag fill - assume immediate reply not turning up for transmission on to wire
	EB_CONFIG_AUN_RETRIES = 5;
	EB_CONFIG_AUN_NAKTOLERANCE = 2; // How many NAKs we tolerate before we dump the packet off an AUN outq. Used to appease RiscOS, which sometimes isn't listening when it should be
	EB_CONFIG_WIRE_INTERPACKETGAP = 25; // Make sure some stations are listening // Not used any more
	EB_CONFIG_AUN_NAKTOLERANCE = 2;
	EB_CONFIG_PKT_DUMP_OPTS = 0; // Nothing dumped
	EB_CONFIG_MAX_DUMP_BYTES = 0; // No data bytes dumped by default
	EB_CONFIG_LOCAL = 0; // Use econet devices
	EB_CONFIG_DYNAMIC_EXPIRY = 10; // 10 mins to expire an unused AUN station
	EB_CONFIG_STATS_PORT = 6809; // Memories of a fire-breather
	EB_CONFIG_FLASHTIME = 100; // 0.1s flash time on the Read/Write LEDs
	EB_CONFIG_BLINK_ON = 0; // LEDs are on and blink off by default
	EB_CONFIG_LEDS_OFF = 0; // Disable LEDs - turn them off at the start and don't blink them

	strcpy (config_path, "/etc/econet-gpio/econet-hpbridge.cfg");
	/* Clear networks[] table */

	memset (&networks, 0, sizeof(networks));
	memset (&networks_initial, 0, sizeof(networks_initial));

	/* Initialize other lists */

	devices = NULL;
	aun_remotes = NULL;
	bridge_fw = NULL;
	trunks = NULL;
	exposures = NULL;
	port99_list = NULL;

	strcpy (debug_path, "");

	// Turn on FS seven bit bodge - force it to be on always now.
	fs_sevenbitbodge = 1; // Make this configurable later.

	static struct option long_options[] = {
		{"wire-max-tx", 	required_argument,	0, 	0 },
		{"aun-max-tx",		required_argument,	0,	0 },
		{"wire-interval", 	required_argument, 	0, 	0 },
		{"aun-interval",	required_argument,	0, 	0 },
		{"malloc-debug",	0,			0,	0 },
		{"aun-nak-tolerance",	required_argument,	0,	0 },
		{"disable-7bitbodge",	0,			0,	0 },
		{"dynamic-expiry",	required_argument,	0,	0 },
		{"stats-port", 		required_argument, 	0, 	0 },
		{"max-sockets",		required_argument,	0,	0 },
		{"flashtime", 		required_argument,	0,	0 },
		{"led-blink-on",	0,			0,	0 },
		{"leds-off",		0,			0,	0 },
		{"normalize-debug@",	0,			0,	0 },
		{0, 			0,			0,	0 }
	};

	/* Parse command line */

	while ((opt = getopt_long(argc, argv, "hc:d:ln:p:sz", long_options, &optind)) != -1)	
	{
		switch (opt)
		{
			case 0: // Long option
			{
				switch (optind)
				{
					case 0: 	EB_CONFIG_WIRE_RETRIES = atoi(optarg); break;
					case 1:		EB_CONFIG_AUN_RETRIES = atoi(optarg); break;
					case 2:		EB_CONFIG_WIRE_RETX = atoi(optarg); break;
					case 3:		EB_CONFIG_AUN_RETX = atoi(optarg); break;
					case 4:		EB_DEBUG_MALLOC = 1; break;
					case 5:		EB_CONFIG_AUN_NAKTOLERANCE = atoi(optarg); break;
					case 6:		fs_sevenbitbodge = 0; break;
					case 7:		EB_CONFIG_DYNAMIC_EXPIRY = atoi(optarg); break;
					case 8:		EB_CONFIG_STATS_PORT = atoi(optarg); break;
					case 9:		max_fds.rlim_cur = max_fds.rlim_max = atoi(optarg); break;
					case 10:	EB_CONFIG_FLASHTIME = atoi(optarg); break;
					case 11:	EB_CONFIG_BLINK_ON = 1; break;
					case 12:	EB_CONFIG_LEDS_OFF = 1; EB_CONFIG_BLINK_ON = 1; break;
					case 13:	normalize_debug = 1; break;
				}
			} break;
			case 'c':	strncpy(config_path, optarg, 1023); break;
			case 'd':	strncpy(debug_path, optarg, 1023); break;
			case 'h':	eb_help(argv[0]); exit(EXIT_SUCCESS); break;
			case 'l':	EB_CONFIG_LOCAL = 1; break;
			case 'n':	EB_CONFIG_MAX_DUMP_BYTES = atoi(optarg); break; // Max packet dump data bytes
			case 'p':	
			{
				if (strchr(optarg, 'i'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_PRE_I;
				if (strchr(optarg, 'I'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_POST_I;
				if (strchr(optarg, 'o'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_PRE_O;
				if (strchr(optarg, 'O'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_POST_O;
			}; break;
			case 's':	dumpconfig++; break;	
			case 'z':	EB_DEBUG_LEVEL++; break;
		}
	}

	if (strlen (debug_path) > 0)
	{
		EB_DEBUG_OUTPUT = fopen(debug_path, "w");
		if (!EB_DEBUG_OUTPUT)
			fprintf (stderr, "Cannot open debug output file %s. Quitting.", debug_path);
	}
	
	if (max_fds.rlim_cur != 0) // User changed it
		setrlimit (RLIMIT_NOFILE, &max_fds);

	/* Increase core size so we can debug */

	/* Temporarily re-use max_fds */

	max_fds.rlim_cur = max_fds.rlim_max = RLIM_INFINITY;

	setrlimit (RLIMIT_CORE, &max_fds);

	/* Read config */

	if (!eb_readconfig(config_path))
		exit (EXIT_FAILURE);

	/* Now copy stations to stations_initial in each wire, and copy networks[] to networks_initial[] */

	memcpy (&networks_initial, &networks, sizeof(networks));
	
	p = devices;

	while (p)
	{
		if (p->type == EB_DEF_WIRE)
			memcpy (&p->wire.stations_initial, &p->wire.stations, sizeof(p->wire.stations));
		p = p->next;
	}

	/* Does the user want us to dump the config? */

	if (dumpconfig)
	{

		struct __eb_device *p = devices;
		struct __eb_aun_remote *r = aun_remotes;
		uint8_t		net;

		fprintf (stderr, "Net Type            Info\n");

		if (!p)	eb_debug (1, 0, "CONFIG", "No networks found.");

		//fprintf (stderr, "Packet dump options flags 0x%02X\n", EB_CONFIG_PKT_DUMP_OPTS);

		for (net = 1; net < 255; net++)
		{
			p = eb_get_network(net);

			if (p)
			{
				fprintf (stderr, "%03d %-15s %s\n", p->net, eb_type_str(p->type), 
					(p->type == EB_DEF_WIRE) ? p->wire.device : "");

				if (p->type == EB_DEF_WIRE || p->type == EB_DEF_NULL)
				{
					uint8_t			found = 0;
					uint8_t			count;
					struct __eb_aun_exposure	*exposed;
					
					for (count = 1; count < 255; count++)
					{

						exposed = eb_is_exposed (net, count, 0);

						//if ((p->type == EB_DEF_WIRE && p->wire.divert[count]) || (p->type == EB_DEF_NULL && p->null.divert[count]))
						if ((p->type == EB_DEF_WIRE) || (p->type == EB_DEF_NULL))
						{
				
							struct __eb_device	*d;
							char			info[512], tmp[128];
							uint8_t			prev_info = 0;

							d = p->type == EB_DEF_WIRE ? p->wire.divert[count] : p->null.divert[count];
							
							strcpy (info, "");

							if (d && d->type == EB_DEF_LOCAL && d->local.fs.rootpath)
							{
								sprintf (tmp, "Fileserver at %s", d->local.fs.rootpath);
								strcat (info, tmp);
								prev_info = 1;
							}
				
							if (d && d->type == EB_DEF_LOCAL && d->local.printers)
							{
								struct __eb_printer *prn = d->local.printers;
								uint8_t first = 1;

								if (prev_info) strcat(info, ", ");

								strcat(info, "Printers: ");

								while (prn)
								{
									if (!first) strcat (info, ", ");

									strcat(info, prn->acorn_name);
									if (strlen(prn->user) > 0)
									{
										strcat (info, " (");
										strcat (info, prn->user);
										strcat (info, ")");
									}
									prn = prn->next;
									first = 0;
								}
			
								prev_info = 1;

							}

							if (d && d->type == EB_DEF_LOCAL && d->local.ip.tunif[0] != '\0') // Tunnel config
							{

								if (prev_info) strcat(info, ", IP gw on ");

								strcat(info, d->local.ip.tunif);
								strcat(info, " (");
								strcat(info, d->local.ip.addr);
								strcat(info, ")");

								prev_info = 1;

							}

							if (d && d->type == EB_DEF_PIPE && d->pipe.base[0] != '\0') // Live pipe
							{
								sprintf (info, "Pipe to %s (%s)", d->pipe.base, (d->config & EB_DEV_CONF_DIRECT) ? "Passthru" : "ACK generated by pipe despatcher");
								prev_info = 1;
							}
							
							if (exposed)
							{
								char	exp_string[128];

								if (exposed->addr)
									sprintf (exp_string, "%sExposed to AUN at %d.%d.%d.%d:%d",
										(prev_info ? ", " : ""), 
										(exposed->addr & 0xff000000) >> 24,
										(exposed->addr & 0xff0000) >> 16,
										(exposed->addr & 0xff00) >> 8,
										(exposed->addr & 0xff),
										exposed->port);
								else
									sprintf (exp_string, "%sExposed to AUN on port %d",
										(prev_info ? ", " : ""), 
										exposed->port);

								strcat(info, exp_string);

							}

							if ( d && ( ( ( (d->type & 0xff00) >> 8) != EB_AUN) || ((d && d->aun->is_dynamic == 0) || dumpconfig > 2) ) )
							{
								if (!found) fprintf (stderr, "|-->Stn Type\n");

								found = 1;
	
								if (d->type == EB_DEF_AUN)
									sprintf(info, "%d.%d.%d.%d:%d",
										(d->aun->addr & 0xff000000) >> 24,
										(d->aun->addr & 0xff0000) >> 16,
										(d->aun->addr & 0xff00) >> 8,
										(d->aun->addr & 0xff),
										d->aun->port);

								fprintf(stderr, "    %03d %-11s %s\n",
									count,
									eb_type_str(d->type),
									info
								);
							}
							else if (p->type == EB_DEF_WIRE && dumpconfig > 3) // Dump every station in the device if it's wire (if it's null, it will only ever have diverts - which we deal with above)
							{

								if (!found) fprintf (stderr, "|-->Stn Type\n");

								found = 1;
	
								fprintf(stderr, "    %03d %-11s %s\n",
									count,
									eb_type_str(p->type),
									info
								);

							}
							
	
						}
					}
				}

				fprintf (stderr, "\n");

			}
		}

		if (trunks)
		{
			struct __eb_device 	*t;

			fprintf (stderr, "Known trunks\nLocal port   Hostname                       Remote Port\n");
			
			t = trunks;

			while (t)
			{

				if (t->trunk.hostname) // IP trunk
					fprintf (stderr, "%5d        %-30s %5d\n", 
						t->trunk.local_port,
						t->trunk.hostname,
						t->trunk.remote_port
					);
				else // Serial trunk
					fprintf (stderr, "            %-30s %s\n", t->trunk.serialport, t->trunk.dialstring ? t->trunk.dialstring : "Direct cable");
				
				t = t->next;
			}
			
			fprintf (stderr, "\n");

		}

		if (aun_remotes && dumpconfig > 1)
		{
			
			fprintf (stderr, "Known AUN remote machines\nNet Stn Info\n");

			while (r)
			{
				struct __eb_device	*tmp;

				tmp = (struct __eb_device *) r->eb_device;

				if (!(r->is_dynamic))
				{

					fprintf (stderr, "%3d %3d ", tmp->net, r->stn);

					fprintf (stderr, "%d.%d.%d.%d:%d\n",
					(r->addr & 0xff000000) >> 24,
					(r->addr & 0xff0000) >> 16,
					(r->addr & 0xff00) >> 8, 
					(r->addr & 0xff),
					(r->port == -1 ? 0 : r->port));
				}

				r = r->next;
			}

			fprintf (stderr, "\n");
		}
		
	}
	
	// Map check on sample config
	if (0) {
		struct __eb_device *p;

		p = devices;

		while (p)
		{
			if (p->type == EB_DEF_WIRE)
				if (ECONET_DEV_STATION((p->wire.stations),0,251))
				{
					eb_debug (0, 1, "DEBUG", "Found station 0.251 in the station map at thread %p", p);
				}

			p = p->next;
		}
	}

	/* Start the engines, captain! */

	eb_debug (0, 1, "MAIN", "Internal         Bridge to engine room: Start main engines...");

	p = devices;

	while (p)
	{
		int 	e;

		eb_debug (0, 2, "MAIN", "%-8s %3d     Starting %s despatcher thread", eb_type_str(p->type), p->net, eb_type_str(p->type));

		if ((e = pthread_create(&(p->me), NULL, eb_device_despatcher, p)))
			eb_debug (1, 0, "MAIN", "Thread creation for net %d failed: %s", p->net, strerror(e));

		pthread_detach(p->me);

		eb_thread_started();

		p = p->next;
	}

	/* Start the trunk devices */

	p = trunks;

	while (p)
	{
		int e;

		eb_debug (0, 2, "MAIN", "%-8s         Starting trunk handler thread", eb_type_str(p->type));

		if ((e = pthread_create(&(p->me), NULL, eb_device_despatcher, p)))
			eb_debug (1, 0, "MAIN", "Thread creation for trunk failed: %s", strerror(e));

		pthread_detach(p->me);

		eb_thread_started();

		p = p->next;
	}

/* OLD CODE COMMENTED OUT AFTER MOVE TO ONE-THREAD-PER-NETWORK AUN LISTENERS

	// Start the inactive AUN listeners - which won't have been started
	// by their parent devices, because they're orphans

	e = exposures;

	while (e)
	{
		int 	err;
		pthread_attr_t	attrs;

		pthread_attr_init (&attrs);
		pthread_attr_setstacksize(&attrs, 2 * PTHREAD_STACK_MIN);

		pthread_mutex_lock(&(e->exposure_mutex));

		if (!e->active)
		{
			pthread_mutex_unlock(&(e->exposure_mutex));
			if ((err = pthread_create (&(e->me), NULL, eb_aun_listener, e)))
				eb_debug (1, 0, "MAIN", "%-8s         Unable to start AUN listener for %d.%d (%s)", "", e->net, e->stn, strerror(err));

			pthread_detach (e->me);

			eb_thread_started();
		}
		else
			pthread_mutex_unlock(&(e->exposure_mutex));

		e = e->next;

	}
*/

	/* Start exposures here */

	{
		uint8_t			nets_done[8];

#define NETMAP_SET(x, y)	{ (x)[(y)/8] |= (1 << ((y) % 8)); }
#define NETMAP_ISSET(x, y)	((x)[(y)/8] & (1 << ((y) % 8)))
#define NETMAP_RESET(x)		memset(&(x), 0, sizeof((x)))

		NETMAP_RESET(nets_done);

		e = exposures;

		while (e)
		{

			if (!NETMAP_ISSET(nets_done, e->net))
			{
				NETMAP_SET(nets_done, e->net); // Flag this one as done
				pthread_create (&(e->me), NULL, eb_aun_listener, e);
				pthread_detach (e->me);
				eb_thread_started();
			}	

			e = e->next;
		}
	}

	{ // Start stats thread
		
		int err;
		pthread_t	stats;
		pthread_attr_t	attrs;

		pthread_attr_init (&attrs);
		pthread_attr_setstacksize(&attrs, PTHREAD_STACK_MIN);
	
		if ((err = pthread_create (&stats, NULL, eb_statistics, NULL)))
			eb_debug (1, 0, "MAIN", "STATS        Unable to start statistics thread");

		pthread_detach(stats);

		eb_thread_started();

	}

	/* See if all the threads are in the ready state */

	while (1)
	{
		pthread_mutex_lock (&threadcount_mutex);
	
		if (threads_started == threads_ready)
			break;

		pthread_mutex_unlock (&threadcount_mutex);

	}

	pthread_mutex_unlock (&threadcount_mutex);

	eb_debug (0, 1, "MAIN", "%-8s         Engine room to bridge: %d engines at full chat. Wait for traffic.", "Internal", threads_ready);

	{
		cpu_set_t	*cpus;
		uint8_t		num_cpus;


		num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

		cpus = eb_malloc(__FILE__, __LINE__, "THREAD", "Allocating space for CPU set", sizeof(cpu_set_t) * num_cpus);
		
		if (cpus && !pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t) * num_cpus, cpus))
		{
			uint8_t count;
			
			for (count = 0; count < num_cpus; count++)
				if (CPU_ISSET(count, cpus))	eb_debug (0, 4, "MAIN", "                 Main thread CPU affinity to CPU %d", count);
	
		}
		else	eb_debug (0, 1, "MAIN", "                 Unable to obtain CPU affinity. (Not that bothered.)");

		eb_free (__FILE__, __LINE__, "THREAD", "Freeing CPU set allocation", cpus);

	}

	/* Send a local bridge reset */

	eb_bridge_reset (NULL); // NULL indicates internal reset, rather than one received from a bridge

	/* Set up our signal handler */

	signal (SIGINT, eb_signal_handler);

	/* Now doze off */

	eb_debug (0, 2, "MAIN", "%-8s         Main loop going to sleep.", "");

	while (1)
		sleep (600); // ZZzzzzz....

}

/* Get sequence number for locally emulated station
*/

uint32_t get_local_seq (unsigned char net, unsigned char stn)
{

	struct __eb_device *network;

	if (!(network = eb_get_network(net)))
		return 0;

	// if it's a local station, it must exist as a divert in a wire or Null driver

	if (network->type != EB_DEF_NULL && network->type != EB_DEF_WIRE)
		return 0;

	if (network->type == EB_DEF_NULL)
	{
		if (!network->null.divert[stn] || network->null.divert[stn]->type != EB_DEF_LOCAL)
			return 0;
	
		return (network->null.divert[stn]->local.seq += 4);
	}
	else // Wire divert
	{
		if (!network->wire.divert[stn] || network->wire.divert[stn]->type != EB_DEF_LOCAL)
			return 0;

		return (network->wire.divert[stn]->local.seq += 4);
	}

}

/* Determine if a station is a print server
*/

struct __eb_device * is_printserver(unsigned char net, unsigned char stn)
{

	struct __eb_device 	*p, *r;

	// Is this a print server?

	if (!(p = eb_get_network(net))) // We don't even know the network
		return NULL;

	if (p->type != EB_DEF_WIRE && p->type != EB_DEF_NULL) // Not the right type of network
		return NULL;

	/* Barf if there is no diverted station entry for the station in question
	*/

	if (
		!(p->type == EB_DEF_WIRE && p->wire.divert[stn] && (r = p->wire.divert[stn]))
	&&	!(p->type == EB_DEF_NULL && p->null.divert[stn] && (r = p->null.divert[stn]))
	)
		return NULL;

	if (r->type != EB_DEF_LOCAL) // Not a local emulator
		return NULL;

	if (!(r->local.printers)) // Not a print server
		return NULL;

	return r;
}

int8_t get_printer(unsigned char net, unsigned char stn, char *pname)
{

	struct __eb_device	*p;
	struct __eb_printer	*printer;
	int8_t			count;

	p = is_printserver(net, stn);

	if (!p) return -1;

	count = 0;
	printer = p->local.printers;

	while (printer)
	{
		if (!strncasecmp(printer->acorn_name, pname, 6))
			return count;

		printer = printer->next;
		count++;
	}
	
	return -1; // Not found if we got here

}

/* Get / Set Printer Info for the Fileserver */
uint8_t get_printer_info(unsigned char net, unsigned char stn, uint8_t printer_id, char *pname, char *banner, uint8_t *control, uint8_t *status, short *user)
{

	struct __eb_device	*p;
	struct __eb_printer	*printer;
	int8_t			count;

	p = is_printserver(net, stn);

	if (!p)	return 0; // Not a print server

	count = 0;
	printer = p->local.printers;

	while (count < printer_id)
	{
		if (printer->next)
		{
			count++;
			printer = printer->next;
		}
		else	return 0; // Not found
	}

	// By here, we've found a printer.

	snprintf (pname, 7, "%6.6s", printer->acorn_name);
	snprintf (banner, 24, "%23.23s", "SystemBanner");
	*control = printer->control;
	*status = printer->status;
	*user = 0; // We need to convert the name to a userid somehow here.... ignore for now.

	return 1;
}

uint8_t set_printer_info(unsigned char net, unsigned char stn, uint8_t printer_id, char *pname, char *banner, uint8_t control, ushort user)
{

        struct __eb_device      *p;
        struct __eb_printer     *printer;
        int8_t                  count;

        p = is_printserver(net, stn);

        if (!p) return 0; // Not a print server

        count = 0;
        printer = p->local.printers;

        while (count < printer_id)
        {
                if (printer->next)
                {
                        count++;
                        printer = printer->next;
                }
                else    return 0; // Not found
        }

        // By here, we've found a printer.

	snprintf (printer->acorn_name, 7, "%6.6s", pname);
	printer->control = control;

	// Deal with user ID here...

	return 1;	

}

/* Statistics output via TCP connection */

static void * eb_statistics (void *nothing)
{

	struct sockaddr_in	server;

	int			stat_socket;
	int			optval = 1;

	// TO DO: Open a TCP listener on the socket specified in the config (default 6809)
	// When we get a connection, spit out the current stats and close.

	// Initialization section

	stat_socket = socket(AF_INET, SOCK_STREAM, 0); 

	if (stat_socket == -1)
		eb_debug (1, 0, "STATS", "                 Unable to open statistics TCP socket: %s", strerror(errno));

	if (setsockopt(stat_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1)
		eb_debug (1, 0, "STATS", "                 Unable to set SO_REUSEADDR on statistics TCP socket: %s", strerror(errno));

	memset (&server, 0, sizeof(server));

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(EB_CONFIG_STATS_PORT);

	if (bind(stat_socket, (struct sockaddr *) &server, sizeof(server)) == -1)
		eb_debug (1, 0, "STATS", "                 Unable to bind statistics TCP socket: %s", strerror(errno));

	if (listen(stat_socket, 5) == -1)
		eb_debug (1, 0, "STATS", "                 Unable to listen on statistics TCP socket: %s", strerror(errno));

	eb_thread_ready();

	eb_debug (0, 2, "STATS", "                 Statistics listener started on port %d", EB_CONFIG_STATS_PORT);
	// Listener loop

	while (1)
	{
		int 		connection;
		FILE *		output;

		struct __eb_device	*device;

		uint8_t		net;

		connection = accept(stat_socket, (struct sockaddr *) NULL, NULL);

		output = fdopen(connection, "w");

		fprintf (output, "#Pi Econet Bridge Statistics Socket\n");

		device = devices;

		while (device)
		{
			char 	trunkdest[256];

			strcpy (trunkdest, "");

			switch (device->type)
			{
				case EB_DEF_TRUNK:
					sprintf (trunkdest, "%s:%d", 
						(device->trunk.hostname ? device->trunk.hostname : device->trunk.serialport), 
						(device->trunk.hostname ? device->trunk.remote_port : device->trunk.baudrate));
					break;
				case EB_DEF_WIRE:
					sprintf (trunkdest, "%s", device->wire.device);
					break;
				case EB_DEF_NULL:
					sprintf (trunkdest, "Local null");
					break;
			}
						
			pthread_mutex_lock (&(device->statsmutex));

			fprintf (output, "%03d|000|%s|%s|%llu|%llu\n",	device->net, eb_type_str(device->type), 
				trunkdest,
				device->b_in, device->b_out);
		
			pthread_mutex_unlock (&(device->statsmutex));

			if (device->type == EB_DEF_NULL || device->type == EB_DEF_WIRE)
			{

				for (uint8_t stn = 1; stn < 255; stn++)
				{
					struct __eb_device	*divert;

					divert = NULL;

					if (device->type == EB_DEF_NULL && device->null.divert[stn])
						divert = device->null.divert[stn];
					else if (device->type == EB_DEF_WIRE && device->wire.divert[stn])
						divert = device->wire.divert[stn];

					if (divert)
					{
						uint8_t stn;

						char info[128];

						strcpy (info, "");

						switch (divert->type)
						{
							case EB_DEF_AUN:	stn = divert->aun->stn; if (divert->aun->port == -1) sprintf (info, "Inactive"); else sprintf(info, "%08X:%d", divert->aun->addr, divert->aun->port); break;
							case EB_DEF_LOCAL:	stn = divert->local.stn; sprintf(info, "%c%c%c", ((divert->local.printers) ? 'P' : ' '),
								((divert->local.fs.index >= 0) ? 'F' : ' '),
								((divert->local.ip.tunif[0] != '\0') ? 'I' : ' ')); break;
							case EB_DEF_PIPE:	stn = divert->pipe.stn; sprintf(info, "%s", divert->pipe.base); break;
							default:		stn = 0; break;
						}
	
						pthread_mutex_lock (&(divert->statsmutex));

						fprintf (output, "%03d|%03d|%s|%s|%llu|%llu\n",	divert->net, stn, eb_type_str(divert->type), info, divert->b_in, divert->b_out);
		
						pthread_mutex_unlock (&(divert->statsmutex));
					}
				}						
			}

			device = device->next;

		}

		device = trunks;

		while (device)
		{

			pthread_mutex_lock (&(device->statsmutex));

			fprintf (output, "999|000|Trunk|%s:%d|%llu|%llu\n",	(device->trunk.hostname ? device->trunk.hostname : device->trunk.serialport), (device->trunk.hostname ? device->trunk.remote_port : device->trunk.baudrate), device->b_in, device->b_out);
		
			pthread_mutex_unlock (&(device->statsmutex));

			device = device->next;
		}

		// And now the rest of the networks which are via other devices

		for (net = 1; net < 255; net++)
		{
			struct __eb_device *device;

			char 	trunkdest[256];

			device = eb_get_network(net);

			if (device && (device->net != net)) // Display
			{

				strcpy (trunkdest, "");

				switch (device->type)
				{
					case EB_DEF_TRUNK:
						sprintf (trunkdest, "%s:%d", 
							(device->trunk.hostname ? device->trunk.hostname : device->trunk.serialport), 
							(device->trunk.hostname ? device->trunk.remote_port : device->trunk.baudrate));
						break;
					case EB_DEF_WIRE:
						sprintf (trunkdest, "%s", device->wire.device);
						break;
					case EB_DEF_NULL:
						sprintf (trunkdest, "Local null");
						break;
				}
							
				pthread_mutex_lock (&(device->statsmutex));
	
				fprintf (output, "%03d|%03d|%s|%s|%llu|%llu\n",	net, (device->type == EB_DEF_TRUNK && (device->trunk.xlate_out[net])) ? device->trunk.xlate_out[net] : net, eb_type_str(device->type), 
					trunkdest,
					device->b_in, device->b_out);
			
				pthread_mutex_unlock (&(device->statsmutex));
	
			}
		}

		fclose(output);
		
	}

	return NULL;
	

}
