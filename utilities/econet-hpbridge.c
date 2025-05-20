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

// #define IPV6_TRUNKS

#define EB_JSONCONFIG
#define _GNU_SOURCE

#include "econet-hpbridge.h"
#include "econet-pserv.h"
#include "econet-fs-hpbridge-common.h"
#include "fs.h"

#ifdef EB_JSONCONFIG
#include "json.h"
#endif

extern int h_errno;

extern uint8_t fs_get_maxdiscs();

extern short fs_sevenbitbodge;
extern short normalize_debug;
extern uint8_t fs_set_syst_bridgepriv;

char	tar_path[PATH_MAX];

uint32_t	interface_index = 0x1000; // Used for loop detection
uint32_t	last_root_id_seen = 0xFFFFFFFF; // See header
time_t		when_root_id_seen = 0;
uint32_t	loopdetect_hostdata; // See header
pthread_t	loopdetect_thread;
pthread_mutex_t	loopdetect_mutex;
void *		eb_loopdetect_thread(void *);

// Some globals

char	hostname[255];

uint8_t	dumpconfig = 0;

in_addr_t 	bindhost = 0; // IP to bind to if specified. Only used for trunks at the moment.
#ifdef IPV6_TRUNKS
struct addrinfo	*trunk_bindhosts; // For when we entertain IPv6
#endif

//struct __eb_fw *bridge_fw; // Bridge-wide firewall policy
struct __eb_fw_chain	*bridge_fw; // Bridge-wide firewall policy

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
struct __eb_device	*multitrunks; // List of multitrunks.
struct __eb_interface_group	*interface_groups; // List of interface groups or NULL
struct __eb_pool	*pools; // List of pool definitions
struct __eb_fw_chain	*fw_chains; // List of firewall chains

uint16_t		threads_started, threads_ready;

pthread_mutex_t		threadcount_mutex; // Locks the thread counter

/* Moved to header 
#define eb_thread_started() { pthread_mutex_lock(&threadcount_mutex); threads_started++; pthread_mutex_unlock(&threadcount_mutex); }
#define eb_thread_ready() { pthread_mutex_lock(&threadcount_mutex); threads_ready++; pthread_mutex_unlock(&threadcount_mutex); }
*/
	
#define eb_update_lastrx(d) { pthread_mutex_lock(&(d->statsmutex)); d->last_rx = time(NULL); pthread_mutex_unlock(&(d->statsmutex)); }

pthread_mutex_t         networks_update; // Must acquire before changing/reading networks[] array

pthread_mutex_t		fs_mutex, ps_mutex, ip_mutex; // Mutexes (mutices?) for ensuring only one thread talks to a FS, PS, or IPS at the same time

uint8_t eb_assume_true_aun = 0;         // If 1, will assume that if we don't have a route to network numbers 128+, then we should try addressing the AUN packet to... where? (Not implemented yet.)

struct __eb_config	config; // Holds bridge-wide config information

char	debug_path[1024]; 	// Filename to dump debug to

/* Bridge internal sequence number */

uint32_t	bridgewide_seq = 0x4000;

/* Some function defines - but not all of them because I couldn't be bothered */

// Now in the header: uint8_t eb_enqueue_input (struct __eb_device *, struct __econet_packet_aun *, uint16_t);
void eb_set_whole_wire_net (uint8_t, struct __eb_device *);
void eb_set_single_wire_host (uint8_t, uint8_t);
void eb_clr_single_wire_host (uint8_t, uint8_t);
void eb_setclr_single_wire_host (uint8_t, uint8_t, uint8_t);
void eb_clear_zero_hosts (struct __eb_device *);
uint8_t eb_firewall (struct __eb_fw_chain *, struct __econet_packet_aun *);
void eb_reset_tables(void);
// void eb_debug (uint8_t, uint8_t, char *, char *, ...);
uint32_t eb_get_local_seq (struct __eb_device *);
static void * eb_statistics (void *);
static void * eb_fs_statistics (void *);
extern void fs_dump_handle_list (FILE *, int);
struct __eb_fw_chain * eb_get_fw_chain_byname (char *);

unsigned char beebmem[65536];

/* Define for structure passed to bridge update/reset threads */

struct __eb_update_info {
	struct __eb_device	*trigger, *dest;
	uint8_t			ctrl, sender_net;
};

/* Some defines for the FAST handler */
#define EB_FAST_LOGON 0
#define EB_FAST_READY 1
#define EB_FAST_CLOSE 2
#define EB_FAST_NOTREADY 3

void eb_exit_cleanup(void)
{

	// Remove any IP addresses / tunnel interfaces we may have created

}

void eb_signal_handler (int sig)
{

	switch (sig)
	{

		case SIGINT:
			eb_exit_cleanup();
			signal(SIGINT, SIG_DFL);
			raise(SIGINT);
			break;
		case SIGUSR1:
			EB_DEBUG_LEVEL = (EB_DEBUG_LEVEL == 5 ? 5 : EB_DEBUG_LEVEL+1);
			break;
		case SIGUSR2:
			EB_DEBUG_LEVEL = (EB_DEBUG_LEVEL == 0 ? 0 : EB_DEBUG_LEVEL-1);
			break;
		default: // Do nothing
			break;

	}


}

#if 0
/* Config file path */

char	config_path[1024];
#endif

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
		case EB_MULTITRUNK: return (char *)"M-Trunk"; break;
		case EB_PIPE: return (char *)"Pipe"; break;
		case EB_LOCAL: return (char *)"Local"; break;
		case EB_AUN: return (char *)"AUN"; break;
		case EB_NULL: return (char *)"Virtual"; break;
		case EB_POOL: return (char *)"Pool"; break;
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

	fprintf (EB_DEBUG_OUTPUT, "[+%15.6f] %7ld %-8s: %s\n", timediffstart(), syscall(SYS_gettid), module, formatted);
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
 * Both these *were* static inline, but changed to support FS
*/

void eb_free (char *file, int line, char *module, char *purpose, void *ptr)
{

	if (EB_DEBUG_MALLOC)
		eb_debug (0, 2, "MEM MGT", "%-8s         %s:%d freeing %p for purpose %s", module, file, line, ptr, purpose);

	free (ptr);

}

void * eb_malloc (char *file, int line, char *module, char *purpose, size_t size)
{

	void *r;
	//int	res;

	/*
	  if (EB_DEBUG_MALLOC)
		eb_debug (0, 2, "MEM MGT", "%-8s         %s:%d seeking malloc(%d) for purpose %s", module, file, line, size, purpose);
		*/

	r = calloc(1, size);
	//r = malloc(size);

	/* res = posix_memalign(&r, 256, size); */
	if (EB_DEBUG_MALLOC)
		eb_debug (0, 2, "MEM MGT", "%-8s         %s:%d sought  malloc(%d) for purpose %s (r = %p)", module, file, line, size, purpose, r);
	/*
	if (res == 0) // Success
		return r;
	else	return NULL;
	*/

	// memset(r, 0, size); // Zero everything out - Now done using calloc() 

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

/*
 *
 * POOL ADDRESS HANDLERS
 *
 */

#define EB_POOL_SET_STN_MAP(m,s) (m)[(s)/32] |= (1 << ((s) & 0x07))
#define EB_POOL_CLR_STN_MAP(m,s) (m)[(s)/32] &= ~(1 << ((s) & 0x07))
#define EB_POOL_IS_MAPPED(m,s) ((m)[(s)/32] & (1 << ((s) & 0x07)))

// Find new dynamic station number in a pool.
// Do not call this unless you have locked the pool updatemutex!
// Returns 1 on success, 0 on failure (nothing available)

uint8_t eb_pool_get_dynamic (struct __eb_pool *pool, uint8_t *net, uint8_t *stn)
{

	uint8_t	net_search, net_start;
	uint16_t net_loop; // Needs 16 bits otherwise the for() loop goes bonkers

	*net = *stn = 0; // Rogue. We fill these in on success

	eb_debug (0, 3, "POOL", "%-16s eb_pool_get_dynamic() called for pool %p", "", pool);

	if (!pool) return 0; // Bad pool

	net_start = pool->last_net + 1; // Works because initial rogue is 0

	/* If net_start is not in the pool, loop round until we find one that is. Since net_start is uint8_t this should be fine */

	while (!pool->networks[net_start++]);

	eb_debug (0, 3, "POOL", "%-16s eb_pool_get_dynamic() called for pool %p net_start = %d", "", pool, net_start);
	
	for (net_loop = 0; net_loop <= 255; net_loop++)
	{
		uint8_t	stations[32]; // Bitmap, 1 bit per host
		uint8_t	stn_count;

		struct __eb_pool_host *host;

		net_search = (net_start + net_loop) & 0xff;
		//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - searching net %3d", net_search);

		if (net_search == 0 || net_search == 255)
			continue;

		memset(&stations, 0, sizeof(stations));

		if (!(pool->networks[net_search]))
		{

			//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - searching net %3d - not in pool", net_search);

			continue; //  Network is not in this pool
		}

		eb_debug (0, 3, "POOL", "eb_pool_get_dynamic - searching net %3d (deep search)", net_search);

		host = pool->hosts_net[net_search];

		while (host)
		{
			//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - searching net %3d - flag stn %3d as in use", net_search, host->stn);
			EB_POOL_SET_STN_MAP(stations, host->stn);
			host = host->next_net;
		}

		for (stn_count = 1; stn_count < 255; stn_count++)
		{
			//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - searching net %3d - examining stn %3d to see if in use", net_search, stn_count);
			if (!(EB_POOL_IS_MAPPED(stations, stn_count))) // This station wasn't found
			{
				//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - searching net %3d - allocating stn %3d as free", net_search, stn_count);
				*net = net_search;
				*stn = stn_count;
				pool->last_net = net_search;
				return 1;
			}
			//else
				//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - searching net %3d - flagging stn %3d as NOT free", net_search, stn_count);
		}
	}
	//eb_debug (0, 2, "POOL", "eb_pool_get_dynamic - nothing free");
	return 0;
}

// Find an existing pool entry from a net.stn pair
// If source is not null, then it's a source device struct, so the match is on
// (source device, source net, source stn - i.e. the distant, original end)
// Otherwise net.stn are a pool address and we're looking by reference to that
// NULL return is not found; else return address of pool host object
// Must be called with pool updatemutex locked

struct __eb_pool_host *eb_pool_find_addr (struct __eb_pool *pool, uint8_t net, uint8_t stn, struct __eb_device *source)
{

	uint8_t		net_search;
	struct __eb_pool_host	*ret;
	struct timeval	now;

	if (!pool)	return NULL; // Can't search a null pool.

	gettimeofday(&now, 0);

	ret = NULL;

	for (net_search = (source ? 1 : net); net_search <= (source ? 254 : net); net_search++) // Connive to only search the relevant net if we are searching for a pool address
	{
		struct __eb_pool_host	*h;

		h = pool->hosts_net[net_search];

		while (!ret && h)
		{

			// Ignore non-static inactive maps - Splice out elsewhere because the device might or might not be locked here; all we mandate is that the *pool* updatemutex is locked. We might, for example, not know which device the thing is on and there's a risk of deadlock if we try to lock the device here.

			if ((h->is_static) || (timediffmsec(&(h->last_traffic), &now) <= (EB_CONFIG_POOL_DEAD_INTERVAL * 1000)))
			{

				if (
					(source && h->source == source && h->s_net == net && h->s_stn == stn)
				||	(!source && h->net == net && h->stn == stn)
				)
					ret = h;
				else
					h = h->next_net;
			}
			else
				h = h->next_net;
		}

		if (ret)
			return ret;
	}

	return NULL; // Not found

}

// Find an existing pool entry for net.stn pair and impose the mutex locks first 
// This just calls the function above with a lock/unlock wrapper.

struct __eb_pool_host *eb_pool_find_addr_lock (struct __eb_pool *pool, uint8_t net, uint8_t stn, struct __eb_device *source)
{

	struct __eb_pool_host 	*ret;

	pthread_mutex_lock(&(pool->updatemutex));

	ret = eb_pool_find_addr (pool, net, stn, source);

	pthread_mutex_unlock(&(pool->updatemutex));

	return ret;

}

char *eb_pool_err (uint8_t err)
{

	switch (err)
	{
		case 0: return (char *)"Success"; break;
		case 1: return (char *)"malloc() error"; break;
		case 3: return (char *)"No pool on source device"; break;
		case 4: return (char *)"Source device inapposite"; break;
		case 5: return (char *)"Static network not part of pool"; break;
		case 6: return (char *)"Pool exhausted"; break;
		default: return (char *)"Unspecified error"; break;
	}

}

// Create either static or dynamic pool host object. Crate if it doesn't exist.
// Either way, return the address of the object.

struct __eb_pool_host *eb_find_make_pool_host (struct __eb_device *source,
			uint8_t s_net, uint8_t s_stn,
			uint8_t p_net, uint8_t p_stn, // only relevant if is_static is set
			uint8_t is_static, // Create new static
			uint8_t *err)	// 0 if successful (created or exists)
					// 1 can't malloc - not used - will kill the bridge
					// 3 no pool assigned to source device
					// 4 Source device is neither trunk nor wire
					// 5 Selected static network not in pool
					// 6 No addresses available
					// 255 Unspecified failure (i.e. a cockup)
{

	struct __eb_pool	*pool;
	struct __eb_pool_host	*host;
	uint8_t			new_net, new_stn; // Address to put in new host entry

	*err = 255; // Default
	
	if (source->type == EB_DEF_TRUNK)
		pool = source->trunk.pool;
	else if (source->type == EB_DEF_WIRE)
		pool = source->wire.pool;
	else
	{
		*err = 4;
		return NULL;
	}

	if (!pool)
	{
		*err = 3;
		return NULL;
	}

	// Even in config mode, the pool and source should already exist and should
	// have had their update mutexes initialized

	pthread_mutex_lock(&(pool->updatemutex)); // Because we're going to tinker with it, and search it...

	if ((host = eb_pool_find_addr(pool, s_net, s_stn, source))) // Exists - return it
	{
		pthread_mutex_unlock(&(pool->updatemutex));
		*err = 0;
		return host;
	}

	if (is_static) // Create new static entry
	{
		if (!(pool->networks[p_net]))
		{
			pthread_mutex_unlock(&(pool->updatemutex));
			*err = 5;
			return NULL;
		}
		new_net = p_net;
		new_stn = p_stn;
	}
	else // Find a vacant station number
	{
		eb_debug (0, 2, "POOL", "%-8s %3d.%3d Searching for new translation for %s %d",
			"Pool",
			s_net, s_stn,
			eb_type_str(source->type),
			(source->type == EB_DEF_TRUNK ? source->trunk.local_port : source->net));
		if (!eb_pool_get_dynamic(pool, &new_net, &new_stn))
		{
			pthread_mutex_unlock(&(pool->updatemutex));
			*err = 6;
			return NULL;
		}
		eb_debug (0, 2, "POOL", "%-8s %3d.%3d New pool nat translation on %s %d to pool address %d.%d",
			"Pool",
			s_net, s_stn,
			eb_type_str(source->type),
			(source->type == EB_DEF_TRUNK ? source->trunk.local_port : source->net),
			new_net, new_stn);
	}

	// By here, we have our new address (which will be the supplied static if that's what
	// was asked for), and the pool's updatemutex will be locked, as will the source's
	// updatemutex. Since we have already looked for, and not found, the source address
	// on the specified device, we know we have to create it.

	// So, first create a new pool host object
		
	host = eb_malloc(__FILE__, __LINE__, "POOL", "Create new pool host structure", sizeof(struct __eb_pool_host));

	if (!host)
	{
		eb_debug (1, 0, "POOL", "Failed malloc for new pool host structure for %s %d address %d.%d", (source->type == EB_DEF_TRUNK ? "trunk" : "wire"), (source->type == EB_DEF_TRUNK ? source->trunk.local_port : source->net), s_net, s_stn);
	}

	host->is_static = is_static;
	gettimeofday(&(host->last_traffic), 0);
	host->b_in = host->b_out = 0;

	if (pthread_mutex_init(&(host->statsmutex), NULL) == -1)
		eb_debug (1, 0, "POOL", "Failed to initialize pool host stats mutex for %s %d address %d.%d", (source->type == EB_DEF_TRUNK ? "trunk" : "wire"), (source->type == EB_DEF_TRUNK ? source->trunk.local_port : source->net), s_net, s_stn);
	
	host->source = source;

	host->pool = pool;

	host->s_net = s_net;
	host->s_stn = s_stn;
	host->net = new_net;
	host->stn = new_stn;

	// Splice into the various structs...

	// Head of the list in the pool
	//fprintf (stderr, "host->next_net = %p, pool->hosts_net[%d]=%p\n", host->next_net, new_net, pool->hosts_net[new_net]);
	host->next_net = pool->hosts_net[new_net];
	if (host->next_net) host->next_net->prev_net = host;
	host->prev_net = NULL; // This is top of list
	pool->hosts_net[new_net] = host;
	//fprintf (stderr, "host->next_net = %p, pool->hosts_net[%d]=%p\n", host->next_net, new_net, pool->hosts_net[new_net]);
	if (0) {
		struct __eb_pool_host *dummy;

		dummy = pool->hosts_net[new_net];

		while (dummy)
		{
			fprintf (stderr, "%d.%d map to %d.%d on device at %p\n", 
					dummy->net, dummy->stn,
					dummy->s_net, dummy->s_stn,
					dummy->source);
			dummy = dummy->next_net;
		}
	}

	// Advertise on the wires, Unlock and return

	eb_set_single_wire_host(new_net, new_stn);

	pthread_mutex_unlock(&(pool->updatemutex));
	*err = 0;
	return host;
}

// Inactive pool host garbage collector thread

static void *eb_pool_garbage_collector(void *ignored)
{
	struct __eb_pool	*p;
	struct __eb_pool_host	*h;
	struct timeval		now;

	eb_thread_ready();

	while (1)
	{

		eb_debug (0, 4, "POOL", "%16sPool garbage collector running", "");

		p = pools;

		gettimeofday(&now, 0);

		while (p)
		{
			uint8_t net;

			// Lock the pool
			pthread_mutex_lock(&(p->updatemutex));
				
			for (net = 1; net < 255; net++)
			{
				h = p->hosts_net[net];

				while (h)
				{
					if ((!(h->is_static)) && timediffmsec(&(h->last_traffic), &now) > (EB_CONFIG_POOL_DEAD_INTERVAL * 1000))
					{
						struct __eb_pool_host	*new_h;

						new_h = h->next_net;

						// First update the prev_net pointer in new_h, if new_h exists
						
						if (new_h)
							new_h->prev_net = h->prev_net;

						// Splice out of list
						
						if (h->prev_net == NULL)
							h->pool->hosts_net[net] = new_h;
						else
							h->prev_net->next_net = new_h;
						
						// Drop it off the wire nets

						eb_clr_single_wire_host (h->net, h->stn);

						eb_debug (0, 4, "POOL", "Freeing idle pool host %d.%d (source address %d.%d on %s %d) at %p",
							h->net, h->stn,
							h->s_net, h->s_stn,
							(h->source->type == EB_DEF_TRUNK ? "trunk" : "wire"),
							(h->source->type == EB_DEF_TRUNK ? h->source->trunk.local_port : h->source->net),
							h);

						eb_free(__FILE__, __LINE__, "POOL", "Freeing pool host structure", h);

						h = new_h;
						
					}
					else	h = h->next_net;
				}
			}

			// Unlock this pool
			pthread_mutex_unlock(&(p->updatemutex));	

			p = p->next; // No locking needed here - the list of pools is fixed at config time
		}

		sleep(60);
	}

	return NULL;
}



/*
 * 
 *
 * REST OF CODE
 *
 *
 *
 */





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

	if (!(EB_CONFIG_PKT_DUMP_OPTS & dir) && !(EB_CONFIG_PKT_DUMP_OPTS != 0 && dir == EB_PKT_DUMP_DUMPED))
		return;

	if (EB_CONFIG_NOKEEPALIVEDEBUG && p->p.port == 0x9C && p->p.ctrl == 0xD0) // Trunk keepalive - exit if filtered
		return;

	if (EB_CONFIG_NOBRIDGEANNOUNCEDEBUG && p->p.port == 0x9C) // Trunk traffic generally - exit if filtered
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
			(p->p.aun_ttype == ECONET_AUN_INK ? "INK" :
			(p->p.aun_ttype == ECONET_AUN_NAK ? "NAK" : "UNK")
			)))))),
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
		p->index = interface_index++;
		p->im = NULL; /* No interface group by default */

		if (pthread_mutex_init(&(p->qmutex_in), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize queue mutex inbound for net %d", net);

		if (pthread_mutex_init(&(p->qmutex_out), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize queue mutex outbound for net %d", net);

		if (pthread_cond_init(&(p->qwake), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize queue wake condition for net %d", net);

		if (pthread_mutex_init(&(p->aun_out_mutex), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize AUN output mutex for net %d", net);

		if (pthread_cond_init(&(p->aun_out_cond), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize AUN output condition for net %d", net);

		if (pthread_mutex_init(&(p->priority_mutex), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize priority mutex for net %d", net);

		p->out = NULL; // Init queues
		p->in = NULL;

		// AUN output queues

		p->aun_out_head = p->aun_out_tail = NULL;

		// Clear priority

		p->p_seq = p->p_net = p->p_stn = p->p_isresilience = 0;

		// Clear all exposures

		p->exposures = NULL;

		// Set up config

		p->config = config;

		// Traffic stats
		
		p->b_in = p->b_out = 0; // Traffic stats

		if (pthread_mutex_init(&(p->statsmutex), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize stats mutex for net %d", net);

		if (pthread_mutex_init(&(p->updatemutex), NULL) == -1)
			eb_debug (1, 0, "CONFIG", "Cannot initialize update mutex for net %d", net);

		if (p->type == EB_DEF_WIRE)
		{
			if (pthread_mutex_init(&(p->wire.stations_lock), NULL) == -1)
				eb_debug (1, 0, "CONFIG", "Cannot initialize wire station update mutex for net %d", net);
			p->wire.stations_update_rq = 0;
		}

		p->all_nets_pooled = 0; // Starting point

		p->self = p;

		p->fw_in = p->fw_out = NULL;
	
		p->next = NULL;

	}
	else	eb_debug (1, 0, "CONFIG", "Unable to malloc() device struct for network %d type %02x", net, type);

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
		DEVINIT_DEBUG ("Created new virtual network %d", net);
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
			existing->local.fs.server = NULL; // No station
			strcpy(existing->local.ip.tunif, ""); // Flag as no IP gateway
			pthread_mutex_init(&existing->local.ports_mutex, NULL);
			memset(&(existing->local.ports), 0, sizeof(existing->local.ports)); // Clear ports in use
			memset(&(existing->local.reserved_ports), 0, sizeof(existing->local.reserved_ports)); // Clear ports in use
			existing->local.last_port = 0;
			/* Insert some reserved ports to the port allocator */
			EB_PORT_SET(existing, reserved_ports, 0x99, NULL, NULL); /* FS */
			EB_PORT_SET(existing, reserved_ports, 0x9E, NULL, NULL); /* PS ? */
			EB_PORT_SET(existing, reserved_ports, 0x9F, NULL, NULL); /* PS Query */
			EB_PORT_SET(existing, reserved_ports, 0xA0, NULL, NULL); /* *FAST */
			EB_PORT_SET(existing, reserved_ports, 0xB0, NULL, NULL); /* FindServer */
			EB_PORT_SET(existing, reserved_ports, 0xD1, NULL, NULL); /* PS Data */
			EB_PORT_SET(existing, reserved_ports, 0xD2, NULL, NULL); /* IP/Econet */

			DEVINIT_DEBUG("Created new local device on station %d.%d", net, stn);

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

/* Locate the device struct for a net.stn destination
 * Returns pointer to struct if found; else NULL
 */

struct __eb_device * eb_find_station_internal (uint8_t net, uint8_t stn)
{

	struct __eb_device 	*result;

	result = NULL;

	eb_debug (0, 4, "BRIDGE", "%-8s %3d.%3d Looking for station struct... eb_get_network() returns %p", "", net, stn, (result = eb_get_network(net)));


	if ((net != 255) && (stn != 255) && result) // Good start, this network looks like it might exist, and we aren't looking for a broadcast
	{
	
		eb_debug (0, 5, "BRIDGE", "%-8s %3d.%3d eb_get_network() result->net is %d", "", net, stn, result->net);

		if (stn == 0) // Bridge internal - don't look for diversions
			return result;

		eb_debug (0, 5, "BRIDGE", "%-8s %3d.%3d eb_get_network() Checking diverts", "", net, stn);

		if (result->net != net) // This is a secondary network on the same device - don't look for diverts
		{
			eb_debug (0, 4, "BRIDGE", "%-8s %3d.%3d eb_find_station() not searching diverts - net %d is different to device net %d", "", net, stn, net, result->net);
			return result;
		}

		// Now see if this is a diversion

		if (result->type == EB_DEF_NULL)
			result = result->null.divert[stn]; // Which will be NULL if the station doesn't exist
		else if (result->type == EB_DEF_WIRE && result->wire.divert[stn]) // Only if there's actually a divert on a wire
			result = result->wire.divert[stn];

	}
	else	eb_debug (0, 5, "BRIDGE", "%-8s %3d.%3d eb_get_network() result->net returned NULL - network unknown", "", net, stn);

	eb_debug (0, 4, "BRIDGE", "%-8s %3d.%3d eb_find_station() returning %p", "", net, stn, result);

	return result;

}

/* Packet version of find_station */
/* Locate the device struct for a packet's source/destination
 * Returns pointer to struct if found; else NULL
 * dir = 1 means source, dir = 2 means destination (to be found)
 */

struct __eb_device * eb_find_station (uint8_t dir, struct __econet_packet_aun *p)
{

	uint8_t			net, stn;

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

	return eb_find_station_internal(net, stn);
}

/* Apply pool nat, if applicable, to the source address specified */

void eb_pool_nat (struct __eb_device *d, uint8_t *net, uint8_t *stn)
{

	struct __eb_pool_host	*h;
	struct __eb_pool	*p;
	struct timeval		t;

	gettimeofday(&t, 0);

	// no pool nat for broadcasts or 0 stations
	if (*net == 255 || *stn == 0)
		return;

	if (d->type != EB_DEF_WIRE && d->type != EB_DEF_TRUNK)
		return; // No pool nat on these

	// See if pool nat applies to this device
	
	p = (d->type == EB_DEF_WIRE ? d->wire.pool : d->trunk.pool);

	h = eb_pool_find_addr_lock (p, *net, *stn, d);

	// if h not found, but *net is to be natted then create a new entry
	// (and if it wasn't found by now, it isn't static, so we make it non-static)
	
	if (!h)
	{
		if (
			((d->type == EB_DEF_WIRE) && (d->wire.use_pool[*net]))
		||	((d->type == EB_DEF_TRUNK) && (d->trunk.use_pool[*net]))
		)
		{
			uint8_t	err;

			h = eb_find_make_pool_host(d, *net, *stn, 0, 0, 0, &err);

			if (!h)
			{
				eb_debug (0, 1, "POOL", "Unable to create new dynamic pool entry for %d.%d on %s %d in pool %s (%s) - likely traffic loss",
						*net, *stn,
						eb_type_str(d->type),
						(d->type == EB_DEF_TRUNK ? d->trunk.local_port : d->net),
						p->name,
						eb_pool_err(err));
				*net = 0;
				*stn = 0; // Nat failed
			}
			else
			{
				eb_debug (0, 2, "POOL", "Mapping %d.%d on %s %d in pool %s to %d.%d",
				*net, *stn,
				eb_type_str(d->type),
				(d->type == EB_DEF_TRUNK ? d->trunk.local_port : d->net),
				p->name,
				h->net, h->stn);
			}
		}

	}

	if (h) // Found
	{
		*net = h->net;
		*stn = h->stn;
		pthread_mutex_lock(&h->pool->updatemutex);
		gettimeofday (&(h->last_traffic), 0);
		pthread_mutex_unlock(&h->pool->updatemutex);

	}

	// Leave untouched otherwise - no nat applies

}

/* If traffic received to a pool network, this does the 'unnat' and gives you source device, real net & station number */
/* Provide net & stn and they'll be translated, or set to 0 if failed (drop traffic if so), and source is sent as NULL and is converted to the device you need to send the traffic to */
void eb_pool_unnat(uint8_t *net, uint8_t *stn, struct __eb_device **source)
{

	struct __eb_pool	*p;
	struct __eb_pool_host	*h;

	// First, find the pool with this network in it

	p = pools;

	while (p)
	{
		pthread_mutex_lock(&(p->updatemutex)); // In case it's changing while we look

		h = p->hosts_net[*net];

		while (h) // There are some mappings on this network
		{
			if (h->stn == *stn) // Found it
			{
				*net = h->s_net;
				*stn = h->s_stn;
				*source = h->source;
				gettimeofday (&(h->last_traffic), 0);
				pthread_mutex_unlock(&(p->updatemutex));
				return;
			}
			h = h->next_net;
		}
		
		pthread_mutex_unlock(&(p->updatemutex));

		p = p->next;
	}


	// If we get here, it wasn't found - set to 0 to show failed
	//
	
	*net = *stn = 0;
	*source = NULL;
	return;
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
		ioctl (values->wire_device->wire.socket, ECONETGPIO_IOC_READGENTLE);

		values->wire_device->p_isresilience = values->wire_device->p_net = values->wire_device->p_stn = values->wire_device->p_seq = 0; // Reset
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

/* 
 * eb_bridge_sender_net()
 *
 * Find a network number to use as our bridge sender address
 * (Which is supposed to be the other side network on a trad Acorn bridge,
 * so it can't be a network which is on the same device as the one
 * that needs to know a sender net (i.e. 'destnet') - so we just hunt
 * for one which is not destnet and isn't NULL either.
 */

uint8_t eb_bridge_sender_net (struct __eb_device *destnet)
{

	uint8_t			result = 0; // Rogue for none found
	uint8_t			count = 1;

	// Search for active net which is not destnet and which we are prepared to announce on this network

	pthread_mutex_lock (&networks_update);

	while (count < 255 && !result)
	{
		uint8_t 	filtered;

		filtered = 0;

		if (networks[count] &&
			(
				(networks[count]->type == EB_DEF_WIRE && networks[count]->wire.filter_out[count])
			||	(networks[count]->type == EB_DEF_TRUNK && networks[count]->trunk.filter_out[count])
			)
		)
			filtered = 1;

		if (networks[count] && (networks[count] != destnet) && (networks[count]->net != destnet->net) && !filtered)
			result = count;
		else	count++;
		
	}

	pthread_mutex_unlock (&networks_update);

	eb_debug (0, 4, "BRIDGE", "Core             Sender net is %d for %s device net %d", result, eb_type_str(destnet->type), destnet->net);

	return result;

}

/* eb_bridge_update_watcher()
 *
 * Sits and waits until woken up. When woken up will send
 * n bridge updates on its nominated device (passed as the
 * void * argument). 
 *
 * If it detects that the net list has changed part way through
 * the n updates, it'll go back to the start.
 *
 * n is either EB_CONFIG_WIRE_UPDATE_QTY or
 * EB_CONFIG_TRUNK_UPDATE_QTY depending on type of device.
 *
 * Each device starts two of these just in case a cond signal
 * is sent whilst the other is going back to sleep
 *
 */

static void * eb_bridge_update_watcher (void *device)
{
	struct __eb_device	*me;
	uint8_t			qty, real_qty;
	char			debug_string[1024];
	uint8_t			old_update[255]; /* Data portion of previous update */
	uint8_t			old_numnets; 	/* number of valid bytes in old_update */
	uint8_t			numnets, net_count;
	uint8_t			sender_net; /* Src net num used for transmission of broadcast */
	uint8_t			tx_count;
	struct timespec		wait_timeout;
	int			update_delay = 30;
	uint8_t			dead;

	struct __econet_packet_aun	* update; 

	me = (struct __eb_device *) device;

	qty = (me->type == EB_DEF_WIRE ? EB_CONFIG_WIRE_UPDATE_QTY : EB_CONFIG_TRUNK_UPDATE_QTY);

	old_numnets = 0; /* Invalidate old_update, effectively */

	pthread_mutex_lock (&(me->bridge_update_lock));

	while (1)
	{

		int	result;

		/* Establish a delay between automatic updates if we are on a trunk, just in case the other end is all pooled */

		clock_gettime(CLOCK_REALTIME, &wait_timeout);

		wait_timeout.tv_sec += update_delay;

		if (me->type == EB_DEF_TRUNK) // Send period announcements all the time
			result = pthread_cond_timedwait(&(me->bridge_update_cond), &(me->bridge_update_lock), &wait_timeout);
		else
			result = pthread_cond_wait(&(me->bridge_update_cond), &(me->bridge_update_lock));

		dead = 0; /* Assume alive */

		if (me->type == EB_DEF_TRUNK && !me->trunk.hostname) // Unconnected trunk
			dead = 1;

		/* See if we are an unconnected multitrunk child, and continue if so */

		if (me->type == EB_DEF_TRUNK && me->trunk.mt_parent)
		{

			pthread_mutex_lock(&(me->trunk.mt_mutex));
			if (!(me->trunk.mt_data))
				dead = 1; // We're not alive
			pthread_mutex_unlock(&(me->trunk.mt_mutex));

		}

		if (dead)
			continue; /* Don't send anything */

		/* We are awake here, and we have the lock
		 *
		 * So something wants us to send an update
		 *
		 */

		/* Find our sender net */

		sender_net = eb_bridge_sender_net(me);

		if (!sender_net) // No bridge sender net available!
		{
			/* Go around again */
			eb_debug (0,2, "BRIDGE", "%-8s   %7d Unable to find sender net. Not sending bridge update.", eb_type_str(me->type), (me->type == EB_DEF_WIRE) ? me->net : me->trunk.local_port);
			continue;
		}

		// Just send a single update (two, since there's two threads) if we're on a trunk and the cond wait timed out.

		if (me->type == EB_DEF_TRUNK && result == ETIMEDOUT)
			real_qty = 1;
		else	real_qty = qty;

		for (tx_count = 0; tx_count < real_qty; tx_count++)
		{

			/* Allocate packet to send */
	
			update = eb_malloc (__FILE__, __LINE__, "BRIDGE", "Creating bridge packet", 12 + 255);
	
			if (!update)
				eb_debug (1, 0, "BRIDGE", "Core         Malloc() failed creating bridge packet!");
	
			/* Make our update */
	
#pragma GCC diagnostic ignored "-Warray-bounds"
			update->p.aun_ttype = ECONET_AUN_BCAST;
			update->p.port = BRIDGE_PORT;
			update->p.ctrl = BRIDGE_UPDATE; /* Resets done elsewhere */
			update->p.seq = (bridgewide_seq += 4);
			update->p.srcstn = 0;
			update->p.srcnet = sender_net;
			update->p.dstnet = 0xff;
			update->p.dststn = 0xff;
			
			strcpy (debug_string, "");
	
			numnets = 0;
	
			pthread_mutex_lock (&networks_update);
	
			strcpy (debug_string, " with nets ");
		
			for (net_count = 1; net_count < 255; net_count++)
			{
	
				uint8_t		is_filtered = 0;

				if (me->type == EB_DEF_WIRE)
					is_filtered = me->wire.filter_out[net_count];
				else	is_filtered = me->trunk.filter_out[net_count];
	
				if (!is_filtered && networks[net_count] && networks[net_count] != me) // Don't send to trigger, and don't trombone
				{
					char netstr[10];
	
					update->p.data[numnets++] = net_count;
					snprintf (netstr, 6, "%3d ", net_count);
					strcat (debug_string, netstr);
				}
			}

#pragma GCC diagnostic warning "-Warray-bounds"

			pthread_mutex_unlock (&networks_update);

			/* Detect if netlist has changed here and reset tx_count to 1 (we've already sent packet 0) */

			if (
				(old_numnets != numnets)
			||	(memcmp(&(old_update), &(update->p.data), numnets))
			)
				tx_count = 1; /* Start at 1 again */

			/* Copy current update to old */

			old_numnets = numnets;
			memcpy (&(old_update), &(update->p.data), 255);

			/* Send the update */

			eb_enqueue_input (me, update, numnets);

			pthread_cond_signal (&(me->qwake));
	
			if (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG)
			{
				if (me->type == EB_DEF_WIRE)
					eb_debug (0, 2, "BRIDGE", "Wire     %3d     Send bridge update #%d %s", me->net, tx_count + 1, debug_string);
				else
					eb_debug (0, 2, "BRIDGE", "Trunk    %7d Send bridge update #%d to Trunk to %s%s", me->trunk.local_port, tx_count + 1, me->trunk.hostname, debug_string);
			}

			if (tx_count < qty) sleep(1);

		}

		/* Go back to sleep */

	}

	return NULL;

}

/* eb_bridge_reset_watcher()
 *
 * Sits and waits until woken up. When woken up will send
 * n bridge resets on its nominated device (passed as the
 * void * argument). 
 *
 * n is either EB_CONFIG_WIRE_RESET_QTY or
 * EB_CONFIG_RESET_UPDATE_QTY depending on type of device.
 *
 */

static void * eb_bridge_reset_watcher (void *device)
{
	struct __eb_device	*me;
	uint8_t			qty;
	uint8_t			sender_net; /* Src net num used for transmission of broadcast */
	uint8_t			tx_count;
	uint8_t			dead; /* Whether trunk is not alive yet */

	struct __econet_packet_aun	* update; 

	me = (struct __eb_device *) device;

	qty = (me->type == EB_DEF_WIRE ? EB_CONFIG_WIRE_RESET_QTY : EB_CONFIG_TRUNK_RESET_QTY);

	pthread_mutex_lock (&(me->bridge_reset_lock));

	while (1)
	{

		pthread_cond_wait(&(me->bridge_reset_cond), &(me->bridge_reset_lock));

		//if (me->type == EB_DEF_TRUNK && !me->trunk.hostname) // Unconnected trunk
			//continue;

		dead = 0; /* Assume alive */

		if (me->type == EB_DEF_TRUNK && !me->trunk.hostname) // Unconnected trunk
			dead = 1;

		/* See if we are an unconnected multitrunk child, and continue if so */

		if (me->type == EB_DEF_TRUNK && me->trunk.mt_parent)
		{

			pthread_mutex_lock(&(me->trunk.mt_mutex));
			if (!(me->trunk.mt_data))
				dead = 1; // We're not alive
			pthread_mutex_unlock(&(me->trunk.mt_mutex));

		}

		if (dead)
			continue; /* Don't send anything */

		/* We are awake here, and we have the lock
		 *
		 * So something wants us to send an update
		 *
		 */

		/* Find our sender net */

		sender_net = eb_bridge_sender_net(me);

		if (!sender_net) // No bridge sender net available!
		{
			/* Go around again */
			eb_debug (0,2, "BRIDGE", "%-8s   %7d Unable to find sender net. Not sending bridge reset.", eb_type_str(me->type), (me->type == EB_DEF_WIRE) ? me->net : me->trunk.local_port);
			continue;
		}

		for (tx_count = 0; tx_count < qty; tx_count++)
		{

			/* Allocate packet to send */
	
			update = eb_malloc (__FILE__, __LINE__, "BRIDGE", "Creating bridge packet", 12 + 255);
	
			if (!update)
				eb_debug (1, 0, "BRIDGE", "Core         Malloc() failed creating bridge packet!");
	
#pragma GCC diagnostic ignored "-Warray-bounds"
	
			/* Make our update */
	
			update->p.aun_ttype = ECONET_AUN_BCAST;
			update->p.port = BRIDGE_PORT;
			update->p.ctrl = BRIDGE_RESET; /* Resets done elsewhere */
			update->p.seq = (bridgewide_seq += 4);
			update->p.srcstn = 0;
			update->p.srcnet = sender_net;
			update->p.dstnet = 0xff;
			update->p.dststn = 0xff;
			
			update->p.data[0] = sender_net;

#pragma GCC diagnostic warning "-Warray-bounds"

			/* Send the reset */

			eb_enqueue_input (me, update, 1);

			pthread_cond_signal (&(me->qwake));
	
			if (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG)
			{
				if (me->type == EB_DEF_WIRE)
					eb_debug (0, 2, "BRIDGE", "Wire     %3d     Send bridge RESET #%d", me->net, tx_count + 1);
				else
					eb_debug (0, 2, "BRIDGE", "Trunk    %7d Send bridge RESET #%d to Trunk on %s", me->trunk.local_port, tx_count + 1, me->trunk.hostname);
			}

			if (tx_count < qty) sleep(1);

		}

		/* Now send a series of updates on our device */

		pthread_cond_signal (&(me->bridge_update_cond));

		/* Go back to sleep */


	}

	return NULL;

}

/* 
 * eb_bridge_update()
 *
 * Bridge update sender 
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
	/*
	uint8_t				sender_net;
	struct __eb_update_info		*info;
	pthread_t			update_thread;
	int				err;
	*/

	// If ALL nets on trigger are pooled, don't bother sending reset or updates onwards - nothing will change - but *do* send updates if we got a reset from this source.
	// Logic is this (for a trunk/wire which is all pooled):
	// - When the remote bridge re-starts it will send a reset. We don't forward that as nothing will change, but we'll send it a list of our nets.
	// - When we get an update, we don't forward it because nothing will change elsewhere either. Pooling happens independently of net announcements.
	// - But resets & updates received *from* somewhere other than a network which is all pooled *are* forwarded so that the pooled trunk/wire
	//   knows what is where.
	
	if (trigger && trigger->all_nets_pooled && !EB_CONFIG_POOL_RESET_FWD)
	{
		eb_debug (0, 2, "BRIDGE", "%-8s %7d Bridge %s not forwarded (all nets pooled)", eb_type_str(trigger->type), (trigger->type == EB_DEF_TRUNK ? trigger->trunk.local_port : trigger->net), (ctrl == BRIDGE_RESET) ? "reset" : "update");
		if (ctrl == BRIDGE_RESET)
		{
			eb_debug (0, 2, "BRIDGE", "%-8s %7d Triggering bridge updates", eb_type_str(trigger->type), (trigger->type == EB_DEF_TRUNK ? trigger->trunk.local_port : trigger->net));
			pthread_cond_signal(&(trigger->bridge_update_cond));
		}
		return;
	}

	// Send to all but trigger. If trigger is NULL, this was an internally forced reset/update - send everywhere

	dev = devices;

	while (dev)
	{

		/* If trigger is null (internal reset), or it's an update, or (in which case it's a reset) trigger != dev, do reset/update as need be */

		/* If it's a reset and the dev is not the trigger, send a reset to dev. Otherwise, send an update to dev (because either
		 * we received an update, or we got a reset from the trigger and we need to reply with an update.
		 */

		if (
			(dev->type == EB_DEF_WIRE)
		//&&	 (!trigger || ctrl == BRIDGE_UPDATE || (dev != trigger))
		)
		{
			if ((ctrl == BRIDGE_RESET) && (dev != trigger))
				pthread_cond_signal(&(dev->bridge_reset_cond));
			else
				pthread_cond_signal(&(dev->bridge_update_cond));

		}

		dev = dev->next;

	}

	// Then trunks

	dev = trunks;

	while (dev)
	{
		/* If trigger is null (internal reset), or trigger != dev, do reset/update as need be */

		if (
			(dev->type == EB_DEF_TRUNK)
		//&&	 (!trigger || ctrl == BRIDGE_UPDATE || (dev != trigger))
		)
		{
			if ((ctrl == BRIDGE_RESET) && (dev != trigger))
				pthread_cond_signal(&(dev->bridge_reset_cond));
			else
				pthread_cond_signal(&(dev->bridge_update_cond));

		}

		dev = dev->next;
	}

}

/* 
 * eb_bridge_reset()
 *
 * Bridge reset routine
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
	uint8_t	pipe_stations[8192]; // Flag currently active pipes and reactivate them on the station reset
	uint16_t	pipe_counter;

	if (trigger)
		snprintf (info, 19, "net %d", trigger->net);
	else
		strcpy (info, "internal");

	if (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG)
		eb_debug (0, 2, "BRIDGE", "%-8s         Bridge reset from %s", (trigger ? eb_type_str(trigger->type) : "Core"), info);

	// Put our networks structure back to the start

	pthread_mutex_lock (&networks_update);

	for (uint8_t n = 1; n < 255; n++) // Reset temporarily active exposures to inactive
		if (networks[n])
			eb_set_exposures_inactive(n);

	memcpy (&networks, &networks_initial, sizeof(networks));
	
	/* Find active pipe devices
	 * so that we can re-activate them after we re-set the
	 * station map to the startup value, below
	 *
	 * ** Known potential issue: the skt_write value on
	 * a pipe might be changing while we look at it here.
	 * It probably needs a lock.
	 *
	 */

	memset (pipe_stations, 0, sizeof(pipe_stations));

	dev = devices;

	while (dev)
	{

		if ((dev->type == EB_DEF_PIPE) && (dev->pipe.skt_write != -1)) // Active pipe
		{
			ECONET_SET_STATION(pipe_stations, dev->net, dev->pipe.stn);
		}

		dev = dev->next;

	}

	pthread_mutex_unlock (&networks_update);

	eb_debug (0, 2, "BRIDGE", "%-8s         Networks list reset", (trigger ? eb_type_str(trigger->type) : "Core"));

	// Reset station map to defaults on each wire net as well
	// Re-uses dev

	dev = devices;

	while (dev)
	{
		if (dev->type == EB_DEF_WIRE)
		{
			/* Unlock it */
			dev->loop_blocked = 0;

			pthread_mutex_lock (&(dev->wire.stations_lock));

			memcpy (&(dev->wire.stations), &(dev->wire.stations_initial), sizeof (dev->wire.stations));

			/* Copy active pipe stations into the MAP */

			for (pipe_counter = 0; pipe_counter < sizeof(pipe_stations); pipe_counter++)
				dev->wire.stations[pipe_counter] |= pipe_stations[pipe_counter];

			ioctl (dev->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(dev->wire.stations));
			eb_debug (0, 2, "BRIDGE", "%-8s         Station set reset on wire network %d", (trigger ? eb_type_str(trigger->type) : "Core"), dev->net);

			dev->wire.stations_update_rq = 1;

			pthread_mutex_unlock (&(dev->wire.stations_lock));
			pthread_cond_signal (&(dev->qwake));
		}

		dev = dev->next;

	}

	/* Unlock the trunks */

	dev = trunks;
	while (dev)
	{
		dev->loop_blocked = 0;
		dev = dev->next;
	}

	// Send bridge reset onwards to sources other than trigger - use eb_bridge_update with correct ctrl byte

	eb_bridge_update (trigger, BRIDGE_RESET); // Reset

	/* Reset the loop detector */

	pthread_mutex_lock(&(loopdetect_mutex));
	last_root_id_seen = 0xFFFFFFFF; /* Detected by the loop detector as meaning it needs to listen again */
	when_root_id_seen = 0; /* Make sure the data is invalid */
	pthread_mutex_unlock(&(loopdetect_mutex));
}

/* 
 * Respond to a station's WhatNet or IsNet query. Do so with
 * full packet from <farside>.0.
 */

void eb_bridge_whatis_net (struct __eb_device *source, uint8_t net, uint8_t stn, uint8_t ctrl, uint8_t reply_port, uint8_t query_net)
{
	uint8_t 			farside;
	struct __econet_packet_aun	*reply;
	struct __eb_pool_host		*host;
	struct __eb_pool		*pool;

	reply = eb_malloc (__FILE__, __LINE__, "BRIDGE", "Creating bridge What/IsNet reply packet", 14);

	if (!reply)
	{
		eb_debug (0, 2, "BRIDGE", "%-8s %3d Failed to malloc() bridge What/IsNet reply packet", eb_type_str (source->type), source->net);
		return;
	}

	farside = eb_bridge_sender_net (source);

	if (!farside)
		return; // Barf - No farside net

	if (source->type == EB_DEF_WIRE) // Always should be wire, but just in case
	{

		pthread_mutex_lock (&(source->wire.stations_lock));
		/*
		 * Clear any .0 hosts out of this wire's station map
		 * and then add farside.0 to the map so the kernel
		 * module listens for the ACK on the 4-way we are
		 * about to send.
		 */

		eb_clear_zero_hosts (source);

		/*
		 * Now set the map to include farside.0
		 * that we are actually sending from.
		 *
		 */

		ECONET_SET_STATION(source->wire.stations, farside, 0);

		/* And poke the map into the kernel */

		source->wire.stations_update_rq = 1;

		pthread_mutex_unlock (&(source->wire.stations_lock));
		pthread_cond_signal (&(source->qwake));
		//ioctl(source->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(source->wire.stations)); 
	}

#pragma GCC diagnostic ignored "-Warray-bounds"
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


	// Undo pool Nat here if need be
	
	if ((source->type == EB_DEF_WIRE && (pool = source->wire.pool)) || (source->type == EB_DEF_TRUNK && (pool = source->trunk.pool)))
	{
		host = eb_pool_find_addr_lock(pool, net, stn, NULL);
		if (host)
		{
			reply->p.dstnet = host->s_net;
			reply->p.dststn = host->s_stn;
		}
	}

#pragma GCC diagnostic warning "-Warray-bounds"

	/*
	 * On IsNet, only reply if:
	 * (i) we know the network
	 * (ii) it isn't a network on this source device (i.e. local or known by another bridge on the device)
	 *
	 */
	
	if ((ctrl == BRIDGE_ISNET && networks[query_net] && networks[query_net] != source) || (ctrl == BRIDGE_WHATNET))
	{
		
		struct timeval	now;

		gettimeofday (&now, NULL);

		if (
			(ctrl == BRIDGE_WHATNET && (timediffmsec(&(source->wire.last_bridge_whatnet[stn]), &now) > EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL))
		||	
			(ctrl == BRIDGE_ISNET /* this is wrong! && (timediffmsec(&(source->wire.last_bridge_isnet[stn]), &now) > EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL) */)
		)
		{
			//usleep (5 * 1000 * farside); // Delay

			eb_enqueue_input (source, reply, 2);
			pthread_cond_signal(&(source->qwake));
	
			if (ctrl == BRIDGE_WHATNET)
				gettimeofday(&(source->wire.last_bridge_whatnet[stn]), NULL);
			else
				gettimeofday(&(source->wire.last_bridge_isnet[stn]), NULL);

			eb_debug (0, 2, "BRIDGE", "%-8s %3d     What/IsNet reply from %3d.%3d to %3d.%3d", eb_type_str(source->type), source->net, farside, 0, net, stn);
		}

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
				if ((dev->type == EB_DEF_AUN && e) || (dev->type != EB_DEF_AUN && ((dev->type != EB_DEF_PIPE) || (dev->pipe.skt_write != -1))))
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

			//char				hostname[256]; // Now global

			// We know this network - we'll reply, increment the hop count & forward it unless the network is local to us.

			if (route->net == net)
				final = 1;
			
			if (final)
			{
				if (route->type == EB_DEF_WIRE && route->wire.divert[stn])	route = route->wire.divert[stn];
				else if (route->type == EB_DEF_NULL && route->null.divert[stn])	route = route->null.divert[stn];
			}
				
			switch (route->type)
			{
				case EB_DEF_WIRE:
					snprintf(reply_diags, 383, "%s %03d via Wire on %s (%d)", hostname, net, route->wire.device, route->net); break;
				case EB_DEF_TRUNK:
					snprintf(reply_diags, 383, "%s %03d via Trunk to %s:%d", hostname, net, route->trunk.hostname ? route->trunk.hostname : "(Not connected)", route->trunk.hostname ? route->trunk.remote_port : 0); break;
				case EB_DEF_NULL:
					snprintf(reply_diags, 383, "%s %03d via Local Null - undefined divert", hostname, net); break;
				case EB_DEF_LOCAL:
					snprintf(reply_diags, 383, "%s %03d.%03d via Local Emulation", hostname, net, stn); break;
				case EB_DEF_PIPE:
					snprintf(reply_diags, 383, "%s %03d.%03d via Local Pipe %s", hostname, net, stn, route->pipe.base); break;
				case EB_DEF_POOL:
					snprintf(reply_diags, 383, "%s %03d.%03d via Pool", hostname, net, stn); break;
				case EB_DEF_AUN:
				{
					if (route->aun->port == -1)
						snprintf(reply_diags, 383, "%s %03d.%03d via AUN (Inactive)", hostname, net, stn); 
					else
						snprintf(reply_diags, 383, "%s %03d.%03d via AUN at %08X:%d", hostname, net, stn, route->aun->addr, route->aun->port); 
				} break;
				default:	snprintf(reply_diags, 383, "%s %03d Unknnwn destination type", hostname, net); break;
			}

			reply = eb_malloc (__FILE__, __LINE__, "TRACE", "Allocating reply packet for a trace query", 12 + strlen(reply_diags) + 4);

			if (reply)
			{

				struct __eb_pool_host *h;

				eb_debug (0, 2, "TRACE", "%-8s %3d.%3d Received trace request for known net %d, hop %d - %s (%s)", eb_type_str(source->type), p->p.srcnet, p->p.srcstn, net, hop + 1, reply_diags, final ? "last hop" : "intermediate hop");

#pragma GCC diagnostic ignored "-Warray-bounds"
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
				
				// Undo pool nat if there is any...
				
				if (source->type == EB_DEF_WIRE && source->wire.pool)
				{
					h = eb_pool_find_addr_lock (source->wire.pool, reply->p.dstnet, reply->p.dststn, NULL);
					if (h)
					{
						reply->p.dstnet = h->s_net;
						reply->p.dststn = h->s_stn;
					}
				}
				else if (source->type == EB_DEF_TRUNK && source->trunk.pool)
				{
					h = eb_pool_find_addr_lock (source->trunk.pool, reply->p.dstnet, reply->p.dststn, NULL);
					if (h)
					{
						reply->p.dstnet = h->s_net;
						reply->p.dststn = h->s_stn;
					}

				}

#pragma GCC diagnostic warning "-Warray-bounds"
				
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

	if (p->p.port == BRIDGE_PORT) // Bridge traffic
	{
		if (p->p.ctrl == EB_CONFIG_TRUNK_KEEPALIVE_CTRL)
		{
			// This is a keepalive - ignore it. So long as it got marked as a received packet, it's fine
		}
		else if (p->p.ctrl >= BRIDGE_WHATNET) // What/IsNet (IsNet is WHATNET+1)
		{
			if (!strncasecmp((char *) &(p->p.data), "BRIDGE", 6))
				eb_bridge_whatis_net (source, p->p.srcnet, p->p.srcstn, p->p.ctrl, p->p.data[6], p->p.data[7]);

		}
		else if ((p->p.ctrl & 0xFE) == BRIDGE_RESET) // Incoming reset or update
		{

			uint8_t		data_count, netlist_changed = 1; /* Starting assumption is the netlist will change, just in case */
			char		debug_string[1024];

			struct __eb_device	*old_networks[255];

			/*
			 * Copy networks[] array so we can see if it changed, either
			 * by reference to defined/known networks, or the device that
			 * handles a particular network (since that will affect
			 * where we advertise those networks).
			 */

			pthread_mutex_lock (&networks_update);

			memcpy (&(old_networks), &(networks), sizeof(networks));

			pthread_mutex_unlock (&networks_update);

			if (p->p.ctrl == BRIDGE_RESET
			&& (
				!(source->all_nets_pooled) // Don't reset if all nets on this device are pooled - no point
			   ||	EB_CONFIG_POOL_RESET_FWD 	// Unless we want to
			   )
			) 
				eb_reset_tables(); // Reset if need be. 

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
				else if ((source->type == EB_DEF_WIRE && source->wire.use_pool[in_adv]) || (source->type == EB_DEF_TRUNK && source->trunk.use_pool[in_adv])) // Don't process networks which are subject to pool nat - we won't advertise them further because all source traffic will have its address altered
				{
					strcat (net_string, "P"); // Flag in the debug
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

					if ((networks[in_adv]) && (networks[in_adv] != source) && (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG))
					{
						if (networks[in_adv]->type == EB_DEF_WIRE)
							eb_debug (0, 2, "BRIDGE", "%-8s %3d     Ignored incoming bridge update for net %d: already known on wire net %d", eb_type_str(source->type), source->net, in_adv, networks[in_adv]->net);
						else if (networks[in_adv]->type == EB_DEF_TRUNK)
							eb_debug (0, 2, "BRIDGE", "%-8s         Ignored incoming bridge update for net %d (%s): already known on trunk to %s:%d", eb_type_str(source->type), in_adv, (in_adv != old_in_adv ? "translated" : "untranslated"), networks[in_adv]->trunk.hostname, networks[in_adv]->trunk.remote_port);
						else 
							eb_debug (0, 2, "BRIDGE", "%-8s         Ignored incoming bridge update for net %d (%s): already known on %s net %d", eb_type_str(source->type), in_adv, (in_adv != old_in_adv ? "translated" : "untranslated"), eb_type_str(networks[in_adv]->type), networks[in_adv]->net);

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

			/* See if we can avoid doing a new update. Always send resets. Default netlist_changed is 1 so we look to see if we can safely set to 0 */

			if (p->p.ctrl == BRIDGE_UPDATE && !memcmp(&(networks), &(old_networks), sizeof(networks)))
				netlist_changed = 0;
	
			if (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG)
			{
				if (source->type == EB_DEF_WIRE)
					eb_debug (0, 2, "BRIDGE", "Wire     %3d     Received bridge %s with %s%s%s", source->net, (p->p.ctrl == BRIDGE_RESET ? "reset" : "update"), (strlen(debug_string) == 0 ? "no networks" : "nets"), debug_string, 
							(netlist_changed ? "" : " (Not forwarded - net list unchanged)"));
				else
				{
					eb_debug (0, 2, "BRIDGE", "Trunk    %7d Received bridge %s from %s:%d with %s%s%s", source->trunk.local_port, (p->p.ctrl == BRIDGE_RESET ? "reset" : "update"), source->trunk.hostname ? source->trunk.hostname : "(Not connected)", source->trunk.hostname ? source->trunk.remote_port : 0, (strlen(debug_string) == 0 ? "no networks" : "nets"), debug_string,
							(netlist_changed ? "" : " (Not forwarded - net list unchanged)"));
				}
			}


			if (netlist_changed)
				eb_bridge_update (source, p->p.ctrl);
	
		}
				

	}
	else
	{
		// It's going on input queues, so we have to replicate for each tx. In future will optimize with ref count in the packetqueue structure
	
		struct __eb_device		*d;

		uint32_t	loop_id;
		uint64_t	hostdata;
		uint8_t		send_broadcast = 1;
		struct __eb_loop_probe	*probe;

		if (p->p.port == ECONET_BRIDGE_LOOP_PROBE)
		{
			probe = (struct __eb_loop_probe *) &(p->p.data);
			loop_id = ntohl (probe->root);
			hostdata = ntohl (probe->hostdata);

			if (
				(loop_id == EB_CONFIG_TRUNK_LOOPDETECT_ID) 
			&&	(hostdata = loopdetect_hostdata)
			)
			{
				char	interface_string[25];

				/* This is one of ours coming back! - We have a loop */
				/* Disable the source */
				source->loop_blocked = 1;
				send_broadcast = 0; // Don't send onwards
				snprintf (interface_string, 24, "%s %d",
						((source->type == EB_DEF_WIRE) ? "Wire" : "Trunk"),
					 	((source->type == EB_DEF_WIRE) ? source->net : source->trunk.local_port));
				eb_debug (0, 1, "BRIDGE", "%8s %3d.%3d Loop detected. Blocking interface %s", interface_string);
			}
			else
			{
				/* Update our loop detection records */

				pthread_mutex_lock (&loopdetect_mutex);
				if (	(time(NULL) - when_root_id_seen > EB_CONFIG_TRUNK_LOOPDETECT_INTERVAL) 
				||	(loop_id <= last_root_id_seen && hostdata < loopdetect_hostdata)
				)
				{
					when_root_id_seen = time(NULL);
					last_root_id_seen = loop_id;
				}
				pthread_mutex_unlock (&loopdetect_mutex);

				probe->hops++; /* Increment hop count */
			}
		}

		d = devices; // We use this list because if we cycle through networks[], we may see the same network twice if it's had an inbound bridge advert that it accepted. This list has each device (WIRE, TRUNK, NULL) only once. Within WIRE & NULL, we need to look for diverts to send to as well.

		if (send_broadcast) while (d)
		{
			if (d->type == EB_DEF_WIRE && (p->p.port != ECONET_BRIDGE_LOOP_PROBE || !d->all_nets_pooled)) /* Send all non-probe traffic, or if it's probe traffic don't send it if all nets are pooled because we don't care */
				eb_send_broadcast(source, d, p, length);

			if (p->p.port != ECONET_BRIDGE_LOOP_PROBE && (d->type == EB_DEF_NULL || d->type == EB_DEF_WIRE)) /* Don't send loop probes to diverts */
				eb_send_broadcast_diverted(source, d, p, length);

			d = d->next;
		}

		// Then trunks

		d = trunks;

		while (d)
		{
			if (p->p.port != ECONET_BRIDGE_LOOP_PROBE || !d->all_nets_pooled)
				eb_send_broadcast(source, d, p, length);
			d = d->next;
		}

	}

}

/* Take a packet received from a device, put it on the device output queue, and wake up the 
   Device's transmission routine

   forcedest is a device we are forcing the traffic toward - used where we are sending 
   traffic to a host which is subject to pool nat, because its source network address
   won't be in networks[] so we can't find it. (It's basically hidden from the core
   bridge down a pooled trunk.) This parameter is NULL if the routine is to look the
   destination device up as normal.

   returns 1 for success, 0 for failure (e.g. can't find source station)
*/

uint8_t eb_enqueue_output (struct __eb_device *source, struct __econet_packet_aun *packet, uint16_t length, struct __eb_device *forcedest)
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
	packetq->notlistening = 0; // Counts up the not listening errors
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

			if (forcedest)
				outq->destdevice = forcedest;
			else
				outq->destdevice = eb_find_station (2, packet);
			
			if (!outq->destdevice) // Can't work out where we are going!
			{
				eb_debug (0, 2, "QUEUE", "%-8s %3d.%3d from %3d.%3d Seq 0x%08X Attempting to queue traffic when destination device cannot be found", eb_type_str(source->type), p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, p->p.seq);

				/* Send INK back to source here if it was an immediate and the host doesn't exist */

				/* Commented out - may well be causing problems 
				if ((source->type == EB_DEF_TRUNK || source->type == EB_DEF_POOL) && p->p.aun_ttype == ECONET_AUN_IMM) // An unroutable immediate - send an INK back to source
				{
					struct __econet_packet_aun 	*ack;

					if ((ack = eb_malloc(__FILE__, __LINE__, "Q-OUT", "Trunk Immediate NAK packet", 12)))
					{
						ack->p.aun_ttype = ECONET_AUN_INK;
						ack->p.seq = p->p.seq;
						ack->p.dststn = p->p.srcstn;
						ack->p.dstnet = p->p.srcnet;
						ack->p.srcstn = p->p.dststn;
						ack->p.srcnet = p->p.dstnet;

						// How to inject this reply?
						// I *think* we can safely put it on our own input queue

						eb_enqueue_input(source, ack, 0); // Data len 0
					}

				}

				*/

				eb_free (__FILE__, __LINE__, "Q-OUT", "Free packet after dest device unknown", p);
				eb_free (__FILE__, __LINE__, "Q-OUT", "Free packetq after dest device unknown", packetq);
				eb_free (__FILE__, __LINE__, "Q-OUT", "Free outq after dest device unknown", outq);

				eb_debug (0, 4, "QUEUE", "%-8s %3d     Output queue manager releasing mutex", eb_type_str(source->type), source->net);

				pthread_mutex_unlock (&(source->qmutex_out));
	
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

	if ((dest == source) && (dest->type != EB_DEF_POOL)) // This would be a loop - but we allow it if it's a pool device because pool members need to be able to talk to each other 20240311
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

	if (eb_firewall(bridge_fw, packet) != EB_FW_ACCEPT)
	{
		eb_dump_packet (dest, EB_PKT_DUMP_DUMPED, packet, length);
		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound packet after packet firewalled", packet);

		return 0;
	}

	/* See if this was an INK reply to a priority packet, and drop flag fill if it was. If it was an ACK to a data packet we sent in resilience mode, send the final ACK on the wire */

	pthread_mutex_lock (&(dest->priority_mutex));

	if (dest->type == EB_DEF_WIRE && (packet->p.aun_ttype == ECONET_AUN_NAK || packet->p.aun_ttype == ECONET_AUN_INK || packet->p.aun_ttype == ECONET_AUN_ACK)
			)
	{
		eb_debug (0, 3, "WIRE", "%-8s %3d     Checking priority markers net (%3d = %3d), stn (%3d = %3d), seq (%08X = %08X), type (%02X = %02X), resilience mode %s, waiting for resilient ACK: %s",
			"", dest->net, 
			dest->p_net ? dest->p_net : dest->net, packet->p.srcnet, 
			dest->p_stn, packet->p.srcstn,
			dest->p_seq, packet->p.seq,
			ECONET_AUN_INK, packet->p.aun_ttype,
			dest->wire.resilience ? "ON" : "OFF",
			dest->p_isresilience ? "YES" : "NO"
			 );

		// Resilience mode implementation alongside the older INK implementation

		if ((dest->p_net == packet->p.srcnet || (dest->p_net == 0 && dest->net == packet->p.srcnet)) && dest->p_stn == packet->p.srcstn && dest->p_seq == packet->p.seq)
		{
			if (
				(dest->p_isresilience && packet->p.aun_ttype == ECONET_AUN_NAK)  // resilience and we got a NAK back
			|| 	(packet->p.aun_ttype == ECONET_AUN_INK) // priority and we got INK
			)
			{
				ioctl(dest->wire.socket, ECONETGPIO_IOC_READGENTLE); // Drop flag fill
	
				eb_debug (0, 3, "WIRE", "%-8s %3d    Dropping flag fill on failed immedaite / failed data transmission in resilience mode", "", dest->net);

				// Clear down. Whatever it was, we found it.

				dest->p_isresilience = dest->p_net = dest->p_stn = dest->p_seq = 0;
			}
			else if (dest->wire.resilience && dest->p_isresilience && packet->p.aun_ttype == ECONET_AUN_ACK)
			{
				// We've had an ACK back on a packet where we're holding flag fill prior to final 4-way ACK, so send the 4-way ACK. (If it never comes, another thread will drop flag fill.
				eb_debug (0, 3, "WIRE", "%-8s %3d.%3d Sending closing 4-way ACK", "", dest->net, dest->p_stn);
	
				ioctl(dest->wire.socket, ECONETGPIO_IOC_RESILIENTACK);

				// Clear down. Whatever it was, we found it.

				dest->p_isresilience = dest->p_net = dest->p_stn = dest->p_seq = 0;
			}

		}
	}

	pthread_mutex_unlock (&(dest->priority_mutex));

	if (dest->type == EB_DEF_WIRE && (packet->p.aun_ttype == ECONET_AUN_ACK || packet->p.aun_ttype == ECONET_AUN_NAK || packet->p.aun_ttype == ECONET_AUN_INK)) // Don't queue these 
	{
		
		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound ACK/NAK/INK to wire - not queued", packet);

		return 1;

	}

	eb_dump_packet (dest, EB_PKT_DUMP_PRE_O, packet, length);

	/*
	if (packet->p.dstnet == 0xff && packet->p.dststn == 0xff) // broadcast
		eb_debug (0, 2, "BCAST", "Broadcast being sent to %3d.%3d", dest->net, (dest->type == EB_DEF_LOCAL ? dest->local.stn : 0));
		*/

	// If we've got an IMMREP which matches our priority list on a wire device,
	// Put it on the head of the input queue, not the tail.

	if (!(q = eb_malloc(__FILE__, __LINE__, "Q-IN", "Create packetq structure", sizeof(struct __eb_packetqueue))))
	{
		eb_debug (0, 1, "BRIDGE", "malloc(input, packetqueue) failed for packet from %3d.%3d to %3d.%3d port &%02X ctrl &%02X length &%04X seq 0x%08lX",
			packet->p.srcnet,
			packet->p.srcstn,
			packet->p.dstnet,
			packet->p.dststn,
			packet->p.port,
			packet->p.ctrl,
			length,
			packet->p.seq
		);

		eb_free (__FILE__, __LINE__, "Q-IN", "Freeing inbound packet after malloc(packetq) failed", packet);
		result = 0;
	}
	else
	{
		pthread_mutex_lock (&(dest->qmutex_in));

		q->p = packet;
		q->last_tx.tv_sec = q->last_tx.tv_usec = 0;
		q->tx = 0;
		q->errors = 0;
		q->notlistening = 0;
		q->n = NULL;
		q->length = length;
		
		pthread_mutex_lock (&(dest->priority_mutex));

		// Trunk NAT (outbound) here - TODO

		// Prioritize replies to our priority flags - this will include IMMREP packets.

		// 20240606 Changed - looks like we have had the src/dst mapping wrong here for years! if (!dest->in || (dest->type == EB_DEF_WIRE && dest->p_net == packet->p.dstnet && dest->p_stn == packet->p.dststn && dest->p_seq == packet->p.seq))
		// But don't prioritise data/broadcast/immediate *query* packets which happen to turn up with matching net.stn/sequence

		if (!dest->in || (dest->type == EB_DEF_WIRE && dest->p_net == packet->p.srcnet && dest->p_stn == packet->p.srcstn && dest->p_seq == packet->p.seq && (packet->p.aun_ttype != ECONET_AUN_DATA && packet->p.aun_ttype != ECONET_AUN_BCAST && packet->p.aun_ttype != ECONET_AUN_IMM)))
		{
			q->n = dest->in;
			dest->in = q;

			dest->p_isresilience = dest->p_net = dest->p_stn = dest->p_seq = 0;

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

			eb_enqueue_output (d, q->p, q->length, NULL);
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

/* Implement a firewall chain without a policy, and recursively call sub-chains */

/* Implement a firewall chain on a packet traversing the bridge, and recursively call subchains.
 * Don't apply policy
   Used by the bridge transfer routines immediately prior to eb_enqueue_input()
   Returns EB_FW_ACCEPT or EB_FW_REJECT, or EB_FW_NOMATCH if not matched. Defaults to the defined default.
*/

uint8_t eb_firewall_inner (struct __eb_fw_chain *chain, struct __econet_packet_aun *p)
{

	uint8_t		result;
	struct __eb_fw	*f;

	if (!chain)
		return EB_FW_ACCEPT;

	//result = chain->fw_default;
	result = EB_FW_NOMATCH;

	f = chain->fw_chain_start;

	while (f)
	{
		// Note - the bridge firewall entries are bidirectional! - NOT ANY MORE!

		if (	(	(f->srcstn == 0x00 || f->srcstn == p->p.srcstn)
			&&	(f->srcnet == 0x00 || f->srcnet == p->p.srcnet)
			&&	(f->dststn == 0x00 || f->dststn == p->p.dststn)
			&&	(f->dstnet == 0x00 || f->dstnet == p->p.dstnet)
			&&	(f->port   == 0x00 || f->port   == p->p.port || (f->port == 0xFF && p->p.port == 0)) /* if you configure port 0xff in the FW entry, it will match port 0 in the packet */
			)
		)
		{
			if (f->action == EB_FW_CHAIN)
			{
				uint8_t inner_result;

				inner_result = eb_firewall_inner(f->fw_subchain, p);

				if (inner_result != EB_FW_NOMATCH)
				{
					result = inner_result;
					break;
				}
				// Otherwise we keep going through the current chain.
			}
			else
			{
				result = f->action;
				break;
			}
		}
		
		f = f->next;

	}

	eb_debug (0, 3, "FW", "FW       %3d.%3d from %3d.%3d eb_firewall_inner processing chain %s returned %s: P:&%02X, C:&%02X, Seq:&%08X", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, chain->fw_chain_name, (result == EB_FW_ACCEPT ? "ACCEPT" : (result == EB_FW_REJECT ? "REJECT" : "NO MATCH")), p->p.port, p->p.ctrl, p->p.seq);

	return result;

}

/* eb_firewall
 * Wrapper which applies default on a chain
 */

uint8_t eb_firewall (struct __eb_fw_chain *chain, struct __econet_packet_aun *p)
{

	uint8_t	result;

	if (!chain)
		return EB_FW_ACCEPT;

	result = eb_firewall_inner(chain, p);

	if (result == EB_FW_NOMATCH)
		result = chain->fw_default;

	if (result == EB_FW_REJECT)
		eb_debug (0, 2, "FW", "FW       %3d.%3d from %3d.%3d Firewall chain %s dropped traffic: P:&%02X, C:&%02X, Seq:&%08X (default = %02X)", p->p.dstnet, p->p.dststn, p->p.srcnet, p->p.srcstn, chain->fw_chain_name, p->p.port, p->p.ctrl, p->p.seq, chain->fw_default);

	return result;
}

/* 
 * Test to see whether a device should handle traffic.
 *
 * This is primarily to signal when a trunk or Econet device
 * should refuse to handle traffic except bridge keepalives
 * beacuse the interface is in an interface group. 
 *
 * However, it will also signal when a pipe interface
 * has no client connected and nothing should be 
 * sent to it.
 */

uint8_t	eb_device_usable (struct __eb_device *device)
{
	uint8_t		result = 1; /* Default usable */
	struct __eb_interface_member	*im;

	if (device->type == EB_DEF_PIPE && device->pipe.skt_write == -1) /* Pipe inactive */
		result = 0;
	else if (	(device->type == EB_DEF_TRUNK || device->type == EB_DEF_WIRE) /* Possible bridge connections */
		&&	(im = device->im) /* Don't set inactive if not a member of an IG */
		)
	{

		struct __eb_interface_member	*im_cursor;
		struct __eb_interface_group	*ig = im->ig;

		im_cursor = ig->first;

		result = 0; /* Default now disabled, unless we find ourselves as the first active group member */

		while (im_cursor)
		{

			uint8_t	dead = 0;
			time_t	last_rx;

			/* Whatever device we've found, let's see if it's active */

			/* Econets are always active - i.e. not dead - so we only check trunks */

			if (im_cursor->device->type == EB_DEF_TRUNK) /* Econets are always active */
			{
				pthread_mutex_lock (&(device->statsmutex));
				last_rx = device->last_rx;
				pthread_mutex_unlock (&(device->statsmutex));

				if (difftime(time(NULL), last_rx) > EB_CONFIG_TRUNK_DEAD_INTERVAL)
					dead = 1;
			}

			if (im_cursor == im) /* We've found ourselves in the list */
			{
				result = !dead;
				break;
			}
			else if (!dead) /* Something - which must be higher priority - is not dead, so our interface is inactive */
				break; /* Returns the default result = 0 */

			/* Find the next entry */

			im_cursor = im_cursor->next;
		}

	}

	return result;

}


/* Generic device listener loop
 */

static void * eb_device_listener (void * device)
{

	struct __eb_device	*d = device;	// Us
	struct pollfd		*p, *p_reset;
	uint16_t		numfd = 1; // Number of descriptors we're listening for - initially just the one

	p = eb_malloc (__FILE__, __LINE__, "LISTEN", "Allocate pollfd struct", sizeof(struct pollfd));
	p_reset = eb_malloc (__FILE__, __LINE__, "LISTEN", "Allocate pollfd reset struct", sizeof(struct pollfd));

	memcpy (p_reset, &(d->p_reset), sizeof(struct pollfd));

	if ((d->type == EB_DEF_LOCAL && d->local.ip.tunif[0] != '\0') || d->type == EB_DEF_PIPE)
		eb_debug (0, 2, "LISTEN", "%-8s %3d.%3d Device listener started (fd %d)", eb_type_str(d->type), d->net, (d->type == EB_DEF_LOCAL ? d->local.stn : d->pipe.stn), d->p_reset.fd);
	else if (d->type == EB_DEF_TRUNK)
		eb_debug (0, 2, "LISTEN", "%-8s %7d Device listener started (fd %d)", eb_type_str(d->type), d->trunk.local_port, d->p_reset.fd);
	else if (d->type != EB_DEF_LOCAL)
		eb_debug (0, 2, "LISTEN", "%-8s %3d     Device listener started (fd %d)", eb_type_str(d->type), d->net, d->p_reset.fd);

	memcpy (p, p_reset, sizeof(struct pollfd));

	eb_thread_ready();

	// If we are a local device, we have no need of a listener unless we're an IP gateway, So unless the IP gateway is live, die.
	// We do this after signalling ready so we don't get a threadcount mismatch. (Sounds like bedding...)

	if (d->type == EB_DEF_LOCAL && d->local.ip.tunif[0] == '\0')
		return NULL;
	
	if (d->type == EB_DEF_WIRE && !strcasecmp(d->wire.device, "/dev/null")) // Don't even bother
		return NULL;

	if (d->type == EB_DEF_TRUNK && d->trunk.mt_parent) // Multitrunk child - update the socket we're polling
	{
		pthread_mutex_lock(&(d->trunk.mt_mutex));
		if (!(d->trunk.mt_data)) // Not connected
		{
			pthread_cond_wait(&(d->trunk.mt_cond), &(d->trunk.mt_mutex));
			/* Connected by now */
			eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk now connected - device listener woken", eb_type_str(d->type), d->trunk.local_port);
		}
		p->fd = d->trunk.mt_data->trunk_socket[0];
		p_reset->fd = d->trunk.mt_data->trunk_socket[0];
		pthread_mutex_unlock(&(d->trunk.mt_mutex));
	}

	while (poll(p, 1, -1))
	{
		/* TODO - Handle multitrunk pipe disconnections here */

		if (p->revents & POLLHUP && d->type == EB_DEF_TRUNK && d->trunk.mt_parent) // Looks like our pipe to the MT parent has closed. Wait to be woken up again.
		{
			eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk disconnected - device listener sleeping", eb_type_str(d->type), d->trunk.local_port);
			pthread_mutex_lock(&(d->trunk.mt_mutex));
			pthread_cond_wait(&(d->trunk.mt_cond), &(d->trunk.mt_mutex));
			eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk now connected - device listener woken", eb_type_str(d->type), d->trunk.local_port);
			p->fd = d->trunk.mt_data->trunk_socket[0];
			p_reset->fd = d->trunk.mt_data->trunk_socket[0];
			pthread_mutex_unlock(&(d->trunk.mt_mutex));
			poll(p, 1, -1);
		}

		if ((p->revents & POLLHUP) && d->type == EB_DEF_PIPE && (d->pipe.skt_write != -1)) // Presumably PIPE - close writer socket
		{
			struct __eb_packetqueue 	*q, *q_next;
			char	readerfile[512];

			close (d->pipe.skt_write);
			d->pipe.skt_write = -1;

			eb_debug (0, 3, "LISTEN", "%-8s %3d.%3d Pipe client went away - closing writer socket", "Pipe", d->net, d->pipe.stn);

			// Close & re-open the reader socket

			close (d->pipe.skt_read);
			snprintf(readerfile, 510, "%s.tobridge", d->pipe.base);
			d->pipe.skt_read = open (readerfile, O_RDONLY | O_NONBLOCK | O_SYNC);

                        if (d->pipe.skt_read < 0) // Failed
                                eb_debug (1, 0, "DESPATCH", "%-8s %3d.%3d Cannot re-open pipe reader socket %s", "", d->net, d->
pipe.stn, readerfile);
                        else
                                eb_debug (0, 3, "DESPATCH", "%-8s %3d.%3d Pipe reader device %s re-opened", "", d->net, d->pipe.
stn, readerfile);
			d->p_reset.fd = d->pipe.skt_read;

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

			// Take the host out of the kernel stations map
			
			eb_clr_single_wire_host (d->net, d->pipe.stn);

			eb_debug (0, 3, "LISTEN", "Pipe     %3d.%3d Removed from kernel station map", d->net, d->pipe.stn);

		}

		if (p->revents & POLLIN && (!(p->revents & POLLHUP))) // Traffic has arrived from the device
		{
	
			if ((d->type == EB_DEF_PIPE) && (d->pipe.skt_write == -1))
			{
				char	pipewriter[128];

				eb_debug (0, 3, "LISTEN", "Pipe     %3d.%3d Pipe client connected - opening writer socket", d->net, d->pipe.stn);

				snprintf (pipewriter, 127, "%s.frombridge", d->pipe.base);

				d->pipe.skt_write = open (pipewriter, O_WRONLY | O_NONBLOCK | O_SYNC);

				if (d->pipe.skt_write == -1)
					eb_debug (0, 1, "LISTEN", "Pipe     %3d.%3d Failed to open writer socket %s: %s", d->net, d->pipe.stn, pipewriter, strerror(errno));
				else /* Successfully opened when the pipe client arrived - put it in the listen map on the wire */
				{
					eb_set_single_wire_host (d->net, d->pipe.stn);
					eb_debug (0, 3, "LISTEN", "Pipe     %3d.%3d Added to kernel station map", d->net, d->pipe.stn);
				}

			}

			pthread_cond_signal(&d->qwake);

		}

		// Reset poll structure
	
		memcpy (p, p_reset, sizeof(struct pollfd) * numfd);
		
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
		
		addrlen = sizeof(addr);

		length = recvfrom(e->socket, &(incoming.p.aun_ttype), sizeof(struct __econet_packet_aun), 0, (struct sockaddr *) &addr, &addrlen);

		if (length < 0)
			eb_debug (0, 2, "LISTEN", "%-8s %3d.%3d Error %d reading on exposure socket %d (%s)", "AUN", e->net, e->stn, errno, e->socket, strerror(errno));
		if (length < 8)
			eb_debug (0, 2, "LISTEN", "%-8s %3d.%3d Error reading on exposure socket %d (Runt packet < 8 bytes received)", "AUN", e->net, e->stn, errno, e->socket);
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

				uint8_t fw_result;

				eb_add_stats(&(source_device->statsmutex), &(source_device->b_out), length-12); // Traffic stats - this is the remote device generating output

				incoming.p.dstnet = e->net;
				incoming.p.dststn = e->stn;
				incoming.p.srcnet = source_device->net;
				incoming.p.srcstn = source_device->aun->stn;
				incoming.p.ctrl |= 0x80;

				if ((fw_result = eb_firewall(source_device->fw_out, &incoming)) == EB_FW_REJECT) // fw_out because this is traffic coming *from* the AUN device. fw_in is for traffic going *to* it.
				{
					eb_dump_packet (e->parent, EB_PKT_DUMP_DUMPED, &incoming, length - 8); // (Drop the header length)
				}
				else
				{
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
	
						//pthread_mutex_lock (&(my_parent->qmutex_out));
						pthread_mutex_lock (&(my_parent->aun_out_mutex));
	
						eb_debug (0, 4, "QUEUE", "%-8s %3d.%3d Locks acquired for incoming search of outq for packet to %3d.%3d P:&%02X C: &%02X Seq: 0x%08X Length 0x%04X, combo = 0x%04X", eb_type_str(my_parent->type), incoming.p.dstnet, incoming.p.dststn, incoming.p.srcnet, incoming.p.srcstn, incoming.p.port, incoming.p.ctrl, incoming.p.seq, length, combo);
	
						outq_parent = NULL;
						//outq = my_parent->out;
						outq = my_parent->aun_out_head;
	
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
								{
									//my_parent->out = outq->next;
									my_parent->aun_out_head = outq->next;
								}
		
								eb_free (__FILE__, __LINE__, "AUN-EXP", "Free outq after locating packet to splice out because of ACK/NAK", outq);
							}
						}

						pthread_mutex_unlock (&(my_parent->aun_out_mutex));
	
						pthread_cond_signal (&(my_parent->qwake));

					}

				}
	
				if (fw_result == EB_FW_ACCEPT)
				{
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
	
					/* AUN PROCESS */
						eb_debug (0, 4, "AUN", "                 source_device = %p, type %s, AUN Auto Ack is %s", source_device, eb_type_str(source_device->type), (source_device->config & EB_DEV_CONF_AUTOACK) ? "On" : "Off");
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

				// Credit to @sweh for spotting the bug here


				// See if this is a WIRE or NULL divert

				if (parent->type == EB_DEF_WIRE)
				{
					e->parent = parent;
					if (e->parent->wire.divert[e->stn]) // There was a wire divert
						e->parent = e->parent->wire.divert[e->stn];
				}
				else if (parent->type == EB_DEF_NULL && parent->null.divert[e->stn]) // Can only have diverts
					e->parent = parent->null.divert[e->stn];
				else if (parent->type == EB_DEF_TRUNK)
					e->parent = parent; // Just sent to trunk

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

/* Trunk keepalive generator, and dead detector
 */

static void * eb_trunk_keepalive (void * device)
{

	struct __econet_packet_aun	*p;
	struct __eb_device		*d;
	time_t				last_reset, last_rx;

	d = device;

	eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk keepalive thread started (tid %d)", eb_type_str(d->type), d->trunk.local_port, syscall(SYS_gettid));

	last_reset = 0; // To make sure we do a *first* reset...

	eb_thread_ready();

	while (1)
	{
		uint8_t		dead;

		p = eb_malloc (__FILE__, __LINE__, "TRUNK", "Memory for trunk keepalive packet", 12);
	
		if (!p)
			eb_debug (1, 0, "FSLIST", "Unable to malloc() new trunk keepalive packet");

		// Distant trunks ignore src/destination on trunk keepalives, so we don't need to worry about them

#pragma GCC diagnostic ignored "-Warray-bounds"
		p->p.srcstn = 0;
		p->p.srcnet = eb_bridge_sender_net(d);
		p->p.dststn = p->p.dstnet = 0xff;
		p->p.aun_ttype = ECONET_AUN_DATA;
		p->p.seq = 0x00000000;
		p->p.port = 0x9C; // Bridge traffic
		p->p.ctrl = EB_CONFIG_TRUNK_KEEPALIVE_CTRL;

#pragma GCC diagnostic warning "-Warray-bounds"

		// Send packet on trunk

		eb_enqueue_input (d, p, 0);
		pthread_cond_signal(&(d->qwake));


		if (!EB_CONFIG_NOKEEPALIVEDEBUG) eb_debug (0, 3, "BRIDGE", "%-8s %7d Trunk keepalive sent", eb_type_str(d->type), d->trunk.local_port);

		// Check last_rx to see if dead

		dead = 0;

		// See if it's dead
		pthread_mutex_lock (&(d->statsmutex));
		last_rx = d->last_rx;
		pthread_mutex_unlock (&(d->statsmutex));

		if (difftime(time(NULL), last_rx) > EB_CONFIG_TRUNK_DEAD_INTERVAL)
			dead = 1;

		if (dead) 
		{

			// If dynamic, clear the dynamic variables and signal disconnected

			if (d->trunk.is_dynamic)
			{
				pthread_mutex_lock (&(d->qmutex_in));

				if (!EB_CONFIG_NOKEEPALIVEDEBUG) eb_debug (0, 3, "DESPATCH", "%-8s %7d Trunk dead - clearing dynamic host data", eb_type_str(d->type), d->trunk.local_port);

				if (d->trunk.remote_host && d->trunk.remote_host->ai_addr) eb_free(__FILE__, __LINE__, "TRUNK", "Freeing trunk.remote_host.ai_addr structure", d->trunk.remote_host->ai_addr);
				if (d->trunk.remote_host) eb_free(__FILE__, __LINE__, "TRUNK", "Freeing trunk.remote_host structure", d->trunk.remote_host);
				if (d->trunk.hostname) eb_free(__FILE__, __LINE__, "TRUNK", "Freeing trunk.hostname string", d->trunk.hostname);

				d->trunk.remote_host = NULL;
				d->trunk.hostname = NULL;

				pthread_mutex_unlock (&(d->qmutex_in));
			}

			// Global bridge reset if our last reset was before the last reception time (so we don't constantly reset on a dead trunk)

			if (last_rx > last_reset)
			{
				if (!EB_CONFIG_NOKEEPALIVEDEBUG) eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk dead - sending bridge reset", eb_type_str(d->type), d->trunk.local_port);
				eb_bridge_reset(NULL);
				last_reset = time(NULL);
			}

		}

		usleep (EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL * 1000000); // Sleep

	}

	return NULL;
}

void send_printjob (char *handler, uint8_t fs_net, uint8_t fs_stn, uint8_t clt_net, uint8_t clt_stn, char *username, char *acorn_printer, char *unix_printer, char *file)
{

	char	command_string[1024];

	snprintf (command_string, 1023, "%s %d %d %d %d %s %s %s %s",
		handler == NULL ? PRN_DEFAULT_HANDLER : handler,
		fs_net, fs_stn,
		clt_net, clt_stn,
		username,
		unix_printer,
		acorn_printer,
		file);

	if (!fork())
		execl("/bin/sh", "sh", "-c", command_string, (char *) 0);

}

char * get_user_print_handler (uint8_t net, uint8_t stn, uint8_t printer_index, char *unixprinter, char *acornprinter)
{

	struct __eb_device	*d;
	struct __eb_printer	*printer;
	uint8_t			index;

	d = eb_find_station_internal (net, stn);

	if (!d)
		return NULL;

	if (d->type != EB_DEF_LOCAL)
		return NULL; // Not a local device

	printer = d->local.printers;

	index = printer_index;

	if (index != 0xff)
		while ((index-- > 0) && printer)
			printer = printer->next;	

	if (!printer)
		return NULL;
	else
	{
		strcpy(unixprinter, printer->unix_name);
		strcpy(acornprinter, printer->acorn_name);
		if (printer->handler[0] == '\0')
			return PRN_DEFAULT_HANDLER;
		else
			return printer->handler;
	}

}

void beeb_print (uint8_t y, uint8_t x, char *s) /* Display string in beebmem at x,y */
{
	memcpy(&(beebmem[0x7c00 + (40 * y) + x]), s, strlen(s));

}

// Used by the FS to notify when a bridge privileged user logs in or out
void eb_fast_priv_notify(struct __eb_device *d, uint8_t net, uint8_t stn, uint8_t mode)
{
	if (mode)
	{
		ECONET_SET_STATION(d->local.fast_priv_stns, net, stn);
	}
	else
	{
		ECONET_CLR_STATION(d->local.fast_priv_stns, net, stn);
	}
}

// printf() equivalent but puts the stuff on our pipe to the IO handler
void fastprintf (struct __eb_device *d, char *fmt, ...)
{

	va_list ap;
	char str[16384];

	va_start(ap, fmt);

	vsnprintf (str, 16382, fmt, ap);

	va_end(ap);

	write (d->local.fast_to_handler[0], str, strlen(str));
	pthread_cond_signal(&(d->local.fast_wake)); // Wake up the IO thread

}

// Send a *fast input ready notification
void eb_fast_input_ready(struct __eb_device *d, uint8_t net, uint8_t stn, uint8_t cmd)
{
	struct __econet_packet_aun *reply;

	reply = eb_malloc(__FILE__, __LINE__, "FAST", "Allocate input request packet", ECONET_MAX_PACKET_SIZE);

	if (!reply)
		eb_debug (1, 0, "FAST", "Failed to allocate input request packet structure");

	reply->p.port = 0x00; 
	reply->p.ctrl = 0x84;
	reply->p.seq = eb_get_local_seq(d);
	reply->p.dstnet = net;
	reply->p.dststn = stn;
	reply->p.srcnet = d->net;
	reply->p.srcstn = d->local.stn;
	reply->p.aun_ttype = ECONET_AUN_DATA;

	reply->p.data[0] = 0xff;
	reply->p.data[1] = 0xff;
	reply->p.data[2] = 0xff;
	reply->p.data[3] = 0xff;
	reply->p.data[4] = d->local.stn;
	reply->p.data[5] = (d->net == net) ? 0 : d->net;
	reply->p.data[6] = cmd; // See if this is it!

	eb_enqueue_output(d, reply, 7, NULL);
	pthread_cond_signal(&(d->qwake));
}

// Thread to mediate IO between despatcher and the *FAST handler
static void * eb_fast_io_handler (void *device)
{

	struct __eb_device 	*d = device;
	struct pollfd		fds;

	eb_debug (0, 2, "FAST", "FAST     %3d.%3d Initializing *FAST IO handler thread", d->net, d->local.stn);

	pthread_mutex_lock(&(d->local.fast_io_mutex));

	while (1)
	{

		eb_debug (0, 3, "FAST", "Fast Handler Loop - client ready = %d, about to sleep", d->local.fast_client_ready);

		// the cond wait will release the mutex, wait on the signal, and re-acquire the mutex on wake - so we don't need to tinker with it

		pthread_cond_wait(&(d->local.fast_wake), &(d->local.fast_io_mutex));

		eb_debug (0, 3, "FAST", "Fast Handler Loop - client ready = %d, just woken", d->local.fast_client_ready);
		// Look for reset here and if so, sink everything coming from the handler
		// How shall we sink the input from both handler and despatcher?

		// We don't bother with input from client - it goes straight from despatch to the handler

		// If fast_client_ready, read up to 32 bytes from fast_to_handler[1] and put it on the output queue; reset fast_client_ready to 0

		fds.fd = d->local.fast_to_handler[1];
		fds.events = POLLIN;
		fds.revents = 0;

		if ((d->local.fast_client_ready == EB_FAST_READY) && poll(&fds, 1, 0) && (fds.revents & POLLIN))
		{
			unsigned char	t[33];
			uint8_t		s;


			s = read(d->local.fast_to_handler[1], t, 32);

			if (s)
			{
				struct __econet_packet_aun 	*p;

				// Now indicate not ready and wait for it to reset

				//eb_debug (0, 3, "FAST", "Fast Handler Read from Handler - s = %d", s);

				d->local.fast_client_ready = EB_FAST_NOTREADY;

				p = eb_malloc(__FILE__, __LINE__, "FAST", "Allocate fast output packet", ECONET_MAX_PACKET_SIZE);

				if (!p)
					eb_debug (1, 0, "FAST", "Unable to allocate memory for *FAST output packet");

				p->p.srcstn = d->local.stn;
				p->p.srcnet = d->net;
				p->p.dststn = d->local.fast_client_stn;
				p->p.dstnet = d->local.fast_client_net;
				p->p.aun_ttype = ECONET_AUN_DATA;
				p->p.port = 0xA0;
				p->p.ctrl = 0x80 | d->local.fastbit; d->local.fastbit ^= 0x01;
				p->p.seq = eb_get_local_seq(d);
				memcpy(&(p->p.data), t, s);

				eb_debug (0, 3, "FAST", "Fast Handler Loop - if(ready) succeeded - transmitting output to device %p, packet at %p, length %d to %d.%d", d, p, s, p->p.dstnet, p->p.dststn);
				eb_enqueue_output(d, p, s, NULL);
				pthread_cond_signal(&(d->qwake));
				eb_fast_input_ready(d, d->local.fast_client_net, d->local.fast_client_stn, EB_FAST_READY);

				eb_free(__FILE__, __LINE__, "FAST", "Free fast output packet", p);
			}
		}
		else
			eb_debug (0, 3, "FAST", "Fast Handler Loop - if(ready) failed: client ready = %d, revents is %s", d->local.fast_client_ready, (fds.revents & POLLIN) ? "set" : "unset");
	}

	return NULL;
}

/* Return keypress (blocking) or 0xff if new logon or client signalled close */
uint8_t eb_fast_getkey (struct __eb_device *d)
{

	int				s = d->local.fast_to_handler[0];
	uint8_t				c, quit = 0;
	struct pollfd			fds;
	int				pollresult;

	eb_fast_input_ready(d, d->local.fast_client_net, d->local.fast_client_stn, EB_FAST_READY);

	fds.fd = s;
	fds.events = POLLIN;

	pollresult = poll(&fds, 1, 100); // 100ms poll

	while (!quit)
	{
		if (pollresult)
			read(s, &c, 1);

		pthread_mutex_lock(&(d->local.fast_io_mutex));
		// When logged on, the fast client ready state will be EB_FAST_READY (client has signalled it wants output), or EB_FAST_NOTREADY (logged on, but not ready for output). If it's neither of those, then the client has either started a new session (EB_FAST_LOGON), or has requested severance of the connection (EB_FAST_CLOSE) - so signal quit
		if (d->local.fast_client_ready != EB_FAST_READY && d->local.fast_client_ready != EB_FAST_NOTREADY)
			quit = 1;
		pthread_mutex_unlock(&(d->local.fast_io_mutex));

		if (pollresult && !quit)
			return c;

		fds.fd = s;
		fds.events = POLLIN;

		pollresult = poll(&fds, 1, 100); // 100ms poll

	}

	return 0xff; // Nothing read - give up

}

/* Return 0xFF if new logon or client signalled close */
uint8_t eb_fast_getstring (struct __eb_device *d, int s, uint8_t len, char *string)
{

	unsigned char	c;
	uint8_t		ptr = 0;

	*string = 0; // Initialize

	while ((c = eb_fast_getkey(d)))
	{
		if (c == 0xff) break;

		if (c == 0x0D) // Enter
			break;
		else if (c == 0x7F)
		{
			if (ptr > 0)
			{
				string[ptr-1] = 0;
				ptr--;
				fastprintf (d, "%c%c%c", 0x08, 0x20, 0x08);
			}
		}
		else if (ptr < len)
		{
			fastprintf (d, "%c", c);
			string[ptr] = c;
			string[ptr+1] = 0;
			ptr++;
		}
	}

	if (c == 0xff)
		return 0xff;

	return ptr;
}

// Print FS disc names in order (for *FAST handler)

uint8_t eb_fast_printdiscs (struct __eb_device *d)
{

	uint8_t 	count;
	uint8_t		max_discs;

	max_discs = fs_get_maxdiscs();

	for (count = 0; count < max_discs; count++)
	{
		unsigned char	discname[128];

		fsop_get_disc_name (d->local.fs.server, count, discname);

		fastprintf (d, "%1x: %02d - %s\r\n", count, count, discname);
	}

	return max_discs;
}

// Thread to handle *FAST
static void * eb_fast_handler (void *device)
{
	struct __eb_device		*d = device;
	int				s = d->local.fast_to_handler[0];
	uint8_t				state;

	eb_debug (0, 2, "FAST", "FAST     %3d.%3d Initializing *FAST server thread", d->net, d->local.stn);

	pthread_mutex_lock (&(d->local.fast_io_mutex));
	d->local.fast_thread_alive = 1;
	pthread_mutex_unlock (&(d->local.fast_io_mutex));

	// Wait for client to say it wants stuff to display
	
fast_handler_reset:

	pthread_mutex_lock(&(d->local.fast_io_mutex));
	while (d->local.fast_client_ready == 0)
	{
		pthread_mutex_unlock(&(d->local.fast_io_mutex));
		sleep(1);
		pthread_mutex_lock(&(d->local.fast_io_mutex));
	}

	state = d->local.fast_client_ready;

	pthread_mutex_unlock(&(d->local.fast_io_mutex));

	eb_fast_input_ready (d, d->local.fast_client_net, d->local.fast_client_stn, EB_FAST_READY);

	while (state == 1) { 

		unsigned char	key, key2;
		struct pollfd	fds;
		struct utsname	u;

		// Print main menu
	
		uname (&u);

		fastprintf(d, "%c*** Pi Econet Bridge Console\r\n*** Station: %d.%d\r\n\n",
				0x0C, d->net, d->local.stn);

		if (fsop_is_enabled(d->local.fs.server))
		{
			fastprintf (d, "  A: Alter fileserver parameters\r\n");
			fastprintf (d, "  F: Display fileserver info\r\n");
			fastprintf (d, "  S: Shut down file server\r\n");
		}
		else
		{
			fastprintf (d, "  B: Boot/Restart file server\r\n");
			fastprintf (d, "  R: Rename disc\r\n");
			fastprintf (d, "  C: Format new disc\r\n");
		}
		fastprintf (d, "  P: Clear SYST pw\r\n");
		fastprintf (d, "  X: Shut down the Pi Bridge\r\n"); // Only display if has BRIDGE priv
		fastprintf (d, "  Q: Quit\r\n"); 
	
		fastprintf (d, "\r\n  Command: "); // Only display if has BRIDGE priv
	
		eb_debug (0, 2, "FAST", "FAST     %3d.%3d Main menu sent", d->net, d->local.stn);

		key = 0;

		fds.fd = s;
		fds.events = POLLIN;
		fds.revents = 0;

		if (poll(&fds, 1, 100000) == 1 && (fds.revents & POLLIN) && (key = eb_fast_getkey(d)) && key != 0xff)
		{

			fastprintf (d, "%c", key);

			key &= 0xDF;

			switch (key) {
				case 'A':
					{
						uint8_t 	finished = 0;
						uint32_t	params;
						uint8_t		fnlength;

						pthread_mutex_lock (&(d->local.fs.server->fs_mutex));
						fsop_get_parameters (d->local.fs.server, &params, &fnlength);
						pthread_mutex_unlock (&(d->local.fs.server->fs_mutex));

						while (!finished)
						{

							fastprintf (d, "%c*** Alter FS parameters on %d.%d\r\n\n", 0x0C, d->net, d->local.stn);
							fastprintf (d, " A: Acorn home dir permssions:  %s\r\n", (params & FS_CONFIG_ACORNHOME) ? "On" : "Off");
							fastprintf (d, " S: SJ MDFS functionality:      %s\r\n", (params & FS_CONFIG_SJFUNC) ? "On" : "Off");
							fastprintf (d, " C: Use : for / in filesystem:  %s\r\n", (params & FS_CONFIG_INFCOLON) ? "On" : "Off");
							fastprintf (d, " I: MDFS extended *INFO:        %s\r\n", (params & FS_CONFIG_MDFSINFO) ? "On" : "Off");
							fastprintf (d, " D: Acorn Directory display (D/)%s\r\n", (params & FS_CONFIG_MASKDIRWRR) ? "On" : "Off");
							fastprintf (d, " F: Filename length:            %d\r\n", fnlength);

							// Do stuff here
							fastprintf (d, "\n Q: Quit to main menu\r\n\n Select option: ");
							key2 = eb_fast_getkey(d);

							switch (key2)
							{
								case 'A': params ^= FS_CONFIG_ACORNHOME; break;
								case 'S': params ^= FS_CONFIG_SJFUNC; break;
								case 'C': params ^= FS_CONFIG_INFCOLON; break;
								case 'I': params ^= FS_CONFIG_MDFSINFO; break;
								case 'D': params ^= FS_CONFIG_MASKDIRWRR; break;
								case 'F': 
								  { 
									char	newlength[3];
									uint8_t	l;
								
									fastprintf (d, "\r\n\n New length (10-79): ");
									eb_fast_getstring (d, s, 2, newlength);
									
									l = atoi(newlength);

									if (l < 10 || l > 79)
									{
										fastprintf (d, "\r\n\n*** Bad filename length. Press a key.");
										key2 = eb_fast_getkey(d);
									}
									else
										fnlength = l;

								  } break;
								case 0xFF:
								case 'Q':
									{
										fastprintf (d, "\r\n\n Save Y/N ? ");

										key2 = eb_fast_getkey(d);

										while (key2 != 0xFF && (key2 & 0xDF) != 'Y' && (key2 & 0xDF) != 'N')
										{
											if (key2 == 0xFF) 
											{
												finished = 1;
												break;
											}
											else key2 = eb_fast_getkey(d);
										}

										if ((key2 & 0xDF) == 'Y')
										{
											pthread_mutex_lock(&fs_mutex);
											fsop_set_parameters(d->local.fs.server, params, fnlength);
											pthread_mutex_unlock(&fs_mutex);
										}

										finished = 1;
									} break;
							}
						}
					} break;
				case 'F':
					{
						uint8_t 	count;
						uint8_t		max_discs;

						fastprintf (d, "%c*** FS info on server %d.%d\r\n",
							0x0C, d->net, d->local.stn);
						fastprintf (d, "*** Hostname: %s\r\n*** OS: %s %s\r\n*** Architecture: %s\r\n", 
							u.nodename, u.sysname, u.release, u.machine);
	
						if (d->local.ip.tunif[0])
							fastprintf (d, "*** Eco IP Address: %s\r\n", d->local.ip.addr);

						fastprintf (d, "\n*** Discs:\r\n");
						max_discs = fs_get_maxdiscs();

						for (count = 0; count < max_discs; count++)
						{
							unsigned char	discname[128];

							fsop_get_disc_name (d->local.fs.server, count, discname);
							if (discname[0]) fastprintf (d, "%02d:%-16s ", count, discname);
						}

						fastprintf (d, "\r\n");

						if (d->local.printers)
						{
							struct __eb_printer	*p;

							p = d->local.printers;

							fastprintf (d, "\n*** Printers:\r\n");

							while (p)
							{
								fastprintf (d, "%-20s", p->acorn_name);
								p = p->next;
							}

						}
						else	fastprintf (d, "\n*** No printers configured\r\n");

						fastprintf (d, "\r\n\nPress a key...");
						key2 = eb_fast_getkey(d);
					} break;
				case 'S': // Shut down local fileserver
				case 'B': // Start up fileserver (the code does both depending on fileserver state, but only one of the two options is displayed on screen)
					if (fsop_is_enabled(d->local.fs.server))
					{
						if (key == 'B')
							fastprintf (d, "\r\n\n*** ERROR: Fileserver on %d.%d already startedr\n\n", d->net, d->local.stn);
						else
						{
							pthread_mutex_lock(&(d->local.fs.server->fs_mutex));
							d->local.fs.server->enabled = 0;
							pthread_mutex_unlock(&(d->local.fs.server->fs_mutex));
							pthread_cond_signal(&(d->local.fs.server->fs_condition));
							fastprintf (d, "\r\n\n*** Fileserver on %d.%d has shut down\r\n\n", d->net, d->local.stn);
						}
					}	
					else
					{
						if (key == 'S')
							fastprintf (d, "\r\n\n*** ERROR: Fileserver on %d.%d not active\r\n\n", d->net, d->local.stn);
						else
						{
							d->local.fs.server = fsop_initialize (d, d->local.fs.rootpath, d->local.fs.tapehandler, d->local.fs.tapecompletionhandler);
							if (d->local.fs.server)
							{
								int r;
								r = fsop_run(d->local.fs.server);

								switch (r)
								{
									case 0:
										{
											fastprintf (d, "\r\n\n*** Fileserver on %d.%d would not start\r\n\n", d->net, d->local.stn);
										} break;
									case -1:
										{
											fastprintf (d, "\r\n\n*** Fileserver on %d.%d was already running\r\n\n", d->net, d->local.stn);
										} break;
									case 1:
										{
											fastprintf (d, "\r\n\n*** Fileserver on %d.%d booted successfully\r\n\n", d->net, d->local.stn);
										} break;
									default:
										{
											fastprintf (d, "\r\n\n*** Fileserver on %d.%d boot returned unknown result\r\n\n", d->net, d->local.stn);
										} break;
								}
							}
							else
								fastprintf (d, "\r\n\n*** ERROR: Fileserver on %d.%d BOOT FAILED\r\n\n", d->net, d->local.stn);

						}
					}
					fastprintf (d, "Press any key...");
					key2 = eb_fast_getkey(d);
					break;
				case 'P': 
					{
						fastprintf (d, " Are you sure (y/n)?");
						key2 = eb_fast_getkey(d);
						if (key2 == 0xff) break;
						key2 &= 0xDF; // convert lower to caps
						while (key2 != 'Y' && key2 != 'N')
						{
							read (s, &key2, 1);
							key2 &= 0xDF;
						}

						if (key2 == 'Y')
						{
							// Do stuff here
							if (fsop_clear_syst_pw(d->local.fs.server))
								fastprintf (d, "\r\n\n*** SYST password cleared.");
							else
								fastprintf (d, "\r\n\n*** ERROR: SYST password not cleared.");

							fastprintf (d, "\r\n\nPress any key...");

							key2 = eb_fast_getkey(d);
						}
					} break;
				case 'R':
				case 'C':
					{
						uint8_t 	max_discs;

						fastprintf (d, "%c*** ", 0x0C);
						if (key == 'R')
							fastprintf (d, "Rename fileserver disc\r\n\n", 0x0C);
						else
							fastprintf (d, "Format fileserver disc\r\n\n", 0x0C);

						max_discs = eb_fast_printdiscs (d);

						if (key == 'R')
							fastprintf (d, "\nRename ");
						else if (key == 'C')
							fastprintf (d, "\nFormat ");
						
						fastprintf (d, "which disc (<Q>uit)? ");

						key2 = eb_fast_getkey(d);
						if (key2 == 0xff) break;
						if ( key2 != 'Q' && key2 != 'q' &&
							(((max_discs <= 10) && ((key2 < '0') || (key2 >= ('0' + max_discs))))
						|| 	((max_discs > 10) && !( (key2 >= '0' && key2 <= '9') || (key2 >= 'A' && key2 <= ('A' + max_discs - 10))))
						)
						)
						{
							fastprintf (d, "\r\n\n*** ERROR: Invalid input. Press a key.");
							key2 = eb_fast_getkey(d);
							if (key2 == 0xff) break;
						}
						else if (key2 == 'Q' || key2 == 'q')
						{
							fastprintf (d, "\r\n\n*** Press a key.");
							key2 = eb_fast_getkey(d);
							if (key2 == 0xff) break;
						}
						else
						{
							unsigned char		discname[128], new_discname[17];
							uint8_t		discnumber;

							fastprintf (d, "%c\r\n\n", key2);

							discnumber = key2 - '0';
							if (discnumber > 9)
								discnumber -= 7;

							fsop_get_disc_name (d->local.fs.server, discnumber, discname);
							if (key == 'R' && strlen((char *) discname) == 0)
								fastprintf (d, "*** ERROR: Disc does not exist.");
							else if (key == 'C' && strlen((char *) discname) > 0)
								fastprintf (d, "*** ERROR: Disc already formatted.");
							else
							{
								uint8_t	discname_len;

								fastprintf (d, "New name for disc %d: ", discnumber);
								discname_len = eb_fast_getstring (d, s, 16, (char *) new_discname);

								if (discname_len == 0xff) // Connection sever
									break;
								else if (discname_len == 0)
									fastprintf (d, "\r\n\n*** ERROR: Bad name");
								else
								{
									fastprintf (d, "\r\n\n%s disc %d as %s\r\n", (key == 'C' ? "Creating" : "Renaming"), discnumber, new_discname);

									fsop_set_disc_name (d->local.fs.server, discnumber, new_discname);
								}
							}

							fastprintf (d, "\r\n\nPress any key...");
							key2 = eb_fast_getkey(d);
						}
					} break;
				case 'Q':
					{
						eb_fast_input_ready(d, d->local.fast_client_net, d->local.fast_client_stn, EB_FAST_CLOSE);
						pthread_mutex_lock(&(d->local.fast_io_mutex));
						d->local.fast_client_ready = 0; // Go back to logon
						pthread_mutex_unlock(&(d->local.fast_io_mutex));
					} break;
				case 'X':
					{
						uint8_t	key2;

						fastprintf (d, "\r\n*** Shut down Pi - Are you sure?");		
						key2 = eb_fast_getkey(d);
						if (key2 == 0xFF) break; // Connection sever
						key2 &= 0xDF; // convert lower to caps
						while (key2 != 'Y' && key2 != 'N')
						{
							key2 = eb_fast_getkey(d);
							if (key2 == 0xFF) break; // Connection sever
							key2 &= 0xDF;
						}

						if (key2 == 'Y')
						{
							fastprintf (d, "\r\n\n*** Pi shutting down.");

							if (!fork())
							{
								/* Grab root privs */

								if (!seteuid(0))
									execl ("/usr/sbin/shutdown", "shutdown", "-h", "now", (char *) 0);
							}

							while (1)
								sleep(100); // Sleep forever

						}

					} break;
				case 0: break;
				default:
					fastprintf (d, "\r\n\n  Not implemented yet. Press a key.");
					key = eb_fast_getkey(d);
				break;
			}
		}

		pthread_mutex_lock(&(d->local.fast_io_mutex));
		state = d->local.fast_client_ready;
		if (state != 1)
			d->local.fast_client_ready = EB_FAST_LOGON;
		pthread_mutex_unlock(&(d->local.fast_io_mutex));
	} 

	goto fast_handler_reset;

	return NULL;

}

/* 
 * Notify logger for local emulation devices
 *
 */

static void * eb_notify_watcher (void * device)
{
	struct __eb_device		*d = device;
	struct __eb_notify		*l, *parent, *n;

	while (1)
	{
		sleep (2);

		pthread_mutex_lock (&(d->local.notify_mutex));

		/* Scan the list & print */

		parent = NULL;
		l = d->local.notify;

		while (l)
		{
			time_t	t;

			t = time(NULL);

			n = l->next;

			if ((t - l->last_rx) > 2) // 2 second timeout to display
			{
				eb_debug (0, 1, "NOTIFY", "%-8s %3d.%3d from %3d.%3d NOTIFY: %s", "Local", l->net, l->stn, d->net, d->local.stn, l->msg);

				/* Splice out */

				if (!parent)
					d->local.notify = l->next;
				else
					parent->next = l->next;

				eb_free (__FILE__, __LINE__, "NOTIFY", "Free notify structure", l);

			}
			else	parent = l;

			l = n;
		}

		pthread_mutex_unlock (&(d->local.notify_mutex));

	}

	return NULL;
}

/* Put a packetqueue entry on the AUN output queue for a device */
/*
 * Returns:
 *
 * 0 - Free your packet queue - it's going nowhere
 * 1 - Success
 */


uint8_t eb_aunpacket_to_aun_queue (struct __eb_device *d, struct __eb_device *destdevice, struct __econet_packet_aun *p, uint16_t length)
{

	struct __eb_aun_exposure	*exp;
	struct __eb_outq		*aun_out;
	struct __eb_packetqueue 	*pq, *skip;

	/* Put it on our AUN queue and wake the AUN sender */

	exp = eb_is_exposed(p->p.srcnet, p->p.srcstn, 1); /* 1 = must be active */

	if (exp) /* Exposed. If not, packet gets dumped anyway */
	{
		eb_debug (0, 4, "DESPATCH", "%-8s %3d     Traffic from %3d.%3d to %3d.%3d being put on AUN Output queue", 
				eb_type_str(d->type),
				d->net,
				p->p.srcnet,
				p->p.srcstn,
				p->p.dstnet,
				p->p.dststn);

		pthread_mutex_lock(&(d->aun_out_mutex));

		aun_out = d->aun_out_head;

		/* Find queue for this device */

		while (aun_out)
		{
			if (aun_out->destdevice == destdevice)	/* Found it */
				break;
			else
				aun_out = aun_out->next;
		}

		if (!aun_out) /* No outq for this device, make one */
		{
			aun_out = eb_malloc (__FILE__, __LINE__, "DESPATCH", "Create new AUN outq entry", sizeof(struct __eb_outq));

			/* eb_malloc() does a zero-out */

			aun_out->next = d->aun_out_head;
			d->aun_out_head = aun_out;
			aun_out->destdevice = destdevice;
			aun_out->p = NULL;
			aun_out->destcombo = (p->p.dstnet << 8) | (p->p.dststn); // Used by the AUN listener to take things out of the outbound queue

			/* is_aun_output not used - this is an AUN queue, we just do it by device */
		}

		pq = eb_malloc (__FILE__, __LINE__, "DESPATCH", "Create new AUN packetqueue entry", sizeof(struct __eb_packetqueue));

		pq->p = p;
		pq->last_tx.tv_sec = 0;
		pq->tx = 0;
		pq->errors = 0;
		pq->length = length;
		pq->n = NULL;

		skip = aun_out->p;

		while (skip && skip->n)
			skip = skip->n;

		if (skip)
			skip->n = pq;
		else
			aun_out->p = pq;

		eb_dump_packet (d, EB_PKT_DUMP_PRE_O, pq->p, pq->length);

		/* Unlock */

		pthread_mutex_unlock(&(d->aun_out_mutex));

		/* Wake up the AUN thread */

		pthread_cond_signal(&(d->aun_out_cond));

		/* Job done */

		return 1;
	}
	else	return 0;

}

/* 
 * Generic AUN tx thread
 */

static void * eb_device_aun_sender (void *device)
{
	struct __eb_device		*d = device;
	char				devstring[20];

	/* 
	 * The device as an AUN outqueue (head, tail pointed to by d->aun_out_head, aun_out_tail).
	 *
	 * The main despatcher puts outbound AUN on that outqueue, locked by aun_out_mutex.
	 *
	 * This loop reads that queue, sleeping on aun_out_cond for the minimum time before
	 * another packet remaining on the queue needs to be retransmitted. It then
	 * loops down the queue and does the retransmissions.
	 *
	 * The timeout will always be the AUN retransmission time (set in config).
	 * But when the condition sleep wakes early (because it is told of new traffic
	 * on the queue head), the loop will detect that remaining packets on the queue
	 * have not expired their timer and will keep track of the lowest time to sleep
	 * until one of them needs another re-tx. It will then sleep for that lower time
	 * rather than the usual inter-packet gap.
	 *
	 * Packets are taken off the queue in two circumstances:
	 *
	 * (a) Maximum re-tx limit reached
	 * (b) An ACK, NAK or INK (special packet for bridge to bridge signalling of an
	 * Econet Immediate which got 'Not listening' on a distant wire) arrives.
	 */

	eb_thread_ready();

	sprintf (devstring, "%-8s ", eb_type_str(d->type));

	if (d->type == EB_DEF_WIRE || d->type == EB_DEF_TRUNK || d->type == EB_DEF_POOL)
	{
		if (d->type == EB_DEF_TRUNK)
			sprintf (devstring, "%-8s %7d", eb_type_str(d->type), d->trunk.local_port);
		else
			sprintf (devstring, "%-8s %3d    ", eb_type_str(d->type), d->net);
	}
	else
		sprintf(devstring, "%-8s %3d.%3d", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE) ? d->pipe.stn : d->local.stn);

	eb_debug (0, 2, "AUNSEND", "%-16s AUN Sender thread starting", devstring);

	pthread_mutex_lock (&d->aun_out_mutex);

	while (1)
	{
		struct timespec		wait;
		uint16_t		min_sleep;
		struct __eb_outq	*o, *o_next, *o_parent; /* List of output queues for this thread */
		struct __eb_packetqueue	*p, *p_next, *p_parent; /* Packet queue within the outq */

		/* On entry to this loop, mutex is locked - either at the start before
		 * the while(), or by the return from the cond_wait
		 */

		eb_debug (0, 4, "AUNSEND", "%16s Loop starting", devstring);

		min_sleep = EB_CONFIG_AUN_RETX; // Main AUN retransmit interval in ms 

		o = d->aun_out_head;
		o_parent = NULL;

		/* Clear out outqueues where the device has gone away */

		while (o)
		{
			eb_debug (0, 4, "AUNSEND", "%16s Loop looking at outq %p to see if device has gone away", devstring, o);

			o_next = o->next;

			if (!o->destdevice) /* Destination went away - dump this queue */
			{
				eb_debug (0, 4, "AUNSEND", "%-8s     %3d Exposure not known - dumping this queue (%p)", eb_type_str(d->type), d->net, o);

				p = o->p;

				while (p)
				{
					p_next = p->n;
					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "AUNSEND", "%-8s %3d.%3d Thread freeing packet data at %p in packetqueue %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p->p, p);
					else
						eb_debug (0, 4, "AUNSEND", "%-8s %3d     Thread freeing packet data at %p in packetqueue %p", eb_type_str(d->type), d->net, p->p, p); 

					eb_free (__FILE__, __LINE__, "AUNSEND", "Freeing packet within packet queue - Destination device unknown", p->p);

					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "AUNSEND", "%-8s %3d.%3d Thread freeing packetqueue %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p);
					else
						eb_debug (0, 4, "AUNSEND", "%-8s %3d     Thread freeing packetqueue %p", eb_type_str(d->type), d->net, p); 

					eb_free (__FILE__, __LINE__, "AUNSEND", "Freeing packetq - Destination device unknown", p);

					p = p_next;
				}

				if (o_parent)
					o_parent->next = o_next;
				else
					d->aun_out_head = o_next;

				if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
					eb_debug (0, 4, "AUNSEND", "%-8s %3d.%3d Thread freeing outq at %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), o);
				else
					eb_debug (0, 4, "AUNSEND", "%-8s %3d     Thread freeing outq at %p", eb_type_str(d->type), d->net, o);

				eb_free (__FILE__, __LINE__, "AUNSEND", "Freeing outq when destination unknown", o);

			}
			else	o_parent = o; /* This entry's device hasn't gone away, so update parent */
				
			o = o_next; // Move to next in queue

		}

		d->aun_out_tail = o_parent;

		/* Now send what's left */

		o = d->aun_out_head;
		o_parent = NULL;

		eb_debug (0, 4, "AUNSEND", "%16s Output queue head is %p", devstring, o);

		while (o)
		{
			o_next = o->next;

			p = o->p;
			p_parent = NULL;
			
			eb_debug (0, 4, "AUNSEND", "%16s Looking at outq %p to send traffic, packetqueue head is %p", devstring, o, p);

			while (p)
			{
				struct __eb_aun_exposure	*exp;

				uint16_t	timediff;
				struct timeval	now;

				gettimeofday (&now, 0);

				p_next = p->n;

				exp = eb_is_exposed (p->p->p.srcnet, p->p->p.srcstn, 1); /* 1 = must be active */

				if (!exp || (p->tx++ == EB_CONFIG_AUN_RETRIES)) /* Too many attempts - splice */
				{
					/* Don't print the packet dump if the destination device is AUN & has autoack, because something else will already have done it */
					if (
						(
						 !((o->destdevice->config & EB_DEV_CONF_AUTOACK) && (p->p->p.aun_ttype == ECONET_AUN_ACK || p->p->p.aun_ttype == ECONET_AUN_NAK))
						) 
					&& 	(p->p->p.aun_ttype != ECONET_AUN_INK && p->p->p.aun_ttype != ECONET_AUN_IMMREP)
					) 
						eb_dump_packet (d, EB_PKT_DUMP_DUMPED, p->p, p->length);

					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "AUNSEND", "%-8s %3d.%3d Freeing packet data at %p in packetqueue %p on outq %p (TX attempts exceeded or not exposed)", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p->p, p, o);
					else
						eb_debug (0, 4, "AUNSEND", "%-8s %3d     Freeing packet data at %p in packetqueue %p on outq %p (TX attempts exceeded or not exposed)", eb_type_str(d->type), d->net, p->p, p, o); 

					eb_free (__FILE__, __LINE__, "AUNSEND", "Freeing packet w ithin packet queue - TX attempts exceeded or not exposed", p->p);

					if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
						eb_debug (0, 4, "AUNSEND", "%-8s %3d.%3d Freeing packetqueue %p (TX attempts exceeded or not exposed)", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), p);
					else
						eb_debug (0, 4, "AUNSEND", "%-8s %3d     Freeing packetqueue %p (TX attempts exceeded or not exposed)", eb_type_str(d->type), d->net, p); 

					eb_free (__FILE__, __LINE__, "AUNSEND", "Freeing packetq - TX attempts exceeded or not exposed", p);

					if (p_parent)
						p_parent->n = p_next;
					else
						o->p = p_next;
				}
				else if ((timediff = timediffmsec(&(p->last_tx), &now)) >= EB_CONFIG_AUN_RETX)
				{
					/* Send it! */

					struct sockaddr_in	dest;

					gettimeofday(&(p->last_tx), 0);

					dest.sin_family = AF_INET;
					dest.sin_port = htons(o->destdevice->aun->port);
					dest.sin_addr.s_addr = htonl(o->destdevice->aun->addr);

					p->p->p.ctrl &= 0x7F; /* Strip high bit on True AUN */

					if (
						(
						 !((o->destdevice->config & EB_DEV_CONF_AUTOACK) && (p->p->p.aun_ttype == ECONET_AUN_ACK || p->p->p.aun_ttype == ECONET_AUN_NAK))
						) 
					&& 	(p->p->p.aun_ttype != ECONET_AUN_INK)
					) // Don't send ACK / NAK to AUTOACK stations because they'll already have had one ; and NEVER send INK packets to AUN stations, because they won't understand them
					{
						int	r;

						eb_debug (0, 4, "AUNSEND", "%16s Looking at outq %p, packet %p - Sending (time diff = %d)", devstring, o, p, timediff);


						eb_add_stats(&(o->destdevice->statsmutex), &(o->destdevice->b_in), p->length);
						if (eb_firewall(o->destdevice->fw_in, p->p) == EB_FW_REJECT)
						{
							eb_dump_packet (o->destdevice, EB_PKT_DUMP_DUMPED, p->p, p->length);
						}
						else
						{
							eb_dump_packet (o->destdevice, EB_PKT_DUMP_POST_O, p->p, p->length);

							if ((r = sendto (exp->socket, &(p->p->p.aun_ttype), p->length + 8, MSG_DONTWAIT, (struct sockaddr *) &dest, sizeof(dest))) < 0)
								eb_debug (0, 1, "AUNSEND", "%16s Packet at %p AUN transmission failed: %s", devstring, p->p, strerror(errno));


						}
							if (p->p->p.aun_ttype != ECONET_AUN_DATA) // && p->p->p.aun_ttype != ECONET_AUN_IMM) // Everything else only gets a single shot tx
								p->tx = EB_CONFIG_AUN_RETRIES; /* Cheat by flagging max retries */
					}
					else
						eb_debug (0, 4, "AUNSEND", "%16s Looking at outq %p, packet %p - NOT Sending ACK/NAK/INK", devstring, o, p);


					p_parent = p;

				}
				else /* Time not expired */
				{
					eb_debug (0, 4, "AUNSEND", "%16s Looking at outq %p, packet %p - not sending (time diff = %d)", devstring, o, p, timediff);

					if ((EB_CONFIG_AUN_RETX - timediff) < min_sleep)	min_sleep = (EB_CONFIG_AUN_RETX - timediff); /* Shorten our snooze because this packet needs to go sooner */

					p_parent = p;

				}

				p = p_next;
			}

			if (o->p) /* Packets remain */
				o_parent = o; /* Otherwise if nothing remains, we'll splice this out and parent needs to be unaltered */
			else
			{
				/* No packets remain - splice outq off queue */

				if (d->type == EB_DEF_PIPE || d->type == EB_DEF_LOCAL)
					eb_debug (0, 4, "AUNSEND", "%-8s %3d.%3d Freeing outq at %p", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE ? d->pipe.stn : d->local.stn), o);
				else
					eb_debug (0, 4, "AUNSEND", "%-8s %3d     Freeing outq at %p", eb_type_str(d->type), d->net, o);

				eb_free (__FILE__, __LINE__, "AUNSEND", "Freeing outq when destination unknown", o);

				if (o_parent)
					o_parent->next = o_next;
				else
					d->aun_out_head = o_next;
			}

			o = o_next;
		}

		d->aun_out_tail = o_parent;

		/* Snooze off for a while */

		if (!d->aun_out_head) /* Infinite wait - nothing to re-tx */
		{

			eb_debug (0, 4, "AUNSEND", "%16s Permanent sleep - no traffic left", devstring, min_sleep);
			pthread_cond_wait(&(d->aun_out_cond), &(d->aun_out_mutex));
		}
		else
		{
			eb_debug (0, 4, "AUNSEND", "%16s Timed wait for %d ms", devstring, min_sleep);
	
			clock_gettime(CLOCK_REALTIME, &wait);
	
			wait.tv_nsec += (min_sleep * 1000000);
	
			if (wait.tv_nsec > 1000000000)
			{
				wait.tv_nsec -= 1000000000;
				wait.tv_sec++;
			}

			pthread_cond_timedwait(&(d->aun_out_cond), &(d->aun_out_mutex), &wait);
		}


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
	int32_t				length = -1; // Needs to be signed to catch errors on read
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
		eb_debug (0, 2, "DESPATCH", "%-8s %7d Thread started for trunk to %s:%d (tid %d)", eb_type_str(d->type), d->trunk.local_port, d->trunk.hostname ? d->trunk.hostname : "(Unregistered dynamic host)", d->trunk.hostname ? d->trunk.remote_port : 0, syscall(SYS_gettid));

	d->last_rx = 0; // Reset timeout

	if (d->type == EB_DEF_WIRE && !strcasecmp("/dev/null", d->wire.device)) // Flag as a dummy wire so we don't try and receive traffic from it
		wire_null = 1;

	// Start our device listener

	if (EB_CONFIG_LOCAL && d->type == EB_DEF_WIRE)
		eb_debug (0, 1, "WIRE", "%-8s %3d     Econet device disabled", "", d->net);

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

	// Initialize our bridge conditions / mutex / etc

	if (pthread_cond_init (&(d->bridge_update_cond), NULL) == -1)
		eb_debug (1, 0, "BRIDGE", "Failed to initialize bridge update pthread_cond");

	// Open our device, whatever it might be

	switch (d->type)
	{
		case EB_DEF_WIRE:
		{

			uint32_t	kernvers;
			char 		hardwareclass[4];

			if (EB_CONFIG_LOCAL)
				d->wire.socket = open("/dev/null", O_RDWR);
			else
				d->wire.socket = open(d->wire.device, O_RDWR);

			if (d->wire.socket < 0) // Failed
				eb_debug (1, 0, "DESPATCH", "%-8s %3d     Cannot open device %s", "", d->net, (EB_CONFIG_LOCAL ? "/dev/null" : d->wire.device));

			// Do station setup
	
			ioctl(d->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(d->wire.stations));	
			ioctl(d->wire.socket, ECONETGPIO_IOC_READMODE); // Rest just in case...

			ioctl(d->wire.socket, ECONETGPIO_IOC_EXTRALOGS, EB_CONFIG_EXTRALOGS);

			kernvers = ioctl(d->wire.socket, ECONETGPIO_IOC_KERNVERS);

			sprintf (hardwareclass, "%1d", (kernvers & 0xff));

			eb_debug (0, 1, "DESPATCH", "%-8s %3d     Pi hardware is %s class; bridge hardware is version %d", eb_type_str(d->type), d->net, hardwareclass, (kernvers & 0xff00) >> 8);
					
			if (pthread_create(&d->bridge_update_thread, NULL, eb_bridge_update_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %3d     Cannot start bridge updater on this device.", "Wire", d->net);
		
			if (pthread_create(&d->bridge_update_thread2, NULL, eb_bridge_update_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %3d     Cannot start second bridge updater on this device.", "Wire", d->net);
		
			if (pthread_create(&d->bridge_reset_thread, NULL, eb_bridge_reset_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %3d     Cannot start bridge reset thread on this device.", "Wire", d->net);
		
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
				eb_debug (0, 2, "DESPATCH", "%-8s %3d     Network clock configured %.2f period / %.2f mark us", "Wire", d->net, (float) d->wire.period / 4, (float) d->wire.mark / 4);
			}

			// Enable resilience mode if selected
			
			ioctl(d->wire.socket, ECONETGPIO_IOC_RESILIENCEMODE, d->wire.resilience);

			eb_debug (0, 2, "DESPATCH", "%-8s %3d     Econet device %s opened successfully (fd %d)", "Wire", d->net, (EB_CONFIG_LOCAL ? "/dev/null" : d->wire.device), d->wire.socket);	

		} break;

		case EB_DEF_LOCAL:
		{
			// Initialize fileserver, printerserver, ipserver, etc.

			if (d->local.fs.rootpath) // Active FS
			{
				d->local.fs.server = fsop_initialize (d, d->local.fs.rootpath, d->local.fs.tapehandler, d->local.fs.tapecompletionhandler);
				if (d->local.fs.server && (fsop_run(d->local.fs.server) >= 1))
					eb_debug (0, 2, "BRIDGE", "FS       %3d.%3d Fileserver initialized at %s", d->net, d->local.stn, d->local.fs.rootpath);
				else
					eb_debug (1, 0, "BRIDGE", "FS       %3d.%3d Fileserver at %s FAILED to initialize", d->net, d->local.stn, d->local.fs.rootpath);
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

				eb_debug (0, 2, "IPGW", "%-8s %3d.%3d Tunnel interface %s opened", eb_type_str(d->type), d->net, d->local.stn, d->local.ip.tunif);

				d->local.ip.socket = handle;
				
			}

			// Initialize *FAST handler - but only if we're a fileserver

			if (d->local.fs.rootpath)
			{
				d->local.fastbit = 0;
				d->local.fast_input_ctrl = 0;
				if (pthread_mutex_init(&(d->local.fast_io_mutex), NULL) == -1)
					eb_debug (1, 0, "FAST", "Cannot initialize IO mutex");
	
				d->local.fast_thread_alive = 0;
				d->local.fast_reset = 0;
				d->local.fast_client_net = d->local.fast_client_stn = 0;
				d->local.fast_client_ready = 0;
				ECONET_INIT_STATIONS(d->local.fast_priv_stns); // Clear the privileged station bitmap
				if (pthread_cond_init (&(d->local.fast_wake), NULL) == -1)
					eb_debug (1, 0, "FAST", "Failed to initialize fast_wake pthread_cond");
	
				if (socketpair(AF_UNIX, SOCK_STREAM, 0, d->local.fast_to_handler) || socketpair(AF_UNIX, SOCK_STREAM, 0, d->local.fast_to_despatch))
					eb_debug (1, 0, "FAST", "Cannot create socketpairs for *FAST handler and IO");
				
				if (pthread_create(&(d->local.fast_handler), NULL, eb_fast_handler, d))
					eb_debug(1, 0, "DESPATCH", "Cannot start *FAST handler thread for station %d.%d", d->net, d->local.stn);
				pthread_detach(d->local.fast_handler);
	
				if (pthread_create(&(d->local.fast_io_handler), NULL, eb_fast_io_handler, d))
					eb_debug(1, 0, "DESPATCH", "Cannot start *FAST IO handler thread for station %d.%d", d->net, d->local.stn);
				pthread_detach(d->local.fast_io_handler);
			}

			// Initialize the notify list & mutex

			d->local.notify = NULL;

			if (pthread_mutex_init(&(d->local.notify_mutex), NULL) == -1)
				eb_debug (1, 0, "NOTIFY", "Cannot initialize notify mutex");

			// Start the notify thread

			if (pthread_create(&d->local.notify_thread, NULL, eb_notify_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %3d.%3d Cannot start notify watcher on this device.", "Local", d->net, d->local.stn);
		


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

			char 			portname[6];
			struct addrinfo		hints;
			struct sockaddr_in	service;
			int			s;

			// No longer required - can still operate plaintext trunks if defined host
			//if (!(d->trunk.sharedkey))
				//eb_debug (1, 0, "DESPATCH", "%-8s         Unable to start trunk for local port %d - No shared key defined!", "Trunk", d->trunk.local_port);

			if (!d->trunk.mt_parent) // Not a multitrunk connected trunk
			{
				if (!(d->trunk.is_dynamic)) // IP trunk and is defined
				{
		
					if (!(d->trunk.hostname))
						eb_debug (1, 0, "DESPATCH", "%-8s %7d Unable to open trunk listener socket - Static remote host but no hostname defined!", "Trunk", d->trunk.local_port);
	
					snprintf(portname, 6, "%d", d->trunk.remote_port);
	
					memset (&hints, 0, sizeof(struct addrinfo));
	
					hints.ai_family = AF_INET;
					hints.ai_socktype = SOCK_DGRAM;
					hints.ai_flags = 0;
					hints.ai_protocol = 0;
	
					if ((s = getaddrinfo(d->trunk.hostname, portname, &hints, &(d->trunk.remote_host))) != 0)
					{
						// 20240607 eb_debug (1, 0, "DESPATCH", "%-8s         Unable to resolve hostname %s: %s", "", d->trunk.hostname, gai_strerror(s));
						eb_debug (0, 1, "DESPATCH", "TRUNK    %7d Unable to resolve hostname %s: %s - leaving inactive", d->trunk.local_port, d->trunk.hostname, gai_strerror(s));
						d->trunk.remote_host = NULL; // Flag inactive
					}
	
				}
				else if (d->trunk.is_dynamic) // Dynamic
					d->trunk.remote_host = NULL; // Flags as unresolved dynamic
	
				// Set up local listener
	
				d->trunk.socket = socket(AF_INET, SOCK_DGRAM, 0);
	
				if (d->trunk.socket == -1)
					eb_debug (1, 0, "DESPATCH", "%-8s %7d Unable to open trunk listener socket to %s:%d", "Trunk", d->trunk.local_port, d->trunk.hostname ? d->trunk.hostname : "(Dynamic)", d->trunk.hostname ? d->trunk.remote_port : 0);
	
	
				service.sin_family = AF_INET;
				service.sin_addr.s_addr = htonl(bindhost); // INADDR_ANY;
				service.sin_port = htons(d->trunk.local_port);
	
				if (bind(d->trunk.socket, (struct sockaddr *) &service, sizeof(service)) != 0)
					eb_debug (1, 0, "DESPATCH", "%-8s %7d Unable to bind trunk listener socket to %s:%d (%s)", "Trunk", d->trunk.local_port, d->trunk.hostname ? d->trunk.hostname : "(Dynamic)", d->trunk.hostname ? d->trunk.remote_port : 0, strerror(errno));
			}
			else /* Multitrunk child */
			{
				int e;

				if (d->trunk.mt_type == MT_CLIENT) /* Multitrunk child and it's a client */
				{
					eb_debug (0, 1, "DESPATCH", "M-Trunk  %7d Starting multitrunk client handler to %s:%d", d->trunk.local_port, d->trunk.hostname, d->trunk.remote_port);

					d->trunk.is_dynamic = 0; // All MT Clients have known remote endpoints

					/* Start a client device */
			
					e = pthread_create(&(d->mt_client_thread), NULL, eb_multitrunk_client_device, d);
			
					if (e)
						eb_debug (1, 0, "DESPATCH", "M-Trunk  %7d Thread creation for multitrunk client handler for %s:%d failed", d->trunk.local_port, d->trunk.hostname, d->trunk.remote_port);

					pthread_detach(d->mt_client_thread);

					eb_thread_started();
				}
			}

			// Set up keepalive thread

			if ((err = pthread_create(&(d->trunk.keepalive_thread), NULL, eb_trunk_keepalive, d)))
				eb_debug (1, 0, "DESPATCH", "%-8s %7d Unable to create trunk keepalive thread", "Trunk", d->trunk.local_port);
			else
			{
				eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk keepalive thread started", "Trunk", d->trunk.local_port);
				pthread_detach (d->trunk.keepalive_thread);
				eb_thread_started(); // Is this neeed? We aren't counting the keepalive thread...
			}
			
			if (!(d->trunk.is_dynamic))
				eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk initialized (%s) to %s:%d with key %s", "Trunk", d->trunk.local_port, (d->trunk.remote_host ? "active" : "inactive until DNS resolves"), d->trunk.hostname ? d->trunk.hostname : "(Dynamic)", d->trunk.hostname ? d->trunk.remote_port : 0, d->trunk.sharedkey);
			else
				eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk initialized to dynamic remote host with key %s", "Trunk", d->trunk.local_port, d->trunk.sharedkey);
	
			if (pthread_create(&d->bridge_update_thread, NULL, eb_bridge_update_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %7d Cannot start bridge updater on this device.", "Trunk", d->trunk.local_port);
		
			if (pthread_create(&d->bridge_update_thread2, NULL, eb_bridge_update_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %7d Cannot start second bridge updater on this device.", "Trunk", d->trunk.local_port);
		
			if (pthread_create(&d->bridge_reset_thread, NULL, eb_bridge_reset_watcher, d))
				eb_debug (1, 0, "DESPATCH", "%-8s %7d Cannot start bridge reset thread on this device.", "Trunk", d->trunk.local_port);
		
			// Added 20240607
			
			pthread_detach (d->bridge_update_thread);
			pthread_detach (d->bridge_update_thread2);
			pthread_detach (d->bridge_reset_thread);

		} break;

		case EB_DEF_NULL:
		{
		} break; // No device 

		case EB_DEF_POOL:
		{
			// Nothing to do
		} break;

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
		case EB_DEF_POOL:
		case EB_DEF_NULL:
			l_socket = 0; // Shouldn't be used on a NULL or Pool device anyway
			break;
		default:
			l_socket = 0;
			eb_debug (1, 0, "DESPATCH", "Cannot identify device type so as to local appropriate listener socket! (Device type %08X)", d->type);
	}

	d->p_reset.fd = l_socket;

	// Start our listener thread

	if ((d->type != EB_DEF_NULL) && (d->type != EB_DEF_POOL))//  && d->type != EB_DEF_LOCAL))
	{
		if ((err = pthread_create (&(d->listen), NULL, eb_device_listener, d))) // NULL has nothing to listen for - its diverts do it; Local devices don't either - they are hard coded devices which inject directly into the queue & wake the despatcher thread
			eb_debug (1, 0, "DESPATCH", "Unable to start device listener thread for net %d: %s", d->net, strerror(err));
		pthread_detach(d->listen);
		eb_thread_started();
	}

	// Start the AUN sender thread
	
	if (d->type != EB_DEF_AUN && d->type != EB_DEF_NULL)
	{

		int 	err;
		char	devstring[20];

		if (d->type == EB_DEF_WIRE || d->type == EB_DEF_POOL)
			sprintf(devstring, "%-8s %3d   ", eb_type_str(d->type), d->net);
		else if (d->type == EB_DEF_TRUNK)
			sprintf(devstring, "%-8s %7d", eb_type_str(d->type), d->trunk.local_port);
		else
			sprintf(devstring, "%-8s %3d.%3d", eb_type_str(d->type), d->net, (d->type == EB_DEF_PIPE) ? d->pipe.stn : d->local.stn);

		if ((err = pthread_create (&(d->aun_out_thread), NULL, eb_device_aun_sender, d)))
			eb_debug (1, 0, "DESPATCH", "%-16s Cannot create AUN sender: %s", devstring, strerror(err));
		else
			eb_debug (0, 2, "DESPATCH", "%-16s Created AUN sender thread", devstring);
		
		pthread_detach(d->aun_out_thread);
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

		/* If this is a wire device, see if it needs its station set updating */

		if (d->type == EB_DEF_WIRE)
		{
			pthread_mutex_lock (&(d->wire.stations_lock));
			if (d->wire.stations_update_rq)
				ioctl (d->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(d->wire.stations));
			d->wire.stations_update_rq = 0;
			pthread_mutex_unlock (&(d->wire.stations_lock));
			pthread_cond_signal (&(d->qwake));
		}

		new_output = 0;

		// First do a poll(0) to see if there was anything to read

		memcpy (&p, &(d->p_reset), sizeof(p));

		/* Update that struct if this is a multitrunk child */

		if (d->type == EB_DEF_TRUNK && d->trunk.mt_parent)
		{
			pthread_mutex_lock(&(d->trunk.mt_mutex));
			if (!d->trunk.mt_data) /* NOT Connected */
			{
				pthread_cond_wait(&(d->trunk.mt_cond), &(d->trunk.mt_mutex));
				eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk now connected - despatcher woken", eb_type_str(d->type), d->trunk.local_port);
			}
			
			/* Connected now */

			p.fd = d->trunk.mt_data->trunk_socket[0];
			pthread_mutex_unlock(&(d->trunk.mt_mutex));
		}

		// To receive traffic after a poll(), must be not local, or if it is local then it's an IP gateway. Otherwise there should be no traffic arriving at all from a local, because the FS and PS put their stuff straight into the queues! // NB the while below is guarded by the if on this line, but not indented

		if (!(d->type == EB_DEF_WIRE && wire_null) && (d->type != EB_DEF_POOL) && ((d->type != EB_DEF_LOCAL) || (d->local.ip.tunif[0] != '\0'))) while (poll(&p, 1, 0) && (p.revents & POLLIN)) // A 0-time poll() apparently works
		{

			uint8_t		packetreceived = 0; // Default state. Trunk serial receiver sets to 0 unless a whole packet has arrived

			if (d->type == EB_DEF_WIRE || (d->type == EB_DEF_TRUNK)) // Read straight to packet structure (Restrict to IP trunks)
			{

				if (d->type == EB_DEF_TRUNK)
				{

					uint16_t		datalength; // Stores length as set out in received encrypted packet

					unsigned char		temp_packet[ECONET_MAX_PACKET_SIZE+6];

					struct sockaddr_in	src_addr;
					socklen_t		addr_len;

					uint8_t			was_dead;

					time_t			now, dead_diff, last_rx;

					// See if this trunk was dead - used to work out whether to reset if we have valid traffic
					
					pthread_mutex_lock (&(d->statsmutex));

					last_rx = d->last_rx;
					now = time(NULL);

					dead_diff = now - last_rx;

					pthread_mutex_unlock (&(d->statsmutex));

					was_dead = 0;

					if (dead_diff > EB_CONFIG_TRUNK_DEAD_INTERVAL)
						was_dead = 1;

					addr_len = sizeof(src_addr);

					pthread_mutex_lock(&(d->trunk.mt_mutex));

					if (d->trunk.mt_parent && d->trunk.mt_data) // Part of multitrunk and the connection is live
						length = read (d->trunk.mt_data->trunk_socket[0], &(d->trunk.cipherpacket), TRUNK_CIPHER_TOTAL);
					else
						length = recvfrom (l_socket, &(d->trunk.cipherpacket), TRUNK_CIPHER_TOTAL, 0, (struct sockaddr *) &src_addr, &addr_len);

					pthread_mutex_unlock(&(d->trunk.mt_mutex));

					if (was_dead)
					{
						if (last_rx == 0)
							eb_debug (0, 2, "DESPATCH", "%-8s %7d Packet received for trunk which was dead (first packet since startup)", eb_type_str(d->type), d->trunk.local_port);
						else
							eb_debug (0, 2, "DESPATCH", "%-8s %7d Packet received for trunk which was dead (previous packet was %d ago)", eb_type_str(d->type), d->trunk.local_port, dead_diff);
					}

					if (d->trunk.sharedkey && (length < (TRUNK_CIPHER_DATA + AES_BLOCK_SIZE)) && !d->trunk.mt_parent)
						eb_debug (0, 2, "DESPATCH", "%-8s %3d     Encrypted runt packet received - discarded", eb_type_str(d->type), d->net);
					else if (d->trunk.sharedkey && !d->trunk.mt_parent) // Encrypted trunk and not part of multitrunk (which delivers cleartext traffic to us)
					{
						if (!(d->trunk.ctx_dec = EVP_CIPHER_CTX_new()))
							eb_debug (1, 0, "DESPATCH", "%-8s %7d Unable to set up decryption control", "Trunk", d->trunk.local_port);

						eb_debug (0, 4, "DESPATCH", "%-8s %7d Encrypted trunk packet received - type %d, IV bytes %02x %02x %02x ...", eb_type_str(d->type), d->trunk.local_port, d->trunk.cipherpacket[TRUNK_CIPHER_ALG], d->trunk.cipherpacket[TRUNK_CIPHER_IV], d->trunk.cipherpacket[TRUNK_CIPHER_IV+1], d->trunk.cipherpacket[TRUNK_CIPHER_IV+2]);

						switch (d->trunk.cipherpacket[TRUNK_CIPHER_ALG])
						{
							case 1:
								EVP_DecryptInit_ex(d->trunk.ctx_dec, EVP_aes_256_cbc(), NULL, d->trunk.sharedkey, &(d->trunk.cipherpacket[TRUNK_CIPHER_IV]));
								break;
							default:
								eb_debug (0, 2, "DESPATCH", "%-8s %7d Encryption type %02x in encrypted unknown - discarded", eb_type_str(d->type), d->trunk.local_port, d->trunk.cipherpacket[TRUNK_CIPHER_ALG]);
								break;
						}

						if (d->trunk.cipherpacket[TRUNK_CIPHER_ALG] && (d->trunk.cipherpacket[TRUNK_CIPHER_ALG] <= 1))
						{

							int	tmp_len;

							eb_debug (0, 4, "DESPATCH", "%-8s %7d Encryption type in encrypted is valid - %02x; encrypted data length %04x", eb_type_str(d->type), d->trunk.local_port, d->trunk.cipherpacket[TRUNK_CIPHER_ALG], (length - TRUNK_CIPHER_DATA));

							if ((!EVP_DecryptUpdate(d->trunk.ctx_dec, temp_packet, &(d->trunk.encrypted_length), (unsigned char *) &(d->trunk.cipherpacket[TRUNK_CIPHER_DATA]), length - TRUNK_CIPHER_DATA)))
								eb_debug (0, 2, "DESPATCH", "%-8s %3d     DecryptUpdate of trunk packet failed", eb_type_str(d->type), d->net);
							else if (EVP_DecryptFinal_ex(d->trunk.ctx_dec, (unsigned char *) &(temp_packet[d->trunk.encrypted_length]), &tmp_len))
							{

								d->trunk.encrypted_length += tmp_len;

								eb_debug (0, 4, "DESPATCH", "%-8s %7d Trunk packet length %04x", eb_type_str(d->type), d->trunk.local_port, d->trunk.encrypted_length);

								datalength = (temp_packet[0] * 256) + temp_packet[1];

								if (datalength >= 12) // Valid packet size received
								{
									eb_debug (0, 4, "DESPATCH", "%-8s %7d Encrypted trunk packet validly received - specified length %04x, decrypted length %04x, marking receipt at %d seconds", eb_type_str(d->type), d->trunk.local_port, datalength, d->trunk.encrypted_length, time(NULL));
									memcpy(&packet, &(temp_packet[2]), datalength); // data length always ignores the ECONET part of the data
									length = datalength;
									packetreceived = 1;
									
									// Mark receipt
									
									eb_update_lastrx(d);

									// Having received a valid packet, let's update our remote end status if we are dynamic

									if (d->trunk.is_dynamic)
									{

										if (d->trunk.remote_host || (!d->trunk.remote_host && (d->trunk.remote_host = eb_malloc(__FILE__, __LINE__, "TRUNK", "Create trunk remote_host structure", sizeof(struct addrinfo))) && (d->trunk.remote_host->ai_addr = NULL)))
										{

											if ((d->trunk.remote_host->ai_addr || (d->trunk.remote_host->ai_addr = eb_malloc(__FILE__, __LINE__, "TRUNK", "Create trunk remote_host->ai_addr structure", sizeof(struct sockaddr_in)))) && (d->trunk.hostname || (d->trunk.hostname = eb_malloc(__FILE__, __LINE__, "TRUNK", "Create trunk hostname space", HOST_NAME_MAX)))) // 20 because for now it'll just be an IP address
											{

												// Is it the same host as we had before?

												if (was_dead || memcmp(&src_addr, d->trunk.remote_host->ai_addr, sizeof(struct sockaddr_in))) // Not equal - host has changed
												{
													d->trunk.remote_host->ai_family = AF_INET;
													d->trunk.remote_host->ai_next = NULL;
													d->trunk.remote_host->ai_canonname = NULL;
													memcpy (d->trunk.remote_host->ai_addr, &src_addr, sizeof(struct sockaddr_in));
													d->trunk.remote_host->ai_addrlen = sizeof(struct sockaddr_in);

													d->trunk.remote_port = ntohs(src_addr.sin_port);

													if (getnameinfo((struct sockaddr *) d->trunk.remote_host->ai_addr, sizeof (struct sockaddr_in), d->trunk.hostname, HOST_NAME_MAX, NULL, 0, 0) != 0) // = is success and we'll have the hostname in d->trunk.hostname; otherwise put numeric in there
														strncpy (d->trunk.hostname, inet_ntoa(src_addr.sin_addr), 19);

													eb_debug (0, 1, "DESPATCH", "%-8s %7d Dynamic trunk endpoint found at host %s port %d (addr_len = %d, family = %d)", eb_type_str(d->type), d->trunk.local_port, d->trunk.hostname, ntohs(src_addr.sin_port), addr_len, src_addr.sin_family);

													// Do a bridge reset

													// eb_bridge_reset(NULL); // Now done if was dead

												}
											}
											else
												eb_debug (1, 1, "DESPATCH", "%-8s %7d Dynamic trunk endpoint found at host %s port %d, but failed to allocate memory for sockaddr_in structure!", eb_type_str(d->type), d->trunk.local_port, inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
										}
										else if (!d->trunk.remote_host)
											eb_debug (1, 1, "DESPATCH", "%-8s %7d Dynamic trunk endpoint found at host %s port %d, but failed to allocate memory for addrinfo structure!", eb_type_str(d->type), d->trunk.local_port, inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
									}

									if (was_dead && d->all_nets_pooled) // It needs some updates, just in case it has restarted and we missed its reset
									{
										if (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG)
											eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk received traffic after being dead - all nets pooled - send bridge updates", eb_type_str(d->type), d->trunk.remote_port);
										pthread_cond_signal(&(d->bridge_update_cond));

									}
									else if (was_dead && (packet.p.port != BRIDGE_PORT || packet.p.ctrl != BRIDGE_RESET)) // If this trunk was dead before this packet arrived, do a bridge reset - which will also start the update process - but don't do a reset if what's just turned up is a reset
									{
										if (!EB_CONFIG_NOBRIDGEANNOUNCEDEBUG)
											eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk received traffic after being dead - send bridge reset", eb_type_str(d->type), d->trunk.remote_port);
										eb_bridge_reset(NULL);

									}
								}
								else
									eb_debug (0, 2, "DESPATCH", "%-8s %7d Decrypted trunk packet too small (data length = %04x) - discarded", eb_type_str(d->type), d->trunk.local_port, datalength);
							}
							else
								eb_debug (0, 2, "DESPATCH", "%-8s %7d DecryptFinal of trunk packet failed - decrypted length before call was %04x", eb_type_str(d->type), d->trunk.local_port, d->trunk.encrypted_length);
						}

						EVP_CIPHER_CTX_free(d->trunk.ctx_dec);
					}
					else // Plaintext trunk or part of multitrunk
					{

						eb_debug (0, 3, "DESPATCH", "%-8s %7d Plaintext trunk packet received - specified length %04x, marking receipt at %d seconds", eb_type_str(d->type), d->trunk.local_port, length, time(NULL));
						memcpy (&packet, &d->trunk.cipherpacket, length);

						if (length >= 12)
						{
							packetreceived = 1;

							// Mark receipt
							eb_update_lastrx(d);

							if (was_dead && (packet.p.port != BRIDGE_PORT || packet.p.ctrl != BRIDGE_RESET)) // If this trunk was dead before this packet arrived, do a bridge reset - which will also start the update process - but dont do this if what we received was a reset, because there'll just be lots of resets flying around.
							{
								eb_debug (0, 2, "DESPATCH", "%-8s %7d Trunk received traffic after being dead - send bridge reset", eb_type_str(d->type), d->trunk.remote_port);
								eb_bridge_reset(NULL);
							}
						}

					}
				}

				if (d->type == EB_DEF_WIRE)
				{
					length = read (l_socket, &packet, ECONET_MAX_PACKET_SIZE);
					if (length >= 12) { eb_update_lastrx(d); packetreceived = 1; }
				}

				/* See if this was received on an interface group and we need to ignore it */

				if (d->type == EB_DEF_WIRE || d->type == EB_DEF_TRUNK) /* We won't invalidate PIPE traffic because receipt means the pipe is alive */
				{
					if (!eb_device_usable(d) && !(d->type == EB_DEF_WIRE && (packet.p.srcnet == 0 || packet.p.srcnet == d->net)) && !(packet.p.port == 0x9C && packet.p.ctrl == EB_CONFIG_TRUNK_KEEPALIVE_CTRL)) /* Either device not usable, and it's not wire from local network and it's not a trunk keepalive */
						packetreceived = 0; /* Pretend we've gone deaf */

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

						eb_debug (0, 4, "IMMED", "                 Checking for immediate match: %3d.%3d vs %3d.%3d seq %08X v %08X", d->wire.last_imm_dest_net, d->wire.last_imm_dest_stn, packet.p.srcnet, packet.p.srcstn, packet.p.seq, d->wire.last_imm_seq);

						// Make the Sequence Number match if this was an immediate reply we were expecting
						if (	(packet.p.aun_ttype == ECONET_AUN_IMMREP)
						&&	(packet.p.srcnet == d->wire.last_imm_dest_net)
						&&	(packet.p.srcstn == d->wire.last_imm_dest_stn)
						)
						{
							eb_debug (0, 4, "IMMED", "                 Found immediate match: %3d.%3d seq %08X", d->wire.last_imm_dest_net, d->wire.last_imm_dest_stn, d->wire.last_imm_seq);
							packet.p.seq = d->wire.last_imm_seq;
						}


						// In all cases, if we've received *anything* off the wire, blank off those immediate trackers because either we got a reply, or we didn't and it'll never come

						d->wire.last_imm_dest_net = d->wire.last_imm_dest_stn = 0;
						d->wire.last_imm_seq = 0;
	
						pthread_mutex_lock (&(d->priority_mutex));
	
						if (packet.p.aun_ttype == ECONET_AUN_IMM || (d->wire.resilience && packet.p.aun_ttype == ECONET_AUN_DATA)) // Prioritize the reply
						{
							pthread_attr_t	attrs;
							pthread_t	sleeper;
	
							pthread_attr_init (&attrs);
							pthread_attr_setstacksize(&attrs, PTHREAD_STACK_MIN);


							d->p_net = packet.p.dstnet;
							d->p_stn = packet.p.dststn;
							d->p_seq = packet.p.seq;
							d->p_isresilience = 0;

							if (d->wire.resilience && packet.p.aun_ttype == ECONET_AUN_DATA)
								d->p_isresilience = 1;

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
							d->p_isresilience = d->p_net = d->p_stn = d->p_seq = 0; // If we've received something else on a wire, it doesn't matter if we unset this, because it means the flag fill that the ADLC has started must have ended which means it's a while since the immediate was received
			
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

							eb_enqueue_output (d, outgoing, length, NULL);
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
							eb_enqueue_output (d, arp, 8, NULL);
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

					// Mark receipt
					eb_update_lastrx(d);

					// Insert source address

					packet.p.srcstn = d->pipe.stn;
					packet.p.srcnet = d->net;
				}
			}
		
			if (packetreceived && length >= 12)	 // Should always have at the least 4 bytes of addressing and 8 bytes AUN
			{
				// Do the inbound packet dump here, before we add a network number
				//

				uint8_t		dump_traffic = 0; // Flagged if the pool nat fails

				eb_add_stats(&(d->statsmutex), &(d->b_out), length); // Traffic stats - local pipe producing traffic outbound to the bridge
				
				/* If this device is loop_blocked, then dump things we aren't interested in */

				if (d->loop_blocked)
				{
					if (!
						(
							(d->type == EB_DEF_WIRE && packet.p.srcnet == 0)
						||	(	(packet.p.port == BRIDGE_PORT)
							&&	(packet.p.ctrl == BRIDGE_RESET)
							)
						)
					   )
						dump_traffic = 1;
				}

				/* Apply inbound firewall. Note that eb_firewall() returns an EB_FW_ACCEPT if the chain
				 * it is given is NULL
				 */

				if (eb_firewall (d->fw_out, &packet) == EB_FW_REJECT) // fw_out - this has come from the device itself
				{
					eb_dump_packet (d, EB_PKT_DUMP_DUMPED, &packet, length);
					dump_traffic = 1;
				}

				if (!dump_traffic) eb_dump_packet (d, EB_PKT_DUMP_PRE_I, &packet, length - 12);

				if (!dump_traffic && d->type != EB_DEF_TRUNK) // Fill in network numbers if need be
				{
					if (packet.p.srcnet == 0)	packet.p.srcnet = d->net;
					if (packet.p.dstnet == 0)	packet.p.dstnet = d->net;
				}	

				// Apply pool nat to wire & trunk devices

				if (!dump_traffic && packet.p.srcstn != 0 && // Don't translate bridge updates from bridges, which come from .0
					(
					(d->type == EB_DEF_TRUNK && d->trunk.use_pool[packet.p.srcnet])
				||	(d->type == EB_DEF_WIRE && d->wire.use_pool[packet.p.srcnet])
					)
				)
				{
					// We are on a device which can use pool nat, and has it enabled for this source network

					struct __eb_pool_host 	*host;
					uint8_t err;

					host = eb_find_make_pool_host(d,
							packet.p.srcnet, packet.p.srcstn,
							0, 0, 0, 
							&err);

					if (!host) // Oh dear, pool nat failed
					{
						eb_debug (0, 1, "POOL", "%-8s %3d.%3d Pool nat translation failed on %s %d (%s) - traffic dropped",
								eb_type_str(d->type), 
								packet.p.srcnet, packet.p.srcstn,
								eb_type_str(d->type),
								(d->type == EB_DEF_TRUNK ? d->trunk.local_port : d->net),
								eb_pool_err(err));

						dump_traffic = 1;
					}
					else // Apply the pool nat
					{
						packet.p.srcnet = host->net;
						packet.p.srcstn = host->stn;
					}

				}

				// Put it on an output queue here
			
				if (!dump_traffic)
				{
					if (packet.p.aun_ttype == ECONET_AUN_BCAST) // Send to broadcast handler
						eb_broadcast_handler (d, &packet, length - 12);
					else
					{
						if (((packet.p.port == ECONET_TRACE_PORT) && eb_trace_handler (d, &packet, length - 12)) || (packet.p.port != ECONET_TRACE_PORT))
							if (!eb_enqueue_output (d, &packet, length - 12, NULL)) // Couldn't queue
							{
								if (d->type == EB_DEF_WIRE && packet.p.aun_ttype == ECONET_AUN_IMM) // Drop to flag fill if we couldn't queue the inbound immediate we got off the wire
								{
									ioctl(d->wire.socket, ECONETGPIO_IOC_READMODE);	
									// And clear any priority flags
									pthread_mutex_lock (&(d->priority_mutex));
									d->p_isresilience = d->p_net = d->p_stn = d->p_seq = 0;
									pthread_mutex_unlock (&(d->priority_mutex));
								}

							}
					}
	
					// new_output = 1; // Added when output processing moved above
	
					eb_dump_packet (d, EB_PKT_DUMP_POST_I, &packet, length - 12);

				}
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

							// This next line sometimes coredumps...?
							eb_debug (0, 4, "DESPATCH", "%-8s %3d     Output queue - examining packetqueue at %p; destination device %p (%s)", eb_type_str(d->type), d->net, p, o->destdevice, eb_type_str(o->destdevice->type));

							if (p->p->p.port == 0x99 && p->p->p.aun_ttype == ECONET_AUN_DATA) // Track fileservers
								eb_mark_fileserver(p->p->p.dstnet, p->p->p.dststn);

							remove = packetfree = 0;

							/*
							 * JOB:
							 *
							 * Move this whole routine into an 'eb_trf_to_input()' routine
							 * which
							 * (a) Moves AUN outbound to a new thread which does the re-tx's
							 * (b) otherwise moves to the desired input queue.
							 *
							 * Then change eb_enqueue_input so that if the dest device is
							 * WIRE then that routine dumps the packet if it's ACK, NAK, INK.
							 *
							 * Then this routine in the despatcher can remove *all* packets
							 * immediately because they only remain here for AUN re-transmit
							 * purposes, so it's cleaner. BUT also the FS can use eb_trf_to_input()
							 * to queue its output so that we don't risk it sitting in the
							 * output queue of this device when it's a local FS. Instead they'll
							 * go straight to the destination device or AUN. 
							 *
							 * That also clens up this lump of code quite a bit.
							 *
							 * Note though, that this code doesn't duplicate the packet data -
							 * it doesn't eb_free() it if it's gone on an input queue, 
							 * but it will when it's finished doing an AUN re-transmit. So
							 * any routine which calls eb_trf_to_input() needs to make sure
							 * that it is providing a copy of the packet which can be passed
							 * around the bridge, and certainly not a statically allocated
							 * one from a calling routine's heap.
							 *
							 * This probably has another side-effect in that we could
							 * more easily create a broadcast listener device, which can
							 * take in traffic and figure out where it's supposed to go
							 * if anywhere. The AUN transmit thread can also *send*
							 * broadcasts to the local LAN, so that the broadcast
							 * handler can send traffic there rather than to individual
							 * AUN hosts on the local net. It could identify which IP
							 * networks are reachable by local broadcast with (one or more)
							 * config lines along the lines of 'LOCAL BROADCAST n.n.n.n/mask'.
							 * Anything not in that list has to be sent a broadcast in a 
							 * unicast AUN packet. 
							 *
							 * The AUN transmit thread needs to track how long it needs
							 * to sleep on its condwait by keeping a decreasing counter
							 * of how long to wait as it loops through its (probably
							 * one) output queue. That would probably also mean we ca
							 * get rid of 'aun_output_pending' logic in this routine. Yay!
							 *
							 * Yet another bonus is that the eb_trf_to_input() routine
							 * would then be being used pretty ubiquitously, and could
							 * be the location for the pipe tap interface.
							 *
							 */

							if (o->destdevice->type == EB_DEF_AUN)
							{
								if (!eb_aunpacket_to_aun_queue(d, o->destdevice, p->p, p->length))
									packetfree = 1;

								remove = 1; /* Either way we want it off our queue */
							}
							else
							{
								// Move it and wake the in queue
								
								// Only dump ACK/NAK if not in resilience mode
								//
								// 20250323 Change of plan. The wire driver just never sends ACK/NAK/INK to the module, so send everything on...
								
								/*
								if (o->destdevice->type == EB_DEF_WIRE && (o->destdevice->wire.resilience == 0) && (p->p->p.aun_ttype == ECONET_AUN_ACK || p->p->p.aun_ttype == ECONET_AUN_NAK))
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Dropping packetqueue at %p because it is an ACK/NAK and input device %p is %s", eb_type_str(d->type), d->net, p, o->destdevice, eb_type_str(o->destdevice->type));
								else
								*/
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
	
				/* Apply inbound firewall - this is traffic going to the device */

				if ((eb_firewall(d->fw_in, p->p) == EB_FW_REJECT))
				{
					eb_dump_packet (d, EB_PKT_DUMP_DUMPED, p->p, p->length);
					remove = 1;
				}

				ack.p.aun_ttype = ECONET_AUN_ACK; // Default; update later if not
				ack.p.dstnet = p->p->p.srcnet;
				ack.p.dststn = p->p->p.srcstn;
				ack.p.srcnet = p->p->p.dstnet;
				ack.p.srcstn = p->p->p.dststn;
				ack.p.seq = p->p->p.seq;
				ack.p.port = p->p->p.port;
				ack.p.ctrl = p->p->p.ctrl;

				/* Dump traffic we don't want if this device is loop blocked */

				if (d->loop_blocked)
				{
					if (!
						(
							(p->p->p.port == BRIDGE_PORT && p->p->p.ctrl == BRIDGE_RESET)
						||	(d->type == EB_DEF_WIRE && p->p->p.dstnet == d->net)
						)
					)
						remove = 1;

				}

				if (!remove && p->p->p.port == 0x99 && p->p->p.aun_ttype == ECONET_AUN_DATA) // Track fileservers
					eb_mark_fileserver(p->p->p.dstnet, p->p->p.dststn);

				if (d->type == EB_DEF_WIRE) // Get rid of things we won't send to the kernel
				{
					if (p->p->p.aun_ttype == ECONET_AUN_ACK ||
					    p->p->p.aun_ttype == ECONET_AUN_NAK ||
					    p->p->p.aun_ttype == ECONET_AUN_INK)
						remove = 1;

					/* Apply interface group restriction */

					if (!eb_device_usable(d) && (p->p->p.dstnet != d->net)) /* Device not usable and not local net */
						remove = 1;
				}

				if (d->type == EB_DEF_TRUNK) /* Apply interface group restriction */
				{
					if (!eb_device_usable(d) && (p->p->p.port != 0x9C || p->p->p.ctrl != EB_CONFIG_TRUNK_KEEPALIVE_CTRL))
						remove = 1; /* Remove if the trunk isn't usable and this isn't a trunk keepalive, which we'll always send. */
				}

				if (!remove) switch (d->type)
				{
					case EB_DEF_TRUNK:
					{
						int result;
						struct __econet_packet_aun *ap;
						struct mt_client *mtc;

						ap = eb_malloc(__FILE__, __LINE__, "DESPATCH", "Trunk send packet copy", p->length+12 + 6);

						if (!(d->trunk.is_dynamic) && !(d->trunk.remote_host)) // We have an unresolved static trunk
						{
							char			portname[6];
							struct addrinfo		hints;
							int			s;

							snprintf(portname, 6, "%d", d->trunk.remote_port);
	
							memset (&hints, 0, sizeof(struct addrinfo));

							hints.ai_family = AF_INET;
							hints.ai_socktype = SOCK_DGRAM;
							hints.ai_flags = 0;
							hints.ai_protocol = 0;

							if ((s = getaddrinfo(d->trunk.hostname, portname, &hints, &(d->trunk.remote_host))) != 0)
								d->trunk.remote_host = NULL;
							else	
							{
								eb_debug (0, 1, "TRUNK", "%-8s %7d Trunk endpoint address %s resolved. Trunk now active.", "Trunk", d->trunk.local_port, d->trunk.hostname);

								// Trigger a reset

								pthread_cond_signal (&(d->bridge_reset_cond));
							}
						}

						pthread_mutex_lock(&(d->trunk.mt_mutex));
						mtc = d->trunk.mt_data;
						pthread_mutex_unlock(&(d->trunk.mt_mutex));

						// This if() tests:
						// (i) that the packet copy malloc() worked
						// AND
						// either (ii)(a) there's an addrinfo in remote_host, for non-multitrunks, or
						//        (ii)(b) for multitrunk children, that there's a mt_client struct in existence (i.e. connected)
						if (ap && (d->trunk.remote_host || (d->trunk.mt_parent && mtc))) // And if !ap, just remove, below. If remote_host is NULL, this is a dynamic trunk with no remote endpoint yet
						{

							unsigned char temp_packet[ECONET_MAX_PACKET_SIZE + 12 + 2];
							int 	tmp_len;

							memcpy(ap, p->p, p->length + 12);

							ap->p.dstnet = (d->trunk.xlate_out[ap->p.dstnet] ? d->trunk.xlate_out[ap->p.dstnet] : ap->p.dstnet);

							result = -1; // Gets overwritten on success
// Encrypted version starts here
							if (d->trunk.sharedkey && !d->trunk.mt_parent) // Encryption on and not multitrunk child
							{
								RAND_bytes(d->trunk.iv, AES_BLOCK_SIZE);

								d->trunk.cipherpacket[TRUNK_CIPHER_ALG] = 1;

								memcpy (&(d->trunk.cipherpacket[TRUNK_CIPHER_IV]), &(d->trunk.iv), EVP_MAX_IV_LENGTH);
								temp_packet[0] = ((p->length+12) & 0xff00) >> 8;
								temp_packet[1] = (p->length+12) & 0xff;

								memcpy (&(temp_packet[2]), ap, p->length + 12);

								if (!(d->trunk.ctx_enc = EVP_CIPHER_CTX_new()))
									eb_debug (1, 0, "DESPATCH", "%-8s %7d Unable to set up encryption control", "Trunk", d->trunk.local_port);

								EVP_EncryptInit_ex(d->trunk.ctx_enc, EVP_aes_256_cbc(), NULL, d->trunk.sharedkey, d->trunk.iv);

								if ((!EVP_EncryptUpdate(d->trunk.ctx_enc, (unsigned char *) &(d->trunk.cipherpacket[TRUNK_CIPHER_DATA]), &(d->trunk.encrypted_length), temp_packet, p->length + 12 + 2)))
									eb_debug (0, 2, "DESPATCH", "%-8s %3d     EncryptUpdate of trunk packet failed", eb_type_str(d->type), d->net);
								else if  ((!EVP_EncryptFinal_ex(d->trunk.ctx_enc, (unsigned char *) &(d->trunk.cipherpacket[TRUNK_CIPHER_DATA + d->trunk.encrypted_length]), &tmp_len)))
									eb_debug (0, 2, "DESPATCH", "%-8s %3d     EncryptFinal of trunk packet failed", eb_type_str(d->type), d->net);
								else
								{
	
									d->trunk.encrypted_length += tmp_len;
	
									result = sendto (d->trunk.socket, (unsigned char *) &(d->trunk.cipherpacket), TRUNK_CIPHER_DATA + d->trunk.encrypted_length, MSG_DONTWAIT, d->trunk.remote_host->ai_addr, d->trunk.remote_host->ai_addrlen);
									eb_debug (0, 4, "DESPATCH", "Trunk            Encryption succeeded: cleartext length %04x, encrypted length %04x", (p->length + 12 + 2), d->trunk.encrypted_length);
								}	
	
								EVP_CIPHER_CTX_free(d->trunk.ctx_enc);

// Encrypted version stops here
							}
							else // Plaintext - just spit the packet out (or multitrunk child)
							{
								if (!d->trunk.mt_parent)
									result = sendto (d->trunk.socket, ap, p->length + 12, MSG_DONTWAIT, d->trunk.remote_host->ai_addr, d->trunk.remote_host->ai_addrlen);
								else
								{
									pthread_mutex_lock(&(d->trunk.mt_mutex)); // Lock because mt_data is volatile
									if (d->trunk.mt_data)
									{
										/* Base64 & encrypt, then sendto d->trunk.mt_data->socket with start & end markers */ 
										result = eb_mt_base64_encrypt_tx((uint8_t *) ap->raw, p->length + 12, d, '*');
										if (result == -1)
											eb_debug (0, 1, "DESPATCH", "M-Trunk  %7d Packet transmission for trunk %s failed (%s)", d->trunk.mt_parent->multitrunk.port, d->trunk.mt_name, strerror(errno));
									}
									else
									{
										result = -1;
										eb_debug (0, 1, "DESPATCH", "M-Trunk  %7d Packet transmission failed for trunk %s - trunk not connected", d->trunk.mt_parent->multitrunk.port, d->trunk.mt_name);
									}
									pthread_mutex_unlock(&(d->trunk.mt_mutex));

										
								}
							}

					
							eb_free (__FILE__, __LINE__, "DESPATCH", "Trunk send packet copy free", ap);
							eb_add_stats (&(d->statsmutex), &(d->b_in), p->length);

							if (result == -1 && !d->trunk.mt_parent) // Only generate this if not multitrunk, because failure in multitrunk is logged above
								eb_debug (0, 1, "DESPATCH", "Trunk            Packet transmission failed to %s:%d (%s)", d->trunk.hostname, d->trunk.remote_port, strerror(errno));

							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
						}

						if (ap && !(d->trunk.remote_host))
							eb_debug (0, 3, "DESPATCH", "Trunk    %7d Packet transmission failed - dynamic (or unresolved static) remote endpoint not established", d->trunk.local_port); 

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
								eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempting to transmit packet at pq %p, packet at %p, length 0x%04X, attempt %d", eb_type_str(d->type), d->net, p, p->p, p->length, p->tx);

								gettimeofday(&(d->wire.last_tx), 0); // Update last transmission time

								gettimeofday(&start, 0);

								led_write.flashtime = EB_CONFIG_FLASHTIME * (p->length > 4096 ? 2 : 1);

								if (!EB_CONFIG_LEDS_OFF && !pthread_create(&flash_write_thread, NULL, eb_flash_led, &led_write))
									pthread_detach(flash_write_thread);

								result = write (d->wire.socket, &tx, p->length + 12);

								eb_add_stats (&(d->statsmutex), &(d->b_in), p->length);

								err = ioctl(d->wire.socket, ECONETGPIO_IOC_TXERR);

								if (err == ECONET_TX_NOCLOCK || err == ECONET_TX_NOCOPY /* || err == ECONET_TX_NECOUTEZPAS */) // Catches too many other errors || (result != p->length + 12))
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
		
									eb_debug (0, 4, "DESPATCH", "%-8s %3d     while() loop ended for packet at pq %p, packet at %p after %d ms (result = %02X)", eb_type_str(d->type), d->net, p, p->p, timediffmsec(&start, &now), err);

									if (err == ECONET_TX_SUCCESS)
									{
										remove = 1;
		
										if (tx.p.aun_ttype == ECONET_AUN_IMM) // Record the sequence number & destination so we can match the sequence number on a reply
										{
											// Sleep for a short time and check the status again to see if it was still success - it might be not have been listening!)

											usleep(10); // Read the error again and see if not listening

											err = ioctl(d->wire.socket, ECONETGPIO_IOC_TXERR);

											if (err == ECONET_TX_NECOUTEZPAS) // Not listening
											{
												eb_debug (0, 4, "DEBUG", "                 Line idle after immediate tx - sending INK to %3d.%3d from %3d.%3d seq 0x%08X", ack.p.dstnet, ack.p.dststn, ack.p.srcnet, ack.p.srcstn, ack.p.seq);
												ack.p.aun_ttype = ECONET_AUN_INK;
												eb_enqueue_output (d, &ack, 0, NULL);
												new_output = 1;
											}
											else // Record the seq and destination so we can match the sequence number on reply
											{
												eb_debug (0, 4, "IMMED", "                 Tracking immediate sent: %3d.%3d seq %08X", tx.p.dstnet, tx.p.dststn, tx.p.seq);
												d->wire.last_imm_dest_net = tx.p.dstnet;
												d->wire.last_imm_dest_stn = tx.p.dststn;
												d->wire.last_imm_seq = tx.p.seq;
											}
										}

										if (tx.p.aun_ttype == ECONET_AUN_DATA)
										{
											eb_debug (0, 4, "DEBUG", "                 Attempting to send ACK to %3d.%3d from %3d.%3d port &%02X seq 0x%08X", ack.p.dstnet, ack.p.dststn, ack.p.srcnet, ack.p.srcstn, ack.p.port, ack.p.seq);
											eb_enqueue_output (d, &ack, 0, NULL);			
											new_output = 1;
										}
		
										eb_dump_packet (d, EB_PKT_DUMP_POST_O, &tx, p->length);
					
										// This was not very effective. It caused the load to balance a bit, but there were lots of 'No reply's. if (p->n && p->n->p->p.dststn == p->p->p.dststn && p->n->p->p.dstnet == p->p->p.dstnet) usleep (10000); // Try and give someone else a chance to transmit if we have a traffic queue - 10ms

									}
									else
									{
										int aunstate;

										aunstate = ioctl(d->wire.socket, ECONETGPIO_IOC_GETAUNSTATE);

										p->errors++;	
										if (err == ECONET_TX_NECOUTEZPAS) p->notlistening++;

										if (EB_DEBUG_LEVEL < 4 && (err == ECONET_TX_NECOUTEZPAS))
											eb_debug (0, 2, "DESPATCH", "Wire     %3d.%3d from %3d.%3d P:&%02X C:&%02X Not listening for packet length 0x%04X seq 0x%08X", tx.p.dstnet, tx.p.dststn, tx.p.srcnet, tx.p.srcstn, tx.p.port, tx.p.ctrl, p->length, tx.p.seq);
										else
											eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempt to transmit packet to %d.%d from %d.%d at %p FAILED with error 0x%02X (%s) - attempt %d - errors %d (not listening %d/%d), kernel tx ptr = 0x%02X, aun_state = 0x%02X", eb_type_str(d->type), d->net, tx.p.dstnet, tx.p.dststn, tx.p.srcnet, tx.p.srcstn, p, err, econet_strtxerr(err), p->tx, p->errors, p->notlistening, EB_CONFIG_WIRE_MAX_NOTLISTENING, (aunstate >> 16), aunstate & 0xff);
										wire_output_pending++;

										if (p->notlistening > /* 3 */ EB_CONFIG_WIRE_MAX_NOTLISTENING && (err == ECONET_TX_NECOUTEZPAS))
										{
											remove = 1; // Dump it - lots of errors on this - TODO - Suspect this line is wrong too.
											// Send NAK if DAT packet got not listening, or our internal-special "INK" for an immediate not listening - so a source can tell that's what happened
											// TODO - THIS IS WRONG - It's only done after full packet retries, below. But leave the immediate INK bit in because that doesn't require retries.
											/* This code in error - is done before after several retries for RISC OS
											if (tx.p.aun_ttype == ECONET_AUN_DATA)
											{
												ack.p.aun_ttype = ECONET_AUN_NAK;
												eb_enqueue_output (d, &ack, 0, NULL);
											}
											else */ if (tx.p.aun_ttype == ECONET_AUN_IMM) /* TODO: Is there any reason this needs to have p->errors > XX - can't it just fail on the first one? */
											{
												ack.p.aun_ttype = ECONET_AUN_INK;
												eb_enqueue_output (d, &ack, 0, NULL);
												new_output = 1;
											}
											
										}
									}
								}
								else // Wrong length - try again - repeat of code above
								{
									int aunstate;

									aunstate = ioctl(d->wire.socket, ECONETGPIO_IOC_GETAUNSTATE);

									eb_debug (0, 4, "DESPATCH", "%-8s %3d     Attempt to transmit packet to %d.%d from %d.%d at %p FAILED with error 0x%02X (%s) - attempt %d - kernel tx ptr = 0x%02X, aun_state = 0x%02X", eb_type_str(d->type), d->net, tx.p.dstnet, tx.p.dststn, tx.p.srcnet, tx.p.srcstn, p, err, econet_strtxerr(err), p->tx, (aunstate >> 16), aunstate & 0xff);
									p->errors++;	
									wire_output_pending++;

									/* TODO */ if (p->errors > 3 && (err == ECONET_TX_NECOUTEZPAS))
										remove = 1; // Dump it - lots of errors on this


								}
							}
							else
							{
								remove = 1; // Dump it - too many retries
								ack.p.aun_ttype = ECONET_AUN_NAK;
								if (tx.p.aun_ttype == ECONET_AUN_DATA)
								{
									eb_enqueue_output (d, &ack, 0, NULL);
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
							struct __eb_device	*ackdevice;
							struct __econet_packet_aun 	*ap;

							if (ack.p.dstnet == 0)
								ack.p.dstnet = d->net;

							ap = eb_malloc(__FILE__, __LINE__, "ACK", "New ACK packet to return to sender", 12);
							memcpy (ap, &ack, 12);

							eb_debug (0, 4, "LOCAL", "%-8s %3d.%3d from %3d.%3d attempting to send ACK from local emulator, P: &%02X, C: &%02X, Seq: 0x%08X", "Local", ack.p.dstnet, ack.p.dststn, ack.p.srcnet, ack.p.srcstn, ack.p.port, ack.p.ctrl, ack.p.seq);
							/* 20250327 CHange this to enqueue_input and wake, because otherwise data from (e.g.) a fileserver goes on the destination queue before this ACK, and that screws up resilience mode. The ACK needs to get there first! */
							//eb_enqueue_output (d, &ack, 0, NULL); // No data on this packet
							//new_output = 1;

							if ((ackdevice = eb_find_station(2, &ack)))
							{
								if (ackdevice->type == EB_DEF_AUN)
								{
									if (eb_aunpacket_to_aun_queue(d, ackdevice, ap, 12))
										eb_add_stats(&(d->statsmutex), &(d->b_out), 12);
									else
										eb_free(__FILE__, __LINE__, "ACK", "Free ACK packet on failure to send to AUN", ap);
								}
								else
								{
									eb_enqueue_input (ackdevice, ap, 12);
									pthread_cond_signal(&(ackdevice->qwake));
									/* Don't free - despatcher does it on transmit */
								}
							}

						}

						if (p->p->p.aun_ttype == ECONET_AUN_DATA && p->p->p.port == 0x00 && p->p->p.ctrl == 0x85 && p->p->p.data[0] == 0x00)
						{
							struct __eb_notify 	*l;

							pthread_mutex_lock (&(d->local.notify_mutex));

							l = d->local.notify;

							while (l && (l->net != p->p->p.srcnet || l->stn != p->p->p.srcstn))
								l = l->next;

							if (!l) // No structure - make one
							{
								l = eb_malloc (__FILE__, __LINE__, "NOTIFY", "New notify receipt structure", sizeof(struct __eb_notify));
								if (!l)
									eb_debug (1, 0, "NOTIFY", "Unable to malloc notify receipt structure");
								l->net = p->p->p.srcnet;
								l->stn = p->p->p.srcstn;
								l->next = d->local.notify;
								l->msg[0] = 0;
								l->len = 0;
								d->local.notify = l;
							}

							if (l->len < 255)
							{
								l->msg[l->len] = p->p->p.data[4];
								l->msg[l->len + 1] = 0;
								l->len++;
								time (&(l->last_rx));
								eb_debug (0, 3, "NOTIFY", "%-8s %3d.%3d from %3d.%3d Notify string currently '%s'", "Local", l->net, l->stn, p->p->p.srcnet, p->p->p.srcstn, l->msg);
							}

							pthread_mutex_unlock (&(d->local.notify_mutex));

						}

						// Invite a queue for a single station if the FS has had an ACK from it
						// in case there's a load queue waiting.

						if (p->p->p.aun_ttype == ECONET_AUN_IMM && p->p->p.port == 0x00 && p->p->p.ctrl == 0x81) // Immediate Peek to local emulator
						{
							struct __eb_printer *printer;
							//struct __eb_device *l;
							struct __econet_packet_aun *reply;
							struct utsname u;

							//uint8_t counter;
							uint8_t yline = 8;
							uint8_t found = 0;
							uint32_t replydatalen = 0;
							uint32_t startaddr, endaddr;

							memset (&(beebmem[0x7c00]), ' ', 1024);

							startaddr = (p->p->p.data[0] + (p->p->p.data[1] << 8) + (p->p->p.data[2] << 16) + (p->p->p.data[3] << 24));
							endaddr = (p->p->p.data[4] + (p->p->p.data[5] << 8) + (p->p->p.data[6] << 16) + (p->p->p.data[7] << 24));

							startaddr &= 0xffff;
							endaddr &= 0xffff;
							replydatalen = endaddr - startaddr;

							if (!uname(&u))
							{

								char os_string[80];
								uint8_t counter;

								snprintf (os_string, 40, "%-10.10s %-15.15s %-10.10s", u.sysname, u.nodename, u.release);
								beeb_print(0, 0, os_string);
								snprintf (os_string, 40, "Pi Econet Bridge %x.%x on%c%d.%d", ((EB_VERSION & 0xf0) >> 4), (EB_VERSION & 0x0f), 134, d->net, d->local.stn);
								beeb_print(2, 0, os_string);

								snprintf (os_string, 40, "%c%c%c%cStatus  %c", 141, 132, 157, 135, 156);
								beeb_print(4, 11, os_string);
								beeb_print(5, 11, os_string);
	
								/* Announce known nets */

								beeb_print(6, 0, "Known nets:");
								for (counter = 1; counter < 255; counter++)
								{
									if (networks[counter])
									{
										char	net[5];

										snprintf(net, 4, "%3d", counter);
										beeb_print (yline+(found/10), (found % 10) * 4, net);
										found++;
									}
								}

								yline += (2 + (found / 10));

								if (fsop_is_enabled(d->local.fs.server))
								{
									beeb_print (yline++, 0, "FS Discs:");
									pthread_mutex_lock(&(d->local.fs.server->fs_mutex));
									yline += 1 + fsop_writedisclist (d->local.fs.server, &(beebmem[0x7c00 + (yline * 40)]));
									pthread_mutex_unlock(&(d->local.fs.server->fs_mutex));
								}

								if ((printer = d->local.printers)) // Is a print server
								{
									//uint8_t printer_count = 0;
									char p[10];

									// Put print server text here
									

									beeb_print(yline++, 0, "Known printers:");

									found = 0;

									while (printer)
									{
										snprintf (p, 9, "%s", printer->acorn_name);
										beeb_print(yline+(found/4), (found % 4) * 10, p);
										printer = printer->next;	
										found++;
									}
									
									yline += 2 + (found / 4);	
								}
	
								if (d->local.ip.tunif[0]) // Is an IP gateway
								{
									char addr_string[40];

									snprintf(addr_string, 39, "IP Gateway at%c%s", 129, d->local.ip.addr);
									beeb_print (yline, 0, addr_string);
									yline += 2;

								}
							}

							reply = eb_malloc (__FILE__, __LINE__, "BRIDGE", "Allocate PEEK reply packet", ECONET_MAX_PACKET_SIZE);

							if (!reply)
								eb_debug (1, 0, "BRIDGE", "Unable to malloc() new PEEK reply packet");

							reply->p.srcnet = d->net;
							reply->p.srcstn = d->local.stn;
							reply->p.dstnet = p->p->p.srcnet;
							reply->p.dststn = p->p->p.srcstn;
							reply->p.aun_ttype = ECONET_AUN_IMMREP;
							reply->p.port = 0x00;
							reply->p.ctrl = 0x81;
							reply->p.seq = p->p->p.seq;
							
							memcpy (&(reply->p.data), &(beebmem[startaddr]), replydatalen);

							eb_enqueue_output (d, reply, replydatalen, NULL);
							new_output = 1;
							
							eb_free (__FILE__, __LINE__, "BRIDGE", "Freeing PEEK reply packet", reply);
							
						}
						else if (p->p->p.aun_ttype == ECONET_AUN_DATA && p->p->p.port == 0x00 && p->p->p.ctrl == 0x84 && d->local.fs.rootpath && (ECONET_DEV_STATION(d->local.fast_priv_stns, p->p->p.srcnet, p->p->p.srcstn)) && (p->p->p.data[0] == 0xff && p->p->p.data[1] == 0xff)) // USRPROC &FFFF Immediate to a local emulator - but only bother if we are an FS and would have started the *FAST handler - and ignore anything that isn't from a privileged station
						{
							pthread_mutex_lock (&(d->local.fast_io_mutex));
							d->local.fast_client_ready = p->p->p.data[4]; // 0 = Logon, 1 = Ready for data, 2 = Disconnect
							if (d->local.fast_client_ready == EB_FAST_LOGON) // New connection
							{

								d->local.fastbit = 0x00;
								d->local.fast_input_ctrl = 0;
								d->local.fast_client_net = p->p->p.srcnet;
								d->local.fast_client_stn = p->p->p.srcstn;

							}

							pthread_mutex_unlock(&(d->local.fast_io_mutex));
							pthread_cond_signal (&(d->local.fast_wake)); // Wake up the FAST handler - it should find its reset and ... well, reset.
							/*
							struct __econet_packet_aun	*r;

							if (p->p->p.data[4] == 0x00) // *FAST New Connection
							{
								eb_debug (0, 2, "LOCAL", "Local    %3d.%3d from %3d.%3d New *FAST connection",
									p->p->p.dstnet, p->p->p.dststn,
									p->p->p.srcnet, p->p->p.srcstn);

								r = eb_malloc (__FILE__, __LINE__, "FAST", "Allocate initial reply packet", ECONET_MAX_PACKET_SIZE);

								if (!r)
									eb_debug (1, 0, "FAST", "Local           Cannot allocate packet structure");

								r->p.srcstn = d->local.stn;
								r->p.srcnet = d->net;
								r->p.dststn = p->p->p.srcstn;
								r->p.dstnet = p->p->p.srcnet;
								r->p.aun_ttype = ECONET_AUN_DATA;
								r->p.port = 0x00;
								r->p.ctrl = 0x84;
								r->p.seq = eb_get_local_seq(d);
								memset(&(r->p.data), 0xff, 4);
								r->p.data[4] = 0x80;

								pthread_mutex_lock (&(d->local.fast_io_mutex));

								d->local.fastbit = 0x00;
								d->local.fast_input_ctrl = 0;
								d->local.fast_reset = 0x01; // Please re-set
								d->local.fast_client_net = p->p->p.srcnet;
								d->local.fast_client_stn = p->p->p.srcstn;
								d->local.fast_client_ready = 0;

								pthread_mutex_unlock (&(d->local.fast_io_mutex));

								pthread_cond_signal (&(d->local.fast_wake)); // Wake up the FAST handler - it should find its reset and ... well, reset.

								eb_enqueue_output (d, r, 5, NULL);

								eb_free(__FILE__, __LINE__, "FAST", "Freeing initial reply packet", r);

							}
							if (p->p->p.data[4] == 0x01) // *FAST "Client ready for output reception"
							{
								//eb_debug (0, 2, "FAST", "FAST Client signalled ready for output");
								pthread_mutex_lock (&(d->local.fast_io_mutex));
								d->local.fast_client_ready = 1;
								pthread_mutex_unlock(&(d->local.fast_io_mutex));
								pthread_cond_signal (&(d->local.fast_wake)); // Wake up the FAST handler - it should find its reset and ... well, reset.
							}
							*/
						}
						else if (p->p->p.port == 0xA0 && p->p->p.aun_ttype == ECONET_AUN_DATA && d->local.fs.rootpath && (ECONET_DEV_STATION(d->local.fast_priv_stns, p->p->p.srcnet, p->p->p.srcstn))) // *FAST character input has arrived
						{
							if ((p->p->p.ctrl & 0x01) == d->local.fast_input_ctrl)
							{
								write (d->local.fast_to_handler[1], p->p->p.data, p->length); // Write straight to the handler - why not...
								d->local.fast_input_ctrl ^= 1;
								// Signal we're ready for more input...
								eb_fast_input_ready(d, d->local.fast_client_net, d->local.fast_client_stn, EB_FAST_READY);
								new_output = 1;
							}
							else
								eb_debug (0, 2, "FAST", "         %3d.%3d from %3d.%3d Fast input ignored (ctrl bit wrong)", 
										p->p->p.dstnet, p->p->p.dststn,
										p->p->p.srcnet, p->p->p.srcstn);

						}
						else if (p->p->p.port == 0x00 && p->p->p.ctrl == 0x88 && p->p->p.aun_ttype == ECONET_AUN_IMM)
						{
							// Deal with machinetype queries here
							ack.p.aun_ttype = ECONET_AUN_IMMREP;
							ack.p.data[0] = ack.p.data[1] = 0xee;
							ack.p.data[2] = (EB_VERSION & 0x0f) << 4;
							ack.p.data[3] = (EB_VERSION & 0xf0) >> 4;

							eb_enqueue_output (d, &ack, 4, NULL);
							new_output = 1;

						}
						else if (p->p->p.port == 0x9f && (p->p->p.aun_ttype == ECONET_AUN_DATA || p->p->p.aun_ttype == ECONET_AUN_BCAST)) // Print server query
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
							reply->p.seq = eb_get_local_seq(d);
							reply->p.data[0] = reply->p.data[1] = reply->p.data[2] = 0;

							if (reply->p.dstnet == 0)
								reply->p.dstnet = d->net;

							if (querytype == PRN_QUERY_STATUS)
							{
								found = 0;

								printer = d->local.printers;

								while (printer && !found)
								{
									//eb_debug (0, 3, "PRINTER", "Looking at printer named %s", printer->acorn_name);
									if (!strcasecmp(printer->acorn_name, (char *) pname) || !strcasecmp("PRINT ", (char *) pname))
										found = 1;
									else printer = printer->next;
								}

								if (found) 
								{
									eb_debug (0, 3, "PRINTER", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s - found at %p", 
										d->net, d->local.stn,
										p->p->p.srcnet, p->p->p.srcstn,	
										(querytype == PRN_QUERY_STATUS) ? "status" : "name",
										pname, printer);

									eb_enqueue_output (d, reply, 3, NULL);	
									new_output = 1;
								}
								else eb_debug (0, 2, "PRINTER", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s NOT FOUND",
                                                                	d->net, d->local.stn,
                                                                	p->p->p.srcnet, p->p->p.srcstn,
                                                                	(querytype == PRN_QUERY_STATUS) ? "status" : "name",
                                                                	pname);

							}
							else if (querytype == PRN_QUERY_NAME)
							{
								printer = d->local.printers;

								while (printer)
								{
									snprintf ((char * restrict) &(reply->p.data[0]), 7, "%6s", printer->acorn_name);
									eb_enqueue_output (d, reply, 6, NULL);
									new_output = 1;
									printer = printer->next;
									reply->p.seq = eb_get_local_seq(d);
								}

							}

							eb_free (__FILE__, __LINE__, "PRINTER", "Freeing printer reply packet", reply);
						}
						else if (p->p->p.port == 0xD1 && p->p->p.aun_ttype == ECONET_AUN_DATA) // Print server data
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
								{
									if (job->net == p->p->p.srcnet && job->stn == p->p->p.srcstn)
										jobfound = found = 1;
									else job = job->next;
								}

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
									int8_t		printerindex;
									char *		space;
									struct __fs_active	*a;

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

									printerindex = 0xff;

									if (fsop_is_enabled(d->local.fs.server) && (a = fsop_stn_logged_in_lock(d->local.fs.server, (job->net == d->net ? 0 : job->net), job->stn))) // Is fileserver
									{
										fsop_get_username_lock(a, job->username);
										printerindex = fsop_get_user_printer(a);
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
								reply->p.seq = eb_get_local_seq(d);

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
										//char	command[512];

										if (printer->handler[0] == -'\0')
											strncpy (handler, PRN_DEFAULT_HANDLER, 126);
										else	strncpy (handler, printer->handler, 126);

	
										fclose (job->spoolfile);
	/*	
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
*/

										send_printjob (handler, reply->p.srcnet, reply->p.srcstn, 
												reply->p.dstnet, reply->p.dststn,
												job->username,
												printer->acorn_name,
												printer->unix_name,
												job->spoolfilename);

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

								eb_enqueue_output (d, reply, 1, NULL);
								new_output = 1;

							}

						}
						else if (p->p->p.port == 0xB0 && p->p->p.ctrl == 0x80 && (p->p->p.aun_ttype == ECONET_AUN_DATA || p->p->p.aun_ttype == ECONET_AUN_BCAST)) // FindServer query
						{

							char	findserver_type[9], server_type[9];
							uint8_t	my_length;
							struct __econet_packet_aun	*reply;
								
							reply = eb_malloc (__FILE__, __LINE__, "FINDSRV", "Allocate status query reply packet", 128);

							if (!reply)
								eb_debug (1, 0, "FINDSRVR", "Unable to malloc() new FindServer reply packet");
							reply->p.srcnet = d->net;
							reply->p.srcstn = d->local.stn;
							reply->p.dstnet = p->p->p.srcnet;
							reply->p.dststn = p->p->p.srcstn;
							reply->p.aun_ttype = ECONET_AUN_DATA;
							reply->p.port = 0xb1;
							reply->p.ctrl = p->p->p.ctrl;
							reply->p.seq = eb_get_local_seq(d);
			
							reply->p.data[0] = 0;
							reply->p.data[2] = EB_VERSION;
							strcpy ((char *) &(reply->p.data[12]), EB_SERVERID);
							reply->p.data[11] = strlen(EB_SERVERID);

							my_length = 12 + strlen(EB_SERVERID);

							if (reply->p.dstnet == 0)
								reply->p.dstnet = d->net;

							memset (findserver_type, 0, 9);

							memcpy (findserver_type, p->p->p.data, 8);

							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);

							eb_debug (0, 1, "FIND", "%-8s %3d.%3d FindServer request received - type '%-8s'",
								eb_type_str(d->type), d->net, d->local.stn, findserver_type);

							if (fsop_is_enabled(d->local.fs.server)) // Is fileserver
							{
								strcpy (server_type, "FILE    ");	
								if (!strcasecmp(findserver_type, "FILE    ") || !strcasecmp(findserver_type, "        "))
								{
									memcpy (&(reply->p.data[3]), server_type, 8);
									eb_enqueue_output (d, reply, my_length, NULL);
									new_output = 1;
								}
							}

							if (d->local.ip.tunif[0]) // Non-null tunnel - IP server
							{

								strcpy (server_type, "IPGW    ");	

								if (!strcasecmp(findserver_type, "IPGW    ") || !strcasecmp(findserver_type, "        "))
								{
									memcpy (&(reply->p.data[3]), server_type, 8);
									eb_enqueue_output (d, reply, my_length, NULL);
									new_output = 1;
								}
							}
							
							if (d->local.printers) // Print server
							{

								strcpy (server_type, "PRINT   ");	

								if (!strcasecmp(findserver_type, "PRINT   ") || !strcasecmp(findserver_type, "        "))
								{
									memcpy (&(reply->p.data[3]), server_type, 8);
									eb_enqueue_output (d, reply, my_length, NULL);
									new_output = 1;

								}

							}

							eb_free (__FILE__, __LINE__, "FINDSRVR", "Freeing FindServer reply packet", reply);

						}
						else if (p->p->p.port == 0xD2 && d->local.ip.tunif[0] && (p->p->p.aun_ttype == ECONET_AUN_DATA || p->p->p.aun_ttype == ECONET_AUN_BCAST)) // IP/Econet
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

										eb_enqueue_output(d, arp_reply, 8, NULL);
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
						else
						{
							/* Check to see if this is a handled port */

							eb_debug (0, 3, "BRIDGE", "%-8s %3d.%3d Looking for handler for port &%02X (ports list says 0x%02X)", eb_type_str(d->type), d->net, d->local.stn,p->p->p.port, (EB_PORT_ISSET(d,ports,p->p->p.port)));

							if (EB_PORT_ISSET(d,ports,p->p->p.port))
							{
								eb_debug (0, 3, "BRIDGE", "%-8s %3d.%3d Found handler for port &%02X, traffic type %02X, length %04X", eb_type_str(d->type), d->net, d->local.stn,p->p->p.port, p->p->p.aun_ttype, p->length);
								eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
								(d->local.port_funcs[p->p->p.port])(p->p, p->length + 12, d->local.port_param[p->p->p.port]);
							}
							/* JOB : If it's ECONET_AUN_DATA and we get here, send a NAK - port not handled - e.g. fileserver shut down. */
							/* JOB : Probably want to handle requests for port &00 here - we'll need a *list* of functions we need to send them to because it'll be more than one bit of code - but the list will be port ctrl byte, within port &00 - logically only one bit of code can handle each type of immediate. */
							else if (p->p->p.aun_ttype == ECONET_AUN_ACK || p->p->p.aun_ttype == ECONET_AUN_NAK)
							{
								/* Send ACK & NAK to fileserver, if active */

								if (fsop_is_enabled(d->local.fs.server) && EB_PORT_ISSET(d,ports,0x99))
								{
									eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
									(d->local.port_funcs[0x99])(p->p, p->length + 12, d->local.port_param[0x99]);
								}
							}
							else if (p->p->p.aun_ttype == ECONET_AUN_IMMREP && d->local.fs.server)
							{
								struct __fs_machine_peek_reg *m;

								eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
								m = eb_malloc(__FILE__, __LINE__, "Core", "New machine peek registration struct", sizeof (struct __fs_machine_peek_reg));

								m->s = d->local.fs.server;
								m->net = p->p->p.srcnet;
								m->stn = p->p->p.srcstn;
								m->mtype = (p->p->p.data[0] << 24) 
									|  (p->p->p.data[1] << 16) 
									|  (p->p->p.data[2] << 8) 
									|  (p->p->p.data[3]);

								eb_debug (0, 3, "BRIDGE", "%-8s %3d.%3d from %3d.%3d MachinePeek reply received - sending type %08X to FS", eb_type_str(d->type), d->net, d->local.stn, m->net, m->stn, m->mtype);

								fsop_register_machine (m); /* this function will free the struct */

							}
							else
								eb_debug (0, 3, "BRIDGE", "%-8s %3d.%3d NO HANDLER found for port &%02X type 0x%02X", eb_type_str(d->type), d->net, d->local.stn,p->p->p.port, p->p->p.aun_ttype);
						}
					} break;

					case EB_DEF_PIPE:
					{
						remove = 1;

						if (p->p->p.srcnet == d->net)	p->p->p.srcnet = 0;
						if (p->p->p.dstnet == d->net)	p->p->p.dstnet = 0;

						if (p->p->p.aun_ttype == ECONET_AUN_DATA)
							eb_enqueue_output (d, &ack, 0, NULL);

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
						else if (p->p->p.aun_ttype != ECONET_AUN_BCAST)
							eb_debug (0, 1, "DESPATCH", "%-8s %3d.%3d Unexpected traffic to pipe whose writer socket is not open", "Pipe", d->net, d->pipe.stn);

						
						if ((!(d->config & EB_DEV_CONF_DIRECT)) && (p->p->p.aun_ttype == ECONET_AUN_DATA))
						{
							eb_enqueue_output (d, &ack, 0, NULL); // No data on this packet
							new_output = 1;
						}
					} break;

					case EB_DEF_POOL: // Find, translate and stick on an output queue
					{
						uint8_t			dstnet, dststn;
						struct __eb_pool_host	*h;

						remove = 1;

						dstnet = p->p->p.dstnet;
						dststn = p->p->p.dststn;

						eb_add_stats(&(d->statsmutex), &(d->b_in), p->length);

						h = eb_pool_find_addr (d->pool.data, dstnet, dststn, NULL);

						if (!h) // Barf - we cannot deal with this traffic.
						{
							eb_debug (0, 1, "DESPATCH", "%-8s %3d.%3d Unable to find source pool host for pool address - traffic dropped",
									"Pool", dstnet, dststn);

						}
						else
						{
							// h will tell us where to send this.
									
							gettimeofday(&(h->last_traffic), 0);
							p->p->p.dstnet = h->s_net;
							p->p->p.dststn = h->s_stn;

							eb_enqueue_output(d, p->p, p->length, h->source); // Enqueue on source device

							eb_dump_packet (d, EB_PKT_DUMP_POST_O, p->p, p->length);
							eb_add_stats(&(h->statsmutex), &(h->b_in), p->length);

							new_output = 1;

						}
						
						remove = 1; // Take this packet off the queue, whether we sent it on or not... if we didn't, we need to drop it.


					} break;

					// NB, we don't need to deal with NULL (shouldn't have an input queue)
					// Nor should we find DEF_AUN here, because all TX to them is done via exposures direct from output queue
					default: // Don't know what to do with this
					{
						if (p->p->p.aun_ttype == ECONET_AUN_DATA)
						{
							ack.p.aun_ttype = ECONET_AUN_NAK;
							eb_enqueue_output (d, &ack, 0, NULL);
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

			uint8_t count; // Need to catch potential bridge 4-ways, so start at 0

			eb_debug (0, 4, "BRIDGE", "%-8s %3d     Setting station set for net %d", eb_type_str(other->type), other->net, net);

			pthread_mutex_lock (&(other->wire.stations_lock));

			for (count = 0; count < 255; count++)
				ECONET_SET_STATION((other->wire.stations), net, count);	

			other->wire.stations_update_rq = 1;

			pthread_mutex_unlock (&(other->wire.stations_lock));
			pthread_cond_signal (&(other->qwake));
			//ioctl(other->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(other->wire.stations));

		}
	
		other = other->next;
	}

}

/*
 * eb_setclr_single_wire_host()
 *
 * Insert, or remove, a single station from
 * an Econet wire station map used by the kernel.
 *
 */

void eb_setclr_single_wire_host (uint8_t net, uint8_t stn, uint8_t set)
{

	struct __eb_device *other;

	other = devices;

	while (other)
	{
		if (other->type == EB_DEF_WIRE)
		{
			uint8_t		real_net;

			real_net = (net == other->net) ? 0 : net;

			pthread_mutex_lock (&(other->wire.stations_lock));

			if (set)
			{
				// Listen for native net so stations can talk to it as (e.g.) 1.254 as well as 0.254 if it's on the local network (see below)
				ECONET_SET_STATION(other->wire.stations, real_net, stn);	 
			}
			else
			{
				// or take it out of the map.
				// 
				ECONET_CLR_STATION(other->wire.stations, real_net, stn);	 
				//other->wire.stations[(real_net * 32) + (stn/8)] &= ~(1 << (stn % 8));
			}

			other->wire.stations_update_rq = 1;

			pthread_mutex_unlock (&(other->wire.stations_lock));
			pthread_cond_signal (&(other->qwake));
			//ioctl(other->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(other->wire.stations)); // Poke to kernel
		}
	
		other = other->next;
	}


}

/* 
 * eb_clear_zero_hosts()
 *
 * Take all n.0 hosts out of a station map in one go.
 * Used by WhatNet/IsNet to clear out any old .0 hosts
 * which may be lurking in a station map because only
 * one 'farside' (station 0) host will respond with
 * 4-ways to WhatNet/IsNet Queries.
 *
 * NB does NOT update kernel map - caller must do that,
 * because typically the caller will have some other
 * update to follow this one.
 *
 */

void eb_clear_zero_hosts (struct __eb_device *dev)
{

	uint8_t net;

	for (net = 1; net < 255; net++)
		ECONET_CLR_STATION(dev->wire.stations, net, 0);

}

/* 
 * eb_set_single_wire_host()
 *
 * Put a single host in all the station[] values on all wired networks 
 */

void eb_set_single_wire_host (uint8_t net, uint8_t stn)
{

	eb_setclr_single_wire_host (net, stn, 1); // 1 == set

}

/* Clear a single station out of the station[] values on all wired networks */

void eb_clr_single_wire_host (uint8_t net, uint8_t stn)
{

	eb_setclr_single_wire_host (net, stn, 0); // 0 == Clear from map

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
		{
			pthread_mutex_lock (&(d->wire.stations_lock));
			memcpy (&(d->wire.stations), &(d->wire.stations_initial), sizeof (d->wire.stations));
			d->wire.stations_update_rq = 1;
			pthread_mutex_unlock (&(d->wire.stations_lock));
			pthread_cond_signal (&(d->qwake));
			//ioctl(d->wire.socket, ECONETGPIO_IOC_SET_STATIONS, &(d->wire.stations));
		}
		
		d = d->next;
	}

}

/* Return list of nets which are comma separated into an array, and return first one found, or 0 if none found */
/* If there's an asterisk anywhere in the string, it'll take it as a wildcard for "all nets" */
uint8_t	eb_parse_nets(char *netlist, uint8_t nets[])
{
	uint8_t	netptr = 0;
	char	netread[5];
	uint8_t	first_net = 0, net;

	if (strchr(netlist, '*')) // Wildcard
	{
		memset (nets, 0xff, 255);
		nets[0] = nets[255] = 0;
		return 1;
	}

	strcpy (netread, "");

	while (netptr < strlen(netlist))
	{
		if (netlist[netptr] >= '0' && netlist[netptr] <= '9' && strlen(netread) < 3)
		{
			if (strlen(netread) < 3)
			{
				netread[strlen(netread)+1] = 0;
				netread[strlen(netread)] = netlist[netptr];
			}
			else
				eb_debug (1, 0, "CONFIG", "Bad network number in list %s", netlist);
		}
		else
		{
			if (strlen(netread) > 0)
			{
				net = atoi(netread);
				nets[net] = 0xff;

				if (!first_net)
					first_net = net;

				strcpy (netread, "");
			}
			else
				eb_debug (1, 0, "CONFIG", "Bad network number in list %s", netlist);
		}

		netptr++;


	}

	if (strlen(netread) > 0)
	{
		net = atoi(netread);
		nets[net] = 0xff;

		if (!first_net)
			first_net = net;

	}

	return first_net;

}

/* Extract matched string from config file line
*/

char * eb_getstring (char *line, regmatch_t *m)
{

	line[m->rm_eo] = 0x00; // Null terminate the match, because we always have a space after our matches
	return (&line[m->rm_so]);

}

#ifdef EB_JSONCONFIG
/* If JSON Config enabled, search the json config for a network in wires and virtuals */

struct json_object * eb_json_get_net(struct json_object *jc, uint8_t net)
{
	struct json_object	*wires, *virtuals, *current, *jnet;
	uint8_t			count, wlen, vlen;

	if (!json_object_object_get_ex(jc, "econets", &wires))
		eb_debug (1, 0, "JSON", "Unable to get wires array");

	if (!json_object_object_get_ex(jc, "virtuals", &virtuals))
		eb_debug (1, 0, "JSON", "Unable to get virtuals array");

	wlen = json_object_array_length(wires);
	vlen = json_object_array_length(virtuals);

	count = 0;

	while (count < wlen)
	{
		current = json_object_array_get_idx(wires, count);
		if (json_object_object_get_ex(current, "net", &jnet))
		{
			if (json_object_get_int(jnet) == net)
				return current;
		}
		count++;
	}

	/* Try virtuals */

	count = 0;

	while (count < vlen)
	{
		current = json_object_array_get_idx(virtuals, count);
		if (json_object_object_get_ex(current, "net", &jnet))
		{
			if (json_object_get_int(jnet) == net)
				return current;
		}
		count++;
	}

	return NULL; /* Not found */
}

struct json_object * eb_json_get_net_makevirtual(struct json_object *jc, uint8_t net)
{

	struct json_object	*res, *virtuals;

	if  (!(res = eb_json_get_net(jc, net)))
	{
		json_object_object_get_ex(jc, "virtuals", &virtuals);
		res = json_object_new_object();
		json_object_object_add(res, "net", json_object_new_int(net));
		json_object_object_add(res, "diverts", json_object_new_array());
		json_object_array_add(virtuals, res);
	}

	return res;
}

struct json_object *eb_json_get_divert(struct json_object *d, uint8_t stn)
{
	struct json_object 	*current, *jstn;
	uint8_t			count, length;

	count = 0;
	length = json_object_array_length(d);

	while (count < length)
	{
		current = json_object_array_get_idx(d, count);
		if (json_object_object_get_ex(current, "station", &jstn))
		{
			if (json_object_get_int(jstn) == stn)
				return current;
		}
		count++;
	}

	return NULL;

}

struct json_object *eb_json_get_divert_makenew(struct json_object *d, uint8_t stn)
{
	struct json_object	*res;

	res = eb_json_get_divert(d, stn);

	if (!res)
	{
		/* If we got here, it wasn't found. Make one, with the right station number */

		res = json_object_new_object();
		json_object_object_add(res, "station", json_object_new_int(stn));
		json_object_object_add(res, "printers", json_object_new_array());
		json_object_object_add(res, "ipservers", json_object_new_array());
		json_object_array_add(d, res);
	}

	return res;
}

/* This works for both finding / making new aun nets, and exposed net array entries */

struct json_object *eb_json_aunnet_makenew(struct json_object *jauns, uint8_t net)
{
	uint8_t			jlength, jcount;
	struct json_object	*cur, *n;

	jlength = json_object_array_length(jauns);

	jcount = 0;

	while (jcount < jlength)
	{
		cur = json_object_array_get_idx(jauns, jcount);
		json_object_object_get_ex(cur, "net", &n);
		if (net == json_object_get_int(n))
			return cur;
		jcount++;
	}

	/* If we got here, it didn't exist - make one */

	cur = json_object_new_object();
	json_object_object_add(cur, "net", json_object_new_int(net));
	json_object_array_add(jauns, cur);

	return cur;

}

/* 
 * Add a device to an interface group, with a given priority.
 * Must be inserted in descending priority order.
 * If the group doesn't exist, create it.
 */

void eb_ig_insert_member(unsigned char *group_name, struct __eb_device *device, uint8_t group_priority)
{
	struct __eb_interface_group 	*ig;
	struct __eb_interface_member	*im, *im_cursor;

	im = eb_malloc(__FILE__, __LINE__, "IGROUP", "New group member struct", sizeof(struct __eb_interface_member));

	/* Set up content of the member struct */

	im->device = device;
	im->priority = group_priority;
	im->next = NULL;

	/* Next, see if the group exists. Callers to this routine must give us an upper case group name */

	ig = interface_groups;

	while (ig)
	{
		if (!strcmp((char *) ig->ig_name, (char *) group_name))
			break;
		else
			ig = ig->next;
	}

	if (!ig)
	{
		/* Create new interface group */

		ig = eb_malloc(__FILE__, __LINE__, "IGROUP", "New interface group", sizeof(struct __eb_interface_group));
		strncpy ((char *) ig->ig_name, (char *) group_name, 20);
		ig->first = im;
		ig->next = interface_groups;
	}
	else
	{
		im_cursor = ig->first; /* Cycle through and see if this is where we are going to insert */

		if (im_cursor && (im_cursor->priority < group_priority)) // See if first in list is lower priority than us
		{
			im->next = im_cursor;
			ig->first = im;
		}
		else
		{
			/* Trawl the list */

			while (im_cursor->next && (im_cursor->next->priority > group_priority))
			{
				im_cursor = im_cursor->next;
			}

			if (im_cursor->next) /* Next one exists, but has priority less than ours */
				im->next = im_cursor->next;

			/* We're splicing after the current entry come what may - the if() above is whether we need to join the rest of the queue on the end of our current entry */

			im_cursor->next = im;
		}
	}

	/* Set member parent group */

	im->ig = ig;

	/* Put the member struct into the device */

	device->im = im;

}

/* Parse virtuals or econets object - they're similarly formatted */

void eb_create_json_virtuals_econets(struct json_object *o, uint8_t otype)
{
	/* otype == 1 means virtuals; 2 means econets */

	uint8_t		net, stn;
	uint16_t	jcount, jlength;
	struct json_object	*jdiverts, *jstation, *jstation_number, *jprinters, *jfs, *jips, *jpipepath, *jnetclock;

	if (!json_object_object_get_ex(o, "net", &jdiverts)) /* Temp use of jdiverts */
		eb_debug (1, 0, "JSON", "Econet or virtual device in %s JSON config without a network numbers", (otype == 2) ? "Econet" : "Virtual");

	net = json_object_get_int(jdiverts);

	if (otype == 2)
	{
		struct json_object	*jfw;
		struct __eb_fw_chain	*fw_in = NULL, *fw_out = NULL;

		if (json_object_object_get_ex(o, "fw-in", &jfw))
			fw_in = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

		if (json_object_object_get_ex(o, "fw-out", &jfw))
			fw_out = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

		if (json_object_object_get_ex(o, "device", &jdiverts)) /* Temp use of jdiverts */
			eb_device_init_wire (net, (char *) json_object_get_string(jdiverts), fw_in, fw_out);
		else
			eb_debug (1, 0, "JSON", "Econet device in JSON config without a device name");

		if (json_object_object_get_ex(o, "resilience", &jfw)) // jfw being used temporarily
			networks[net]->wire.resilience = (json_object_get_boolean(jfw) ? 1 : 0);

		if (json_object_object_get_ex(o, "net-clock", &jnetclock))
		{
			double	period, mark;

			if (sscanf(json_object_get_string(jnetclock), "%lf/%lf", &period, &mark) != 2)
				eb_debug (1, 0, "JSON", "Invalid clock specifier for econet device %s", json_object_get_string(jdiverts));

			eb_device_init_set_net_clock(networks[net], period, mark);

		}

		if (json_object_object_get_ex(o, "group-name", &jfw)) /* Re-use of jfw */
		{
			unsigned char	group_name[25];
			uint8_t		group_priority;
			uint8_t		counter;

			strncpy((char *) group_name, json_object_get_string(jfw), 19);

			if (!json_object_object_get_ex(o, "group-priority", &jfw))
				eb_debug (1, 0, "JSON", "Group name set for econet network %d but group priority not set", net);

			group_priority = json_object_get_int(jfw);

			for (counter = 0; counter < strlen((char *) group_name); counter++)
				group_name[counter] = toupper(group_name[counter]);

			eb_ig_insert_member(group_name, networks[net], group_priority);
		}
	}
	else
		eb_device_init_virtual(net);

	/* Now create virtual servers */

	if (json_object_object_get_ex(o, "diverts", &jdiverts))
	{
		jcount = 0;

		jlength = json_object_array_length(jdiverts);

		while (jcount < jlength)
		{
			jstation = json_object_array_get_idx(jdiverts, jcount);	

			if (!json_object_object_get_ex(jstation, "station", &jstation_number))
				eb_debug (1, 0, "JSON", "No station number in divert number %d in %s net %d", jcount, (otype == 1) ? "virtual" : "econet", net);

			stn = json_object_get_int(jstation_number);

			json_object_object_get_ex(jstation, "printers", &jprinters);
			json_object_object_get_ex(jstation, "ipservers", &jips);

			/* Printers */

			if (jprinters)
			{
				uint16_t	pcount, plength;

				pcount = 0;

				plength = json_object_array_length(jprinters);

				while (pcount < plength)
				{
					struct json_object	*jprinter, *jacorn, *junix, *jpriority, *jdefault, *jhandler, *jusers, *juser, *jptype;
					uint8_t		priority = 1, pdefault = 1, printertype = EB_PRINTER_OTHER;


					jprinter = json_object_array_get_idx(jprinters, pcount);

					if (!json_object_object_get_ex(jprinter, "acorn-name", &jacorn))
						eb_debug (1, 0, "JSON", "Malformed printer definition on station %d.%d, index %d, has no Acorn name", net, stn, pcount);

					if (!json_object_object_get_ex(jprinter, "unix-name", &junix))
						eb_debug (1, 0, "JSON", "Malformed printer definition on station %d.%d, index %d, has no Unix printer name", net, stn, pcount);

					if (json_object_object_get_ex(jprinter, "priority", &jpriority))
						priority = json_object_get_int(jpriority);

					if (json_object_object_get_ex(jprinter, "parallel", &jptype) && json_object_get_boolean(jptype))
						printertype = EB_PRINTER_PARALLEL;
					else if (json_object_object_get_ex(jprinter, "serial", &jptype) && json_object_get_boolean(jptype))
						printertype = EB_PRINTER_SERIAL;


					if (json_object_object_get_ex(jprinter, "default", &jdefault) && !json_object_get_boolean(jdefault))
						pdefault = 0;

					/* This handles only the first user for now - but the users list is an array so in the future
					 * we can support more than one user.
					 */

					juser = NULL;

					if (json_object_object_get_ex(jprinter, "users", &jusers))
					{
						if (json_object_array_length(jusers) >= 1)
							juser = json_object_array_get_idx(jusers, 0);
					}

					eb_device_init_ps (net, stn, (char *) json_object_get_string(jacorn),
							(char *) json_object_get_string(junix),
							juser ? (char *) json_object_get_string(juser) : "",
							priority, pdefault, printertype);
						
					if (json_object_object_get_ex(jprinter, "handler", &jhandler))
						eb_device_init_ps_handler (net, stn, (char *) json_object_get_string(jacorn), (char *) json_object_get_string(jhandler));	

					pcount++;
				}
			}

			/* IP gateways */

			if (jips)
			{
				struct json_object	*jip;
				uint16_t		icount, ilength;

				icount = 0;

				ilength = json_object_array_length (jips);

				while (icount < ilength)
				{
					struct json_object	*jipinterface, *jipaddress;
					uint8_t			ip[4], masklen;
					uint32_t		ip_host, mask_host;
					char			address[30];

					jip = json_object_array_get_idx (jips, icount);

					if (!json_object_object_get_ex(jip, "interface", &jipinterface))
						eb_debug (1, 0, "JSON", "Malformed IP interface configuration on %d.%d index %d - no tunnel interface specified", net, stn, icount);

					if (!json_object_object_get_ex(jip, "ip", &jipaddress))
						eb_debug (1, 0, "JSON", "Malformed IP interface configuration on %d.%d index %d - no ip address specified", net, stn, icount);

					strncpy (address, json_object_get_string(jipaddress), 29);

					/* Parse the address / mask */

					if (sscanf(address, "%hhd.%hhd.%hhd.%hhd/%hhd",
						&(ip[3]), &(ip[2]), &(ip[1]), &(ip[0]), &masklen) != 5)
						eb_debug(1, 0, "JSON", "Bad network and/or mask for IP gateway on %d.%d index %d", net, stn, icount);
					
					ip_host = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];

					mask_host = 0;
	
					while (masklen-- > 0)
						mask_host = (mask_host >> 1) | 0x80000000;

					eb_device_init_ip (net, stn, (char *) json_object_get_string(jipinterface), ip_host, mask_host);

					icount++;	
				}
			}

			if (json_object_object_get_ex(jstation, "fileserver-path", &jfs))
			{
				struct json_object	*jtapehandler;
				uint32_t		fs_new_user_quota;
				char			fs_tape_completion_handler[512];

				if (json_object_object_get_ex(jstation, "fileserver-new-user-quota", &jtapehandler)) // Temp use of jtapehandler
					fs_new_user_quota = json_object_get_int(jtapehandler);
				else
					fs_new_user_quota = FS_DEFAULT_NEW_USER_QUOTA; // 10Mb

				if (json_object_object_get_ex(jstation, "fileserver-tape-completion-handler", &jtapehandler))
					strncpy (fs_tape_completion_handler, json_object_get_string(jtapehandler), 510);
				else	fs_tape_completion_handler[0] = 0;

				if (json_object_object_get_ex(jstation, "fileserver-tapehandler", &jtapehandler))
					eb_device_init_fs(net, stn, (char *) json_object_get_string(jfs), (char *) json_object_get_string(jtapehandler), fs_new_user_quota, (strlen(fs_tape_completion_handler) ? fs_tape_completion_handler : NULL));
				else
					eb_device_init_fs(net, stn, (char *) json_object_get_string(jfs), (char *) FS_DEFAULT_TAPE_HANDLER, fs_new_user_quota, (strlen(fs_tape_completion_handler) ? fs_tape_completion_handler : NULL));
			}

			if (json_object_object_get_ex(jstation, "pipe-path", &jpipepath))
			{
				uint8_t	flags = 0;
				struct json_object	*jpipedirect;
				char 			*pipebase;

				if (json_object_object_get_ex(jstation, "pipe-direct", &jpipedirect) && (json_object_get_boolean(jpipedirect)))
					flags |= EB_DEV_CONF_DIRECT;

				pipebase = eb_malloc (__FILE__, __LINE__, "JSON", "Create pipe base path string", json_object_get_string_len(jpipepath) + 1);
				strcpy (pipebase, json_object_get_string(jpipepath));
				eb_device_init_pipe(net, stn, pipebase, flags);
			}

			{
				struct __eb_device 	*s, *dvt;
				struct json_object	*jfw;

				s = networks[net];
				if (s->type == EB_DEF_WIRE)
					dvt = s->wire.divert[stn];
				else
					dvt = s->null.divert[stn];

				if (json_object_object_get_ex(jstation, "fw-in", &jfw))
					dvt->fw_in = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));
	
				if (json_object_object_get_ex(jstation, "fw-out", &jfw))
					dvt->fw_out = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

			}

			jcount++;
		}
	}
}

/* Parse through a list of Econets / Virtuals and feed them to the individual creator function above */

void eb_create_json_virtuals_econets_loop(struct json_object *o, uint8_t otype)
{

	uint16_t	count, length;

	count = 0;

	length = json_object_array_length(o);

	while (count < length)
	{
		eb_create_json_virtuals_econets(json_object_array_get_idx(o, count), otype);
		count++;
	}
}

/* 
 * Find pool object by name
 */

struct __eb_pool *eb_find_pool_by_name (char *poolname)
{
	struct __eb_pool *p;

	p = pools;

	while (p)
	{
		if (!strcmp((char *)p->name, poolname))
			return p;

		p = p->next;
	}

	return NULL;
}

/* Parse through a list of Econet JSON objects (0) or Trunk JSON objects (1)
 * and apply the pool assignments. At the moment, we only implement the
 * first one in the array. This will be expanded to more than one in the
 * future.
 */

void eb_json_pool_assignment (struct json_object *j, uint8_t objtype)
{

	struct json_object	*jdevice, *jpools, *jpool, *jnets, *jnet, *jpoolname, *jallpool;

	uint8_t			all_pooled = 0;
	char 			*poolname;
	uint16_t		dcount = 0, dlength;

	dlength = json_object_array_length(j);

	while (dcount < dlength)
	{
		jdevice = json_object_array_get_idx (j, dcount);

		json_object_object_get_ex (jdevice, "pool-assignment", &jpools);
		json_object_object_get_ex (jdevice, "pool-all", &jallpool);
		if (jallpool) all_pooled = json_object_get_boolean(jallpool);
	
		if (jpools)
		{
			uint16_t	pcount = 0, plength;
			struct json_object	*jnetlocalport;
	
			if (objtype) /* Trunk */
				json_object_object_get_ex (jdevice, "local-port", &jnetlocalport);
			else
				json_object_object_get_ex (jdevice, "net", &jnetlocalport);

			if (!jnetlocalport)
				eb_debug (1, 0, "JSON", "%s cannot find %s key whilst trying to do pool assignments", objtype ? "Trunk" : "Econet", objtype ? "local-port" : "net");

			plength = json_object_array_length (jpools);
	
			while (pcount < plength && pcount < 1) /* Second clause limits us to the first one */
			{
				uint8_t		ncount = 0, nlength;
				uint16_t	netlocalport;
				struct __eb_pool	*pool;
				uint8_t		nets[255];

				netlocalport = json_object_get_int(jnetlocalport);

				jpool = json_object_array_get_idx(jpools, pcount);
	
				json_object_object_get_ex (jpool, "pool-name", &jpoolname);
	
				if (!jpoolname)
					eb_debug (1, 0, "JSON", "Cannot implement pool assignment for %s %d - no pool name in pool assignment array index %d", objtype ? "Trunk" : "Econet", netlocalport, pcount);

				poolname = eb_malloc (__FILE__, __LINE__, "JSON", "Pool name string", json_object_get_string_len(jpoolname) + 1);

				strcpy (poolname, json_object_get_string(jpoolname));

				pool = eb_find_pool_by_name(poolname);

				if (!pool)
					eb_debug (1, 0, "JSON", "Cannot implement pool assignment for %s %d - pool name %s does not exist for array index %d", objtype ? "Trunk" : "Econet", netlocalport, poolname, pcount);

				json_object_object_get_ex (jpool, "nets", &jnets);

				if (!jnets)
					eb_debug (1, 0, "JSON", "Cannot implement pool assignment for %s %d - no pool 'nets' key for pool assignment array index %d", objtype ? "Trunk" : "Econet", netlocalport, pcount);

				memset(nets, 0, 255);
							
				nlength = json_object_array_length (jnets);

				while (ncount < nlength)
				{
					jnet = json_object_array_get_idx(jnets, ncount);

					nets[json_object_get_int(jnet)] = 0xff;

					ncount++;
				}
				
				/* Find the relevant wire or trunk device, and the named pool, and call eb_device_init_set_pooled_nets (pool, dev, all_pooled, nets) */

				if (!objtype) /* Econet */
				{
					if (networks[netlocalport] && networks[netlocalport]->net == netlocalport)
						eb_device_init_set_pooled_nets (pool, networks[netlocalport], all_pooled, nets);
				}
				else
				{
					struct __eb_device	*trunk;
					uint8_t			found = 0;

					/* Find relevant trunk */

					trunk = trunks;

					while (trunk && !found)
					{
						if (trunk->trunk.local_port == netlocalport)
						{
							eb_device_init_set_pooled_nets (pool, trunk, all_pooled, nets);
							found = 1;
						}

						trunk = trunk->next;
					}

					if (!found)
						eb_debug (1, 0, "JSON", "Cannot implement pool assignment for %s %d - cannot find trunk local port %d array index %d", objtype ? "Trunk" : "Econet", netlocalport, pcount);
				}

				pcount++;
			}
		}

		dcount++;
	}
}


/* Parse a JSON config and create the relevant threads etc. */

int eb_parse_json_config(struct json_object *jc)
{

	/* Order of play is this:
	 *
	 * Create firewall chains / policies (do these first so we can apply them to objects)
	 * Create interface groups
	 * Create pools, but without static mappings (we leave statics until we've created the objects they might refer to!)
	 * Create virtual networks and their 'diverted' servers (in case we've tried to create a virtual network which overlaps with an econet) - No, do this after econets because otherwise our station maps all screw up. Econets first!
	 * Create the legacy 'dynamic' network - which ultimately will refer to a pool in due course
	 * Create econets and their 'diverted' servers
	 * Create AUN hosts (these are out on their own somewhere, but we'll find out here if we're createing an AUN host which already exists as a pool, virtual or econet device)
	 * Create Trunks (these have no networks, so won't theoretically overlap with anything, so they're safe here)
	 * Create Multitrunks (likewise trunks - these are just single port TCP/TCP6 listeners which divert traffic to the real trunk when it arrives)
	 * Create pool static entries (by the time we're here, everything that should exist to map a static to should exist)
	 * Create exposures (and by here, everything should exist, save for networks we only know about on trunks / bridges, and those get disabled at startup until they are known)
	 * Set general parameters - if they haven't been changed on the command line
	 */

	struct json_object	*jgeneral;

	json_object_object_get_ex(jc, "general", &jgeneral);

	if (!jgeneral)
		eb_debug (1, 0, "JSON", "No generals entry in JSON config - cannot parse.");

	{
		struct json_object	*jchains, *jchain, *jchain_name, *jchain_entries, *jchain_default;
		uint16_t		jlength, jcount;
		uint16_t		elength, ecount;
		struct __eb_fw_chain	*fw_chain;
		struct __eb_fw		*fw_entry_last;
		uint8_t			policy;

		jcount = 0;

		if (json_object_object_get_ex(jc, "firewall-chains", &jchains))
		{
			jlength = json_object_array_length(jchains);

			while (jcount < jlength)
			{
				jchain = json_object_array_get_idx(jchains, jcount);

				if (!json_object_object_get_ex(jchain, "name", &jchain_name))
					eb_debug (1, 0, "JSON", "Cannot traverse firewall chains - found one without a name (index %d)", jcount);

				policy = EB_FW_ACCEPT;

				if (json_object_object_get_ex(jchain, "accept", &jchain_default) && !json_object_get_boolean(jchain_default))
					policy = EB_FW_REJECT;

				fw_chain = eb_malloc (__FILE__, __LINE__, "JSON", "Create new firewall chain head", sizeof(struct __eb_fw_chain));

				fw_chain->fw_chain_name = eb_malloc (__FILE__, __LINE__, "JSON", "Create firewall chain name string", strlen(json_object_get_string(jchain_name)+2));
				
				strcpy((char *) fw_chain->fw_chain_name, json_object_get_string(jchain_name));
				fw_chain->fw_default = policy;
				fw_chain->fw_chain_start = fw_entry_last = NULL;
				fw_chain->next = fw_chains;
				fw_chains = fw_chain;

				/* Now look for the entries */
				
				if (json_object_object_get_ex(jchain, "entries", &jchain_entries))
				{
					struct json_object	*jentry;

					ecount = 0;

					elength = json_object_array_length(jchain_entries);

					while (ecount < elength)
					{
						struct json_object	*jint, *jpolicy;
						struct __eb_fw		*fw_entry;

						jentry = json_object_array_get_idx(jchain_entries, ecount);

						fw_entry = eb_malloc (__FILE__, __LINE__, "JSON", "New firewall chain entry", sizeof(struct __eb_fw));
						memset (fw_entry, 0x00, sizeof(struct __eb_fw)); // 0x00 is the wildcard value, but we need to set next to NULL
						fw_entry->action = EB_FW_ACCEPT;
						fw_entry->next = NULL;

						if (json_object_object_get_ex(jentry, "source-net", &jint))
							fw_entry->srcnet = json_object_get_int(jint);
						
						if (json_object_object_get_ex(jentry, "source-station", &jint))
							fw_entry->srcstn = json_object_get_int(jint);
						
						if (json_object_object_get_ex(jentry, "destination-net", &jint))
							fw_entry->dstnet = json_object_get_int(jint);
						
						if (json_object_object_get_ex(jentry, "destination-station", &jint))
							fw_entry->dststn = json_object_get_int(jint);
						
						if (json_object_object_get_ex(jentry, "port", &jint))
							fw_entry->port = json_object_get_int(jint);
						
						fw_entry->fw_subchain = NULL;

						if ((json_object_object_get_ex(jentry, "accept", &jpolicy)))
						{
							if (json_object_get_boolean(jpolicy))
								fw_entry->action = EB_FW_ACCEPT;
							else	fw_entry->action = EB_FW_REJECT;
						}
						else if ((json_object_object_get_ex(jentry, "subchain", &jpolicy)))
						{
							fw_entry->fw_subchain = eb_get_fw_chain_byname((char *) json_object_get_string(jpolicy));
							if (!fw_entry->fw_subchain)
								eb_debug (1, 0, "JSON", "Cannot find firewall sub-chain named %s in chain name %s entry index %d", json_object_get_string(jpolicy), fw_chain->fw_chain_name, ecount);
						}

						//fprintf (stderr, "Adding firewall entry to chain %s: %d.%d -> %d.%d port %d %s\n", fw_chain->fw_chain_name, fw_entry->srcnet, fw_entry->srcstn, fw_entry->dstnet, fw_entry->dststn, fw_entry->port, fw_entry->action == EB_FW_ACCEPT ? "Accept" : "Reject");

						if (fw_entry_last)
							fw_entry_last->next = fw_entry;
						else
							fw_chain->fw_chain_start = fw_entry;

						fw_entry_last = fw_entry;

						ecount++;
					}

				}

				jcount++;
			}
		}	
		
	}

	/* Next, create interface groups */
	/* Not any more - they get created when interfaces get put in them */

	if (0) {
		struct json_object	*jig, *jig_name;
		uint16_t		jlength, jcount;

		jcount = 0;

		if (json_object_object_get_ex(jc, "interface-groups", &jig))
		{
			jlength = json_object_array_length(jig);

			while (jcount < jlength)
			{
				struct json_object	*jelement;

				jelement = json_object_array_get_idx (jig, jcount);
				if (!json_object_object_get_ex(jelement, "name", &jig_name))
					eb_debug (1, 0, "JSON", "Cannot find Interface Group name in interface group list entry %d", jcount);
				else
				{
					struct __eb_interface_group	*ig;

					ig = eb_malloc(__FILE__, __LINE__, "JSON", "New firewall interface group structure", sizeof(struct __eb_interface_group));
					ig->next = interface_groups;
					strncpy((char *) ig->ig_name, (char *) json_object_get_string(jig_name), sizeof(ig->ig_name)-2);
					interface_groups = ig;
				}

				jcount++;
			}

		}

	}

	/* Now create pools, but not static mappings - which are done when the other devices have been created */

	{
		struct json_object	*jpools, *jpool, *jpool_name, *jpool_nets, *jpool_net;
		uint16_t		jlength, jcount, nlength, ncount;
		uint8_t			nets[255], start_net;

		jcount = 0;

		if (json_object_object_get_ex(jc, "pools", &jpools))
		{
			jlength = json_object_array_length(jpools);

			while (jcount < jlength)
			{
				jpool = json_object_array_get_idx(jpools, jcount);
				if (!json_object_object_get_ex(jpool, "name", &jpool_name))
					eb_debug (1, 0, "JSON", "Cannot find pool name in pool %d", jcount);
				if (!json_object_object_get_ex(jpool, "nets", &jpool_nets))
					eb_debug (1, 0, "JSON", "Cannot find pool net list in pool %d", jcount);

				memset(&nets, 0, 255);

				nlength = json_object_array_length(jpool_nets);
				ncount = 0;

				start_net = 0xff;

				while (ncount < nlength)
				{
					uint8_t		net;

					jpool_net = json_object_array_get_idx(jpool_nets, ncount);
					net = json_object_get_int(jpool_net);

					nets[net] = 0xff;

					if (net < start_net)
						start_net = net;

					ncount++;
				}

				eb_device_init_create_pool ((char *) json_object_get_string(jpool_name), start_net, nets);	
					
				jcount++;
			}
		}
	}

	/* Now create econet(s) */

	{

		struct json_object	*jeconets;

		if (json_object_object_get_ex(jc, "econets", &jeconets))
			eb_create_json_virtuals_econets_loop(jeconets, 2);
	}

	/* Now create virtual networks & their diverted servers */

	{
		struct json_object	*jvirtuals;

		if (json_object_object_get_ex(jc, "virtuals", &jvirtuals))
			eb_create_json_virtuals_econets_loop(jvirtuals, 1);
	}

	/* Now set up the legacy 'dynamic' network */

	{
		struct json_object	*jdynamic, *jdynamic_autoack;

		if (json_object_object_get_ex(jgeneral, "dynamic", &jdynamic))
		{
			uint8_t	flags = 0, net;
			struct json_object	*jfw;
			struct __eb_fw_chain *fw_in = NULL, *fw_out = NULL;

			if (json_object_object_get_ex(jgeneral, "dynamic-fw-in", &jfw))
				fw_in = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

			if (json_object_object_get_ex(jgeneral, "dynamic-fw-out", &jfw))
				fw_out = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

			if (json_object_object_get_ex(jgeneral, "dynamic-autoack", &jdynamic_autoack) && json_object_get_boolean(jdynamic_autoack))
				flags |= EB_DEV_CONF_AUTOACK;

			net = json_object_get_int(jdynamic);

			eb_device_init_dynamic (net, flags, fw_in, fw_out);
		}
	}

	/* AUN Hosts */

	{
		struct json_object	*jaun, *jaun_entry, *jaun_net, *jstations, *jstation, *jstation_stn, *jstation_host, *jstation_port, *jstation_autoack, *jnet_baseport, *jnet_fixedport;;

		if (json_object_object_get_ex(jc, "aun", &jaun))
		{
			uint16_t	alength, acount = 0;

			alength = json_object_array_length (jaun);

			while (acount < alength)
			{

				jaun_entry = json_object_array_get_idx (jaun, acount);

				if (jaun_entry)
				{
					if (json_object_object_get_ex(jaun_entry, "net", &jaun_net))
					{
						uint8_t		net;
						struct json_object	*jfw;
						struct __eb_fw_chain	*fw_in = NULL, *fw_out = NULL;

						net = json_object_get_int(jaun_net);

						/* Not sure this is needed. If it's a whole network, the devinit should create it, and if it's a host, the new AUN host thing will create the divert */

						//if (!networks[net]) // Create if not exist
							//eb_device_init (net, EB_DEF_NULL, 0);

						if (json_object_object_get_ex(jaun_entry, "fw-in", &jfw))
							fw_in = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

						if (json_object_object_get_ex(jaun_entry, "fw-out", &jfw))
							fw_out = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

						if (json_object_object_get_ex(jaun_entry, "net-address", &jstations)) // This is an AUN MAP for a network
						{
							uint16_t	port = 32768;
							uint8_t		flags = 0, is_fixed = 1, is_autoack = 0;
							char		*net_address;
							uint8_t		base_parts[4];
							uint32_t	base;

							json_object_object_get_ex(jaun_entry, "fixed-port", &jnet_fixedport);
							json_object_object_get_ex(jaun_entry, "base-port", &jnet_baseport);
							json_object_object_get_ex(jaun_entry, "autoack", &jstation_autoack);
							json_object_object_get_ex(jaun_entry, "net-address", &jstation_host);

							if (jstation_autoack && json_object_get_boolean(jstation_autoack))
								is_autoack = 1;

							if (jnet_baseport)
								port = json_object_get_int(jnet_baseport);

							if (jnet_fixedport && !json_object_get_boolean(jnet_fixedport))
								is_fixed = 0;

							if (jstation_autoack && json_object_get_boolean(jstation_autoack))
								flags |= EB_DEV_CONF_AUTOACK;

							net_address = eb_malloc (__FILE__, __LINE__, "JSON", "New AUN Net address string", json_object_get_string_len(jstations)+1);
							strcpy (net_address, json_object_get_string(jstations));

							if (sscanf(net_address, "%hhd.%hhd.%hhd.%hhd", &base_parts[0], 
										&base_parts[1], 
										&base_parts[2],
										&base_parts[3]) != 4)
								eb_debug (1, 0, "JSON", "AUN MAP for net %d has a net-address string (%s) which is unparseable", net, net_address);

							base = 0;

							for (uint8_t count = 0; count < 4; count++)
								base = (base << 8) | base_parts[count];

							if ((base & 0xff) != 0)
								eb_debug (1, 0, "JSON", "AUN MAP for net %d has a net-address string whose LSB is non-zero (%s)", net, net_address);

							eb_free (__FILE__, __LINE__, "JSON", "AUN Net address string", net_address);

							eb_device_init_aun_net (net, base, is_fixed, port, is_autoack, fw_in, fw_out);

						}
						else
						{
							uint8_t		slength, scount = 0;

							json_object_object_get_ex(jaun_entry, "stations", &jstations);

							if (!jstations)
								eb_debug (1, 0, "JSON", "AUN Network %d is not a whole network map but has no stations key", net);

							slength = json_object_array_length (jstations);

							while (scount < slength)
							{

								uint8_t		stn, flags = 0;
								uint16_t	port = 32768;
								char 		* host;
								in_addr_t	address;
								struct hostent	*h;

								jstation = json_object_array_get_idx(jstations, scount);

								json_object_object_get_ex(jstation, "station", &jstation_stn);
								json_object_object_get_ex(jstation, "host", &jstation_host);
								json_object_object_get_ex(jstation, "port", &jstation_port);
								json_object_object_get_ex(jstation, "autoack", &jstation_autoack);

								if (json_object_get_boolean(jstation_autoack))
									flags |= EB_DEV_CONF_AUTOACK;

								if (jstation_port)
									port = json_object_get_int(jstation_port);

								if (!jstation_stn)
									eb_debug (1, 0, "JSON", "AUN host defined in net %d without a station number", net);

								stn = json_object_get_int(jstation_stn);

								if (!jstation_host)
									eb_debug (1, 0, "JSON", "AUN Host defined at %d.%d without a hostname", net, stn);

								host = eb_malloc (__FILE__, __LINE__, "JSON", "New AUN single host string", json_object_get_string_len(jstation_host) + 1);
								strcpy (host, json_object_get_string(jstation_host));

								h = gethostbyname2(host, AF_INET); // IPv4 only for AUN

								if (!h)
									eb_debug (1, 0, "JSON", "AUN Host defined at %d.%d with an unknown hostname (%s)", net, stn, host);
								address = ntohl(*((in_addr_t *)h->h_addr));

								eb_device_init_aun_host (net, stn, address, port, flags, 1, fw_in, fw_out);

								eb_free (__FILE__, __LINE__, "JSON", "AUN single host string", host);

								scount++;
							}
					
						}

					}
				}

				acount++;

			}
		}
	}

	/* Multitrunks */

	{
		uint16_t	tcount = 0, tlength;
		json_object	*jtrunks, *jtrunk;

		json_object_object_get_ex(jc, "multitrunks", &jtrunks);

		if (jtrunks)
		{
			tlength = json_object_array_length(jtrunks);

			while (tcount < tlength)
			{
				uint16_t	port = 0; /* If port unset, this multitrunk only does client connections */
				int		ai_family = AF_UNSPEC;
				json_object	*jport, *jtrunkname, *jhost, *jfamily, *jtimeout;

				jtrunk = json_object_array_get_idx(jtrunks, tcount);

				json_object_object_get_ex(jtrunk, "port", &jport);
				json_object_object_get_ex(jtrunk, "host", &jhost);
				json_object_object_get_ex(jtrunk, "family", &jfamily);
				json_object_object_get_ex(jtrunk, "name", &jtrunkname);
				json_object_object_get_ex(jtrunk, "timeout", &jtimeout); // ms of unacked data before TCP shuts connection

				if (!jtrunkname)
					eb_debug(1, 0, "JSON", "Multi-Trunk index %d does not have a trunk name", tcount);

				if (!jport)
					eb_debug (1, 0, "JSON", "Multi-Trunk index %d does not have a port number", tcount);
				else
					port = json_object_get_int(jport);

				if (jfamily)
				{
					if (strchr(json_object_get_string(jfamily), '4'))
						ai_family = AF_INET;
					else if (strchr(json_object_get_string(jfamily), '6'))
						ai_family = AF_INET6;
					else
						eb_debug (1, 0, "JSON", "Multi-Trunk index %d has unknown family parameter '%s'", json_object_get_string(jfamily));
				}	
				/*
				else
					fprintf (stderr, "\n\n** MULTITRUNK %s has no family\n\n", json_object_get_string(jtrunkname));

				fprintf (stderr, "\n\n** MULTITRUNK %s has family %d\n\n", json_object_get_string(jtrunkname), ai_family);
				*/

				eb_device_init_multitrunk(
						jhost ? (char *) json_object_get_string(jhost) : (char *) NULL,
						(char *) json_object_get_string(jtrunkname),
						port,
						ai_family,
						jtimeout ? json_object_get_int(jtimeout) : 0);

				tcount++;
			}

		}
	}

	/* Trunks */

	{
		uint16_t	tcount = 0, tlength;
		json_object	*jtrunks, *jtrunk, *jnats, *jnat, *jlocalport, *jremoteport, *jremotehost, *jkey;

		json_object_object_get_ex(jc, "trunks", &jtrunks);

		if (jtrunks)
		{
			tlength = json_object_array_length(jtrunks);

			while (tcount < tlength)
			{
				uint16_t	local_port, remote_port = 0;
				char		* remote_host, *key, *name = NULL;
				uint8_t		nat_local, nat_distant;
				uint16_t	nlength, ncount = 0;
				uint32_t	retry_interval = 10;
				unsigned char	group_name[21];
				uint8_t		group_priority;
				struct __eb_device	*trunk;
				struct json_object	*jnat_local, *jnat_remote, *jfw, *jname, *jmt_parent, *jmt_type, *jmt_retry;
				struct json_object	*jgroup_name, *jgroup_priority;
				struct __eb_fw_chain	*fw_in = NULL, *fw_out = NULL;
				struct __eb_device 	*mtp_device;
				int		mt_type = 2; /* Server by default */
				//struct __eb_interface_group	*ig;

				remote_host = NULL; // Assume dynamic unless we have a host

				jtrunk = json_object_array_get_idx(jtrunks, tcount);

				json_object_object_get_ex(jtrunk, "nat", &jnats);
				json_object_object_get_ex(jtrunk, "local-port", &jlocalport);
				json_object_object_get_ex(jtrunk, "remote-port", &jremoteport);
				json_object_object_get_ex(jtrunk, "remote-host", &jremotehost);
				json_object_object_get_ex(jtrunk, "key", &jkey);
				json_object_object_get_ex(jtrunk, "name", &jname);
				json_object_object_get_ex(jtrunk, "multitrunk-parent", &jmt_parent);
				json_object_object_get_ex(jtrunk, "multitrunk-client", &jmt_type); // Boolean - true = client
				json_object_object_get_ex(jtrunk, "multitrunk-retry-interval", &jmt_retry); // ms between connection attempts
				json_object_object_get_ex(jtrunk, "group-name", &jgroup_name);
				json_object_object_get_ex(jtrunk, "group-priority", &jgroup_priority);
	
				if (!jkey && (!jremotehost || !jremoteport)) 
				{
					/* No key, and no remote host data. If no remote host data, there
					 * has to be a key because the trunk is dynamic.
					 */

					eb_debug(1, 0, "JSON", "UDP trunk index %d has neither key nor remote host or remote port. Either specify a key (for a dynamic trunk) or host name and port (for an unencrypted static trunk)", tcount);
				}

				if (!jlocalport)
					eb_debug (1, 0, "JSON", "UDP trunk index %d has no local port specified. Cannot establish trunk without a local port.", tcount);

				local_port = json_object_get_int(jlocalport);

				if ((jremotehost && !jremoteport) || (jremoteport && !jremotehost))
					eb_debug (1, 0, "JSON", "UDP trunk index %d specifies only one of remote-port and remote-host: either specify both (for a static trunk) or neither (with a key - for a dynamic trunk)", tcount);

				if (jremoteport)
					remote_port = json_object_get_int(jremoteport);

				if (jremotehost)
				{
					remote_host = eb_malloc (__FILE__, __LINE__, "JSON", "New Trunk remote endpoint host string", json_object_get_string_len(jremotehost) + 1);
					strcpy (remote_host, json_object_get_string(jremotehost));
				}

				key = NULL; /* Dynamic trunk */

				if (jkey)
				{
					key = eb_malloc (__FILE__, __LINE__, "JSON", "New trunk key", json_object_get_string_len(jkey) + 1);
					strcpy (key, json_object_get_string(jkey));
				}

				if (jname)
				{
					name = eb_malloc (__FILE__, __LINE__, "JSON", "New trunk name", json_object_get_string_len(jname) + 1);
					strcpy (name, json_object_get_string(jname));
				}

				if (jmt_parent)
				{
					mtp_device = eb_mt_find((char *) json_object_get_string(jmt_parent));
					if (!mtp_device)
						eb_debug (1, 0, "JSON", "Multitrunk parent name %s unknown while creating trunk index %d", json_object_get_string(jmt_parent), tcount);

					if (json_object_get_boolean(jmt_type)) /* Is client */
						mt_type = 1;
				}
				else	mtp_device = NULL;

				if (json_object_object_get_ex(jtrunk, "fw-in", &jfw))
					fw_in = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

				if (json_object_object_get_ex(jtrunk, "fw-out", &jfw))
					fw_out = eb_get_fw_chain_byname((char *) json_object_get_string(jfw));

				if (jmt_retry)
					retry_interval = json_object_get_int(jmt_retry);

				if (jgroup_name && !jgroup_priority)
					eb_debug (1, 0, "JSON", "Trunk definition %d has group-name but no group-priority", tcount);

				if (jgroup_name)
				{
					strncpy ((char *) group_name, json_object_get_string(jgroup_name), 20);
					for (uint8_t counter = 0; counter < strlen((char *) group_name); counter++)
						group_name[counter] = toupper(group_name[counter]);
					group_priority = json_object_get_int(jgroup_priority);
				}
				else
				{
					group_name[0] = 0;
					group_priority = 0;
				}

				eb_device_init_singletrunk (remote_host, local_port, remote_port, key, fw_in, fw_out, name, mtp_device, mt_type, retry_interval);

				/* Insert any group data into the trunk */

				trunk = trunks;
				while (trunk)
				{
					if (trunk->trunk.local_port == local_port)
						break;
					else
						trunk = trunk->next;
				}

				if (!trunk)
					eb_debug (1, 0, "JSON", "Created trunk with local port %d but cannot find it in the trunks list!", local_port);

				/* trunk reused below for nat */

				if (group_name[0]) /* This trunk is in a group */
					eb_ig_insert_member(group_name, trunk, group_priority);

				if (key)
					eb_free (__FILE__, __LINE__, "JSON", "New trunk key", key); /* Free - the devinit routine copies it to a new malloced area */
				nlength = json_object_array_length(jnats);

				while (ncount < nlength)
				{
					jnat = json_object_array_get_idx (jnats, ncount);

					json_object_object_get_ex(jnat, "distant-net", &jnat_remote);
					json_object_object_get_ex(jnat, "local-net", &jnat_local);

					if (!jnat_remote || !jnat_local)
						eb_debug (1, 0, "JSON", "UDP Trunk definition %d has a nat entry (no. %d) which is missing either distant or local network number", tcount, ncount);

					nat_local = json_object_get_int(jnat_local);
					nat_distant = json_object_get_int(jnat_remote);

					eb_device_init_trunk_nat (trunk, nat_local, nat_distant);

					ncount++;
				}

				tcount++;

			}
		}

	}

	/* Now implement pools on wire devices and trunks, one by one */

	{

		struct json_object	*jdevs;

		/* First Econets */

		json_object_object_get_ex (jc, "econets", &jdevs);

		eb_json_pool_assignment (jdevs, 0); /* 0 = Econets */

		json_object_object_get_ex (jc, "trunks", &jdevs);

		eb_json_pool_assignment (jdevs, 1); /* 1 = Trunks */

	}

	/* Pool statics */

	{
		struct json_object	*jpools, *jpool, *jstatics, *jstatic, *jintftype, *jintfref, *jpoolnet, *jpoolstn, *jsrcnet, *jsrcstn;
		uint16_t	pcount = 0, plength;

		json_object_object_get_ex (jc, "pools", &jpools);

		if (jpools)
		{
			plength = json_object_array_length(jpools);

			while (pcount < plength)
			{
				uint16_t	scount = 0, slength, netlocalport;
				char		*poolname;
				struct json_object	* jpoolname;
				struct __eb_pool	*pool;

				jpool = json_object_array_get_idx (jpools, pcount);

				json_object_object_get_ex (jpool, "name", &jpoolname);

				if (!jpoolname)
					eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool index %d - no name key", pcount);

				poolname = eb_malloc (__FILE__, __LINE__, "JSON", "Pool name string", json_object_get_string_len(jpoolname)+1);
				strcpy ((char *)poolname, json_object_get_string(jpoolname));

				pool = eb_find_pool_by_name (poolname);

				json_object_object_get_ex (jpool, "statics", &jstatics);

				if (jstatics)
				{
					slength = json_object_array_length(jstatics);

					while (scount < slength)
					{
						jstatic = json_object_array_get_idx (jstatics, scount);
	
						json_object_object_get_ex (jstatic, "interface-type", &jintftype);
						json_object_object_get_ex (jstatic, "interface-ref", &jintfref);
						json_object_object_get_ex (jstatic, "static-net", &jpoolnet);
						json_object_object_get_ex (jstatic, "static-stn", &jpoolstn);
						json_object_object_get_ex (jstatic, "source-net", &jsrcnet);
						json_object_object_get_ex (jstatic, "source-stn", &jsrcstn);
	
						if (!jintftype)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - no interface-type key", poolname, pcount);
						if (!jintfref)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - no interface-ref key", poolname, pcount);
						netlocalport = json_object_get_int(jintfref);
	
						if (!jpoolnet)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - no static-net key", poolname, pcount);
	
						if (!jpoolstn)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - no static-stn key", poolname, pcount);
	
						if (!jsrcnet)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - no source-net key", poolname, pcount);
	
						if (!jsrcstn)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - no source-stn key", poolname, pcount);
	
						if (!strcmp("econet", json_object_get_string(jintftype)))
						{
							if (networks[netlocalport] && networks[netlocalport]->type == EB_DEF_WIRE && networks[netlocalport]->net == netlocalport)
								eb_device_init_set_pool_static (pool, networks[netlocalport],
										json_object_get_int(jpoolnet),
										json_object_get_int(jpoolstn),
										json_object_get_int(jsrcnet),
										json_object_get_int(jsrcstn));
						}
						else if (!strcmp("trunk", json_object_get_string(jintftype)))
						{
							struct __eb_device 	*trunk;
							uint8_t			found = 0;
	
							trunk = trunks;
	
							while (trunk && !found)
							{
								if (trunk->trunk.local_port == netlocalport)
									found = 1;
								else
									trunk = trunk->next;
							}
	
							if (!found)
								eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - trunk port %d doesn't exist", poolname, pcount, netlocalport);
	
							eb_device_init_set_pool_static (pool, trunk,
										json_object_get_int(jpoolnet),
										json_object_get_int(jpoolstn),
										json_object_get_int(jsrcnet),
										json_object_get_int(jsrcstn));
						}

						if (!netlocalport)
							eb_debug (1, 0, "JSON", "Cannot assign static pool address in pool %s index %d - invalid interface type %s", poolname, pcount, json_object_get_string(jintftype));
	
						scount++;
					}
				}

				eb_free (__FILE__, __LINE__, "JSON", "Pool name string", poolname);

				pcount++;
			}
		}
	}

	/* Exposures */

	{
		struct json_object	*jexposures, *jexposure, *jnet, *jipaddr, *jport, *jfixed, *jstns, *jstn;
		uint16_t		ecount = 0, elength;

		json_object_object_get_ex (jc, "exposures", &jexposures);

		if (jexposures)
		{
			elength = json_object_array_length (jexposures);

			while (ecount < elength)
			{
				jexposure = json_object_array_get_idx (jexposures, ecount);

				if (jexposure)
				{
					uint8_t		net;

					json_object_object_get_ex (jexposure, "net", &jnet);
					json_object_object_get_ex (jexposure, "net-address", &jipaddr);
					json_object_object_get_ex (jexposure, "base-port", &jport);
					json_object_object_get_ex (jexposure, "fixed-port", &jfixed);
					json_object_object_get_ex (jexposure, "stations", &jstns);

					if (!jnet)
						eb_debug (1, 0, "JSON", "Cannot create exposure index %d - no net key", ecount);

					net = json_object_get_int (jnet);

					if (!jstns) /* Expose whole net */
					{
						uint8_t		stn, is_fixed;
						uint8_t		addr_parts[4];
						uint16_t	port;
						in_addr_t	addr;
						char		* s_addr;

						if (!jipaddr)
							eb_debug (1, 0, "JSON", "Cannot create exposure for net %d index %d - no net-address key", net, ecount);
						if (jfixed)
							is_fixed = json_object_get_int (jfixed);

						s_addr = eb_malloc (__FILE__, __LINE__, "JSON", "Expose net address", json_object_get_string_len(jipaddr)+1);
						strcpy ((char *) s_addr, json_object_get_string(jipaddr));

						addr_parts[0] = addr_parts[1] = addr_parts[2] = addr_parts[3] = 0 ; // Any

						if (strcmp(s_addr, "*") && ((sscanf (s_addr, "%hhd.%hhd.%hhd.%hhd", &addr_parts[0], &addr_parts[1], &addr_parts[2], &addr_parts[3])) != 4))
							eb_debug (1, 0, "JSON", "Cannot create exposure for net %d index %d - bad ip address %s", net, ecount, s_addr);
						
						addr =	(addr_parts[0] << 24) |
							(addr_parts[1] << 16) |
							(addr_parts[2] << 8) |
							(addr_parts[3]);

						is_fixed = json_object_get_boolean(jfixed);

						if (jport)
							port = json_object_get_int(jport);
						else
							port = is_fixed ? 10000 + (256 * net) : 32768;

						for (stn = 1; stn < 255; stn++)
							eb_device_init_expose_host (net, stn, (addr & 0xff) == 0 ? (addr | stn) : addr, 
									port + (is_fixed ? 0 : stn),
									0);

						DEVINIT_DEBUG ("Exposed net %d at address %s base-port %d (%sfixed)", net, s_addr, port, is_fixed ? "" : "not ");

						eb_free (__FILE__, __LINE__, "JSON", "Expose net address", s_addr);

					}
					else /* Expose single hosts */
					{
						uint16_t	scount = 0, slength;

						slength = json_object_array_length (jstns);

						while (scount < slength)
						{
							struct json_object 	*jhost, *jport, *jstation, *jfwin, *jfwout;
							uint8_t			stn;
							uint16_t		port;
							uint8_t			addr_parts[4];
							in_addr_t		addr;
							char			*s_addr;

							jstn = json_object_array_get_idx (jstns, scount);

							json_object_object_get_ex (jstn, "host", &jhost);
							json_object_object_get_ex (jstn, "port", &jport);
							json_object_object_get_ex (jstn, "station", &jstation);
							json_object_object_get_ex (jstn, "fw-in", &jfwin);
							json_object_object_get_ex (jstn, "fw-out", &jfwout);

							if (!jhost)
								eb_debug (1, 0, "JSON", "Cannot create exposure for station index %d in net %d - no host key", scount, net);
							s_addr = eb_malloc (__FILE__, __LINE__, "JSON", "Expose host address string", json_object_get_string_len(jhost) + 1);
							strcpy ((char *) s_addr, json_object_get_string(jhost));

							addr_parts[0] = addr_parts[1] = addr_parts[2] = addr_parts[3] = 0 ; // Any
	
							if (strcmp(s_addr, "*") && ((sscanf (s_addr, "%hhd.%hhd.%hhd.%hhd", &addr_parts[0], &addr_parts[1], &addr_parts[2], &addr_parts[3])) != 4))
								eb_debug (1, 0, "JSON", "Cannot create exposure for net %d index %d - bad ip address %s", net, ecount, s_addr);
						
							//if ((sscanf(s_addr, "%hhd.%hhd.%hhd.%hhd", &addr_parts[0], &addr_parts[1], &addr_parts[2], &addr_parts[3])) != 4)
								//eb_debug (1, 0, "JSON", "Cannot create exposure for station index %d in net %d - bad host IP address %s", scount, net, s_addr);
								
							eb_free (__FILE__, __LINE__, "JSON", "Expose host address string", s_addr);

							addr = (addr_parts[0] << 24) | (addr_parts[1] << 16) | (addr_parts[2] << 8) | addr_parts[3];

							if (!jport)
								eb_debug (1, 0, "JSON", "Cannot create exposure for station index %d in net %d - no port key", scount, net);

							port = json_object_get_int (jport);

							if (!jstation)
								eb_debug (1, 0, "JSON", "Cannot create exposure for station index %d in net %d - no station key", scount, net);
							stn = json_object_get_int (jstation);

							eb_device_init_expose_host (net, stn, addr, port, 1);

							scount++;
						}
					}

				}

				ecount++;
			}
		}
	}

	/* Now go through each device - econet, trunk, exposure, pipe, local emulator - and find any firewall chain that's been applied,
	 * and set them in the relevant devices.
	 *
	 * Actually, we should just do this in the device creation - we construct the firewall chains first off, so they'll all exist.
	 * Just need to set fw-in / fw-out
	 *
	 * And we need to implement that in the actual bridge, too...
	 */

	/* Generals */

	{
		struct json_object	*j, *jgen;
		uint8_t	hostcount, hostnamelen;

		json_object_object_get_ex(jc, "general", &jgen);
		if (!jgen)
			eb_debug (1, 0, "JSON", "Unable to find general key in JSON config!");

		/* Bridge-wide firewall */
		json_object_object_get_ex(jgen, "fw", &j);

		if (j)
		{
			char	*fwchain;

			fwchain = eb_malloc (__FILE__, __LINE__, "JSON", "Bridge-wide firewall chain name string", json_object_get_string_len(j)+1);
			strcpy (fwchain, json_object_get_string(j));

			bridge_fw = eb_get_fw_chain_byname(fwchain);

			eb_free (__FILE__, __LINE__, "JSON", "Bridge-wide firewall chain name string", fwchain);
		}
		else	bridge_fw = NULL;

#define EB_JSON_TUNABLE_INT(x,y)	json_object_object_get_ex(jgen, x, &j); \
				if (j) \
				{\
					uint32_t	i;\
					i = json_object_get_int(j); \
					y = i; \
				}

#define EB_JSON_TUNABLE_BOOL(x,y)	json_object_object_get_ex(jgen, x, &j); \
				if (j) \
				{\
					uint32_t	i;\
					i = json_object_get_boolean(j);\
					y = !!i;\
				}

#define EB_JSON_TUNABLE_STRING(x,y)	json_object_object_get_ex(jgen, x, &j); \
				if (j) \
				{\
					strcpy(y,json_object_get_string(j));\
				}

		srandom(time(NULL));
		config.trunk_loopdetect_id = random();
		config.trunk_loopdetect_disable = 0; /* Not disabled */
		gethostname (hostname, 255);
		loopdetect_hostdata = 0;
		EB_CONFIG_TRUNK_LOOPDETECT_INTERVAL = 10;

		/* Build our hostdata, to differentiate between accidentally identical loopdetect IDs */

		hostcount = 0;
		hostnamelen = strlen(hostname);

		while (hostcount < 8)
		{
			loopdetect_hostdata = loopdetect_hostdata << 4;
			loopdetect_hostdata |= ((hostcount >= hostnamelen) ? 0x0F : (hostname[hostcount] & 0x0F));
			hostcount++;
		}	
		
		if (pthread_mutex_init(&loopdetect_mutex, NULL) == -1)
		{
			fprintf (stderr, "Failed to initialize loop detect mutex.\n");
			exit (EXIT_FAILURE);
		}

		config.trunk_pool_no_unmapped_fsver = 0;

		EB_JSON_TUNABLE_BOOL("disable-econet", EB_CONFIG_LOCAL);
		EB_JSON_TUNABLE_INT("debug-level", EB_DEBUG_LEVEL);
		if (!j) // No debug-level
			EB_DEBUG_LEVEL = 0;
		EB_JSON_TUNABLE_INT("packet-dump-bytes", EB_CONFIG_MAX_DUMP_BYTES);
		EB_JSON_TUNABLE_BOOL("kernel-extralogs", EB_CONFIG_EXTRALOGS);
		EB_JSON_TUNABLE_INT("fs-stats-port", EB_CONFIG_FS_STATS_PORT);
		EB_JSON_TUNABLE_BOOL("no-bridge-announce-debug", EB_CONFIG_NOBRIDGEANNOUNCEDEBUG);
		EB_JSON_TUNABLE_BOOL("no-keepalive-debug", EB_CONFIG_NOKEEPALIVEDEBUG);
		EB_JSON_TUNABLE_INT("wire-max-not-listening", EB_CONFIG_WIRE_MAX_NOTLISTENING);
		EB_JSON_TUNABLE_INT("trunk-keepalive-interval", EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL);
		EB_JSON_TUNABLE_INT("trunk-dead-interval", EB_CONFIG_TRUNK_DEAD_INTERVAL);
		EB_JSON_TUNABLE_INT("pool-dead-interval", EB_CONFIG_POOL_DEAD_INTERVAL);
		EB_JSON_TUNABLE_BOOL("leds-off", EB_CONFIG_LEDS_OFF);
		EB_JSON_TUNABLE_BOOL("leds-off", EB_CONFIG_BLINK_ON); /* Yes, we need to set both */
		EB_JSON_TUNABLE_BOOL("led-blink-on", EB_CONFIG_BLINK_ON);
		EB_JSON_TUNABLE_INT("wire-max-tx", EB_CONFIG_WIRE_RETRIES);
		EB_JSON_TUNABLE_INT("aun-max-tx", EB_CONFIG_AUN_RETRIES);
		EB_JSON_TUNABLE_INT("wire-interval", EB_CONFIG_WIRE_RETX);
		EB_JSON_TUNABLE_INT("aun-interval", EB_CONFIG_AUN_RETX);
		EB_JSON_TUNABLE_INT("wire-imm-wait", EB_CONFIG_WIRE_IMM_WAIT);
		EB_JSON_TUNABLE_INT("aun-nak-tolerance", EB_CONFIG_AUN_NAKTOLERANCE);
		EB_JSON_TUNABLE_INT("immediate-timeout", EB_CONFIG_WIRE_IMM_WAIT);
		EB_JSON_TUNABLE_INT("flashtime", EB_CONFIG_FLASHTIME);
		EB_JSON_TUNABLE_BOOL("enable-syst-fast", fs_set_syst_bridgepriv);
		EB_JSON_TUNABLE_INT("wire-reset-qty", EB_CONFIG_WIRE_RESET_QTY);
		EB_JSON_TUNABLE_INT("wire-update-qty", EB_CONFIG_WIRE_UPDATE_QTY);
		EB_JSON_TUNABLE_INT("trunk-reset-qty", EB_CONFIG_TRUNK_RESET_QTY);
		EB_JSON_TUNABLE_INT("trunk-update-qty", EB_CONFIG_TRUNK_UPDATE_QTY);
		EB_JSON_TUNABLE_INT("trunk-loopdetect-id", EB_CONFIG_TRUNK_LOOPDETECT_ID);
		EB_JSON_TUNABLE_BOOL("trunk-loopdetect-disable", EB_CONFIG_TRUNK_LOOPDETECT_DISABLE);
		EB_JSON_TUNABLE_INT("trunk-loopdetect-interval", EB_CONFIG_TRUNK_LOOPDETECT_INTERVAL);
		EB_JSON_TUNABLE_BOOL("trunk-pool-no-unmapped-fsver", EB_CONFIG_TRUNK_POOL_NO_UNMAPPED_FSVER);
		EB_JSON_TUNABLE_INT("bridge-query-interval", EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL);
		EB_JSON_TUNABLE_BOOL("bridge-loop-detect", EB_CONFIG_BRIDGE_LOOP_DETECT);
		EB_JSON_TUNABLE_BOOL("pool-reset", EB_CONFIG_POOL_RESET_FWD);
		EB_JSON_TUNABLE_INT("stats-port", EB_CONFIG_STATS_PORT);
		EB_JSON_TUNABLE_INT("fs-stats-port", EB_CONFIG_FS_STATS_PORT);
		EB_JSON_TUNABLE_BOOL("malloc-debug", EB_DEBUG_MALLOC);
		EB_JSON_TUNABLE_BOOL("normalize-debug", normalize_debug);

		/* This one's a negative bool */

		json_object_object_get_ex(jgen, "disable-7bitbodge", &j); 

		if (j) 
		{
			uint32_t	i;
			i = json_object_get_boolean(j); 
			fs_sevenbitbodge = !i; 
		}

		json_object_object_get_ex(jgen, "max-sockets", &j);

		if (j)
		{
			struct rlimit	max_fds;

			max_fds.rlim_cur = max_fds.rlim_max = json_object_get_int(j);

			setrlimit (RLIMIT_NOFILE, &max_fds);
		}

		json_object_object_get_ex(jgen, "packet-dump", &j);

		if (j)
		{
			char 	*opt;

			opt = eb_malloc(__FILE__, __LINE__, "JSON", "Packet dump option string", json_object_get_string_len(j)+1);
			strcpy(opt, json_object_get_string(j));
                        if (strchr(opt, 'i'))        EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_PRE_I;
                        if (strchr(opt, 'I'))        EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_POST_I;
                        if (strchr(opt, 'o'))        EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_PRE_O;
                        if (strchr(opt, 'O'))        EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_POST_O;
		}
 
	}

	/* Free up the pointers */

	json_object_put(jc); /* Free the memory */

	eb_debug (0, 2, "CONFIG", "%-16s JSON configuration read successfully", "Core");

	return 1;

}

/* Find a firewall chain called 'name' in json config 'config' */

struct json_object * eb_json_fw_chain(char *name, struct json_object *config)
{

	struct json_object	*jchains, *jchain, *jchain_name;
	uint16_t		jlength, jcount;

	jcount = 0;

	if (json_object_object_get_ex(config, "firewall-chains", &jchains))
	{
		jlength = json_object_array_length(jchains);

		while (jcount < jlength)
		{
			jchain = json_object_array_get_idx(jchains, jcount);
			if (!json_object_object_get_ex(jchain, "name", &jchain_name))
				eb_debug (1, 0, "JSON", "Cannot traverse firewall chains - found one without a name!");
			if (!strcasecmp(name, json_object_get_string(jchain_name)))
				return jchain;

			jcount++;
		}

		/* If we get here, we didn't find it */

	}
	else
		eb_debug (1, 0, "JSON", "Cannot find firewall-chains element in main config");

	return NULL; /* Not found */
}

/* Find a firewall chain called 'name' in json config 'config' using the function above, and make a new one if we can't find it
 */

struct json_object * eb_json_fw_chain_makenew(char *name, struct json_object *config)
{
	struct json_object	*jchain, *jchains;

	jchain = eb_json_fw_chain(name, config);

	if (!jchain)
	{
		if (json_object_object_get_ex(config, "firewall-chains", &jchains))
		{
			jchain = json_object_new_object();
			json_object_object_add(jchain, "name", json_object_new_string(name));
			json_object_object_add(jchain, "accept", json_object_new_boolean((json_bool)1)); /* Default - we can change it */
			json_object_object_add(jchain, "entries", json_object_new_array());
			json_object_array_add(jchains, jchain);

			return jchain;
		}
		else
			eb_debug (1, 0, "JSON", "Cannot find firewall-chains element in main config");
	}

	return jchain;
}

/*
 * Find a firewall chain by name in the main
 * bridge config, and return its chain struct
 */

struct __eb_fw_chain * eb_get_fw_chain_byname (char * name)
{

	struct __eb_fw_chain 	*chain;

	chain = fw_chains;

	while (chain)
	{
		if (!strcasecmp(name, (char *) chain->fw_chain_name))
			return chain;

		chain = chain->next;
	}

	return NULL;
}

#endif 

/* Read and execute the main bridge config
*/

#ifdef EB_JSONCONFIG
int eb_readconfig(char *f, char *json, struct json_object **jcparam)
#else
int eb_readconfig(char *f, char *json)
#endif
{

	FILE 	*cfg;

#ifdef EB_JSONCONFIG
	struct json_object *	jc, *jgeneral, *jpools, *jfw_chains, *jfw_bridge, *jfw_bridge_entries;
	FILE 	*jsonfile;
#endif

#ifdef IPV6_TRUNKS
	int	getaddrerr;
	
	struct addrinfo	hints;
#endif

#ifdef EB_JSONCONFIG
	jc = json_object_new_object();
	*jcparam = jc;
	jgeneral = json_object_new_object();
	json_object_object_add(jc, "general", jgeneral);
	json_object_object_add(jgeneral, "fw", json_object_new_string("BRIDGE"));
	json_object_object_add(jc, "econets", json_object_new_array());
	json_object_object_add(jc, "virtuals", json_object_new_array());
	json_object_object_add(jc, "trunks", json_object_new_array());
	json_object_object_add(jc, "multitrunks", json_object_new_array());
	jpools = json_object_new_array();
	json_object_object_add(jc, "pools", jpools);
	json_object_object_add(jc, "aun", json_object_new_array());
	json_object_object_add(jc, "exposures", json_object_new_array());
	jfw_chains = json_object_new_array();
	jfw_bridge = json_object_new_object(); // Bridge-wide firewall
	json_object_object_add(jfw_bridge, "name", json_object_new_string("BRIDGE"));
	json_object_object_add(jfw_bridge, "accept", json_object_new_boolean((json_bool)1));
	jfw_bridge_entries = json_object_new_array();
	json_object_object_add(jfw_bridge, "entries", jfw_bridge_entries);
	json_object_object_add(jc, "firewall-chains", jfw_chains);
	json_object_array_add(jfw_chains, jfw_bridge);
#endif

	regex_t	r_comment,
		r_empty,
		r_wire,
		r_trunk,
		r_trunk_plaintext,
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
		r_bindto,
		r_pool_new,
		r_pool_static_trunk,
		r_pool_static_wire,
		r_pool_net_trunk,
		r_pool_net_wire;

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
	
	if (regcomp(&r_trunk_plaintext, EB_CFG_TRUNK_PLAINTEXT, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile Plaintext IP trunk regex");
	
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
	
	if (regcomp(&r_pool_new, EB_CFG_NEW_POOL, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile new pool regex");

	if (regcomp(&r_pool_static_trunk, EB_CFG_STATIC_POOL_TRUNK, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile trunk static pool regex");

	if (regcomp(&r_pool_static_wire, EB_CFG_STATIC_POOL_WIRE, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile wire static pool regex");

	if (regcomp(&r_pool_net_trunk, EB_CFG_NET_POOL_TRUNK, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile trunk net pool regex");

	if (regcomp(&r_pool_net_wire, EB_CFG_NET_POOL_WIRE, REG_EXTENDED | REG_ICASE) != 0)
		eb_debug(1, 0, "CONFIG", "Cannot compile wire net pool regex");

#ifdef IPV6_TRUNKS

	/* Set up default trunk bind hosts - NB this is not used yet... */

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;

	if ((getaddrerr = getaddrinfo(NULL, "32768", &hints, &trunk_bindhosts)))
	{
		eb_debug(1, 0, "CONFIG", "Cannot getaddrinfo(any): %s", gai_strerror(getaddrerr));
	}
	else
	{
		struct addrinfo	*a;
		/*
		 * NB, if user has TRUNK BIND in their config, we'll need to
		 * free the *res list with freeaddrinfo()
		 */

		a = trunk_bindhosts;

		while (a)
		{
			char 	addr_str[40];

			switch (a->ai_family)
			{
				case AF_INET:
					inet_ntop(AF_INET, &(((struct sockaddr_in *)a->ai_addr)->sin_addr), addr_str, a->ai_addrlen);
					break;
				case AF_INET6:
					inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)a->ai_addr)->sin6_addr), addr_str, a->ai_addrlen);
					break;

				default: strcpy(addr_str, "Unknown family"); break;
			}

			eb_debug (0, 1, "CONFIG", "'Any' address includes %s", addr_str);

			a = a->ai_next;
		}



	}
#endif // IPV6_TRUNKS

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
		uint8_t		is_plaintext = 0; // Used in the recgcomp to detect a plaintext trunk
		
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
#ifndef EB_JSONCONFIG
				/* Old - moved to devinit
				struct __eb_device	*p;
				short			c_net, c_stn;
				*/
#endif

#ifdef EB_JSONCONFIG
				struct json_object	*wire, *econets;
#endif

				net = atoi(eb_getstring(line, &matches[1]));
				strncpy (device, eb_getstring(line, &matches[2]), 127);

#ifdef EB_JSONCONFIG
				json_object_object_get_ex(jc, "econets", &econets);
				wire = json_object_new_object();
				json_object_object_add(wire, "device", json_object_new_string(device));
				json_object_object_add(wire, "net", json_object_new_int(net));
				json_object_object_add(wire, "diverts", json_object_new_array());
				json_object_object_add(wire, "pool-assignment", json_object_new_array());
				json_object_array_add(econets, wire);
#else
				eb_device_init_wire (net, device, NULL, NULL);
#endif
			}
			else if (!regexec(&r_trunk, line, 4, matches, 0) ||
				(!regexec(&r_trunk_plaintext, line, 3, matches, 0) && (is_plaintext = 1)))
			{
				char *			destination;
				char *			colon;
				uint16_t		local_port, remote_port;
				// Old uint8_t			is_dynamic;
				char *			psk;
#ifdef EB_JSONCONFIG
				struct json_object	*jtrunk, *jtrunks;
#endif

				if (!regexec(&r_trunk_plaintext, line, 3, matches, 0))
					is_plaintext = 1; // Old non-keyed trunk - cannot do dynamic

				destination = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create Trunk destination host string", strlen(eb_getstring(line, &matches[2])) + 1);
				if (!destination)	eb_debug (1, 0, "CONFIG", "Unable to malloc() string for trunk destination %s", eb_getstring(line, &matches[2]));

				//strncpy (destination, eb_getstring(line, &matches[2]), strlen(eb_getstring(line, &matches[2])) + 1);
				strcpy (destination, eb_getstring(line, &matches[2])); // Won't overflow because of the eb_malloc above.
				local_port = atoi(eb_getstring(line, &matches[1]));
				remote_port = 0;

				/* Old
				is_dynamic = 0;
				*/

				if (!strcasecmp(destination, "dynamic") && !is_plaintext)
				{
					eb_free(__FILE__, __LINE__, "CONFIG", "Free unused trunk destination host string", destination);
					destination = NULL;
				}
				else
				{
					colon = strchr(destination, ':');
					if (!colon)	eb_debug (1, 0, "CONFIG", "Bad configuration line - no port specifier on trunk destination: %s", destination);
					*colon = '\0';
					colon++; // Now points to port
					remote_port = atoi(colon);

				}

				if (!is_plaintext)
				{
					psk = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create trunk shared key string", 32);
						
					// Pad supplied key with zeros
					memset (psk, 0, 32);
	
					if (!psk)
						eb_debug (1, 0, "CONFIG", "Unable to malloc() string for trunk shared key - trunk port %d", local_port);

					//strncpy ((char *) psk, eb_getstring (line, &matches[3]), strlen(eb_getstring(line, &matches[3])) + 1);
					strncpy ((char *) psk, eb_getstring (line, &matches[3]), 31);
				}
				else	psk = NULL;

#ifdef EB_JSONCONFIG
				json_object_object_get_ex(jc, "trunks", &jtrunks);
				jtrunk = json_object_new_object();
				json_object_object_add(jtrunk, "nat", json_object_new_array());
				json_object_object_add(jtrunk, "pool-assignment", json_object_new_array());
				json_object_object_add(jtrunk, "local-port", json_object_new_int(local_port));
				// Old if (!is_dynamic)
				if (destination) /* Not dyunamic */
				{
					json_object_object_add(jtrunk, "remote-port", json_object_new_int(remote_port));
					json_object_object_add(jtrunk, "remote-host", json_object_new_string(destination));
				}
				if (!is_plaintext)
					json_object_object_add(jtrunk, "key", json_object_new_string(psk));

				json_object_array_add(jtrunks, jtrunk);

				// Free destination - not required any more and it's a leak otherwise
				eb_free (__FILE__, __LINE__, "CONFIG", "Free trunk destination string - copied to JSON", destination);
				// Similarly the psk if there is one
				if (psk)
					eb_free (__FILE__, __LINE__, "CONFIG", "Free trunk key string - copied to JSON", psk);

#else
				eb_device_init_singletrunk (destination, local_port, remote_port, psk, NULL, NULL, NULL, 10000);
#endif
				
			}
			else if (!regexec(&r_dynamic, line, 3, matches, 0))
			{
				//printf ("Identified as dynamic - network %s flags %s\n", eb_getstring(line, &matches[1]), eb_getstring(line, &matches[2]));

				uint8_t			net;
				uint8_t			flags = 0;
#ifdef EB_JSONCONFIG
				struct json_object	*general;
#endif

				if (!strcasecmp(eb_getstring(line, &matches[2]), "AUTOACK"))
					flags = EB_DEV_CONF_AUTOACK;
				
				net = atoi(eb_getstring(line, &matches[1]));

#ifdef EB_JSONCONFIG
				json_object_object_get_ex(jc, "general", &general);
				json_object_object_add(general, "dynamic", json_object_new_int(net));
				if (flags & EB_DEV_CONF_AUTOACK)
					json_object_object_add(general, "dynamic-autoack", json_object_new_boolean((json_bool)1));
#else
				eb_device_init_dynamic (net, flags, NULL, NULL);

#endif

			}
			else if (!regexec(&r_fileserver, line, 3, matches, 0))
			{
				uint8_t			net, stn;
#ifdef EB_JSONCONFIG
				struct json_object	*jnet, *divert, *jfs, *diverts;
#endif

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for fileserver in config line %s", line);
#ifdef EB_JSONCONFIG
				jnet = eb_json_get_net_makevirtual(jc, net);

				json_object_object_get_ex(jnet, "diverts", &diverts);
				divert = eb_json_get_divert_makenew(diverts, stn);
				if (json_object_object_get_ex(divert, "fileserver-path", &jfs))
					eb_debug (1, 0, "JSON", "Fileserver already exists on %d.%d", net, stn);

				json_object_object_add(divert, "fileserver-path", json_object_new_string(eb_getstring(line, &matches[2])));
#else
				eb_device_init_fs (net, stn, eb_getstring(line, &matches[2]), FS_DEFAULT_TAPE_HANDLER, FS_DEFAULT_NEW_USER_QUOTA, NULL);
#endif

			}
			else if (!regexec(&r_printserver, line, 4, matches, 0) || !regexec(&r_printserver_user, line, 5, matches, 0))
			{
				uint8_t			net, stn;
				char			acorn_printer[7], unix_printer[128];
				char			user[11];

#ifdef EB_JSONCONFIG
				struct json_object	*jnet, *jps, *jpusers, *diverts, *divert, *jprinter;
#endif

				strncpy (acorn_printer, eb_getstring(line, &matches[2]), 7);
				strncpy (unix_printer, eb_getstring(line, &matches[3]), 127);

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for print server in config line %s", line);

#ifdef EB_JSONCONFIG
				jnet = eb_json_get_net_makevirtual(jc, net);

				json_object_object_get_ex(jnet, "diverts", &diverts);
				divert = eb_json_get_divert_makenew(diverts, stn);
				json_object_object_get_ex(divert, "printers", &jps);
				jprinter = json_object_new_object();
				json_object_object_add(jprinter, "acorn-name", json_object_new_string(acorn_printer));
				json_object_object_add(jprinter, "unix-name", json_object_new_string(unix_printer));
				json_object_object_add(jprinter, "priority", json_object_new_int(json_object_array_length(jps) + 1));
				json_object_object_add(jprinter, "default", json_object_new_boolean((json_bool) json_object_array_length(jps) == 0 ? 1 : 0));
#endif
				strcpy (user, "");

                                if (!regexec(&r_printserver_user, line, 5, matches, 0))
				{
					strcpy (user, eb_getstring(line, &matches[4]));
#ifdef EB_JSONCONFIG
					jpusers = json_object_new_array();
					json_object_array_add(jpusers, json_object_new_string(user));
					json_object_object_add(jprinter, "users", jpusers);
#endif
				}
#ifdef EB_JSONCONFIG
				json_object_array_add(jps, jprinter);
#else
				eb_device_init_ps (net, stn, acorn_printer, unix_printer, user, 1, 1, EB_PRINTER_OTHER);
#endif

			}
			else if (!regexec(&r_printhandler, line, 4, matches, 0))
			{
				uint8_t		net, stn;
				char		acorn_name[7], handler[128];

#ifdef EB_JSONCONFIG
				struct json_object	*jnet, *diverts, *divert, *jps, *jprinter;
				uint8_t			jlength, jcount;
#endif

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for print handelr configuration line %s", line);

				strncpy (acorn_name, eb_getstring(line, &matches[2]), 6);

				strncpy (handler, eb_getstring(line, &matches[3]), 126);
				
#ifdef EB_JSONCONFIG
			
				jnet = eb_json_get_net(jc, net);

				if (!jnet)
					eb_debug (1, 0, "JSON", "Attempt to set print handler for printer on unknown network %d", net);

				json_object_object_get_ex(jnet, "diverts", &diverts);

				divert = eb_json_get_divert(diverts, stn);

				if (!divert)
					eb_debug (1, 0, "JSON", "Attempt to set print handler for printer on unknown station %d.%d", net, stn);

				if (!json_object_object_get_ex(divert, "printers", &jps))
					eb_debug (1, 0, "JSON", "printers key missing from divert for %d.%d", net, stn);

				jcount = 0;

				jlength = json_object_array_length(jps);

				while (jcount < jlength)
				{
					jprinter = json_object_array_get_idx(jps, jcount);

					if (jprinter)
					{
						struct json_object	*jacorn_name;

						if (json_object_object_get_ex(jprinter, "acorn-name", &jacorn_name))
						{
							if (!strcasecmp(acorn_name, json_object_get_string(jacorn_name)))
							{
								/* Found */

								json_object_object_add(jprinter, "handler", json_object_new_string(handler));
								jcount = 254; /* Rogue */
							}
						}
						else
							eb_debug (1, 0, "JSON", "Missing acorn_name key in JSON for printer!");
					}

					jcount++;
				}
				
#else
				eb_device_init_ps_handler (net, stn, acorn_name, handler);
#endif
				
			}
			else if (!regexec(&r_ipserver, line, 4, matches, 0))
			{
				char			addr[20], tunif[10];
				uint8_t			net, stn;
				uint8_t			ip[4];
				uint8_t			masklen;
#ifndef EB_JSONCONFIG
				uint32_t		ip_host, mask_host;
#else
				struct json_object	*jnet, *diverts, *divert, *ipservers, *jipaddr;
#endif

				strcpy (tunif, eb_getstring(line, &matches[2]));
				strcpy (addr, eb_getstring(line, &matches[3]));

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for IP gateway in config line %s", line);

				if (sscanf(eb_getstring(line, &matches[3]), "%hhd.%hhd.%hhd.%hhd/%hhd",
					&(ip[3]), &(ip[2]), &(ip[1]), &(ip[0]), &masklen) != 5)
					eb_debug(1, 0, "CONFIG", "Bad network and/or mask for IP gateway in config line %s", line);
					
#ifndef EB_JSONCONFIG
				ip_host = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];

				mask_host = 0;

				while (masklen-- > 0)
					mask_host = (mask_host >> 1) | 0x80000000;
				
				eb_device_init_ip (net, stn, tunif, ip_host, mask_host);
#else
				jipaddr = json_object_new_object();
				json_object_object_add(jipaddr, "interface", json_object_new_string(tunif));
				json_object_object_add(jipaddr, "ip", json_object_new_string(addr));

				jnet = eb_json_get_net_makevirtual(jc, net);

				json_object_object_get_ex(jnet, "diverts", &diverts);

				divert = eb_json_get_divert_makenew(diverts, stn);

				if (!json_object_object_get_ex(divert, "ipservers", &ipservers))
					eb_debug (1, 0, "JSON", "ipservers key missing from divert for %d.%d", net, stn);

				json_object_array_add(ipservers, jipaddr);
#endif

			}
			else if (!regexec(&r_pipeserver, line, 5, matches, 0))
			{

				uint8_t			net, stn, flags;
				char 			*pipepath;
#ifdef EB_JSONCONFIG
				struct json_object	*jnet, *diverts, *divert, *jpipeserver;
#endif

				if (sscanf(eb_getstring(line, &matches[1]), "%3hhd.%3hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station ID for pipe gateway in config line %s", line);

				pipepath = eb_malloc(__FILE__, __LINE__, "CONFIG", "Create pipe base string", strlen(eb_getstring(line, &matches[2]))+1);

				if (!pipepath)
					eb_debug (1, 0, "CONFIG", "Unable to malloc() for pipe filename for station %d.%d", net, stn);

				strcpy(pipepath, eb_getstring(line, &matches[2]));

				flags = 0;

				if (!strcasecmp(eb_getstring(line, &matches[3]), "passthru"))
					flags = EB_DEV_CONF_DIRECT;

#ifdef EB_JSONCONFIG

				jnet = eb_json_get_net_makevirtual(jc, net);

				json_object_object_get_ex(jnet, "diverts", &diverts);
				divert = eb_json_get_divert_makenew(diverts, stn);
				if (json_object_object_get_ex(divert, "pipe-path", &jpipeserver))
					eb_debug (1, 0, "JSON", "Pipe server already exists on %d.%d", net, stn);

				json_object_object_add(divert, "pipe-path", json_object_new_string(pipepath));
				eb_free(__FILE__, __LINE__, "CONFIG", "Free pipe base string", pipepath);
				if (flags & EB_DEV_CONF_DIRECT)
					json_object_object_add(divert, "pipe-direct", json_object_new_boolean((json_bool) 1));
#else
				eb_device_init_pipe (net, stn, pipepath, flags);
#endif
				/* Put this in all wire station[] maps */

				/* Don't do this until it's live - stops the kernel listening for traffic for a host that's not there */
				// eb_set_single_wire_host (net, stn);

			}
			else if (!regexec(&r_aunmap, line, 6, matches, 0))
			{

				in_addr_t	base;
				uint8_t		base_parts[4];
				char		base_string[20];
				uint8_t		net;
				uint16_t	port;
				uint8_t		is_fixed; // 0 = fixed port, 1 = sequential
				uint8_t		is_autoack;
#ifdef EB_JSONCONFIG
				struct json_object	*jauns, *jaun, *jaun_already;

				strcpy(base_string, eb_getstring(line, &matches[2]));
#endif

				net = atoi(eb_getstring(line, &matches[1]));

				if (networks[net])
					eb_debug (1, 0, "CONFIG", "Cannot map AUN net %d - already defined as %s", net, eb_type_str(networks[net]->type));

				if (sscanf(base_string, "%hhd.%hhd.%hhd.%hhd", &base_parts[0], &base_parts[1], &base_parts[2], &base_parts[3]) != 4)
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
#ifndef EB_JSONCONFIG	
				eb_device_init_aun_net (net, base, is_fixed, port, is_autoack, NULL, NULL);
#else
				json_object_object_get_ex(jc, "aun", &jauns);
				jaun = eb_json_aunnet_makenew(jauns, net); 
				if (json_object_object_get_ex(jaun, "net-address", &jaun_already)) // Already exposed as a network
					eb_debug (1, 0, "JSON", "Cannot AUN map net %d twice", net);
				json_object_object_add(jaun, "net-address", json_object_new_string(base_string));
				json_object_object_add(jaun, "base-port", json_object_new_int(port ? port : (is_fixed ? 32768 : 10000)));
				json_object_object_add(jaun, "fixed-port", json_object_new_boolean((json_bool) is_fixed ? 1 : 0));
				json_object_object_add(jaun, "autoack", json_object_new_boolean((json_bool) is_autoack ? 1 : 0));

#endif
			}
			else if (!regexec(&r_aunhost, line, 5, matches, 0))
			{

				struct hostent		*h;
				uint8_t			net, stn, flags;
				uint16_t		port;
#ifdef EB_JSONCONFIG
				struct json_object	*jauns, *jaun, *jaun_already, *jaun_station;
#else
				in_addr_t		address;
#endif

				if (sscanf(eb_getstring(line, &matches[1]), "%hhd.%hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station number %s for AUN host %s", eb_getstring(line, &matches[1]), eb_getstring(line, &matches[2]));

				flags = 0;

				if (!strcasecmp("AUTOACK", eb_getstring(line, &matches[4]))) // Automatic ACK
					flags = EB_DEV_CONF_AUTOACK;

				port = atoi(eb_getstring(line, &matches[3]));
				
				if (port == 0)	port = (10000 + (256 * net) + (stn)); // 'AUTO'

				h = gethostbyname2(eb_getstring(line, &matches[2]), AF_INET); // IPv4 only

				if (h)
				{
#ifndef EB_JSONCONFIG
					address = ntohl(*((in_addr_t *)h->h_addr));

					eb_device_init_aun_host (net, stn, address, port, flags, 1, NULL, NULL);
#else
					json_object_object_get_ex(jc, "aun", &jauns);
					jaun = eb_json_aunnet_makenew(jauns, net);
					if (json_object_object_get_ex(jaun, "net-address", &jaun_already)) // Already exposed as a network
						eb_debug (1, 0, "JSON", "Net %d already mapped as a network, cannot map an individual host as well", net);
	
					if (!json_object_object_get_ex(jaun, "stations", &jaun_already)) // Re-use to save space
					{
						/* Make the stations array object */
	
						jaun_already = json_object_new_array();
						json_object_object_add(jaun, "stations", jaun_already);
					}
	
					jaun_station = json_object_new_object();
	
					json_object_object_add(jaun_station, "station", json_object_new_int(stn));
					json_object_object_add(jaun_station, "host", json_object_new_string(eb_getstring(line, &matches[2])));
					json_object_object_add(jaun_station, "port", json_object_new_int(port));
					if (flags & EB_DEV_CONF_AUTOACK)
						json_object_object_add(jaun_station, "autoack", json_object_new_boolean((json_bool) 1));
					json_object_array_add(jaun_already, jaun_station);
#endif
				}
				else
					eb_debug (1, 0, "CONFIG", "Cannot resolve remote AUN host %s", eb_getstring(line, &matches[1]));
			}
			else if (!regexec(&r_exposenet, line, 5, matches, 0))
			{
				uint8_t			net;
				int			port;
				char			addr[256];
				uint8_t			fixed;
				struct hostent		*h;
				in_addr_t		s_addr;
#ifdef EB_JSONCONFIG
				struct json_object	*jexposures, *jexposure, *jexp_already;
#else
				uint8_t			stn;
#endif

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

				if (!strcmp(addr, "*"))	s_addr = 0; 
				else
					s_addr = ntohl(*((in_addr_t *)h->h_addr));

				if (strcmp(addr, "*") && fixed && ((s_addr & 0xff) != 0)) // Low byte of address must be 0
					eb_debug (1, 0, "CONFIG", "Cannot expose network %d with fixed port if low byte of exposed address is non-zero: %s (%08X)", net, addr, s_addr);

				if (!strcmp(addr, "*") && fixed)
					eb_debug (1, 0, "CONFIG", "Cannot expose whole network %d on a fixed port without specifying base network ending .0", net);

#ifdef EB_JSONCONFIG
				json_object_object_get_ex(jc, "exposures", &jexposures);
				jexposure = eb_json_aunnet_makenew(jexposures, net); /* The AUN makenew() function is just as good here */
				if (json_object_object_get_ex(jexposure, "net-address", &jexp_already)) // Already exposed as a network
					eb_debug (1, 0, "JSON", "Cannot expose net %d twice", net);
				json_object_object_add(jexposure, "net-address", json_object_new_string(addr));
				json_object_object_add(jexposure, "base-port", json_object_new_int(port));
				json_object_object_add(jexposure, "fixed-port", json_object_new_boolean((json_bool) fixed ? 1 : 0));
#else
				for (stn = 254; stn > 0; stn--)	
				{
					if (fixed) s_addr = (s_addr & ~0xff) | stn;

					eb_device_init_expose_host (net, stn, s_addr, port + (fixed ? 0 : stn), 0, NULL, NULL);

				}

				DEVINIT_DEBUG ("Created exposure for net %d with base address %d.%d.%d.%d with base-port %d (%sfixed)",
					net,
					(s_addr & 0xff000000) >> 24,
					(s_addr & 0x00ff0000) >> 16,
					(s_addr & 0x0000ff00) >> 8,
					(s_addr & 0x000000ff),
					port,
					fixed ? "" : "not ");	
#endif
	
			}
			else if (!regexec(&r_exposehost, line, 3, matches, 0))
			{
				
				uint8_t			net, stn;
				int			port;
				char			addr[256];
				char 			*colon;
#ifdef EB_JSONCONFIG
				struct json_object	*jexposures, *jexposures_net, *jexposure, *jexp_already;
#else
				in_addr_t		s_addr;
				struct hostent		*h;
#endif

				if (sscanf(eb_getstring(line, &matches[1]), "%hhd.%hhd", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad station for exposure: %s", line);

				// matches2 can be either host:port or AUTO

				strcpy (addr, eb_getstring(line, &matches[2]));

				colon = strchr(addr, ':');

				if (colon) *colon = '\0';

				if (!colon)
				{
#ifndef EB_JSONCONFIG
					s_addr = 0; // All interfaces
#endif
					port = atoi(addr);
					if (!port) port = (10000 + (256 * net) + stn);
				}
				else
				{
					colon++;
#ifndef EB_JSONCONFIG
					if (!strcmp(addr, "*")) // All interfaces
						s_addr = 0;
					else
					{
						h = gethostbyname2(addr, AF_INET); // IPv4 only
						s_addr = ntohl(*((in_addr_t *)h->h_addr));
					}
#endif
					port = atoi(colon);
				}


#ifdef EB_JSONCONFIG
				json_object_object_get_ex(jc, "exposures", &jexposures);
				jexposures_net = eb_json_aunnet_makenew(jexposures, net);
				if (json_object_object_get_ex(jexposures_net, "net-address", &jexp_already)) // Already exposed as a network
					eb_debug (1, 0, "JSON", "Net %d already exposed as a network, cannot expose an individual host as well", net);

				if (!json_object_object_get_ex(jexposures_net, "stations", &jexp_already)) // Re-use to save space
				{
					/* Make the stations array object */

					jexp_already = json_object_new_array();
					json_object_object_add(jexposures_net, "stations", jexp_already);
				}

				jexposure = json_object_new_object();
				json_object_object_add(jexposure, "station", json_object_new_int(stn));
				json_object_object_add(jexposure, "host", json_object_new_string(addr));
				json_object_object_add(jexposure, "port", json_object_new_int(port));
				json_object_array_add(jexp_already, jexposure);
#else
				eb_device_init_expose_host (net, stn, s_addr, port, 1, NULL, NULL);
#endif

			}
			else if (!regexec(&r_trunk_nat, line, 4, matches, 0))
			{
				uint8_t			local_net, distant_net;
				uint16_t		trunk_port;
#ifdef EB_JSONCONFIG
				struct json_object	*jtrunks, *jtrunk, *jnats, *jnat, *jport;
#else
				uint8_t			found;
				struct __eb_device	*trunk;
#endif

				trunk_port = atoi(eb_getstring(line, &matches[1]));
				distant_net = atoi(eb_getstring(line, &matches[2]));
				local_net = atoi(eb_getstring(line, &matches[3]));

				if (!local_net || !distant_net)
					eb_debug (1, 0, "CONFIG", "Bad trunk NAT configuration %s: one or other network numbers resolves to 0.", line);
#ifndef EB_JSONCONFIG
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

				eb_device_init_trunk_nat (trunk, local_net, distant_net);
#else
				if (json_object_object_get_ex(jc, "trunks", &jtrunks))
				{
					uint16_t	jcount, jlength;

					jlength = json_object_array_length(jtrunks);

					jcount = 0;

					while (jcount < jlength)
					{
						jtrunk = json_object_array_get_idx(jtrunks, jcount);
						if (jtrunk)
						{
							json_object_object_get_ex(jtrunk, "local-port", &jport);

							if ((trunk_port == json_object_get_int(jport) && json_object_object_get_ex(jtrunk, "nat", &jnats)))
							{
								jnat = json_object_new_object();
								json_object_object_add(jnat, "distant-net", json_object_new_int(distant_net));
								json_object_object_add(jnat, "local-net", json_object_new_int(local_net));
								json_object_array_add(jnats, jnat);
							}
						}
						jcount++;
					}
				}
#endif
			}
			else if (!regexec(&r_bridge_net_filter, line, 5, matches, 0))
			{
				uint16_t	trunk_port;
				uint8_t		distant_net;
				uint8_t		drop, inbound;
				char		device[128];
				regex_t		r_wort;
#ifdef EB_JSONCONFIG
				struct json_object	*jfw_array, *jdevice = NULL, *jfw_entry, *jfw_entries;
				uint8_t		is_trunk = 0;
				char		fw_name[128];
#endif

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
#ifndef EB_JSONCONFIG
						if (trunk_port && networks[trunk_port])
							eb_device_init_set_bridge_filter (networks[trunk_port], distant_net, drop, inbound);
						else
							eb_debug (1, 0, "CONFIG", "Attempt to configure bridge filter on wire net %d which is not configured", trunk_port);
#endif
					}
					else // Trunk
					{
#ifdef EB_JSONCONFIG
						is_trunk = 1;
#else
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

						eb_device_init_set_bridge_filter(trunk, distant_net, drop, inbound);
#endif
					}

#ifdef EB_JSONCONFIG
					jfw_entry = json_object_new_object();
					json_object_object_add(jfw_entry, "accept", json_object_new_boolean((json_bool) drop ? 0 : 1));
					json_object_object_add(jfw_entry, "distant-net", json_object_new_int(distant_net));

					sprintf (fw_name, "%s_%d_%s", is_trunk ? "TRUNK" : "ECONET", trunk_port, inbound ? "IN" : "OUT");

					if (is_trunk)
					{
						struct json_object	*jtrunk, *jtrunkport;
						uint8_t			jlength, jcount;

						json_object_object_get_ex(jc, "trunks", &jtrunk);

						jlength = json_object_array_length(jtrunk);
						jcount = 0;

						while (jcount < jlength)
						{
							jdevice = json_object_array_get_idx(jtrunk, jcount);
							json_object_object_get_ex(jdevice, "local-port", &jtrunkport);
							if (trunk_port == json_object_get_int(jtrunkport))
								break;

							jcount++;
						}

						if (jcount == jlength)	jdevice = NULL;
					}
					else
					{
						/* Wire */
						struct json_object *jwire, *jnet;
						uint8_t		jlength, jcount;

						json_object_object_get_ex(jc, "econets", &jwire);
						jlength = json_object_array_length(jwire);
						jcount = 0;
						while (jcount < jlength)
						{
							jdevice = json_object_array_get_idx(jwire, jcount);
							json_object_object_get_ex(jdevice, "net", &jnet);
							if (trunk_port == json_object_get_int(jnet))
								break;
							jcount++;

						}

						if (jcount == jlength)	jdevice = NULL;
					}

					if (!jdevice)
						eb_debug(1, 0, "JSON", "Attempt to set firewall on non-existent %s %d", (is_trunk ? "Trunk port" : "Wire net"), trunk_port);

					jfw_array = eb_json_fw_chain_makenew(fw_name, jc);
					json_object_object_get_ex(jfw_array, "entries", &jfw_entries);
					if (!jfw_entries)
						eb_debug(1, 0, "JSON", "Attempt to set firewall on %s %d, but the firewall chain does not have an 'entries' array", (is_trunk ? "Trunk port" : "Wire net"), trunk_port);

					json_object_array_add(jfw_entries, jfw_entry);
#endif
	
				}
				else	eb_debug (1, 0, "CONFIG", "Unable to work out device in line %s", line);

				regfree(&r_wort);
				
			}
			else if (!regexec(&r_bridge_traffic_filter, line, 6, matches, 0))
			{
#ifdef EB_JSONCONFIG
				struct json_object	*jfw_entry;
#endif
				uint8_t	srcnet, srcstn, dstnet, dststn, action;

				srcnet = atoi(eb_getstring(line, &matches[2]));
				srcstn = atoi(eb_getstring(line, &matches[3]));
				dstnet = atoi(eb_getstring(line, &matches[4]));
				dststn = atoi(eb_getstring(line, &matches[5]));

				action = (!strcasecmp(eb_getstring(line, &matches[1]), "drop")) ? EB_FW_REJECT : EB_FW_ACCEPT;

#ifdef EB_JSONCONFIG
				jfw_entry = json_object_new_object();

				if (srcnet != 0xff)
					json_object_object_add(jfw_entry, "source-net", json_object_new_int(srcnet));

				if (srcstn != 0xff)
					json_object_object_add(jfw_entry, "source-station", json_object_new_int(srcstn));

				if (dstnet != 0xff)
					json_object_object_add(jfw_entry, "destination-net", json_object_new_int(dstnet));

				if (dststn != 0xff)
					json_object_object_add(jfw_entry, "destination-station", json_object_new_int(dststn));

				/* Don't bother setting destination-port because the legacy config can't set it - will always be wildcard */

				json_object_object_add(jfw_entry, "accept", json_object_new_boolean((json_bool) (action == EB_FW_ACCEPT) ? 1 : 0));

				json_object_array_add(jfw_bridge_entries, jfw_entry);
#else
				eb_device_init_add_fw_to_chain (&bridge_fw, srcnet, srcstn, dstnet, dststn, 0xff, action);
#endif

			}
			else if (!regexec(&r_netclock, line, 7, matches, 0))
			{
				double	period;
				double	mark;
				uint8_t	net;
#ifdef EB_JSONCONFIG
				struct json_object	*jwires, *jdevice, *jnet;
				char			jclockstring[30];
				uint8_t			jcount, jlength;
#endif

				net = atoi(eb_getstring(line, &matches[1]));	
				period = atof(eb_getstring(line, &matches[2]));
				mark = atof(eb_getstring(line, &matches[6]));

#ifdef EB_JSONCONFIG
				json_object_object_get_ex(jc, "econets", &jwires);
				jcount = 0;
				jlength = json_object_array_length(jwires);
				sprintf (jclockstring, "%f/%f", period, mark);
				while (jcount < jlength)
				{
					jdevice = json_object_array_get_idx(jwires, jcount);
					if (json_object_object_get_ex(jdevice, "net", &jnet))
					{
						if (net == json_object_get_int(jnet)) /* Found it */
							json_object_object_add(jdevice, "net-clock", json_object_new_string(jclockstring));
					}

					jcount++;
				}	
#else
				if (!networks[net])
					eb_debug (1, 0, "CONFIG", "Cannot set network clock on net %d - network not yet defined", net);

				eb_device_init_set_net_clock (networks[net], period, mark);
#endif
					
			}
			else if (!regexec(&r_bindto, line, 2, matches, 0))
			{
				char		host[255];
#ifndef EB_JSONCONFIG
				struct hostent	*h;

				strncpy (host, eb_getstring(line, &matches[1]), 254);

				/* TODO
				 *
				 * Change to getaddrinfo() and change bindhost to be
				 * struct addrinfo * - the res parameter on
				 * getaddrinfo(). Then change the trunks to be able
				 * to open both IPv4 and IPv6 sockets (there will need
				 * to be an array of sockets...), poll them all, and
				 * deal with what happens if the host at the other end
				 * is multi-homed.
				 * If there's no bindhost list, the trunks should open
				 * INADDR_ANY / IPv6 equivalent sockets on all 
				 * addresses. 
				 *
				 * The poll() calls can just deal with the first one
				 * they find with traffic, and the others will flag
				 * POLLIN on the next poll() anyway.
				 *
				 * The trunks will also want changing to understand IPv6
				 * traffic from an unknown source.
				 *
				 * No point doing IPv6 for AUN because no true AUN
				 * devices actually use it.
				 *
				 */

				h = gethostbyname2(host, AF_INET); // IPv4 only

				if (h)
					eb_device_init_set_trunk_bind_address (NULL, ntohl(*((in_addr_t *)h->h_addr)));
				/* OLD
				{
					bindhost = ntohl(*((in_addr_t *)h->h_addr));
				}
				*/
				else	eb_debug (1, 0, "CONFIG", "Cannot resolve IP address for host to bind to (%s) in line: %s", host, line);
#else
				json_object_object_add(jgeneral, "trunk-bind-host", json_object_new_string(host));
#endif
			}
			else if (!regexec(&r_pool_new, line, 3, matches, 0))
			{
				char		poolname[10];
				char		netlist[255];
				uint8_t		nets[255], first_net = 0;
#ifdef EB_JSONCONFIG
				struct json_object	*jpool, *jnet_array, *jstatic_array;
				uint8_t		net;
#endif
				
				if (strlen(eb_getstring(line, &matches[1])) > 9)
					eb_debug (1, 0, "CONFIG", "Pool name %s is more than the maximum 9 characters", eb_getstring(line, &matches[1]));

				strcpy (poolname, eb_getstring(line, &matches[1]));

				// Find nets

				memset (&nets, 0, sizeof(nets));

				strcpy (netlist, eb_getstring(line, &matches[2]));

				first_net = eb_parse_nets(netlist, nets);

				if (first_net == 0)
					eb_debug (1, 0, "CONFIG", "No networks found for pool %s", poolname);

#ifdef EB_JSONCONFIG
				jpool = json_object_new_object();
				json_object_array_add(jpools, jpool);
				json_object_object_add(jpool, "name", json_object_new_string(poolname));
				jnet_array = json_object_new_array();
				json_object_object_add(jpool, "nets", jnet_array);
				jstatic_array = json_object_new_array();
				json_object_object_add(jpool, "statics", jstatic_array);

				for (net = 1; net < 255; net++)
					if (nets[net])
						json_object_array_add(jnet_array, json_object_new_int(net));

#else
				eb_device_init_create_pool (poolname, first_net, nets);
#endif
			}
			else if (!regexec(&r_pool_static_wire, line, 6, matches, 0) || !regexec(&r_pool_static_trunk, line, 6, matches, 0))
			{
				uint16_t		trunkportorwirenet; // Trunk port, or wire net number we are deploying to
				char			poolname[128]; // Name of pool
				char			dtype[6];
				int			s_net, s_stn, net, stn; // s_ variants are at the far end; net & stn are within the pool
				enum			{ TRUNK, WIRE } variant;
#ifdef EB_JSONCONFIG
				struct json_object	*jpool;
				uint16_t		jpool_count, jpool_length;
#else
				struct __eb_pool	*pool; // Pool being deployed to
				struct __eb_device	*source; // Device where the source machine is / will be
#endif

				strcpy(poolname, eb_getstring(line, &matches[1]));
				strcpy(dtype, eb_getstring(line, &matches[2]));
				trunkportorwirenet = atoi(eb_getstring(line, &matches[3]));
				// Decode station numbers

				if (sscanf(eb_getstring(line, &matches[4]), "%3d.%3d", &s_net, &s_stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad source station number %s in static assignment within pool %s", eb_getstring(line, &matches[4]), poolname);

				if (sscanf(eb_getstring(line, &matches[5]), "%3d.%3d", &net, &stn) != 2)
					eb_debug (1, 0, "CONFIG", "Bad pool station number %s in static assignment within pool %s", eb_getstring(line, &matches[5]), poolname);

				variant = WIRE;

				if (!strcasecmp("TRUNK", dtype))
					variant = TRUNK;

#ifndef EB_JSONCONFIG
				pool = pools;

				while (pool)
				{
					if (!strcasecmp((const char *)pool->name, poolname))
						break;
					else	pool = pool->next;
				}

				if (!pool)
					eb_debug (1, 0, "CONFIG", "Cannot find pool %s to deploy to %s %d", poolname, dtype, trunkportorwirenet);

				// Make sure the source device already exists

				source = NULL;

				if (variant == TRUNK)
				{
					source = trunks;

					while (source)
					{
						if (source->type == EB_DEF_TRUNK && source->trunk.local_port == trunkportorwirenet)
							break;
						else	source = source->next;
					}
				}
				else
				{
					if (networks[trunkportorwirenet] && (networks[trunkportorwirenet]->type == EB_DEF_WIRE))
						source = networks[trunkportorwirenet];
				}

				if (!source)
					eb_debug (1, 0, "CONFIG", "Cannot assign pool %s to %s %s %d because it target device does not exist", poolname, dtype, (variant == TRUNK ? "on port" : "on net"), trunkportorwirenet);

#endif

#ifdef EB_JSONCONFIG
				jpool_length = json_object_array_length(jpools);
				jpool_count = 0;

				while (jpool_count < jpool_length)
				{
					struct json_object	*jpoolname_object, *jstatic_array_entry, *jstatics;
					char 			jpoolname[30];

					jpool = json_object_array_get_idx (jpools, jpool_count);

					if (json_object_object_get_ex(jpool, "name", &jpoolname_object) && json_object_object_get_ex(jpool, "statics", &jstatics))
					{
						strcpy(jpoolname, json_object_get_string(jpoolname_object));
						if (!strcasecmp(jpoolname, poolname)) /* Found correct pool */
						{
							jstatic_array_entry = json_object_new_object();
							if (variant == TRUNK)
								json_object_object_add(jstatic_array_entry, "interface-type", json_object_new_string("trunk"));
							else
								json_object_object_add(jstatic_array_entry, "interface-type", json_object_new_string("econet"));

							json_object_object_add(jstatic_array_entry, "interface-ref", json_object_new_int(trunkportorwirenet));

							json_object_object_add(jstatic_array_entry, "static-net", json_object_new_int(net));
							json_object_object_add(jstatic_array_entry, "static-stn", json_object_new_int(stn));
							json_object_object_add(jstatic_array_entry, "source-net", json_object_new_int(s_net));
							json_object_object_add(jstatic_array_entry, "source-stn", json_object_new_int(s_stn));

							json_object_array_add(jstatics, jstatic_array_entry);

							break;
						}

					}

					jpool_count++;
				}
#else
				eb_device_init_set_pool_static (pool, source, net, stn, s_net, s_stn);
#endif

			}

			else if (!regexec(&r_pool_net_wire, line, 5, matches, 0) || !regexec(&r_pool_net_trunk, line, 5, matches, 0))
			{

				uint8_t			nets[255];
				uint16_t		trunkportorwirenet; // Trunk port, or wire net number we are deploying to
				char			poolname[128]; // Name of pool
				char			dtype[6];
				enum			{ TRUNK, WIRE } variant;
				uint8_t			all_pooled = 0;
#ifdef EB_JSONCONFIG
				struct json_object	*jdevices;
				uint16_t		jpool_count, jpool_length;
#else
				struct __eb_pool	*pool; // Pool being deployed
				struct __eb_device	*source; // Device we are deploying to
				uint8_t			first_net;
#endif

				trunkportorwirenet = atoi(eb_getstring(line, &matches[2]));
				strcpy(poolname, eb_getstring(line, &matches[3]));
				strcpy(dtype, eb_getstring(line, &matches[1]));

				memset(&nets, 0, sizeof(nets));

				variant = WIRE;

				if (!strcasecmp("TRUNK", dtype))
					variant = TRUNK;

#ifndef EB_JSONCONFIG
				// See if we can find the pool
				
				pool = pools;

				while (pool)
				{
					// fprintf (stderr, "Comparing %s with %s\n", pool->name, poolname);
					if (!strcasecmp((const char *)pool->name, poolname))
						break;
					else	pool = pool->next;
				}

				if (!pool)
					eb_debug (1, 0, "CONFIG", "Cannot find pool %s to deploy to %s %d", poolname, dtype, trunkportorwirenet);

				source = NULL;

				if (variant == TRUNK)
				{
					source = trunks;

					while (source)
					{
						if (source->type == EB_DEF_TRUNK && source->trunk.local_port == trunkportorwirenet)
							break;
						else	source = source->next;
					}
				}
				else
				{
					if (networks[trunkportorwirenet] && (networks[trunkportorwirenet]->type == EB_DEF_WIRE))
						source = networks[trunkportorwirenet];
				}

				if (!source)
					eb_debug (1, 0, "Cannot assign pool %s to %s %s %d because it target device does not exist", poolname, dtype, (variant == TRUNK ? "on port" : "on net"), trunkportorwirenet);

				first_net = eb_parse_nets(eb_getstring(line, &matches[4]), nets);

				if (!first_net)
					eb_debug (1, 0, "Bad net list in pool deployment %s", eb_getstring(line, &matches[0]));

				if (!strcmp(eb_getstring(line, &matches[4]), "*"))
					all_pooled = 1; // Flag for reset purposes
					//source->all_nets_pooled = 1; // Flag for reset purposes
#endif

#ifdef EB_JSONCONFIG
				if (variant == WIRE)
				{
					if (!json_object_object_get_ex(jc, "econets", &jdevices))
						eb_debug(1, 0, "JSON", "Cannot find econets node in JSON config!");
				}
				else
				{
					if (!json_object_object_get_ex(jc, "trunks", &jdevices))
						eb_debug(1, 0, "JSON", "Cannot find trunks node in JSON config!");
				}

				jpool_length = json_object_array_length(jdevices);
				jpool_count = 0;

				while (jpool_count < jpool_length)
				{
					struct json_object	*jdevice_object, *jdevice_ref, *jdevice_pool_array, *jdevice_assignment, *jdevice_nets;

					jdevice_object = json_object_array_get_idx (jdevices, jpool_count);

					if ((variant == TRUNK && json_object_object_get_ex(jdevice_object, "local-port", &jdevice_ref))
							|| json_object_object_get_ex(jdevice_object, "net", &jdevice_ref))
					{
						if (json_object_get_int(jdevice_ref) == trunkportorwirenet)
						{
							json_object_object_get_ex(jdevice_object, "pool-assignment", &jdevice_pool_array);
							jdevice_assignment = json_object_new_object();
							json_object_array_add(jdevice_pool_array, jdevice_assignment);
							jdevice_nets = json_object_new_array();
							json_object_object_add (jdevice_assignment, "nets", jdevice_nets);
							json_object_object_add (jdevice_assignment, "pool-name", json_object_new_string(poolname));

							if (all_pooled)
								json_object_object_add(jdevice_object, "pool-all", json_object_new_boolean((json_bool) 1));
							else
							{
								for (uint8_t net = 1; net < 255; net++)
								{
									if (nets[net])
										json_object_array_add(jdevice_nets, json_object_new_int(net));
								}
							}
						}
						break;
					}

					jpool_count++;
				}
#else
				eb_device_init_set_pooled_nets (pool, source, all_pooled, nets);

#endif
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
	regfree (&r_trunk_plaintext);
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
	regfree (&r_pool_new);
	regfree (&r_pool_net_wire);
	regfree (&r_pool_net_trunk);
	regfree (&r_pool_static_wire);
	regfree (&r_pool_static_trunk);
	
#ifdef EB_JSONCONFIG
	if (json[0]) /* Non-null string */
	{
		eb_debug (0, 2, "JSON", "%16s Writing JSON config to %s", "", json);
		jsonfile = fopen(json, "w");
		fprintf (jsonfile, "%s", json_object_to_json_string_ext(jc, JSON_C_TO_STRING_PRETTY));
		fclose(jsonfile);
		//json_object_put(jc);
	}
#endif

	return 1;

}

void eb_help(char *name)
{

	printf ("\n\
Copyright (c) 2025 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
GIT repository version: "GIT_VERSION"\n\
\n\
Usage: %s [options] \n\
Version: %d.%d\n\
Options:\n\
\n\
\t-h\t\tThis help text\n\
\n\
\t-c <path>\tUse alternative config file\n\
"
#ifdef EB_JSONCONFIG
"\t-j <path>\tUse alternative JSON config file\n\
"
#endif
"\t-d <path>\tSet debug file output. Will overwrite, not append\n\
\t-l\t\tDon't try to open Econet devices. IP only operation\n\
\t-n <num>\tMax data bytes in a packet dump (default 0)\n\
\t-p [iIoO]\tPacket dump - i/I: input phase, before/after NAT; o/O: output phase, likewise\n\
\t-s\t\tDump configuration at startup (repeat for extra debug)\n\
\t-y\t\tDebug Level during configuration phase (each occurrence increases; max 5)\n\
\t-z\t\tDebug Level (each occurrence increases; max 5)\n\
\t-e\t\tTurn on extra logging from kernel module to dmesg\n\
\n\
Queuing management options (usually need not be adjusted):\n\
\n\
--wire-max-tx n\t\tMaximum number of retransmits for wire packets (current: %d)\n\
--wire-max-not-listening n\tMaximum number of 'Not listening' errors to ignore (current: %d)\n\
--wire-interval n\tMinimum wait before wire retransmission of failed packet (ms) (current: %d)\n\
--wire-imm-wait n\tMaximum time (ms) to wait for an immediate reply destined for the wire (current %d)\n\
--aun-max-tx n\t\tMaximum number of retransmits for AUN packets (current: %d)\n\
--aun-interval n\tMinimum wait before AUN retransmission of unacknowledged packet (ms) (current: %d)\n\
--aun-nak-tolerance n\tNumber of AUN NAKs to tolerate before dumping packet. (current: %d)\n\
--immediate-timeout n\tNumber of ms to wait before cancelling flag fill when immediate query received (current:%d)\n\
--max-sockets n\t\tMaximum numbers of sockets that can be open (increase if system cannot do AUN listens)\n\
\t\t\t(Minimum 1. Used because sometimes RiscOS isn't listening when it should be!)\n\
--flashtime n\t\tTime in ms to flash each activity LED off to show activity. (current: %d)\n\
--led-blink-on\t\tActivity LEDs are off by default, and blink on for activity (current: ON and blink OFF)\n\
--leds-off\t\tTurn the activity LEDs off and leave them off\n\
--trunk-keepalive-interval n\tSeconds between trunk keepalive packets\n\
--trunk-dead-interval n\tSeconds without reception before trunk considered dead\n\
--pool-dead-interval n\tSeconds before a dynamic pool entry times out as idle (current %d)\n\
--enable-syst-fast\tEnable bridge control privilege for SYST on all fileservers (once only)\n\
\n\
Bridge protocol tuning:\n\
\n\
--wire-reset-qty n\tNumber of bridge resets to send on Econet wires (current %d)\n\
--wire-update-qty n\tNumber of bridge update packets to send on Econet wires (current %d)\n\
--trunk-reset-qty n\tNumber of bridge resets to send on UDP trunks (current %d)\n\
--trunk-update_qty n\tNumber of bridge update packets to send on UDP trunks (current %d)\n\
--bridge-query-interval n\tMinimum time between bridge query responses sent to a given station on the Econet (ms) (current %d)\n\
--no-keepalive-debug\tFilter packet dumps for port &9C ctrl &D0 (bridge keepalives)\n\
--no-bridge-announce-debug\tFilter packet dumps for all port &9C traffic (bridge net resets, updates, keepalives (also sets --no-keepalive-debug))\n\
--bridge-loop-detect n\t1 or 0 - (en/dis)ables bridge loop detection (current: %s) (** not yet implemented **)\n\
--pool-reset n\t\t1 or 0 - (en/dis)ables forwarding of bridge resets & updates from trunks/wires where all nets are pooled (current: %s)\n\
\n\
Statistics port control:\n\
\n\
--stats-port n\t\tTCP port number for traffic stats burst (current: %d)\n\
--fs-stats-port n\t\tTCP port number for FS stats output (current: %d)\n\
\n\
Fileserver control (global to all servers):\n\
\n\
--disable-7bitbodge\tDisable Y2K date compliance which uses an extra 3 bits for year\n\
\n\
Deep-level debugging options:\n\
\n\
--malloc-debug\t\tTurn on (very verbose) malloc()/free() debug when at loglevel 2 or above\n\
\n\
"
#ifdef EB_JSONCONFIG
"Configuration:\n\
\n\
--json-config-write <path>\tFilename to write JSON version of legacy config to\n\
\n\
"
#endif
	, name,
	(EB_VERSION & 0xf0) >> 4,
	(EB_VERSION & 0x0f),
	EB_CONFIG_WIRE_RETRIES,
	EB_CONFIG_WIRE_MAX_NOTLISTENING,
	EB_CONFIG_WIRE_RETX,
	EB_CONFIG_WIRE_IMM_WAIT,
	EB_CONFIG_AUN_RETRIES,
	EB_CONFIG_AUN_RETX,
	EB_CONFIG_AUN_NAKTOLERANCE,
	EB_CONFIG_WIRE_IMM_WAIT,
	EB_CONFIG_FLASHTIME, 
	EB_CONFIG_POOL_DEAD_INTERVAL,
	EB_CONFIG_WIRE_RESET_QTY,
	EB_CONFIG_WIRE_UPDATE_QTY,
	EB_CONFIG_TRUNK_RESET_QTY,
	EB_CONFIG_TRUNK_UPDATE_QTY,
	EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL,
	EB_CONFIG_BRIDGE_LOOP_DETECT ? "ON" : "OFF",
	EB_CONFIG_POOL_RESET_FWD ? "ON" : "OFF",
	EB_CONFIG_STATS_PORT,
	EB_CONFIG_FS_STATS_PORT
					    
					    );


}

/* Main bridge
*/

int main (int argc, char **argv)
{

	int	opt;
	struct __eb_device *p;
	struct __eb_aun_exposure *e;
	int	long_index;
	struct rlimit	max_fds;
	char 	config_path[256];
	char	jsonconfig_path[256], jsonconfigout_path[256];
#ifdef EB_JSONCONFIG
	struct	json_object	*json_config;
	struct 	stat		config_stat, json_stat;
	int			config_stat_res, json_stat_res;
#endif

	/* Drop privs in case we're setuid for *FAST */

	if (seteuid(getuid()) != 0)
	{
		fprintf (stderr, "Failed to drop privileges on startup. Quitting. \n");
		exit (EXIT_FAILURE);
	}

	/* Set up some initial config
	*/

	fsop_setup();

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
	EB_CONFIG_WIRE_RETX = 50; // Reduced to 10 20231226 to see if !Machines performance improves - 20240611 increased to 25 - seems to make RISC OS happier on getbytes - increased to 50 20240630 to see if we can help RISC OS limp along
	EB_CONFIG_AUN_RETX = 1000;  // BeebEm Seems to need quite a while - and does not like another packet turning up before it's ACKd the last one. Long timeout. If the ACK turns up, the inbound AUN listener wakes the queue anyway, so it should be fine.
	EB_CONFIG_WIRE_RETRIES = 10;
	EB_CONFIG_WIRE_MAX_NOTLISTENING = 5; // Number of not listenings to treat as non-fatal on transmission of a 4-way (to cope with RISC OS bug where it sometimes isn't listening for a data burst on getbytes/load 
	EB_CONFIG_WIRE_IMM_WAIT = 1000; // Wait 1s before resetting ADLC from flag fill - assume immediate reply not turning up for transmission on to wire - TODO - Implemennt command line variable
	EB_CONFIG_AUN_RETRIES = 5;
	EB_CONFIG_AUN_NAKTOLERANCE = 2; // How many NAKs we tolerate before we dump the packet off an AUN outq. Used to appease RiscOS, which sometimes isn't listening when it should be
	EB_CONFIG_WIRE_INTERPACKETGAP = 25; // Make sure some stations are listening // Not used any more
	EB_CONFIG_AUN_NAKTOLERANCE = 2;
	EB_CONFIG_PKT_DUMP_OPTS = 0; // Nothing dumped
	EB_CONFIG_MAX_DUMP_BYTES = 0; // No data bytes dumped by default
	EB_CONFIG_LOCAL = 0; // Use econet devices
	EB_CONFIG_DYNAMIC_EXPIRY = 10; // 10 mins to expire an unused AUN station
	EB_CONFIG_STATS_PORT = 6809; // Memories of a fire-breather
	EB_CONFIG_FS_STATS_PORT = 6084; // Memories of an IBM
	EB_CONFIG_FLASHTIME = 100; // 0.1s flash time on the Read/Write LEDs
	EB_CONFIG_BLINK_ON = 0; // LEDs are on and blink off by default
	EB_CONFIG_LEDS_OFF = 0; // Disable LEDs - turn them off at the start and don't blink them
	EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL = 30; // Default 30s keepalive interval
	EB_CONFIG_TRUNK_KEEPALIVE_CTRL = 0xD0; // Default keepalive packet ctrl byte
	EB_CONFIG_TRUNK_DEAD_INTERVAL = EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL * 2.5; // Default trunk dead interval
	EB_CONFIG_POOL_DEAD_INTERVAL = 1800; // 30 minutes to dead
	EB_CONFIG_TRUNK_RESET_QTY = 1; // UDP trunks are fairly reliable
	EB_CONFIG_TRUNK_UPDATE_QTY = 2; // UDP trunks are fairly reliable
	EB_CONFIG_WIRE_RESET_QTY = 1; // Same as Acorn / SJ Bridges
	EB_CONFIG_WIRE_UPDATE_QTY = 10; // Same as Acorn / SJ Bridges - avoids clashing with resets
	EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL = 2000; // 2s between responses to WhatNet / IsNet to a particular station
	EB_CONFIG_EXTRALOGS = 0; // Extra kernel logging
	EB_CONFIG_NOKEEPALIVEDEBUG = 0; // Log keepalives on trunks as normal (1 means filter it)
	EB_CONFIG_POOL_RESET_FWD = 0; // Don't forward resets when all nets on device are pooled
	EB_CONFIG_BRIDGE_LOOP_DETECT = 1; // Enable bridge loop detection & trunk/wire shutdown. (Only ignores traffic on the wire which is not destined for a local emulator on this bridge, so they can still talk to local fileservers etc.)

	strcpy (config_path, "/etc/econet-gpio/econet-hpbridge.cfg");
#ifdef EB_JSONCONFIG
	strcpy (jsonconfig_path, "/etc/econet-gpio/econet-hpbridge.json");
	strcpy (jsonconfigout_path, "");
#else
	strcpy (jsonconfig_path, "");
	strcpy (jsonconfigout_path, "");
#endif

	/* Clear networks[] table */

	memset (&networks, 0, sizeof(networks));
	memset (&networks_initial, 0, sizeof(networks_initial));

	/* Initialize other lists */

	devices = NULL;
	aun_remotes = NULL;
	bridge_fw = NULL;
	trunks = NULL;
	multitrunks = NULL;
	interface_groups = NULL;
	pools = NULL;
	exposures = NULL;
	port99_list = NULL;
	fw_chains = NULL;

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
		{"normalize-debug",	0,			0,	0 },
		{"trunk-keepalive-interval", 	required_argument, 	0, 	0},
		{"trunk-dead-interval", 	required_argument, 	0, 	0},
		{"pool-dead-interval",	required_argument,	0,	0},
		{"enable-syst-fast",	0, 			0, 	0},
		{"wire-reset-qty",	required_argument,	0,	0},
		{"wire-update-qty",	required_argument,	0,	0},
		{"trunk-reset-qty",	required_argument,	0,	0},
		{"trunk-update-qty",	required_argument,	0,	0},
		{"bridge-query-interval",	required_argument,	0,	0},
		{"no-keepalive-debug",	0,			0,	0},
		{"immediate-timeout", 	required_argument, 	0, 	0},
		{"bridge-loop-detect",	required_argument,	0,	0},
		{"pool-reset",		required_argument,	0,	0},
		{"wire-max-not-listening", required_argument,	0, 	0},
		{"no-bridge-announce-debug", 0,			0, 	0},
		{"fs-stats-port", 	required_argument, 	0, 	0},
#ifdef EB_JSONCONFIG
		{"json-config-write", 	required_argument, 	0, 	0},
#else
		{"XXXX-json-config-write-disabled", 		0,	0},
#endif
		{0, 			0,			0,	0 }
	};

	/* Parse command line */

	/* TODO - we need to parse only some options here, namely the ones which
	 * don't override the config file. Then repeat the getopt after we have
	 * read the config, and implement those which *do* override the config.
	 * Otherwise the config will always win over the command line, which is
	 * wrong.
	 */

	while ((opt = getopt_long(argc, argv, "hc:d:eln:p:svyz", long_options, &long_index)) != -1)	
	{
		switch (opt)
		{
			case 0: // Long option
			{
				switch (long_index)
				{
					/* Commented - these are implemented after reading the config file 
					case 0: 	EB_CONFIG_WIRE_RETRIES = atoi(optarg); break;
					case 1:		EB_CONFIG_AUN_RETRIES = atoi(optarg); break;
					case 2:		EB_CONFIG_WIRE_RETX = atoi(optarg); break;
					case 3:		EB_CONFIG_AUN_RETX = atoi(optarg); break;
					case 4:		EB_DEBUG_MALLOC = 1; break;
					case 5:		EB_CONFIG_AUN_NAKTOLERANCE = atoi(optarg); break;
					case 6:		fs_sevenbitbodge = 0; break;
					case 7:		EB_CONFIG_DYNAMIC_EXPIRY = atoi(optarg); break;
					case 8:		EB_CONFIG_STATS_PORT = atoi(optarg); break;
					*/
					case 9:		max_fds.rlim_cur = max_fds.rlim_max = atoi(optarg); break;
							/* Commented - same reason as above
					case 10:	EB_CONFIG_FLASHTIME = atoi(optarg); break;
					case 11:	EB_CONFIG_BLINK_ON = 1; break;
					case 12:	EB_CONFIG_LEDS_OFF = 1; EB_CONFIG_BLINK_ON = 1; break;
					case 13:	normalize_debug = 1; break;
					case 14:	EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL = atoi(optarg); break;
					case 15:	EB_CONFIG_TRUNK_DEAD_INTERVAL = atoi(optarg); break;
					case 16:	EB_CONFIG_POOL_DEAD_INTERVAL = atoi(optarg); break;
					case 17:	fs_set_syst_bridgepriv = 1; break;
					case 18:	EB_CONFIG_WIRE_RESET_QTY = atoi(optarg); break;
					case 19:	EB_CONFIG_WIRE_UPDATE_QTY = atoi(optarg); break;
					case 20:	EB_CONFIG_TRUNK_RESET_QTY = atoi(optarg); break;
					case 21:	EB_CONFIG_TRUNK_UPDATE_QTY = atoi(optarg); break;
					case 22:	EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL = atoi(optarg); break;
					case 23: 	EB_CONFIG_NOKEEPALIVEDEBUG = 1; break;
					case 24:	EB_CONFIG_WIRE_IMM_WAIT = atoi(optarg); break;
					case 25:	EB_CONFIG_BRIDGE_LOOP_DETECT = (atoi(optarg) ? 1 : 0); break;
					case 26:	EB_CONFIG_POOL_RESET_FWD = (atoi(optarg) ? 1 : 0); break;
					case 27:	EB_CONFIG_WIRE_MAX_NOTLISTENING = atoi(optarg); break;
					case 28:	EB_CONFIG_NOBRIDGEANNOUNCEDEBUG = 1; EB_CONFIG_NOKEEPALIVEDEBUG = 1; break;
					case 29:	EB_CONFIG_FS_STATS_PORT = atoi(optarg); break;
					*/
					case 30:	strncpy(jsonconfigout_path, optarg, 255); break;
				}
			} break;
			case 'c':	strncpy(config_path, optarg, 255); break;
			case 'd':	strncpy(debug_path, optarg, 1023); break;
					/* Commented same reason as above
			case 'e':	EB_CONFIG_EXTRALOGS = 1; break;
			*/
			case 'h':	eb_help(argv[0]); exit(EXIT_SUCCESS); break;
			case 'j':	strncpy(jsonconfig_path, optarg, 255); break;
					/* Commented same reason as above
			case 'l':	EB_CONFIG_LOCAL = 1; break;
			case 'n':	EB_CONFIG_MAX_DUMP_BYTES = atoi(optarg); break; // Max packet dump data bytes
			case 'p':	
			{
				if (strchr(optarg, 'i'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_PRE_I;
				if (strchr(optarg, 'I'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_POST_I;
				if (strchr(optarg, 'o'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_PRE_O;
				if (strchr(optarg, 'O'))	EB_CONFIG_PKT_DUMP_OPTS |= EB_PKT_DUMP_POST_O;
			}; break;
			*/
			case 's':	dumpconfig++; break;	
			case 'v':	printf("econet-hpbridge: v%d.%d, GIT repository "GIT_VERSION"\n",
					(EB_VERSION & 0xf0) >> 4,
					(EB_VERSION & 0x0f));
					exit(0);
					break;
			case 'y':	EB_DEBUG_LEVEL++; break;
			
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

	/* Clear BeebMem - used for *VIEW */

	memset (&beebmem, 0, 65536);

	/* Now set up some parameters for *VIEW */

	{
		FILE *b;

		if ((b = fopen("/etc/econet-gpio/BEEBMEM", "r")))
		{
			fread (beebmem, 32768, 1, b);
			fclose (b);
		}
	}

	/* Read config */

#ifdef EB_JSONCONFIG
	/* Compare modified dates of json & legacy configs and pick the right one */
	
	config_stat_res = stat(config_path, &config_stat);
	json_stat_res = stat(jsonconfig_path, &json_stat);

	if (!config_stat_res) /* Stat succeeded */
		if ((config_stat.st_mode & S_IFMT) != S_IFREG) 
			eb_debug (1, 0, "CONFIG", "Configuration file is not a regular file");

	if (!json_stat_res) /* Stat succeeded */
		if ((json_stat.st_mode & S_IFMT) != S_IFREG) 
			eb_debug (1, 0, "CONFIG", "JSON Configuration file is not a regular file");

	if (json_stat_res && config_stat_res)
		eb_debug (1, 0, "CONFIG", "Neither regular nor JSON configuration files was found");

	if (json_stat_res || (json_stat.st_mtime < config_stat.st_mtime)) /* No JSON or stat failed, or legacy config modified more recently, at least in seconds, than JSON config file */
	{
		eb_debug (0, 2, "CONFIG", "%16s Reading legacy config %s and converting to JSON internally", "", config_path);
		if (!eb_readconfig(config_path, jsonconfigout_path, &json_config))
			exit (EXIT_FAILURE);
	}
	else if (!json_stat_res) /* JSON must exist and (given the if() above) must be newer */
	{
		eb_debug (0, 2, "CONFIG", "%16s Reading JSON config %s", "", jsonconfig_path);
		json_config = json_object_from_file(jsonconfig_path);
		if (!json_config)
			eb_debug (1, 0, "JSON", "Cannot read %s as JSON", jsonconfig_path);
	}

	if (!eb_parse_json_config(json_config))
	{
		eb_debug (1, 0, "JSON", "Parsing JSON config failed");
		exit(EXIT_FAILURE);
	}

#else
	if (!eb_readconfig(config_path, jsonconfigout_path))
		exit (EXIT_FAILURE);
#endif

	/* Second parse of command line options so that we override the config file where necessary */

	optind = 1; /* Reset option processing */

	while ((opt = getopt_long(argc, argv, "hc:d:eln:p:sz", long_options, &long_index)) != -1)	
	{
		switch (opt)
		{
			case 0: // Long option
			{
				switch (long_index)
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
					/* case 9:		max_fds.rlim_cur = max_fds.rlim_max = atoi(optarg); break; */
					case 10:	EB_CONFIG_FLASHTIME = atoi(optarg); break;
					case 11:	EB_CONFIG_BLINK_ON = 1; break;
					case 12:	EB_CONFIG_LEDS_OFF = 1; EB_CONFIG_BLINK_ON = 1; break;
					case 13:	normalize_debug = 1; break;
					case 14:	EB_CONFIG_TRUNK_KEEPALIVE_INTERVAL = atoi(optarg); break;
					case 15:	EB_CONFIG_TRUNK_DEAD_INTERVAL = atoi(optarg); break;
					case 16:	EB_CONFIG_POOL_DEAD_INTERVAL = atoi(optarg); break;
					case 17:	fs_set_syst_bridgepriv = 1; break;
					case 18:	EB_CONFIG_WIRE_RESET_QTY = atoi(optarg); break;
					case 19:	EB_CONFIG_WIRE_UPDATE_QTY = atoi(optarg); break;
					case 20:	EB_CONFIG_TRUNK_RESET_QTY = atoi(optarg); break;
					case 21:	EB_CONFIG_TRUNK_UPDATE_QTY = atoi(optarg); break;
					case 22:	EB_CONFIG_WIRE_BRIDGE_QUERY_INTERVAL = atoi(optarg); break;
					case 23: 	EB_CONFIG_NOKEEPALIVEDEBUG = 1; break;
					case 24:	EB_CONFIG_WIRE_IMM_WAIT = atoi(optarg); break;
					case 25:	EB_CONFIG_BRIDGE_LOOP_DETECT = (atoi(optarg) ? 1 : 0); break;
					case 26:	EB_CONFIG_POOL_RESET_FWD = (atoi(optarg) ? 1 : 0); break;
					case 27:	EB_CONFIG_WIRE_MAX_NOTLISTENING = atoi(optarg); break;
					case 28:	EB_CONFIG_NOBRIDGEANNOUNCEDEBUG = 1; EB_CONFIG_NOKEEPALIVEDEBUG = 1; break;
					case 29:	EB_CONFIG_FS_STATS_PORT = atoi(optarg); break;
					//case 30:	strncpy(jsonconfigout_path, optarg, 255); break;
				}
			} break;
			//case 'c':	strncpy(config_path, optarg, 255); break;
			//case 'd':	strncpy(debug_path, optarg, 1023); break;
			case 'e':	EB_CONFIG_EXTRALOGS = 1; break;
			//case 'h':	eb_help(argv[0]); exit(EXIT_SUCCESS); break;
			//case 'j':	strncpy(jsonconfig_path, optarg, 255); break;
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
				fprintf (stderr, "%03d %-15s %s\n", net, eb_type_str(p->type), 
					(p->type == EB_DEF_WIRE) ? p->wire.device : 
					((p->type == EB_DEF_POOL) ? (char *) p->pool.data->name : ""));

				if (p->type == EB_DEF_POOL)
				{
					struct __eb_pool_host	*h;
					uint8_t	started = 0;

					h = p->pool.data->hosts_net[net];

					while (h)
					{

						char	destdevinfo[100];

						if (!started)
							fprintf(stderr, "|-->Stn Destination\n");

						started = 1;

						if (h->source->type == EB_DEF_WIRE)
							sprintf(destdevinfo, "on %s", h->source->wire.device);
						else if (h->source->type == EB_DEF_TRUNK)
							snprintf(destdevinfo, 99, "to %s:%d", h->source->trunk.hostname, h->source->trunk.remote_port);
						else	strcpy(destdevinfo, "");

						fprintf (stderr, "    %03d %-8s %s station %3d.%3d %s\n",
								h->stn,
								eb_type_str(h->source->type),
								destdevinfo,
								h->s_net, h->s_stn,
								(h->is_static ? "(static)" : "")
							);

						h = h->next_net;

					}


				}
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
							char			fw_in[128], fw_out[128];

							d = (p->type == EB_DEF_WIRE) ? p->wire.divert[count] : p->null.divert[count];

							strcpy(fw_in, "I/B FW: None");
							strcpy(fw_out, "O/B FW: None");
							if (d && d->fw_in)
								snprintf(fw_in, 126, "I/B FW: %s", d->fw_in->fw_chain_name);
							if (d && d->fw_out)
								snprintf(fw_out, 126, "O/B FW: %s", d->fw_out->fw_chain_name);
							
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

								fprintf(stderr, "    %03d %-11s %s, %s, %s\n",
									count,
									eb_type_str(d->type),
									info, fw_in, fw_out
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
				char	ig_data[50];

				if (t->im)
					snprintf (ig_data, 49, " (Group %s priority %d)", (char *) t->im->ig->ig_name, t->im->priority);
				else	strcpy(ig_data, "");


				fprintf (stderr, "%5d        %-30s %5d%s\n", 
					t->trunk.local_port,
					t->trunk.hostname ? t->trunk.hostname : "(Dynamic)",
					t->trunk.hostname ? t->trunk.remote_port : 0,
					ig_data
				);
				
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
		
		if (fw_chains) // Dump firewall rules
		{
			struct __eb_fw	*f;
			struct __eb_fw_chain *chain;
			int		counter;

			chain = fw_chains;

			fprintf (stderr, "\nFirewall chains\n\n");

			while (chain)
			{
				fprintf (stderr, "Chain name: %s (default: %s)\n", chain->fw_chain_name, chain->fw_default == EB_FW_ACCEPT ? "Accept" : "Reject");
				f = chain->fw_chain_start;

				counter = 1;
	
				while (f)
				{
					fprintf (stderr, "  %7d %3d.%-3d --> %3d.%-3d port &%02X %s", counter++,
							f->srcnet, f->srcstn,
							f->dstnet, f->dststn, f->port,
							(f->action == EB_FW_ACCEPT) ? "Accept" : (f->action == EB_FW_REJECT ? "Drop" : "Pass to")
						);
	
					if (f->action == EB_FW_CHAIN)
						fprintf (stderr, " %s", f->fw_subchain->fw_chain_name);

					fprintf (stderr, "\n");

					f = f->next;
				}
	
				fprintf (stderr, "\n");
				chain = chain->next;
			}

		}

	}
	
	/* Start the engines, captain! */

	eb_debug (0, 1, "MAIN", "Core             Bridge to engine room: Start main engines...");

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

	/* Start up the multitrunk devices */

	p = multitrunks;

	while (p)
	{
		int e;

		eb_debug (0, 2, "MAIN", "%-8s %7d Starting multitrunk handler thread for %s", eb_type_str(p->type), p->multitrunk.port, p->multitrunk.mt_name);

		/*
		if (p->multitrunk.mt_type == MT_SERVER)
			e = pthread_create(&(p->me), NULL, eb_multitrunk_server_device, p);
		else
			e = pthread_create(&(p->me), NULL, eb_multitrunk_client_device, p);
		*/

		/* All multitrunks will listen on a port unless the port isn't defined (i.e. client connections outbound only */

		if (p->multitrunk.port)
		{
			e = pthread_create(&(p->mt_server_thread), NULL, eb_multitrunk_server_device, p);

			if (e)
				eb_debug (1, 0, "MAIN", "Thread creation for multitrunk server handler for %s failed", eb_type_str(p->type), p->multitrunk.port, p->multitrunk.mt_name);

			pthread_detach(p->mt_server_thread);

			eb_thread_started();
		}

		/* client devices are started on the trunks themselves if they're mt children */

		p = p->next;

	}

	/* Start the trunk devices */

	p = trunks;

	while (p)
	{
		int e;

		eb_debug (0, 2, "MAIN", "%-8s %7d Starting trunk handler thread", eb_type_str(p->type), p->trunk.local_port);

		if ((e = pthread_create(&(p->me), NULL, eb_device_despatcher, p)))
			eb_debug (1, 0, "MAIN", "Thread creation for trunk failed: %s", strerror(e));

		pthread_detach(p->me);

		eb_thread_started();

		p = p->next;
	}


	/* Start exposures here */

	{
		uint8_t			nets_done[255];

		memset (nets_done, 0, 255);

		e = exposures;

		while (e)
		{

			if (!nets_done[e->net])
			{
				nets_done[e->net] = 1;
				pthread_create (&(e->me), NULL, eb_aun_listener, e);
				pthread_detach (e->me);
				eb_thread_started();
			}	

			e = e->next;
		}
	}

	{ // Start stats threads
		
		int err;
		pthread_t	stats, fs_stats;
		pthread_attr_t	attrs;

		pthread_attr_init (&attrs);
		pthread_attr_setstacksize(&attrs, PTHREAD_STACK_MIN);
	
		if ((err = pthread_create (&stats, NULL, eb_statistics, NULL)))
			eb_debug (1, 0, "MAIN", "STATS        Unable to start statistics thread");

		pthread_detach(stats);

		eb_thread_started();

		pthread_attr_init (&attrs);
		pthread_attr_setstacksize(&attrs, PTHREAD_STACK_MIN);
	
		if ((err = pthread_create (&fs_stats, NULL, eb_fs_statistics, NULL)))
			eb_debug (1, 0, "MAIN", "STATS        Unable to start FS statistics thread");

		pthread_detach(fs_stats);

		eb_thread_started();
	}

	// Start the pool garbage collector
	
	{
		int err;
		pthread_t	pool_garbage;
		pthread_attr_t	attrs;

		pthread_attr_init (&attrs);
		pthread_attr_setstacksize(&attrs, PTHREAD_STACK_MIN);
	
		if ((err = pthread_create (&pool_garbage, NULL, eb_pool_garbage_collector, NULL)))
			eb_debug (1, 0, "MAIN", "POOL         Unable to start pool garbage collector thread");

		pthread_detach(pool_garbage);

		eb_thread_started();

	}

	/* Start the loopdetect thread */

	{
		int err;
	
		if ((err = pthread_create(&loopdetect_thread, NULL, eb_loopdetect_thread, NULL)))
			eb_debug (1, 0, "MAIN", "Thread creation for loopdetect failed: %s", strerror(err));

		eb_thread_started();
		pthread_detach(loopdetect_thread);
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

	if (!EB_CONFIG_TRUNK_LOOPDETECT_DISABLE)
		eb_debug (0, 1, "BRIDGE", "%-8s         Bridge loop detection identifier 0x%08X", "Core", EB_CONFIG_TRUNK_LOOPDETECT_ID);
	

	eb_debug (0, 1, "MAIN", "%-8s         Engine room to bridge: %d engines at full chat. Wait for traffic.", "Core", threads_ready);

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
	signal (SIGUSR1, eb_signal_handler);
	signal (SIGUSR2, eb_signal_handler);

	/* Now doze off */

	eb_debug (0, 2, "MAIN", "Core             Main loop going to sleep.", "");

	while (1)
		sleep (600); // ZZzzzzz....

}

/* Get sequence number for locally emulated station
*/

uint32_t eb_get_local_seq (struct __eb_device *d)
{

	/* Old code
	struct __eb_device *network = d;
	*/

	// if it's a local station, it must exist as a divert in a wire or Null driver

	if (d->type != EB_DEF_LOCAL)
		return 0;
/* Old code
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
	*/

	return (d->local.seq += 4);

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
uint8_t get_printer_info(unsigned char net, unsigned char stn, uint8_t printer_id, char *pname, char *banner, uint8_t *control, uint8_t *status, short *user, uint8_t *printertype)
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
	*printertype = printer->printertype;

	return 1;
}

uint8_t set_printer_info(unsigned char net, unsigned char stn, uint8_t printer_id, char *pname, char *banner, uint8_t control, ushort user, uint8_t printertype)
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
	if (printertype != 0xFF) printer->printertype = printertype; // 0xFF used to signal "don't update"

	// Deal with user ID here...

	return 1;	

}

/* FS Statistics output via TCP connection */

static void * eb_fs_statistics (void *nothing)
{

	struct sockaddr_in	server;

	int			stat_socket;
	int			optval = 1;

	// TO DO: Open a TCP listener on the socket specified in the config (default 8086)
	// When we get a connection, spit out the current stats and close.

	// Initialization section

	stat_socket = socket(AF_INET, SOCK_STREAM, 0); 

	if (stat_socket == -1)
		eb_debug (1, 0, "STATS", "                 Unable to open FS statistics TCP socket: %s", strerror(errno));

	if (setsockopt(stat_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1)
		eb_debug (1, 0, "STATS", "                 Unable to set SO_REUSEADDR on FS statistics TCP socket: %s", strerror(errno));

	memset (&server, 0, sizeof(server));

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(EB_CONFIG_FS_STATS_PORT);

	if (bind(stat_socket, (struct sockaddr *) &server, sizeof(server)) == -1)
		eb_debug (1, 0, "STATS", "                 Unable to bind FS statistics TCP socket: %s", strerror(errno));

	if (listen(stat_socket, 5) == -1)
		eb_debug (1, 0, "STATS", "                 Unable to listen on FS statistics TCP socket: %s", strerror(errno));

	eb_thread_ready();

	eb_debug (0, 2, "STATS", "                 FS Statistics listener started on port %d", EB_CONFIG_FS_STATS_PORT);
	// Listener loop

	while (1)
	{
		int 		connection;
		FILE *		output;

		struct __eb_device	*device;

		connection = accept(stat_socket, (struct sockaddr *) NULL, NULL);

		output = fdopen(connection, "w");

		fprintf (output, "#Pi Econet Bridge FS Statistics Socket\n");

		// Look for WIRE & NULL devices that may have local diverts with fileservers on them

		device = devices;

		while (device)
		{
			struct __eb_device	*local;

			//fprintf (output, "Look at device %p (%s)\n\n", device, eb_type_str(device->type));

			if (device->type == EB_DEF_WIRE || device->type == EB_DEF_NULL) // Can contain diverts
			{
				uint8_t	stn;

				for (stn = 1; stn < 255; stn++)
				{
					local = NULL;

					//fprintf (output, "Look at device %p (%s) net %d stn %d...", device, eb_type_str(device->type), device->net, stn);

					if (device->type == EB_DEF_WIRE && device->wire.divert[stn])
						local = device->wire.divert[stn];
					else if (device->type == EB_DEF_NULL && device->null.divert[stn])
						local = device->null.divert[stn];

					if (local && local->type == EB_DEF_LOCAL)
					{
						if (fsop_is_enabled(local->local.fs.server))
						{
							fsop_dump_handle_list (output, local->local.fs.server);
						}

					}
				}
			}

			device = device->next;

		}

		fclose(output);
	}

	return NULL;
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

		/* Dump trunk info first */

		device = trunks;

		while (device)
		{

			char 	ig_data[50];

			if (device->im) /* See if we're in an interface group */
				snprintf (ig_data, 49, " (Intf. group %s priority %d)", device->im->ig->ig_name, device->im->priority);
			else	strcpy(ig_data, "");

			pthread_mutex_lock (&(device->statsmutex));

			if (difftime(time(NULL), device->last_rx) > EB_CONFIG_TRUNK_DEAD_INTERVAL) // Trunk never used
				fprintf (output, "999|000|Trunk|Local %d to %s:%d%s|%" PRIu64 "|%" PRIu64 "|Dead|\n",	(device->trunk.local_port), (device->trunk.hostname ? device->trunk.hostname : "(Not connected)"), (device->trunk.hostname ? device->trunk.remote_port : 0), ig_data, device->b_in, device->b_out);
			else
				fprintf (output, "999|000|Trunk|Local %d to %s:%d%s|%" PRIu64 "|%" PRIu64 "|%.0f|\n",	(device->trunk.local_port), (device->trunk.hostname ? device->trunk.hostname : "(Not connected)"), (device->trunk.hostname ? device->trunk.remote_port : 0), ig_data, device->b_in, device->b_out, difftime(time(NULL), device->last_rx));
		
			pthread_mutex_unlock (&(device->statsmutex));

			device = device->next;
		}


/*
		device = devices;

		while (device)
		{
*/

		/* Count through the nets instead of devices */

		for (net = 1; net < 255; net++)
		{

			char 	trunkdest[256];
			char	ig_data[50];

			strcpy (trunkdest, "");

			device = eb_get_network(net);

			strcpy (ig_data, "");

			if (!device) continue;

			switch (device->type)
			{
				case EB_DEF_TRUNK:
					sprintf (trunkdest, "%s:%d", 
						(device->trunk.hostname ? device->trunk.hostname : "(Not connected)"), 
						(device->trunk.hostname ? device->trunk.remote_port : 0));
					break;
				case EB_DEF_WIRE:
					sprintf (trunkdest, "%s", device->wire.device);
					if (device->im)
						snprintf (ig_data, 49, " (Group %s priority %d)", device->im->ig->ig_name, device->im->priority);
					break;
				case EB_DEF_NULL:
					sprintf (trunkdest, "Local null");
					break;
				case EB_DEF_POOL:
					sprintf (trunkdest, "Local pool %s", device->pool.data->name);
					break;
			}
						
			pthread_mutex_lock (&(device->statsmutex));

			fprintf (output, "%03d|000|%s|%s%s|%" PRIu64 "|%" PRIu64 "||\n",	net, eb_type_str(device->type), 
				trunkdest, ig_data,
				device->b_in, device->b_out);
		
			pthread_mutex_unlock (&(device->statsmutex));

			if (device->type == EB_DEF_POOL) // Dump live pool connections
			{
				//uint8_t		net;
				struct __eb_pool_host	*hostlist;
				char		dest[128];

				//net = device->net;

				pthread_mutex_lock(&(device->pool.data->updatemutex));

				hostlist = device->pool.data->hosts_net[net];

				while (hostlist)
				{
					struct timeval	now;

					gettimeofday (&now, 0);

					if ((hostlist->is_static) || (timediffmsec(&(hostlist->last_traffic), &now) <= (EB_CONFIG_POOL_DEAD_INTERVAL * 1000)))
					{
					
						if (hostlist->source->type == EB_DEF_TRUNK)
							snprintf (dest, 127, "%d.%d %svia trunk to %s:%d",
								hostlist->s_net, hostlist->s_stn,
								(hostlist->is_static ? "(static) " : ""),
								(hostlist->source->trunk.hostname ? hostlist->source->trunk.hostname : "(Not connected)"), 
								(hostlist->source->trunk.hostname ? hostlist->source->trunk.remote_port : 0));
						else if (hostlist->source->type == EB_DEF_WIRE) // Wire source
							snprintf (dest, 127, "%d.%d %svia wire net %d",
								hostlist->s_net, hostlist->s_stn,
								(hostlist->is_static ? "(static) " : ""),
								hostlist->source->net);
						else 	snprintf (dest, 127, "%d.%d %svia unknown device",
								hostlist->s_net, hostlist->s_stn,
								(hostlist->is_static ? "(static) " : ""));
	
						pthread_mutex_lock (&(hostlist->statsmutex));
						fprintf (output, "%03d|%03d|%s|%s|%" PRIu64 "|%" PRIu64 "||\n",	net, hostlist->stn, "Pool", dest, hostlist->b_in, hostlist->b_out);
						pthread_mutex_unlock (&(hostlist->statsmutex));
					}

					hostlist = hostlist->next_net;
				}

				pthread_mutex_unlock(&(device->pool.data->updatemutex));

			}

			if ((net == device->net) && (device->type == EB_DEF_NULL || device->type == EB_DEF_WIRE))
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
							case EB_DEF_AUN:	stn = divert->aun->stn; if (divert->aun->port == -1) sprintf (info, "Inactive"); else sprintf(info, "%d.%d.%d.%d:%d", (divert->aun->addr & 0xff000000) >> 24, (divert->aun->addr & 0x00ff0000) >> 16, (divert->aun->addr & 0x0000ff00) >> 8, (divert->aun->addr & 0x000000ff), divert->aun->port); break;
							case EB_DEF_LOCAL:	stn = divert->local.stn; sprintf(info, "%c%c%c", ((divert->local.printers) ? 'P' : ' '),
								(fsop_is_enabled(divert->local.fs.server) ? 'F' : ' '),
								((divert->local.ip.tunif[0] != '\0') ? 'I' : ' ')); break;
							case EB_DEF_PIPE:	stn = divert->pipe.stn; sprintf(info, "%s", divert->pipe.base); break;
							default:		stn = 0; break;
						}
	
						pthread_mutex_lock (&(divert->statsmutex));

						/*
						 * Don't bother outputting inactive AUN
						 */

						if (divert->type != EB_DEF_AUN || divert->aun->port != -1) fprintf (output, "%03d|%03d|%s|%s|%" PRIu64 "|%" PRIu64 "||\n",	divert->net, stn, eb_type_str(divert->type), info, divert->b_in, divert->b_out);
		
						pthread_mutex_unlock (&(divert->statsmutex));
					}
				}						
			}

			/* device = device->next; */

		}

		/* Now done above */

		// And now the rest of the networks which are via other devices

		//for (net = 1; net < 255; net++)
		if (0)
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
							(device->trunk.hostname ? device->trunk.hostname : "(Not connected)"), 
							(device->trunk.hostname ? device->trunk.remote_port : 0));
						break;
					case EB_DEF_WIRE:
						sprintf (trunkdest, "%s", device->wire.device);
						break;
					case EB_DEF_NULL:
						sprintf (trunkdest, "Local null");
						break;
					case EB_DEF_POOL:
						sprintf (trunkdest, "Local pool %s", device->pool.data->name);
						break;
				}
							
				pthread_mutex_lock (&(device->statsmutex));
	
				if (device->type == EB_DEF_TRUNK)
				{
					char	extra[128];

					strcpy(extra, "");

					if (device->trunk.xlate_out[net])
						sprintf (extra, " (net %d at remote)", device->trunk.xlate_out[net]);

					strcat(trunkdest, extra);
				}

				fprintf (output, "%03d|000|%s|%s|%" PRIu64 "|%" PRIu64 "||\n",	net, eb_type_str(device->type), 
					trunkdest,
					device->b_in, device->b_out);
			
				pthread_mutex_unlock (&(device->statsmutex));

				if (device->type == EB_DEF_POOL) // Dump live pool connections
				{
					struct __eb_pool_host	*hostlist;
					char		dest[128];
	
					pthread_mutex_lock(&(device->pool.data->updatemutex));
	
					hostlist = device->pool.data->hosts_net[net];
	
					while (hostlist)
					{
						struct timeval	now;
	
						gettimeofday (&now, 0);
	
						if ((hostlist->is_static) || (timediffmsec(&(hostlist->last_traffic), &now) <= (EB_CONFIG_POOL_DEAD_INTERVAL * 1000)))
						{
						
							if (hostlist->source->type == EB_DEF_TRUNK)
								snprintf (dest, 127, "%d.%d %svia trunk to %s:%d",
									hostlist->s_net, hostlist->s_stn,
									(hostlist->is_static ? "(static) " : ""),
									(hostlist->source->trunk.hostname ? hostlist->source->trunk.hostname : "(Not connected)"), 
									(hostlist->source->trunk.hostname ? hostlist->source->trunk.remote_port : 0));
							else if (hostlist->source->type == EB_DEF_WIRE) // Wire source
								snprintf (dest, 127, "%d.%d %svia wire net %d",
									hostlist->s_net, hostlist->s_stn,
									(hostlist->is_static ? "(static) " : ""),
									hostlist->source->net);
							else 	snprintf (dest, 127, "%d.%d %svia unknown device",
									hostlist->s_net, hostlist->s_stn,
									(hostlist->is_static ? "(static) " : ""));
		
							pthread_mutex_lock (&(hostlist->statsmutex));
							fprintf (output, "%03d|%03d|%s|%s|%" PRIu64 "|%" PRIu64 "||\n",	net, hostlist->stn, "Pool", dest, hostlist->b_in, hostlist->b_out);
							pthread_mutex_unlock (&(hostlist->statsmutex));
						}
	
						hostlist = hostlist->next_net;
					}
	
					pthread_mutex_unlock(&(device->pool.data->updatemutex));
	
				}
			}
		}


		fclose(output);
		
	}

	return NULL;
	

}

/* Port allocator for local emulators */
/* If req_port != 0, asking for specific port, so we ignore the reserved flag */

uint8_t	eb_port_allocate(struct __eb_device *d, uint8_t req_port, port_func func, void *param)
{

	uint8_t		port, start, last;

	last = d->local.last_port;
	start = d->local.last_port + 1;
	if (start == 0xFF || start == 0x00)
		start = 0x01;

	port = start;

	if (req_port != 0)
		port = req_port;

	if (d->type != EB_DEF_LOCAL) /* Should noly be local emulators asking! */
	{
		eb_debug (0, 1, "BRIDGE", "%-8s %3d.%3d Impermissible non-local request to allocate port &%02X", eb_type_str(d->type), d->net, d->local.stn, req_port);
		return 0;
	}

	pthread_mutex_lock(&(d->local.ports_mutex));

	while (port != last)
	{
		if (!EB_PORT_ISSET(d,ports,port) && (!EB_PORT_ISSET(d,reserved_ports,port) || req_port != 0))
		{
			EB_PORT_SET(d,ports,port,func,param);
			if (req_port == 0) d->local.last_port = port;
			pthread_mutex_unlock(&(d->local.ports_mutex));
			eb_debug (0, 2, "BRIDGE", "%-8s %3d.%3d Port &%02X allocated (%s)", eb_type_str(d->type), d->net, d->local.stn, port, (req_port == 0x00 ? "Dynamic" : "Static"));
			return port;
		}

		if (req_port != 0) /* No use if we got here */
			break;

		port++;

		if (port == 0xFF || port == 0x00)
			port = 0x01;

	}

	pthread_mutex_unlock(&(d->local.ports_mutex));

	/* If we get here, no port */

	if (req_port == 0x00)
		eb_debug (0, 2, "BRIDGE", "%-8s %3d.%3d Failed request to allocate dynamic port", eb_type_str(d->type), d->net, d->local.stn);
	else
		eb_debug (0, 2, "BRIDGE", "%-8s %3d.%3d Failed request to allocate port &%02X", eb_type_str(d->type), d->net, d->local.stn, req_port);

	return 0;
}

void eb_port_deallocate(struct __eb_device *d, uint8_t port)
{

	pthread_mutex_lock(&(d->local.ports_mutex));
	EB_PORT_CLR(d,ports,port);
	pthread_mutex_unlock(&(d->local.ports_mutex));

	eb_debug (0, 2, "BRIDGE", "%-8s %3d.%3d Port &%02X de-allocated", eb_type_str(d->type), d->net, d->local.stn, port);

}

/* Bridge loop detect routines */

/*
 * eb_loopdetect_send_probe
 *
 * Sends a loop detect probe on a given interface
 */

void eb_loopdetect_send_probe (struct __eb_device *d)
{
	struct __econet_packet_aun 	*p;
	uint8_t	sender_net;
	struct __eb_loop_probe		probe;

	if (d->type != EB_DEF_WIRE && d->type != EB_DEF_TRUNK)
		return;

	if (d->all_nets_pooled)
		return;

	p = eb_malloc (__FILE__, __LINE__, "TRUNK", "Trunk loop probe packet", 12 + sizeof(struct __eb_loop_probe));

	if (!p) return;

	sender_net = eb_bridge_sender_net (d);

	p->p.srcnet = sender_net;
	p->p.srcstn = 0;
	p->p.dstnet = p->p.dststn = 0xFF;
	p->p.aun_ttype = ECONET_AUN_BCAST;
	p->p.port = ECONET_BRIDGE_LOOP_PROBE;
	p->p.ctrl = 0x80;
	p->p.seq = 0x00;

	probe.root = htonl(EB_CONFIG_TRUNK_LOOPDETECT_ID);
	probe.hostdata = htonl(loopdetect_hostdata);
	probe.src_int = htonl(d->index);
	probe.hops = 0x00;

	memcpy (&(p->p.data), &probe, 13);

	eb_enqueue_input(d, p, 13);
}

/* 
 * eb_loopdetect_thread
 * 
 *
 * Waits (bridge id)ms so that the receiver threads can 
 * receive probes in case they are lower than ours...
 *
 * If at that stage nobody has sent a probe with an ID
 * less than ours, we send probes every 10 seconds until
 * a lower probe turns up.
 *
 * If the bridge core signals it's had a bridge reset,
 * we wait again.
 *
 */

void * eb_loopdetect_thread (void *data)
{

	eb_thread_ready();

	eb_debug (0, 1, "BRIDGE", "%-8s %7s Bridge loop detect thread running", "Core", "");

	if (!EB_CONFIG_TRUNK_LOOPDETECT_DISABLE)
	{
		struct __eb_device *d = devices;
		uint8_t	is_root = 0;
		uint32_t	usleep_time;

		usleep_time = EB_CONFIG_TRUNK_LOOPDETECT_ID >> 6; /* Max is 0xffffffff >> 6 us, which is about 64,000,000us, or 64s */

		while (1)
		{
			pthread_mutex_lock (&loopdetect_mutex);

			if (last_root_id_seen == 0xFFFFFFFF && !is_root) /* Rogue - set when there's been a bridge reset, so we sleep */
				usleep(usleep_time); /* Wait to see if anyone more eligible sends a probe */

			if (!
				(
					(last_root_id_seen > EB_CONFIG_TRUNK_LOOPDETECT_ID)
				||	((time(NULL) - when_root_id_seen) > (EB_CONFIG_TRUNK_LOOPDETECT_INTERVAL+2))
				)
			) // Not root bridge
			{
				if (is_root)
					eb_debug (0, 1, "BRIDGE", "%-8s %7s Not root bridge - root is %08X", "Core", "", last_root_id_seen);

				eb_debug (0, 3, "BRIDGE", "%-8s %7s Bridge loop detect - not root bridge - sleeping %dms - last_root_id_seen = %08X, mine = %08X, now-last_seen = %d", "Core", "", usleep_time / 1000, last_root_id_seen, EB_CONFIG_TRUNK_LOOPDETECT_ID, (time(NULL) - when_root_id_seen));

				is_root = 0;
				pthread_mutex_unlock (&loopdetect_mutex);
				if (last_root_id_seen != 0xFFFFFFFF)
					usleep(usleep_time); /* Wait to see if anyone more eligible sends a probe */
			}
			else // We appear to be the root bridge
			{
				if (!is_root)
					eb_debug (0, 1, "BRIDGE", "%-8s %7s Elected root bridge", "Core", "");
				
				is_root = 1;

				eb_debug (0, 3, "BRIDGE", "%-8s %7s Bridge loop detect - root bridge sending probes", "Core", "");

				while (d)
				{
					if (d->type == EB_DEF_WIRE)
						eb_loopdetect_send_probe(d);
					d = d->next;
				}

				d = trunks;

				while (d)
				{
					eb_loopdetect_send_probe(d);
					d = d->next;
				}

				pthread_mutex_unlock (&loopdetect_mutex);
				sleep (EB_CONFIG_TRUNK_LOOPDETECT_INTERVAL);
			}
		}
	}

	eb_debug (0, 1, "BRIDGE", "%8s %7s Bridge loop detect thread ending - loop detection disabled", "", "");

	return NULL;
}
