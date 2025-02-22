/*
  (c) 2025 Chris Royle
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
 * econet-hpbridge-multitrunk.c
 *
 * Contains the despatcher routine for multitrunks.
 *
 * When a multitrunk client is initialized, it will have its
 * mt_parent pointer set to one of these despatcher objects.
 * As the TCP listener socket can be created to listen on
 * IPv4 and IPv6 at the same time, each such multitrunk
 * server object only listens on a single TCP socket.
 *
 * At startup, it will create a pipe2() pair for each
 * client trunk that is associated to it via its mt_parent
 * pointer. Those pipe2() pairs will use
 * O_NONBLOCK and O_DIRECT so that packets sent and 
 * received from the client trunks go as a single
 * unit, like they are doing on UDP at the moment.
 *
 * It'll lock the client trunk and put that pair of ints
 * into the client's mt_socket array. The client will
 * have slept on a signal, which this despatcher will
 * wake up when it finds traffic for those trunks.
 *
 * When this thread gets a new connection, it'll put it on
 * its list of "unknown trunk" connections and wait for
 * traffic. It'll sit listening for traffic on those connections
 * and looks for the '*' packet start marker. It then receives
 * the following Base64 data (upto 32k in 8bit form) up to
 * a '*' packet end marker. 
 *
 * If the multitrunk doesn't yet know the key for the traffic,
 * it works through each multitrunk client object (by
 * iterating over *trunks) and tries to find one under lock
 * which is (i) attached to this multitrunk and (ii) is marked
 * inactive. If that trunk's key successfully decrypts the 
 * traffic then the key is copied into local storage and used
 * thereafter. The socket is added to the list of sockets the
 * multitrunk object listens on, together with the appropriate
 * member of the pipe2() pair, in order to receive traffic
 * for outbound transmission.
 *
 * If no such trunk is found, the connection is simply closed.
 *
 * If the TCP connection drops, the trunk client is locked,
 * marked inactive, and a bridge reset triggered.
 * 
 */

#define _GNU_SOURCE

#include "econet-hpbridge.h"

struct mt_client {
	struct __eb_device	*trunk, *multitrunk_parent; 
	int			mt_pipe[2];
	int			socket; // Socket to distant end 
	unsigned char *		key; // Will also be NULL until we've found the relevant trunk client
	uint8_t 		* recv_buffer; // malloced when data turns up after a '*'. The trailing '*' is never put in this buffer. This buffer is decoded from Base64
	uint16_t		recv_length; // Current malloc'd length of recv_buffer
	uint8_t			* packet; // Buffer for transfer to trunk pipe - this will be encrypted on transmission to the trunk client (distant end) if this is a TCP trunk, or a UDP encrypted trunk
	uint16_t		packet_length;
	uint8_t			* decrypted_buffer; // Only used when we are trying to work out which endpoint has connected to us
	enum			{ MT_IDLE = 1, MT_START = 2, MT_DATA = 3 } mt_state; // IDLE = waiting for beginning '*', START means '*' received but no data, DATA means receiving data (and waiting for trailing '*')
	enum			{ MT_TYPE_UDP = 1, MT_TYPE_TCP = 2 } mt_type; // Not used at present - TCP trunks only for now. This is for later when we might consolidate UDP and TCP listening into the same infrastructure
	struct mt_client 	* next;
};

/* 
 * Multitrunk transceiver thread
 *
 * Parameter is pointer to struct mt_client
 *
 * Spawned by server or client device threads.
 *
 * If started by client thread, then *trunk and key will be populated already.
 * If started by server thread, we'll need to wait for received traffic,
 * find a trunk within *trunks that matches and decrypts successfully and then
 * populate.
 *
 * On disconnection, just clear out the necessary data in the underlying
 * trunk to flag it as inactive, lock the multitrunk struct & splice out
 * our device, and then the thread dies - we wait for server or client to
 * start a new one. Probably need to wake the client thread somehow to
 * get it to start trying to connect unconnected multitrunks again.
 */

void * eb_multitrunk_handler_thread (void * input)
{
	struct mt_client	* me;

	me = (struct mt_client *) input;
}

/* 
 * multitrunk client device.
 *
 * Attempts to connect (and, when disconnected, reconnect) trunks which have
 * a defined remote endpoint.
 *
 * Uses locking within the (ordinary) trunk device to update all the 
 * relevant fields so that the multitrunk server doesn't accept a 
 * connection from an already connected trunk and vice versa.
 */

void * eb_multitrunk_client_device (void * device)
{
	struct __eb_device	*me; /* A multi-trunk device */

	return NULL;
}

/* multitrunk server device
 * listens and spins off a tcp transceiver thread for
 * each device opened
 */

void * eb_multitrunk_server_device (void * device)
{
	struct __eb_device	*me;
	struct pollfd		*fds, *fds_initial;
	uint16_t		numfds = 0; // How many things in *fds, *fds_initial
	int			ga_return, poll_return;
	struct addrinfo		hints;
	struct addrinfo		*mt_addresses, *mt_iterate;
	char			portstring[10];

	/* Note: port number & host (or NULL) to listen on are in device->multitrunk->port, device->multitrunk->host */

	me = (struct __eb_device *) device;

	sprintf (portstring, "%5d", me->multitrunk.port);

	memset (&hints, 0, sizeof(hints));
	hints.ai_family = me->multitrunk.ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (me->multitrunk.host) ? 0 : AI_PASSIVE; // Give us the "all addresses" struct if name is null
	hints.ai_protocol = 6;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	eb_thread_ready();

	ga_return = EAI_AGAIN;

	while (ga_return == EAI_AGAIN)
	{
		ga_return = getaddrinfo(me->multitrunk.host, portstring, &hints, &mt_addresses);
		if (ga_return == EAI_AGAIN)
		{
			eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Server on %s:%d Temporary failure in name resolution, trying again in 10s", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);
			sleep(10);
		}
	}

	if (ga_return != 0)
		eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to resolve listen address: %s", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, gai_strerror(ga_return));

	eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Server on %s:%d successfully resolved hostname", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);
	
	if (!mt_addresses)
		eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d getaddrinfo() returned no addresses", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

	/* Now lets create some sockets */

	for (mt_iterate = mt_addresses; mt_iterate != NULL; mt_iterate = mt_iterate->ai_next)
	{
		int mt_socket;
		int on = 1;

		mt_socket = socket (mt_iterate->ai_family,
					mt_iterate->ai_socktype,
					mt_iterate->ai_protocol);

		if (mt_socket == -1)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to create a required socket", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		if (setsockopt(mt_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to set SO_REUSEADDR", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		if (bind(mt_socket, mt_iterate->ai_addr, mt_iterate->ai_addrlen) != 0)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to bind to %s (addr family %d)", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, mt_iterate->ai_canonname, mt_iterate->ai_protocol);

		if (listen(mt_socket, me->multitrunk.listenqueue ? me->multitrunk.listenqueue : 10) < 0)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to set listen queue length", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		if (numfds == 0) // fds_initial won't point to anything yet
			fds_initial = eb_malloc(__FILE__, __LINE__, "M-TRUNK", "Allocate first pollfd structure for fs_initial", sizeof(struct pollfd));
		else // Reallocate
			fds_initial = realloc(fds_initial, (numfds + 1) * sizeof(struct pollfd));

		if (!fds_initial)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Error reallocating fds structure on server %s:%d", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		memset(&(fds_initial[numfds]), 0, sizeof(struct pollfd));

		fds_initial[numfds].fd = mt_socket;
		fds_initial[numfds].events = POLLIN;
		numfds++;
	}

	eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Server on %s:%d successfully opened %d listener(s)", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, numfds);

	fds = eb_malloc (__FILE__, __LINE__, "M-TRUNK", "Allocate memory for list of fds to accept on", sizeof(struct pollfd) * numfds);

	memcpy (fds, fds_initial, sizeof(struct pollfd) * numfds);

	while ((poll_return = poll(fds, numfds, 10000))) // 10s timeout
	{

		if (poll_return > 0)
		{
			uint16_t	count;
			int		newconn;
			char		*text = "Test message";

			/* Loop through the fds struct, accept what needs accepting, and spin off some server threads */

			for (count = 0; count < numfds; count++)
			{
				if (fds[count].revents & POLLIN)
				{
					newconn = accept(fds[count].fd, NULL, NULL);

					if (newconn >= 0)	
					{
						/* Spawn a thread */

						/* For now... */

						send(newconn, text, strlen(text), 0);	

						close(newconn);
					}
				}
			}
		}

		/* Go again */

		memcpy (fds, fds_initial, sizeof(struct pollfd) * numfds);

	}

	return NULL;
}
