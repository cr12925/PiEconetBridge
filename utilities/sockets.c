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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef SKS_SSH_ENABLED
	#include <libssh2.h>
#endif
#include "../include/econet-gpio-consumer.h"

#define SKS_PORT 0xDF // Econet Port number

extern int fs_get_server_id(unsigned char, unsigned char);
extern int fs_stn_logged_in(int, unsigned char, unsigned char);
extern int get_local_seq(unsigned char, unsigned char);
extern int aun_send (struct __econet_packet_udp *, int, short, short, short, short);

unsigned short sks_active_connection(int, unsigned char, unsigned char, unsigned short *, unsigned short *, unsigned short *);

// Running commentary switch
unsigned short sks_quiet = 0;
unsigned short sks_max = 0; // First unused server struct (or number of configured servers, whichever you prefer)

// Max number of virtual servers that can be run in one bridge instance
#define SKS_MAX_SERVERS 16
// Max sockets a single server can handle at once and thus be configured for
#define SKS_MAX_SERVICES 32
// Max connections to each server - whether the server is limited to fewer readers/writers or not
#define SKS_MAX_CONNECTIONS 8

// Maximum TX/RX buffer size -- The beeb client will typically reserve 1 page for workspace, and uses 48 byte buffers
#define SKS_MAX_BUFSIZE 48 

// Note each station can only have one connection at once, so no table of stations->connections is needed - just see if the station crops up 
// in the user_nets/user_stns elements of the sks_server struct

enum sks_errors {
	SKS_SUCCESS = 0, // Operation succeeded, or data follows
	SKS_NOTLOGGEDIN = 1, // You need to be logged in and you aren't
	SKS_NOSUCHSERVICE = 2, // Service name unknown
	SKS_SERVICEBUSY = 3, // Too many readers / writers - interlock failure, basically
	SKS_CANNOTOPEN = 4, // Device/file/socket/whatever could not be opened even though you were entitled to ask
	SKS_CLOSED = 5, // From server - means unexpected close without the user asking
	SKS_UNKNOWN = 0xff // Unknown function call
};

enum sks_funcs {
	SKS_NOP = 0,
	SKS_LIST = 1, // List services available on this host with type numbers, hostnames and port numbers etc.
	SKS_OPEN = 2, // Open a service (mode as enum below)
	SKS_CLOSE = 3, // Close a service - finished, thank you so much
	SKS_DATA = 4 // Sending data from other end
};

enum sks_types {
	SKS_TCP = 1,
	SKS_SSH,
	SKS_FILE
};

struct sks_server {
	unsigned short sks_type; // One of sks_types
	char sks_name[16]; // Service name
	union {
		struct {
			char hostname[1024];
			unsigned short port;
		} tcpopts;
		struct {
			char hostname[1024];
			unsigned short port;
		} sshopts;
		struct {
			char filename[1024];
		} fileopts;
	} sks_data;
	unsigned short max_conns; 
	unsigned char must_login; // non-zero if config requires user to be logged in
	unsigned short user_nets[SKS_MAX_CONNECTIONS], user_stns[SKS_MAX_CONNECTIONS]; // net, stn & mode of each live connection. 0,0,0 = unused
	unsigned char user_tx_buffers[SKS_MAX_CONNECTIONS][SKS_MAX_BUFSIZE];
	unsigned char user_rx_buffers[SKS_MAX_CONNECTIONS][SKS_MAX_BUFSIZE];
	unsigned short user_remote_win[SKS_MAX_CONNECTIONS]; // last advertised available bytes in remote receiver buffer
	unsigned short user_local_win[SKS_MAX_CONNECTIONS]; // number of available bytes in tx buffer for this user
	union {
		int socket; // For TCP
		FILE *fhandle; // For files
#ifdef SKS_SSH_ENABLED
		LIBSSH2_SESSION *ssh_session; // For SSH
#endif
	} handles[SKS_MAX_CONNECTIONS];
};

struct {
	unsigned char net, stn; // net.stn of this server
	unsigned short services; // Total number of entries in info element. So 0 = none valid.
	struct sks_server info[SKS_MAX_SERVICES];
} sks_servers[SKS_MAX_SERVERS];

struct sks_rx {
	unsigned char func;
	unsigned char reply_port;
	unsigned char window[2]; // LSB first.
	union {
		struct {
			unsigned char start_index;
			unsigned char number; // How many entries to query
		} list;
		struct {
			unsigned short service;
		} open;
		struct {
			unsigned char data[SKS_MAX_BUFSIZE]; // Data. Length calaculated from packet length
		} data;
	} d;
};

struct sks_tx {
	unsigned char error;
	unsigned char window[2]; // LSB first - this is our side's receiver window
	union {
		struct {
			unsigned char number; // Number of entries returned
			struct {
				char sks_name[16];
				unsigned char sks_type; // From the enum
			} entries[SKS_MAX_SERVICES];
		} list;
		struct {
			unsigned char data[SKS_MAX_BUFSIZE]; // Data // Length calculated from packet length
		} data;
	} d;
};

int sks_initialize(unsigned char net, unsigned char stn, char *config)
{
	unsigned short server;
	char sks_name[16], sks_type[5], data1[1024];
	unsigned short data2;
	char tmp[1024]; // Temp string holder
	unsigned short ptr, service;
	unsigned short mustlogin;

	server = sks_max + 1;

	if (!sks_quiet) fprintf(stderr, "  SKS: Attempting to initialize server %d on %3d.%3d\n", server, net, stn);

	sks_servers[server].net = net;
	sks_servers[server].stn = stn;

	// Parse the config
	// It will be one string SERVICENAME:type{ssh/tcp/file}:{hostname or filename}[:portnumber],next one - no spaces
	
	ptr = 0; // Pointer into config string
	service = 0; // Next service to create

	while (ptr < strlen(config))
	{

		unsigned short dptr; // Pointer into whichever variable we're reading to at the time. We use data3 as a string holder for 
		
		dptr = 0;

		mustlogin = 0;

		// Zero out the struct
		memset (&(sks_servers[server].info[service]), 0, sizeof(struct sks_server));

		sks_servers[server].info[service].max_conns = 1; 

		if ((*(config+ptr)) == '*')
		{
			mustlogin = 1;
			ptr++;
		}

		if ((*(config+ptr)) == '+') // Set max users (otherwise 1)
		{
			char number[4];
			unsigned short counter, max;

			ptr++; // Skip the +

			counter = 0;

			while (counter < 3 && (isdigit(*(config+ptr))))
				number[counter++] = *(config+(ptr++));

			number[counter] = '\0';

			max = atoi(number);

			if (counter == 0)
			{
				fprintf (stderr, "  SKS: Bad config line %s - no numbers after +\n", config);
				return -1;
			}
			else if (max > SKS_MAX_CONNECTIONS)
			{
				fprintf (stderr, "  SKS: Bad config line %s - max service connections is %d\n", config, SKS_MAX_CONNECTIONS);
				return -1;
			}
			else sks_servers[server].info[service].max_conns = max;
			
		}

		while ((*(config+ptr) != ':') && dptr < 16)
		{
			sks_name[dptr] = *(config+ptr);
			ptr++; dptr++;
		}

		if (*(config+ptr) != ':')
		{
			fprintf (stderr, "  SKS: Bad config line %s\n", config);
			return -1;
		}

		sks_name[dptr] = '\0';

		//fprintf (stderr, "Found service name %s\n", sks_name);

		ptr++;

		dptr = 0;

		while ((*(config+ptr) != ':') && dptr < 5)
		{
			sks_type[dptr] = *(config+ptr);
			ptr++; dptr++;
		}

		if (*(config+ptr) != ':')
		{
			fprintf (stderr, "  SKS: Bad config line %s\n", config);
			return -1;
		}

		sks_type[dptr] = '\0';

		//fprintf (stderr, "Found service type %s\n", sks_type);

		ptr++;

		dptr = 0;

		while ((*(config+ptr) != ':') && (*(config+ptr) != ',') && dptr < 1024)
		{
			data1[dptr] = *(config+ptr);
			ptr++; dptr++;
		}

		if ((*(config+ptr) != ':') && (*(config+ptr) != ',') && (ptr < strlen(config)))
		{
			fprintf (stderr, "  SKS: Bad config line %s\n", config);
			return -1;
		}

		data1[dptr] = '\0';

		//fprintf (stderr, "Found data1 = %s\n", data1);
	
		if (*(config+ptr) != ',') ptr++;

		if (ptr < strlen(config) && *(config+ptr-1) != ',') // Entry with final port number
		{

			dptr = 0;

			while ((*(config+ptr) != ',') && dptr < 1024)
			{
				tmp[dptr] = *(config+ptr);
				ptr++; dptr++;
			}
	
			if ((*(config+ptr) != ',') && (ptr < strlen(config)))
			{
				fprintf (stderr, "  SKS: Bad config line %s\n", config);
				return -1;
			}

			tmp[dptr] = '\0';

			data2 = atoi(tmp);
		}
		else	data2 = 0;

		//fprintf (stderr, "Found data2 = %d\n", data2);

		sks_servers[server].info[service].must_login = mustlogin; 

		if (!strcasecmp(sks_type, "tcp"))
		{
			sks_servers[server].info[service].sks_type = SKS_TCP;
			strcpy(sks_servers[server].info[service].sks_name, sks_name);
			strcpy(sks_servers[server].info[service].sks_data.tcpopts.hostname, data1);
			sks_servers[server].info[service].sks_data.tcpopts.port = data2;
			service++;
		}
		else if (!strcasecmp(sks_type, "ssh"))
		{
#ifndef SKS_SSH_ENABLED
			fprintf (stderr, "  SKS: No SSH support - bad config line %s\n", config);
			return -1;
#else
			sks_servers[server].info[service].sks_type = SKS_SSH;
			strcpy(sks_servers[server].info[service].sks_name, sks_name);
			strcpy(sks_servers[server].info[service].sks_data.sshopts.hostname, data1);
			sks_servers[server].info[service].sks_data.sshopts.port = data2;
			service++;
#endif
		}
		else if (!strcasecmp(sks_type, "file"))
		{
			sks_servers[server].info[service].sks_type = SKS_FILE;
			strcpy(sks_servers[server].info[service].sks_name, sks_name);
			strcpy(sks_servers[server].info[service].sks_data.fileopts.filename, data1);
			service++;
		}
		else
		{
			fprintf (stderr, "  SKS: Unknown service type %s\n", sks_type);
			return -1;
		}


		ptr++;
	}
	
// Dump harness
	if (!sks_quiet)
	{

		short counter;

		for (counter = 0; counter < service; counter++)
		{
			fprintf (stderr, "  SKS: - service %02d (%s) is type %02X (%s), ", counter, sks_servers[server].info[counter].sks_name,
							sks_servers[server].info[counter].sks_type,
							(sks_servers[server].info[counter].sks_type == SKS_TCP ? "tcp" :
							 	sks_servers[server].info[counter].sks_type == SKS_SSH ? "ssh" : "file"));
			switch (sks_servers[server].info[counter].sks_type)
			{
				case SKS_TCP:
					fprintf (stderr, "%s:%d", sks_servers[server].info[counter].sks_data.tcpopts.hostname,
							sks_servers[server].info[counter].sks_data.tcpopts.port);
					break;
				case SKS_SSH:
					fprintf (stderr, "%s", sks_servers[server].info[counter].sks_data.sshopts.hostname);
					break;
				case SKS_FILE:
					fprintf (stderr, "pathname %s", sks_servers[server].info[counter].sks_data.fileopts.filename);
					break;
			}
	
			fprintf (stderr, " (%s)", (sks_servers[server].info[counter].must_login ? "Must log in" : "Open"));
			if (sks_servers[server].info[counter].max_conns > 1) fprintf (stderr, " (max. %d)", sks_servers[server].info[counter].max_conns);
			fprintf (stderr, "\n");
		}

	}

	if (!sks_quiet) fprintf (stderr, "  SKS: Server %d successfully initialised on %3d.%3d\n", server, net, stn);

	sks_servers[server].services = service;

	return ++sks_max; // Success because always > 0

}

int sks_aun_send (struct sks_tx *t, int server, unsigned short length, unsigned char port, unsigned char net, unsigned char stn)
{

	struct __econet_packet_udp p;
	unsigned short service, index, window;

	p.p.ptype = ECONET_AUN_DATA;
	p.p.port = port;
	p.p.ctrl = 0x80; // Always
	p.p.pad = 0x00;
	p.p.seq = 0x00004000; // We need to have a consistent sequence number across PS, FS, SKS.

	// Insert window if station is connected, otherwise 0

	if (sks_active_connection(server, net, stn, &service, &index, &window))
	{
		t->window[0] = window & 0xff;
		t->window[1] = (window & 0xff00) >> 8;
	}
	else
		t->window[0] = t->window[1] = 0;

	memcpy (p.p.data, t, length);

	return aun_send (&p, 8+length, sks_servers[server].net, sks_servers[server].stn, net, stn);

}

unsigned short sks_is_logged_in(int server, unsigned char net, unsigned char stn)
{
	int fserver;
	
	fserver = fs_get_server_id(sks_servers[server].net, sks_servers[server].stn);

	if (fserver < 0) // We are not a fileserver, so the station cannot be logged into us
		return 0;

	else return fs_stn_logged_in(fserver, net, stn);
}

unsigned short sks_active_connection(int server, unsigned char net, unsigned char stn, unsigned short *service, unsigned short *connection, unsigned short *windowsize)
{

	unsigned short service_counter, connection_counter, found;

	service_counter = connection_counter = 0;
	found = 0;

	while (service_counter < SKS_MAX_SERVICES && connection_counter < SKS_MAX_CONNECTIONS && !found)
	{
		if (sks_servers[server].info[service_counter].user_nets[connection_counter] == net && 
		    sks_servers[server].info[service_counter].user_stns[connection_counter] == stn)
			found++;
		else	
		{
			connection_counter++;
			if (connection_counter == SKS_MAX_CONNECTIONS)
				service_counter++;
			connection_counter %= SKS_MAX_CONNECTIONS;
		}
				
	}

	*service = (found ? service_counter : 0);
	*connection = (found ? connection_counter : 0);
	*windowsize = (found ? sks_servers[server].info[*service].user_local_win[*connection] : 0);

	return found;

}

void sks_nop(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int window)
{
	struct sks_tx tx;

	if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d NOP, window %04X\n", "", net, stn, window);

	tx.error = SKS_UNKNOWN;
	sks_aun_send(&tx, server, 3, reply_port, net, stn); // 3 because there is always at least 2 bytes for windowsize...


}

void sks_list (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{

	struct sks_tx tx;
	unsigned short counter, ptr;
	unsigned short service, index, window;

	ptr = 0;
	tx.error = SKS_SUCCESS;

	if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d LIST services from %d, number %d\n", "", net, stn, rx->d.list.start_index, rx->d.list.number);

	// If active user, replace with our local window size
	if (sks_active_connection(server, net, stn, &service, &index, &window))
	{
		tx.window[0] = sks_servers[server].info[service].user_local_win[index] & 0xff;
		tx.window[1] = (sks_servers[server].info[service].user_local_win[index] & 0xff00) >> 8;
		// Update incoming window - TODO.
	}
	
	ptr = rx->d.list.start_index;
	counter = 0;

	while (ptr < sks_servers[server].services && counter < rx->d.list.number) // ptr is beneath the total number of services, and we have copied less than the required number of services. NB .services = 0 means no services, so this is right
	{
		strcpy(tx.d.list.entries[counter].sks_name, sks_servers[server].info[ptr].sks_name);
		tx.d.list.entries[counter].sks_type = sks_servers[server].info[ptr].sks_type;
		counter++; ptr++;
	}
	
	tx.d.list.number = counter;

	sks_aun_send(&tx, server, 3 + 1 + (counter * 17), rx->reply_port, net, stn);
}

// The silent close, used by sks_close and sks_open
void sks_close_internal (int server, unsigned short service, unsigned short connection)
{
	switch (sks_servers[server].info[service].sks_type)
	{
		case SKS_TCP:
			break;
		
		case SKS_FILE:
			fclose(sks_servers[server].info[service].handles[connection].fhandle);
			break;

#ifdef SKS_SSH_ENABLED
		case SKS_SSH:
			libssh2_session_disconnect(sks_servers[server].info[service].handles[connection].ssh_session, "Remote requested disconnection");
			break;
#endif
	}

	sks_servers[server].info[service].user_nets[connection] = sks_servers[server].info[service].user_stns[connection] = 0;

	return;
}

void sks_close (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{
	unsigned short service, connection, window;
	struct sks_tx tx;

	// First, find if we are connected at all

	if (sks_active_connection(server, net, stn, &service, &connection, &window))
		sks_close_internal(server, service, connection);

	tx.error = SKS_SUCCESS;
	sks_aun_send(&tx, server, 3, rx->reply_port, net, stn);

}

void sks_open (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{

	struct sks_tx tx;

	unsigned short service, connection, window;
	unsigned short req_service;

	req_service = rx->d.open.service;
	
	if (sks_active_connection(server, net, stn, &service, &connection, &window))
	{
		// Disconnect existing service
		sks_close_internal (server, net, stn);

	}

	if (req_service > sks_servers[server].services) // Not a known service
	{
		tx.error = SKS_NOSUCHSERVICE;
		sks_aun_send(&tx, server, 3, rx->reply_port, net, stn);
		return;
	}

	if (sks_servers[server].info[connection].must_login && !sks_is_logged_in(server, net, stn)) // Requires login, but not logged in
	{
		tx.error = SKS_NOTLOGGEDIN;
		sks_aun_send(&tx, server, 3, rx->reply_port, net, stn);
		return;
	}
	
}

void sks_data (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{

}

// Looks for traffic on our connections and spits it out to stations if possible, within their advertised window (and decrements window
// as need be)

void sks_poll(int server)
{

}

void sks_handle_traffic(int server, unsigned char net, unsigned char stn, unsigned char ctrl, char *data, unsigned short datalen)
{
	struct sks_rx *rx;
	struct sks_tx tx;
	unsigned int window;

	rx = (struct sks_rx *) data;

	window = (*(data+2) & 0xff) + ((*(data+3) & 0xff) << 8);

	switch (rx->func)
	{
		case SKS_NOP:	sks_nop(server, rx->reply_port, net, stn, window); break;
		case SKS_LIST:
				sks_list(server, net, stn, rx);
				break;
		case SKS_OPEN:
				sks_open(server, net, stn, rx);
				break;
		case SKS_CLOSE:
				sks_close(server, net, stn, rx);
				break;
		case SKS_DATA:
				sks_data(server, net, stn, rx);
				break;
		default:
				// Unknown function
				tx.error = SKS_UNKNOWN;
				sks_aun_send(&tx, server, 3, rx->reply_port, net, stn);
				break;
	}

	return;


}
