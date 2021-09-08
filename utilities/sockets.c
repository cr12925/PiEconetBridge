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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libgen.h>
#include "../include/econet-gpio-consumer.h"

#define SKS_PORT 0xDF // Econet Port number

extern int fs_get_server_id(unsigned char, unsigned char);
extern int fs_stn_logged_in(int, unsigned char, unsigned char);
extern int get_local_seq(unsigned char, unsigned char);
extern int aun_send (struct __econet_packet_aun *, int);

unsigned short sks_active_connection(int, unsigned char, unsigned char, unsigned short *, unsigned short *, unsigned short *, unsigned short *);

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
	SKS_PIPE,
	SKS_FILE
};

struct sks_server {
	unsigned short sks_type; // One of sks_types
	char sks_name[16]; // Service name
	union {
		struct {
			char hostname[1024];
			char port[128];
		} tcpopts;
		struct {
			char command[1024];
		} pipeopts;
		struct {
			char filename[1024];
		} fileopts;
	} sks_data;
	unsigned short max_conns; 
	unsigned char must_login; // non-zero if config requires user to be logged in
	unsigned short user_nets[SKS_MAX_CONNECTIONS], user_stns[SKS_MAX_CONNECTIONS]; // net, stn & mode of each live connection. 0,0,0 = unused
	unsigned char user_tx_buffers[SKS_MAX_CONNECTIONS][SKS_MAX_BUFSIZE];
	unsigned char user_rx_buffers[SKS_MAX_CONNECTIONS][SKS_MAX_BUFSIZE];
	unsigned short user_remote_win[SKS_MAX_CONNECTIONS], user_remote_ack[SKS_MAX_CONNECTIONS]; // last advertised available bytes in remote receiver buffer
	unsigned short user_local_win[SKS_MAX_CONNECTIONS], user_local_ack[SKS_MAX_CONNECTIONS]; // number of available bytes in tx buffer for this user
	union {
		int socket; // For TCP and pipes
		FILE *fhandle; // For files
		struct {
			int bridge_reader[2];
			int bridge_writer[2];
		} pipe;
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
	unsigned char window[2]; // LSB first. Maximum byte in stream remote can accept - if would be greater than &FFFF, will send &FFFF receipt acknowledged, then wrap to &0 onwards
	unsigned char ack[2]; // LSB first. Last byte in stream received. 
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
	unsigned char window[2]; // LSB first - this is our side's receiver window - maximum byte number in stream we can accept. Same semantics as for the other end (see above)
	unsigned char ack[2]; // LSB first - this is the byte in the stream we acknowledge having received - &0 means nothing received.
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
	char sks_name[16], sks_type[5], data1[1024], data2[128];
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

			strcpy(data2, tmp);
		}
		else	strcpy(data2, "");

		//fprintf (stderr, "Found data2 = %d\n", data2);

		sks_servers[server].info[service].must_login = mustlogin; 

		if (!strcasecmp(sks_type, "tcp"))
		{
			sks_servers[server].info[service].sks_type = SKS_TCP;
			strcpy(sks_servers[server].info[service].sks_name, sks_name);
			strcpy(sks_servers[server].info[service].sks_data.tcpopts.hostname, data1);
			if (!strcmp(data2, "")) // Blank
				strcpy(data2, "echo"); // People should soon figure out what's up with their config....
			strcpy(sks_servers[server].info[service].sks_data.tcpopts.port, data2);
			service++;
		}
		else if (!strcasecmp(sks_type, "pipe"))
		{
			sks_servers[server].info[service].sks_type = SKS_PIPE;
			strcpy(sks_servers[server].info[service].sks_name, sks_name);
			strcpy(sks_servers[server].info[service].sks_data.pipeopts.command, data1);
			service++;
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
							 	sks_servers[server].info[counter].sks_type == SKS_PIPE ? "pipe" : "file"));
			switch (sks_servers[server].info[counter].sks_type)
			{
				case SKS_TCP:
					fprintf (stderr, "%s:%s", sks_servers[server].info[counter].sks_data.tcpopts.hostname,
							sks_servers[server].info[counter].sks_data.tcpopts.port);
					break;
				case SKS_PIPE:
					fprintf (stderr, "%s", sks_servers[server].info[counter].sks_data.pipeopts.command);
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

	struct __econet_packet_aun p;
	unsigned short service, index, window, ack;

	p.p.aun_ttype = ECONET_AUN_DATA;
	p.p.port = port;
	p.p.ctrl = 0x80; // Always
	p.p.padding = 0x00;
	p.p.seq = get_local_seq(sks_servers[server].net, sks_servers[server].stn); 

	p.p.srcnet = sks_servers[server].net;
	p.p.srcstn = sks_servers[server].stn;
	p.p.dstnet = net;
	p.p.dststn = stn;

	// Insert window if station is connected, otherwise 0

	if (sks_active_connection(server, net, stn, &service, &index, &window, &ack))
	{
		t->window[0] = window & 0xff;
		t->window[1] = (window & 0xff00) >> 8;
		t->ack[0] = ack & 0xff;
		t->ack[1] = (ack & 0xff00) >> 8;
	
	}
	else
		t->window[0] = t->window[1] = t->ack[0] = t->ack[1] = 0;

	memcpy (p.p.data, t, length);

	return aun_send (&p, 12+length);

}

unsigned short sks_is_logged_in(int server, unsigned char net, unsigned char stn)
{
	int fserver;
	
	fserver = fs_get_server_id(sks_servers[server].net, sks_servers[server].stn);

	if (fserver < 0) // We are not a fileserver, so the station cannot be logged into us
		return 0;

	else return fs_stn_logged_in(fserver, net, stn);
}

unsigned short sks_active_connection(int server, unsigned char net, unsigned char stn, unsigned short *service, unsigned short *connection, unsigned short *windowsize, unsigned short *ack)
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
	*ack = (found ? sks_servers[server].info[*service].user_local_ack[*connection] : 0);

	return found;

}

void sks_nop(int server, unsigned char reply_port, unsigned char net, unsigned char stn, unsigned int window, unsigned int ack)
{
	struct sks_tx tx;

	if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d NOP, window %04X\n", "", net, stn, window);

	tx.error = SKS_SUCCESS;
	sks_aun_send(&tx, server, 5, reply_port, net, stn); // 3 because there is always at least 2 bytes for windowsize...

}

void sks_list (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{

	struct sks_tx tx;
	unsigned short counter, ptr;
	unsigned short service, index, window, ack;

	ptr = 0;
	tx.error = SKS_SUCCESS;

	if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d LIST services from %d, number %d\n", "", net, stn, rx->d.list.start_index, rx->d.list.number);

	// If active user, replace with our local window size
	if (sks_active_connection(server, net, stn, &service, &index, &window, &ack))
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

	sks_aun_send(&tx, server, 5 + 1 + (counter * 17), rx->reply_port, net, stn);
}

// The silent close, used by sks_close and sks_open
void sks_close_internal (int server, unsigned short service, unsigned short connection)
{
	switch (sks_servers[server].info[service].sks_type)
	{
		case SKS_TCP:
			close(sks_servers[server].info[service].handles[connection].socket);
			break;
		case SKS_FILE:
			fclose(sks_servers[server].info[service].handles[connection].fhandle);
			break;
		case SKS_PIPE:
			close(sks_servers[server].info[server].handles[connection].pipe.bridge_reader[0]);
			close(sks_servers[server].info[server].handles[connection].pipe.bridge_writer[1]);
			break;
	}

	sks_servers[server].info[service].user_nets[connection] = sks_servers[server].info[service].user_stns[connection] = 0;

	return;
}

void sks_close (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{
	unsigned short service, connection, window, ack;
	struct sks_tx tx;

	// First, find if we are connected at all

	if (sks_active_connection(server, net, stn, &service, &connection, &window, &ack))
		sks_close_internal(server, service, connection);

	tx.error = SKS_SUCCESS;
	sks_aun_send(&tx, server, 5, rx->reply_port, net, stn);

}

void sks_open (int server, unsigned char net, unsigned char stn, struct sks_rx *rx)
{

	struct sks_tx tx;

	unsigned short service, connection, window, ack;
	unsigned short req_service;
	unsigned short counter;

	req_service = rx->d.open.service;
	
	if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Open service %d\n", "", net, stn, req_service);

	if (sks_active_connection(server, net, stn, &service, &connection, &window, &ack))
	{
		if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Closing existing connection\n", "", net, stn);
		// Disconnect existing service
		sks_close_internal (server, net, stn);
	}

	if (req_service > sks_servers[server].services) // Not a known service
	{
		if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - no such service\n", "", net, stn);
		tx.error = SKS_NOSUCHSERVICE;
		sks_aun_send(&tx, server, 5, rx->reply_port, net, stn);
		return;
	}

	if (sks_servers[server].info[connection].must_login && !sks_is_logged_in(server, net, stn)) // Requires login, but not logged in
	{
		if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - not logged in\n", "", net, stn);
		tx.error = SKS_NOTLOGGEDIN;
		sks_aun_send(&tx, server, 5, rx->reply_port, net, stn);
		return;
	}
	
	// Find a spare connection if there is one

	counter = 0;

	while ((counter < sks_servers[server].info[req_service].max_conns) &&
			((sks_servers[server].info[req_service].user_nets[counter] != 0) || (sks_servers[server].info[req_service].user_stns[counter] != 0))
		)
		counter++;

	if (counter == sks_servers[server].info[req_service].max_conns) // No space here
	{
		tx.error = SKS_SERVICEBUSY;
		if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - maximum connections reached - service busy\n", "", net, stn);
		sks_aun_send(&tx, server, 5, rx->reply_port, net, stn);
                return;
	}

	// Attempt to open service - set req_service = 0xffff as a rogue for failure

	switch (sks_servers[server].info[req_service].sks_type)
	{
		case SKS_TCP:
		{
			int sockfd, ai;
			struct addrinfo hints, *result, *rp;

			bzero (&hints, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = AF_INET;
			hints.ai_family = AF_INET;

			ai = getaddrinfo(sks_servers[server].info[req_service].sks_data.tcpopts.hostname,
				sks_servers[server].info[req_service].sks_data.tcpopts.port,
				&hints,
				&result);	
			
			if (ai != 0) // failed
			{
				if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - Address lookup for TCP connection failed (%s:%s)\n", "", net, stn, sks_servers[server].info[req_service].sks_data.tcpopts.hostname, sks_servers[server].info[req_service].sks_data.tcpopts.port);
				req_service = 0xffff;
			}
			else
			{
				for (rp = result; rp != NULL; rp = rp->ai_next)
				{
					sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

					if (sockfd == -1) continue;

					if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
						break; // connected	

					close(sockfd); // Close this one, have another go.
					
				}
		
				freeaddrinfo(result); // Finished with that.

				if (rp == NULL) // Nothing connected
				{
					if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - socket creation failed\n", "", net, stn);
					req_service = 0xffff;
				}
				else // Succeeded - set up the user state
				{
					sks_servers[server].info[req_service].handles[counter].socket = sockfd;
					sks_servers[server].info[req_service].user_remote_win[counter] = 0;
					sks_servers[server].info[req_service].user_remote_ack[counter] = 0;
					sks_servers[server].info[req_service].user_local_win[counter] = SKS_MAX_BUFSIZE;
					sks_servers[server].info[req_service].user_local_ack[counter] = 0;
					sks_servers[server].info[req_service].user_nets[counter] = net;
					sks_servers[server].info[req_service].user_stns[counter] = stn;
				}	
			}

		}
			break;
		
		case SKS_FILE:
			if (!(sks_servers[server].info[req_service].handles[connection].fhandle = fopen(sks_servers[server].info[req_service].sks_data.fileopts.filename, "r+")))
			{
				if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - cannot open file %s\n", "", net, stn, sks_servers[server].info[req_service].sks_data.fileopts.filename);
				req_service = 0xffff; // Failure
			}
			break;

		case SKS_PIPE: // This needs to be updated to use exec...() functions to avoid manipulation of user environment - see popen man page. TODO.
		{
			int p2r, p2w;

			p2r = pipe2(sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader, O_NONBLOCK);
			p2w = pipe2(sks_servers[server].info[req_service].handles[counter].pipe.bridge_writer, O_NONBLOCK);

			if ((p2r == -1) || (p2w == -1))
			{
				 if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - cannot open pipes\n", "", net, stn);
				req_service = 0xffff;
			}
			else
			{
				
				int childpid;

				if ((childpid = fork()) == -1)
				{
					close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader[0]);
					close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader[1]);
					close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_writer[0]);
					close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_writer[1]);
				 	if (!sks_quiet) fprintf (stderr, "  SKS:%12sfrom %3d.%3d Cannot open - cannot fork child process\n", "", net, stn);
					req_service = 0xffff;
				}
				else
				{
					if (childpid == 0) // child
					{
						char *base;

						close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader[0]);
						close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_writer[1]);
						// Probably need to close all our other descriptors here - UDP, etc. etc.
						dup2(0, sks_servers[server].info[req_service].handles[counter].pipe.bridge_writer[0]);
						dup2(1, sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader[1]);
						dup2(2, sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader[1]);

						base = basename(sks_servers[server].info[req_service].sks_data.pipeopts.command);

						execl(sks_servers[server].info[req_service].sks_data.pipeopts.command, base, NULL);

						// Should never get here. If we do, exit.
		
						exit(EXIT_SUCCESS);
					}
					else // parent
					{
						close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_reader[1]);
                                                close (sks_servers[server].info[req_service].handles[counter].pipe.bridge_writer[0]);
						// All ready, unless the exec in the child failed, in which case hopefully we'll detect that on sks_poll() or sks_data(), if we haven't run out of talent by then....
					}
				}
	
			}
		}
		break;
	}

	if (req_service == 0xffff) // Connection failed
		tx.error = SKS_CANNOTOPEN;
	else
		tx.error = SKS_SUCCESS; // Successful open
	
	// Tell the station
	sks_aun_send(&tx, server, 5, rx->reply_port, net, stn);

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
	unsigned int window, ack;

	rx = (struct sks_rx *) data;

	window = (*(data+2) & 0xff) + ((*(data+3) & 0xff) << 8);
	   ack = (*(data+4) & 0xff) + ((*(data+5) & 0xff) << 8);

	switch (rx->func)
	{
		case SKS_NOP:	sks_nop(server, rx->reply_port, net, stn, window, ack); break;
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
				sks_aun_send(&tx, server, 5, rx->reply_port, net, stn);
				break;
	}

	return;


}
