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

/*
 
 This is a short library to enable production of code to talk to the
 Econet bridge on a Raspberry Pi over a named pipe

 Since the named pipes control which station number the client will
 be, there is no sense in which the code knows (or needs to know)
 what station is actually is. All the packet header information in
 that regard is inserted for you. HOWEVER, the bridge-standard
 AUN-extended packets are used (with source/destination net/stn
 included - it's just that the bridge will overwrite any source
 addressing you care to give it.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
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

// Packet buffers

extern uint32_t seq; // Starting AUN sequence number

extern int tobridge, frombridge; // Descriptors

extern char pipebase[256]; // Starting path to pipe. We append 'frombridge' and 'tobridge'

// Packet dump to stderr
void econet_dump(struct __econet_packet_aun *p, int len, uint8_t source)
{

	char srcstr[8];

	if (source) // Not local
		snprintf (srcstr, 8, "%3d.%3d", p->p.srcnet, p->p.srcstn);
	else
		snprintf (srcstr, 8, "-LOCAL-");

	fprintf(stderr, "To %3d.%3d from %7s %3s port 0x%02x ctrl 0x%02x seq 0x%08x data length 0x%04x",
		p->p.dstnet, p->p.dststn,
		srcstr,
		(	p->p.aun_ttype == ECONET_AUN_BCAST ? "BRD" :
			p->p.aun_ttype == ECONET_AUN_IMM ? "IMM" :
			p->p.aun_ttype == ECONET_AUN_IMMREP ? "IMR" :
			p->p.aun_ttype == ECONET_AUN_DATA ? "DAT" : 
			p->p.aun_ttype == ECONET_AUN_ACK ? "ACK" :
			p->p.aun_ttype == ECONET_AUN_NAK ? "NAK" : "UNK" ),
			
		p->p.port, p->p.ctrl,
		p->p.seq,
		len);

	if (len > 0)
	{
		int count;
	
		for (count = 0; count < (len < 8 ? len : 8); count++)
			fprintf (stderr, " %02x %c", p->p.data[count], (p->p.data[count] >= 32 && p->p.data[count] < 125) ? p->p.data[count] : '.');
	}

	fprintf (stderr, "\n");
}

// Initialize pipebase
void econet_setbase(char * base)
{
	strncpy(pipebase, base, 255);
}

// Open reading pipe - returns result of open()
int econet_openreader()
{

	char frompath[300];
	int fd;

	snprintf(frompath, 299, "%s.frombridge", pipebase);

	fd = open(frompath, O_RDONLY | O_NONBLOCK);

/*
	if (fd != -1)
		fprintf (stderr, "Opened reading socket, fd = %d\n", fd);
	else
*/
	if (fd == -1)
	{
		fprintf (stderr, "Failed to open reader socket: %s. Is your bridge running?\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	frombridge = fd;

	return fd;

}

// Open writing pipe - returns result of open()
int econet_openwriter()
{
	char topath[300];
	int fd;

	snprintf(topath, 299, "%s.tobridge", pipebase);

	fd = open(topath, O_WRONLY | O_NONBLOCK | O_SYNC);

/*
	if (fd != -1)
		fprintf (stderr, "Opened writing socket, fd = %d\n", fd);
	else
*/
	if (fd == -1)
	{
		fprintf (stderr, "Failed to open writer socket: %s. Is your bridge running?\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	tobridge = fd;

	return fd;

}

// Send AUN
int aun_send (struct __econet_packet_aun *p, int len)
{
	int r;
	struct __econet_packet_pipe delivery;

	delivery.length_low = (unsigned char) len & 0xff;
	delivery.length_high = (unsigned char) (len >> 8) & 0xff;
	p->p.seq = (seq += 4);
	memcpy (&(delivery.dststn), p, len);
	r = write(tobridge, &delivery, len+2);
	
	if (r > 0) return (r-2); else return r;
}

// Receive AUN
int aun_read (struct __econet_packet_aun *p)
{
	int length;
	struct __econet_packet_pipe arrival;

	read (frombridge, &(arrival.length_low), 1);
	read (frombridge, &(arrival.length_high), 1);
	length = (arrival.length_high << 8) + arrival.length_low;
	read(frombridge, &(arrival.dststn), length);
	memcpy (p, &(arrival.dststn), length);
	return length;

}

// Receive pollwait (waits ms, or if 0 then forever)
int econet_poll(int ms)
{

	struct pollfd p;

	p.events = POLLIN;
	p.revents = 0;
	p.fd = frombridge;

	poll(&p, 1, ms);

	if (p.revents & POLLHUP) // Pipe closed!
	{
		fprintf (stderr, "Bridge has gone away. Exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (p.revents)
		return 1;

	return 0;
}

