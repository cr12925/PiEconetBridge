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
	*NOTIFY via a named pipe
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

//  Necessary variables for the pipe library
uint32_t seq = 0x4000; // Starting AUN sequence number

int tobridge, frombridge; // Descriptors

char pipebase[256]; // Starting path to pipe. We append 'frombridge' and 'tobridge'

extern void econet_setbase(char *);
extern int econet_openreader();
extern int econet_openwriter();
extern int aun_send (struct __econet_packet_aun *, int);
extern int aun_read (struct __econet_packet_aun *);
extern int econet_poll(int);
extern void econet_dump (struct __econet_packet_aun *, int, uint8_t);

uint8_t noisy = 1; // Packet stuff
uint8_t localnet = 0, distantnet = 0; // local net = the number associated with our local network, distantnet is the network notionally on the other side of the bridge (in Pi world, there may be several)

char dest[10], text[255];
uint8_t net, stn;

int pipeeg_aun_send(struct __econet_packet_aun *p, int len)
{
	if (noisy) econet_dump (p, len, 0);
	return aun_send (p, len+12);
}

int econet_ispresent(uint8_t net, uint8_t stn)
{

	int result = 0;
	struct __econet_packet_aun p;
	int len;

	p.p.aun_ttype = ECONET_AUN_IMM;
	p.p.port = 0x00;
	p.p.ctrl = 0x88;
	p.p.dststn = stn;
	p.p.dstnet = net;
	p.p.data[0] = p.p.data[1] = p.p.data[2] = p.p.data[3] = 0;

	pipeeg_aun_send(&p, 4);

	if (econet_poll(500))
	{
		// Assume we got an answer
		result = 1;

	}
	
	return result;

}

// Main loop here
void econet_pipeeg_run(void)
{

	struct __econet_packet_aun p;

	// First, we need to send something on the pipe, because it will wake the bridge up and it'll open
	// it's writer socket to us. Let's try a bridge broadcast. Also it might generate something 
	// back to us that we can display.

	p.p.dststn = p.p.dstnet = 0xff; // Broadcast destination
	// Don't bother setting the source - the bridge will fill it in
	p.p.aun_ttype = ECONET_AUN_BCAST;
	p.p.port = 0x9c; // Bridge
	p.p.ctrl = 0x82; // Ctrl - Local net query
	strncpy(p.p.data, "BRIDGE", 7);
	p.p.data[6] = 0x9c; // Reply port
	p.p.data[7] = 0; // Net being queried

	pipeeg_aun_send (&p, 8);

	if (econet_poll(1000)) // Wait 100ms for a reply to our bridge query. We might not get one, because the bridge might not be bridging to other network numbers
	{
		int len;

		len = aun_read(&p);

		if (len == 14) // Length of a bridge reply
		{
			if (noisy) econet_dump (&p, len-12, 1);
			localnet = p.p.data[0];
			if (noisy) fprintf (stderr, "Network numbers: local %d, distant %d\n", localnet, p.p.srcnet);
		}

	}
	else
		if (noisy) fprintf (stderr, "No bridge reply received (assuming single local network)\n");
	

	// Probe to see if station is present
	if (econet_ispresent(net, stn))
	{
		uint8_t c;

		for (c = 0; c < strlen(text); c++)
		{
			p.p.dststn = stn;
			p.p.dstnet = net;
			p.p.aun_ttype = ECONET_AUN_DATA; // Special funky immediate 0x85
			p.p.port = 0x00;
			p.p.ctrl = 0x85;
			p.p.data[0] = p.p.data[1] = 0x00;
			p.p.data[2] = text[c];
			p.p.data[3] = 0x0f;
			p.p.data[4] = text[c];

			pipeeg_aun_send(&p, 5);

		}
	}
	else
		fprintf (stderr, "Station %d.%d not present\n", net, stn);


}

void main(int argc, char **argv)
{

	int opt, initialized = 0;

	net = 0;

	while ((opt = getopt(argc, argv, "n:p:hqs:t:")) != -1)
	{
		switch (opt) {
			case 'h':
				fprintf (stderr, " \n\
Copyright (c) 2022 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
Usage: %s [options]\n\
\
Options:\n\
\n\
\t-h\tThis help text\n\
\t-n <net>\tNetwork number of destination station (default 0)\n\
\t-p <base path>\tBase path (excluding tobridge/frombridge) of named pipe to join\n\
\t-q\tQuiet mode - no packet dumps or other unnecessary output\n\
\t-s <stn>\tStation number of destination station\n\
\t-t <text>\tText to notify\n\
\n\
", argv[0]);
				break;
			case 'n':
				net = atoi(optarg);
				break;
			case 'p':
				econet_setbase(optarg);
				initialized++;
				break;
			case 'q': // Quiet
				noisy = 0;
				break;
			case 's': 
				stn = atoi(optarg);
				initialized++;
				break;
			case 't': // Text
				snprintf(text, 100, "%c__ %s __", 7, optarg);
				initialized++;
				break;
		}
	}

	if (initialized < 3)
	{
		fprintf (stderr, "Must specify -p to identify the named pipe to be used, -s for destination and -t for text.\n");
		exit(EXIT_FAILURE);
	}

	if (econet_openreader())
	{

		if (econet_openwriter())
		{
			
			econet_pipeeg_run();
			if (noisy) fprintf (stderr, "Exiting\n");
			exit(EXIT_SUCCESS);
		}
		else
		{
			fprintf(stderr, "\nCannot open writing pipe. Exiting.\n");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		fprintf(stderr, "Can't open reading pipe!\n");
		exit(EXIT_FAILURE);
	}	
}
