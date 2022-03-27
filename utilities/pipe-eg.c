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
	Example of how to talk to the Econet bridge over a named pipe
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

int pipeeg_aun_send(struct __econet_packet_aun *p, int len)
{
	if (noisy) econet_dump (p, len, 0);
	return aun_send (p, len+12);
}

// Handle an immediate
void econet_immediate(struct __econet_packet_aun *p, int len)
{

	struct __econet_packet_aun r; // Reply

	switch (p->p.ctrl)
	{
		case 0x88: // Machine type
			r.p.port = 0x00;
			r.p.ctrl = 0x88;
			r.p.dststn = p->p.srcstn;
			r.p.dstnet = p->p.srcnet;
			r.p.aun_ttype = ECONET_AUN_IMMREP;
			r.p.data[0] = 0xEE;
			r.p.data[1] = 0xEF;
			r.p.data[2] = 0x01;
			r.p.data[3] = 0x00;
			aun_send (&r, 12+4);
			break;

	}

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
		if (noisy) fprintf (stderr, "No bridge reply received (assuming single local network\n");
	
	while (1)
	{
		if (econet_poll(1000)) // Impose 1 second loops
		{
			int len;
			
			len = aun_read(&p);

			len -= 12; // make this data length

			if (noisy) econet_dump(&p, len, 1);

			if (p.p.aun_ttype == ECONET_AUN_IMM && p.p.port == 0x00) // Immediate
				econet_immediate(&p, len);
			if (p.p.port == 0x99) // Fileserver port - spoof a reply to FS type
			{
				switch (p.p.data[1])
				{
					case 0x19: // FS Type
					{
						char fsver[100];

						p.p.aun_ttype = ECONET_AUN_DATA;
						p.p.port = p.p.data[0]; // Reply port
						p.p.ctrl = 0x80;
						p.p.dststn = p.p.srcstn;
						p.p.dstnet = p.p.srcnet;
						p.p.data[0] = p.p.data[1] = 0x00;
						snprintf(fsver, 99, "PiEconetBridge NPC 1.0%c", 0x0d);
						strcpy(&(p.p.data[2]), fsver);
						pipeeg_aun_send(&p, strlen(fsver)+2);
					} break;

				}
			}
			

		}

	}

}

void main(int argc, char **argv)
{

	int opt, initialized = 0;

	while ((opt = getopt(argc, argv, "p:hq")) != -1)
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
\t-p <base path>\tBase path (excluding tobridge/frombridge) of named pipe to join\n\
\t-q\tQuiet mode - no packet dumps or other unnecessary output\n\
\n\
", argv[0]);
				break;
			case 'p':
				econet_setbase(optarg);
				initialized++;
				break;
			case 'q': // Quiet
				noisy = 0;
				break;
		}
	}

	if (!initialized)
	{
		fprintf (stderr, "Must specify -p to identify the named pipe to be used.\n");
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
