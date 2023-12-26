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

char buffer[32768];
int bufferlen;
uint32_t dest_address;

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

			p.p.dststn = stn;
			p.p.dstnet = net;
			p.p.aun_ttype = ECONET_AUN_DATA; // Special funky immediate 0x85
			p.p.port = 0x00;
			p.p.ctrl = 0x82;
			// data[0] - 4 byte poke start address, data[4] = 4 byte poke end address+1, data[8] = data 
			p.p.data[0] = dest_address & 0xff;
			p.p.data[1] = (dest_address & 0xff00 ) >> 8;
			p.p.data[2] = (dest_address & 0xff0000 ) >> 16;
			p.p.data[3] = (dest_address & 0xff000000 ) >> 24;
			dest_address += bufferlen;
			p.p.data[4] = dest_address & 0xff;
			p.p.data[5] = (dest_address & 0xff00 ) >> 8;
			p.p.data[6] = (dest_address & 0xff0000 ) >> 16;
			p.p.data[7] = (dest_address & 0xff000000 ) >> 24;
			memcpy(&(p.p.data[8]), buffer, bufferlen);
			pipeeg_aun_send(&p, 8+bufferlen);
	}
	else
		fprintf (stderr, "Station %d.%d not present\n", net, stn);


}

void main(int argc, char **argv)
{

	int opt, initialized = 0;

	net = 0;

	while ((opt = getopt(argc, argv, "n:p:hqs:f:a:")) != -1)
	{
		switch (opt) {
			case 'h':
				fprintf (stderr, " \n\
Copyright (c) 2023 Chris Royle\n\
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
\t-f <filename>\tFile of data to poke\n\
\t-a <address>\tHex address to poke to in remote machine - e.g. -a 2000 pokes to &2000\n\
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
			case 'a':
				if (sscanf(optarg, "%x", &dest_address) != 1)
				{
					fprintf (stderr, "Bad destination address %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				initialized++;
				break;
			case 'f': // Filename to send
				if (strlen(optarg) > 254)
				{
					fprintf (stderr, "Filename too long - maximum 254 characters.\n");
					exit(EXIT_FAILURE);
				}
				snprintf(text, 254, "%s", optarg);
				initialized++;
				break;
		}
	}

	if (initialized < 4)
	{
		fprintf (stderr, "Must specify -p to identify the named pipe to be used, -s for destination and -f for file contents to send and -a for destination address.\n");
		exit(EXIT_FAILURE);
	}

	if (econet_openreader())
	{
	
		FILE *datahandle;

		if (!(datahandle = fopen(text, "r")))
		{
			fprintf (stderr, "Cannot open %s\n", text);
			exit(EXIT_FAILURE);
		}

		bufferlen = fread(&buffer, 1, 32768, datahandle);

		fclose(datahandle);

		fprintf(stderr, "Read %d bytes to send\n", bufferlen);

		if (bufferlen == 0)
		{
			fprintf(stderr, "Zero-length file. Aborting.\n");
			exit(EXIT_FAILURE);
		}

		fprintf (stderr, "Attempting to send &%04X bytes to address &%08X at %d.%d\n", bufferlen, dest_address, net, stn);

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
