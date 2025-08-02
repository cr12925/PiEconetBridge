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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
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
#include "../include/econet-gpio-consumer.h"

struct timespec start;
uint8_t timestamps = 0;

int read_wire (int);
int write_wire (short, short, short, short, short, short, char *, int);

void dump_pkt_data(unsigned char *, int, unsigned long);

int econet_fd;
int dumpmode_brief = 0;

// Packet Buffer
struct __econet_packet_wire wire_pkt_rx;

void dump_pkt_data(unsigned char *a, int len, unsigned long start_index)
{
	int count;

	count = 0;
	while (count < len)
	{
		char dbgstr[200];
		char tmpstr[200];
		int z;

		sprintf (dbgstr, "%08x ", count + start_index);
		z = 0;
		while (z < 32)
		{
			if ((count+z) < len)
			{
				sprintf(tmpstr, "%02x ", *(a+count+z)); 
				strcat(dbgstr, tmpstr);
			}
			else	strcat(dbgstr, "   ");
			z++;
		}

		z = 0;
		while (z < 32)
		{
			if ((count+z) < len)
			{
				sprintf(tmpstr, "%c", (*(a+count+z) >= 32 && *(a+count+z) < 127) ? *(a+count+z) : '.');
				strcat(dbgstr, tmpstr);
			}
			z++;
		}

		fprintf(stderr, "%s\n", dbgstr);		

		count += 32;

	}
	if (start_index == 0)
		fprintf (stderr, "%08x --- END ---\n\n", len);
}

/* 
	Dump an Econet packet to stderr

	s = packet length
	d = direction (0 in from somewhere, 1 going out to somewhere)
	a = packet data structure
	medium: 0 = Econet, 1 = UDP RAW
*/
void dump_eco_pkt(int len, struct __econet_packet_wire *a)
{

	int count = 0;
	char bytestream[5*24];
	struct timespec 	t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	if (t.tv_nsec < start.tv_nsec)
	{
		t.tv_sec--;
		t.tv_nsec = (1000000000 - (start.tv_nsec - t.tv_nsec));
	}
	else
		t.tv_nsec -= start.tv_nsec;

	t.tv_sec -= start.tv_sec;

	if (dumpmode_brief)
	{
		if (timestamps) fprintf (stderr, "%02dd:%02dh:%02dm:%02ds.%09d ",
				(t.tv_sec / (24 * 60 * 60)),
				(t.tv_sec % (24 * 60 * 60)) / 3600,
				(t.tv_sec % (3600)) / 60,
				(t.tv_sec % 60),
				t.tv_nsec);

		fprintf (stderr,"%3d.%3d -> ", a->p.srcnet, a->p.srcstn);
		if (a->p.dststn != 0xff) fprintf(stderr, "%3d.%3d ", a->p.dstnet, a->p.dststn);
		else fprintf(stderr, "B'CAST  ");
		fprintf (stderr, " len %04x : ", len);

		if (len > 4)
		{
			for (count = 4; count < ((len > 24) ? 24 : len); count++)
			{
				sprintf(&(bytestream[5*(count-4)]), "%02x %c ", a->data[count],
					(a->data[count] < 'z' && a->data[count] > ' ') ? a->data[count] : '.');
			}
			bytestream[5*((len > 24) ? 24 : len)] = 0;
			fprintf(stderr, "%-s", bytestream);	
		}
	
		fprintf (stderr, "\n");
	}
	else
	{
		if (timestamps) fprintf (stderr, "%02dd:%02dh:%02dm:%02ds.%09d\n",
				(t.tv_sec / (24 * 60 * 60)),
				(t.tv_sec % (24 * 60 * 60)) / 3600,
				(t.tv_sec % (3600)) / 60,
				(t.tv_sec % 60),
				t.tv_nsec);

		fprintf (stderr, "%08x --- PACKET ---\n", len);

		fprintf (stderr, "         DST Net/Stn 0x%02x/0x%02x\n", a->p.dstnet, a->p.dststn);
	
		fprintf (stderr, "         SRC Net/Stn 0x%02x/0x%02x\n", a->p.srcnet, a->p.srcstn);

		dump_pkt_data((unsigned char *) a, len, 0);
	}

}

void econet_usage(char *name)
{

				fprintf(stderr, " \n\
Copyright (c) 2021 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
A utility to monitor an attached Econet\n\
Usage: %s [options] \n\
Options:\n\
\n\
\t-b\tDo brief packet dumps\n\
\t-h\tPrint this help message\n\
\t-t\tAdd timestamps to packets\n\
\n\
\nNote: If not running as root, you must make /dev/econet-gpio\
\nGlobally read/writeable - e.g. sudo chmod a+rw /dev/econet-gpio\
\nor this will not work.\
\n\n\
", name);
	exit (EXIT_FAILURE);

}

void main(int argc, char **argv)
{
	int s;
	int opt;
	
	struct pollfd p;

	clock_gettime(CLOCK_MONOTONIC, &start);

	while ((opt = getopt(argc, argv, "bht")) != -1)
	{
		switch (opt) {
			case 'b': /* Brief Dump mode */
				dumpmode_brief = 1;
				break;
			case 'h':	
				econet_usage(argv[0]); break;
			case 't':
				timestamps = 1; break;
		}
	}

	/* The open() call will do an econet_reset() in the kernel */
	econet_fd = open("/dev/econet-gpio", O_RDWR);

	if (econet_fd < 0)
	{
		fprintf(stderr, "Unable to open econet device. You may need to be root?\n");
		exit (EXIT_FAILURE);
	}

	// Force raw mode (turns off AUN / 4-way handshake handling in the kernel) 

	ioctl(econet_fd, ECONETGPIO_IOC_AUNMODE, 0);

	fprintf(stderr, "Econet Monitor waiting for traffic\n\n");

	p.fd = econet_fd;
	p.events = POLLIN;
	
	s = 0;

	while (poll(&p, 1, -1))
	{
		if ((p.revents & POLLIN) && (s = read(econet_fd, &wire_pkt_rx, sizeof(wire_pkt_rx))) && (s > 0))
			dump_eco_pkt(s, &wire_pkt_rx);
		else break;
		p.events = POLLIN;
	}

	if (s < 0)
	{
		fprintf (stderr, "Read error from network - %d\n", s);
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);

}
