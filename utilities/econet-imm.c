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
#include "../include/econet-gpio-consumer.h"

int econet_fd;

// Packet Buffers
struct __econet_packet_wire wire_pkt_rx;
struct __econet_packet_wire wire_pkt_tx;

char * econet_strtxerr(int e)
{
	switch (e * -1)
	{
		case ECONET_TX_JAMMED: return (char *)"Line jammed";
		case ECONET_TX_HANDSHAKEFAIL: return (char *)"Handshake failure";
		case ECONET_TX_NOCLOCK: return (char *)"No clock";
		case ECONET_TX_UNDERRUN: return (char *)"Transmit underrun";
		case ECONET_TX_TDRAFULL: return (char *)"Data register full on tx";
		case ECONET_TX_NOIRQ: return (char *)"No IRQ received to being/continue transmit";
		case ECONET_TX_NOCOPY: return (char *)"Could not copy packet from userspace";
		case ECONET_TX_NOTSTART: return (char *)"Transmission never begun";
		case ECONET_TX_COLLISION: return (char *)"Collision during transmission";
		default: return (char *)"Unknown error";
	}	

}

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
                        else    strcat(dbgstr, "   ");
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
}

void machinepeek(void)
{
	int r;

	wire_pkt_tx.p.ctrl = 0x88;
	
	r = write(econet_fd, &wire_pkt_tx, 6);

	if (r <= 0)
	{
		fprintf(stderr, "Transmit failed: %s (%d).\n", econet_strtxerr(r), r);
		return;
	}

	usleep(10000);

	r = read(econet_fd, &wire_pkt_rx, ECONET_MAX_PACKET_SIZE);

	if (r < 0)
	{
		fprintf(stderr, "Error %d on reading reply\n", r);
	}
	else if (r == 0)
	{
		fprintf(stderr, "read() returned 0 on reading reply\n");
	}
	else
	{
		
		char 		machinetype[60];
	
		unsigned long 	response;

		int 		reply_type, reply_version;

		response = (unsigned long) wire_pkt_rx.data[4]; // Only works on ARM-endian machines

		reply_type = response & 0xffff;
	
		switch (reply_type)
		{
			case 1:	strcpy(machinetype, " BBC Microcomputer"); break;
			case 2:	strcpy(machinetype, " Acorn Atom"); break;
			case 3:	strcpy(machinetype, " Acorn System 3 or 4"); break;
			case 4:	strcpy(machinetype, " Acorn System 5"); break;
			case 5:	strcpy(machinetype, " BBC Master 128 OS 3"); break;
			case 6:	strcpy(machinetype, " Acorn Electron OS 0"); break;
			case 7:	strcpy(machinetype, " Acorn Archimedes OS 6"); break;
			case 8:	strcpy(machinetype, " reserved machien type"); break;
			case 9:	strcpy(machinetype, " Acorn Communicator"); break;
			case 0xa:	strcpy(machinetype, " Master Compact Econet Terminal"); break;
			case 0xb:	strcpy(machinetype, " Acorn Filestore"); break;
			case 0xc:	strcpy(machinetype, " Master Compact OS 5"); break;
			case 0xd:	strcpy(machinetype, " Acorn Ecolink PC"); break;
			case 0xe:	strcpy(machinetype, " Acorn Unix Workstation"); break;
			case 0xf:	strcpy(machinetype, " RISC PC"); break;
			case ADVERTISED_MACHINETYPE: strcpy(machinetype, " Raspberry Pi Econet Bridge"); break;
			case 0xfff8: strcpy(machinetype, " SJ Research GP server"); break;
			case 0xfff9: strcpy(machinetype, " SJ Research 80386 UNIX machine"); break;
			case 0xfffa: strcpy(machinetype, " SCSI Interface"); break;
			case 0xfffb: strcpy(machinetype, " SJ Research IBM PC Econet Interface"); break;
			case 0xfffc: strcpy(machinetype, " Nascom 2"); break;
			case 0xfffd: strcpy(machinetype, " Research Machines 480Z"); break;
			case 0xfffe: strcpy(machinetype, " SJ Research File Server"); break;
			case 0xffff: strcpy(machinetype, " Z80 CP/M machine"); break;
			default: sprintf(machinetype, "n unkown type (%x)", wire_pkt_rx.data[4]); break;
		}

		// NB, the values for the NFS version are actually decimal values, so &0425 means 4.25

		printf("Station reports being a%s, NFS version %x.%x.\n", 
			machinetype, (int) wire_pkt_rx.data[7], wire_pkt_rx.data[6]);

	}
}

// Send peek packet to another machine.

void memorypeek(unsigned long start, unsigned long end)
{
	int 	r;
	int	count;

	wire_pkt_tx.p.ctrl = 0x81;

	for (count = 0; count < 8; count++)	
		wire_pkt_tx.p.data[count] = 0;

	wire_pkt_tx.p.data[0] = start & 0xff;
	wire_pkt_tx.p.data[1] = (start & 0xff00) >> 8;
	wire_pkt_tx.p.data[2] = (start & 0xff0000) >> 16;
	wire_pkt_tx.p.data[3] = (start & 0xff000000) >> 24;
	wire_pkt_tx.p.data[4] = end & 0xff;
	wire_pkt_tx.p.data[5] = (end & 0xff00) >> 8;
	wire_pkt_tx.p.data[6] = (end & 0xff0000) >> 16;
	wire_pkt_tx.p.data[7] = (end & 0xff000000) >> 24;

	fprintf (stderr, "Memory peek for range 0x%08x - 0x%08x\n", start, end);
	r = write(econet_fd, &wire_pkt_tx, 14);

	if (r < 0)
		fprintf(stderr, "Transmit failure on peek: %s (%d)\n", strerror(r), r);
	else
	{	

		struct 	pollfd p;

		p.fd = econet_fd;
		p.events = POLLIN;

		poll(&p, 1, 3000);

		if (p.revents & POLLIN)
		{
			r = read(econet_fd, &wire_pkt_rx, ECONET_MAX_PACKET_SIZE);

			if (r < 0) // Receive error
				fprintf(stderr, "Receive error on reply - %d\n", r);
			else if (r == 0) fprintf(stderr, "Nothing received in reply\n");
			else
			{
				fprintf(stderr, "Remote memory peek received:\n");
				dump_pkt_data((char *) (&wire_pkt_rx)+4, (r-4), start);
			}
		}
		else	fprintf(stderr, "No reply.\n");
	}

}

void haltcontinue(char ctrl)
{
	int r;

	wire_pkt_tx.p.ctrl = ctrl;

	r = write(econet_fd, &wire_pkt_tx, 6);	

	if (r < 0)
		fprintf(stderr, "Error on transmit: %s (%d)\n", econet_strtxerr(r), r);

}

int usage(char *name)
{

	fprintf(stderr, " \n\
Copyright (c) 2021 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
Usage: %s -s n -d n [options] \n\
Options:\n\
\n\
\t-d n\tSet destination station. Utility will not function without.\n\
\t-s n\tSet my station number. Ditto.\n\
\n\
\nQuery type options\n\
\t-c\tSend Continue\n\
\t-j\tSend Halt\n\
\t-m\tSend Machine Peek query\n\
\t-p\tSend Memory Peek query. Use -q & -r to set start & end locations\n\
\n\
\nOptions for memory peek queries (both required)\n\
\t-q\tSet start address in hex - e.g. 2000\n\
\t-r\tSet end address in hex - e.g. 22FF\n\
\n\
\nHelp:\n\
\t-h\tThis help message.\n\n\
\nNote: Only up to about &2ff bytes can be peeked in one packet.\n\n\
", name);

	exit(EXIT_FAILURE);
}

void main(int argc, char **argv)
{

	int 		opt;
	short 		source, destination;
	short 		p_continue, p_halt, p_mpeek, p_rpeek;
	unsigned int 	mem_start, mem_end;

	source = destination = 0;

	p_continue = p_halt = p_mpeek, p_rpeek = 0;
	mem_start = mem_end = 0;

	while ((opt = getopt(argc, argv, "hs:d:pcjmpq:r:")) != -1)
	{
		switch (opt) {
			case 's': /* Set source address */
				source = atoi(optarg);
				break;
			case 'd': /* Set destination address */
				destination = atoi(optarg);
				break;
			case 'c': /* Continue machine */
				p_continue = 1;
				break;
			case 'j': /* Halt machine */
				p_halt = 1;
				break;
			case 'm': /* Machine peek */
				p_mpeek = 1;
				break;
			case 'p': /* Memory peek */
				p_rpeek = 1;
				break;
			case 'q': /* Set start address */
				mem_start = strtoul(optarg, 0, 16); 
				break;
			case 'r': /* Set end address */
				mem_end = strtoul(optarg, 0, 16);
				break;
			case 'h': usage(argv[0]); break;
		}
	}

	if (source == 0 || destination == 0)
	{
		fprintf(stderr, "Must specify BOTH -s and -d.\n\n");
		exit(EXIT_FAILURE);
	}

	if (p_rpeek && ((mem_start == 0) || (mem_end == 0))) /* Ram peek */
	{
		fprintf(stderr, "Must specify BOTH -q and -r for a memory peak operation.\n\n");
		exit(EXIT_FAILURE);
	}

	if (p_rpeek && ((mem_end - mem_start) > 0x2ff))
	{
		fprintf(stderr, "Too large a range specified for memory peak. See help.\n\n");
		exit(EXIT_FAILURE);
	}
		
	if (p_continue && p_halt)
	{
		fprintf(stderr, "Not useful to specify continue & halt at same time.\n\n");
		exit(EXIT_FAILURE);
	}

	/* The open() call will do an econet_reset() in the kernel */
	econet_fd = open("/dev/econet-gpio", O_RDWR);

	if (econet_fd < 0)
	{
		printf("Unable to open econet device. You may need to be root?\n");
		exit (EXIT_FAILURE);
	}

	ioctl(econet_fd, ECONETGPIO_IOC_AUNMODE, 0);

	// Build generic packet for transmit

	wire_pkt_tx.p.dststn = destination;
	wire_pkt_tx.p.dstnet = 0;
	wire_pkt_tx.p.srcstn = source;
	wire_pkt_tx.p.srcnet = 0;
	wire_pkt_tx.p.port = 0; // Immediate
	
	if (p_mpeek)
		machinepeek();

	if (p_rpeek)
		memorypeek(mem_start, mem_end);

	if (p_continue)
		haltcontinue(0x87);

	if (p_halt)
		haltcontinue(0x86);

}
