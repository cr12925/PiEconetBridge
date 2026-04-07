/*
  (c) 2026 Chris Royle
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
#include "../include/econet-gpio-chipctrl.h"

enum econet_aunstate	aun_state = 0;
uint32_t expected_ack = 0;
uint8_t		cached_port, cached_ctrl;

uint8_t	not_idle = 0;
uint8_t machinepeek = 0;

struct timespec start;
uint8_t timestamps = 0;

int read_wire (int);
int write_wire (short, short, short, short, short, short, char *, int);

void dump_pkt_data(unsigned char *, int, unsigned long);

int econet_fd;
int dumpmode_brief = 0;

uint32_t	ack_expected;

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

void econet_printD (uint8_t *w)
{
	uint16_t c = 0;

	while (*(w+c) != 0x0D)
	{
		printf ("%c", *(w+c));
		c++;
	}

}

/* Extract 24 bit value from packet */

uint32_t econet_get24(struct __econet_packet *p, uint16_t start)
{
	return (
			p->data[start] +
			(p->data[start+1] << 8) +
			(p->data[start+2] << 16)
	       );
}

/* Extract 32 bit value from packet */

uint32_t econet_get32(struct __econet_packet *p, uint16_t start)
{
	return (econet_get24(p, start) + (p->data[start+3] << 24));
}

/* Decode a machine peek reply */

void econet_mpdecode(struct __econet_packet *p)
{
	switch (p->data[5]) /* Manufacturer */
	{
		case 0x00: printf ("Acorn"); break;
		case 0x10: printf ("JGH"); break;
		case 0x50: printf ("PB"); break;
		case 0xEC: printf ("Generic"); break;
		case 0xEE: printf ("Raspberry Pi"); break;
		case 0xFF: printf ("SJ Research"); break;
		default: printf ("Unknown manufacturer's"); break;
	}

	printf (" ");

	switch (p->data[4]) /* Machine type */
	{
		case 0x01: printf ("BBC Microcomputer"); break;
		case 0x02: printf ("Atom"); break;
		case 0x03: printf ("System 3 or 4"); break;
		case 0x04: printf ("System 5"); break;
		case 0x05: printf ("BBC Master 128"); break;
		case 0x06: printf ("Electron"); break;
		case 0x07: printf ("Archimedes"); break;
		case 0x08: printf ("(Reserved)"); break;
		case 0x09: printf ("Communicator"); break;
		case 0x0A: printf ("Master ET"); break;
		case 0x0B: printf ("Filestore"); break;
		case 0x0C: printf ("Master 128 Compact"); break;
		case 0x0D: printf ("Ecolink PC Card"); break;
		case 0x0E: printf ("Unix(R) Workstation"); break;
		case 0x0F: printf ("RISC PC"); break;
		case 0x10: printf ("CTL Iyonix"); break;
		case 0x11: printf ("A9"); break;
		case 0x40: printf ("Spectrum"); break;
		case 0x41: printf ("Amstrad CPC"); break;
		case 0xE0: printf ("Pyco Client"); break;
		case 0xE1: printf ("unknown model of Raspberry Pi"); break;
		case 0xED: printf ("Pi 5"); break;
		case 0xEE: printf ("Pi 4"); break;
		case 0xEF: printf ("Pi 3"); break;
		case 0xF8: printf ("GP Server"); break;
		case 0xF9: printf ("80386 Unix"); break;
		case 0xFA: printf ("SCSI Interface"); break;
		case 0xFB: printf ("IBM PC Econet Interface"); break;
		case 0xFC: printf ("Nascom 2"); break;
		case 0xFD: printf ("RM 480Z"); break;
		case 0xFE: printf ("Fileserver"); break;
		case 0xFF: printf ("Z80 CP/M"); break;
		default: printf ("unknown machine"); break;
	}

	printf (" NFS v %02X.%02X", p->data[7], p->data[6]);
}

void econet_portdecode (struct __econet_packet *p, uint8_t port, uint8_t ctrl)
{

	machinepeek = 0;

	switch (port) /* Port */
	{
		case 0x00: /* Immediate */
		{
			printf ("Immediate ");

			switch (ctrl)
			{
				case 0x81: printf ("Peek "); break;
				case 0x82: printf ("Poke "); break;
				case 0x83: printf ("JSR "); break;
				case 0x84: printf ("USERPROC "); break;
				case 0x85: {
						uint8_t proc = p->data[6];
						printf ("OSPROC "); 
						switch (proc)
						{
						case 0: printf ("Notify character &%02X (%c) ",
									p->data[4],
									(p->data[4] < 32 || p->data[4] > 126) ? '.' : p->data[4]);
							break;
						case 1: printf ("Start REMOTE "); break;
						case 2: printf ("Start VIEW "); break;
						case 3: printf ("Cause fatal error "); break;
						case 4: printf ("Character from REMOTE "); break;
						default: printf ("(Undecoded "); break;
					   	} 
					   } break;
				case 0x86: printf ("HALT "); break;
				case 0x87: printf ("CONTINUE "); break;
				case 0x88: printf ("Machine peek "); machinepeek = 1; break;
				case 0x89: printf ("Get registers "); break;
			 	default: printf ("(Unknown type "); break;
			}
		} break;
		case 0x9C: /* Bridge protocol */
		{
			printf ("Bridge ");

			switch (ctrl)
			{
				case 0x80: 
				{
					if (!not_idle)
						printf ("reset from net %d", p->data[6]); 
					else	printf ("what/is net reply for net %d", p->data[4]);
				} break;
				case 0x81: 
				{
					uint8_t count = 6;
					printf ("update with nets"); 
					while (count < p->ptr)
					{
						printf (" %d", p->data[count]);
						count++;
					}
				} break;
				case 0x82: printf ("what net query"); break;
				case 0x83: 
				{
					if (p->ptr >= 7)
						printf ("is net query for net %d", p->data[7]);
					else	printf ("malformed isnet query");
				} break;
			}
		} break;
		
		case 0x93: /* Remote */
		{
			printf ("Remote ");
		} break;

		case 0x99: /* Fileserver protocol */
		{
			uint8_t	fsop = p->data[5];
			uint8_t reply_port = p->data[4], urd = p->data[6], cwd = p->data[7], lib = p->data[8];

			printf ("FS Op &%02X ", fsop);

			switch (fsop)
			{
				case 0x00: /* OSCLI */
				{
					printf ("*");
					econet_printD(&(p->data[9]));
				} break;
				case 0x01: /* Save */
				{
					uint32_t	load, exec, length;

					load = econet_get32(p, 9);
					exec = econet_get32(p, 13);
					length = econet_get24(p, 17);

					printf ("Save ");
					econet_printD(&(p->data[20]));
					printf (" %X +%X %X", load, length, exec);

				} break;
				case 0x02: /* Load */
				{
					printf ("Load ");
					econet_printD(&(p->data[9]));
				} break;
				case 0x03: /* Examine */
				{
					printf ("Examine '");
					econet_printD(&(p->data[12]));
					printf ("' relative to handle &%02X, starting at &%02X and returning &%02X entries, arg = &%02X", cwd, p->data[10], p->data[11], p->data[9]);
				} break;
				case 0x04: /* Catalogue header */
				{
					printf ("Catalogue header ");
				} break;
				case 0x05: /* Runas */
				{
					printf ("Run ");
					econet_printD(&(p->data[9]));
				} break;
				case 0x06: /* Open */
				{
					printf ("Open ");
					econet_printD(&(p->data[9]));
				} break;
				case 0x07: /* Close */
				case 0x2E: /* 32 bit close fall through */
				{
					printf ("Close%s#&%02X ", (fsop == 0x2E ? "32" : ""), p->data[9]);
				} break;
				case 0x08: /* Get byte */
				{
					printf ("Get byte on handle %d ", p->data[7]);
				} break;
				case 0x09: /* Put byte */
				{
					printf ("Put byte &%02X on handle %d ", p->data[8], p->data[7]);
				} break;
				case 0x0A: /* Get bytes */
				{
					printf ("Get &%06X bytes on handle %d ", econet_get24(p, 11), p->data[9]);
					if (p->data[10]) printf ("from cursor ");
					else printf ("from &%06X ", econet_get24(p, 14));
				} break;
				case 0x0B: /* Put bytes */
				{
					printf ("Put &%06X bytes on handle %d ", econet_get24(p, 11), p->data[9]);
					if (p->data[10]) printf ("from cursor ");
					else printf ("from &%06X ", econet_get24(p, 14));
				} break;
				case 0x0C: /* Get Random Access Info */
				{
					printf ("Get random access info ");
				} break;
				case 0x0D: /* Set Random Access Info */
				{
					printf ("Set random access info ");
				} break;
				case 0x0E: /* Read discs */
				{
					printf ("Read disc names starting at %d, %d entries ", p->data[9], p->data[10]); /* Corrected */
				} break;
				case 0x0F: /* Read users */
				{
					printf ("Read logged on users starting at %d, %d entries ", p->data[9], p->data[10]);
				} break;
				case 0x10: /* Read server time */
				{
					printf ("Read server time ");
				} break;
				case 0x11: /* Check EOF */
				{
					printf ("Check EOF on handle %d ", p->data[9]);
				} break;
				case 0x12: /* Read object info */
				{
					uint8_t	arg = p->data[9];

					if (arg == 0xBC) printf ("32bit FSOp probe ");
					else
					{
						printf ("Read object info for ");
						if (arg == 3)
							econet_printD(&(p->data[14]));
						else	econet_printD(&(p->data[10]));
						
						printf (" arg = %d ", arg);
					}
				} break;
				case 0x13: /* Set object info */
				{
					uint8_t	arg = p->data[9];
					uint8_t	fpos;

					switch (arg)
					{
						case 1: fpos = 19; break;
						case 2:
						case 3: fpos = 14; break;
						case 4: fpos = 11; break;
						case 5: fpos = 12; break;
					}

					printf ("Set object info ");

					if (arg == 0x40) /* MDFS */
						printf ("(MDFS variant)");
					else
						econet_printD(&(p->data[fpos]));
					printf (" arg %d ", arg);
				} break; 
				case 0x14: /* Delete */
				{
					printf ("Delete ");
					econet_printD(&(p->data[9]));
					printf (" ");
				} break;
				case 0x15: /* Read user environment */
				{
					printf ("Read user environment ");
				} break;
				case 0x16: /* Option set */
				{
					printf ("Set boot option to &%02X ", p->data[9]);
				} break;
				case 0x17: /* Bye / Logoff */
				{
					printf ("Bye / Logoff ");
				} break;
				case 0x18: /* Read user information */
				{
					printf ("Read user information for ");
					econet_printD(&(p->data[9]));
					printf (" ");
				} break;
				case 0x19: /* Read FS Ver */
				{
					printf ("Read FS version ");
				} break;
				case 0x1A: /* Get free space */
				{
					printf ("Get disc space on ");
					econet_printD(&(p->data[9]));
					printf (" ");
				} break;
				case 0x1B: /* Change directory */
				{
					printf ("Change directory to ");
					econet_printD(&(p->data[10]));
					printf (" ");
				} break;
				case 0x1C: /* Set RTC */
				{
					printf ("Set real time clock ");
				} break;
				case 0x1D: /* Create */
				{
					printf ("Create ");
					econet_printD(&(p->data[20]));
				} break;
				case 0x1E: /* Read user free space */
				{
					printf ("Read user free space for user '");
					econet_printD(&(p->data[9]));
					printf ("'");
				} break;
				case 0x1F: /* Set user free space */
				{
					printf ("Set user free space for user '");
					econet_printD(&(p->data[13]));
					printf ("' to &%02X%02X%02X%02X ",
							econet_get32(p, 9));

				} break;
				case 0x20: /* Read client ID */
				{
					printf ("Read client ID ");
				} break;
				case 0x24: /* Manager interface */
				{
					printf ("Manager operation ");
				} break;
				case 0x40: /* MDFS Calls */
				{
					uint8_t	arg = p->data[9];

					printf ("MDFS call");

					if (arg == 2)
					{
						printf (": read %d account information entries starting at %d on disc no. %d (arg 2)",
								(p->data[10] + (p->data[11] << 8)),
								(p->data[12] + (p->data[13] << 8)),
								p->data[14]
								);
					}
					else printf (" with undecoded argument ");
				} break;
				case 0x41: /* MDFS read system information */
				{
					uint8_t	arg = p->data[9];

					printf ("MDFS read system information &%02X: ", arg);

					switch (arg)
					{
						case 0: /* Reset print server info */
							printf ("Reset print server information ");
							break;
						case 1: /* Read current state of printer */
							printf ("Read printer state for printer %d ", p->data[10]);
							break;
						case 2: /* Set current state of printer */
						       	printf ("Set printer state for printer %d ", p->data[10]);
						 	break;
						case 5: /* Read system msg channel */
							printf ("Read system message channel ");
							break;
						case 6: /* Set system msg channel */
							printf ("Set system message channel ");
							break;
						case 7: /* Read current FS msg level */
							printf ("Read system message level ");
							break;
						case 8:	/* Set system message level */
							printf ("Set system message level to %d ", p->data[10]);
							break;
						case 9: /* Read default printer */
							printf ("Read default printer ");
							break;
						case 10: /* Write default printer */
							printf ("Set default printer ");
							break;
						case 11: /* Read priv required to change system time */
							printf ("Read privilege required to change system time ");
							break;
						case 12: /* Set priv required to change system time */
							printf ("Set privilege required to change system time ");
							break;
						case 15: /* Read printer information */
							printf ("Read printer information starting at printer %d, %d entries ",
								p->data[11], p->data[10]);
							break;	
						default: printf ("(Undecoded operation) ");
							 break;
					}
				}
				case 0x42: /* Encryption settings */
					printf ("Encryption functions ");
					break;
				case 0x43: /* Tape functions */
				{
					uint8_t arg;
					printf ("MDFS Tape management: ");
					arg = p->data[9];

					switch (arg)
					{
						case 0: printf ("Check if backup possible "); break;
						case 1: printf ("Read tape ID block "); break;
						case 2: printf ("Read auto backup status "); break;
						case 3: printf ("Set auto backup status "); break;
						case 4: printf ("Read tape partition size "); break;
						case 16: printf ("Format tape (PiFS) "); break;
						case 17: printf ("Mount tape (PiFS) "); break;
						case 18: printf ("Dismount tape (PiFS) "); break;
						case 19: printf ("Select tape drive (PiFS) "); break;
						case 20: printf ("Get tape drive number (PiFS) "); break;
						case 21: printf ("Get tape names (PiFS) starting at %d, %d entries ", p->data[10], p->data[11]); break;
						default: printf ("(Undecoded operation) "); break;
					}

				}
				case 0x60: /* PiBridge operations */
				{
					uint8_t arg;

					arg = p->data[9];

					switch (arg)
					{
						case 0: printf ("Get PiBridge Git version "); break;
						case 1: printf ("Shut down / power off "); break;
						case 16: printf ("Get UID and privilege bits for user "); econet_printD(&(p->data[10])); break;
						case 17: printf ("Get FS Parameters "); break;
						case 18: printf ("Set FS Parameters "); break;
						case 19: printf ("Shut down fileserver "); break;
						case 20: 
							 {
								 uint8_t arg2;

								 arg2 = p->data[10];

								 printf ("Force log user off ");

								 switch (arg2)
								 {
									 case 0: printf ("by username: "); econet_printD(&(p->data[11])); break;
									 case 1: printf ("by userid: &%04X ", (p->data[11] + (p->data[12] << 8))); break;
									 case 2: printf ("by station %d.%d ", p->data[11], p->data[12]); break;
									 default: printf ("(bad argument) "); break;
								 }

							 } break;

						default: printf ("Undecoded operation "); break;
					}
				}
				default: printf ("Undecoded operation "); break;
			}
		}
		break;

		case 0x9B: /* Bridge trace */
		{
			printf ("Bridge trace ");
		} break;

		case 0x9D: /* Resource locator */
		{
			printf ("Resource locator ");
		} break;

		case 0x9E: /* PS protocol */
		{
			printf ("Printserver protocol ");
		} break;

		case 0x9F: /* PS Query */
		{
			printf ("Printserver query ");
		} break;

		case 0xA0: /* FAST */
		{
			printf ("FAST protocol ");
		} break;

		case 0xB0: /* FINDSERVER */
		{
			printf ("Find server ");
		} break;

		case 0xB1: /* FINDSERVER reply */
		{
			printf ("Find server reply ");
		} break;

		case 0xB2: /* TTS reply */
		{
			printf ("Teletext server reply ");
		} break;

		case 0xB3: /* TTS Command */
		{
			printf ("Teletext server command ");
		} break;

		case 0xB4: /* TTS Data */
		{
			printf ("Teletext data ");
		} break;

		case 0xB5: /* TTS Header */
		{
			printf ("Teletext header ");
		} break;

		case 0xD1: /* PS Data */
		{
			printf ("Printserver data ");
		} break;

		case 0xD2: /* IP/Econet */
		{
			printf ("IP/Econet ");

			switch (ctrl)
			{
				case 0xA1: printf ("ARP Request: who has %d.%d.%d.%d? Tell %d.%d.%d.%d ", 
					p->data[6], p->data[7], p->data[8], p->data[9],
					p->data[10], p->data[11], p->data[12], p->data[13]
					);
					   break;
				case 0xA2: printf ("ARP Reply: %d.%d.%d.%d - station %3d.%3d has %d.%d.%d.%d ",
					p->data[6], p->data[7], p->data[8], p->data[9],
					p->data[3], p->data[2],
					p->data[10], p->data[11], p->data[12], p->data[13]
					);
					   break;
				case 0x81: printf ("Datagram "); break;
				default: printf ("Unknown IP traffic type ");
			}

		} break;

	}

}

void econet_newdump(struct __econet_packet *p)
{

	struct timespec t;
	uint16_t	counter = 0, data_base = 0;
	struct __econet_packet pkt;
	uint8_t		was_ack = 0;

	memcpy(&pkt, p, sizeof(pkt) - ECONET_MAX_PACKET_SIZE + p->ptr);
	
	clock_gettime(CLOCK_MONOTONIC, &t);

	if (t.tv_nsec < start.tv_nsec)
	{
		t.tv_sec--;
		t.tv_nsec = (1000000000 - (start.tv_nsec - t.tv_nsec));
	}
	else
		t.tv_nsec -= start.tv_nsec;

	t.tv_sec -= start.tv_sec;

	if (pkt.ptr > 0)
	{
		if (!dumpmode_brief || !not_idle) printf ("\n");

		if (timestamps && (!dumpmode_brief || !not_idle))
			printf ("%02dd %02d:%02d:%02d.%04ds ",
				(t.tv_sec / (24 * 60 * 60)),
				(t.tv_sec % (24 * 60 * 60)) / 3600,
				(t.tv_sec % (3600)) / 60,
				(t.tv_sec % 60),
				t.tv_nsec);
	}

	if (pkt.ptr >= 3 && (!not_idle || !dumpmode_brief))
	{
		printf ("%2s ", (pkt.tx == EP_PACKET_RX ? "RX" : "TX"));
		if (pkt.data[2] == 0) /* Source is a bridge */
			printf ("Brg#%03d", pkt.data[3]);
		else	printf ("%3d.%3d", pkt.data[3], pkt.data[2]);
		printf (" > ");

		if (pkt.data[0] == 0xff || pkt.data[1] == 0xff) printf ("Br/Cast");
		else	printf ("%3d.%3d", pkt.data[1], pkt.data[0]);

	}

	if (pkt.ptr >= 5) 
	{
		if (!not_idle)
		{
			cached_port = pkt.data[5];
			cached_ctrl = pkt.data[4];

			printf (" Port &%02X Ctrl &%02X ", pkt.data[5], pkt.data[4]);

			data_base = 6;

			if (
				(pkt.data[0] == 0xff || pkt.data[1] == 0xff) /* Broadcast */
			||	(pkt.data[5] == 0x00 && (pkt.data[4] <= 0x81 || pkt.data[4] == 0x88)) /* two-way immediates */
			   )
				econet_portdecode (&pkt, pkt.data[5], pkt.data[4]);
		}
		else printf (" ");

		if (not_idle == 1 && machinepeek) /* Decode machine peek */
			econet_mpdecode(&pkt);

		if (not_idle == 2) /* Data portion of 4-way */
		{
			data_base = 4;
			econet_portdecode(&pkt, cached_port, cached_ctrl);
		}
	}

	if (not_idle & 0x01 == 1)
		data_base = 4;

	if (!dumpmode_brief && pkt.ptr >= 3) printf ("\n");

	counter = data_base;

	if (!not_idle && pkt.ptr >= 6) /* Copy the addresses to compare with incoming */
	{
		uint32_t tmp;

		memcpy(&ack_expected, &(p->data), 4);

		tmp = ((ack_expected & 0xFFFF0000) >> 16) | ((ack_expected & 0x0000FFFF) << 16); /* Swap the pairs round */

		ack_expected = tmp; 
	}

	if ((not_idle & 0x01 == 0) && pkt.ptr == 4) /* Likely ACK if it's 2nd or 4th packet in sequence */
	{
		uint32_t tmp;

		memcpy(&tmp, &(p->data), 4);

		if (tmp == ack_expected) /* Got it */
			was_ack = 1;
		else	was_ack = 0;


		//if (was_ack) printf ("ACK ");
		if (was_ack) printf ("\xE2\x9C\x94 ");
	}

	if ((not_idle & 0x01 == 0) && !was_ack) /* The expected ACK did not arrive ... */ /* This will screw up on 2-way immediates... */
		printf (" Missing Ack\n");

	if (!dumpmode_brief) while (!was_ack && (counter < pkt.ptr))
	{
		uint16_t	internal;

		if (counter != 0 && timestamps) printf ("    "); /* Pad the timestamp area of the line */

		if (((counter - data_base) % 8) == 0)
			printf ("%08X:", counter);

		internal = 0; 

		while ((internal+counter < pkt.ptr) && (internal < 8))
			printf ("  %02X", pkt.data[counter+(internal++)]);

		while (internal++ < 8)
		{
			/* Fill space */
			printf ("    ");
		}

		/* Now print character verions */

		printf ("    ");

		internal = 0;

		while ((internal+counter < pkt.ptr) && (internal < 8))
		{
			uint8_t	c;

			c = pkt.data[counter+internal];
			if (c < 33 || c > 126) c = '.';

			printf ("%c", c);
			internal++;
		}

		printf ("\n");

		counter += 8;
	}

	if (!dumpmode_brief && pkt.ptr != 0) 
	{
		if (timestamps)
			printf ("    ");
		
		printf ("%08X*", pkt.ptr); /* Pad the timestamp area of the line */
	}

	if (	!dumpmode_brief && 
		((pkt.sr1 & ~(ECONET_GPIO_S1_IRQ | ECONET_GPIO_S1_S2RQ | ECONET_GPIO_S1_CTS))
	||	(pkt.sr2 & ~(ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_RX_IDLE))
		)
	   )
	{
		if (pkt.ptr == 0)
		{
			if (timestamps)
				printf ("%02dd %02d:%02d:%02d.%04ds ",
				(t.tv_sec / (24 * 60 * 60)),
				(t.tv_sec % (24 * 60 * 60)) / 3600,
				(t.tv_sec % (3600)) / 60,
				(t.tv_sec % 60),
				t.tv_nsec);
			else printf ("Flags: ");
		}

		//if (pkt.sr1 & ECONET_GPIO_S1_IRQ) printf("IRQ ");
		//if (pkt.sr1 & ECONET_GPIO_S1_S2RQ) printf("S2RQ ");
		if (pkt.sr1 & ECONET_GPIO_S1_LOOP) printf("LOOP ");
		if (pkt.sr1 & ECONET_GPIO_S1_FLAG) printf("FLAG ");
		//if (pkt.sr1 & ECONET_GPIO_S1_CTS) printf("COLLISION ");
		if (pkt.sr1 & ECONET_GPIO_S1_UNDERRUN) printf("TX-UNDERRUN ");
		if (!(pkt.sr1 & ECONET_GPIO_S1_TDRA)) printf("INCOMPLETE-FRAME ");
		if (pkt.sr1 & ECONET_GPIO_S1_RDA) printf("RX-DATA ");

		if (pkt.sr2 & ECONET_GPIO_S2_AP) printf("AP ");
		//if (pkt.sr2 & ECONET_GPIO_S2_VALID) printf("VALID ");
		if (pkt.sr2 & ECONET_GPIO_S2_RX_ABORT) printf("RX-ABORT ");
		if (pkt.sr2 & ECONET_GPIO_S2_ERR) printf("!CRC ");
		if (pkt.sr2 & ECONET_GPIO_S2_DCD) printf("!CLOCK ");
		if (pkt.sr2 & ECONET_GPIO_S2_OVERRUN) printf("RX_OVERRUN ");
		if (pkt.sr2 & ECONET_GPIO_S2_RDA) printf("RX-DATA ");

		if (pkt.tx_flags & EP_IRQHANDLER_FAILED) printf("NO-IRQ ");
	}

	if (pkt.sr2 & ECONET_GPIO_S2_RX_IDLE)
	{
		not_idle = 0;
		machinepeek = 0; /* We also do this in the port decoder, this is just for belt & braces */
		printf ("\n");
		if (timestamps)
			printf ("%02dd %02d:%02d:%02d.%04ds ",
				(t.tv_sec / (24 * 60 * 60)),
				(t.tv_sec % (24 * 60 * 60)) / 3600,
				(t.tv_sec % (3600)) / 60,
				(t.tv_sec % 60),
				t.tv_nsec);
		printf ("Idle\n");
	}
	else	not_idle++;
}

void econet_newmonitor(void)
{
	int	fd, s;
	struct pollfd	p;

	fd = open ("/dev/econet-monitor", O_RDONLY);

	if (fd < 0)
	{
		fprintf (stderr, "Unable to open /dev/econet-monitor: %s", strerror(fd));
		exit(EXIT_FAILURE);
	}

	p.fd = fd;
	p.events = POLLIN;
	
	s = 0;

	printf ("Listening on /dev/econet-monitor...\n\n");

	while (poll(&p, 1, -1))
	{
		struct __econet_packet	pkt;

		if ((p.revents & POLLIN) && (s = read(fd, &pkt, sizeof(struct __econet_packet))))
		{
			if (s > 0)
			{
				econet_newdump(&pkt);

			}
			else
				printf ("Error: read() returned <= 0!\n");

		}
		else break;
		p.events = POLLIN;
	}

	if (s < 0)
	{
		fprintf (stderr, "Read error from network - %d\n", s);
		exit(EXIT_FAILURE);
	}

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

	if (access("/dev/econet-monitor", R_OK) == 0)
	{
		econet_newmonitor();
		exit(EXIT_SUCCESS);
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
