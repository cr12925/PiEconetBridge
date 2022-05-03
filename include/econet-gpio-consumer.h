/*
  (c) 2020 Chris Royle
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

#ifndef __ECONETGPIOCONSUMER_H__
#define __ECONETGPIOCONSUMER_H__

#include <linux/ioctl.h>
#include <linux/types.h>

/* This is the map of stations we want to handle traffic for that
   are not on the local econet wire. One bit per station, arranged
   0...255	Network 0 (the local network)
   256...511	Network 1 (distant - on UDP)
   ... etc.
  
   This ararngement allows us to have some stations in network 0
   which are on UDP/IP, which get bridged, and others which are 
   on the physical wire - and neither need know which is which.
*/

#define ECONET_MAX_PACKET_SIZE 32768 /* BeebEm uses 2048, but there is mention of 4K somewhere. But then a *VIEW screendump seems to come in a single packet, so we'll try 32768 */

/* This is what we get from the Kernel (or send to it). 
   Actual structure of 'data' is:
   Byte		Content
   0		Destination station
   1		Destination network
   2		Source station
   3		Source network
   4		Control byte
   5		Port number
   6		... data
*/
struct __econet_packet {
	int ptr; /* Read/Write pointer - holds the index of the *next* byte to be read/written, so always starts at 0 */
	char data[ECONET_MAX_PACKET_SIZE];
};


/* Clear the station map */
#define	ECONET_INIT_STATIONS(m)	 	memset(&(m), 0, 8192);
/* Clear a station's bitmap entry - x=stn, y=net */
#define ECONET_CLR_STATION(m,y,x)		(m)[((y)*32)+((x)/8))] ~= (1 << ((x)%8))
/* Set a station's bitmap entry */
#define ECONET_SET_STATION(m,y,x)		(m)[((y)*32)+(((x)/8))] |= (1 << ((x)%8))
/* Check to see if a station has its bit set in the bitmap */
#define ECONET_DEV_STATION(m,y,x)		((m)[((y)*32)+(((x)/8))] & (1 << (x)%8))

struct __econet_packet_wire {
	union {
		unsigned char data[ECONET_MAX_PACKET_SIZE];
		struct {
			unsigned char dststn;
			unsigned char dstnet;
			unsigned char srcstn;
			unsigned char srcnet;
			unsigned char ctrl; // Ctrl & Port are the other way round on the wire from an AUN packet
			unsigned char port;
			unsigned char data[ECONET_MAX_PACKET_SIZE-6];
		} p;
	};
};

/* AUN Packet Types */

#define ECONET_AUN_BCAST 0x01
#define ECONET_AUN_DATA 0x02
#define ECONET_AUN_ACK 0x03
#define ECONET_AUN_NAK 0x04
#define ECONET_AUN_IMM 0x05
#define ECONET_AUN_IMMREP 0x06

/* Data structure for passing AUN packets userspace<->kernel via /dev/econet-gpio, and within the kernel
 * NB: This does NOT match what they look like on the wire, even within the UDP data portion because the
 * format has source & destination net/station at the start, which the real ones don't - but these are to
 * assist in directing traffic within the local machine. They are stripped off before the packet hits
 * the UDP socket
 * ie. what is written to a UDP AUN socket is from byte 4 onwards (aun_ttype)
 */
struct __econet_packet_aun {
	union {
		struct {
			unsigned char dststn;
			unsigned char dstnet;
			unsigned char srcstn;
			unsigned char srcnet;
			unsigned char aun_ttype; // See definitions above
			unsigned char port;
			unsigned char ctrl; // Internally, this will have high bit set. On the UDP packet it is stripped off
			unsigned char padding;
#ifdef u32
			u32 seq;
#else
			uint32_t seq;
#endif

			unsigned char data[ECONET_MAX_PACKET_SIZE-9];
		} p;
		unsigned char raw[ECONET_MAX_PACKET_SIZE];
	};
};

struct __econet_packet_udp {
	union {
		unsigned char raw[ECONET_MAX_PACKET_SIZE];
		struct {
			unsigned char ptype;
			unsigned char port; /* Yes, port first on AUN; it's CB first on the Econet wire! */
			unsigned char ctrl;
			unsigned char pad;
			uint32_t seq;
			unsigned char data[ECONET_MAX_PACKET_SIZE-4];
		} p;
	};
};

// Not used in the kernel module
// Struct for carrying packets over named pipes - includes the packet length because we keep getting two stuck together!
struct __econet_packet_pipe { 
	unsigned char length_low; // LSB first
	unsigned char length_high; // MSB
			unsigned char dststn;
			unsigned char dstnet;
			unsigned char srcstn;
			unsigned char srcnet;
			unsigned char aun_ttype; // See definitions above
			unsigned char port;
			unsigned char ctrl; // Internally, this will have high bit set. On the UDP packet it is stripped off
			unsigned char padding;
#ifdef u32
			u32 seq;
#else
			uint32_t seq;
#endif

			unsigned char data[ECONET_MAX_PACKET_SIZE-9];
};

/* IOCTL Magic */

#define ECONETGPIO_MAGIC        (0xa9) /* LDA Opcode for a 6502 */

#define ECONETGPIO_IOC_RESET		_IO(ECONETGPIO_MAGIC, 0) /* Will also take us out of test mode */
#define ECONETGPIO_IOC_PACKETSIZE	_IOR(ECONETGPIO_MAGIC, 1, int) /* Read maximum packet size */
#define ECONETGPIO_IOC_AVAIL		_IOR(ECONETGPIO_MAGIC, 2, int) /* Read size of next available packet, or -1 if nothing available  */
#define ECONETGPIO_IOC_FLAGFILL		_IOW(ECONETGPIO_MAGIC, 4, int) /* Set or clear Flag Fill */
#define ECONETGPIO_IOC_SET_STATIONS	_IOW(ECONETGPIO_MAGIC, 5, unsigned char*) /* Bitmap for stations we are interested in on AUN */
#define ECONETGPIO_IOC_AUNMODE		_IOW(ECONETGPIO_MAGIC, 6, int) /* Turn AUN mode (4-way handshake) on / off */
#define ECONETGPIO_IOC_IMMSPOOF		_IOW(ECONETGPIO_MAGIC, 7, int) /* Turn in-kernel immediate spoofing for wire stations on/off  */
#define ECONETGPIO_IOC_TXERR		_IOR(ECONETGPIO_MAGIC, 8, int) /* Read last tx error number  */
#define ECONETGPIO_IOC_READMODE		_IO(ECONETGPIO_MAGIC, 9) /* Set module to read mode  */
#define ECONETGPIO_IOC_GETAUNSTATE	_IOR(ECONETGPIO_MAGIC, 10, int) /* Read current AUN state */

/* The following are for debugging and testing only, and only with interrupts off */
#define ECONETGPIO_IOC_SETA		_IOW(ECONETGPIO_MAGIC, 100, int) /* bit0 is A0, bit1 is A1 */
#define ECONETGPIO_IOC_WRITEMODE	_IOW(ECONETGPIO_MAGIC, 101, int) /* Set / clear R/W and DIR */
#define ECONETGPIO_IOC_SETCS		_IOW(ECONETGPIO_MAGIC, 102, int) /* Set / clear Chip Select */
#define ECONETGPIO_IOC_SETBUS		_IOW(ECONETGPIO_MAGIC, 103, char)
#define ECONETGPIO_IOC_TEST		_IO(ECONETGPIO_MAGIC, 104) /* Put into test mode - interrupts off, ignore all user-space read/write ops. Use RESET to come back to normal ops */
#define ECONETGPIO_IOC_TESTPACKET	_IO(ECONETGPIO_MAGIC, 105)


#define ECONET_GPIO_WRITE 0
#define ECONET_GPIO_READ 1
#define ECONET_GPIO_CS_ON 0
#define ECONET_GPIO_CS_OFF 1
#define ECONET_GPIO_RST_RST 0
#define ECONET_GPIO_RST_CLR 1

#define ECONET_TX_SUCCESS 0
#define ECONET_TX_BUSY 0x10
#define ECONET_TX_JAMMED 0x40
#define ECONET_TX_HANDSHAKEFAIL 0x41
#define ECONET_TX_NECOUTEZPAS 0x42 // Not listening
#define ECONET_TX_NOTLISTENING 0x42
#define ECONET_TX_NOCLOCK 0x43
#define ECONET_TX_UNDERRUN 0x50
#define ECONET_TX_TDRAFULL 0x51
#define ECONET_TX_NOIRQ 0x52 // Gave up waiting for IRQ line to be inactive
#define ECONET_TX_NOCOPY 0x53 // Coulndn't copy from userspace
#define ECONET_TX_NOTSTART 0x54 // TX start timed out - we never got a result back from the IRQ routine
#define ECONET_TX_COLLISION 0x55 // CTS went high during transmit - try again
#define ECONET_TX_DATAPROGRESS 0xfd // Flags the fact that we got an ack to the Scout
#define ECONET_TX_INPROGRESS 0xfe
#define ECONET_TX_STARTWAIT 0xff

#define ADVERTISED_MACHINETYPE 0xeeee
#define ADVERTISED_VERSION 0x0001

#define ECONET_HOSTTYPE_TDIS 0x02
#define ECONET_HOSTTYPE_TWIRE 0x04
#define ECONET_HOSTTYPE_TLOCAL 0x08
#define ECONET_HOSTTYPE_TAUN 0x01

#define ECONET_HOSTTYPE_DIS_RAW (ECONET_HOSTTYPE_TDIS)
#define ECONET_HOSTTYPE_DIS_AUN (ECONET_HOSTTYPE_TDIS | ECONET_HOSTTYPE_TAUN)
#define ECONET_HOSTTYPE_WIRE_RAW (ECONET_HOSTTYPE_TWIRE)
#define ECONET_HOSTTYPE_WIRE_AUN (ECONET_HOSTTYPE_TWIRE | ECONET_HOSTTYPE_TAUN)
#define ECONET_HOSTTYPE_LOCAL_RAW (ECONET_HOSTTYPE_TLOCAL)
#define ECONET_HOSTTYPE_LOCAL_AUN (ECONET_HOSTTYPE_TLOCAL | ECONET_HOSTTYPE_TAUN)

#define ECONET_SERVER_FILE 0x01
#define ECONET_SERVER_PRINT 0x02

enum econet_aunstate {
        EA_IDLE = 1, // Waiting for something to happen
        EA_W_WRITESCOUT, // Given a data packet by userspace. Writing the Scout
        EA_W_READFIRSTACK, // We've been given an AUN packet by userspace, and written the scout, now waiting for first ack from wire
        EA_W_WRITEDATA, // Given a data packet by userspace, done the scout, picked up the first ack, now writing the data packet
        EA_W_READFINALACK, // We've written the data packet to the wire, now waiting for final ack
        // Any read of a Data scout will happen in EA_IDLE, so first state is WRITEFIRSTACK
        EA_R_WRITEFIRSTACK, // We've read a scout from the wire, now transmitting first ack
        EA_R_READDATA, // We've read a scout from the wire, written the ack, now waiting for the data packet
        EA_R_WRITEFINALACK, // We've read a scout from the wire, written the first ack, read the data packet, now tx final ack
        EA_I_WRITEREPLY, // We've read an immediate from the wire; we are now writing out the response to the wire
        EA_I_WRITEIMM, // We got an immediate from userspace and are putting it on the wire
        EA_I_READREPLY, // We've written an immediate to the wire, we are now waiting for the response from the wire
        EA_I_IMMSENTTOAUN, // We've received an immediate off the wire and sent it to userspace. We are waiting for a reply to come back and will then transmit it
        EA_W_WRITEBCAST // Writing a broadcast. Don't hang about for a reply
};

#endif
