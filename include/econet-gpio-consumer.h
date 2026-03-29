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
//#ifndef u32
#ifndef ECONETGPIO_KERNEL
	#include <stdint.h>
	#define u8 uint8_t
	#define u16 uint16_t
#endif

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
	u16 ptr; /* Read/Write pointer - holds the index of the *next* byte to be read/written, so always starts at 0 */
	u16 txlen; /* Data length to transmit */
	u8	sr1, sr2; /* SR1, SR2 on completion of transaction */
	u8	tx; /* 0 0=RX packet, 1=TX packet */
	u8	tx_flags; /* See below */
	char data[ECONET_MAX_PACKET_SIZE];
};

#define EP_DSTSTN(p)	p.data[0]
#define EP_DSTNET(p)	p.data[1]
#define EP_SRCSTN(p)	p.data[2]
#define EP_SRCNET(p)	p.data[3]
#define EP_CTRL(p)	p.data[4]
#define EP_PORT(p)	p.data[5]
#define EP_FOURDATA(p,n)	p.data[4+n]
#define EP_SCOUTDATA(p,n)	p.data[6+n]

/* Pointer equivalents */
#define __SRCSTN(p)			p->data[2]
#define __SRCNET(p)			p->data[3]
#define __DSTSTN(p)			p->data[0]
#define __DSTNET(p)			p->data[1]
#define __CTRL(p)			p->data[4]
#define __PORT(p)			p->data[5]
#define __SCOUTDATA(p,n)		p->data[6+n]
#define __DATA(p,n)			p->data[4+n]
#define __IS_BROADCAST(p)		( __DSTSTN(p) == 0xFF && __DSTNET(p) == 0xFF )
#define __IS_IMM_FOURWAY(p)		( __PORT(p) == 0x00 && (__CTRL(p) >= 0x82 && __CTRL(p) <= 0x85) ) /* 0x82-85 are the funky 4-way immediates */
#define __IS_FOURWAY(p)			( (!__IS_BROADCAST(p)) && ( (__PORT(p) > 0) || __IS_IMM_FOURWAY(p) ) )  /* If 4-way, then on tx we send scout and wait for reply etc.; on rx we flag fill and send acks */
#define __IS_TWOWAY(p)			( (!__IS_BROADCAST(p)) && ( __PORT(p) == 0x00 && !(__IS_IMM_FOURWAY(p) ) ) ) /* If 2-way on a receive, we flag fill, waiting for userspace to tx a reply */

/* And some AUN equivalents for __econet_packet_aun structures */

#define __AUN_SRCSTN(r)			r.p.srcstn
#define __AUN_SRCNET(r)			r.p.srcnet
#define __AUN_DSTSTN(r)			r.p.dststn
#define __AUN_DSTNET(r)			r.p.dstnet
#define __AUN_CTRL(r)			r.p.ctrl
#define __AUN_PORT(r)			r.p.port
#define __AUN_TYPE(r)			r.p.aun_ttype
#define __IS_AUN_BROADCAST(r)		(__AUN_TYPE(p) == ECONET_AUN_BCAST)
#define __IS_AUN_IMM_FOURWAY(r)		((__AUN_TYPE(r) == ECONET_AUN_DATA || __AUN_TYPE(r) == ECONET_AUN_IMM) && __AUN_PORT(r) == 0x00 && (__AUN_CTRL(r) >= 0x82 && __AUN_CTRL(r) <= 0x85))
#define __IS_AUN_FOURWAY(r)		( (__AUN_TYPE(r) == ECONET_AUN_DATA || __IS_AUN_IMM_FOURWAY(r)) )
#define __IS_AUN_TWOWAY(r)		(__AUN_TYPE(r) == ECONET_AUN_IMM && (!(__IS_AUN_IMM_FOURWAY(r))))
#define __AUN_SCOUTBYTES(r)		((__IS_AUN_IMM_FOURWAY(r)) ? \
		(__AUN_CTRL(r) == 0x82 ? 8 : 4) : 0) /* 8 bytes on 4-way immediates with ctrl 0x82, otherwise 4, and none on ordinary 4-ways */

/* Packet direction - for use in tx field */

#define EP_PACKET_RX	0
#define EP_PACKET_TX	1

/* Tx flags - for use in tx_flags field */

#define EP_TX_NO_SEIZE_IF_ACK 0x01 /* Do not flag fill on receipt of an ACK corresponding to this frame. This is used when sending the data portion of a 4-way transaction. Ordinarily, the module will always seize the line on a packet which is destined for a station we are handling (i.e. not including broadcast traffic). That works because if it's an incoming 2-way, we'll want to flag fill ready to see if there's a reply coming, and if it's an incoming scout, we'll flag fill ready to send an ACK. However, the exception is if we're sending the data portion of a 4-way - the ACK which will follow is 'end of transaction', so we don't want to flag fill. */

/* Clear the station map */
#define	ECONET_INIT_STATIONS(m)	 	memset(&(m), 0, 8192);
/* Clear a station's bitmap entry - x=stn, y=net */
#define ECONET_CLR_STATION(m,y,x)		(m)[((y)*32)+(((x)/8))] &= ~(1 << ((x)%8))
/* Set a station's bitmap entry */
#define ECONET_SET_STATION(m,y,x)		(m)[((y)*32)+(((x)/8))] |= (1 << ((x)%8))
/* Check to see if a station has its bit set in the bitmap */
#define ECONET_DEV_STATION(m,y,x)		((m)[((y)*32)+(((x)/8))] & (1 << (x)%8))

/* Packets as they come off the wire - used in RAW made */

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
#define ECONET_AUN_INK 0x07 // econet-hpbridge only: This is an "Immediate NAK". It's sent by a wire device which gets a 'Not listening' when it tried to send a 2-way immediate. Assuming it gets back to the source machine, if the source machine was also a wire when it will enable to source device to drop its flag fill early. This is also sent by a bridge where a destination device just doesn't exist and what was transmitted was an immediate. Aim is to drop flag fill on the local network quickly where there is going to be no reply, so that utilities like !Machines and *STATIONS can progress more quickly without the timeout

#define ECONET_AUN_MAXTYPE	ECONET_AUN_INK
#define ECONET_AUN_BEEBEM_PROBE	0xFF	// Used by dev BeebEm to negotiate / announce local Econet addresses in their emulator. Defined here to pick it up and allow sane logging / ability not to log "Unknown AUN" error

/* 20251128 New data structure for internal kernel use, but put here because they may be passed on a monitor device in the future */

#ifdef ECONETGPIO_KERNEL
#define		uint8_t		u8
#define		uint16_t	u16
#define 	uint32_t	u32
#define		uint64_t	u64
#endif

/* Structure to hold timings for phases of 4-way transmissions. If you are in raw mode (i.e. not doing 4-way at all) then only the first 4 and the last will hold valid data.
 * Likewise if you transmit a broadcast or a 2-way immediate. (Some immedaites are 4-way).
 * All times are in ns from boot.
 */
struct __econet_packet_timings {
	uint64_t	time_on_queue; // Inserted by userspace not kernel
	uint64_t	packet_from_user; // ns from boot when module received the packet and able to deal. If you got told the module was busy, this will be invalid and probably relates to a different packet.
	uint64_t	line_seize; // ns from boot when line successfully seized
	uint64_t	scout_start; // ns from boot when scout tx started. Will be 0 if it never did (as with the rest below).
	uint64_t	scout_end;
	uint64_t	first_ack_start;
	uint64_t	first_ack_end;
	uint64_t	data_start;
	uint64_t	data_end;
	uint64_t	final_ack_start;
	uint64_t	final_ack_end;
};

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
//#ifdef u32
#ifdef ECONETGPIO_KERNEL
			u32 seq;
#else
			uint32_t seq;
#endif

			unsigned char data[ECONET_MAX_PACKET_SIZE-12]; // 20250323 Was -9 (not sure why...)
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
			unsigned char data[ECONET_MAX_PACKET_SIZE-8]; // 20250323 Was -4 (not sure why)
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
//#ifdef u32
#ifdef ECONETGPIO_KERNEL
			u32 seq;
#else
			uint32_t seq;
#endif

			unsigned char data[ECONET_MAX_PACKET_SIZE-9];
};

#define ECONETGPIO_READLED	0x02
#define ECONETGPIO_WRITELED	0x00 // Bit 1 clear
#define ECONETGPIO_LEDON	0x01 
#define ECONETGPIO_LEDOFF	0x00 // Bit 0 clear

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
#define ECONETGPIO_IOC_LED		_IOW(ECONETGPIO_MAGIC, 11, char) /* Turn an activity LED on / off */
#define ECONETGPIO_IOC_NETCLOCK		_IOW(ECONETGPIO_MAGIC, 12, uint32_t) /* Set network clock via hardware PWM on v2r3 boards */
/* No function 13 - bad luck */
#define ECONETGPIO_IOC_READGENTLE	_IO(ECONETGPIO_MAGIC, 14) /* Set module to read mode without a full cleardown */
#define ECONETGPIO_IOC_RESILIENTACK	_IO(ECONETGPIO_MAGIC, 15) /* Send final ACK to client station on wire because we received an ACK from the distant station the client was sending a 4-way to - moves kernel module out of EA_PENDINGFINALACK */
#define ECONETGPIO_IOC_RESILIENCEMODE	_IOW(ECONETGPIO_MAGIC, 16, uint8_t) /* Change in/out of resilient mode - 0 = off, 1 = on */
#define ECONETGPIO_IOC_TWOBYTEMODE	_IOW(ECONETGPIO_MAGIC, 17, uint8_t) /* 0 = 1 byte per IRQ, 1 = 2 bytes per IRQ to/from the ADLC */
#define ECONETGPIO_IOC_GETTIMINGS	_IOR(ECONETGPIO_MAGIC, 18, struct __econet_packet_timings *) /* Retrieve timing data for last packet transmission */
/* The following are for debugging and testing only, and only with interrupts off */
#define ECONETGPIO_IOC_SETA		_IOW(ECONETGPIO_MAGIC, 100, int) /* bit0 is A0, bit1 is A1 */
#define ECONETGPIO_IOC_WRITEMODE	_IOW(ECONETGPIO_MAGIC, 101, int) /* Set / clear R/W and DIR */
#define ECONETGPIO_IOC_SETCS		_IOW(ECONETGPIO_MAGIC, 102, int) /* Set / clear Chip Select */
#define ECONETGPIO_IOC_SETBUS		_IOW(ECONETGPIO_MAGIC, 103, char)
#define ECONETGPIO_IOC_TEST		_IO(ECONETGPIO_MAGIC, 104) /* Put into test mode - interrupts off, ignore all user-space read/write ops. Use RESET to come back to normal ops */
#define ECONETGPIO_IOC_TESTPACKET	_IO(ECONETGPIO_MAGIC, 105)
#define ECONETGPIO_IOC_EXTRALOGS	_IOW(ECONETGPIO_MAGIC, 106, char) /* TUrn on additional logging */
#define ECONETGPIO_IOC_KERNVERS		_IO(ECONETGPIO_MAGIC, 107) /* Obtain Pi version (based on HW GPIO address) (b8-b15), Hardware HAT version (low byte) */
#define ECONETGPIO_IOC_MODULEVERS	_IO(ECONETGPIO_MAGIC, 108) /* Obtain kernel module version: 1 = Original; 2 = Fast */

#define ECONET_GPIO_WRITE 0
#define ECONET_GPIO_READ 1
#define ECONET_GPIO_CS_ON 0
#define ECONET_GPIO_CS_OFF 1
#define ECONET_GPIO_RST_RST 0
#define ECONET_GPIO_RST_CLR 1

#define ECONET_TX_SUCCESS 0
#define ECONET_TX_AWAITSTART 1 /* Module has a packet from userspace, but hasn't started sending it yet */
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
#define ECONET_OVERRUN 0x56 /* Overrun whilst receiving - may be used to signal overrun during receive on part of a 4-way */
#define ECONET_CRCERROR 0x57 /* CRC Error - may also arise during receive phases of a 4-way */
#define ECONET_RXABORT 0x58 /* RX Abort received - may also arise during receive phases of a 4-way */
#define ECONET_TX_NOMEM 0x59 /* Memory allocation failure within kernel module */
#define ECONET_TX_INSUFFICIENTDATA 0x5a /* not enough data in four-way transaction */
#define ECONET_TX_INVALID 0xfc // Attempt to transmit packet which cannot go on a wire - e.g. ACK, NAK, INK
#define ECONET_TX_DATAPROGRESS 0xfd // Flags the fact that we got an ack to the Scout
#define ECONET_TX_INPROGRESS 0xfe
#define ECONET_TX_STARTWAIT 0xff

#define ADVERTISED_MACHINETYPE 0xeeee
#define ADVERTISED_VERSION 0x0301

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
        EA_IDLE = 1, // Waiting for something to happen - more accurately, we're in read mode before a transaction has happened
	EA_R_READSCOUT, // Reading a scout (including 1 & 2-way transaction first packets),
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
        EA_W_WRITEBCAST, // Writing a broadcast. Don't hang about for a reply
	EA_R_PENDINGFINALACK, // We received scout, sent ACK, received data, and are now flagfilling whilst waiting for userspace to tell us whether to send final ack. (And userspace must put us back in read mode if that ACK is not received from the distant station - based on a timeout.)
};


#define __AUN_IS_IDLE(t) (t == EA_IDLE)

#define __AUN_TX_OPERATION(t) \
	(t == EA_W_WRITESCOUT || t == EA_W_READFIRSTACK || t == EA_W_WRITEDATA || t == EA_W_READFINALACK \
	 || t == EA_I_WRITEREPLY || t == EA_I_WRITEIMM || t == EA_W_WRITEBCAST)

#define __AUN_RX_OPERATION(t) \
	(t == EA_R_READSCOUT || t == EA_R_WRITEFIRSTACK || t == EA_R_READDATA || t == EA_R_WRITEFINALACK \
	 t == EA_I_READREPLY || t == EA_R_PENDINGFINALACK)

#endif
