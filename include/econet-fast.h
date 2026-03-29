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

#ifndef __ECONETFASTKERNEL_H__

#define __ECONETFASTKERNEL_H__

#include "econet-gpio.h"

enum __econet_txn {
	EF_ONEWAY = 1,
	EF_TWOWAY,
	EF_FOURWAY
};

enum __econet_dir {
	EF_TX = 1,
	EF_RX
};

#define __ECONET_FAST_MAXPACKET 32768

/*
 * Econet packet struct. Pointers to these structs
 * (i) go on the workqueue for the userspace deferred work queue when
 *     a packet is transmitted or received
 * (ii) are the struct into which a packet *to be* transmitted is put
 *      into the transmit queue.
 *
 * Transmission:
 * For 1-way transaction, scoutdatabytes will be automatically set to length-6 and transmission of whole packet attempted
 * For 2-way transaction, likewise for 1-way. If the receiver does not seize the line, a Line Idle IRQ will be generated 
 *   which will cause an __econet_packet with length 0 to be put on the workqueue with the relevant sr1, sr2 set.
 * For 4-way transaction, a scout will be sent with length scoutlength (which must be >= 6), and the balance of 'length'
 *   will be sent in the data phase.
 *
 * Reception:
 * For 1-way transaction, the module will set scoutlength == length and deliver the whole packet to the workqueue. This will include ACKs received for stations not in our map when monitoring.
 * For 2-way transaction, likewise, but it will also seize the line if the packet is for a station in our map
 * For 4-way transaction, it will receive the scout, set scoutlength == length and deliver the scout into the workqueue. If the packet is for us, it will seize the line and send an ACK, which it will 
 *     notify to the workqueue with the __EF_STATUS_FIRSTACK bit set in p->status; it will then receive a further __econet_packet off the wire (in normal operation) which it will deliver to
 *     the workqueue, and then seize the line and transmit a final ack, which it will notify the workqueue of in the same was as FIRSTACK but with the LASTACK bit set in p->status
 */

struct __econet_packet {
	__econet_txn	txn_type;
	u16		scoutlength; /* Number of bytes on scout, including 6-byte header */
	u16		length; /* Total number of valid bytes in packet, from start to finish */
	u8		sr1; /* What was in SR1 at completion of packet */
	u8		sr2; /* Ditto SR2 */
	u8		status; /* Kernel internal status flags */
	u8		direction; /* See enum */
	u8		aun_state_entry; /* AUN state before last byte received */
	u8		aun_state_exit; /* AUN state after last byte received */
	u8		chip_state_entry; /* Chip state before last byte received */
	u8		chip_state_exit; /* Chip state after last byte received */
	u32		ptr; /* Data pointer into packet[] - only really needs 16 bits, but we use 32 to put the packet[] area on a 32-bit boundary */
	u32		seq; /* AUN sequence number to which this packet pertains */
	u8		packet[__ECONET_FAST_MAXPACKET]; /* Data received/transmitted - all bytes - complete frame */
};

/* 
 * Status flags within __econet_packet.status 
 */

#define __EF_STATUS_TARGET	(1 << 0)	/* This received packet was destined for a station in our station map */
	
/*
 * Macros to access packet data in an __econet_packet struct 
 */

#define __EF_DSTSTN(p)	(p->packet[0])
#define __EF_DSTNET(p)	(p->packet[1])
#define __EF_SRCSTN(p)	(p->packet[2])
#define __EF_SRCNET(p)	(p->packet[3])
#define __EF_CTRL(p)	(p->packet[4])
#define __EF_PORT(p)	(p->packet[5])
#define __EF_DATA(p,n)	(p->packet[6+n])

/* Macro to work out whether 1, 2 or 4-way */

#define __EF_TXN_TYPE(p)	(	(__EF_DSTSTN(p) == 0xFF && __EF_DSTNET(p) == 0xFF) ? EF_ONEWAY :  \
					(__EF_PORT(p) > 0x00 || (__EF_CTRL(p) >= 0x82 && __EF_CTRL(p) <= 0x85)) ? EF_FOURWAY : EF_TWOWAY \
				)

/* And one to work out how many bytes the scout will be - really for use by the process-side code to set scoutlength as needed.
 * A future extension may allow the bridge code to use the AUN padding byte to signal scout length in case new protocols come up.
 * That could extend over trunks as well.
 */

#define __EF_SCOUTBYTES(p,len)	(	( __EF_TXN_TYPE(p) == EF_FOURWAY ) ? (	(__EF_PORT(p) > 0x00) ? 6 : \
									        (__EF_CTRL(p) == 0x82) ? 14 : \
										(__EF_CTRL(p) >= 0x83 && __EF_CTRL(p) <= 0x85) ? 10 : len \
									     ) : len	\
				)

/* Some short versions of the SR status flags */

#define __EF_BIT(n)	(1 << n)
#define __EF_S1_RDA	__EF_BIT(0) /* Received data available */
#define __EF_S1_S2	__EF_BIT(1) /* There's something in SR2 for us */
#define __EF_S1_LOOP	__EF_BIT(2) /* Loop mode enabled */
#define __EF_S1_FLAG	__EF_BIT(3) /* Flag detected on line */
#define __EF_S1_CTS	__EF_BIT(4) /* /CTS positive transition */
#define __EF_S1_UNDERRUN __EF_BIT(5) /* TX underrun */
#define __EF_S1_TDRA	__EF_BIT(6) /* TX FIFO available; if CR2_TDRA=1 then this means frame complete */
#define __EF_S1_IRQ	__EF_BIT(7) /* IRQ state */

#define __EF_S2_AP	__EF_BIT(0)	/* Address present - i.e. first byte of frame */
#define __EF_S2_VALID	__EF_BIT(1)	/* Frame received completely, without error */
#define __EF_S2_IDLE	__EF_BIT(2)	/* Line idle */
#define __EF_S2_ABORT	__EF_BIT(3)	/* RX Abort received */
#define __EF_S2_ERR	__EF_BIT(4)	/* RX CRC Error */
#define __EF_S2_DCD	__EF_BIT(5)	/* /DCD high - i.e. no clock */
#define __EF_S2_OVERRUN __EF_BIT(6)	/* RX Overrun detected */
#define __EF_S2_RDA	__EF_BIT(7)	/* Received data available */

/* Macro to detect errors */

#define __EF_S1_ERRORBITS	(__EF_S1_UNDERRUN)
#define __EF_S2_ERRORBITS	(__EF_S2_ABORT | __EF_S2_ERR | __EF_S2_DCD | __EF_S2_OVERRUN)
#define __EF_SR_ERROR	(	((sr1 & __EF_S1_ERRORBITS) || (sr2 & __EF_S2_ERRORBITS)) ? 1 : 0	)

/* And to detect various states in the ADLC */

#define __EF_RDA	(	(sr1 & __EF_S1_RDA)	)
#define __EF_IRQ	(	(sr1 & __EF_S1_IRQ)	)
#define __EF_TDRA	(	(sr1 & __EF_S1_TDRA)	)
#define __EF_CLOCK	(	!!!(sr2 & __EF_S2_DCD)	)
#define __EF_IDLE	(	(sr2 & __EF_S2_IDLE)	)

/* And to build an ACK */

#define __EF_MK_ACK(r,t)	{ \
					__EF_DSTSTN(t) = __EF_SRCSTN(r); \
					__EF_DSTNET(t) = __EF_SRCNET(r); \
					__EF_SRCSTN(t) = __EF_DSTSTN(r); \
					__EF_SRCNET(t) = __EF_DSTNET(r); \
					t->length = t->scoutlength = 4; \
					t->ptr = 0; \
					t->txn_type = EF_ONEWAY; \
					t->direction = EF_TX; \
				}
/* Externs */

extern struct __econet_packet	*ef_rx, *ef_tx;
extern struct mutex		ef_rx_mutex, ef_tx_mutex; /* Governs read/write to the rx, tx pointers */
extern atomic_t			*ef_busy;
extern kfifo_rec_ptr_2		ef_workqueue;

/* Macros to move things onto the workqueue - use as __EF_QUEUE(rx) or __EF_QUEUE(tx) */

#define __EF_QUEUE(p)	{ \
				mutex_lock(&ef_##p_mutex); \
				kfifo_in(&ef_workqueue, &(ef_##p), sizeof(void *)); \
				ef_##p = NULL; /* Will reallocate when needed */ \
				mutex_unlock(&ef_##p_mutex); \
			}

/* Macro to allocate new internal packet struct */

#define __EF_NEW(p)	{ \
				mutex_lock(&ef_##p_mutex); \
				ef_##p = kzalloc(sizeof(struct __econet_packet), GFP_KERNEL); \
				mutex_unlock(&ef_##p_mutex); \
			}

/* Macro to lock packet mutex */

#define __EF_LOCK(p)	{	mutex_lock(&ef_##p_mutex);	}
#define __EF_UNLOCK(p)	{	mutex_unlock(&ef_##p_mutex);	}

/* Macro to check if packet pointer is valid - must use under lock */

#define __EF_VALID(p)	(	ef_##p != NULL 	)
		
/* Function prototypes for kernel module */

extern inline u8	__ef_seize();		/* Line seize */
extern inline u8	__ef_receive(struct __econet_packet *);		/* Receiver data detected - deal with it */
extern inline u8	__ef_transmit(struct __econet_packet *);	/* Tx IRQ received - deal with it */
extern inline void	__ef_rx_statemachine(struct __econet_packet *);	/* Implement 2 & 4-way RX AUN statemachine based on current packet */
extern inline void	__ef_tx_statemachine(struct __econet_packet *); /* Likewise for TX */

#endif
