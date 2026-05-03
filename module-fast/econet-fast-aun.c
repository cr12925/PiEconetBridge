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

#define ECONETGPIO_KERNEL

#include "../include/econet-gpio.h"

#define EMF_PBUF_FILE	EMF_PBUF_AUN

/* State machine responses */

#define EWAS_DATA_READ 1 /* Packet to readfd queue and wake */
#define EWAS_DATA_WRITE 2 /* Wake writefd */
#define EWAS_NOTHING 0
#define EWAS_BOTH (EWAS_DATA_READ | EWAS_DATA_WRITE) /* Means we got an out of sequence packet and need to signal to WRITE that something failed, but also present a packet to the read fifo */

/* Prototypes */

void econet_workqueue_copy_new_packet(struct __econet_packet *, u8);
void econet_workqueue_build_ack(struct __econet_packet *);
u8 econet_workqueue_respond_new_packet(struct __econet_packet *, u8, u8);
u8 econet_workqueue_aun_statemachine(struct __econet_packet *);

/* 
 * econet_workqueue_copy_new_packet
 *
 * Starts to build an AUN packet in aun_packet and aun_packet_length
 * from whatever is in p - expects p to have been validated for length
 * first!
 *
 */

void econet_workqueue_copy_new_packet(struct __econet_packet *p, u8 aun_state)
{

	void *datastart;

	/* Copy relevant data */

	memcpy(&(econet_data->aun_packet_rx), &(p->data), 4); /* Address bytes */
	__AUN_SRCSTN(econet_data->aun_packet_rx) = __SRCSTN(p);
	__AUN_SRCNET(econet_data->aun_packet_rx) = __SRCNET(p);
	__AUN_DSTSTN(econet_data->aun_packet_rx) = __DSTSTN(p);
	__AUN_DSTNET(econet_data->aun_packet_rx) = __DSTNET(p);
	__AUN_PORT(econet_data->aun_packet_rx) = __PORT(p);
	__AUN_CTRL(econet_data->aun_packet_rx) = __CTRL(p);

	/* Put a sequence number in */

	econet_data->aun_packet_rx.p.seq = (econet_data->aun_seq += 4);
	econet_data->aun_packet_rx.p.padding = 0;

	/* Packet type */

	if (aun_state == EA_I_READREPLY)
		econet_data->aun_packet_rx.p.aun_ttype = ECONET_AUN_IMMREP;
	else if (__IS_FOURWAY(p))
		econet_data->aun_packet_rx.p.aun_ttype = ECONET_AUN_DATA;
	else if (__IS_BROADCAST(p))
		econet_data->aun_packet_rx.p.aun_ttype = ECONET_AUN_BCAST;
	else if (__IS_TWOWAY(p))
		econet_data->aun_packet_rx.p.aun_ttype = ECONET_AUN_IMM;

	/* And the data element if any */

	if (aun_state == EA_I_READREPLY)
	{
		econet_data->aun_packet_len_rx = p->ptr - 4;
		datastart = &(p->data[4]);
	}
	else
	{
		econet_data->aun_packet_len_rx = p->ptr - 6;
		datastart = &(p->data[6]);
	}

	if (econet_data->aun_packet_len_rx > 0)
	{
		memcpy (&(econet_data->aun_packet_rx.p.data),
			datastart,
			econet_data->aun_packet_len_rx);	
	}
}

/*
 * econet_workqueue_correct_reply_source
 *
 * Checks to see if the source of the incoming packet
 * we just received is the destination we just transmitted
 * to and vice versa
 */

inline u8 econet_workqueue_correct_reply_source(struct __econet_packet *p)
{

	u8 ret = 0;

	if (
		__DSTSTN(p) == __AUN_SRCSTN(econet_data->aun_packet_tx)
	&&	__DSTNET(p) == __AUN_SRCNET(econet_data->aun_packet_tx)
	&&	__SRCSTN(p) == __AUN_DSTSTN(econet_data->aun_packet_tx)
	&&	__SRCNET(p) == __AUN_DSTNET(econet_data->aun_packet_tx)
	)
		ret = 1;

	return ret;

}

/* 
 * econet_workqueue_build_ack
 *
 * Builds a 4-byte ACK in its parameter
 * from econet_data->aun_packet
 */

void econet_workqueue_build_ack (struct __econet_packet *p)
{
	__SRCSTN(p) = __AUN_DSTSTN(econet_data->aun_packet_rx);
	__SRCNET(p) = __AUN_DSTNET(econet_data->aun_packet_rx);
	__DSTSTN(p) = __AUN_SRCSTN(econet_data->aun_packet_rx);
	__DSTNET(p) = __AUN_SRCNET(econet_data->aun_packet_rx);

	p->tx = EP_PACKET_TX;
	p->txlen = 4;

}

u8 econet_workqueue_respond_new_packet(struct __econet_packet *p, u8 sr1_errors, u8 sr2_errors)
{
	u8	aun_state, minlength;

	aun_state = econet_get_aunstate();

	/* Errors ? */

	if (
		(sr1_errors || sr2_errors)
	&&	!( /* Ignore rx abort where it's the only error and the packet is the right size */
			(sr2_errors == ECONET_GPIO_S2_RX_ABORT)
		   &&	(	(	aun_state == EA_IDLE && p->ptr == 6 
						&& (__PORT(p) > 0x00 
						    || (__CTRL(p) >= 0x82 && __CTRL(p) <= 0x85) /* Immediate special 4-way */
						   )
				)
		  		||	
				(	(aun_state == EA_W_READFIRSTACK || aun_state == EA_W_READFINALACK)
				   &&	(p->ptr == 4)
				)
			)
		) /* Exclusions! */
	)
	{
		ECONET_NOT_BUSY();
		if (!(aun_state == EA_IDLE && sr1_errors == 0 && sr2_errors == ECONET_GPIO_S2_RX_IDLE)) /* Don't report on innocuous "error" */
			printk ("econet-fast: AUN workqueue responder found errors: SR1 = 0x%02X, SR2 = 0x%02X, AUN state 0x%02X, ptr = 0x%04X\n", sr1_errors, sr2_errors, aun_state, p->ptr);
		
		/* Notify writefd() as necessary */
		
		if (__AUN_TX_OPERATION(aun_state))
			return EWAS_DATA_WRITE;

		return EWAS_NOTHING; /* Just stay where we are */
	}

	minlength = 6;

	if (aun_state == EA_W_READFIRSTACK || aun_state == EA_W_READFINALACK)
		minlength = 4;

	/* Packet should be at least 6 bytes */

	if (p->ptr < minlength)
	{
		printk (KERN_ERR "econet-fast: Runt state 0x%02X packet length 0x%02X received from %3d.%3d to %3d.%3d, sr1 = 0x%02X, sr2 = 0x%02X\n",
			aun_state,
			p->ptr,
			__SRCNET(p),
			__SRCSTN(p),
			__DSTNET(p),
			__DSTSTN(p),
			p->sr1, p->sr2
	       );

		econet_set_aunstate(EA_IDLE);
		econet_set_read_mode();
		ECONET_NOT_BUSY();

		return EWAS_NOTHING;
	}

	/* If it was a scout or 2-way immediate, the
	 * IRQ handler will have gone into flag fill.
	 * (it doesn't if it receives a broadcast or
	 * a final ACK on a 4-way
	 */

	/* NB: IRQ handler should set ECONET_IS_BUSY() */

	econet_workqueue_copy_new_packet(p, econet_get_aunstate());

	if (__IS_BROADCAST(p) || __IS_TWOWAY(p))
	{
		/* Stay in idle and return it to readfd */
		/* IRQ routine will have flag filled if
		 * the immedaite is one that userspace
		 * may respond to
		 */

		if (__IS_TWOWAY(p))
		{
			econet_set_aunstate(EA_I_WRITEREPLY);
		}
		//else
		//{
			ECONET_NOT_BUSY(); /* We need writefd() to think we're not busy if we are doing WRITEREPLY */
		//}

		return EWAS_DATA_READ;
	}
	else if (__IS_FOURWAY(p))
	{
		econet_set_aunstate(EA_R_WRITEFIRSTACK);

		econet_data->txp = econet_alloc_pbuf();

		if (econet_data->txp)
		{
			econet_workqueue_build_ack(econet_data->txp);

			if (econet_seize(1))
			{
				/* Failed. */
				econet_free_pbuf(econet_data->txp);
				econet_data->txp = NULL;
				econet_data->pkt_since_idle = 0;
				printk (KERN_INFO "econet-fast: EA_R_WRITEFIRSTACK failed line seize - abort to EA_IDLE\n");
				econet_set_aunstate(EA_IDLE);
				econet_set_read_mode();
			}
		}
		else
		{
			econet_set_aunstate(EA_IDLE);
			econet_data->pkt_since_idle = 0;

			printk (KERN_ERR "econet-fast: Unable to allocate packet memory for first ACK having received 4-way from %d.%d to %d.%d\n",
				__SRCNET(p),
				__SRCSTN(p),
				__DSTNET(p),
				__DSTSTN(p)
			       );
			econet_set_read_mode();
		}

	}

	return EWAS_NOTHING;
}

/* 
 * Workqueue AUN state machine
 *
 * Works out what we need to do next based
 * on which state we're in. Makes up ACK
 * packets for four ways by allocating device
 * managed memory and putting it in econet_data->txp
 * if necessary.
 *
 * Returns 1 for send to readfd, 2 for send to 
 * writefd, and 0 not to send anywhere except the
 * monitor (if someone's reading it)
 *
 */

u8 econet_workqueue_aun_statemachine(struct __econet_packet *p)
{

#define	EWAS_TX_FINISHED(status) \
	econet_set_tx_status(status); \
	ret = EWAS_DATA_WRITE; /* Signal to writefd */ \
	ECONET_NOT_BUSY(); \
	econet_set_aunstate(EA_IDLE);

	u8	sr1 = p->sr1, sr2 = p->sr2;

	u8 	sr1_errors = 0, sr2_errors = 0;

	u8 	aun_state = econet_get_aunstate();

	u8	count;

	static struct {	u8 aunstate; u8 pkt_since_idle; } aunstatepkts[] =
	{
		{ EA_W_WRITESCOUT, 1 },
		{ EA_W_READFIRSTACK, 2 },
		{ EA_W_WRITEDATA, 3 },
		{ EA_W_READFINALACK, 4 },
		{ EA_R_WRITEFIRSTACK, 2 },
		{ EA_R_READDATA, 3 },
		{ EA_R_WRITEFINALACK, 4 },
		{ EA_I_WRITEREPLY, 1 }, /* This is 1 not 2 because after we get an immediate *in*, we do ECONET_NOT_BUSY() so that writefd() will write, which puts pkt_since_idle back to 0 */
		{ EA_I_READREPLY, 1 }, /* This feels like it should be 2, but 1 is correct because we go back to an idle state after writing an immediate out to the wire */
		{ 0, 0 }
	};

	// printk (KERN_INFO "econet-fast: AUN state %02X, dir %1d, pkt_since_idle = %d, flag fill = %d\n", aun_state, p->tx, p->pkt_since_idle, p->flagfill);

	if (p->tx != EP_PACKET_RX && p->tx != EP_PACKET_TX)
		printk (KERN_INFO "econet-fast: AUN statemachine invoked with unorthodox packet direction: aun_mode = %d, p = %p, sr1 = %02X, s2 = %02X, ptr = %04x, tx = %1X, txlen = 0x%04X\n", econet_data->aun_mode, p, p->sr1, p->sr2, p->ptr, p->tx, p->txlen);

#if 0
	if (aun_state != EA_IDLE && (sr2 & ECONET_GPIO_S2_RX_IDLE))
		printk (KERN_INFO "econet-fast: AUN statemachine detected RX Idle in state 0x%02X\n", aun_state);
#endif
	
	sr1_errors = (sr1 & ( /* Invert CTS? - it'll be high if not clear to send - not sure about this */
		ECONET_GPIO_S1_UNDERRUN	
		// Unclear this is actually needed. | ECONET_GPIO_S1_CTS /* Collision */
		));

	sr2_errors = sr2 & (
		ECONET_GPIO_S2_RX_IDLE
	|	ECONET_GPIO_S2_RX_ABORT
	|	ECONET_GPIO_S2_ERR
	|	ECONET_GPIO_S2_DCD
	|	ECONET_GPIO_S2_OVERRUN
		);

	/* Debug whether pkt_since_idle was right */

	count = 0;

	if (!sr1_errors && !sr2_errors) while (aunstatepkts[count].aunstate)
	{
		if (aunstatepkts[count].aunstate == aun_state && aunstatepkts[count].pkt_since_idle != p->pkt_since_idle)
			printk (KERN_INFO "econet-fast: State machine received packet in AUN state %02X with %d packets since idle, when it should be %d\n",
				aun_state, p->pkt_since_idle, aunstatepkts[count].pkt_since_idle);
		count++;
	}
	
	/* Filter errors */

	if (p->tx == EP_PACKET_RX) 
	{
		sr1_errors = 0;

		if (sr2 & ECONET_GPIO_S2_VALID) /* If FV set, do what ANFS does and pretend the rest of the world is OK */
			sr2_errors = sr2 & ECONET_GPIO_S2_RX_IDLE; /* We still want to know about idle - stops writefd() getting stuck - we can return not listening */
	}
	else
	{
		sr2_errors &= (ECONET_GPIO_S2_DCD | ECONET_GPIO_S2_RX_IDLE);
	}

	/* If we should have gone into flag fill and didn't, barf the packet */

	if (aun_state == EA_W_READFIRSTACK && p->flagfill != 1 && !(__IS_BROADCAST(p)) && !(sr1_errors == 0 || sr2_errors == 0))
	{
		printk (KERN_INFO "econet-fast: First ACK received but IRQ handler didn't go into flagfill. pkt_since_idle was %d\n", p->pkt_since_idle);
		econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
		p->tx_flags |=  EP_IRQHANDLER_FAILED;
		econet_set_aunstate(EA_IDLE); /* Don't need to check if in aun-mode - means nothing if we're not */
		ECONET_NOT_BUSY();
		return EWAS_DATA_WRITE;	
	}

	/* See if we had an IRQ Handler fail */

	if (p->tx_flags & EP_IRQHANDLER_FAILED) /* IRQ handler got called when ADLC not flagging IRQ! */
	{
		u8 ret = EWAS_NOTHING;

		switch (aun_state)
		{
			case EA_W_WRITESCOUT:
			case EA_W_READFIRSTACK:
			case EA_W_WRITEDATA:
			case EA_I_WRITEIMM:
			case EA_I_WRITEREPLY:
				ret = EWAS_DATA_WRITE; /* Notify the write side */
				break;
			case EA_R_WRITEFIRSTACK:
			case EA_R_READDATA:
			case EA_R_WRITEFINALACK:
				ret = EWAS_DATA_READ;
				break;
			/* EA_IDLE - do nothing */
			/* EA_W_READFINALACK - Handled below */
		}

		if (ret == EWAS_DATA_WRITE)
			econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);

		econet_set_read_mode();
		econet_data->pkt_since_idle = 0;
		econet_set_aunstate(EA_IDLE); /* Back to idle */

		if (ret == EWAS_NOTHING) ECONET_NOT_BUSY();

		return ret; /* Tell the workqueue what to do */
	}

	/* Deal with runts */

	if (p->ptr < 4 && !(p->ptr == 0 && p->tx == EP_PACKET_RX)
		&& !((aun_state != EA_W_READFINALACK && (p->tx_flags & EP_IRQHANDLER_FAILED))) /* Because we handle these specially in the EA_W_READFINALACK section below because we seem to get problems receiving them */
			) /* Ignore "runts" which are just signalling packets */
	{
		u8 	count;
		printk (KERN_ERR "econet-fast: Runt %s packet length 0x%02X at %p received by workqueue from %3d.%3d to %3d.%3d, sr1 = 0x%02X, sr2 = 0x%02X, aun state = 0x%02X\n",
				p->tx == EP_PACKET_RX ? "RX" : "TX",
				p->ptr,
				p,
				__SRCNET(p),
				__SRCSTN(p),
				__DSTNET(p),
				__DSTSTN(p),
				p->sr1, p->sr2,
				aun_state
		       );

		for (count = 0; count < (p->ptr > 3 ? 4 : p->ptr); count++)
			printk (KERN_ERR "econet-fast: Byte %d = 0x%02X\n", count, p->data[count]);

		if (__AUN_TX_OPERATION(aun_state))
			econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);

		econet_set_aunstate(EA_IDLE); /* Don't need to check if in aun-mode - means nothing if we're not */
		ECONET_NOT_BUSY();
		
		if (__AUN_TX_OPERATION(aun_state))
			return EWAS_DATA_WRITE;

		return EWAS_NOTHING;
	}

	/* Check for AUN Line idle where it's a problem */

	/* TODO: Remove the checks in the rest of the state machine */
	
	if (econet_data->aun_mode && (sr2_errors & ECONET_GPIO_S2_RX_IDLE))
	{
		if (p->tx == EP_PACKET_RX && p->ptr >= 4 && !(ECONET_DEV_STATION(econet_stations, __DSTNET(p), __DSTSTN(p)))) /* Not for us */
		{
			ECONET_NOT_BUSY();
			econet_set_aunstate(EA_IDLE);
			return EWAS_NOTHING;
		}

		if (
			(p->tx == EP_PACKET_TX && econet_data->aun_packet_tx.p.aun_ttype != ECONET_AUN_BCAST && aun_state == EA_W_WRITESCOUT) /* Not listening */
		||	(p->tx == EP_PACKET_RX && aun_state == EA_W_READFIRSTACK)
		||	(p->tx == EP_PACKET_TX && aun_state == EA_I_WRITEIMM) /* Not sure we ever go into this state now */
		||	(p->tx == EP_PACKET_RX && aun_state == EA_I_READREPLY)
		)
		{
			econet_set_aunstate(EA_IDLE);
			econet_set_tx_status(ECONET_TX_NOTLISTENING);
			if (econet_data->extralogs)
				printk (KERN_INFO "econet-fast: Resetting state machine after idle on reading first ACK or immediate reply\n");
			return EWAS_DATA_WRITE;
		}
		else if (
			(p->tx == EP_PACKET_TX && aun_state == EA_W_WRITEDATA) /* Failed handshake */
		)
		{
			econet_set_aunstate(EA_IDLE);
			econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
			if (econet_data->extralogs)
				printk (KERN_INFO "econet-fast: Resetting state machine after idle on writing data / waiting for final ACK\n");
			return EWAS_DATA_WRITE;
		}
		else if (
			(p->tx == EP_PACKET_TX && aun_state == EA_R_WRITEFIRSTACK)
		||	(p->tx == EP_PACKET_RX && aun_state == EA_R_READDATA)
		)
		{
			econet_set_aunstate(EA_IDLE);
			econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
			if (econet_data->extralogs)
				printk (KERN_INFO "econet-fast: Resetting state machine after idle on writing first ACK / waiting for data\n");
			return EWAS_DATA_WRITE;
		}
	}

	if (econet_data->aun_mode 
		&& (p->tx == EP_PACKET_TX 
			|| (p->ptr >= 4 && ECONET_DEV_STATION(econet_stations, __DSTNET(p), __DSTSTN(p)))
		   )
	    ) /* Only change state if in AUN mode, otherwise just deal with raw packet */
	{


		if (p->tx == EP_PACKET_TX && __AUN_TX_OPERATION(aun_state)) /* deal with tx errors */
		{
			if (sr1_errors)
			{
				u8 abort = 0;

				if (sr1_errors & ECONET_GPIO_S1_UNDERRUN)
				{
					printk (KERN_ERR "econet-fast: TX underrun on frame size 0x%04X bytes at ptr = 0x%04X\n", p->txlen, p->ptr);
					econet_set_tx_status(ECONET_TX_UNDERRUN);
					abort = 1;
				}
				else if (!(sr1 & ECONET_GPIO_S1_TDRA)) /* Not frame complete; otherwise not fussed about collision */
				{
					printk (KERN_ERR "econet-fast: TX collision on frame size 0x%04X bytes at ptr = 0x%04X\n", p->txlen, p->ptr);
					econet_set_tx_status(ECONET_TX_COLLISION);
					abort = 1;
				}

				if (abort)
				{
					econet_set_aunstate(EA_IDLE);
					econet_set_read_mode();
					return EWAS_DATA_WRITE;
				}
			}

			if (sr2_errors & ECONET_GPIO_S2_DCD)
			{
				printk (KERN_ERR "econet-fast: Lost clock during tx frame; resetting state machine\n");
				econet_set_tx_status(ECONET_TX_NOCLOCK);
				econet_set_aunstate(EA_IDLE);
				econet_set_read_mode();
				return EWAS_DATA_WRITE;
			}

		}

		/* Check for underrun or collision on transmission of ACK */

		if (p->tx == EP_PACKET_TX && 
			(
				(aun_state == EA_R_WRITEFIRSTACK)
			||	(aun_state == EA_R_WRITEFINALACK)
			)
			&&
			(sr1_errors)
		   )
		{
			printk (KERN_INFO "econet-fast: Resetting state machine after error during first or final ACK tx\n");
			econet_set_aunstate(EA_IDLE); /* Abandon */
			return EWAS_NOTHING;
		}

		/* Check for no clock other than during a TX operation to the ADLC, which is caught above */

		if (sr2_errors & ECONET_GPIO_S2_DCD)
		{
			if (__AUN_TX_OPERATION(aun_state))
			{
				printk (KERN_INFO "econet-fast: Resetting state machine after loss of clock (TX)\n");
				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_NOCLOCK);
				return EWAS_DATA_WRITE;
			}
			else /* No clock in idle state or during AUN read operation */
			{
				printk (KERN_INFO "econet-fast: Resetting state machine after loss of clock (RX or idle)\n");
				econet_set_read_mode();
				econet_set_aunstate(EA_IDLE);
				ECONET_NOT_BUSY();
				return EWAS_NOTHING; /* Do nothing. */
			}
		}

		/* Did we get line idle in a state where it's an error ? */

		if	(p->tx == EP_PACKET_RX 
			&&	(sr2_errors & ECONET_GPIO_S2_RX_IDLE)
			)
		{

			/*
			  printk (KERN_INFO "econet-fast: RX Idle detector test: aun_state 0x%02X, sr1 = 0x%02X, sr2 = 0x%02X (errors 0x%02X), p->tx = %02X, p->ptr = %04X\n",
					aun_state, p->sr1, p->sr2, sr2_errors, p->tx, p->ptr);
					*/

			if (econet_data->aun_mode) switch (aun_state)
			{
				/* Fall throughs deliberate - for testing */

				case EA_W_READFIRSTACK:
					{
						//if (p->ptr < 4)
						{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_NOTLISTENING);
							printk (KERN_INFO "econet-fast: Resetting state machine after idle on reading first ACK\n");
							return EWAS_DATA_WRITE;
						}
					} break;
				case EA_W_WRITESCOUT: /* Not listening - if it's a data packet or 2-way immediate (could be broadcast) */
					{
						if (econet_data->aun_packet_tx.p.aun_ttype == ECONET_AUN_DATA || econet_data->aun_packet_tx.p.aun_ttype == ECONET_AUN_IMM)
						{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_NOTLISTENING);
							printk (KERN_INFO "econet-fast: Resetting state machine after idle on writing scout\n");
							return EWAS_DATA_WRITE;
						}

						/* If it was a broadcast or an immediate reply, the receipt of the TX frame below will trigger a return to idle */

						/* Which means that if we get Idle during writescout, it's a failed TX - probably line seize failure */

						econet_set_aunstate(EA_IDLE);
						econet_set_tx_status(ECONET_TX_COLLISION);
						printk (KERN_INFO "econet-fast: RX Idle during Scout write - likely collision. Returning to idle.\n");
						return EWAS_DATA_WRITE;

						
					} break;
#if 1 /* 20260411 I think sometimes clients put a line idle before the final ACK and it confuses the hell out of the statemachine - Except that when they just don't send an ACK at all, everything falls out of bed, so lets not comment this out*/
				case EA_W_READFINALACK:
					{
						if (p->ptr < 4)
						{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
							printk (KERN_INFO "econet-fast: Resetting state machine after idle on reading final ACK\n");
							return EWAS_DATA_WRITE;
						}
					} break;
#endif
				case EA_W_WRITEDATA: /* Net error */
					{
							printk (KERN_INFO "econet-fast: Resetting state machine after idle during 4-way data phase transmission\n");
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL); /* For now. Do we have net error in our list? */
							return EWAS_DATA_WRITE;
					} break;
				/* 20260404 See if we need to detect a line idle on EA_R_READDATA as well? Fall through */
				case EA_R_READDATA:
				case EA_R_WRITEFIRSTACK: /* Handshake failure - no data frame (phase 3) is coming */
					{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL); /* For now. Do we have net error in our list? */
							return EWAS_DATA_WRITE;
					} break;
				/* No equivalent for EA_R_WRITEFINALACK because we expect idle in that case */
			}
		}
			

		/* First, handle the idle state. */

		if (aun_state == EA_IDLE && p->tx == EP_PACKET_RX) /* Something arrived off the line - shouldn't be getting a TX'd packet in idle, so that's an error */
		{
			if (!ECONET_DEV_STATION(econet_stations, __DSTNET(p), __DSTSTN(p))) /* Not for us */
			{
				ECONET_NOT_BUSY();
				return EWAS_NOTHING;
			}

			return econet_workqueue_respond_new_packet(p, sr1_errors, sr2_errors);
		}
		
		/* Now the two states for immediates (reception of a
		 * fresh 2-way immediate happens under EA_IDLE) so we
		 * only need deal with
		 * - Reading a reply to an immediate we sent
		 * - Writing a reply to an immediate we received
		 *
		 * Note that writing a fresh 2-way immediate is handled under
		 * EA_W_WRITESCOUT.
		 *
		 */

		else if (aun_state == EA_I_READREPLY && p->tx == EP_PACKET_RX)
		{
			u8	is_immrep = 0;
			u32	seq;

			if (sr1_errors || sr2_errors)
			{
				/* If not listening, we don't signal data write, we'll have done that on completion of TX of the original immediate. What we do is set the TX status so user space can poll it to see if it needs to send an INK */

				if (sr2_errors & ECONET_GPIO_S2_RX_IDLE) /* Not listening */
					econet_set_tx_status(ECONET_TX_NOTLISTENING);

				ECONET_NOT_BUSY();
				econet_set_aunstate(EA_IDLE);
				return EWAS_NOTHING;
			}

			/* Check src/dst match - flag as immrep if they do */

			if (econet_workqueue_correct_reply_source(p))
				is_immrep = 1;

			seq = econet_data->aun_packet_tx.p.seq; /* Preserve since we are about to overwrite aun_packet */

			if (is_immrep)
			{
				// printk (KERN_ERR "econet-fast: Immediate 2-way reply found from %d.%d\n", p->data[1], p->data[0]);
				econet_workqueue_copy_new_packet(p, aun_state);
				econet_data->aun_packet_rx.p.aun_ttype = ECONET_AUN_IMMREP;
				econet_data->aun_packet_rx.p.seq = seq; /* Restore */
				return EWAS_DATA_READ;
			}
			else
			{
				/* Dump it - we've no idea what it is */

				ECONET_NOT_BUSY();
				return EWAS_NOTHING;

			}
		}
		else if (aun_state == EA_I_WRITEREPLY && p->tx == EP_PACKET_TX)
		{
			/* TX Errors checked above */

			/* Back to idle and signal writefd() we've done */

			econet_set_aunstate(EA_IDLE);
			econet_set_tx_status(ECONET_TX_SUCCESS);

			econet_data->pt.scout_start = p->timing_start;
			econet_data->pt.scout_end = p->timing_end;

			return EWAS_DATA_WRITE;
		}

		/* Next we deal with writing a scout - which for these
		 * purposes includes ANY first packet we transmit, whether
		 * it's a 1-way, 2-way or 4-way transaction */

		else if (aun_state == EA_W_WRITESCOUT && p->tx == EP_PACKET_TX)
		{
			/* TO DO - This state will cover all first packet
			 * writes including 2-way immediates and broadcasts
			 *
			 * Hmm. Don't we deal with WRITEIMM above?
			 *
			 * That probably wants changing. And moving here.
			 *
			 */

			econet_data->pt.scout_start = p->timing_start;
			econet_data->pt.scout_end = p->timing_end;

			/* General TX errors are checked above */

			if (__IS_BROADCAST(p))
			{
				//printk (KERN_INFO "econet-fast: Finished broadcast transmission, return to IDLE\n"); /* See if that's happening! */
				econet_set_tx_status(ECONET_TX_SUCCESS);
				econet_set_aunstate(EA_IDLE);
				return EWAS_DATA_WRITE;
			}
			else if (__IS_TWOWAY(p))
			{
				//printk (KERN_INFO "econet-fast: Finished 2-way transmission, move to EA_I_READREPLY, set TX STATUS = Success\n"); /* See if that's happening! */
				econet_set_tx_status(ECONET_TX_SUCCESS);
				econet_set_aunstate(EA_I_READREPLY);
				return EWAS_DATA_WRITE;
			}
			else if (__IS_FOURWAY(p))
			{
				econet_set_aunstate(EA_W_READFIRSTACK);
				if (sr2 & ECONET_GPIO_S2_RX_IDLE) /* Not listening */
				{
					econet_set_aunstate(EA_IDLE);
					econet_set_tx_status(ECONET_TX_NOTLISTENING);
					printk (KERN_INFO "econet-fast: Resetting state machine after idle writing scout\n");
					return EWAS_DATA_WRITE;
				}
				return EWAS_NOTHING;
			}
			else
			{
				printk (KERN_INFO "econet-fast: Unknown packet type appears to have been transmitted - neither broadcast, nor two-way nor four-way scout!\n");
				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_INVALID);
				return EWAS_DATA_WRITE;
			}
		}

		/* Next we deal with the remaining three phases of writing
		 * a 4-way
		 */

		else if (aun_state == EA_W_READFIRSTACK && p->tx == EP_PACKET_RX)
		{
			u8 	correct_source;

			if (p->ptr != 4 && (sr2_errors & ECONET_GPIO_S2_RX_IDLE)) /* Another form of "not listening" */
			{
				printk (KERN_INFO "econet-fast: Not listening whilst awaiting first ACK from station\n");
				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_NECOUTEZPAS);
				return EWAS_DATA_WRITE;
			}

			correct_source = econet_workqueue_correct_reply_source(p);

			econet_data->pt.first_ack_start = p->timing_start;
			econet_data->pt.first_ack_end = p->timing_end;

			if (sr1_errors || (sr2_errors && !(correct_source && p->ptr == 4))) /* Ignore errors if from the right place and 4 bytes */
			{
				if (sr2_errors & ECONET_GPIO_S2_RX_IDLE) /* Not listening */
				{
					econet_set_tx_status(ECONET_TX_NOTLISTENING);
				}
				else if (sr2_errors & ECONET_GPIO_S2_DCD) /* No clock */
				{
					econet_set_tx_status(ECONET_TX_NOCLOCK);
				}
				else if (sr2_errors)
				{
					econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				}

				return EWAS_DATA_WRITE;
			}

			/* Was it an ACK and was it from the right place? */

			if (correct_source)
			{
				u16	data_balance = 0;
				u8	seized = 0;

				if (p->ptr == 4) /* Correct source and correct length */
				{
					/* How much data didn't go on the scout? */
	
					
	data_balance =
						econet_data->aun_packet_len_tx
					-	econet_data->aun_packet_tx.p.padding;
	
					if (data_balance < 1 || data_balance > ECONET_MAX_PACKET_SIZE)
					{
						printk (KERN_ERR "econet-fast: Unlawful TX frame size (0x%04X)! (aun_packet_len_tx = 0x%04X, padding = 0x%02X\n", data_balance, econet_data->aun_packet_len_tx, econet_data->aun_packet_tx.p.padding);
						/* Abort */
						econet_set_tx_status (ECONET_TX_INVALID);
						econet_set_aunstate(EA_IDLE);
						econet_set_read_mode();
						return EWAS_DATA_WRITE;
					}
	
					/* Make up the data packet and trigger */
					/* Note that number of scout data bytes
				 	* will have been stored in padding for us
				 	*/
	
					//econet_data->txp = emalloc(4 + data_balance);
					econet_data->txp = econet_alloc_pbuf();
	
					if (!econet_data->txp)
					{
						econet_set_tx_status(ECONET_TX_NOMEM);
						econet_set_aunstate(EA_IDLE);
						econet_set_read_mode();
						return EWAS_DATA_WRITE;
					}
	
					/* Copy addressing */
	
					__SRCNET(econet_data->txp) = __DSTNET(p);
					__SRCSTN(econet_data->txp) = __DSTSTN(p);
					__DSTNET(econet_data->txp) = __SRCNET(p);
					__DSTSTN(econet_data->txp) = __SRCSTN(p);
	
					/* Copy data - padding byte tells us 
				 	* how much went on the scout */
					/* We checked there was enough data, above,
				 	* although writefd() also validates this.
				 	*/
	
					memcpy (&(econet_data->txp->data[4]),
						&(econet_data->aun_packet_tx.p.data[econet_data->aun_packet_tx.p.padding]),
						data_balance);
					
					econet_data->txp->txlen = data_balance + 4;
	
					// printk (KERN_INFO "econet-fast: Move to EA_W_WRITEDATA; chip state is %d\n", econet_get_chipstate());
	
					econet_set_aunstate(EA_W_WRITEDATA);
	
					if ((seized = econet_seize(1))) /* NB Kernel module should have put us in flag fill */
					{
						/* Failed. */
						printk (KERN_ERR "econet-fast: Failed to seize line for 4-way data phase: frame length 0x%04X\n", p->txlen);
						econet_set_aunstate(EA_IDLE);
						econet_set_tx_status(seized);
						econet_set_read_mode();
						return EWAS_DATA_WRITE; /* Notify userspace writefd so it can return and report error. This will free the txp */
					}
				}
				else /* Correct source, wrong length - e.g. we sent a scout for port &XX, and there was no idle, but the sender was sending us a scout in reply instead of an ACK */
				{
					printk (KERN_INFO "econet-fast: Expected first ACK from %d.%d but got something else instead - signal failure to writefd()\n",
						__SRCNET(p), __SRCSTN(p));
					econet_set_aunstate(EA_IDLE);
					econet_set_tx_status(ECONET_TX_NOTLISTENING); /* This is good enough if we didn't get a first ACK */
					econet_set_read_mode();
					return EWAS_DATA_WRITE; /* Notify userspace writefd so it can return and report error */
					
				}
			}
			else /* Not correct reply source */
			{
				/* Signal handshake failure and treat as
				 * new incoming. Return a status which
				 * will cause the writer and the reader to
				 * be awoken if the incoming packet is 
				 * something to go on the read queue at this
				 * stage.
				 */

				if (p->ptr == 4)
				{
					printk (KERN_ERR "econet-fast: 4-way TX begun and first ACK expected from %d.%d (to %d.%d) but received from %d.%d (to %d.%d)!\n",
						__AUN_DSTNET(econet_data->aun_packet_tx),
						__AUN_DSTSTN(econet_data->aun_packet_tx),
						__AUN_SRCNET(econet_data->aun_packet_tx),
						__AUN_SRCSTN(econet_data->aun_packet_tx),
						__SRCNET(p),
						__SRCSTN(p),
						__DSTNET(p),
						__DSTSTN(p)
				       );
				}
				else
				{
					printk (KERN_ERR "econet-fast: Expecting ACK from %d.%d but got a longer frame from %d.%d\n",
						__AUN_DSTNET(econet_data->aun_packet_tx),
						__AUN_DSTSTN(econet_data->aun_packet_tx),
						__SRCNET(p),
						__SRCSTN(p)
					);
				}

				econet_set_read_mode(); /* We want to drop flag fill */
				econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				econet_set_aunstate(EA_IDLE);

				// return ((p->ptr > 4) ? econet_workqueue_respond_new_packet(p, sr1_errors, sr2_errors) : 0) | EWAS_DATA_WRITE; /* Process new frame if it was longer than 4 bytes */
				return EWAS_DATA_WRITE;
			}

		}
		else if (aun_state == EA_W_WRITEDATA && p->tx == EP_PACKET_TX)
		{

			econet_data->pt.data_start = p->timing_start;
			econet_data->pt.data_end = p->timing_end;

			if (sr2 & ECONET_GPIO_S2_RX_IDLE) /* Net error */
			{
				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				printk (KERN_INFO "econet-fast: Resetting state machine after idle on writing 4-way data phase\n");
				return EWAS_DATA_WRITE;
			}

			/* TX Underrun and no clock are checked above */

			/* Otherwise looks like we did a successful data TX */

			econet_set_aunstate (EA_W_READFINALACK);

			/* Hard IRQ handler will have gone to read mode */

			return EWAS_NOTHING;
		}
		else if (aun_state == EA_W_READFINALACK && p->tx == EP_PACKET_RX)
		{

			econet_data->pt.final_ack_start = p->timing_start;
			econet_data->pt.final_ack_end = p->timing_end;

			/* Correct length & source ? */

			if (/* BODGE: Accept any old rubbish if it's from the right place p->ptr == 4 && */ econet_workqueue_correct_reply_source(p))
			{
			
				/* Signal successful TX */

				econet_set_tx_status(ECONET_TX_SUCCESS);
				econet_set_aunstate(EA_IDLE);
				return EWAS_DATA_WRITE;
			}
			else
			{
				/* Signal a handshake failure and treat as start of new txn */
				econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				return econet_workqueue_respond_new_packet(p, sr1_errors, sr2_errors) | EWAS_DATA_WRITE;
			}

		}

		/* Now we'll handle the three remaining states of
		 * receiving a 4-way
		 */

		else if (aun_state == EA_R_WRITEFIRSTACK && p->tx == EP_PACKET_TX)
		{
			/* First, look for errors */

			if ((sr2_errors & ECONET_GPIO_S2_DCD)) /* TX Underrun or no clock */
			{
				/* Abandon */

				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				if (sr2_errors & ECONET_GPIO_S2_DCD)
					econet_set_tx_status(ECONET_TX_NOCLOCK);
				printk (KERN_ERR "econet-fast: Aborted 4-way read when writing first ACK: loss of clock\n");
				return EWAS_DATA_WRITE; /* Tell userspace it all fell in a heap */
			}
			else
			{

				/* Apparently successful TX of ACK */

				econet_set_aunstate (EA_R_READDATA);
			}

			return EWAS_NOTHING;
		}
		
		else if (aun_state == EA_R_READDATA && p->tx == EP_PACKET_RX)
		{
			/* Check for errors */

			if (sr2_errors)
			{
				/* Just abandon */
				
				printk (KERN_INFO "econet-fast: Abandoned 4-way RX on errors (SR2 = 0x%02X) reading data phase\n", sr2_errors);

				ECONET_NOT_BUSY();
				econet_set_aunstate(EA_IDLE);
				econet_set_read_mode(); /* I don't think we should need this, but perhaps we do */

				/* No tx status to set - this is a receive state */
			}
			else
			{
				/* Collect our data if it was from the right place, and treat as new packet if not */

				/* Note, we don't use the ACK src/dst check because it will check the wrong way round for a receive in a data phase. */

				/* The IDLE routine will have started building an AUN packet with the original src/dst pairs in it */
				if (
					__SRCSTN(p) == __AUN_SRCSTN(econet_data->aun_packet_rx)
				&& 	__SRCNET(p) == __AUN_SRCNET(econet_data->aun_packet_rx)
				&&	__DSTSTN(p) == __AUN_DSTSTN(econet_data->aun_packet_rx)
				&& 	__DSTNET(p) == __AUN_DSTNET(econet_data->aun_packet_rx)
				)
				{
					/* Copy remaining data to AUN */

					memcpy (&(econet_data->aun_packet_rx.p.data[econet_data->aun_packet_rx.p.padding]),
						&(p->data[4]),
						p->ptr-4); /* Was p->ptr, but surely that copies 4 bytes too much? */

					/* Update aun_packet_len */

					econet_data->aun_packet_len_rx += p->ptr - 4;

					econet_set_aunstate(EA_R_WRITEFINALACK);

					/* Build Ack */

					econet_data->txp = econet_alloc_pbuf();

					if (!econet_data->txp)
					{
						printk (KERN_ERR "econet-fast: Unable to allocate ACK storage when transitioning to EA_R_WRITEFINALACK\n");

						econet_set_aunstate(EA_IDLE);
						econet_set_read_mode();
						ECONET_NOT_BUSY();
					}
					else
					{
						u8 seized;

						econet_workqueue_build_ack(econet_data->txp);

						if ((seized = econet_seize(1)))
						{
							printk (KERN_INFO "econet-fast: Failed to seize line to transmit final ACK\n");
							/* But we could return the data anyway - 20260502 we probably shouldn't now we've sorted out our flag fill issue */
							econet_set_aunstate(EA_IDLE);
							econet_set_read_mode();
							econet_free_pbuf(econet_data->txp);
							econet_data->txp = NULL;
							ECONET_NOT_BUSY();
						}
					}

				}
				else /* Not from the correct place! */
				{
					printk (KERN_INFO "econet-fast: Received packet %d.%d to %d.%d length %d when was expecting data phase packet from %d.%d to %d.%d\n",
						__SRCNET(p),
						__SRCSTN(p),
						__DSTNET(p),
						__DSTSTN(p),
						p->ptr,
						__AUN_SRCNET(econet_data->aun_packet_rx),
						__AUN_SRCSTN(econet_data->aun_packet_rx),
						__AUN_DSTNET(econet_data->aun_packet_rx),
						__AUN_DSTSTN(econet_data->aun_packet_rx)
					       );

					return econet_workqueue_respond_new_packet(p, sr1_errors, sr2_errors);

				}
			}

			return EWAS_NOTHING;
		}

		else if (aun_state == EA_R_WRITEFINALACK && p->tx == EP_PACKET_TX)
		{
			/* We can return the data whatever happened
			 * really, because we've got it.
			 */

			econet_set_aunstate(EA_IDLE);
			return EWAS_DATA_READ;	
		}

		/* And anything else is an anomaly I think. */

		else /* Unhandled */
		{
			printk (KERN_ERR "econet-fast: AUN state machine called with AUN state 0x%02X and packet direction %02d, sr1 = %02X, sr2 = %02X, txlen = 0x%04X, ptr = 0x%04X, tx_flags = %02X\n",
					aun_state,
					p->tx,
					p->sr1,
					p->sr2,
					p->txlen,
					p->ptr,
					p->tx_flags);
			econet_set_aunstate(EA_IDLE);
			ECONET_NOT_BUSY();
			return EWAS_NOTHING;
		}
	}
	else if (econet_data->aun_mode == 0)  /* Raw mode - just copy incoming packets to the aun area and
		flag the length
		*/
	{
		if (p->tx == EP_PACKET_RX)
		{
			if (p->ptr > 0)
			{
				memcpy(&(econet_data->aun_packet_rx),
					p->data,
					p->ptr);
	
				econet_data->aun_packet_len_rx = p->ptr; /* Total length, not just data, in raw mode */
	
				return EWAS_DATA_READ;
			}

			ECONET_NOT_BUSY();
			return EWAS_NOTHING;
		}
		else
		{
			printk (KERN_INFO "econet-fast: Setting raw-mode tx status\n");

			if (sr1_errors || sr2_errors)
			{
				if (sr1_errors & ECONET_GPIO_S1_UNDERRUN)
				{
					econet_set_tx_status(ECONET_TX_UNDERRUN);
				}
				else if (sr2_errors & ECONET_GPIO_S2_DCD)
				{
					econet_set_tx_status(ECONET_TX_NOCLOCK);
				}
				else 
				{
					econet_set_tx_status(ECONET_TX_JAMMED);
				}
			}
			else
				econet_set_tx_status(ECONET_TX_SUCCESS);

			return EWAS_DATA_WRITE;

		}
	}

	return EWAS_NOTHING;

}


/*
 * Process space workqueue handler 
 */

void econet_workqueue_handler (struct work_struct *work)
{
	eco_work_t	*my_work = container_of(work, eco_work_t, econet_work); /* Find parent */
	struct __econet_packet *p;

	u8	statemachine_response;

	if (!my_work)
	{
		printk (KERN_ERR "econet-fast: workqueue handler called but cannot find parent data!\n");
		return;
	}

	p = my_work->p;

	if (!p)
	{
		/* Barf */
		printk (KERN_ERR "econet-fast: workqueue handler called without any packet data!\n");
		econet_free_workbuf(my_work);
		return;
	}
	
	if (p->tx != EP_PACKET_RX && p->tx != EP_PACKET_TX)
		printk (KERN_INFO "econet-fast: workqueue handler invoked with unorthodox packet direction: aun_mode = %d, my_work->p = %p, sr1 = %02X, s2 = %02X, ptr = %04x, tx = %1X, txlen = 0x%04X\n", econet_data->aun_mode, my_work->p, my_work->p->sr1, my_work->p->sr2, my_work->p->ptr, my_work->p->tx, my_work->p->txlen);

	my_work->p->lastseen = EMF_PBUF_LASTSEEN_WORKQUEUE_ENTRY;

	// printk (KERN_INFO "econet-fast: workqueue handler invoked with aun_mode = %d, my_work->p = %p, sr1 = %02X, s2 = %02X, ptr = %04x, tx = %1X, txlen = 0x%04X\n", econet_data->aun_mode, my_work->p, my_work->p->sr1, my_work->p->sr2, my_work->p->ptr, my_work->p->tx, my_work->p->txlen);

	statemachine_response = econet_workqueue_aun_statemachine(p);

	// printk (KERN_INFO "econet-fast: statemachine response 0x%02X\n", statemachine_response);

	spin_lock(&(econet_data->open_count_spinlock));

	if (econet_data->open_count) /* The userspace bridge code or something of that nature has our device open */
	{
		// If we have finished tx-ing a packet, interruptible_wake_up(&(econet_data->tx_queue)); 

		/* Have we finished an AUN tx operation, for good or ill ? */

		if (statemachine_response) /* Unless it was "nothing", signal not busy */
		{
			ECONET_NOT_BUSY();
		}

		if (statemachine_response & EWAS_DATA_WRITE)
		{
			u8	txstatus = econet_get_tx_status();

			econet_data->pkt_since_idle = 0;
			econet_data->tx_status_valid = txstatus | 0x8000; /* Top bit makes it valid */
			wake_up_interruptible(&(econet_data->tx_queue));
		}

		/* Have we finished an AUN rx operation successfully ? */

		if (statemachine_response & EWAS_DATA_READ)
		{
			/* So there should be a packet in aun_packet, with
			 * data length aun_packet_len, or that's the 
			 * overall length in raw mode
			 */

			econet_data->pkt_since_idle = 0;

			if (!kfifo_in(&(econet_data->readfd_fifo), &(econet_data->aun_packet_rx), econet_data->aun_packet_len_rx + (econet_data->aun_mode ? 12 : 0)))
			{
				printk (KERN_ERR "econet-fast: Error putting packet onto RX FIFO, length 0x%04X, %s mode\n",
							econet_data->aun_packet_len_rx,
							econet_data->aun_mode ? "AUN" : "RAW");
			}
			else
			{
				/* Wake up the poller */

				wake_up (&(econet_data->rx_queue));
			}
		}
		
	}

	spin_unlock(&(econet_data->open_count_spinlock));

	spin_lock(&(econet_data->monitor_count_spinlock));

	if (econet_data->monitor_count) /* Someone is looking at the monitor */
	{
		/* Copy only the used portion of the packet into a small
		 * kmalloc'd buffer for the monitor fifo. This decouples
		 * the pbuf pool from monitor userspace drain rate — the
		 * pbuf is freed immediately below regardless. */

		size_t mon_len = sizeof(struct __econet_packet) - (ECONET_MAX_PACKET_SIZE - my_work->p->ptr);
		struct __econet_packet *mon = kmalloc(mon_len, GFP_KERNEL);

		if (mon)
		{
			memcpy(mon, my_work->p, mon_len);

			if (kfifo_in(&(econet_data->monitor_fifo), &mon, sizeof(mon)))
				wake_up(&(econet_data->monitor_queue));
			else
				kfree(mon);
		}
	}

	spin_unlock(&(econet_data->monitor_count_spinlock));

	my_work->p->lastseen = EMF_PBUF_LASTSEEN_WORKQUEUE_EXIT;

	econet_free_pbuf(my_work->p);

	/* Free the work queue data, but not the packet data, which the monitor_readfd() does. */

	econet_free_workbuf(my_work);

	return;

}

MODULE_LICENSE("GPL");
