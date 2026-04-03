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

u8 inline econet_workqueue_correct_reply_source(struct __econet_packet *p)
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

	if (sr1_errors || sr2_errors)
	{
		ECONET_NOT_BUSY();
		if (!(aun_state == EA_IDLE && sr1_errors == 0 && sr2_errors == ECONET_GPIO_S2_RX_IDLE)) /* Don't report on innocuous "error" */
			printk ("econet-fast: AUN workqueue responder found errors: SR1 = 0x%02X, SR2 = 0x%02X\n", sr1_errors, sr2_errors);
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
		else
		{
			ECONET_NOT_BUSY();
		}

		return EWAS_DATA_READ;
	}
	else if (__IS_FOURWAY(p))
	{
		econet_set_aunstate(EA_R_WRITEFIRSTACK);

		econet_data->txp = emalloc(ECONET_ACK_PACKET_SIZE);

		if (econet_data->txp)
		{
			u8 seized = 0;

			econet_workqueue_build_ack(econet_data->txp);

			// printk (KERN_INFO "econet-fast: EA_R_WRITEFIRSTACK seizing line\n");

			if ((seized = econet_seize()))
			{
				/* Failed. */
				printk (KERN_INFO "econet-fast: EA_R_WRITEFIRSTACK failed line seize - abort to EA_IDLE\n");
				econet_set_aunstate(EA_IDLE);
				econet_set_read_mode();
			}

			// printk (KERN_INFO "econet-fast: EA_R_WRITEFIRSTACK: Line seized - TX should begin\n");
		}
		else
		{
			econet_set_aunstate(EA_IDLE);

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

	/* Filter errors */
	if (p->tx == EP_PACKET_RX) 
	{
		sr1_errors = 0;
	}
	else
	{
		sr2_errors &= (ECONET_GPIO_S2_DCD);
	}

	/* Deal with runts */

	if (p->ptr < 4 && !(p->ptr == 0 && p->tx == EP_PACKET_RX)) /* Ignore "runts" which are just signalling packets */
	{
		u8 	count;
		printk (KERN_ERR "econet-fast: Runt %s packet length 0x%02X received by workqueue from %3d.%3d to %3d.%3d, sr1 = 0x%02X, sr2 = 0x%02X, aun state = 0x%02X\n",
				p->tx == EP_PACKET_RX ? "RX" : "TX",
				p->ptr,
				__SRCNET(p),
				__SRCSTN(p),
				__DSTNET(p),
				__DSTSTN(p),
				p->sr1, p->sr2,
				aun_state
		       );

		for (count = 0; count <= (p->ptr > 3 ? 3 : p->ptr); count++)
			printk (KERN_ERR "econet-fast: Byte %d = 0x%02X\n", count, p->data[count]);

		econet_set_aunstate(EA_IDLE); /* Don't need to check if in aun-mode - means nothing if we're not */
		return EWAS_NOTHING;
	}

	if (econet_data->aun_mode) /* Only change state if in AUN mode, otherwise just deal with raw packet */
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
					ECONET_NOT_BUSY();
					econet_set_aunstate(EA_IDLE);
					econet_set_read_mode();
					return EWAS_DATA_WRITE;
				}
			}

			if (sr2_errors & ECONET_GPIO_S2_DCD)
			{
				econet_set_tx_status(ECONET_TX_NOCLOCK);
				ECONET_NOT_BUSY();
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
			econet_set_aunstate(EA_IDLE); /* Abandon */
			return EWAS_NOTHING;
		}

		/* Check for no clock other than during a TX operation to the ADLC, which is caught above */

		if (sr2_errors & ECONET_GPIO_S2_DCD)
		{
			if (__AUN_TX_OPERATION(aun_state))
			{
				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_NOCLOCK);
				return EWAS_DATA_WRITE;
			}
			else /* No clock in idle state or during AUN read operation */
			{
				econet_set_read_mode();
				econet_set_aunstate(EA_IDLE);
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

			switch (aun_state)
			{
				/* Fall throughs deliberate - for testing */

				case EA_W_READFIRSTACK:
					{
						if (p->ptr < 4)
						{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_NOTLISTENING);
							printk (KERN_INFO "econet-fast: Resetting state machine after idle on writing scout\n");
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
				case EA_W_READFINALACK:
					{
						if (p->ptr < 4)
						{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
							printk (KERN_INFO "econet-fast: Resetting state machine after idle on writing scout\n");
							return EWAS_DATA_WRITE;
						}
					} break;
				case EA_W_WRITEDATA: /* Net error */
					{
							econet_set_aunstate(EA_IDLE);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL); /* For now. Do we have net error in our list? */
							return EWAS_DATA_WRITE;
					} break;
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
			//printk (KERN_INFO "econet-fast: Packet received from idle\n");
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
				ECONET_NOT_BUSY();
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
			if (sr1_errors || sr2_errors)
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

				// econet_set_read_mode(); IRQ handler should have done this

				ECONET_NOT_BUSY();
				return EWAS_DATA_WRITE;
			}

			/* Was it an ACK and was it from the right place? */

			if (p->ptr == 4 && econet_workqueue_correct_reply_source(p))
			{
				u16	data_balance = 0;
				u8	seized = 0;

				/* How much data didn't go on the scout? */

				data_balance =
					econet_data->aun_packet_len_tx
				-	econet_data->aun_packet_tx.p.padding;

				if (data_balance < 1 || data_balance > ECONET_MAX_PACKET_SIZE)
				{
					printk (KERN_ERR "econet-fast: Unlawful TX frame size (0x%04X)! (aun_packet_len_tx = 0x%04X, padding = 0x%02X\n", data_balance, econet_data->aun_packet_len_tx, econet_data->aun_packet_tx.p.padding);
					/* Abort */
					ECONET_NOT_BUSY();
					econet_set_tx_status (ECONET_TX_INVALID);
					econet_set_aunstate(EA_IDLE);
					econet_set_read_mode();
					return EWAS_DATA_WRITE;
				}

				/* Make up the data packet and trigger */
				/* Note that number of scout data bytes
				 * will have been stored in padding for us
				 */

				econet_data->txp = emalloc(4 + data_balance);

				if (!econet_data->txp)
				{
					ECONET_NOT_BUSY();
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

				if ((seized = econet_seize())) /* NB Kernel module should have put us in flag fill */
				{
					/* Failed. */
					printk (KERN_ERR "econet-fast: Failed to seize line for 4-way data phase: frame length 0x%04X\n", p->txlen);
					ECONET_NOT_BUSY();
					econet_set_aunstate(EA_IDLE);
					econet_set_tx_status(seized);
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

				printk (KERN_ERR "econet-fast: 4-way TX begun and first ACK expected from %d.%d but received from %d.%d!\n",
						__AUN_DSTNET(econet_data->aun_packet_tx),
						__AUN_DSTSTN(econet_data->aun_packet_tx),
						__SRCNET(p),
						__SRCSTN(p)
				       );
				econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				/* Old module used to treat non-ack frames received when it wanted an ack as just a
				 * new frame. Not sure we want to do that now we track RX IDLE properly. 
				 */
				return /* econet_workqueue_respond_new_packet(p, sr1_errors, sr2_errors) | */ EWAS_DATA_WRITE;
			}

		}
		else if (aun_state == EA_W_WRITEDATA && p->tx == EP_PACKET_TX)
		{
			/* TX Underrun and no clock are checked above */

			/* Otherwise looks like we did a successful data TX */

			// econet_set_read_mode(); IRQ handler should have done this
			econet_set_aunstate (EA_W_READFINALACK);

			return EWAS_NOTHING;
		}
		else if (aun_state == EA_W_READFINALACK && p->tx == EP_PACKET_RX)
		{
			/* TX Underrun is checked above */

			/* Correct length & source ? */

			if (p->ptr == 4 && econet_workqueue_correct_reply_source(p))
			{
				/* Signal successful TX */

				// econet_set_read_mode(); IRQ handler should have done this

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

				// econet_set_read_mode(); IRQ handler should do this on errors
				econet_set_aunstate(EA_IDLE);
				econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
				if (sr2_errors & ECONET_GPIO_S2_DCD)
					econet_set_tx_status(ECONET_TX_NOCLOCK);
				return EWAS_DATA_WRITE; /* Tell userspace it all fell in a heap */
			}
			else
			{

				/* Apparently successful TX of ACK */

				// econet_set_read_mode(); IRQ handler should be doing this
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

				econet_set_aunstate(EA_IDLE);
				// econet_set_read_mode(); /* Module likely in flag fill - IRQ handler should be doing this
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
						p->ptr);

					/* Update aun_packet_len */

					econet_data->aun_packet_len_rx += p->ptr;

					econet_set_aunstate(EA_R_WRITEFINALACK);

					/* Build Ack */

					econet_data->txp = emalloc(ECONET_ACK_PACKET_SIZE);

					if (!econet_data->txp)
					{
						printk (KERN_ERR "econet-fast: Unable to allocate ACK storage when transitioning to EA_R_WRITEFINALACK\n");

						econet_set_aunstate(EA_IDLE);
						econet_set_read_mode();
					}
					else
					{
						u8 seized;

						econet_workqueue_build_ack(econet_data->txp);

						if ((seized = econet_seize()))
						{
							/* Failed. */
							/* But we could return the data anyway */
							ECONET_NOT_BUSY();
							econet_set_aunstate(EA_IDLE);
							econet_set_read_mode();
							return EWAS_DATA_READ;
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
			return EWAS_NOTHING;
		}
	}
	else /* Raw mode - just copy incoming packets to the aun area and
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
		devm_kfree(econet_data->module_dev, my_work);
		return;
	}
	
	// printk (KERN_INFO "econet-fast: workqueue handler invoked with aun_mode = %d, my_work->p = %p, sr1 = %02X, s2 = %02X, ptr = %04x, tx = %1X, txlen = 0x%04X\n", econet_data->aun_mode, my_work->p, my_work->p->sr1, my_work->p->sr2, my_work->p->ptr, my_work->p->tx, my_work->p->txlen);

	statemachine_response = econet_workqueue_aun_statemachine(p);

	// printk (KERN_INFO "econet-fast: statemachine response 0x%02X\n", statemachine_response);

	if (econet_data->open_count) /* The userspace bridge code or something of that nature has our device open */
	{
		// If we have finished tx-ing a packet, interruptible_wake_up(&(econet_data->tx_queue)); 

		/* Have we finished an AUN tx operation, for good or ill ? */

		if (statemachine_response & EWAS_DATA_WRITE)
		{
			u8	txstatus = econet_get_tx_status();

			// printk (KERN_INFO "econet-fast: Waking up R/W TX Queue with TX state 0x%02X\n", txstatus);
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

			// printk (KERN_INFO "econet-fast: Attempting to put packet length 0x%04X on user fifo\n", econet_data->aun_packet_len_rx + (econet_data->aun_mode ? 12 : 0));

			if (!kfifo_in(&(econet_data->readfd_fifo), &(econet_data->aun_packet_rx), econet_data->aun_packet_len_rx + (econet_data->aun_mode ? 12 : 0)))
			{
				printk (KERN_ERR "econet-fast: Error putting packet onto RX FIFO, length 0x%04X, %s mode\n",
							econet_data->aun_packet_len_rx,
							econet_data->aun_mode ? "AUN" : "RAW");
			}
			else
			{
				/* Wake up the poller */

				//printk (KERN_INFO "AUN state machine waking up RW poller\n");

				wake_up (&(econet_data->rx_queue));
			}
		}
		
		if (statemachine_response) /* Unless it was "nothing", signal not busy */
		{
			ECONET_NOT_BUSY();
		}

	}

	if (econet_data->monitor_count) /* Someone is looking at the monitor */
	{
		/* Put work->p onto a read queue and wake up the poller */

		if (kfifo_in (&(econet_data->monitor_fifo), &(my_work->p), sizeof(struct __econet_packet *))) /* Just put packet pointer on queue - it gets free()d by readfd() */
		{	
			/* Wake up the monitor poller */
	
			wake_up (&(econet_data->monitor_queue));

			/* If we've put my_work->p on the fifo, the readfd routine will free it. */
		}
		else
			devm_kfree (econet_data->module_dev, my_work->p);


	}
	else
	{
		/* If monitor not open, free the packet data */

		devm_kfree (econet_data->module_dev, my_work->p);
	}


	/* Free the work queue data, but not the packet data, which the monitor_readfd() does. */

	devm_kfree (econet_data->module_dev, my_work);

	return;

}

MODULE_LICENSE("GPL");
