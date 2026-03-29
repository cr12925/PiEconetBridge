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

/*
 *
 * ECONET GPIO IRQ HANDLING CODE
 * Get the bytes off the wire, put the bytes on the wire, etc.
 *
 *
 */

spinlock_t econet_irq_spin;
spinlock_t econet_tx_spin;
spinlock_t econet_irqstate_spin;

/*
 * econet_irq_mode() - Enable / Disable IRQs from GPIO
 *
 * This has to track whether IRQs are on or off, because if
 * you enable when already enabled (or likewise disable)
 * all hell breakes loose!
 *
 */

void econet_irq_mode(short m)
{

	if (!econet_data || !econet_data->irq) /* Avoid null deref */
	{
		printk (KERN_ERR "econet-fast: Attempt to enable IRQs without successful initialization\n");
		return;
	}

	if (m)
	{
		if (econet_get_irq_state() == 0) // Disabled
		{
			enable_irq(econet_data->irq);
			econet_set_irq_state(1);
		}
	}
	else
	{
		if (econet_get_irq_state() == 1) // Enabled
		{
			disable_irq(econet_data->irq);
			econet_set_irq_state(0);
		}
	}
}

/* 
 * econet_irq_to_workqueue
 *
 * Put a packet of one form or another into the monitor fifo so that it
 * can be dealt with.
 */

void econet_irq_to_workqueue(struct __econet_packet **p, u8 sr1, u8 sr2, u8 dir)
{

	eco_work_t *work = devm_kzalloc(econet_data->module_dev, sizeof(eco_work_t), GFP_KERNEL);

	if (!*p)
	{
		if (econet_data->extralogs)
			printk (KERN_INFO "econet-fast: econet_irq_to_workqueue() called with no packet data!\n");

		if (work) devm_kfree(econet_data->module_dev, work);

		return;
	}

	/*
	if (econet_data->extralogs)
		printk (KERN_INFO "econet-fast: Transferring packet at %p to workqueue, sr1 = %02X, sr2 = %02X, dir = %02X, data bytes = %02X\n", *p, sr1, sr2, dir, (*p)->ptr);
	*/

	if (work)
	{
		(*p)->sr1 = sr1;
		(*p)->sr2 = sr2;
		(*p)->tx = dir;
	
		INIT_WORK (&(work->econet_work), econet_workqueue_handler);
	
		work->p = *p;
	
		if (!(queue_work (econet_data->workqueue, &(work->econet_work))))
		{
			/* Free it up and complain - the workqueue failed! */
	
			if (p)
				devm_kfree (econet_data->module_dev, *p);

			devm_kfree(econet_data->module_dev, work);

			printk (KERN_ERR "econet-fast: Unable to put work on work queue!\n");
		}
	}
	else
	{
		printk (KERN_ERR "econet-fast: Unable to allocate memory to transfer packet to work queue!\n");
		devm_kfree (econet_data->module_dev, *p); // *p must be non-NULL because we checked it above */
	}

	/* Reallocate new RX packet if required */

	if (dir == EP_PACKET_RX)
		*p = devm_kzalloc(econet_data->module_dev, sizeof(struct __econet_packet), GFP_KERNEL);

}

/* econet_irq_read_new(sr1, sr2)
 *
 * Read from the FIFO if there's data available, or deal with errors
 *
 */

void econet_irq_read_new (u8 i_sr1, u8 i_sr2)
{
	u8	sr1 = i_sr1, sr2 = i_sr2;
	u8 	read_counter = 0, bytes_to_read = 1;
	u8	deliver_to_workqueue = 0;

	if (econet_data->twobytemode)
		bytes_to_read = 2;

	while (++read_counter <= bytes_to_read)
	{
		econet_data->rxp->sr1 = sr1;
		econet_data->rxp->sr2 = sr2;
	
		// printk (KERN_INFO "econet-fast: econet_irq_read_new() loop: sr1 = %02X, sr2 = %02X, read_counter = %02X\n", sr1, sr2, read_counter);

		/* First, is there some data available? */
	
		if ((sr1 & ECONET_GPIO_S1_RDA) || (sr2 & ECONET_GPIO_S2_VALID) || (read_counter == 1 && (sr2 & ECONET_GPIO_S2_AP)))
		{
			u8	d;

			if (econet_data->rxp->ptr > ECONET_MAX_PACKET_SIZE)
				econet_data->rxp->ptr--; /* Just let keep overwriting last byte of data */
	
			econet_data->rxp->data[econet_data->rxp->ptr++] = d = econet_read_fifo();

		}

		if (sr2 & ECONET_GPIO_S2_VALID) /* Final byte - quit out */
			break;

		sr1 = econet_read_sr(1);
		sr2 = (sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
	}

	/* First, is it a valid frame? i.e. this was the last byte */

	if (sr2 & ECONET_GPIO_S2_VALID)
	{
		econet_data->pkt_since_idle++;

		deliver_to_workqueue = 1;

		/* Flag fill if the packet was destined to one our stations, UNLESS:
		 * 1. It was a broadcast (because broadcast will be in the station map)
		 * 2. It was a reply to an immediate we sent, or
		 * 3. It was a final ACK coming in on a 4-way transaction we started
		 */

		if (
			(econet_data->rxp->ptr >= 3) /* not a runt */
		&&	(econet_data->aun_mode)
		&&	(ECONET_DEV_STATION(econet_stations, econet_data->rxp->data[1], econet_data->rxp->data[0])) /* Station we're handling */
		&&	! (	/* Times we don't want to FF */
				(econet_data->pkt_since_idle == 1 && __IS_BROADCAST(econet_data->rxp))
			||	econet_data->no_flag_fill
			)
		)
		{
			//printk (KERN_INFO "econet-fast: FLAG filling\n");

			// 20260329 DO WE NEED ECONET_RX_CLEARDOWN HERE? (The old module does it)
			econet_flagfill();
		}
		else {
			/*
			printk (KERN_INFO "econet-fast: not flag filling: ptr = %02X, dst %d.%d (station set %s), pkt_since_idle = %d, no_flag_fill = %d\n",
					econet_data->rxp->ptr,
					econet_data->rxp->data[1], econet_data->rxp->data[0],
					(ECONET_DEV_STATION(econet_stations, econet_data->rxp->data[1], econet_data->rxp->data[0]) ? "match" : "NO match"),
					econet_data->pkt_since_idle,
					econet_data->no_flag_fill
					);
					*/
			econet_data->no_flag_fill = 0;
			econet_set_chipstate(EM_IDLE);
			econet_set_read_mode();
			ECONET_NOT_BUSY();
		}
		
	}

	/* Else , is there something that means we need to put the packet onto the work queue ? */

	if (
		(sr1 & ECONET_GPIO_S1_LOOP /* Which should never be enabled! */ 
		)
	||	(sr2 & (ECONET_GPIO_S2_RX_IDLE |
			ECONET_GPIO_S2_RX_ABORT |
			ECONET_GPIO_S2_ERR |
			ECONET_GPIO_S2_DCD |
			ECONET_GPIO_S2_OVERRUN)
		)
	  )
	{

		if (sr1 & ECONET_GPIO_S1_LOOP)
			printk (KERN_INFO "econet-fast: Loop mode found to be turned on!");
		if (sr2 & ECONET_GPIO_S2_RX_ABORT)
			printk (KERN_INFO "econet-fast: RX Abort received during RX at ptr = %04X", econet_data->rxp->ptr);
		if (sr2 & ECONET_GPIO_S2_ERR)
			printk (KERN_INFO "econet-fast: RX CRC Error");
		if (sr2 & ECONET_GPIO_S2_DCD)
			printk (KERN_INFO "econet-fast: No clock during RX at ptr = %04X", econet_data->rxp->ptr);
		if (sr2 & ECONET_GPIO_S2_OVERRUN)
			printk (KERN_INFO "econet-fast: RX Overrun at ptr = %04X", econet_data->rxp->ptr);
		if (sr2 & ECONET_GPIO_S2_RX_IDLE)
			printk (KERN_INFO "econet-fast: RX Idle received during frame RX at ptr = %04X", econet_data->rxp->ptr);

		econet_discontinue(); /* Discontinue unless valid frame or just an Idle IRQ */
		deliver_to_workqueue = 1;

	}
	
	if (deliver_to_workqueue) /* If the code above says we should be putting this on the workqueue */
		econet_irq_to_workqueue(&(econet_data->rxp), sr1, sr2, EP_PACKET_RX);
}

/* econet_irq_write_new(sr1, sr2)
 *
 * Write to FIFO if we have a packet to write, or deal with errors
 */

void econet_irq_write_new (u8 i_sr1, u8 i_sr2)
{

	u8	sr1 = i_sr1, sr2 = i_sr2;

	u8	tdra;

	/*
	if (econet_data->txp->ptr == 0)
		printk ("econet-fast: IRQ begin tx new frame,  length 0x%04X\n", econet_data->txp->txlen);
	*/

	if (econet_data->txp->ptr < econet_data->txp->txlen) /* Something left to transmit */
	{
		u8	bytes = 0;
		u8	tdra_counter;

		if (econet_data->txp->ptr == 0) /* Start of fresh packet */
		{
			econet_set_tx_status(ECONET_TX_INPROGRESS);
		}

		while (bytes < (econet_data->twobytemode ? 2 : 1))
		{

			if (bytes > 0)  /* Re-read the SRs */
			{
				sr1 = econet_read_sr(1);

				if (sr1 & ECONET_GPIO_S1_S2RQ) { sr2 = econet_read_sr(2); } else sr2 = 0;
			}

			tdra = (sr1 & ECONET_GPIO_S1_TDRA);

			tdra_counter = 0;

			while (tdra_counter++ < 10 && (!tdra)) /* Try 10 times waiting for tdra */
			{
				econet_write_cr(ECONET_GPIO_CR2,
						ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
						ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE |
						(econet_data->twobytemode) ? ECONET_GPIO_C2_2BYTES : 0);

				udelay (10);

				tdra = ((sr1 = econet_read_sr(1)) & ECONET_GPIO_S1_TDRA);
			}

			if (!tdra)
			{
				if (sr1 & ECONET_GPIO_S1_CTS) /* Collision? */
				{
					if (econet_data->extralogs) printk (KERN_INFO "econet-fast: Collision: SR1 = 0x%02X, SR2 = 0x%02X, TX ptr = 0x%04X - TX aborted\n",
							sr1,
							(sr2 = econet_read_sr(2)),
							econet_data->txp->ptr);
					econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
				}
				else
				{
					if (econet_data->extralogs) printk (KERN_INFO "econet-fast: TDRA Unavailable: SR1 = 0x%02X, SR2 = 0x%02X, TX ptr = 0x%04X - TX aborted\n",
							sr1,
							(sr2 = econet_read_sr(2)),
							econet_data->txp->ptr);
					econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
				}

				return;
			}

			if (sr2 & ECONET_GPIO_S2_DCD) /* No clock */
			{
				printk (KERN_ERR "econet-fast: No clock during transmission at byte %02X, SR1 = 0x%02X, SR2 = 0x%02X - TX aborted\n", econet_data->txp->ptr, sr1, sr2);
				econet_set_read_mode();
				econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
			}

			if (sr1 & ECONET_GPIO_S1_UNDERRUN) /* TX Underrun */
			{
				printk (KERN_ERR "econet-fast: Underrun during transmission at byte %02X, SR1 = 0x%02X, SR2 = 0x%02X - TX aborted\n", econet_data->txp->ptr, sr1, sr2);
				econet_set_read_mode();
				econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
			}

			/* TDRA available - put some data in it */

			econet_write_fifo(econet_data->txp->data[econet_data->txp->ptr]);

			econet_data->txp->ptr++;

			if (econet_data->txp->ptr == econet_data->txp->txlen)
			{
				//printk (KERN_INFO "econet-data: TX of 0x%04X bytes complete; sending to workqueue\n", econet_data->txp->ptr);
				econet_finish_tx();
				break;
				return;
			}

			bytes++;
		}
	}

	return;
}

/* econet_irq()
 *
 * New faster IRQ handler
 */

irqreturn_t econet_irq(int irq, void *ident)
{

	unsigned long 	flags;
	u8		chip_state, handled = 0;

	/* Prevent re-entry */

	spin_lock_irqsave(&econet_irq_spin, flags);

	/* Read SR1 only, for speed. SR2 read below if need be */

	sr1 = econet_read_sr(1);

	sr2 = (sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;

	chip_state = econet_get_chipstate();

	if (chip_state == EM_TEST)
	{
		printk (KERN_INFO "econet-fast: IRQ handler called in test mode!");
		/* Turn off ADLC IRQs */
		econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_TX_RESET | ECONET_GPIO_C1_RX_RESET);
	}
	else if (sr1 & ECONET_GPIO_S1_IRQ)
	{

		if (econet_data->rxp) /* Should always be non-null, even during TX */
		{

			if (chip_state == EM_WRITE_WAIT)
			{
				econet_data->pkt_since_idle++; /* We've transmitted a packet - increase our pkt count since idle */

				if (
					(econet_data->pkt_since_idle == 1 && __IS_TWOWAY(econet_data->txp)) /* We've just transmitted a two-way immediate - don't flag fill on the reply */
				||	(econet_data->pkt_since_idle == 3) /* Must be data phase of 4-way */
				)
				{
					econet_data->no_flag_fill = 1;
					// printk (KERN_INFO "econet-fast: Setting no_flag_fill\n");
				}
					
				econet_set_read_mode();
				econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
				econet_set_chipstate(EM_IDLE);
				chip_state = EM_IDLE;
			}

			if ((sr2 & ECONET_GPIO_S2_AP)) /* New packet */
			{
				econet_set_chipstate(EM_READ);
				chip_state = EM_READ;
				ECONET_SET_BUSY();
				/* reset packet pointer */
				econet_data->rxp->ptr = 0;
			}
			else if ( /* Errors we need to clear */
				(sr1 & (ECONET_GPIO_S1_FLAG))
				||	(sr2 & (ECONET_GPIO_S2_RX_IDLE))
				)
			{
				econet_irq_to_workqueue(&(econet_data->rxp), sr1, sr2, EP_PACKET_RX); /* Puts an empty packet into the monitor kfifo, but has the status in it */
				econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Just clear status
				econet_set_chipstate(EM_IDLE);
				chip_state = EM_IDLE;
				econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;
				handled = 1;
			}	

			switch (chip_state) // Otherwise process traffic
			{
				case EM_READ:
					econet_irq_read_new(sr1, sr2);
					handled = 1;
					break;
				case EM_WRITE:
					econet_irq_write_new(sr1, sr2);
					handled = 1;
					break;
				case EM_FLAGFILL:
					handled = 1;
					break;
				case EM_IDLE:
					handled = 1;
					break;
				default:
					/* Shouldn't happen - switch off! */
					printk (KERN_ERR "econet-fast: Unhandled chip mode %02X in IRQ handler, sr1 = 0x%02X, sr2 = 0x%02X. Disabling.\n", chip_state, sr1, sr2);
					econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_TX_RESET | ECONET_GPIO_C1_RX_RESET);
					econet_set_chipstate(EM_TEST);
					ECONET_NOT_BUSY();
					handled = 1;
					break;
			}
		}
		else
		{
			printk (KERN_ERR "econet-fast: No RX packet storage in IRQ handler!\n");

			/* Turn the ADLC off! */

			econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_TX_RESET | ECONET_GPIO_C1_RX_RESET);
			econet_set_chipstate(EM_TEST);
			handled = 1;
		}
		
	}
	else
	{
		printk (KERN_INFO "econet-fast: IRQ handler called but ADLC not flagging an IRQ (SR1 = %02X, SR2 = %02X)", sr1, sr2);
		econet_adlc_cleardown(1);
		econet_set_read_mode();
	}

	/*
	 * Unlock IRQ spinlock prior to return.
	 *
	 */

	spin_unlock_irqrestore(&econet_irq_spin, flags);

	/* Return */

	return IRQ_HANDLED;

}

MODULE_LICENSE("GPL");
