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

/* Prototypes */

void econet_irq_to_workqueue(struct __econet_packet **, u8, u8, u8);
void econet_irq_read_new(u8, u8);
void econet_irq_write_new(u8, u8);

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

inline void econet_irq_to_workqueue(struct __econet_packet **p, u8 sr1, u8 sr2, u8 dir)
{

	eco_work_t *work = econet_alloc_workbuf();

	if (!*p)
	{
		if (econet_data->extralogs)
			printk (KERN_INFO "econet-fast: econet_irq_to_workqueue() called with no packet data!\n");

		if (work) econet_free_workbuf(work);

		return;
	}

	if (econet_data->extralogs)
		printk (KERN_INFO "econet-fast: Transferring packet at %p to workqueue, sr1 = %02X, sr2 = %02X, dir = %02X, data bytes = %02X\n", *p, sr1, sr2, dir, (*p)->ptr);

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
	
			if (*p)
				econet_free_pbuf(*p);

			econet_free_workbuf(work);

			printk (KERN_ERR "econet-fast: Unable to put work on work queue!\n");
		}
	}
	else
	{
		printk (KERN_ERR "econet-fast: Unable to allocate memory to transfer packet to work queue!\n");
		econet_free_pbuf(*p);

	}

	/* Reallocate new RX packet if required */

	if (dir == EP_PACKET_RX)
		*p = econet_alloc_pbuf();
	else	*p = NULL; /* will be econet_data->txp */
	//else	econet_data->txp = NULL;

}

/* econet_irq_read_new(sr1, sr2)
 *
 * Read from the FIFO if there's data available, or deal with errors
 *
 */

inline void econet_irq_read_new (u8 i_sr1, u8 i_sr2)
{
	u8	sr1 = i_sr1, sr2 = i_sr2;
	u8 	read_counter = 0, bytes_to_read = 1;
	u8	deliver_to_workqueue = 0;
	u8	valid = 0;
	u8	irq_loop_count = 0;

	if (econet_data->twobytemode)
		bytes_to_read = 2;

while (!valid && (sr1 & ECONET_GPIO_S1_IRQ) && irq_loop_count++ < 5)
{
	while (!valid && (++read_counter <= bytes_to_read))
	{
		econet_data->rxp->sr1 = sr1;
		econet_data->rxp->sr2 = sr2;
	
		// printk (KERN_INFO "econet-fast: econet_irq_read_new() loop: sr1 = %02X, sr2 = %02X, read_counter = %02X\n", sr1, sr2, read_counter);

		/* First, is there some data available? */
	
#if 0
		if ((sr1 & ECONET_GPIO_S1_RDA) || (sr2 & ECONET_GPIO_S2_VALID) || (read_counter == 1 && (sr2 & ECONET_GPIO_S2_AP)))
#else
		if (
			(econet_data->rxp->ptr == 0 && (sr2 & ECONET_GPIO_S2_AP)) /* New packet */
		||	(sr1 & ECONET_GPIO_S1_RDA &&
				(
					(econet_data->twobytemode && (read_counter == 1 || econet_data->rxp->ptr == 1)) /* ANFS only checks RDA on (i) the byte after AP was set, and (ii) first byte of a two-byte pair */
				||	!(econet_data->twobytemode)
				)
			) /* RDA on either first byte read (only) in two byte mode (we quit out on FV below), or any byte in one byte mode - ANFS does not check RDA on second byte of two byte read */
		||	(sr2 & ECONET_GPIO_S2_VALID) /* Not sure we ought to have this here... */
		)
#endif
		{
			if (econet_data->rxp->ptr >= ECONET_MAX_PACKET_SIZE)
				econet_data->rxp->ptr--; /* Just let keep overwriting last byte of data TODO - discontinue() */
	
			econet_data->rxp->data[econet_data->rxp->ptr++] = econet_read_fifo();

		}

		if (sr2 & ECONET_GPIO_S2_VALID) /* Final byte - quit out */
			valid = 1;
		else
		{
			if (sr2 & ECONET_GPIO_S2_AP) /* If first byte, it's special - don't try and read another one */
				return;

			sr1 = econet_read_sr(1);
			sr2 = (sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
		}
	}

	/* And we loop around if there's another IRQ being flagged - which is what ANFS appears to do */

}

	/* First, is it a valid frame? i.e. this was the last byte */

	if (sr2 & ECONET_GPIO_S2_VALID)
	{
		econet_data->pkt_since_idle++;

		deliver_to_workqueue = 1;

		// econet_data->rxp->timing_end = ktime_get_ns();

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
			printk (KERN_INFO "econet-fast: Loop mode found to be turned on!\n");
		if (econet_data->extralogs && sr2 & ECONET_GPIO_S2_RX_ABORT)
			printk (KERN_INFO "econet-fast: RX Abort received during RX at ptr = %04X, AUN state 0x%02X\n", econet_data->rxp->ptr, econet_get_aunstate());
		if (sr2 & ECONET_GPIO_S2_ERR)
			printk (KERN_INFO "econet-fast: RX CRC Error\n");
		if (sr2 & ECONET_GPIO_S2_DCD)
			printk (KERN_INFO "econet-fast: No clock during RX at ptr = %04X\n", econet_data->rxp->ptr);
		if (sr2 & ECONET_GPIO_S2_OVERRUN)
			printk (KERN_INFO "econet-fast: RX Overrun at ptr = %04X\n", econet_data->rxp->ptr);
		if ((sr2 & ECONET_GPIO_S2_RX_IDLE) && (econet_data->rxp->ptr != 0))
			printk (KERN_INFO "econet-fast: RX Idle received during frame RX at ptr = %04X\n", econet_data->rxp->ptr);

		if (!deliver_to_workqueue) /* Only discontinue if we don't have FV above */
		{
			/* Old discontinue routine does all sorts that was more relevant to old module */

			econet_write_cr(2, C2_READ);
			econet_write_cr(1, C1_READ | ECONET_GPIO_C1_RX_DISC);
			econet_set_chipstate(EM_IDLE);
		}

		deliver_to_workqueue = 1;

	}
	
	if (deliver_to_workqueue) /* If the code above says we should be putting this on the workqueue */
		econet_irq_to_workqueue(&(econet_data->rxp), sr1, sr2, EP_PACKET_RX);
}

/* econet_irq_write_new(sr1, sr2)
 *
 * Write to FIFO if we have a packet to write, or deal with errors
 */

inline void econet_irq_write_new (u8 i_sr1, u8 i_sr2)
{

	u8	sr1 = i_sr1, sr2 = i_sr2;

	u8	tdra;

	if (econet_data->txp->ptr < econet_data->txp->txlen) /* Something left to transmit */
	{
		u8	bytes = 0;
		u8	tdra_counter;

		if (econet_data->txp->ptr == 0) /* Start of fresh packet */
		{
			econet_set_tx_status(ECONET_TX_INPROGRESS);
			// econet_data->txp->timing_start = ktime_get_ns();
		}

		if (sr1 & ECONET_GPIO_S1_UNDERRUN) /* TX Underrun */
		{
			printk (KERN_ERR "econet-fast: Underrun during transmission at byte %02X, SR1 = 0x%02X, SR2 = 0x%02X - TX aborted\n", econet_data->txp->ptr, sr1, sr2);
			econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
			econet_set_read_mode();
		}

		if (sr2 & ECONET_GPIO_S2_DCD) /* No clock */
		{
			printk (KERN_ERR "econet-fast: No clock during transmission at byte %02X, SR1 = 0x%02X, SR2 = 0x%02X - TX aborted\n", econet_data->txp->ptr, sr1, sr2);
			econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX);
			econet_set_read_mode();
		}

		while (bytes < (econet_data->twobytemode ? 2 : 1))
		{

#if 0 /* Shouldn't be necessary */
			if (bytes > 0)  /* Re-read the SRs */
			{
				sr1 = econet_read_sr(1);

				if (sr1 & ECONET_GPIO_S1_S2RQ) { sr2 = econet_read_sr(2); } else sr2 = 0;
			}
#endif

			if (bytes == 0)
			{
				tdra = (sr1 & ECONET_GPIO_S1_TDRA);
	
				tdra_counter = 0;

				while (tdra_counter++ < 10 && (!tdra)) /* Try 10 times waiting for tdra - but only on first byte if in two byte mode */
				{
					econet_write_cr(ECONET_GPIO_CR2,
						ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
						ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE |
						((econet_data->twobytemode) ? ECONET_GPIO_C2_2BYTES : 0));

					tdra = ((sr1 = econet_read_sr(1)) & ECONET_GPIO_S1_TDRA);
				}

				if (!tdra) /* Only check on first byte if in 2-byte mode */
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

	if (econet_data->txp->ptr < econet_data->txp->txlen) /* Something left to transmit - switch fastpath on*/
		atomic_set(&econet_data->fastpath_enabled, 1);

	return;
}

/* econet_irq_hardirq()
 *
 * Hard-IRQ top half with fast-path FIFO drain.
 *
 * When the thread has set fastpath_enabled (we're in EM_READ and
 * receiving frame data, or EM_WRITE and transmitting), the top half reads/writes FIFO bytes directly —
 * this runs in ~2-4µs vs. the ~50+µs thread scheduling latency
 * that was causing RX overruns.
 *
 * For anything other than a plain data byte (frame valid, errors,
 * TX, state transitions), we snapshot the SR values and wake the
 * thread for full state-machine processing.
 *
 * IRQF_ONESHOT guarantees the top half and thread never run
 * concurrently for this IRQ line, so no lock is needed for rxp
 * or the shadow SR fields.
 */

irqreturn_t econet_irq_hardirq(int irq, void *ident)
{
	u8 hsr1, hsr2;
	u8 max_hard_loop = ECONET_GPIO_MAX_RXTX_LOOPS;
	u8 fastpath;
	u8 chipstate = econet_get_chipstate();

	/* Fast path: if the thread told us we're mid-frame RX,
	 * try to grab data bytes without waking the thread.
	 *
	 * We loop to drain all available bytes — if another IRQ
	 * handler delayed us by one byte period (~40µs), the ADLC
	 * FIFO may have accumulated an extra byte. Reading in a
	 * loop prevents overruns from brief scheduling delays. */

#if 0 /* I think this is causing a problem... */

	/* If we're in write mode, we'll always try fastpath */

	if (chipstate == EM_WRITE)
		atomic_set(&econet_data->fastpath_enabled, 1);

#endif

	fastpath = atomic_read(&econet_data->fastpath_enabled);

	hsr1 = econet_read_sr(1);
	hsr2 = (hsr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;

	if (econet_data && econet_data->rxp && chipstate == EM_IDLE && (hsr2 & ECONET_GPIO_S2_AP)) /* New packet */
	{

		econet_data->rxp->ptr = 0;

		atomic_set(&(econet_data->fastpath_enabled), 1);

		econet_set_chipstate(EM_READ);

		econet_data->rxp->data[econet_data->rxp->ptr++] = econet_read_fifo();

		if (econet_data->twobytemode)
		{
			hsr1 = econet_read_sr(1);
			hsr2 = (hsr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;

 			if  (hsr1 & ECONET_GPIO_S1_RDA) /* Second byte */
				econet_data->rxp->data[econet_data->rxp->ptr++] = econet_read_fifo();
		}

		hsr1 = econet_read_sr(1);
		hsr2 = (hsr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;

		if (!(hsr1 & ECONET_GPIO_S1_IRQ)) /* No more IRQ - quit */
			return IRQ_HANDLED;

		/* Otherwise, fall through and have another run at it */
	}

	if (fastpath && chipstate == EM_READ)
	{
		while (max_hard_loop-- > 0 && (hsr1 & ECONET_GPIO_S1_IRQ))
		{
			u8 bytes_to_do = (econet_data->twobytemode) ? 2 : 1;

			while (bytes_to_do--)
			{
				/* Pure data byte: RDA set, no frame-end or error flags,
 				* and NOT a new-packet AP — AP must go through the thread
 				* so it can set EM_READ, reset rxp->ptr, and mark busy.
 				* Otherwise a new frame would accumulate on top of the
 				* previous one's stale data. */

				if ((hsr1 & ECONET_GPIO_S1_RDA)
    				&& !(hsr2 & (ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_ERR
               				| ECONET_GPIO_S2_OVERRUN | ECONET_GPIO_S2_DCD
               				| ECONET_GPIO_S2_RX_IDLE | ECONET_GPIO_S2_RX_ABORT
               				| ECONET_GPIO_S2_AP ))
    				&& econet_data->rxp
    				&& econet_data->rxp->ptr < ECONET_MAX_PACKET_SIZE
				)
				{
					econet_data->rxp->data[econet_data->rxp->ptr++] = econet_read_fifo();
				}
				else
				{
					/* Not a simple data byte — fall through to wake thread */
					econet_data->shadow_sr1 = hsr1;
					econet_data->shadow_sr2 = hsr2;
					return IRQ_WAKE_THREAD;
				}
	
				/* Don't need hsr1 for second byte on 2 byte transfer hsr1 = econet_read_sr(1); */
				hsr2 = (hsr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
			}

			hsr1 = econet_read_sr(1);
			hsr2 = (hsr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
		}
	
		return IRQ_HANDLED; /* Either we've done our max loops, or there was no IRQ */

	}
	else if (fastpath && chipstate == EM_WRITE)
	{

		if (!econet_data->txp) /* Ouch! Where's our TX data?? */
		{
		
			/* Barf to bottom half */
			econet_data->shadow_sr1 = hsr1;
			econet_data->shadow_sr2 = hsr2;
			return IRQ_WAKE_THREAD;
		}

		if (
			(hsr1 & ECONET_GPIO_S1_UNDERRUN) /* TX Underrun */
		   |	(hsr2 & ECONET_GPIO_S2_DCD) /* No clock */
		 )
		{
			/* Barf to bottom half */
			econet_data->shadow_sr1 = hsr1;
			econet_data->shadow_sr2 = hsr2;
			return IRQ_WAKE_THREAD;
		}

		/* Otherwise send some data if there is data to send, we haven't exhausted our hard max loop count, and there's an IRQ */

		while ((econet_data->txp->ptr < econet_data->txp->txlen) 
		  && max_hard_loop-- && (hsr1 & ECONET_GPIO_S1_IRQ))
		{
			
			u8 bytes_to_do = (econet_data->twobytemode) ? 2 : 1;

			/* Do we have an IRQ & TDRA? If not, barf to the lower half */

			if ((hsr1 & (ECONET_GPIO_S1_IRQ | ECONET_GPIO_S1_TDRA)) != (ECONET_GPIO_S1_IRQ | ECONET_GPIO_S1_TDRA)) /* No IRQ or no TDRA */
			{
				return IRQ_HANDLED; /* Surely this is what we need to be doing?? */
#if 0
				printk_ratelimited ("econet-fast: Either no IRQ or no TDRA on fastpath tx: SR1 = %02X\n", hsr1);
				econet_data->shadow_sr1 = hsr1;
				econet_data->shadow_sr2 = hsr2;
				return IRQ_WAKE_THREAD;
#endif

			}

			while (bytes_to_do--)
			{
#if 0
				/* Check for TDRA on (only byte || first of two) - though realistically if it's not available we're stuffed */

				if (bytes_to_do || (!(econet_data->twobytemode))) /* First byte of two, or not in twobyte mode */
				{
					u8 	tdra = 0, tdra_counter = 0;;

					/* Check TDRA available */

					while (tdra_counter++ < 10 && (!tdra))
					{
						econet_write_cr(ECONET_GPIO_CR2,
							(
							ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
							ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE |
							((econet_data->twobytemode) ? ECONET_GPIO_C2_2BYTES : 0)
							)
						);
						tdra = ((hsr1 = econet_read_sr(1)) & ECONET_GPIO_S1_TDRA);
					}

					if (!tdra) /* Quit to lower handle */
					{
						econet_data->shadow_sr1 = hsr1;
						econet_data->shadow_sr2 = hsr2;
						return IRQ_WAKE_THREAD;
					}
				}
#endif

				econet_write_fifo(econet_data->txp->data[econet_data->txp->ptr++]);

				if (econet_data->txp->ptr == econet_data->txp->txlen)
				{
					econet_finish_tx();
					econet_data->shadow_sr1 = econet_read_sr(1);

					if (econet_data->shadow_sr1 & ECONET_GPIO_S1_IRQ) /* Another IRQ present - pass to bottom hald */
					{
						econet_data->shadow_sr2 = (econet_data->shadow_sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
						printk_ratelimited(KERN_INFO "econet-fast: IRQ on fastpath write of last byte: FC is %d, SR1 = %02X, SR2 = %02X\n", !!(econet_data->shadow_sr1 & ECONET_GPIO_S1_TDRA), econet_data->shadow_sr1, econet_data->shadow_sr2);

						/* Should have FC set - if not, clear TX status */

						if (!(econet_data->shadow_sr1 & ECONET_GPIO_S1_TDRA))
						{
							econet_write_cr(2,
								(ECONET_GPIO_C2_PSE |
								 ECONET_GPIO_C2_FLAGIDLE |
								 ECONET_GPIO_C2_CLR_RX_STATUS |
								 ECONET_GPIO_C2_CLR_TX_STATUS |
								 ((econet_data->twobytemode) ? ECONET_GPIO_C2_2BYTES : 0)
								));
							return IRQ_HANDLED;
						}

						return IRQ_WAKE_THREAD;
					}
					else
						return IRQ_HANDLED;
				}
				
			}

			hsr1 = econet_read_sr(1);
			hsr2 = (hsr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
		}

		/* We've either:
		   Done the packet - in which case we've called econet_finish_tx() and are in write-wait, and there was no other IRQ, so it's time to quit, or we've done max loops in which case we need to relinquish 
		*/

		return IRQ_HANDLED;
	}

	econet_data->shadow_sr1 = hsr1;
	econet_data->shadow_sr2 = hsr2;

	return IRQ_WAKE_THREAD;
}

/* econet_irq()
 *
 * Threaded IRQ handler (runs as a kthread with IRQs enabled).
 */

irqreturn_t econet_irq(int irq, void *ident)
{

	u8		chip_state, handled = 0;

	/* Disable fast-path while the thread runs.
	 * IRQF_ONESHOT keeps the line masked so this is safe. */

	atomic_set(&econet_data->fastpath_enabled, 0);

	/* Serialise against econet_writefd */

	spin_lock(&econet_irq_spin);

	/* Use SR values snapshot by the top half if available,
	 * otherwise re-read (e.g. first IRQ before fast_rx is set). */

	if (econet_data->shadow_sr1 || econet_data->shadow_sr2)
	{
		sr1 = econet_data->shadow_sr1;
		sr2 = econet_data->shadow_sr2;
		econet_data->shadow_sr1 = econet_data->shadow_sr2 = 0;
	}
	else
	{
		sr1 = econet_read_sr(1);
		sr2 = (sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;

		if (!(sr1 & ECONET_GPIO_S1_IRQ))
		{
			sr1 = econet_read_sr(1);
			sr2 = (sr1 & ECONET_GPIO_S1_S2RQ) ? econet_read_sr(2) : 0;
		}
	}
	
	chip_state = econet_get_chipstate();

	if (chip_state == EM_TEST)
	{
		printk_ratelimited(KERN_INFO "econet-fast: IRQ handler called in test mode - disabling IRQ");

		/* Turn off ADLC IRQs */
		econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_TX_RESET | ECONET_GPIO_C1_RX_RESET);

		/* Disable at the GIC too — if the ADLC doesn't de-assert
		 * its IRQ line, level-triggered re-entry causes an IRQ storm
		 * that saturates the GPIO bus and triggers a firmware reset.
		 * Must use _nosync from within the handler itself. */
		disable_irq_nosync(econet_data->irq);
		econet_set_irq_state(0);
	}
	else if (chip_state == EM_FLAGFILL) /* IRQs are supposed to be off - let's make sure thye are */
	{
		/* We'll also discontinue RX just in case, and reset RX */

		printk (KERN_INFO "econet-fast: IRQ in EM_FLAGFILL state - ensuring TX IRQs are off\n");

		econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_RX_RESET | ECONET_GPIO_C1_RX_DISC);
		handled = 1;
	}
	else if (sr1 & ECONET_GPIO_S1_IRQ)
	{

		if (econet_data->rxp) /* Should always be non-null, even during TX */
		{

			if (chip_state == EM_WRITE_WAIT)
			{
				econet_data->pkt_since_idle++; /* We've transmitted a packet - increase our pkt count since idle */

				if (!(sr1 & ECONET_GPIO_S1_TDRA)) /* On this IRQ, we should have FC set. If we don't, let's flag an error for now */
					printk (KERN_INFO "econet-data: IRQ received in EM_WRITE_WAIT but Frame Complete not set. txp->ptr = 0x%02X, txp->txlen = 0x%02X\n", econet_data->txp->ptr, econet_data->txp->txlen);

				if (
					(econet_data->pkt_since_idle == 1 && __IS_TWOWAY(econet_data->txp)) /* We've just transmitted a two-way immediate - don't flag fill on the reply */
				||	(econet_data->pkt_since_idle == 3) /* Must be data phase of 4-way */
				)
				{
					econet_data->no_flag_fill = 1; /* Expecting next packet to be reply to immediate, or final phase of 4-way, so don't flag fill */
					// printk (KERN_INFO "econet-fast: Setting no_flag_fill\n");
				}
					
				econet_set_read_mode();
				// econet_data->txp->timing_end = ktime_get_ns();
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

				/* Enable fast-path FIFO reads in the top half
				 * for subsequent data bytes in this frame. */

				atomic_set(&econet_data->fastpath_enabled, 1);

				/* Mark start of reception */
				// econet_data->rxp->timing_start = ktime_get_ns();
			}
			else if ( /* TX-Specific Errors we need to look at */
					chip_state == EM_WRITE 
				&&	econet_data->txp
				&&	(sr1 & ECONET_GPIO_S1_UNDERRUN)
				)
			{
				econet_set_chipstate(EM_IDLE);
				chip_state = EM_IDLE;
				econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;
				printk (KERN_INFO "econet-fast: TX Underrun detected - SR1 = 0x%02X, SR2 = 0x%02X, txp->ptr = 0x%04X, txp->txlen = 0x%04X\n",
						sr1, sr2, econet_data->txp->ptr, econet_data->txp->txlen);
				econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX); /* Puts an empty packet into the monitor kfifo, but has the status in it */
				econet_set_read_mode();
				handled = 1;
			}
			else if ( /* Errors we need to clear */
				(sr1 & (ECONET_GPIO_S1_FLAG))
				||	(sr2 & (ECONET_GPIO_S2_RX_IDLE))
				)
			{
				econet_set_chipstate(EM_IDLE);
				chip_state = EM_IDLE;
				econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;
				if (econet_data->rxp->ptr > 0)
					printk (KERN_INFO "econet-fast: RX Idle received at rxptr=0x%04X", econet_data->rxp->ptr);
				econet_irq_to_workqueue(&(econet_data->rxp), sr1, sr2, EP_PACKET_RX); /* Puts an empty packet into the monitor kfifo, but has the status in it */
				econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Just clear status
				handled = 1;
			}	

			if (econet_data->clock_state && (sr2 & ECONET_GPIO_S2_DCD)) /* Clock lost */
			{
				econet_set_chipstate(EM_IDLE);
				chip_state = EM_IDLE;
				econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;
				printk (KERN_ERR "econet-fast: No clock\n");
				econet_write_cr(1, C1_READ);
				econet_write_cr(2, C2_READ);
				econet_data->clock_state = 0;
				handled = 1;
			}

			if (!(econet_data->clock_state) && !(sr2 & ECONET_GPIO_S2_DCD)) /* Clock resumed */
			{
				econet_set_chipstate(EM_IDLE);
				econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;
				chip_state = EM_IDLE;
				printk (KERN_INFO "econet-fast: Clock resumed\n");
				econet_write_cr(1, C1_READ);
				econet_write_cr(2, C2_READ);
				econet_data->clock_state = 1;
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
				case EM_IDLE:
					handled = 1;
					break;
				default:
					/* Shouldn't happen - switch off! */
					printk (KERN_ERR "econet-fast: Unhandled chip mode %02X in IRQ handler, sr1 = 0x%02X, sr2 = 0x%02X. Disabling.\n", chip_state, sr1, sr2);
					econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_TX_RESET | ECONET_GPIO_C1_RX_RESET);
					disable_irq_nosync(econet_data->irq);
					econet_set_irq_state(0);
					econet_set_chipstate(EM_TEST);
					ECONET_NOT_BUSY();
					handled = 1;
					break;
			}
		}
		else
		{
			printk (KERN_ERR "econet-fast: No RX packet storage in IRQ handler! (rxp = %p) - disabling IRQ\n", econet_data->rxp);

			/* Turn the ADLC off and disable at the GIC to prevent
			 * IRQ storm if the ADLC doesn't de-assert its line. */

			econet_set_chipstate(EM_TEST);

			econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_TX_RESET | ECONET_GPIO_C1_RX_RESET);

			disable_irq_nosync(econet_data->irq);

			econet_set_irq_state(0);

			handled = 1;
		}
		
	}
	else
	{
		printk (KERN_INFO "econet-fast: IRQ handler called but ADLC not flagging an IRQ (SR1 = %02X, SR2 = %02X)", sr1, sr2);

		/* Reset CRs to try and get the thing to continue */
#if 0
		switch (chip_state) 
		{
			case EM_WRITE:
				{
					econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2);
					break;
				}
			case EM_READ:
				{
					econet_write_cr(ECONET_GPIO_CR2, C2_READ);
					break;
				}
			default: /* Probably idle! */
				{
					econet_adlc_cleardown(1);
					econet_set_read_mode();
				}
		}
#else
		if (chip_state == EM_WRITE || chip_state == EM_WRITE_WAIT)
		{
			econet_set_chipstate(EM_IDLE);

			if (!econet_data->txp)
				econet_data->txp = econet_alloc_pbuf();

			if (!econet_data->txp)
				printk (KERN_ERR "econet-fast: No available packet structure for txp! Failure not logged to workqueue.\n");
			else
			{
				econet_data->txp->sr1 = sr1;
				econet_data->txp->sr2 = sr2;
				econet_data->txp->tx_flags = EP_IRQHANDLER_FAILED;
				econet_irq_to_workqueue(&(econet_data->txp), sr1, sr2, EP_PACKET_TX); 
			}
		}
		else
		{
			econet_set_chipstate(EM_IDLE);

			if (!econet_data->rxp)
			{
				printk (KERN_ERR "econet-fast: RX packet buffer is null on IRQ Failure handler!\n");
				econet_data->rxp = econet_alloc_pbuf();
			}

			if (!econet_data->rxp)
				printk (KERN_ERR "econet-fast: RX packet buffer remained null after IRQ failure handler tried to re-allocate it. RX packet buffer starving! Failure not sent to workqueue.\n");
			else
			{
				econet_data->rxp->sr1 = sr1;
				econet_data->rxp->sr2 = sr2;
				econet_data->rxp->tx_flags = EP_IRQHANDLER_FAILED;
				econet_irq_to_workqueue(&(econet_data->rxp), sr1, sr2, EP_PACKET_RX); 
			}
		}

		econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;
		handled = 1;

		ECONET_NOT_BUSY();
#endif
	}

	/*
	 * Sync fastpath_enabled with the current chipstate.
	 * Only EM_READ should allow the top half to fast-path FIFO
	 * reads — any other state means we're between frames, in a
	 * TX phase, or recovering from an error, and the top half
	 * must wake the thread for proper state-machine handling.
	 */
	if (econet_get_chipstate() == EM_READ || econet_get_chipstate() == EM_WRITE)
		atomic_set(&econet_data->fastpath_enabled, 1);
	else
		atomic_set(&econet_data->fastpath_enabled, 0);

	/*
	 * Unlock IRQ spinlock prior to return.
	 *
	 */

	spin_unlock(&econet_irq_spin);

	/* Return */

	return IRQ_HANDLED;

}

MODULE_LICENSE("GPL");
