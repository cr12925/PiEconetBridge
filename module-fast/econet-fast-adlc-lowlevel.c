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

/* Variables primarily used here */

/* Variables to hold the two main status registers */

u8 sr1, sr2;

/* 32-bit value for writing to GPIO register */

u32 gpioset_value;

/* GPIO address */

void __iomem *GPIO_PORT = NULL;
unsigned GPIO_RANGE = 0x40;

/* 
 * econet_set_dir - calls econet_set_rw, but also changes the direction of the data bus GPIOs
 * This is the function which is likely to be used in production; econet_set_rw would really only be
 * used in testing to see if the code / GPIO works
 * ECONET_GPIO_READ / ... _WRITE
 */

/* This routine is no longer used in normal operations and only gets called for testing purposes */
/* All bus direction changes are now done inside econet_read_sr() or econet_write_cr() */

void econet_set_dir(short d)
{

	if (econet_data->current_dir == d)
		return; // No need to do anything - direction currently as we want it

#ifdef ECONET_GPIO_NEW

	u8	count;

	for (count = EGP_D0; count <= EGP_D7; count++)
	{
		if (d == ECONET_GPIO_WRITE)
			gpiod_direction_output(econet_data->econet_gpios[count], 0); // Set to 0 output for now
		else
			gpiod_direction_input(econet_data->econet_gpios[count]);
	}

#else
	iowrite32((ioread32(NGPFSEL2) & ~ECONET_GPIO_DATA_PIN_MASK) | 
		(d == ECONET_GPIO_WRITE ? ECONET_GPIO_DATA_PIN_OUT : 0),
		NGPFSEL2);
#endif

	econet_set_rw(d);

	econet_data->current_dir = d;

	barrier();

}

/* 
 * econet_write_cr - write value to ADLC control register
 *
 */

inline void econet_write_cr(unsigned short r, unsigned char d)
{
#ifdef ECONET_GPIO_NEW
	unsigned long int gpioval;
	u8	count;
#else
	u32 gpioval, gpiomask;
#endif

	if (r > 4)
	{
		printk (KERN_ERR "econet-fast: Attempt to write to CR%d ! What is going on ?", r);
		return;
	}

	r--;

#ifndef ECONET_GPIO_NEW
	gpiomask = ECONET_GPIO_CLRMASK_DATA | ECONET_GPIO_CLRMASK_RW | ECONET_GPIO_CLRMASK_ADDR;

	gpioval = (r & 0x03) << ECONET_GPIO_PIN_ADDR;
	gpioval |= (d << ECONET_GPIO_PIN_DATA);
#endif

	// No need to set RW because it will be 0 by virtue of the first assignment to gpioval above.

	if (econet_data->hwver >= 2)
		econet_wait_not_busy();


#ifdef ECONET_GPIO_NEW

	// Turn direction around

	if (econet_data->current_dir != ECONET_GPIO_WRITE)
		for (count = EGP_D0; count <= EGP_D7; count++)
			gpiod_direction_output(econet_data->econet_gpios[count], 0); // Set to 0 output for now

	econet_data->current_dir = ECONET_GPIO_WRITE;

	// Set address & RnW & data
	gpioval = (r << 8) | d; // RnW = 0 for write
	gpiod_set_array_value (11, data_desc_array, NULL, &gpioval); // 11 because the address & RnW are in 8,9,10

	// Enable nCS - Tell the ADLC we want to talk to it
	
	econet_set_cs(ECONET_GPIO_CS_ON);


#else
	// Put that lot on the GPIO
	iowrite32(gpioval, NGPSET0);
	iowrite32((~gpioval) & gpiomask, NGPCLR0);

	// Now swing our own bus direction round

	if (econet_data->current_dir != ECONET_GPIO_WRITE)
	{
		iowrite32(((ioread32(NGPFSEL2)) & ~ECONET_GPIO_DATA_PIN_MASK) | ECONET_GPIO_DATA_PIN_OUT, NGPFSEL2);
		econet_data->current_dir = ECONET_GPIO_WRITE;
	}

	// Enable nCS - Tell the ADLC we want to talk to it
	
	econet_set_cs(ECONET_GPIO_CS_ON);

	barrier();
#endif

#ifndef ECONET_GPIO_NEW
	// If v1 hardware, wait until we know CS has reached the ADLC

	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}

	barrier(); // Operates for both v1 & v2 hardware
#endif

	// Disable nCS again
	
	econet_set_cs(ECONET_GPIO_CS_OFF);

	// Delay here to allow chip to settle. We had this in write_bus() because it appeared
	// to avoid duplicate writes

	barrier();

#ifndef ECONET_GPIO_NEW
	if (econet_data->hwver < 2)
	{
		econet_ndelay(ECONET_GPIO_CLOCK_DUTY_CYCLE); 
	}
	else
#endif
		econet_wait_not_busy(); // Wait until the ADLC has read our data. Not massively reliable yet.. SHouldn't be required, but seems to be!
}

/* 
 * Macro abstracting econet_read_sr() to read FIFO
 */

/* Moved to header
#define econet_read_fifo() econet_read_sr(3)
*/

/* 
 * econet_read_sr - read value from ADLC status register
 *
 */

inline unsigned char econet_read_sr(unsigned short r)
{
	unsigned char d;
#ifdef ECONET_GPIO_NEW
	unsigned long int 	gpioval_array;
#endif
	u32 gpioval, gpiomask;

	if (r > 4)
	{
		printk (KERN_ERR "econet-fast: Attempt to read SR%d ! What is going on ?\n", r);
		return 0;
	}

	r--;

	if (econet_data->hwver >= 2)
		econet_wait_not_busy();


	// First, set the data pins to read if need be

	if (econet_data->current_dir != ECONET_GPIO_READ)
	{
#ifdef ECONET_GPIO_NEW
		u8	count;
#endif

		econet_data->current_dir = ECONET_GPIO_READ;
#ifdef ECONET_GPIO_NEW

		for (count = EGP_D0; count <= EGP_D7; count++)
			gpiod_direction_input(econet_data->econet_gpios[count]);
#else
		iowrite32(ioread32(NGPFSEL2) & ~ECONET_GPIO_DATA_PIN_MASK, NGPFSEL2);
		// 20251127 Shouldn't be required: barrier();
#endif
	}

#ifdef ECONET_GPIO_NEW

	gpioval = r | 0x04; // 0x04 is third bit in the value, which is the RW figure, and we need 1 for read because the pin is RnW

	if (gpiod_set_array_value (3, a01rw_desc_array, NULL, &gpioval) < 0)
	{
		printk (KERN_ERR "econet-fast: Error writing address lines ready to ready SR\n");
		return 0;
	}
	
#else
	// Sets up a single gpio value & mask and plonks it on the hardware in one go
	// And the mask, so that we can write the 0s properly
	
	gpiomask = ECONET_GPIO_CLRMASK_ADDR | ECONET_GPIO_CLRMASK_RW;

	// Next, put the address into our prepared value - Nothing has gone in this before, so a straigth = rather than |= will be fine
	
	gpioval = (r << ECONET_GPIO_PIN_ADDR) | ECONET_GPIO_CLRMASK_RW;

	// Now, put that on the hardware

	iowrite32(gpioval, NGPSET0);
	iowrite32((~gpioval) & gpiomask, NGPCLR0);
	

#endif

	/* 20260404 Try a delay here in case we are not waiting long enough for address lines to settle */
	// ndelay(5);
	ndelay(1); /* 20260406 Try 1ns instead of 5 in case that's causing these clock lockups ? */

	// Waggle nCS appropriately
	
	econet_set_cs(ECONET_GPIO_CS_ON);

#ifndef ECONET_GPIO_NEW
	/*
	 * Wait for the /CS signal to come back to us on /CSRETURN
	 */

	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}
	else
#endif
		barrier();

	if (econet_data->hwver >= 2)
		ndelay(1); /* 20260406 Try 1ns instead of 5 in case that's causing these clock lockups ? */

	/* Finish with ADLC */

	econet_set_cs(ECONET_GPIO_CS_OFF);	

#ifndef ECONET_GPIO_NEW
	if (econet_data->hwver < 2)
	{
		ndelay(100);
	}
	else
#endif
		econet_wait_not_busy();

#ifdef ECONET_GPIO_NEW

	if (gpiod_get_array_value(8, data_desc_array, NULL, &gpioval_array) < 0)
	{
		printk (KERN_ERR "econet-fast: Error reading GPIOs!\n");
		d = 0;
	}
	else
	{
		d = gpioval_array & 0xff;
	}

#else
	d = (ioread32(NGPLEV0) & ECONET_GPIO_CLRMASK_DATA) >> ECONET_GPIO_PIN_DATA;
#endif

	return d;	
}


/* Chip reset function - Leaves us in test mode with IRQs off */

void econet_reset(void)
{

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "econet-fast: econet_reset() called\n");
#endif

	/* Clear the kernel FIFOs */

	kfifo_reset(&(econet_data->readfd_fifo));
	kfifo_reset(&(econet_data->monitor_fifo));

	/* Turn IRQs off */

	econet_irq_mode(0);

	/* Clear station map */

	ECONET_INIT_STATIONS(econet_stations);

	econet_adlc_cleardown(0); // 0 = not in IRQ context

	init_waitqueue_head(&econet_data->rx_queue);

	/* Take us out of AUN mode and set the chip to read */

	econet_data->aun_mode = 0;
	econet_data->resilience = 0;
	econet_data->aun_last_tx = econet_data->aun_last_rx = 0;
	atomic64_set(&(econet_data->last_aun_rx_complete), 0);

	econet_set_read_mode(); // Required in addition to the cleadown, because this sets the ADLC up to read, where as cleardown doesn't.

	/* Set clock state */

	econet_data->clock_state = !!(econet_read_sr(2) & ECONET_GPIO_S2_DCD);

	if (econet_data->extralogs)
		printk (KERN_INFO "econet-fast: Module reset. AUN mode off. ADLC re-initialized.\n");

}


/*
 * econet_set_read_mode()
 *
 * Resets the receive packet buffer and sets up the ADLC
 * ready to receive. Puts the chip state machine into 
 * Idle init.
 *
 * Re-sets timer for last data reception so we can tell if
 * we got stuck part way through a packet read.
 *
 * Doesn't alter AUN state because this function is used
 * *during* 4-way exchanges where the AUN state has to be
 * maintained.
 *
 */

void econet_set_read_mode(void)
{

	econet_write_cr(ECONET_GPIO_CR2, C2_READ);
	econet_write_cr(ECONET_GPIO_CR1, C1_READ);

	econet_set_chipstate(EM_IDLE);  /* 20260320 was IDLEINIT */

	atomic_set(&(econet_data->fastpath_enabled), 0);

	last_data_rcvd = 0; // Last time we received data off the wire. Detect stuck in read mode when we want to write

	ECONET_NOT_BUSY(); /* Does what it says */
}

/*
 * econet_seize()
 *
 * Attempts to seize the line unless already in flag fill
 *
 * Returns one of the ECONET_TX_ constants from econet-gpio-consumer.h
 *
 * Note, though, that in this context ECONET_TX_SUCCESS does *not* mean the packet has been
 * transmitted, obvs....
 *
 * Do NOT call this routine until econet->txp has a frame ready to tx on the wire otherwise
 * an IRQ for tx will be generated and there may be invalid data read from that structure
 * by the IRQ handler.
 *
 */

/* The old version is below this function. This function is an attempt
   to copy what ANFS 4.08 does
   NEVER call this in IRQ context.
 */

u8 econet_seize(u8 in_irq)
{

	u8 outercount = 0;
	u8 chip_state = econet_get_chipstate();

	if (chip_state == EM_FLAGFILL)
	{
		// printk (KERN_INFO "econet-fast: Set EM_WRITE since in flag fill\n");
		econet_set_chipstate(EM_WRITE); /* Do this before turning IRQs on otherwise IRQ happens in flag fill state! */

		econet_write_cr(ECONET_GPIO_CR2, 
				ECONET_GPIO_C2_PSE
			|	ECONET_GPIO_C2_RTS
			|	ECONET_GPIO_C2_FLAGIDLE /* We do this but ANFS doesn't ? */
			|	(econet_data->twobytemode ? ECONET_GPIO_C2_2BYTES : 0)
		);

		/* We write this again here because it turns IRQs on for us */

		econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2); // + (TIE + RX Reset)

		return ECONET_TX_SUCCESS;
	}

	if (in_irq) /* Don't go further - this loop takes a long time, just barf out */
		return 0;

	sr2 = econet_read_sr(2);

	if (sr2 & ECONET_GPIO_S2_DCD) /* Clock */
	{
		printk_ratelimited (KERN_ERR "econet-fast: No clock attempting to seize line!\n");
		econet_set_read_mode();
		return ECONET_TX_NOCLOCK;
	}

	/* Taken from bridge diassembly at https://acornaeology.uk/acorn-econet-bridge/variant_1.html#addr-E690 */

	while (outercount++ < 256)
	{

		/* Prime CR2 */

		econet_write_cr(2, ECONET_GPIO_C2_CLR_RX_STATUS
				|  ECONET_GPIO_C2_CLR_TX_STATUS
				|  ECONET_GPIO_C2_FLAGIDLE
				|  ECONET_GPIO_C2_PSE
				|  (econet_data->twobytemode ? ECONET_GPIO_C2_2BYTES : 0)
			);

		sr2 = econet_read_sr(2);

		if (sr2 & ECONET_GPIO_S2_RX_IDLE)
		{
			/* Off we go */
			
			econet_set_chipstate(EM_WRITE);
			econet_write_cr(2, ECONET_GPIO_C2_RTS
				|	ECONET_GPIO_C2_CLR_RX_STATUS
				|	ECONET_GPIO_C2_CLR_TX_STATUS
				|	ECONET_GPIO_C2_PSE
				|	ECONET_GPIO_C2_FLAGIDLE
				|	(econet_data->twobytemode ? ECONET_GPIO_C2_2BYTES : 0)
			);
			econet_write_cr(1, ECONET_GPIO_C1_TINT | ECONET_GPIO_C1_RX_RESET);
	
			return ECONET_TX_SUCCESS; /* Not really TX success - just 0 for success */
		}

		if (sr2 & (ECONET_GPIO_S2_AP | ECONET_GPIO_S2_RDA))
		{
			/* Someone is transmitting - fail */

			econet_set_read_mode();
			return ECONET_TX_JAMMED;
		}

		/* Read SR1 - clear pending IRQ (apparently!) */

		sr1 = econet_read_sr(1);

		econet_write_cr(2, ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FC |
			ECONET_GPIO_C2_CLR_RX_STATUS |
			ECONET_GPIO_C2_CLR_TX_STATUS |
			(econet_data->twobytemode ? ECONET_GPIO_C2_2BYTES : 0)
		);

		// udelay (1 << outercount); /* Exponential backoff */

	}

	econet_set_read_mode();
	printk (KERN_INFO "econet-fast: Reporting line jammed on line seize\n");
	return ECONET_TX_JAMMED;
	
}


/* Old version */

u8 econet_seize_old(void)
{

	u8 count = 0, outercount = 0, seize_error = ECONET_TX_JAMMED;

	if (econet_get_chipstate() == EM_FLAGFILL)
	{
		// printk (KERN_INFO "econet-fast: Set EM_WRITE since in flag fill\n");
		econet_set_chipstate(EM_WRITE); /* Do this before turning IRQs on otherwise IRQ happens in flag fill state! */
		econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2); // + (TIE + RX Reset)
		return ECONET_TX_SUCCESS;
	}

	sr2 = econet_read_sr(2);

	if (sr2 & ECONET_GPIO_S2_DCD) /* No clock */
	{
		printk (KERN_ERR "econet-fast: No clock attempting to seize line!\n");
		econet_set_read_mode();
		return ECONET_TX_NOCLOCK;
	}

	/* 20260329 Reset both TX and RX sections */

	econet_write_cr (ECONET_GPIO_CR1, ECONET_GPIO_C1_RX_RESET | ECONET_GPIO_C1_TX_RESET);

	
	while (seize_error && (outercount++ < 2))
	{
		// printk (KERN_INFO "econet-fast: Line seize attempt %d\n", outercount);

		// This gets done in the loop below ? Why do it here too ? econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT1);

		count = 0;

		while (count++ < 5 && !(sr2 & ECONET_GPIO_S2_RX_IDLE))
		{

			// printk (KERN_INFO "econet-fast: Line not idle; inner seize count %d\n", count);

			econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT1);

			/* Exponential backoff */

			udelay (count << 1);

			sr2 = econet_read_sr(2);
		}

		/* Is the line idle ? */

		if (sr2 & ECONET_GPIO_S2_RX_IDLE)
		{
			// printk (KERN_INFO "econet-fast: Line idle after seize attempt\n");

			econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2); // +RTS

			/* Commented 20260329 - C1_WRITE_INIT2 does an RX Reset and enables TIE. Let's not turn TIE on just yet */
			// econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2); // + (TIE + RX Reset)

			/* Check to see if CTS went low */

			sr1 = econet_read_sr(1);

			if (!(sr1 & ECONET_GPIO_S1_CTS))
			{
				// printk (KERN_INFO "econet-fast: Clear to send\n");
				seize_error = ECONET_TX_SUCCESS;
				break;
			}
			else	seize_error = ECONET_TX_JAMMED;
		}
	}

	// printk (KERN_INFO "econet-fast: Line seize loop exit\n");

	if (!seize_error) /* Seized */
	{
		econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2); // + (TIE + RX Reset)
		econet_set_chipstate(EM_WRITE);
	}
	else	
	{
		printk (KERN_INFO "econet-fast: Failed line seize - SR1 = 0x%02X, SR2 = 0x%02X\n", sr1, sr2);
		econet_set_read_mode();
	}

	return seize_error;
}

/* 
 * econet_flagfill()
 *
 * Put the ADLC into flag fill mode.
 *
 */

void econet_flagfill(void)
{

#if 0 /* Old version */
	econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); 
	econet_set_chipstate(EM_FLAGFILL); /* This goes here because otherwise an IRQ turns up quickly and we get an IRQ in FLAGFILL before we've set the registers! */
	econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2); 
#else /* What ANFS does - see ANFS 4.08 disassembly at &878D */

	/* Put RX side into reset until we're ready and turn IRQs off */

	econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_RX_RESET); 

	/* Set chip state now IRQs can't happen */

	econet_set_chipstate(EM_FLAGFILL);

	/* Set up for TX */

	econet_write_cr(ECONET_GPIO_CR2,	ECONET_GPIO_C2_RTS
					|	ECONET_GPIO_C2_CLR_TX_STATUS
					|	ECONET_GPIO_C2_CLR_RX_STATUS /* Added 20260426 as a trial to see if it avoids byte 0 RX Idles */
					|	ECONET_GPIO_C2_FLAGIDLE /* We do this but ANFS doesn't? */
					|	ECONET_GPIO_C2_PSE
					|	(econet_data->twobytemode ? ECONET_GPIO_C2_2BYTES : 0)
					|	ECONET_GPIO_C2_FC /* Probably will stop IRQs in flag fill - we'll undo this when we seize */
			);

	/* TX Interrupts on - NO, they get turned on during line seize */

	// econet_write_cr(ECONET_GPIO_CR1,	ECONET_GPIO_C1_RX_RESET | ECONET_GPIO_C1_TINT);
#endif

}

MODULE_LICENSE("GPL");
