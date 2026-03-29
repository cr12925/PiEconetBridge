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

/* Structure used to dump a packet off the rx FIFO if it's full */
struct __econet_packet dump_pkt;

/* Packet counter */

unsigned long tx_packets;

/*
 * Bitmap of 65536 stations we 
 * might receive traffic for. 
 *
 * Updated from user space with ioctl()
 *
 */

unsigned char econet_stations[8192];

/* 
 * Buffers to hold packets to be tx'd,
 * packet being rx'd and
 * ... er, something else.
 *
 */

struct __econet_pkt_buffer      econet_pkt_tx,
                                econet_pkt_tx_prepare,
                                econet_pkt_rx;

/* 
 * writefd() buffer
 */

struct __econet_pkt_buffer pkt_copy; /* Temporary buffer for incoming / outgoing packets */

/*
 * Tracks when last data received
 *
 * So we can tell whether to start new transaction
 *
 */

u64 last_data_rcvd;

/* 
 * econet_probe_adapter()
 *
 * Probe the v1 hardware, once GPIOs obtained
 *
 */

int econet_probe_adapter(void)
{

	if (econet_data->hwver == 1) /* Test the CSRETURN circuitry */
	{
        	// put CS low, high and then low again and on each occasion
        	// check that the matching signal comes back on the /CS return line
        	// thus showing that there is a D-Type there with a working clock
	
        	econet_set_cs(0);
	
        	udelay(2); // 2us should always be enough
	
        	if ((ioread32(NGPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) != 0)
        	{
	
                	printk (KERN_ERR "econet-fast: Version 1 hardware test failed - nCS return not returning (test 1).\n");
                	return 0;
        	}
	
        	econet_set_cs(1);
	
        	/* This is the old code. Only used on v1 hardware. Duration now hard coded. */
        	/* udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE); */
        	udelay(1);
	
        	if ((ioread32(NGPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) == 0)
        	{
                	printk (KERN_ERR "econet-fast: Version 1 hardware test failed - nCS return not returning (test 2).\n");
                	return 0;
        	}
	
        	econet_set_cs(0);
	
        	/* This is the old code. Only used on v1 hardware. Duration now hard coded. */
        	/* udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE); */
        	udelay(1);
	
	
        	if ((ioread32(NGPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) != 0)
        	{
                	printk (KERN_ERR "econet-fast: Version 1 hardware test failed - nCS return not returning (test 3).\n");
                	return 0;
        	}
	}

	/* All versions, let's put +TIE, wait a microsecond or two and see if IRQ goes high */

	/* TODO */

        return 1;

}

/*
 * econet_adlc_cleardown()
 *
 * Does a full ADLC reset and re-sets up the registers.
 *
 */

void econet_adlc_cleardown(unsigned short in_irq)
{

        if (econet_data->extralogs) printk (KERN_INFO "econet-fast: Performing ADLC chip reset\n");

        if (!in_irq)
                econet_irq_mode(0);

        /* Hold RST low for 100ms */

        econet_set_rst(ECONET_GPIO_RST_RST);

        udelay(10); // Spec says we only need 1us...

        econet_set_rst(ECONET_GPIO_RST_CLR);

        /* Chip is now fully re-set. Set up the one-time registers */

        /* To access CR3 & CR4, we must set the AC bit in CR1 (CR1b0) */

        econet_write_cr(ECONET_GPIO_CR1, 0x01);

        /* CR4 is in the same register as the second write data FIFO (the one
         * which is written to and automatically flags "last byte of frame"
         * but when CR1b0 (AC) is set, it is CR4 instead
         */

        econet_write_cr(ECONET_GPIO_CR4, C4_READ);

        /* CR3, however, is in the same address as CR2, but that "becomes"
         * CR3 when AC=1
         * So here, we are writing to CR3, but we write to the CR2
         * address
         */

        econet_write_cr(ECONET_GPIO_CR2, C3_READ);

        /* Clear the address control bit because write_cr won't do it */

        econet_write_cr(ECONET_GPIO_CR1, 0);

        /* Start in the idle state for the ADLC */

        econet_set_chipstate(EM_IDLE);

        /* Start the AUN state machine in idle */

        econet_set_aunstate(EA_IDLE);

        /* Set TX status to initial value */

        econet_set_tx_status(ECONET_TX_SUCCESS);

	/* Flag fill calculating variables */

	econet_data->pkt_since_idle = econet_data->no_flag_fill = 0;

        /* Set the last write timer so we know what turns up first is new */

        econet_data->aun_last_writefd = 0;

        atomic64_set(&(econet_data->last_aun_rx_complete), 0);

        if (!in_irq)
                econet_irq_mode(1);

}

/*
 * econet_finish_tx()
 *
 * Routine called when the IRQ routine has put the last byte of a frame into the FIFO.
 *
 * Signals to the ADLC that it can now put the checksum on the wire and then the closing flag.
 *
 */

void econet_finish_tx(void)
{


#ifdef ECONET_GPIO_DEBUG_TX
        printk (KERN_INFO "econet-fast: econet_finish_tx(): Finished packet TX\n");
#endif

        /*
         * Tell the 68B54 we've finished so it can end the frame
         *
         */

        econet_set_chipstate(EM_WRITE_WAIT);

        econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_TXLAST | ECONET_GPIO_C2_FC | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_PSE | ((econet_data && econet_data->twobytemode) ? ECONET_GPIO_C2_2BYTES : 0)); // No RX status reset

#ifdef ECONET_GPIO_DEBUG_TX
        econet_get_sr();
        printk (KERN_INFO "econet-fast: econet_finish_tx(): SR after C2_WRITE_EOF: SR1 = 0x%02x, SR2 = 0x%02x\n", sr1, sr2);
#endif

}

MODULE_LICENSE("GPL");
