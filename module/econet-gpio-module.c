/*
  (c) 2021 Chris Royle
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/mod_devicetable.h>
#include <linux/gpio/consumer.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/time64.h>
#include <linux/ktime.h>

#include <asm/uaccess.h>

#include "../include/econet-gpio.h"

#define ECONET_GPIO_CLOCK_DUTY_CYCLE  1000   /* In nanoseconds - 2MHz clock is 500 ns duty cycle, 1MHz is 1us, or 1000ns */
#define ECONET_GPIO_CLOCK_US_DUTY_CYCLE	1	/* In uSecs - 1us is the cycle time on a 1MHz clock, which is what the existing hardware has built on */

unsigned long *GPIO_PORT;
unsigned GPIO_RANGE = 0x40;
unsigned long *GPIO_CLK;
unsigned GPIO_CLK_RANGE = 0xA8;

short sr1, sr2;
long gpioset_value;

unsigned short econet_gpio_reg_obtained[17];

unsigned short econet_gpio_pins[17];
	
struct file_operations econet_fops = {
        .open = econet_open,
        .release = econet_release,
        .unlocked_ioctl = econet_ioctl,
        .poll = econet_poll,
        .read = econet_readfd,
        .write = econet_writefd
};

/* KFIFOs */
struct kfifo_rec_ptr_2 econet_rx_queue;
struct kfifo_rec_ptr_2 econet_tx_queue;

/* Structure used to dump a packet off the rx FIFO if it's full */
struct __econet_packet dump_pkt;

/* Internal data */
struct __econet_data *econet_data;
struct class *econet_class = NULL;

spinlock_t econet_irq_spin;
spinlock_t econet_tx_spin;
spinlock_t econet_irqstate_spin;

void econet_set_read_mode(void);
void econet_set_write_mode(struct __econet_pkt_buffer *, int);

unsigned char econet_stations[8192]; /* Station MAP - which are we proxying for */

struct __econet_pkt_buffer econet_pkt_tx, econet_pkt_tx_prepare, econet_pkt_rx;

struct __aun_pkt_buffer aun_tx, aun_rx;

char aun_stn, aun_net; // The net & station we are presently dealing with in the IP world - used to sanity check whether what comes off the wire is what we expect!

// u64 econet_timer;
u64 last_data_rcvd;

/*
 *
 *
 * ECONET GPIO - CHIP CONTROL CODE - ACCESS TO ADDRESSING, BUS, CONTROL LINES
 *
 * 
 */

/* 
 * econet_set_dir - calls econet_set_rw, but also changes the direction of the data bus GPIOs
 * This is the function which is likely to be used in production; econet_set_rw would really only be
 * used in testing to see if the code / GPIO works
 * ECONET_GPIO_READ / ... _WRITE
 */
void econet_set_dir(short d)
{

/*
	if (econet_data->current_dir == d)
		return;
*/

	econet_data->current_dir = d;

	econet_set_rw(d);

	/* Now change data bus direction */

	/* Always set to read. Read somewhere you needed to do this. Might just be first go, not sure. */
	{
		INP_GPIO(ECONET_GPIO_PIN_DATA);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 1);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 2);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 3);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 4);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 5);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 6);
		INP_GPIO(ECONET_GPIO_PIN_DATA + 7);
	}
	if (d == ECONET_GPIO_WRITE)
	{
		OUT_GPIO(ECONET_GPIO_PIN_DATA);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 1);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 2);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 3);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 4);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 5);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 6);
		OUT_GPIO(ECONET_GPIO_PIN_DATA + 7);
	}

}


/*
 * econet_write_bus - puts values on the bus but the timings are far shorter.
 * This is to see if it's any use in fixing the 3-byte problem on data TX.
 * Sets write mode.
 */

/* DISUSED code commented 12.09.11 - consider removal at v1

unsigned char econet_write_bus (unsigned char d)
{

	unsigned long gpioset_val = (d << ECONET_GPIO_PIN_DATA);

	// Calling routine will have already made sure chip not busy	

#ifdef ECONET_GPIO_DEBUG_BUS
	printk (KERN_DEBUG "ECONET-GPIO: Bus write 0x%02x (%c) - bits %d %d %d %d %d %d %d %d\n",
                d, 
		((d > 32) && (d < 'z') ? d : '.'),
		(d & 0x80) >> 7,
		(d & 0x40) >> 6,
		(d & 0x20) >> 5,
		(d & 0x10) >> 4,
		(d & 0x08) >> 3,
		(d & 0x04) >> 2,
		(d & 0x02) >> 1,
		(d & 0x01));
#endif

	econet_set_dir(ECONET_GPIO_WRITE);
	// Put it on the bus
	writel(gpioset_val, GPIO_PORT + GPSET0);
	writel((~gpioset_val) & ECONET_GPIO_CLRMASK_DATA, GPIO_PORT + GPCLR0);

	barrier();

//
	// Let it settle - was #ifndef ECONET_NO_NDELAY
#if 0
	//econet_ndelay(ECONET_GPIO_CLOCK_DUTY_CYCLE);
#else
	//udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE);
#endif

	// Turn on chip select
	econet_set_cs(ECONET_GPIO_CS_ON);
	barrier();
	
	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}
	//else	while (!econet_isbusy());


	// Turn off chip select
	econet_set_cs(ECONET_GPIO_CS_OFF);

	barrier();

	// Just put some delay in here in case the chip needs to settle
	// We put the line above in because sometimes we got a duplicate - i.e.
	// two bytes the same, and the second was in place of another byte that ought to have
	// been transmitted instead, as opposed to an *inserted extra* byte, which was the original
	// Problem. So this "overwrite" condition may be because the chip is trying to read the bus again
	// too quickkly, so we put a delay in.

	if (econet_data->hwver < 2)
	{
#ifndef ECONET_NO_NDELAY
	econet_ndelay(ECONET_GPIO_CLOCK_DUTY_CYCLE);
#else
	udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE);
#endif
	}

	return d;


}

--DISUSED CODE END COMMENT */

/*
 * econet_read_bus - reads current value off the bus. Sets read mode but DOES NOT set chip select
 */

/* Disused - commented out 12.09.21 - consider removal on release of v1 code

unsigned char econet_read_bus(void)
{

	unsigned char d;

	// Calling routine will have ensured !Busy

	econet_set_dir(ECONET_GPIO_READ);

	econet_set_cs(ECONET_GPIO_CS_ON);
	barrier();

	if (econet_data->hwver < 2)
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));

	econet_set_cs(ECONET_GPIO_CS_OFF); // Put this inactive again once we know the D-Type has clocked it to the 68B54
	barrier();

	if (econet_data->hwver < 2)
	{
// Hmm. What happens if we take this away altogether?

#ifndef ECONET_NO_NDELAY
		econet_ndelay(100); // Max wait time before data settles on bus according to chip spec, less a bit (180ns is what the spec says) // Was 100
#else
		__asm__ ("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; "
		"nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; "
		"nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; "
		"nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; "
		"nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; ");
#endif

	}
	else
	{
		while (econet_isbusy());
		while (econet_isbusy());
	}

	d = (readl(GPIO_PORT + GPLEV0) & ECONET_GPIO_CLRMASK_DATA) >> ECONET_GPIO_PIN_DATA;

#ifdef ECONET_GPIO_DEBUG_BUS
	printk (KERN_DEBUG "ECONET-GPIO: Bus read 0x%02x (%c) - bits %d %d %d %d %d %d %d %d\n",
                d, 
		((d > 32) && (d < 'z') ? d : '.'),
		(d & 0x80) >> 7,
		(d & 0x40) >> 6,
		(d & 0x20) >> 5,
		(d & 0x10) >> 4,
		(d & 0x08) >> 3,
		(d & 0x04) >> 2,
		(d & 0x02) >> 1,
		(d & 0x01));
#endif

	return d;
}

*/

#define econet_write_fifo(x) econet_write_cr(3, (x))

/* econet_write_cr - write value to ADLC control register
 */
void econet_write_cr(short r, unsigned char d)
{
	unsigned long gpioval, gpiomask;

	r--;

/* OLD CODE
	if (econet_data->hwver >= 2) while (econet_isbusy());

	econet_set_addr ((r & 0x02) >> 1, (r & 0x01));
	econet_write_bus(d);
*/

/* NEW CODE */

	gpiomask = ECONET_GPIO_CLRMASK_DATA | ECONET_GPIO_CLRMASK_RW | ECONET_GPIO_CLRMASK_ADDR;

	gpioval = (r & 0x03) << ECONET_GPIO_PIN_ADDR;
	gpioval |= (d << ECONET_GPIO_PIN_DATA);
	// No need to set RW because it will be 0 by virtue of the first assignment to gpioval above.

	if (econet_data->hwver >= 2)
		while (econet_isbusy());

	// Change the bus direction
                INP_GPIO(ECONET_GPIO_PIN_DATA);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 1);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 2);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 3);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 4);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 5);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 6);
                INP_GPIO(ECONET_GPIO_PIN_DATA + 7);

                OUT_GPIO(ECONET_GPIO_PIN_DATA);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 1);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 2);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 3);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 4);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 5);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 6);
                OUT_GPIO(ECONET_GPIO_PIN_DATA + 7);

	econet_data->current_dir = 0;

	// Put that lot on the GPIO
	writel(gpioval, GPIO_PORT+GPSET0);
	writel((~gpioval) & gpiomask, GPIO_PORT + GPCLR0);

	// Enable nCS
	econet_set_cs(ECONET_GPIO_CS_ON);

	// If v1 hardware, wait until we know CS has reached the ADLC
	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}
	else
		barrier();

	// Disable nCS again
	econet_set_cs(ECONET_GPIO_CS_OFF);

	// Delay here to allow chip to settle. We had this in write_bus() because it appeared
	// to avoid duplicate writes

	if (econet_data->hwver < 2)
	{
		// ? Try a barrier() here to see if we get a suitable delay.
		econet_ndelay(ECONET_GPIO_CLOCK_DUTY_CYCLE);
	}
	else
		while (econet_isbusy()); // Wait until the ADLC has read our data. Not massively reliable yet.

}

/* econet_read_sr - read value from ADLC status register
 */

#define econet_read_fifo() econet_read_sr(3)

unsigned char econet_read_sr(short r)
{
	unsigned char d;
	unsigned long gpioval, gpiomask;

	if (r > 4) return 0;

	r--;

	if (econet_data->hwver >= 2)
		while (econet_isbusy());

	// New code - sets up a single gpio value & mask and plonks it on the hardware in one go

	// First, set the data pins to read
	econet_data->current_dir = 1;
        INP_GPIO(ECONET_GPIO_PIN_DATA);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 1);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 2);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 3);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 4);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 5);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 6);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 7);

	// And the mask, so that we can write the 0s properly
	gpiomask = ECONET_GPIO_CLRMASK_ADDR | ECONET_GPIO_CLRMASK_RW;

	// Next, put the address into our prepared value - Nothing has gone in this before, so a straigth = rather than |= will be fine
	//gpioval = (((r & 0x02) << (ECONET_GPIO_PIN_ADDR + 1)) | ((r & 0x01) << (ECONET_GPIO_PIN_ADDR)));
	gpioval = (r & 0x03) << ECONET_GPIO_PIN_ADDR;

	// Next, set the RnW bit appropriately - and since we want a 1 we can use the mask

	gpioval |= ECONET_GPIO_CLRMASK_RW;

	// Now, put that on the hardware

	writel(gpioval, GPIO_PORT + GPSET0);
	writel((~gpioval) & gpiomask, GPIO_PORT + GPCLR0);
	
	// Shouldn't need a barrier here because apparently writel() has one in it.

	// Waggle nCS appropriately
	
	econet_set_cs(ECONET_GPIO_CS_ON);

	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}
	else
		barrier();

	econet_set_cs(ECONET_GPIO_CS_OFF);	

	if (econet_data->hwver < 2)
	{
		// ? Try a barrier() here and see if it generates the right sort of delay so we can ditch ndelay?
		econet_ndelay(100);
	}
	else
		while (econet_isbusy());

	d = (readl(GPIO_PORT + GPLEV0) & ECONET_GPIO_CLRMASK_DATA) >> ECONET_GPIO_PIN_DATA;

	// Old code follows
	
	//if (econet_data->hwver >= 2) while (econet_isbusy());
	//econet_set_addr ((r & 0x02) >> 1, (r & 0x01));
	//d = econet_read_bus();

	// Original retained code follows

#ifdef ECONET_GPIO_DEBUG_REG
	printk (KERN_DEBUG "ECONET-GPIO: Read SR%d = 0x%02x\n", r, d);
#endif
	return d;	
}

/* Release the GPIO pins we successfully obtained */
void econet_gpio_release_pins(void)
{

	unsigned short counter;

	for (counter = 0; counter < 17; counter++)
		if(econet_gpio_reg_obtained[counter])
			gpio_free(econet_gpio_pins[counter]);

	return;

}

/* Probe the hardware, once GPIOs obtained */

int econet_probe_adapter(void)
{

	// Do a reset to make sure IRQ line is clear

	econet_set_rst(ECONET_GPIO_RST_RST);
	msleep(100);
	econet_set_rst(ECONET_GPIO_RST_CLR);

	// Look at the IRQ line and see if it's high (v1) or low (v2 onwards)

	if (econet_gpio_pin(ECONET_GPIO_PIN_IRQ) == 0) // Likely v2 hardware
	{

		// Set nCS active and we should see BUSY immediately
		econet_data->hwver = 2;
		econet_set_cs(ECONET_GPIO_CS_ON);
		barrier();

		if ((readl(GPIO_PORT + GPLEV0) & (1 << ECONET_GPIO_PIN_BUSY)) == 0) // Circuit didn't produce busy when we turned nCS active, which it should - it'll go busy for a variable length of time depending on where we are in the board's local (8MHz divided to) 2MHz clock cycle, but not more than about 500ns. Possible given busy delay on the GPIO that it may have gone !busy by the time we read it, but hopefully not!
		{
			econet_data->hwver = 0;
			printk (KERN_ERR "ECONET-GPIO: Version 2 hardware test failed.\n");
			econet_set_cs(ECONET_GPIO_CS_OFF);	
			return 0;
		}
		econet_set_cs(ECONET_GPIO_CS_OFF);
		return 1;
	}

	// put CS low, high and then low again and on each occasion
	// check that the matching signal comes back on the /CS return line
	// thus showing that there is a D-Type there with a working clock

	econet_set_cs(0);

	udelay(2); // 2us should always be enough
	if ((readl(GPIO_PORT + GPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) != 0)
	{

		printk (KERN_ERR "ECONET-GPIO: Version 1 hardware test failed - nCS return not returning (test 1).\n");
		return 0;
	}

	econet_set_cs(1);
	udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE);

	if ((readl(GPIO_PORT + GPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) == 0)
	{
		printk (KERN_ERR "ECONET-GPIO: Version 1 hardware test failed - nCS return not returning (test 2).\n");
		return 0;
	}

	econet_set_cs(0);
	udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE);

	if ((readl(GPIO_PORT + GPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) != 0)
	{
		printk (KERN_ERR "ECONET-GPIO: Version 1 hardware test failed - nCS return not returning (test 3).\n");
		return 0;
	}

	return 1;

}

/* Set up GPIO region */

short econet_gpio_init(void)
{

	unsigned long t; /* Variable to read / write GPIO registers in this function */
	//unsigned long fsel = 0;
	//unsigned long reg = 0, reg_mask = 0;
	unsigned short counter;
	int err;

	/* Set up the pin assignments array - Data lines */
	for (counter = 0; counter < 8; counter++)
		econet_gpio_pins[EGP_D0 + counter] = ECONET_GPIO_PIN_DATA + counter;

	/* ... and the address lines */
	for (counter = 0; counter < 2; counter++)
		econet_gpio_pins[EGP_A0 + counter] = ECONET_GPIO_PIN_ADDR + counter;

	/* And the rest */
	econet_gpio_pins[EGP_RST] = ECONET_GPIO_PIN_RST;
	econet_gpio_pins[EGP_CS] = ECONET_GPIO_PIN_CS;
	econet_gpio_pins[EGP_CLK] = ECONET_GPIO_PIN_CLK;
	econet_gpio_pins[EGP_RW] = ECONET_GPIO_PIN_RW;
	econet_gpio_pins[EGP_DIR] = ECONET_GPIO_PIN_BUSY;
	econet_gpio_pins[EGP_IRQ] = ECONET_GPIO_PIN_IRQ;
	econet_gpio_pins[EGP_CSRETURN] = ECONET_GPIO_PIN_CSRETURN;

	/* Zero out the pin request array */

	for (counter = 0; counter < 17; counter++)
		econet_gpio_reg_obtained[counter] = 0;
	
	/* Request the pins */

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "ECONET-GPIO: Requesting GPIOs\n");
#endif

	for (counter = 0; counter < 17; counter++)
	{
		if ((err = gpio_request(econet_gpio_pins[counter], THIS_MODULE->name)) != 0)
		{
			printk (KERN_INFO "ECONET-GPIO: Failed to request GPIO BCM %d\n", econet_gpio_pins[counter]);
			econet_gpio_release_pins();
			return err;
		}
		else
		{
			econet_gpio_reg_obtained[counter] = 1;	
			gpio_export(econet_gpio_pins[counter], false);
		}
	}

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "ECONET-GPIO: GPIOs successfully requested.\n");
	printk (KERN_INFO "ECONET-GPIO: Requesting IRQ on BCM pin %02d\n", econet_gpio_pins[EGP_IRQ]);
#endif

	gpio_direction_input(econet_gpio_pins[EGP_IRQ]);

	econet_data->irq_state = 1;

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "ECONET-GPIO: IRQ Successfully set up - IRQ %d\n", econet_data->irq);
#endif
	request_region(GPIO_PERI_BASE, GPIO_RANGE, DEVICE_NAME);
	GPIO_PORT = ioremap(GPIO_PERI_BASE, GPIO_RANGE);

	if (GPIO_PORT)
	{
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "ECONET-GPIO: GPIO base remapped to 0x%08lx\n", (unsigned long) GPIO_PORT);
#endif
	}
	else
	{
		printk (KERN_INFO "ECONET-GPIO: GPIO base remap failed.\n");
		return 0;
	}

	/* Set up the pins */

        t = (readl(GPIO_PORT) & ~(0x707)) | 0x401;
        writel(t, GPIO_PORT); /* Set 0, 6 to output */

	/* Note we must set input first and then output if ultimately we want the pin to be an output */
        INP_GPIO(ECONET_GPIO_PIN_DATA);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 1);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 2);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 3);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 4);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 5);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 6);
        INP_GPIO(ECONET_GPIO_PIN_DATA + 7);

        INP_GPIO(ECONET_GPIO_PIN_ADDR);
        INP_GPIO(ECONET_GPIO_PIN_ADDR + 1);
        OUT_GPIO(ECONET_GPIO_PIN_ADDR);
        OUT_GPIO(ECONET_GPIO_PIN_ADDR + 1);

        INP_GPIO(ECONET_GPIO_PIN_RST);
        OUT_GPIO(ECONET_GPIO_PIN_RST);

        INP_GPIO(ECONET_GPIO_PIN_IRQ);

        INP_GPIO(ECONET_GPIO_PIN_CS);
        OUT_GPIO(ECONET_GPIO_PIN_CS);

        INP_GPIO(ECONET_GPIO_PIN_RW);
        OUT_GPIO(ECONET_GPIO_PIN_RW);

	INP_GPIO(ECONET_GPIO_PIN_CSRETURN);

	INP_GPIO(ECONET_GPIO_PIN_BUSY); // v2 hardware busy line

	if (!econet_probe_adapter())
	{
		econet_gpio_release_pins();
		printk (KERN_ERR "ECONET-GPIO: Hardware not found.\n");
		return -1;
	}

	econet_data->irq = gpio_to_irq(econet_gpio_pins[EGP_IRQ]);

	if ((econet_data->irq < 0) || ((err = request_irq(econet_data->irq, econet_irq, IRQF_SHARED | ((econet_data->hwver < 2) ? IRQF_TRIGGER_FALLING : IRQF_TRIGGER_RISING), THIS_MODULE->name, THIS_MODULE->name)) != 0))
	{
		printk (KERN_INFO "ECONET-GPIO: Failed to request IRQ on pin BCM %d\n", econet_gpio_pins[EGP_IRQ]);
		econet_gpio_release_pins();
		return err;
	}

	econet_irq_mode(0);

	return 1;
}

void econet_gpio_release(void)
{
	iounmap(GPIO_PORT);

	GPIO_PORT = 0;

	/* IRQs off */

	if (econet_data->mode != EM_TEST)
		econet_irq_mode(0);

	econet_gpio_release_pins();
	free_irq(econet_data->irq, THIS_MODULE->name);
	printk (KERN_INFO "ECONET-GPIO: Pins and IRQ released.\n");

}

/* Function just to clear the ADLC down - may help when we get repeated collisions */
void econet_adlc_cleardown(unsigned short in_irq)
{

	printk (KERN_INFO "ECONET-GPIO: Performing ADLC chip reset\n");

	/* Hold RST low for 100ms */
	econet_set_rst(ECONET_GPIO_RST_RST);
	if (in_irq)
		mdelay(100);
	else
		msleep(100);

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

	econet_set_dir(ECONET_GPIO_READ);


}

/* Chip reset function - Leaves us in test mode with IRQs off */

void econet_reset(void)
{

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "ECONET-GPIO: econet_reset() called\n");
#endif

	/* Clear the kernel FIFOs */
	kfifo_reset(&econet_rx_queue);
	kfifo_reset(&econet_tx_queue);

	/* Make sure packet buffer appears to be empty */

	econet_pkt_rx.length = 0;
	econet_pkt_tx.length = 0;

	/* Turn IRQs off */
	econet_irq_mode(0);

	/* Clear station map */
	ECONET_INIT_STATIONS(econet_stations);

	econet_adlc_cleardown(0); // 0 = not in IRQ context

	//printk (KERN_INFO "ECONET-GPIO: econet_reset() finishing. Setting chip state to EM_TEST.\n");
	//econet_set_chipstate(EM_TEST);
	
	init_waitqueue_head(&econet_data->econet_read_queue);

	/* Take us out of AUN mode and set the chip to read */

	econet_data->aun_mode = 0;

	econet_set_read_mode();

	printk (KERN_INFO "ECONET-GPIO: Module reset. AUN mode off. ADLC re-initialized.\n");

}

/* Puts us in read mode & enables IRQs */
void econet_set_read_mode(void)
{

	/* Blank the packet buffers */

	econet_pkt_rx.length = econet_pkt_rx.ptr = 0;

	econet_write_cr(ECONET_GPIO_CR2, C2_READ);
	econet_write_cr(ECONET_GPIO_CR1, C1_READ);

	econet_set_chipstate(EM_IDLEINIT); 

	last_data_rcvd = 0; // Last time we received data off the wire. Detect stuck in read mode when we want to write

	econet_irq_mode(1);

}

/* Puts us in write mode & enables IRQs */
void econet_set_write_mode(struct __econet_pkt_buffer *prepared, int length)
{

	int counter = 0;
	u64 swm_idlewaitstart, swm_idlewaitend;

	econet_irq_mode(1);

	if (econet_data->mode == EM_FLAGFILL)
	{
		spin_lock(&econet_tx_spin);

		memcpy (&econet_pkt_tx, prepared, length);
		econet_pkt_tx.length = length;
		econet_pkt_tx.ptr = 0;
		if (!econet_data->aun_mode) econet_data->tx_status = 0xff; // Rogue - changes when TX succeeds or fails. Don't set this if we are in AUN mode - controlled by the state machine

		econet_set_chipstate(EM_WRITE);
		goto start_transmit; // We just get on with it if we are already in FF
	}

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() called");
#endif
	/* Routine assumes we have a packet ready to go */

	/* First check DCD */

	econet_get_sr();

	if (sr2 & ECONET_GPIO_S2_DCD) // /DCD is high - no clock
	{
		econet_data->tx_status = -ECONET_TX_NOCLOCK;
#ifdef ECONET_GPIO_DEBUG_TX
		printk (KERN_INFO "ECONET-GPIO: No clock on TX\n");
#endif
		econet_set_read_mode();
		return;
	}

	// Now lock the spinlock and see if we are already transmitting, so that we know we are the only one
	// trying to set write mode

	spin_lock (&econet_tx_spin);

econet_idlecheck:

	/* Then check for inactive IDLE or IRQ, and wait a while until neither -
	   see ANFS 4.25 at &86C7 */

	counter = 0;
	swm_idlewaitstart = swm_idlewaitend = 0;

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() - Wait for no IRQ present & RX IDLE = 1. Currently SR1 = 0x%02x, SR2 = 0x%02x", sr1, sr2);
#endif
	while (
		(counter++ < 0xffff) && // Coutner loop
		((sr1 & ECONET_GPIO_S1_IRQ) /* || !(sr2 & ECONET_GPIO_S2_RX_IDLE) */) &&  // If there's an IRQ or *not* RX_IDLE, wait // Took out the search for RX IDLE because it seems to be erroneous
		(econet_pkt_tx.length != 0) // If length !=0 we are transmitting, so wait
              )
	{
		swm_idlewaitstart = ktime_get_ns();
		econet_get_sr();
		swm_idlewaitend = ktime_get_ns();
		udelay(2); // Short wait
	}

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET_GPIO: econet_set_write_mode() instrumentation: After wait %d loops, SR1 = 0x%02x\n", counter, sr1);
	printk (KERN_INFO "ECONET_GPIO: econet_set_write_mode() instrumentation: econet_get_sr() delay was %lld ns, counter loops = %d \n", swm_idlewaitend - swm_idlewaitstart, counter);
#endif

	if (counter == 65536) // Didn't get the right TX state above
	{

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() - Gave up waiting for IRQ=0 / RX IDLE = 0");
#endif
		spin_unlock (&econet_tx_spin); // Release the lock
		econet_data->tx_status =  -ECONET_TX_NOIRQ;
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET | ECONET_GPIO_C1_TX_RESET);
		econet_write_cr(ECONET_GPIO_CR1, C1_READ);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ | ECONET_GPIO_C2_CLR_TX_STATUS);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
		econet_set_chipstate(EM_IDLEINIT);
		return; /* Give up */
	}
	else // Flags in right state - so copy our prepared data into the tx buffer
	{
		memcpy (&econet_pkt_tx, prepared, length);
		econet_pkt_tx.length = length;
		econet_pkt_tx.ptr = 0;
		if (!econet_data->aun_mode) econet_data->tx_status = 0xff; // Rogue - changes when TX succeeds or fails. Don't do this in AUN mode - it's handled by the state machine
	}
		

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() - Clear RX & TX status bits");
#endif

	/* Now clear RX & TX status - See ANFS 4.2 at &86D1 */

	econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT1);

	/* Check for /CTS low */
	
	econet_get_sr();

	if (!(sr1 & ECONET_GPIO_S1_CTS))
	{
#ifdef ECONET_GPIO_DEBUG_TX
		printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() - /CTS high - trying again");
#endif
		goto econet_idlecheck;
	}


	/* Next Set flag fill, put RX side into reset, enable TX irq */

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() - Set flag fill, prime the 68B54 and wait for IRQ");
#endif
	econet_set_chipstate(EM_WRITE);
	econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2);
	udelay(100); // Do a bit of flag filling
start_transmit:
	econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);	
	
	/* And wait for an IRQ */

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_set_write_mode() - Wait for IRQ");
#endif

	spin_unlock (&econet_tx_spin);

	return;

}

void econet_flagfill(void)
{

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: Flag Fill enabled\n");
#endif
	econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET);
	econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2);
	econet_set_chipstate(EM_FLAGFILL);

}

/*
 *
 *
 * ECONET GPIO IRQ HANDLING CODE
 * Get the bytes off the wire, put the bytes on the wire, etc.
 *
 *
 */


void econet_irq_mode(short m)
{

	spin_lock(&econet_irqstate_spin);

	if (m)
	{
		if (econet_data->irq_state == 0) // Disabled
		{
			enable_irq(econet_data->irq);
			econet_data->irq_state = 1;
		}
	}
	else
	{
		if (econet_data->irq_state == 1) // Enabled
		{
			disable_irq(econet_data->irq);
			econet_data->irq_state = 0;
		}
	}

	spin_unlock(&econet_irqstate_spin);
}

void econet_finish_tx(void)
{


#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_finish_tx(): Finished packet TX\n");
#endif
	/* Tell the 68B54 we've finished so it can end the frame */
	econet_set_chipstate(EM_WRITE_WAIT);
	econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_EOF);
	econet_get_sr();
#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_finish_tx(): SR after C2_WRITE_EOF: SR1 = 0x%02x, SR2 = 0x%02x\n", sr1, sr2);
#endif

}

void econet_irq_write(void)
{
	/* This will have occurred if we are in write mode, and we will already have done the preliminary
	   TX set up - see econet_set_write_mode() */

	char tdra_flag;
	int loopcount = 0;


	// Added 25.07.21 - Mark transmission even if not successful otherwise the reset timer gets stuck
	econet_data->aun_last_tx = ktime_get_ns(); // Used to check if we have fallen out of bed on receiving a packet

	if (sr2 & ECONET_GPIO_S2_DCD) // No clock
	{
		//printk(KERN_INFO "ECONET-GPIO: No clock\n");
		econet_pkt_tx.length = 0;
		econet_data->tx_status = -ECONET_TX_NOCLOCK;
		econet_set_aunstate(EA_IDLE);
		econet_set_read_mode();
		return;

	}

	if (econet_pkt_tx.length < 4) // Runt
	{
		printk(KERN_INFO "ECONET-GPIO: Attempt to transmit runt frame (len = %d). Not bothering.\n", econet_pkt_tx.length);
		econet_pkt_tx.length = 0; // Abandon
		econet_data->tx_status = -ECONET_TX_NOTSTART;
	}	
	else if (econet_pkt_tx.ptr <= econet_pkt_tx.length)
	{
		// Something to transmit

		int byte_counter;
		int tdra_counter;

		byte_counter = 0;

		econet_data->tx_status = 0xfe; // Flag transmission has started

		//while (byte_counter < 2)
		while (byte_counter < 1)
		{

			// Check TDRA available.
	
next_byte:
			loopcount++;

			//printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): Registers on entry - SR1 = 0x%02x, SR2 = 0x%02x, ptr = %d, loopcount = %d\n", sr1, sr2, econet_pkt_tx.ptr, loopcount);

			if (sr1 & ECONET_GPIO_S1_UNDERRUN) // Underrun
			{
				printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): TX Underrun at byte %02x - abort transmission\n", econet_pkt_tx.ptr);
				econet_pkt_tx.length = 0;
				// Commented out to see if this is what causes the kernel panic
				econet_data->tx_status = -ECONET_TX_UNDERRUN;
				econet_set_aunstate(EA_IDLE);

				// Set up to read again
				econet_set_read_mode();
				return;
			}

			tdra_flag = (sr1  & ECONET_GPIO_S1_TDRA);

#ifdef ECONET_GPIO_DEBUG_TX
		 	printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): Loop % 2d - TDRA FLAG IS %s. SR1 = 0x%02x, SR2 = 0x%02x\n", loopcount, (sr1 & ECONET_GPIO_S1_TDRA) ? "SET" : "UNSET", sr1, sr2);

#endif 
			tdra_counter = 0;

			while (tdra_counter++ < 5 && (!tdra_flag)) // Clear down and see if it becomes available
			{
				econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
					ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);
				udelay(10);
				econet_get_sr();
				tdra_flag = (sr1  & ECONET_GPIO_S1_TDRA);
			}

			if (!tdra_flag)
			{
				// ANFS 4.25 checks TDRA on IRQ. If not available, it clears RX & TX status and waits for another IRQ

				if (sr1 & ECONET_GPIO_S1_CTS) // Collision?
				{
					printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): /CTS - Collision? TDRA unavailable on IRQ - SR1 - 0x%02X, SR2 = 0x%02X, ptr = %d, loopcount = %d - abort tx\n", sr1, sr2, econet_pkt_tx.ptr, loopcount);
					econet_data->tx_status = -ECONET_TX_COLLISION;
					// See if clearing the ADLC down helps here
					econet_adlc_cleardown(1); // 1 = in IRQ context, so use mdelay not msleep
				}
				else	
				{
					printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): TDRA not available on IRQ - SR1 = 0x%02x, SR2 = 0x%02x, ptr = %d, loopcount = %d - abort transmission\n", sr1, sr2, econet_pkt_tx.ptr, loopcount);
					econet_data->tx_status = -ECONET_TX_TDRAFULL;
				}
				econet_pkt_tx.length = 0;
				econet_set_aunstate(EA_IDLE);
				//spin_unlock(&econet_pkt_spin);
				econet_set_read_mode();
				return;
			}

			/* So by here, the TDRA is available, so we'll put some data in it */

#ifdef ECONET_GPIO_DEBUG_TX
			{
				char c;
				c = econet_pkt_tx.d.data[econet_pkt_tx.ptr];
				printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): TX byte % 4d - %02x %c\n", econet_pkt_tx.ptr, (int) c, ((c > 32) && (c < 127)) ? c : '.');
			}
#endif 
			/* OLD CODE 
			if (econet_data->hwver >= 2) while (econet_isbusy());
			econet_set_addr(1, 0);
			econet_write_bus(econet_pkt_tx.d.data[econet_pkt_tx.ptr++]);
			*/

			econet_write_fifo(econet_pkt_tx.d.data[econet_pkt_tx.ptr++]);

			if (econet_pkt_tx.ptr == econet_pkt_tx.length)
			{
				//spin_unlock(&econet_pkt_spin);
				econet_finish_tx();
				econet_pkt_tx.length = 0;
				return;
			}

			byte_counter++;

			econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
				ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);

			econet_get_sr();
	
			if (sr1 & ECONET_GPIO_S1_IRQ) // If the IRQ line is still active. ANFS sends another byte if it is
				goto next_byte; // This will re-check TDRA anyway

		}

		
	}

	//spin_unlock(&econet_pkt_spin);
	return;

}

void econet_process_rx(unsigned char d)
{

	econet_pkt_rx.d.data[econet_pkt_rx.ptr++] = d;
	if (econet_pkt_rx.ptr == ECONET_MAX_PACKET_SIZE) econet_pkt_rx.ptr--; // We shouldn't be over the limit!
	last_data_rcvd = ktime_get_ns();

}

void econet_irq_read(void)
{

	unsigned char d;
	int copied_to_fifo;
	int copied_from_fifo;

recv_more:

	//if (econet_data->hwver >= 2) while (econet_isbusy());
	//econet_set_addr(1,0);
	//d = econet_read_bus();
	d = econet_read_fifo(); 

#ifdef ECONET_GPIO_DEBUG_RX
	printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): SR1 = %02x, SR2 = %02x, ptr = %d, c = %02x %c\n", sr1, sr2, econet_pkt_rx.ptr, d, (d < 32 || d >126) ? '.' : d);
#endif
	econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Tell the chip we've read the data

	last_data_rcvd = ktime_get_ns();

	if (sr2 & ECONET_GPIO_S2_VALID) // Frame valid received
	{
		econet_process_rx(d);
		//econet_write_cr(ECONET_GPIO_CR2, C2_READ); // clear status // Now done above
		// If kfifo is full, take something out of it before we shove this packet in.
		if (kfifo_is_full(&econet_rx_queue))
			copied_from_fifo = kfifo_out(&econet_rx_queue, &dump_pkt, sizeof(dump_pkt));

		if (econet_pkt_rx.ptr < 4) // Runt
		{
			printk (KERN_INFO "ECONET-GPIO: Runt received (len %d) - jettisoning\n", econet_pkt_rx.ptr);
			econet_set_chipstate(EM_IDLE);
			econet_set_aunstate(EA_IDLE);
			// CR2 done above
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
			return;
		}

		if (!(econet_data->aun_mode)) // Raw mode - straight on the FIFO
		{
			// Put the packet on the kernel FIFO
			copied_to_fifo = kfifo_in(&econet_rx_queue, &(econet_pkt_rx.d.data), econet_pkt_rx.ptr); 
			wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
#ifdef ECONET_GPIO_DEBUG_RX
			printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, %04x bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif
			econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
			econet_set_chipstate(EM_IDLE);
		}
		else
		{
			// Is the traffic for a station we bridge for?

			if (ECONET_DEV_STATION(econet_stations, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn))
			{

				econet_pkt_rx.length = econet_pkt_rx.ptr;

				// If our last transmission was more than 0.8s ago, go back to EA_IDLE
				
				if (
					(	((ktime_get_ns() - econet_data->aun_last_tx) > (2 * ECONET_4WAY_TIMEOUT)) &&
						(econet_data->aun_state == EA_I_READREPLY)
					) 	||
					(
						((ktime_get_ns() - econet_data->aun_last_tx) > ECONET_4WAY_TIMEOUT) && 
						(econet_data->aun_state != EA_IDLE)
					)
				) // If we are waiting for an immediate reply (which might be quite long), wait 2 x 4-way timeout (1.6s - ample for a 20k packet (e.g. MODE 0 screen dump on *VIEW) coming across from a station behind an onward bridge, and if not waiting for one of those and it's more than 0.8 seconds, then go back to idle.
				{
					printk (KERN_INFO "ECONET-GPIO: Last TX was too long ago. Moving back to AUN IDLE state.\n");
					econet_set_aunstate(EA_IDLE);
				}

				// Set up the bones of a reply just in case

				econet_pkt_tx.d.p.dststn = econet_pkt_rx.d.p.srcstn;
				econet_pkt_tx.d.p.dstnet = econet_pkt_rx.d.p.srcnet;
				econet_pkt_tx.d.p.srcstn = econet_pkt_rx.d.p.dststn;
				econet_pkt_tx.d.p.srcnet = econet_pkt_rx.d.p.dstnet;

				// What shall we do about this traffic we've received?

#ifdef ECONET_GPIO_DEBUG_AUN
				//printk (KERN_INFO "ECONET-GPIO: AUN debug - packet from %d.%d, length = 0x%08x, Port %02x, Ctrl %02x\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.length, econet_pkt_rx.d.p.port, econet_pkt_rx.d.p.ctrl);
#endif
				switch (econet_data->aun_state)
				{

					case EA_IDLE: // First in a sequence - see what it is.
					{
unexpected_scout:
						// Is it an immediate?
						if (econet_pkt_rx.d.p.port == 0 && econet_pkt_rx.d.p.ctrl != 0x85) // Ctrl 0x85 appears, from all the traffic sniffing, to in fact be done as a 4-way handshake even though it's port 0. It's used for notify, remote, view, etc.
						{
#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "ECONET-GPIO: Immediate received from %d.%d, Ctrl 0x%02x\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.ctrl);
#endif

							// Are we spoofing immediate replies to wire stations? If not, flagfill and deliver to userspace
							if (!(econet_data->spoof_immediate))
							{

								memcpy (&aun_rx, &econet_pkt_rx, 4); // Copy the addresses
								aun_rx.d.p.srcstn = econet_pkt_rx.d.p.srcstn;
								aun_rx.d.p.srcnet = econet_pkt_rx.d.p.srcnet;
								aun_rx.d.p.dststn = econet_pkt_rx.d.p.dststn;
								aun_rx.d.p.dstnet = econet_pkt_rx.d.p.dstnet;
								aun_rx.d.p.port = econet_pkt_rx.d.p.port;
								aun_rx.d.p.ctrl = econet_pkt_rx.d.p.ctrl; // We don't strip the high bit for the bridge code. It can do it itself
								aun_rx.d.p.aun_ttype = ECONET_AUN_IMM;
								aun_rx.d.p.seq = (econet_data->aun_seq += 4);
								aun_rx.d.p.padding = 0x00;
								if (econet_pkt_rx.length > 6)
									memcpy (&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), econet_pkt_rx.length - 6);
								aun_rx.length = econet_pkt_rx.length + 6; // AUN packets have 12 bytes before the data, econet packets have 6 (on a broadcast or immediate, anyway).
				
								// Put it on the FIFO
								copied_to_fifo = kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
								wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, %04x AUN bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif
								econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
								econet_write_cr(ECONET_GPIO_CR2, C2_READ);
								econet_write_cr(ECONET_GPIO_CR1, C1_READ);
								econet_flagfill();
								econet_set_aunstate(EA_IDLE); // Wait and see what turns up next - probably an immediate reply
								econet_set_chipstate(EM_FLAGFILL);
							}
							else
							{
								switch (econet_pkt_rx.d.p.ctrl) // What sort of immediate?
								{
									case 0x81: // Memory peek - Can probably return some garbage just to be nice
									{
										printk (KERN_INFO "ECONET-GPIO: Ignoring remote peek from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
									}
									break;
	
									case 0x82: // Memory poke - definitely won't be doing that.
									{
										printk (KERN_INFO "ECONET-GPIO: Ignoring remote poke from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
									}
									break;
	
									case 0x83: // Remote JSR - definitely won't want to be implementing this
									{
										printk (KERN_INFO "ECONET-GPIO: Ignoring remote JSR from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
									}
									break;
	
									case 0x84: // User procedure call - definitely won't want to be implementing this
									{
										printk (KERN_INFO "ECONET-GPIO: Ignoring remote user procedure call from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
									}
									break;
	
									case 0x86: // HALT - definitely won't want to be implementing this, but we can reply nicely I suppose
									{
										econet_flagfill();
										econet_pkt_tx.ptr = 0;
										econet_pkt_tx.length = 4;
										
										econet_set_aunstate(EA_I_WRITEREPLY);
										//econet_data->aun_state = EA_I_WRITEREPLY;
										econet_set_chipstate(EM_WRITE);
										econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
										printk (KERN_INFO "ECONET-GPIO: Ignored, but acknowledged, HALT from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
									}
									break;
	
									case 0x87: // CONTINUE - definitely won't want to be implementing this, but we can reply nicely I suppose
									{
										econet_flagfill();
										econet_pkt_tx.ptr = 0;
										econet_pkt_tx.length = 4;
										
										econet_set_aunstate(EA_I_WRITEREPLY);
										//econet_data->aun_state = EA_I_WRITEREPLY;
										econet_set_chipstate(EM_WRITE);
										econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
										printk (KERN_INFO "ECONET-GPIO: Ignored, but acknowledged, CONTINUE from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
									}
									break;
	
									case 0x88: // MachinePeek (which is actually the only thing implemented officially on AUN apparently)
									{
	
										econet_flagfill();
										econet_pkt_tx.d.p.ctrl = (ADVERTISED_MACHINETYPE & 0xff);
										econet_pkt_tx.d.p.port = (ADVERTISED_MACHINETYPE & 0xff00) >> 8;
										econet_pkt_tx.d.p.data[0] = (ADVERTISED_VERSION & 0xff);
										econet_pkt_tx.d.p.data[1] = (ADVERTISED_VERSION & 0xff00) >> 8;
	
										econet_pkt_tx.ptr = 0;
										econet_pkt_tx.length = 8;
										
										econet_set_aunstate(EA_I_WRITEREPLY);	
										//econet_data->aun_state = EA_I_WRITEREPLY;
										econet_set_chipstate(EM_WRITE);
										econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
	#ifdef ECONET_GPIO_DEBUG_AUNIMM
										printk (KERN_INFO "ECONET-GPIO: Responding to Machine Peek from %d.%d\n", econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn);
	#endif
									}
									break;
								}	
							}
						}
						else if ((econet_pkt_rx.d.p.dststn == 0xff) && (econet_pkt_rx.d.p.dstnet == 0xff)) // Broadcast - dump to userspace
						{
							memcpy (&aun_rx, &econet_pkt_rx, 4); // Copy the addresses
							aun_rx.d.p.srcstn = econet_pkt_rx.d.p.srcstn;
							aun_rx.d.p.srcnet = econet_pkt_rx.d.p.srcnet;
							aun_rx.d.p.dststn = econet_pkt_rx.d.p.dststn;
							aun_rx.d.p.dstnet = econet_pkt_rx.d.p.dstnet;
							aun_rx.d.p.port = econet_pkt_rx.d.p.port;
							aun_rx.d.p.ctrl = econet_pkt_rx.d.p.ctrl; // We don't strip the high bit for the bridge code. It can do it itself
							aun_rx.d.p.aun_ttype = ECONET_AUN_BCAST;
							aun_rx.d.p.seq = (econet_data->aun_seq += 4);
							aun_rx.d.p.padding = 0x00;
							if (econet_pkt_rx.length > 6)
								memcpy (&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), econet_pkt_rx.length - 6);
							aun_rx.length = econet_pkt_rx.length + 6; // AUN packets have 12 bytes before the data, econet packets have 6 (on a broadcast or immediate, anyway).
				
							// Put it on the FIFO
							copied_to_fifo = kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
							wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
#ifdef ECONET_GPIO_DEBUG_RX
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, %04x AUN bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif
							econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
							econet_write_cr(ECONET_GPIO_CR2, C2_READ);
							econet_write_cr(ECONET_GPIO_CR1, C1_READ);
							econet_set_chipstate(EM_IDLE);
						}
						else // not immediate or broadcast - Should be a scout, unless it's a broadcast (And if it's not a scout, our state machine has gone wrong)
						{

							// Should be 6 bytes long. If not, drop it and go back to IDLE - we are obviously out of sequence.
							if (econet_pkt_rx.ptr != 6 && !(econet_pkt_rx.d.p.port == 0 && econet_pkt_rx.d.p.ctrl == 0x85)) // Immediate ctrl 0x85 packets are done as 4-way handshakes, BUT there are 4 data bytes on the opening scout
							{
								econet_set_aunstate(EA_IDLE);
								//econet_data->aun_state = EA_IDLE;
								printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting Scout and this wasn't\n", econet_pkt_rx.ptr);
								econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
								econet_write_cr(ECONET_GPIO_CR2, C2_READ);
								econet_write_cr(ECONET_GPIO_CR1, C1_READ);
								econet_set_chipstate(EM_IDLE);
							}
							else // It was a scout, so send an Ack and wait for some data to come in
							{
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN: Scout received from %d.%d with port %02x, ctrl %02x. Acknowledging.\n", 
									econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.port, econet_pkt_rx.d.p.ctrl);
#endif

								// Set up our AUN RX block
								aun_rx.d.p.srcstn = econet_pkt_rx.d.p.srcstn;
								aun_rx.d.p.srcnet = econet_pkt_rx.d.p.srcnet;
								aun_rx.d.p.dststn = econet_pkt_rx.d.p.dststn;
								aun_rx.d.p.dstnet = econet_pkt_rx.d.p.dstnet;
								aun_rx.d.p.port = econet_pkt_rx.d.p.port;
								aun_rx.d.p.ctrl = econet_pkt_rx.d.p.ctrl;

								// Is it immediate ctrl &85, which is done as a 4-way with 4 data bytes on the first Scout?
								if (aun_rx.d.p.port == 0 && aun_rx.d.p.ctrl == 0x85) // Copy the four data bytes onto the start of the aun_rx data buffer
									memcpy(&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), 4);

								econet_pkt_tx.ptr = 0;
								econet_pkt_tx.length = 4;
	
								econet_set_aunstate(EA_R_WRITEFIRSTACK);
								//econet_data->aun_state = EA_R_WRITEFIRSTACK;	
	
								econet_flagfill();
								econet_set_chipstate(EM_WRITE);
								econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
							}
						}

					}
				
					break;
						
					case EA_W_READFIRSTACK: // This should be an ack to the Scout we have written; Implement later.
					{
						// What we should have is an Ack from our Scout whilst sending a data packet, so we need to make sure it's from the right station and looks like an ACK

						if (	(econet_pkt_rx.d.p.srcstn != aun_tx.d.p.dststn)
							||
							(econet_pkt_rx.d.p.srcnet != aun_tx.d.p.dstnet)
							||
							(econet_pkt_rx.d.p.dststn != aun_tx.d.p.srcstn)
							||
							(econet_pkt_rx.d.p.dstnet != aun_tx.d.p.srcnet)
							||
							(econet_pkt_rx.ptr != 4)	
						)
						{
							// If it's 6 bytes, let's assume it's a scout we weren't expecting and dump it in the scout routine
							if (econet_pkt_rx.ptr == 6) goto unexpected_scout;

							printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting first ACK from %d.%d - got packet from %d.%d to %d.%d %02x %02x %02x %02x\n", econet_pkt_rx.ptr, aun_tx.d.p.dstnet, aun_tx.d.p.dststn, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn, econet_pkt_rx.d.p.data[0], econet_pkt_rx.d.p.data[1], econet_pkt_rx.d.p.data[2], econet_pkt_rx.d.p.data[3]);
	
							econet_set_aunstate(EA_IDLE);
							//econet_data->aun_state = EA_IDLE;
							econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
							econet_write_cr(ECONET_GPIO_CR2, C2_READ);
							econet_write_cr(ECONET_GPIO_CR1, C1_READ);
							econet_set_chipstate(EM_IDLE);
						}
						else // It was an ACK from where we expected, so line up the data packet	
						{
							econet_flagfill();
							if (aun_tx.d.p.port != 0x00 || aun_tx.d.p.ctrl != 0x85) // Not one of those 0x85 immediate specials that in fact does a 4-way handshake
							{
								memcpy (&(econet_pkt_tx.d.p.ctrl), &(aun_tx.d.p.data), aun_tx.length-12); // Strip off the header - note, ctrl byte is first on the econet wire, and is where the data portion of a data packet starts
								econet_pkt_tx.length = 4 + (aun_tx.length - 12); // Data starts at byte 4 in a data packet to econet
							} // Else it WAS one of those Immediate 0x85 specials which had 4 data bytes on the "Scout", so we only copy n-4 data bytes into the data packet
							else // Else it WAS one of those Immediate 0x85 specials which had 4 data bytes on the "Scout", so we only copy n-4 data bytes into the data packet
							{
								memcpy (&(econet_pkt_tx.d.p.ctrl), &(aun_tx.d.p.data[4]), aun_tx.length-16); // Strip off the header - note, ctrl byte is first on the econet wire, and is where the data portion of a data packet starts
								econet_pkt_tx.length = 4 + (aun_tx.length - 16); // Data starts at byte 4 in a data packet to econet
							}

							econet_pkt_tx.ptr = 0;
							econet_set_aunstate(EA_W_WRITEDATA);
							//econet_data->aun_state = EA_W_WRITEDATA;	

							econet_set_chipstate(EM_WRITE);
							econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN: Scout ACK received - sending data packet to %d.%d, after scout with port %02x, ctrl %02x\n", 
								econet_pkt_tx.d.p.dstnet, econet_pkt_tx.d.p.dststn, aun_tx.d.p.port, aun_tx.d.p.ctrl);
#endif
						}
					}
					break;

					case EA_W_READFINALACK: // This should be a final ack to the Data packet we just wrote. Go back to EA_IDLE and flag transmission successful to the writefd routine.
					{
						// What we should have is an Ack from our data packet, so we need to make sure it's from the right station and looks like an ACK

						if (	(econet_pkt_rx.d.p.srcstn != aun_tx.d.p.dststn)
							||
							(econet_pkt_rx.d.p.srcnet != aun_tx.d.p.dstnet)
							||
							(econet_pkt_rx.d.p.dststn != aun_tx.d.p.srcstn)
							||
							(econet_pkt_rx.d.p.dstnet != aun_tx.d.p.srcnet)
							||
							(econet_pkt_rx.ptr != 4)	
						)
						{
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, but was expecting final ACK from %d.%d\n", econet_pkt_rx.ptr, aun_tx.d.p.dstnet, aun_tx.d.p.dststn);
							econet_set_aunstate(EA_IDLE);
							//econet_data->aun_state = EA_IDLE;
						}
						else // It was an ACK from where we expected, so flag completion to writefd
						{
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN: Read final ACK from %d.%d, after scout with port %02x, ctrl %02x. Flag transmit success.\n", 
									econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, aun_tx.d.p.port, aun_tx.d.p.ctrl);
#endif
							econet_data->tx_status = ECONET_TX_SUCCESS;	
						}

						// Either way, go back to idle.

						econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
						econet_write_cr(ECONET_GPIO_CR2, C2_READ);
						econet_write_cr(ECONET_GPIO_CR1, C1_READ);
						econet_set_chipstate(EM_IDLE);
						econet_set_aunstate(EA_IDLE);
					}
					break;

					case EA_R_READDATA: // The data we've just read will be a data packet. Transmit a final ACK and /then/ dump the packet to userspace
					{

						// Right destination & source, right length ?
						if ((econet_pkt_rx.d.p.dststn == aun_rx.d.p.dststn) && (econet_pkt_rx.d.p.dstnet == aun_rx.d.p.dstnet) && 
							(econet_pkt_rx.d.p.srcstn == aun_rx.d.p.srcstn) && (econet_pkt_rx.d.p.srcnet == aun_rx.d.p.srcnet) && 
							(econet_pkt_rx.ptr > 4))
						{

#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN: Data received from %d.%d, length wire %d - Sending final ack.\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn, econet_pkt_rx.ptr);
#endif
							if (aun_rx.d.p.port == 0 && aun_rx.d.p.ctrl == 0x85) // Immediate 0x85 special four way. There will have been four important bytes on the Quasi-'Scout' which will have been put into the aun_rx data area already, so we copy to byte 5 onward
								memcpy(&(aun_rx.d.p.data[4]), &(econet_pkt_rx.d.data[4]), econet_pkt_rx.ptr - 4);
							else
								memcpy(&aun_rx.d.p.data, &(econet_pkt_rx.d.data[4]), econet_pkt_rx.ptr - 4); // We copy from the raw data in the rx packet because at [4] is where the reply data actually is, but we copy to the ACTUAL data area in the AUN packet
							aun_rx.d.p.seq = (econet_data->aun_seq += 4);
							aun_rx.d.p.aun_ttype = ECONET_AUN_DATA;
							aun_rx.length = (econet_pkt_rx.ptr - 4 + 12) + ((aun_rx.d.p.port == 0 && aun_rx.d.p.ctrl == 0x85) ? 4 : 0);

							econet_flagfill();

							// Send Final ACK
						
							econet_pkt_tx.ptr = 0;
							econet_pkt_tx.length = 4;

							econet_set_aunstate(EA_R_WRITEFINALACK);
							//econet_data->aun_state = EA_R_WRITEFINALACK;	

							econet_set_chipstate(EM_WRITE);
							econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
						}
						else // Soemthing went wrong - clear down
						{
							printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting data packet from %d.%d and this wasn't\n", econet_pkt_rx.length, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn);
							econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
							econet_write_cr(ECONET_GPIO_CR2, C2_READ);
							econet_write_cr(ECONET_GPIO_CR1, C1_READ);
							econet_set_chipstate(EM_IDLE);
							econet_set_aunstate(EA_IDLE);
							//econet_data->aun_state = EA_IDLE;
						}
					}
					break;
	
					case EA_I_READREPLY: // What we've received is a reply to an Immediate - dump to userspace
					{

						// Is it from the right place?
						// In this case, we are expecting a reply from the station held in aun_tx, the immediate packet we sent

						if (	(aun_tx.d.p.srcstn == econet_pkt_rx.d.p.dststn) &&
							(aun_tx.d.p.srcnet == econet_pkt_rx.d.p.dstnet) &&
							(aun_tx.d.p.dststn == econet_pkt_rx.d.p.srcstn) &&
							(aun_tx.d.p.dstnet == econet_pkt_rx.d.p.srcnet)	)
						{
							memcpy (&(aun_rx.d.raw), &econet_pkt_rx, 4); // Copy the addressing data over
							if (econet_pkt_rx.ptr > 4)
								memcpy (&(aun_rx.d.p.data), &(econet_pkt_rx.d.data[4]), econet_pkt_rx.ptr-4);
							aun_rx.d.p.srcstn = econet_pkt_rx.d.p.srcstn;
							aun_rx.d.p.srcnet = econet_pkt_rx.d.p.srcnet;
							aun_rx.d.p.dststn = econet_pkt_rx.d.p.dststn;
							aun_rx.d.p.dstnet = econet_pkt_rx.d.p.dstnet;
							aun_rx.d.p.port = aun_tx.d.p.port; // Copy control and port from outgoing immediate query - becuase the immedaite reply data sits over them in a wire packet
							aun_rx.d.p.ctrl = aun_tx.d.p.ctrl;
							aun_rx.d.p.seq = aun_tx.d.p.seq;
							aun_rx.d.p.aun_ttype = ECONET_AUN_IMMREP;
							aun_rx.d.p.padding = 0x00;
							copied_to_fifo = kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), econet_pkt_rx.ptr - 4 + 12); 
							wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
#ifdef ECONET_GPIO_DEBUG_RX
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN Immediate reply received from %d.%d - send to userspace, data portion length %d\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn, (econet_pkt_rx.ptr -4));
#endif
						}
						econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // See if this fixes the crashes
						econet_write_cr(ECONET_GPIO_CR2, C2_READ);
						econet_write_cr(ECONET_GPIO_CR1, C1_READ);
						econet_set_chipstate(EM_IDLE);
						econet_set_aunstate(EA_IDLE);
						//econet_data->aun_state = EA_IDLE;

					}
					break;	
				}	
			}

		}
	
		econet_pkt_rx.ptr = 0; // Reset packet receive counter - flags the receive buffer as empty

	}
	//else if (!(sr2 & (ECONET_GPIO_S2_RX_ABORT | ECONET_GPIO_S2_DCD | ECONET_GPIO_S2_OVERRUN | ECONET_GPIO_S2_ERR | ECONET_GPIO_S2_RX_IDLE))) // No errors
	else if ((sr2 & ECONET_GPIO_S2_AP) || (sr1 & ECONET_GPIO_S1_RDA))
	{
		if (sr2 & ECONET_GPIO_S2_AP) // New frame
		{
#ifdef ECONET_GPIO_DEBUG_RX
			printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Address present and no errors. SR1 = 0x%02x\n", sr1);
#endif
			econet_set_chipstate(EM_READ);
			econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
			econet_process_rx(d);
		}
		else if (sr1 & ECONET_GPIO_S1_RDA) // Data available
			econet_process_rx(d);

		econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Clear status

		econet_get_sr();
	
		if (sr1 & (ECONET_GPIO_S1_IRQ | ECONET_GPIO_S1_RDA)) // More data available
			goto recv_more;
	}
	else if (sr2 & ECONET_GPIO_S2_RX_IDLE) // Abort RX
	{
#ifdef ECONET_GPIO_DEBUG_RX
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX Idle received\n");
#endif
		//econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);
		econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
		econet_set_chipstate(EM_IDLE);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); // Discontinue reception
		econet_write_cr(ECONET_GPIO_CR1, C1_READ);
	}
	else if (sr2 & ECONET_GPIO_S2_RX_ABORT) // Abort RX
	{
#ifdef ECONET_GPIO_DEBUG_RX
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX Abort received\n");
#endif
		econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
		econet_set_chipstate(EM_IDLE);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); // Discontinue reception
		econet_write_cr(ECONET_GPIO_CR1, C1_READ);
	}
	else if (sr2 & ECONET_GPIO_S2_DCD) // No clock all of a sudden
	{
#ifdef ECONET_GPIO_DEBUG_RX
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX No clock\n");
#endif
		econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
		econet_set_chipstate(EM_IDLE);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); // Discontinue reception
		econet_write_cr(ECONET_GPIO_CR1, C1_READ);
	}
	else if (sr2 & ECONET_GPIO_S2_OVERRUN) // Overrun RX
	{
#ifdef ECONET_GPIO_DEBUG_RX
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX Overrun\n");
#endif
		econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
		econet_set_chipstate(EM_IDLE);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); // Discontinue reception
		econet_write_cr(ECONET_GPIO_CR1, C1_READ);
	}
	else if (sr2 & ECONET_GPIO_S2_ERR) // Checksum error
	{
#ifdef ECONET_GPIO_DEBUG_RX
		printk (KERN_INFO "ECONET-GPIO: CRC Error\n");
#endif
		econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
		econet_set_chipstate(EM_IDLE);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); // Discontinue reception
		econet_write_cr(ECONET_GPIO_CR1, C1_READ);
	}
	else
	{
#ifdef ECONET_GPIO_DEBUG_RX
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Unhandled state - SR1 = 0x%02x, SR1 = 0x%02x\n", sr1, sr2);
#endif
	}

	// Detect packets we are not interested in and discontinue them
	if (econet_data->aun_mode && econet_pkt_rx.ptr > 1) // If not in AUN mode, we receive everything and dump to userspace. Need ptr > 1 because that will mean destination address is in bytes 0, 1 of the received packet
	{
		if (!ECONET_DEV_STATION(econet_stations, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn)) // Not a station we are interested in
		{
			econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
			econet_set_chipstate(EM_IDLE);
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);
			econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET); // Discontinue reception
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
		}

	}

	return;

}

irqreturn_t econet_irq(int irq, void *ident)
{

	unsigned long flags;

	spin_lock_irqsave(&econet_irq_spin, flags);

	econet_get_sr();

#ifdef ECONET_GPIO_DEBUG_IRQ
	printk (KERN_INFO "ECONET-GPIO: econet_irq(): IRQ in mode %d, SR1 = 0x%02x, SR2 = 0x%02x. RX len=%d,ptr=%d, TX len=%d,ptr=%d\n", econet_data->mode, sr1, sr2, econet_pkt_rx.length, econet_pkt_rx.ptr, econet_pkt_tx.length, econet_pkt_tx.ptr);
#endif

	if (!(sr1 & ECONET_GPIO_S1_IRQ)) // No IRQ actually present - return
	{}
	else if (econet_data->mode == EM_TEST) /* IRQ in Test Mode - ignore */
	{
		printk ("ECONET-GPIO: IRQ in Test mode - how did that happen?");
	}
	// Are we in the middle of writing a packet?
	else if (econet_data->mode == EM_WRITE) /* Write mode - see what there is to do */
		econet_irq_write();
	// Have we flagged end of transmission and are waiting for FC bit to be set before re-initializing read mode?
	else if (econet_data->mode == EM_WRITE_WAIT) /* IRQ on completion of frame */
	{
		if (econet_data->aun_mode) // What state are we in - do we need to move state?
		{
			// Commented 25.07.21
			//econet_data->aun_last_tx = ktime_get_ns(); // Used to check if we have fallen out of bed on receiving a packet

			switch (econet_data->aun_state)
			{
				// First, the states when we are writing a data packet from userspace
				case EA_W_WRITESCOUT: // We've just written the Scout successfully
				{
					econet_set_aunstate(EA_W_READFIRSTACK);
					//econet_data->aun_state = EA_W_READFIRSTACK;
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written Scout to %d.%d, waiting for first ACK\n", aun_tx.d.p.dstnet, aun_tx.d.p.dststn);
#endif
					break;
				}
				case EA_W_WRITEDATA: // We've just written the data packet
				{
					econet_set_aunstate(EA_W_READFINALACK);
					//econet_data->aun_state = EA_W_READFINALACK;
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written data, waiting for final ACK\n");
#endif
					break;
				}	
				case EA_W_WRITEBCAST: // We've successfully put a broadcast on the wire
				{
					econet_set_aunstate(EA_IDLE);
					//econet_data->aun_state = EA_IDLE;
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written broadcast, signalling packet complete\n");
#endif
					econet_data->tx_status = ECONET_TX_SUCCESS;
					break;
				}

				// Now, the states when we are mid read of a 4-way handshake from the wire

				case EA_R_WRITEFIRSTACK: // Just written first ACK - wait for data packet
				{
#ifdef ECONET_GPIO_DEBUG_AUN	
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Scout ACK written to %d.%d, waiting for data\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn);
#endif
					econet_set_aunstate(EA_R_READDATA);
					//econet_data->aun_state = EA_R_READDATA;
					break;
				}
				case EA_R_WRITEFINALACK: // Just written final ACK after a data packet - go back to IDLE & dump received packet to userspace
				{
					
					kfifo_in(&econet_rx_queue, &aun_rx, aun_rx.length); 
					wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
					econet_set_aunstate(EA_IDLE);
					//econet_data->aun_state = EA_IDLE;
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Final ACK to %d.%d, packet delivered to userspace\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn);
#endif
					break;
				}

				// Now immediate handling

				case EA_I_WRITEIMM: // We receive an immediate from userspace and have just written it to the wire, so need to wait for the reply
				{
					econet_set_aunstate(EA_I_READREPLY);
					// Because this is an immediate, we need to flag transmit success to the tx user space
					econet_data->tx_status = ECONET_TX_SUCCESS;
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written immediate query. Signal TX success but move to READREPLY\n");
#endif
					break;
				}
				case EA_I_WRITEREPLY: // We read an immediate from the wire and have just transmitted the reply
				{
					// We don't update tx_status here because the immediate reply will have been generated in-kernel
					econet_data->tx_status = ECONET_TX_SUCCESS;
					econet_set_aunstate(EA_IDLE);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written immediate reply. Signal TX success. Return to IDLE\n");
#endif
					break;
				}
				default: // Which will apply for writing an immediate reply when not in spoof mode
				{
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Default reached on write state machine. Return to IDLE. AUN state = %d\n", econet_data->aun_state);
#endif
					econet_set_aunstate(EA_IDLE);
					break;
				}
						
			}
		}
		else // raw mode - flag transmit success
		{
			econet_data->tx_status = ECONET_TX_SUCCESS;
#ifdef ECONET_GPIO_DEBUG_TX
			printk (KERN_INFO "ECONET-GPIO: econet_irq(): Returning to IDLEINIT, flagging frame completed\n");
#endif
			// Clear the RX FIFO so that next read is whatever came back from this write
			kfifo_reset(&econet_rx_queue);
		}

		// Straight back to IDLEINIT
		// Checking for TDRA (i.e. frame complete) here seemed to do nothing of any use - just go back to IDLEINIT)
		//if (sr1 & ECONET_GPIO_S1_TDRA) // In this mode, this means 'Frame Complete'
		//{
			econet_set_chipstate(EM_IDLEINIT);
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
			// econet_data->tx_status = ECONET_TX_SUCCESS; - Done above when necessary
		//}
		
	}
	// Are we either mid-read, or idle (in which case, this will be a receiver IRQ)
	else if (econet_data->mode == EM_READ || (sr2 & (ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_AP)) || (sr1 & ECONET_GPIO_S1_RDA)) // In case we get address present or data or are already in read mode
		econet_irq_read();
	else if (sr2 & ECONET_GPIO_S2_RX_IDLE) // We seem to occasionally get RX IDLE interrupts when preparing to transmit. We'll ignore them.
	{
		int tmp_status;
#ifdef ECONET_GPIO_DEBUG_IRQ
		printk (KERN_INFO "ECONET-GPIO: econet_irq(): IRQ received with RX IDLE. Clear down.\n");
#endif
		tmp_status = econet_data->mode;
		econet_set_chipstate(EM_IDLEINIT); // econet_data->mode = EM_IDLEINIT;
		econet_write_cr(ECONET_GPIO_CR2, C2_READ); // We use this here to clear the RX status
		if (tmp_status == EM_IDLE) // Only if we were in IDLE
		{
			econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // Maybe try commenting this out to see if we pick up receptions immediately after transmissions?
			econet_write_cr(ECONET_GPIO_CR2, C2_READ); // We use this here to clear the RX status
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
		}
	}
	else if (econet_data->mode == EM_IDLE || econet_data->mode == EM_IDLEINIT) // We seem to get these when the chip gets its pants tangled. (With sr1=0 - but we've handled reading and writing above, so just clear status)
	{
		if (econet_data->mode == EM_IDLEINIT)
			econet_set_chipstate(EM_IDLE);

		if (sr2 & ~(ECONET_GPIO_S2_AP | ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_RDA)) // Errors
		{
			econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // Maybe try commenting this out to see if we pick up receptions immediately after transmissions?
			econet_write_cr(ECONET_GPIO_CR2, C2_READ); // We use this here to clear the RX status
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
		}
		else
			econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Just clear status
	}
	else if (econet_data->mode == EM_IDLEINIT)
	{
		econet_set_chipstate(EM_IDLE); // econet_data->mode = EM_IDLE;
		if (sr2 & ~(ECONET_GPIO_S2_AP | ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_RDA)) // Errors
		{
			econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); // Maybe try commenting this out to see if we pick up receptions immediately after transmissions?
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);
			econet_write_cr(ECONET_GPIO_CR1, C1_READ);
		}
		else	econet_write_cr(ECONET_GPIO_CR2, C2_READ);
	}
	// Otherwise we are in test mode (which might not exist any more) and we shouldn't be getting IRQs at all!
	else
		printk (KERN_INFO "ECONET-GPIO: IRQ received in Test Mode\n");

	/* And if the mode is anything else, just abandon */

	spin_unlock_irqrestore(&econet_irq_spin, flags);

	return IRQ_HANDLED;

}

/*
 *
 * Main module code
 * 
 * probe, read, write, etc.
 *
 * 
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Royle");
MODULE_DESCRIPTION("Acorn Econet(R) to IP bridge");
MODULE_VERSION("0.01");

/* Packet buffers */
struct __econet_pkt_buffer econet_pkt; /* Temporary buffer for incoming / outgoing packets */


const struct of_device_id econet_of_match[] = {
	{ .compatible = DEVICE_NAME },
	{ }
};

/*
struct platform_driver econet_driver = {
	.driver = {
			.name = DEVICE_NAME,
			.of_match_table = of_match_ptr(econet_of_match)
		},
	.probe = econet_probe,
	.remove = econet_remove
};
*/


/* When a process reads from our device, this gets called. */
ssize_t econet_readfd(struct file *flip, char *buffer, size_t len, loff_t *offset) {

	int ret;
	unsigned int copied;

	ret = kfifo_to_user(&econet_rx_queue, buffer, len, &copied);

	if (ret == 0)
		return copied;
	else	return -EFAULT;


}

unsigned long tx_packets;

/* 
 * This routine works out what to do when we are ready to transmit in AUN mode, and
 * implements the AUN statemachine
 *
 * On entry, writefd should have put the packet we want to transmit in aun_tx 
 * ready for us
 *
 */

void econet_aun_tx_statemachine(void)
{
	
	// In AUN mode, the writefd routine should have put the packet into aun_tx for us. 

	memcpy (&econet_pkt_tx_prepare, &aun_tx, 4); // Source & Destination

	if (econet_data->aun_state == EA_IDLE) // Fresh packet in, so set the tx_status to the rogue
		econet_data->tx_status = 0xff;

	switch (econet_data->aun_state)
	{
		case EA_IDLE: // This must be a write from userspace. Write a Scout, or Immediate if port = 0
		{
			if (aun_tx.d.p.aun_ttype == ECONET_AUN_BCAST) // Broadcast
			{
				econet_pkt_tx_prepare.d.p.dstnet = econet_pkt_tx_prepare.d.p.srcnet = 0xff;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	
				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), (aun_tx.length - 12));
				econet_pkt_tx_prepare.length = 6 + (aun_tx.length > 12 ? (aun_tx.length -6) : 0); // i.e. up to the port byte and then any data that's around
				econet_set_aunstate(EA_W_WRITEBCAST);
			}
			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_IMM) // Immediate
			{
				// Send the packet and move to EA_I_WRITEIMM
				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	
				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), (aun_tx.length - 12));
				econet_pkt_tx_prepare.length = 6 + (aun_tx.length > 12 ? (aun_tx.length - 12) : 0); // i.e. up to the port byte and then any data that's around
				econet_set_aunstate(EA_I_WRITEIMM);
			}	
			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_DATA) // Data -- NB this will also be used for the "special" port 0 ctrl 0x85 "4-way immediate" for things like Notify, etc.
			{
				// Send a scout
				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	
				if (!(aun_tx.d.p.port == 0x00 && aun_tx.d.p.ctrl == 0x85)) // Not one of the 0x85 Immediate "specials"
					econet_pkt_tx_prepare.length = 6;
				else // "Scout" on an 0x85 immediate special has 4 data bytes on the end of it
				{
					econet_pkt_tx_prepare.length = 10;
					memcpy(&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), 4);
/*
					printk (KERN_INFO "ECONET-GPIO: Preparing 0x85 10-byte Special Scout with port %02x ctrl %02x data %02x %02x %02x %02x\n", 
						econet_pkt_tx_prepare.d.p.port, econet_pkt_tx_prepare.d.p.ctrl,
						econet_pkt_tx_prepare.d.p.data[0],
						econet_pkt_tx_prepare.d.p.data[1],
						econet_pkt_tx_prepare.d.p.data[2],
						econet_pkt_tx_prepare.d.p.data[3]);
*/
				}

				// Set up to transmit

				econet_pkt_tx_prepare.ptr = 0;
				econet_set_aunstate(EA_W_WRITESCOUT);
			}
			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_IMMREP) // Reply to an immediate we presumably collected off the wire & send to userspace some time ago
			{
/* Dodgy code
				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	
*/
				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.ctrl), &(aun_tx.d.p.data), (aun_tx.length - 12)); // Used to copy to d.p.data, but that's wrong on an immediate reply
				econet_pkt_tx_prepare.length = 4 + (aun_tx.length > 12 ? (aun_tx.length - 12) : 0); // i.e. up to the port byte and then any data that's around WAS 6 + ...
				econet_set_aunstate(EA_I_WRITEREPLY);
			}
		}
		break;
		case EA_W_WRITEDATA: // We've already sent a scout for a data packet, and got the ACK. Now send the actual data...
		{

			// BIG NOTE HERE: THIS CODE NEVER GETS EXECUTED. LOOKS LIKE THE STATE MACHINE IS ONLY EVER RUN ON A FRESH PACKET.
			// CODE ELSEWHERE (ON RECEIPT OF FIRST ACK) SETS UP THE DATA PACKET FOR TRANSMISSION, NOT THIS BIT!

			// A data packet on the wire has the data starting at byte 4 (where the control byte normally is)
			//if (aun_tx.d.p.port == 0 && aun_tx.d.p.ctrl == 0x85) // Special Immediate &85 4-way thingy - the "data" for the data packet starts at 5th byte of the AUN packet
				//memcpy (&(econet_pkt_tx_prepare.d.data), &(aun_tx.d.raw[4]), aun_tx.length - 16);
			//else
				//memcpy (&(econet_pkt_tx_prepare.d.data), &(aun_tx.d.raw), aun_tx.length - 12); // AUN buffers have 12 bytes on the front (4 address, port, ctrl, pad, type, 4 byte seq)
			// The above must be wrong, surely - it's copying from the start of the station number bit (d.raw, not d.p.data), to the start of the station number bit in the prepare packet (d.data, not d.p.data). Try the below instead

			// Copy addressing data
			memcpy (&(econet_pkt_tx_prepare.d.data), &(aun_tx.d.raw), 4); // Note this copies to d.data, not d.p.data - so it's writing over the addressing bytes on the prepared packets, and it's copying them from the incoming AUN packet (with our special 4 byte address block on the start)

			printk (KERN_INFO "ECONET-GPIO: Preparing to write 4-way data packet to %d.%d from %d.%d\n", aun_tx.d.p.dstnet, aun_tx.d.p.dststn, aun_tx.d.p.srcnet, aun_tx.d.p.srcstn);

			if (!(aun_tx.d.p.port == 0x00 && aun_tx.d.p.ctrl == 0x85)) // Not an immediate 0x85 special (4 way handshake job with 4 data bytes on the scout - used for Notify, Remote, View)
			{
				econet_pkt_tx_prepare.length = (aun_tx.length - 12 + 4); // The wire packet is the AUN data portion, so drop off the 12 byte AUN header (8 normal AUN header plus our special 4 for source/dest net/stn), and add the 4 byte Econet wire source/destination length
				memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), aun_tx.length - 12); // AUN buffers have 12 bytes on the front (4 address, port, ctrl, pad, type, 4 byte seq) 
			}
			else // Immediate 0x85 Special - we will have sent the first 4 data bytes on the Quasi-"Scout", so only want whatever is left in this packet
			{
				econet_pkt_tx_prepare.length = (aun_tx.length -4 - 12 + 4); // The wire packet is the AUN data portion, so drop off the 12 byte AUN header (8 normal AUN header plus our special 4 for source/dest net/stn), and add the 4 byte Econet wire source/destination length
				// And copy all but the first four data bytes into our data area, if any
				if (aun_tx.length > 16)
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data[4]), aun_tx.length - 16); // AUN buffers have 12 bytes on the front (4 address, port, ctrl, pad, type, 4 byte seq) . Deduct 16 here because we will already have sent 4 data bytes that we are not copying

				printk (KERN_INFO "ECONET-GPIO: Prepared Immediate 0x85 special data packet length %04x First data byte %02x\n", aun_tx.length, econet_pkt_tx_prepare.d.p.data[0]);
			}
/*
			if (aun_tx.d.p.port == 0 && aun_tx.d.p.ctrl == 0x85 && aun_tx.length > 16) // Special Immediate &85 4-way thingy - the "data" for the data packet starts at 5th byte of the AUN packet
				memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data[4]), aun_tx.length - 16);
			else
				memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), aun_tx.length - 12); // AUN buffers have 12 bytes on the front (4 address, port, ctrl, pad, type, 4 byte seq)
			econet_pkt_tx_prepare.length = (aun_tx.length - 12 + 4 - ((aun_tx.d.p.port == 0 && aun_tx.d.p.ctrl == 0x85) ? 4 : 0));
*/

			printk (KERN_INFO "ECONET-GPIO: EA_W_WRITEDATA Port %02x Ctrl %02x Length %04x\n", econet_pkt_tx_prepare.d.p.port, econet_pkt_tx_prepare.d.p.ctrl, econet_pkt_tx_prepare.length);
		}
		break;
		case EA_R_WRITEFIRSTACK: // We got a scout, we are now writing the first ACK. The read routine should have lined our packet up for us
		case EA_R_WRITEFINALACK: // Ditto
			break;
		case EA_I_WRITEREPLY: // We are replying to an immediate off the wire. In fact, this is equivalent to EA_IDLE too because we go straight back there after TX. This option is probably never reached since the statemachine is in idle during flag fill after receiving an immediate off the wire
			break;
	}
}

// When defined, this printk's some timing information about writefd which was used for debugging why writing took so long.
// It turned out to be something in set_write_mode()
//#define ECONET_WRITE_INSTRUMENTATION

/* Called when a process tries to write to our device */
ssize_t econet_writefd(struct file *flip, const char *buffer, size_t len, loff_t *offset) 
{
	// First wait until we are IDLE

	u64 timer, timer2;
	unsigned short status, aun_status, reset_counter;
	int c;
	int tx_success, status_on_entry;
	u64 ts_entry, ts_tx_start, ts_tx_end, ts_return;

	if (len > ECONET_MAX_PACKET_SIZE)
		return -EINVAL;

	ts_entry = ktime_get_ns();
	status_on_entry = econet_data->mode;
	reset_counter = 0;

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: Adapter mode on entry to writefd() = %d\n", status_on_entry);
#endif

// Check for clock 

	if (!(econet_data->clock))
		econet_get_sr(); // Have another look
	
	if (!(econet_data->clock))
	{
		econet_data->last_tx_user_error = ECONET_TX_NOCLOCK;
#ifdef ECONET_GPIO_DEBUG_TX
		printk (KERN_ERR "ECONET-GPIO: econet_writefd(): No clock\n");
#endif
		econet_set_chipstate(EM_IDLEINIT);
		econet_set_read_mode();
		if (econet_data->aun_mode) // If we are giving up, and in AUN mode, gop back to IDLE
			econet_set_aunstate(EA_IDLE);
		return -1;
	}

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Clock detected\n");
#endif

	if ((c = copy_from_user(&econet_pkt, buffer, len)))
	{
		econet_pkt.ptr = econet_pkt.length = 0; // Empty the packet 
		printk (KERN_ERR "ECONET-GPIO: econet_writefd() Failed to copy %d bytes from userspace", c);
		econet_data->last_tx_user_error = ECONET_TX_NOCOPY;
		return  -1;
	}

outer_reset_loop:

	if (econet_data->aun_mode) // AUN Mode - this is an AUN format packet from userspace, put it in aun_tx
	{
		memcpy (&aun_tx, &econet_pkt, len); // Puts the four src/dst bytes into aun_tx. Line the rest up later.
		aun_tx.length = len;
#ifdef ECONET_GPIO_DEBUG_AUN
		printk (KERN_INFO "ECONET-GPIO: econet_writefd(): AUN: Packet from userspace from %d.%d to %d.%d, data length %d", aun_tx.d.p.srcnet, aun_tx.d.p.srcstn, aun_tx.d.p.dstnet, aun_tx.d.p.dststn, (len - 12));
#endif
	}
	else
#ifdef ECONET_GPIO_DEBUG_TX
		printk (KERN_INFO "ECONET-GPIO: econet_writefd() called - length %d to %d.%d from %d.%d\n", len, econet_pkt.d.p.dstnet, econet_pkt.d.p.dststn, econet_pkt.d.p.srcnet, econet_pkt.d.p.srcstn);
#endif

	if (econet_data->aun_mode)
		timer = ktime_get_ns() + 750000000; // Longer wait time if in AUN mode - need to wait for the AUN state machine, potentially
	else
		timer = ktime_get_ns() + 250000000; // 250ms timeout (was half a second in testing!)

	if (econet_data->mode == EM_READ && (ktime_get_ns() -  last_data_rcvd) > 250000000) // Stuck in read mode
	{
		// Go back to idle mode (is done in the IRQ handler on EM_WRITEWAIT)
		printk (KERN_INFO "ECONET-GPIO: Stuck in EM_READ. Resetting to IDLE.\n");
		econet_set_chipstate(EM_IDLEINIT);
		econet_write_cr(ECONET_GPIO_CR2, C2_READ);
	}

	// If in AUN mode and we are part way through a 4-way handshake, or immediate exchange, which has clearly stalled, give up and reset the AUN state machine back to IDLE

	//printk (KERN_INFO "ECONET-GPIO: AUN State %d, Chip state %d, last tx %lld, now %lld\n", econet_data->aun_state, econet_data->mode, econet_data->aun_last_tx, ktime_get_ns());

	if (econet_data->aun_mode && 
		(econet_data->mode == EM_IDLEINIT || econet_data->mode == EM_IDLE) && 
		(econet_data->aun_state == EA_W_READFIRSTACK || econet_data->aun_state == EA_W_READFINALACK || econet_data->aun_state == EA_R_READDATA || econet_data->aun_state == EA_I_READREPLY) && 
		(econet_data->aun_last_tx < (ktime_get_ns() - ECONET_4WAY_TIMEOUT))
	) // 4-way handshake has failed previously - abandon and go back to idle - i.e. we are being asked to write something but we were stuck in the 4-way waiting to read the next phase and nothing had arrived within the timeout period
		econet_set_aunstate(EA_IDLE);

	// Wait for IDLE state, and if we don't get it after a while then forcibly put the chip there
	do
	{
		status = econet_data->mode; 
		
		aun_status = econet_data->aun_state;

		if ((status == EM_IDLE || status == EM_IDLEINIT || status == EM_FLAGFILL) && ((econet_data->aun_mode && econet_data->aun_state == EA_IDLE) || (!econet_data->aun_mode))) // If we are in AUN mode, the AUN state machine also needs to be IDLE
		{

			unsigned short starter_counter = 0;

			// Instrumentation
			ts_tx_end = ts_tx_start = ktime_get_ns();

			status = EM_WRITE; // Our local copy. set_write_mode updates econet_data;

			tx_packets++;
		
#ifdef ECONET_GPIO_DEBUG_TX
			printk (KERN_INFO "ECONET_GPIO: econet_writefd(): TX Packet no. %lu\n", tx_packets);
#endif

restart_tx:
			if (econet_data->aun_mode)
			{
				econet_aun_tx_statemachine(); // Work out the initial packet and set it up to be transmitted
				// THe state machine prepares its packet in econet_pkt_tx_prepare
				econet_set_write_mode (&econet_pkt_tx_prepare, econet_pkt_tx_prepare.length);
			}
			else
			{
				// Trigger a transmit of the packet we copied from userspace
				econet_set_write_mode(&econet_pkt, len); // Trigger TX
			}

			if (econet_data->tx_status == -ECONET_TX_NOIRQ && (starter_counter++ < 10)) // econet_set_write_mode didn't get an IRQ in time - have another go, up to a limit
				goto restart_tx;

			if (econet_data->tx_status == -ECONET_TX_NOIRQ)
			{
				if (econet_data->aun_mode) // If we are giving up, and in AUN mode, gop back to IDLE
					econet_set_aunstate(EA_IDLE);

				econet_set_read_mode();
				return -1;	
			}
			
			// Wait for TX to start 50ms
#define ECONET_TX_START_WAIT_PERIOD 50000000
#define ECONET_TX_MAXSTARTS 50
		
			timer2 = ktime_get_ns() + ((unsigned long long) ECONET_TX_START_WAIT_PERIOD);

			while ((econet_data->tx_status == 0xff) && (ktime_get_ns() < timer2)); // Wait to see if TX starts or errors in the start wait period

			if (econet_data->tx_status == 0xff && (starter_counter++ < ECONET_TX_MAXSTARTS)) // not started, have another go
				goto restart_tx;

#define ECONET_TX_WAIT_PERIOD 750000000 // 0.5s should be long enough for most packets

			if (starter_counter > 0)
				printk (KERN_INFO "ECONET-GPIO: Needed %d attempts before transmission started within 50ms. Is your Econet busy?\n", starter_counter+1);

			//printk (KERN_INFO "ECONET-GPIO: TX status after 50ms = %02X\n", econet_data->tx_status);

			timer2 = ktime_get_ns() + ((unsigned long long) ECONET_TX_WAIT_PERIOD); 

			// Probably should acquire pkt spin lock each time here...

			//while (((tx_success = econet_data->tx_status) == 0xff) && ((ts_tx_end = ktime_get_ns()) < timer2));
			// Wait for end of transmission
		
			while (((tx_success = econet_data->tx_status) == 0xfe) && ((ts_tx_end = ktime_get_ns()) < timer2));

			//if (ts_tx_end >= timer2) // Timed out
			if (tx_success == 0xff || tx_success == 0xfe) // Never started or didn't finish in time
			{
				ts_return = ktime_get_ns();
#ifdef ECONET_WRITE_INSTRUMENTATION
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): tx instrumentation: started +%lld ns, ended +%lld ns, returned %lld ns\n", (ts_tx_start - ts_entry),
							(ts_tx_end - ts_entry), (ts_return - ts_entry));
#endif
#ifdef ECONET_GPIO_DEBUG_TX
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Returning TX_NOTSTART\n");
#endif
#ifdef ECONET_GPIO_DEBUG_AUN
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): AUN: Timeout waiting for transmission to complete. Returning TX_NOTSTART\n");
#endif
				if (econet_data->aun_mode) // If we are giving up, and in AUN mode, gop back to IDLE
					econet_set_aunstate(EA_IDLE);

				econet_set_read_mode();
				econet_data->last_tx_user_error = ECONET_TX_HANDSHAKEFAIL;
				return -1;
			}	

			if (tx_success == ECONET_TX_SUCCESS)
			{
				ts_return = ktime_get_ns();
#ifdef ECONET_WRITE_INSTRUMENTATION
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): tx instrumentation: started +%lld ns, ended +%lld ns, returned %lld ns\n", (ts_tx_start - ts_entry),
							(ts_tx_end - ts_entry), (ts_return - ts_entry));
#endif
#ifdef ECONET_GPIO_DEBUG_TX
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Returning SUCCESS - %d bytes\n", len);
#endif
#ifdef ECONET_GPIO_DEBUG_AUN
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): AUN: Transmit success - returning %d (data portion %d) to userspace\n", len, len-12);
#endif
				econet_set_read_mode();
				econet_data->last_tx_user_error = 0;
				return len;
			}
			else if (tx_success == -ECONET_TX_NOCLOCK) // No clock on TX
			{
				econet_set_read_mode();
				econet_data->last_tx_user_error = -tx_success;
				return -1;
			}
			else if ((starter_counter++ < ECONET_TX_MAXSTARTS) && (tx_success == ECONET_TX_HANDSHAKEFAIL || tx_success == ECONET_TX_UNDERRUN || tx_success == ECONET_TX_TDRAFULL || tx_success == ECONET_TX_NOTSTART || tx_success == ECONET_TX_COLLISION)) // We've had less than 10 gos and have a non-fatal error, have another go
			{
				if ((econet_data->aun_mode) && (tx_success == ECONET_TX_COLLISION)) // Back off
					udelay (160+(50 * aun_tx.d.p.srcstn)); // per station, prioritising the higher station numbers, increasing every time we have to have another go. Adjusted to match what the SJ Bridge used to do - but not necessarily on a bog standard collision - not sure if I've read the source right.

				goto restart_tx;
			}
			else 
			{
				// Note that in this block, tx_success in fact contains an error code.

				ts_return = ktime_get_ns();
#ifdef ECONET_WRITE_INSTRUMENTATION
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): tx instrumentation: started +%lld ns, ended +%lld ns, returned %lld ns\n", (ts_tx_start - ts_entry),
							(ts_tx_end - ts_entry), (ts_return - ts_entry));
#endif
#ifdef ECONET_GPIO_DEBUG_TX
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Returning ERROR %d\n", tx_success);
#endif
#ifdef ECONET_GPIO_DEBUG_AUN
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): AUN: Transmit failure - returning %d to userspace\n", tx_success);
#endif
				//printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Returning error %d\n", tx_success);
				econet_set_read_mode();
				econet_data->last_tx_user_error =  -tx_success;
				return tx_success;
			}
			
		}
		else
		{
#ifdef ECOENT_GPIO_DEBUG_TX
			printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Chip not idle. Wait.\n");	
#endif
#ifdef ECOENT_GPIO_DEBUG_AUN
			printk (KERN_INFO "ECONET-GPIO: econet_writefd(): Chip not idle. Wait.\n");	
#endif
			if (econet_data->aun_mode && econet_data->aun_state != EA_IDLE) // Longer delay if we are waiting for the AUN state machine
				udelay(200);
			else // Shorter delay if we are just waiting for the chip
				udelay(1); // Wait a bit and see what happens

			// Added 25.07.21
			econet_set_chipstate(EM_IDLE);
		}
	} while (status != EM_IDLE && status != EM_IDLEINIT && status != EM_FLAGFILL && (ktime_get_ns() < timer));

	//econet_set_read_mode(); // Put chip back in read mode (Done in the IRQ handler)

	ts_return = ktime_get_ns();
#ifdef ECONET_WRITE_INSTRUMENTATION
				printk (KERN_INFO "ECONET-GPIO: econet_writefd(): tx instrumentation: started +%lld ns, ended +%lld ns, returned %lld ns\n", (ts_tx_start - ts_entry),
							(ts_tx_end - ts_entry), (ts_return - ts_entry));
#endif
	printk (KERN_INFO "ECONET-GPIO: econet_writefd(): failed to get EM_IDLE state. Chip state = %d, aun state = %d\n", status, aun_status);

	if (econet_data->aun_mode && (econet_data->mode == 6 || econet_data->mode == 7) && reset_counter++ < 4) // AUN mode but chip is idle
	{
		econet_set_aunstate(EA_IDLE);
		goto outer_reset_loop;
	}

	econet_data->last_tx_user_error = EBUSY;
	return -1;

}

/* Called when a process opens our device */
int econet_open(struct inode *inode, struct file *file) {
 /* If device is open, return busy */
 if (econet_data->open_count) {
 return -EBUSY;
 }
 econet_data->open_count++;
 try_module_get(THIS_MODULE);
 return 0;
}

/* Called when a process closes our device */
int econet_release(struct inode *inode, struct file *file) {
 /* Decrement the open counter and usage count. Without this, the module would not unload. */
 econet_data->open_count--;
 module_put(THIS_MODULE);
 return 0;
}

/* Poll routine */
unsigned int econet_poll (struct file *filp, poll_table *wait)
{

        unsigned int mask = 0;

        poll_wait (filp, &(econet_data->econet_read_queue), wait);

        if (!kfifo_is_empty(&econet_rx_queue))
                mask |= POLLIN | POLLRDNORM;

        return mask;
}

/* IOCTL routine */
long econet_ioctl (struct file *gp, unsigned int cmd, unsigned long arg)
{

        // unsigned char w; // Disused after removal of use of econet_write_bus() in data bus test harness ioctl()

#ifdef ECONET_GPIO_DEBUG_IOCTL
        printk (KERN_DEBUG "ECONET-GPIO: IOCTL(%d, %lu)\n", cmd, arg);
#endif

        switch(cmd){
                case ECONETGPIO_IOC_RESET:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(reset) called\n");
#endif
                        econet_reset();
                        break;
                case ECONETGPIO_IOC_PACKETSIZE: /* Return max packet size */
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(max_packet_size) called\n");
#endif
                        return ECONET_MAX_PACKET_SIZE;
                        break;
		case ECONETGPIO_IOC_READMODE: /* Go back to read mode - used after an immediate off the wire went unresponded to, but could be handy at other times */
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set read mode) called\n");
#endif
			econet_set_read_mode();
			if (econet_data->aun_mode)
				econet_set_aunstate(EA_IDLE);
			break;
                case ECONETGPIO_IOC_SET_STATIONS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set stations) called\n");
#endif
                        /* Copy station bitmap from user memory */
                        if ((!access_ok(arg, 8192)) || copy_from_user(econet_stations, (void *) arg, 8192))
			{
				printk (KERN_INFO "ECONET-GPIO: Unable to update station set.\n");
                                return -EFAULT;
			}
                        printk(KERN_INFO "ECONET-GPIO: Station set updated - Switching on AUN mode\n");
			econet_data->aun_mode = 1; // Turn this on if we get a station set
			econet_set_aunstate(EA_IDLE);
			//econet_data->aun_state = EA_IDLE; // Initialize the state machine
                        break;
                case ECONETGPIO_IOC_AVAIL:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(rx queue availablity) called\n");
#endif
			return 0;
                        //return kfifo_avail(&econet_rx_queue);
/* Routines for testing only */
                case ECONETGPIO_IOC_SETA:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set address, %02lx) called\n", (arg & 0x03));
#endif
			if (econet_data->hwver >= 2) while (econet_isbusy());
                        econet_set_addr((arg & 0x2) >> 1, (arg & 0x1));
                        break;
                case ECONETGPIO_IOC_WRITEMODE:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set write mode, %02lx) called\n", (arg & 0x01));
#endif
                        econet_set_dir(arg & 0x01);
                        break;
                case ECONETGPIO_IOC_SETCS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set /CS, %02lx) called\n", (arg & 0x01));
#endif
                        econet_set_cs(arg & 0x01);
                        break;
                case ECONETGPIO_IOC_SETBUS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set bus, %02lx) called\n", (arg & 0xff));
#endif
			// Commented to remove reliance on write bus. This ioctl() only for hardware test harness, so no nCS testing required etc.
                        //w = econet_write_bus((char) (arg & 0xff));

			econet_set_dir(ECONET_GPIO_WRITE);
			
			// Put it on the bus
			writel((arg << ECONET_GPIO_PIN_DATA), GPIO_PORT + GPSET0);
			writel((~(arg << ECONET_GPIO_PIN_DATA)) & ECONET_GPIO_CLRMASK_DATA, GPIO_PORT + GPCLR0);
                        break;
                case ECONETGPIO_IOC_TEST:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set test mode) called\n");
#endif
			econet_reset();
			econet_set_chipstate(EM_TEST);
                        //econet_data->mode = EM_TEST;
                        econet_irq_mode(0);
                        break;
		case ECONETGPIO_IOC_TXERR:

#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(get last tx error) called\n");
#endif
			return (econet_data->last_tx_user_error);
			break;
                case ECONETGPIO_IOC_FLAGFILL: /* Go into flag fill */
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set flag fill) called\n");
#endif
                        if (arg)
                                econet_flagfill();
                        else    econet_set_read_mode();
                        break;

		case ECONETGPIO_IOC_AUNMODE:
			if (arg != 1 && arg != 0)
			{
				printk (KERN_ERR "ECONET-GPIO: Invalid argument (%ld) to ECONETGPIO_IOC_AUNMODE ioctl()\n", arg);
				break;
			}

			// By here, we have a valid arg

			econet_reset();
			econet_data->aun_mode = arg; // Must do this after econet_reset, because econet_reset turns AUN off.

			printk (KERN_INFO "ECONET-GPIO: AUN mode turned %s by ioctl()\n", (arg == 1 ? "on" : "off"));

			break;

		case ECONETGPIO_IOC_IMMSPOOF:
			printk (KERN_INFO "ECONET-GPIO: Changing immediate spoof mode to %s\n", arg ? "ON" : "OFF");
			econet_data->spoof_immediate = arg ? 1 : 0;
			break;
		case ECONETGPIO_IOC_TESTPACKET: /* Send test packet */
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(test packet) called\n");
#endif
			// if there is anything being done, wait for it to go away
			{
				u64 timer;
		
				timer = ktime_get_ns() + 500000000; // Half a second. Probably too much...
	
				while ((ktime_get_ns() < timer) && (econet_data->mode != EM_IDLE));
				
			}
			//econet_reset();
			//mdelay(50);
			//spin_lock(&econet_pkt_spin);
			econet_pkt.d.p.dststn = 1;
			econet_pkt.d.p.dstnet = 0; /* Station 1 on local network */
			econet_pkt.d.p.srcstn = 254;
			econet_pkt.d.p.srcnet = 0; /* Station 254 on local network */
			econet_pkt.d.p.ctrl = 0x88; /* Machine Type query */
			econet_pkt.d.p.port = 0x00; /* Immediate */
			econet_pkt.length = 6;
			econet_pkt.ptr = 0; /* Start at the beginning */
			//spin_unlock(&econet_pkt_spin);
			econet_set_write_mode(&econet_pkt, 6);
			break;
                default:
                        return -ENOTTY;
        }

        return 0;

}

/* Init routine */

//int econet_probe (struct platform_device *pdev)
static int __init econet_init(void)
{

	int err;
	int result;

	/* Initialize some debug instrumentation */
	tx_packets = 0; 

	/* See if our ancient econet_ndelay code is disabled */
#ifdef ECONET_NO_NDELAY
	printk (KERN_INFO "ECONET-GPIO: Old econet_ndelay() code disabled. This is Good.\n");
#endif

	/* Iniialize kfifos */

	result = kfifo_alloc(&econet_rx_queue, 65536, GFP_KERNEL);
	if (result)
	{
		printk (KERN_INFO "ECONET-GPIO: Failed to allocate kernel RX fifo\n");
		return -ENOMEM;
	}

	result = kfifo_alloc(&econet_tx_queue, 65536, GFP_KERNEL);
	if (result)
	{
		printk (KERN_INFO "ECONET-GPIO: Failed to allocate kernel TX fifo\n");
		return -ENOMEM;
	}

	/* Init spinlocks */

	spin_lock_init(&econet_irqstate_spin);
	spin_lock_init(&econet_tx_spin);

	/* Allocate internal state */

	econet_data = kzalloc(sizeof(struct __econet_data), GFP_KERNEL);

	if (!econet_data)
	{
		printk ("ECONET-GPIO: Failed to allocate internal data storage.\n");
		return -ENOMEM;
	}

	econet_set_chipstate(EM_TEST);
	econet_data->irq_state = -1;
	econet_data->aun_mode = 0;
	econet_data->aun_seq = 0x4000;
	econet_data->aun_last_tx = 0;
	econet_data->clock = 0; // Assume no clock to start with
	econet_set_aunstate(EA_IDLE);
	econet_data->spoof_immediate = 0;
	
	// Assume hardware version 1 unless told otherwise
	econet_data->hwver = 1;

	econet_data->major=register_chrdev(0, DEVICE_NAME, &econet_fops);
	if (econet_data->major < 0)
	{
	 	printk (KERN_INFO "ECONET-GPIO: Failed to obtain major device number.\n");
		return econet_data->major;
	}

	if (IS_ERR(econet_class = class_create(THIS_MODULE, CLASS_NAME)))
	{
		printk (KERN_INFO "ECONET-GPIO: Failed creating device class\n");
		result = PTR_ERR(econet_class);
		kfifo_free(&econet_rx_queue);
		kfifo_free(&econet_tx_queue);
		unregister_chrdev(econet_data->major, DEVICE_NAME);
		kfree(econet_data);
		return result;
	}


	if (IS_ERR(econet_data->dev = device_create(econet_class, NULL, MKDEV(econet_data->major, 0), NULL, DEVICE_NAME)))
	{
		printk (KERN_INFO "ECONET-GPIO: Failed creating device class\n");
		result = PTR_ERR(econet_data->dev);
		class_destroy(econet_class);
		kfifo_free(&econet_rx_queue);
		kfifo_free(&econet_tx_queue);
		unregister_chrdev(econet_data->major, DEVICE_NAME);
		kfree(econet_data);
		return result;
	}
		

 	printk(KERN_INFO "ECONET-GPIO: Loaded. Major number %d\n", econet_data->major);

	init_waitqueue_head(&(econet_data->econet_read_queue));

	if ((err = econet_gpio_init()) < 0)
	{
		device_destroy(econet_class, MKDEV(econet_data->major, 0));
		class_destroy(econet_class);
		kfifo_free(&econet_rx_queue);
		kfifo_free(&econet_tx_queue);
		unregister_chrdev(econet_data->major, DEVICE_NAME);
		kfree(econet_data);
		return err;
	}

	econet_reset(); // Does the station array clear

	econet_set_read_mode();

	printk (KERN_INFO "ECONET-GPIO: Hardware present - version %d%s. ADLC initialized.\n", econet_data->hwver, (econet_data->hwver >= 2) ? " - how exciting!" : "");

	econet_get_sr();

	if (!(econet_data->clock))
		printk (KERN_ERR "ECONET-GPIO: No clock! (SR1 = 0x%02x, SR2 = 0x%02x)\n", sr1, sr2);
	else
		printk (KERN_INFO "ECONET-GPIO: Clock detected (SR1 = 0x%02x, SR2 = 0x%02x)\n", sr1, sr2);

 	return 0;

}

/* Exit routine */

//int econet_remove (struct platform_device *pdev)
static void __exit econet_exit(void)
{
	econet_gpio_release();
	
	device_destroy(econet_class, MKDEV(econet_data->major, 0));
	class_destroy(econet_class);
 	unregister_chrdev(econet_data->major, DEVICE_NAME);
	kfree(econet_data);
	kfifo_free(&econet_rx_queue);
	kfifo_free(&econet_tx_queue);
 	printk(KERN_INFO "ECONET-GPIO: Unloaded.");

//	return 0;

}
/* Register module functions */
module_init(econet_init);
module_exit(econet_exit);

//module_platform_driver(econet_driver);
//MODULE_DEVICE_TABLE(of, econet_of_match);
