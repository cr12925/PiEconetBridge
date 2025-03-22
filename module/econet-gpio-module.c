/*
  (c) 2024 Chris Royle
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
#include <linux/pwm.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/time64.h>
#include <linux/ktime.h>
#include <linux/version.h>

#include <asm/uaccess.h>

#define ECONETGPIO_KERNEL
#include "../include/econet-gpio.h"

/* 
 * ECONET_GPIO_NEW define.
 *
 * When defined, switches the operation of the
 * module to use only gpiod_ calls to talk to
 * to the GPIOs. This introduces significant
 * latency and stops the module working
 * properly, so don't define it.
 *
 */

/*
 * Some macros to make the code
 * easier to read when reading the
 * list of gpios.
 *
 */

#define ECOPIN(a)	econet_data->econet_gpios[(a)]
#define ECONET_GETGPIO(i,n,d)	econet_data->econet_gpios[(i)] = devm_gpiod_get(dev, n, (d))
#define ECONET_GPIOERR(i) if (IS_ERR(econet_data->econet_gpios[(i)])) { printk (KERN_INFO "econet-gpio: Failed to obtain GPIO ref %d\n", (i)); return PTR_ERR(econet_data->econet_gpios[(i)]); }

/*
 * Some constants used for the nasty
 * timing loops on v1 hardware.
 */

#define ECONET_GPIO_CLOCK_DUTY_CYCLE  1000   /* In nanoseconds - 2MHz clock is 500 ns duty cycle, 1MHz is 1us, or 1000ns */

#ifdef ECONET_GPIO_NEW
struct gpio_desc *a01rw_desc_array[3];
struct gpio_desc *data_desc_array[11]; // Top 3 are the address & RnW lines in case of need
#endif

// Next 6 lines can be commented if we ever manage to move to all gpiod_ calls.
// 20240623 Pi3 64 Bit change
void __iomem *GPIO_PORT = NULL;
unsigned GPIO_RANGE = 0x40;

/* 
 * Variables to hold
 * ADLC Status Register values when read, and
 * the value to be set into the data reg
 */

u8 sr1, sr2;
u32 gpioset_value;

/* 
 * Module operations
 */

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
u8 econet_rx_queue_initialized = 0;
u8 econet_tx_queue_initialized = 0;

/* writefd() mutex */
struct mutex econet_writefd_mutex;

/* Structure used to dump a packet off the rx FIFO if it's full */
struct __econet_packet dump_pkt;

/* Internal data */
struct __econet_data *econet_data = NULL;
struct class *econet_class = NULL;
u8 econet_class_initialized = 0;
u8 econet_device_created = 0;

spinlock_t econet_irq_spin;
spinlock_t econet_tx_spin;
spinlock_t econet_irqstate_spin;

/* Packet counter */

unsigned long tx_packets;

/* Packet buffers */

struct __econet_pkt_buffer econet_pkt; /* Temporary buffer for incoming / outgoing packets */

void econet_set_read_mode(void);
void econet_set_write_mode(struct __econet_pkt_buffer *, int);
void econet_set_pwm(uint8_t, uint8_t);

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

struct __econet_pkt_buffer 	econet_pkt_tx, 
				econet_pkt_tx_prepare, 
				econet_pkt_rx;

/*
 * AUN+4 format buffers for packet received
 * from userspace / received off wire
 *
 */

struct __aun_pkt_buffer 	aun_tx,  
				aun_rx;

/* Appears to be disused
char aun_stn, aun_net; // The net & station we are presently dealing with in the IP world - used to sanity check whether what comes off the wire is what we expect!
*/

/* 
 * Tracks when last data received
 *
 * So we can tell whether to start new transaction
 *
 */

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
 * Macros which abstract econet_write_cr()
 * to write to the FIFO and write to
 * FIFO and signal last data byte
 */

#define econet_write_fifo(x) econet_write_cr(3, (x))
#define econet_write_last(x) econet_write_cr(4, (x))

/* 
 * econet_write_cr - write value to ADLC control register
 *
 */

void econet_write_cr(unsigned short r, unsigned char d)
{
#ifdef ECONET_GPIO_NEW
	unsigned long int gpioval;
	u8	count;
#else
	u32 gpioval, gpiomask;
#endif

	if (r > 4)
	{
		printk (KERN_ERR "econet-gpio: Attempt to write to CR%d ! What is going on ?", r);
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
		while (econet_isbusy());


#ifdef ECONET_GPIO_NEW

	// Turn direction around

	if (econet_data->current_dir != ECONET_GPIO_WRITE)
		for (count = EGP_D0; count <= EGP_D7; count++)
			gpiod_direction_output(econet_data->econet_gpios[count], 0); // Set to 0 output for now

	econet_data->current_dir = ECONET_GPIO_WRITE;

	// Set address & RnW & data
	gpioval = (r << 8) | d; // RnW = 0 for write
	gpiod_set_array_value (11, data_desc_array, NULL, &gpioval); // 11 because the address & RnW are in 8,9,10

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

	barrier();
#endif

	// Enable nCS - Tell the ADLC we want to talk to it
	
	econet_set_cs(ECONET_GPIO_CS_ON);

#ifndef ECONET_GPIO_NEW
	// If v1 hardware, wait until we know CS has reached the ADLC
	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}
#endif

	barrier(); // Operates for both v1 & v2 hardware

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
		while (econet_isbusy()); // Wait until the ADLC has read our data. Not massively reliable yet.. SHouldn't be required, but seems to be!
}

/* 
 * Macro abstracting econet_read_sr() to read FIFO
 */

#define econet_read_fifo() econet_read_sr(3)

/* 
 * econet_read_sr - read value from ADLC status register
 *
 */

unsigned char econet_read_sr(unsigned short r)
{
	unsigned char d;
#ifdef ECONET_GPIO_NEW
	unsigned long int 	gpioval_array;
#endif
	u32 gpioval, gpiomask;

	if (r > 4)
	{
		printk (KERN_ERR "econet-gpio: Attempt to read SR%d ! What is going on ?\n", r);
		return 0;
	}

	r--;

	if (econet_data->hwver >= 2)
		while (econet_isbusy());

	 
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
		barrier();
#endif
	}

#ifdef ECONET_GPIO_NEW

	gpioval = r | 0x04; // 0x04 is third bit in the value, which is the RW figure, and we need 1 for read because the pin is RnW

	if (gpiod_set_array_value (3, a01rw_desc_array, NULL, &gpioval) < 0)
	{
		printk (KERN_ERR "econet-gpio: Error writing address lines ready to ready SR\n");
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
	
	// Shouldn't need a barrier here because apparently iowrite32() has one in it.

	barrier();

#endif

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

	/* Finish with ADLC */

	econet_set_cs(ECONET_GPIO_CS_OFF);	

	barrier();

#ifndef ECONET_GPIO_NEW
	if (econet_data->hwver < 2)
	{
		econet_ndelay(100);
	}
	else
#endif
		while (econet_isbusy());

#ifdef ECONET_GPIO_NEW

	if (gpiod_get_array_value(8, data_desc_array, NULL, &gpioval_array) < 0)
	{
		printk (KERN_ERR "econet-gpio: Error reading GPIOs!\n");
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


#ifndef ECONET_GPIO_NEW /* Only used for v1 boards which cannot use new mode */

/* 
 * econet_probe_adapter()
 *
 * Probe the v1 hardware, once GPIOs obtained
 *
 */

int econet_probe_adapter(void)
{

	// put CS low, high and then low again and on each occasion
	// check that the matching signal comes back on the /CS return line
	// thus showing that there is a D-Type there with a working clock

	econet_set_cs(0);

	udelay(2); // 2us should always be enough

	if ((ioread32(NGPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) != 0)
	{

		printk (KERN_ERR "econet-gpio: Version 1 hardware test failed - nCS return not returning (test 1).\n");
		return 0;
	}

	econet_set_cs(1);

	/* This is the old code. Only used on v1 hardware. Duration now hard coded. */
	/* udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE); */
	udelay(1);

	if ((ioread32(NGPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) == 0)
	{
		printk (KERN_ERR "econet-gpio: Version 1 hardware test failed - nCS return not returning (test 2).\n");
		return 0;
	}

	econet_set_cs(0);

	/* This is the old code. Only used on v1 hardware. Duration now hard coded. */
	/* udelay(ECONET_GPIO_CLOCK_US_DUTY_CYCLE); */
	udelay(1);


	if ((ioread32(NGPLEV0) & (1 << ECONET_GPIO_PIN_CSRETURN)) != 0)
	{
		printk (KERN_ERR "econet-gpio: Version 1 hardware test failed - nCS return not returning (test 3).\n");
		return 0;
	}

	return 1;

}

#if 0 /* econet_gpio_init() now thought to be redundant, 
	 because on this version even v1 boards have a 
	 DT overlay and grab the GPIOs via gpiod_get */
/*
 * econet_gpio_init()
 *
 * Initialize gpio peripheral access to clock & pwm, set up
 * 8MHz clock to ADLC and PWM clock for network on v2 boards.
 *
 */

short econet_gpio_init(void)
{

	u32 t; /* Variable to read / write GPIO registers in this function */

	// Request the clock region

	request_region(CLOCK_PERI_BASE, GPIO_CLK_RANGE, DEVICE_NAME);

	GPIO_CLK = ioremap(CLOCK_PERI_BASE, GPIO_CLK_RANGE);

	if (GPIO_CLK)
	{
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "econet-gpio: Clock base remapped to %p\n", GPIO_CLK);
#endif
	}
	else
	{
		printk (KERN_INFO "econet-gpio: Clock base remap failed.\n");
		return 0;
	}
	
	// Ask for clock function on CLK pin - done in probe if ECONET_GPIO_NEW defined.

	t = (ioread32(GPIO_PORT) & ~(0x07 << (3 * ECONET_GPIO_PIN_CLK))) | (ECONET_GPIO_CLK_ALT_FUNCTION << (3 * ECONET_GPIO_PIN_CLK));

	iowrite32 (t, GPIO_PORT); /* Select alt function for clock output pin */

	// Now set the clock up on it

	iowrite32 ((ioread32(GPIO_CLK + ECONET_GPIO_CMCTL) & ~0xF0) | ECONET_GPIO_CLOCKDISABLE, GPIO_CLK + ECONET_GPIO_CMCTL); // Disable clock

	barrier();

	while (ioread32(GPIO_CLK + ECONET_GPIO_CMCTL) & 0x80); // Wait for not busy

	// Select speed

	iowrite32(ECONET_GPIO_CLOCKSOURCEPLLD, GPIO_CLK + ECONET_GPIO_CMCTL); // Select PLLD

	barrier();
	
	iowrite32(econet_data->clockdiv, GPIO_CLK + ECONET_GPIO_CMCTL + 1);

	barrier();

	iowrite32(ECONET_GPIO_CLOCKENABLE, GPIO_CLK + ECONET_GPIO_CMCTL); // Turn the clock back on

	barrier();


	// Set up access to PWM control so we can put a network clock waveform out on pin 18 if someone wants us to

	request_region(PWM_PERI_BASE, GPIO_PWM_RANGE, DEVICE_NAME);

	GPIO_PWM = ioremap(PWM_PERI_BASE, GPIO_PWM_RANGE);

	if (GPIO_PWM)
	{
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "econet-gpio: PWM base remapped to %p\n", GPIO_PWM);
#endif
	}
	else
	{
		printk (KERN_INFO "econet-gpio: PWM base remap failed.\n");
		return 0;
	}
	
	if (econet_data->hwver >= 2) // Attempt to initialize PWM clock on /CSRETURN (unused on v2 and above)
	{
		
		uint32_t	clockdiv;

		// Ask for ALT5 function (PWM0) on pin 18

		t = (ioread32(GPIO_PORT + (ECONET_GPIO_PIN_NET_CLOCK / 10)) & ~(0x07 << (3 * (ECONET_GPIO_PIN_NET_CLOCK % 10)))) | (0x02 << (3 * (ECONET_GPIO_PIN_NET_CLOCK % 10))); // 0x02 is the sequence for ALT 5.
		iowrite32 (t, GPIO_PORT + (ECONET_GPIO_PIN_NET_CLOCK / 10)); /* Select alt function for clock output pin */

		// Put a default 5us period with 1us mark out but set it up on a 4MHz clock so that we can do quarter point marks

		while (ioread32(GPIO_CLK + ECONET_GPIO_PWM_CLKCTL) & 0x80) // Wait for not busy
		{
			iowrite32 ((ioread32(GPIO_CLK + ECONET_GPIO_PWM_CLKCTL) & ~0xF0) | ECONET_GPIO_CLOCKDISABLE, GPIO_CLK + ECONET_GPIO_PWM_CLKCTL); // Disable clock
			barrier();
		}

		// Select clock - PLLD
	
		iowrite32(ECONET_GPIO_CLOCKSOURCEPLLD, GPIO_CLK + ECONET_GPIO_PWM_CLKCTL); // Select PLLD
	
		barrier();
		
		// Note, we run the PWM clock at 4MHz so that we can get quarter-us divisions for
		// Period and Mark.

		if ((of_machine_is_compatible("raspberrypi,4-model-b"))|| (of_machine_is_compatible("raspberrypi,400"))) // Bigger divider because PLLD is 750MHz
			clockdiv = (ECONET_GPIO_CLOCKPASSWD | (187 << 12) | 512); // 750 / 187.5 = 4
		else
			clockdiv = (ECONET_GPIO_CLOCKPASSWD | (125 << 12));
			
		iowrite32(clockdiv, GPIO_CLK + ECONET_GPIO_PWM_CLKDIV);

		barrier();

		iowrite32(ECONET_GPIO_CLOCKENABLE, GPIO_CLK + ECONET_GPIO_PWM_CLKCTL); // Turn the clock back on
	
		barrier();
	
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "econet-gpio: Contents of PWMCTL = %lX, PWMRNG = %lX, PWMDAT = %lX\n", *(GPIO_PWM + PWM_CTL), *(GPIO_PWM + PWM_RNG1), *(GPIO_PWM + PWM_DAT1));
#endif

		// period 20 = 5us and mark 4 = 1us - Default clock setting. Change via ioctl from userspace

		econet_set_pwm(20, 4); 

	}

#ifdef ECONET_GPIO_DEBUG_IRQ
	printk (KERN_INFO "econet-gpio: GPREN0(%d) = %s, GPFEN0(%d) = %s, GPHEN0(%d) = %s, GPLEN0(%d) = %s\n",
		ECONET_GPIO_PIN_IRQ,
		(ioread32(GPIO_PORT + GPREN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset",
		ECONET_GPIO_PIN_IRQ,
		(ioread32(GPIO_PORT + GPFEN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset",
		ECONET_GPIO_PIN_IRQ,
		(ioread32(GPIO_PORT + GPHEN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset",
		ECONET_GPIO_PIN_IRQ,
		(ioread32(GPIO_PORT + GPLEN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset");
#endif

	return 1;
}

#endif 
#endif /* ECONET_GPIO_NEW - if defined, econet_probe_adapter() and econet_gpio_init() are redundant */


/*
 * econet_adlc_cleardown()
 *
 * Does a full ADLC reset and re-sets up the registers.
 *
 */

void econet_adlc_cleardown(unsigned short in_irq)
{

	if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: Performing ADLC chip reset\n");

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

	/* Set the last write timer so we know what turns up first is new */

	econet_data->aun_last_writefd = 0;

	if (!in_irq)
		econet_irq_mode(1);

}

/* Chip reset function - Leaves us in test mode with IRQs off */

void econet_reset(void)
{

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "econet-gpio: econet_reset() called\n");
#endif

	/* Clear the kernel FIFOs */

	kfifo_reset(&econet_rx_queue);
	kfifo_reset(&econet_tx_queue);

	/* initialize writefd mutex */
	
	mutex_init (&econet_writefd_mutex);

	/* Make sure packet buffer appears to be empty */

	econet_pkt_rx.length = 0;
	econet_pkt_tx.length = 0;

	/* Turn IRQs off */

	econet_irq_mode(0);

	/* Clear station map */

	ECONET_INIT_STATIONS(econet_stations);

	econet_adlc_cleardown(0); // 0 = not in IRQ context

	init_waitqueue_head(&econet_data->econet_read_queue);

	/* Take us out of AUN mode and set the chip to read */

	econet_data->aun_mode = 0;
	econet_data->aun_last_tx = econet_data->aun_last_rx = 0;

	econet_set_read_mode(); // Required in addition to the cleadown, because this sets the ADLC up to read, where as cleardown doesn't.

	printk (KERN_INFO "econet-gpio: Module reset. AUN mode off. ADLC re-initialized.\n");

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

	/* Blank the packet buffers */

	econet_pkt_rx.length = econet_pkt_rx.ptr = 0;

	econet_write_cr(ECONET_GPIO_CR2, C2_READ);
	econet_write_cr(ECONET_GPIO_CR1, C1_READ);

	econet_set_chipstate(EM_IDLEINIT); 

	last_data_rcvd = 0; // Last time we received data off the wire. Detect stuck in read mode when we want to write

}


/*
 * econet_set_write_mode()
 *
 * Sets the ADLC up ready to write a fresh packet.
 *
 * Detects if transmission in progress and bounces the request.
 *
 * Otherwise, copies the packet into the tx buffer, resets the
 * various counters etc., and the packet length, 
 * seizes the line if the chip is not already in flag fill mode,
 * enables the transmitter interrupt and that should kick
 * everything off. (It has done so far...)
 *
 * This is only ever called from econet_writefd(), where IRQs are
 * off - except for testing circumstances.
 *
 * Like econet_set_read_mode() this does not tinker with the AUN
 * state machine because it is used *during* 4-way handshakes.
 *
 */

void econet_set_write_mode(struct __econet_pkt_buffer *prepared, int length)
{

	if (econet_pkt_tx.length != 0) // Already in progress
	{
		if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: Flag busy because length != 0\n");
		econet_set_tx_status(ECONET_TX_BUSY);
		return;
	}

	// Set the packet up
	
	memcpy(&econet_pkt_tx, prepared, length);

	econet_pkt_tx.length = length;
	econet_pkt_tx.ptr = 0;

	/*
	 * If not in flagfill, seize line.
	 *
	 */

	if (!(econet_get_chipstate() == EM_FLAGFILL))
	{
		uint8_t count, outercount, seized = 0;

		outercount = 0;

		while (outercount++ < 1 && !seized)
		{
			// Attempt to seize line
			econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT1);
			sr2 = econet_read_sr(2);

			if (sr2 & ECONET_GPIO_S2_DCD) // No clock
			{
				econet_set_tx_status(ECONET_TX_NOCLOCK);
				econet_set_read_mode();
			}
			else
			{
				count = 0;

				while (count++ < 5 && (!(sr2 & ECONET_GPIO_S2_RX_IDLE))) // Was 25!
				{
					econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT1);
					udelay(count << 2); // Possibly alter this to put a minimum 20us delay - less aggressive (i.e. as if count is always at least 5, and then back off. Or possibly just start count at 5 and stop at 30...?)
					sr2 = econet_read_sr(2);
				}

				// Is line idle?
				
				if (sr2 & ECONET_GPIO_S2_RX_IDLE)
				{
					econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2); // +RTS
					econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2); // TIE + RX Reset
					econet_set_chipstate(EM_WRITE);
					econet_set_tx_status(ECONET_TX_INPROGRESS);
					sr1 = econet_read_sr(1);
					if (!(sr1 & ECONET_GPIO_S1_CTS)) // Should be low if successful, so this indicates OK
						seized = 1;
				}
			}
		}	


		if (!seized) // Jammed - give up
		{
			econet_set_tx_status(ECONET_TX_JAMMED);
			econet_set_read_mode();
		}

	}
	else
	{
		// We are already in flagfill
		econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2); // TIE + RX Reset
		econet_set_chipstate(EM_WRITE);
		econet_set_tx_status(ECONET_TX_INPROGRESS);
	}

}


/* 
 * econet_flagfill()
 *
 * Put the ADLC into flag fill mode.
 *
 */

void econet_flagfill(void)
{

#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "econet-gpio: Flag Fill enabled\n");
#endif
	econet_write_cr(ECONET_GPIO_CR1, ECONET_GPIO_C1_RX_DISC | ECONET_GPIO_C1_RX_RESET);
	econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_INIT2);
	econet_set_chipstate(EM_FLAGFILL);

}

/*
 *
 * ECONET GPIO IRQ HANDLING CODE
 * Get the bytes off the wire, put the bytes on the wire, etc.
 *
 *
 */


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
	printk (KERN_INFO "econet-gpio: econet_finish_tx(): Finished packet TX\n");
#endif

	/* 
	 * Tell the 68B54 we've finished so it can end the frame 
	 * 
	 */

	econet_set_chipstate(EM_WRITE_WAIT);

	econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_TXLAST | ECONET_GPIO_C2_FC | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_PSE); // No RX status reset

#ifdef ECONET_GPIO_DEBUG_TX
	econet_get_sr();
	printk (KERN_INFO "econet-gpio: econet_finish_tx(): SR after C2_WRITE_EOF: SR1 = 0x%02x, SR2 = 0x%02x\n", sr1, sr2);
#endif

}


/* 
 * econet_aun_setidle_txstatus()
 * 
 * Puts the AUN state back to IDLE, sets the TX status, clears the TX length and goes back to read mode.
 *
 */

static inline void econet_aun_setidle_txstatus(int txstate)
{
	econet_pkt_tx.length = 0;
	econet_set_tx_status(txstate);
	econet_set_aunstate(EA_IDLE);
	econet_set_read_mode();
}


/* econet_irq_write()
 *
 * Routine called by main IRQ handler when it has been established that we are in write mode so that
 * we need to put another byte of data in the FIFO from our queued packet
 *
 */

void econet_irq_write(void)
{
	/* This will have occurred if we are in write mode, and we will already have done the preliminary
	   TX set up - see econet_set_write_mode() */

	char tdra_flag;
	int loopcount = 0;

	// Added 25.07.21 - Mark transmission even if not successful otherwise the reset timer gets stuck
	
	econet_data->aun_last_tx = ktime_get_ns(); // Used to check if we have fallen out of bed on receiving a packet

	/* Check for clock */

	if (sr2 & ECONET_GPIO_S2_DCD) // No clock. /* This shouldn't happen at this stage - consider removal - once we get going on a Tx, we can fairly assume the clock will stay around... */
	{
		//econet_pkt_tx.length = 0;
		//econet_set_tx_status(ECONET_TX_NOCLOCK);
		//econet_set_aunstate(EA_IDLE);
		//econet_set_read_mode();
		econet_aun_setidle_txstatus(ECONET_TX_NOCLOCK);
		return;

	}

	/* Check for someone sending a duff runt packet and ditch it */
	 
	if (econet_pkt_tx.length < 4) // Runt
	{
		printk(KERN_INFO "econet-gpio: Attempt to transmit runt frame (len = %d). Not bothering.\n", econet_pkt_tx.length);
		//econet_pkt_tx.length = 0; // Abandon
		//econet_set_tx_status(ECONET_TX_NOTSTART);
		econet_aun_setidle_txstatus(ECONET_TX_NOTSTART);
	} /* else if we are still within the packet, put a byte on the FIFO */	
	else if (econet_pkt_tx.ptr <= econet_pkt_tx.length)
	{
		// Something to transmit

		int byte_counter;
		int tdra_counter;

		byte_counter = 0;

		econet_set_tx_status(ECONET_TX_INPROGRESS);


		/* The byte_counter loop is here for when we finally get round to
		 * implementing 2-byte-per-IRQ reads and writes.
		 *
		 */

		while (byte_counter < 1)
		{

			// Check TDRA available.
	
			loopcount++;

			if (sr1 & ECONET_GPIO_S1_UNDERRUN) // Underrun
			{
				printk (KERN_INFO "econet-gpio: econet_irq_write(): TX Underrun at byte %02x - abort transmission\n", econet_pkt_tx.ptr);

				econet_aun_setidle_txstatus(ECONET_TX_UNDERRUN);

				/* These commented out lines are left here - TODO - 
				 * these may be sensible things to do - 
				 * wonder why they were commented out? 
				 *
				 * Could well be because econet_aun_setidle_txstatus() does
				 * that job now.
				 *
				 */

				//econet_pkt_tx.length = 0;
				//econet_set_tx_status(ECONET_TX_UNDERRUN);
				//econet_set_aunstate(EA_IDLE);
				//econet_set_read_mode();

				return;
			}

			/* Find out if the TDRA (transmit FIFO) is available. */

			tdra_flag = (sr1  & ECONET_GPIO_S1_TDRA);

#ifdef ECONET_GPIO_DEBUG_TX
			printk (KERN_INFO "econet-gpio: econet_irq_write(): Loop % 2d - TDRA FLAG IS %s. SR1 = 0x%02x, SR2 = 0x%02x\n", loopcount, (sr1 & ECONET_GPIO_S1_TDRA) ? "SET" : "UNSET", sr1, (sr2 = econet_read_sr(2)));

#endif 
			tdra_counter = 0;

			/*
			 * Try up to 5 times to seize the line. Clear down each time in case that helps. 
			 *
			 */

			while (tdra_counter++ < 5 && (!tdra_flag)) // Clear down and see if it becomes available
			{
				// Next line reinstated 20211024 to see if it helps

				econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
					ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);

				udelay(10); // Shorter delay - 20240325 was 20us

				tdra_flag = ((sr1 = econet_read_sr(1)) & ECONET_GPIO_S1_TDRA); // Only read SR1. (get_sr now always reads both, but we aren't fussed about sr2 here)
			}

			/* 
			 * If we still don't have TX FIFO available, 
			 * look for collision and otherwise decide something was just plain wrong. 
			 *
			 * The call to econet_aun_setidle_txstatus() also puts us back to the idle state.
			 *
			 */

			if (!tdra_flag)
			{
				// ANFS 4.25 checks TDRA on IRQ. If not available, it clears RX & TX status and waits for another IRQ

				// Sub-clauses read sr2 beacuse we changed from econet_get_sr() in the loop above, so the sr2 value may be out of date by now.

				if (sr1 & ECONET_GPIO_S1_CTS) // Collision?
				{
					if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: econet_irq_write(): /CTS - Collision? TDRA unavailable on IRQ - SR1 - 0x%02X, SR2 = 0x%02X, ptr = %d, loopcount = %d - abort tx\n", sr1, (sr2 = econet_read_sr(2)), econet_pkt_tx.ptr, loopcount);
					econet_aun_setidle_txstatus(ECONET_TX_COLLISION);
				}
				else	
				{
					if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: econet_irq_write(): TDRA not available on IRQ - SR1 = 0x%02x, SR2 = 0x%02x, ptr = %d, loopcount = %d - abort transmission\n", sr1, (sr2 = econet_read_sr(2)), econet_pkt_tx.ptr, loopcount);
					econet_aun_setidle_txstatus(ECONET_TX_TDRAFULL);
				}

				return;
			}

			/* So by here, the TDRA is available, so we'll put some data in it */

#ifdef ECONET_GPIO_DEBUG_TX
			{
				char c;
				c = econet_pkt_tx.d.data[econet_pkt_tx.ptr];
				printk (KERN_INFO "econet-gpio: econet_irq_write(): TX byte % 4d - %02x %c\n", econet_pkt_tx.ptr, (int) c, ((c > 32) && (c < 127)) ? c : '.');
			}
#endif 

			econet_write_fifo(econet_pkt_tx.d.data[econet_pkt_tx.ptr++]);

			/*
			 * Was that the last byte of our packet? 
			 *
			 * If it was, call econet_finish_tx() which writes to the CR
			 * and flags end of packet. Then reset length to 0 so we know
			 * there is no valid packet in the buffer.
			 *
			 */

			if (econet_pkt_tx.ptr == econet_pkt_tx.length)
			{
				econet_finish_tx();
				econet_pkt_tx.length = 0;
				return;
			}
			else
			{

				/* As at 20240325, it was thought this was unnecessary because
				 * TDRA availability flag is self-resetting. Not doing this appears
				 * to have had no impact on performance at all.
				 *
				 * The top version also resets RX status, which appears to be wholly
				 * unnecessary either way.
				 *
				 */

				/* RX & TX Reset version
				econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
					ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);
				*/
				
				/* TX-only reset version
				econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_TX_STATUS |
					ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE); 
				*/
			}

			byte_counter++;

		}
		
	}

	return;

}


/* 
 * econet_process_rx(byte off fifo)
 *
 * Does nothing more than stick the byte we got off the fifo into our reception buffer.
 *
 * If we are about to overrun the receive buffer, stop it. 
 *
 * Update last data received time - used to detect blockages!
 *
 */

static inline void econet_process_rx(unsigned char d)
{

	econet_pkt_rx.d.data[econet_pkt_rx.ptr++] = d;

	if (econet_pkt_rx.ptr == ECONET_MAX_PACKET_SIZE) econet_pkt_rx.ptr--; // We shouldn't be over the limit!

	last_data_rcvd = ktime_get_ns();

}


/* 
 * econet_irq_read() 
 *
 * Called by the main IRQ handler when it thinks there is some data to read off the FIFO
 *
 */

void econet_irq_read(void)
{

	unsigned char d;
	unsigned short old_ptr;

//recv_more:


	old_ptr = econet_pkt_rx.ptr;

#ifdef ECONET_GPIO_DEBUG_RX
	printk (KERN_INFO "econet-gpio: econet_irq_read(): SR1 = %02x, SR2 = %02x, ptr = %d, c = %02x %c\n", sr1, sr2, econet_pkt_rx.ptr, d, (d < 32 || d >126) ? '.' : d);
#endif

	/* 
	 * Update our byte receive timer 
	 * so as to detect a fresh packet starting
	 * when we think we are in the middle of
	 * an old one.
	 *
	 */

	last_data_rcvd = ktime_get_ns();

	// Check for errors first, because we were getting RX ABort + Frame Valid at same time!

	/* 
	 * First check sr2 for errors.
	 *
	 */

	if (sr2 & (ECONET_GPIO_S2_RX_ABORT | ECONET_GPIO_S2_OVERRUN | ECONET_GPIO_S2_ERR)) 
	{
		if (sr2 & ECONET_GPIO_S2_RX_ABORT) // Abort flag set
			printk (KERN_INFO "econet-gpio: econet_irq_read(): RX Abort received at ptr = 0x%02x (SR1 = 0x%02X, SR1 = 0x%02X)\n", econet_pkt_rx.ptr, sr1, sr2);
		else if (sr2 & ECONET_GPIO_S2_OVERRUN) // Receiver overrun
			printk (KERN_INFO "econet-gpio: econet_irq_read(): RX Overrun at ptr = 0x%02x (SR1 = 0x%02X, SR2 = 0x%02X)\n", econet_pkt_rx.ptr, sr1, sr2);
		else if (sr2 & ECONET_GPIO_S2_ERR) // Checksum error
			printk (KERN_INFO "econet-gpio: CRC Error (SR1 = 0x%02X, SR2 = 0x%02X)\n", sr1, sr2);

		/* 
		 * If CRC error, that suggests something is badly wrong. 
		 * Try a cleardown. I suspect we are writing to CRs in both
		 * writefd and IRQ routine at the same time, though how I have
		 * no idea.
		 *
		 */

		if (sr2 & ECONET_GPIO_S2_ERR)
			econet_adlc_cleardown(1);

		/*
		 * In all cases, discontinue reception.
		 *
		 */

		econet_discontinue();


	}
	else if (sr2 & ECONET_GPIO_S2_VALID) // Frame valid received - i.e. end of frame received
	{

		/* 
		 * Read the byte off the FIFO
		 *
		 */

		d = econet_read_fifo(); 

		/* Send it into the packet buffer */

		econet_process_rx(d); // Process the (final) incoming byte

		/* Detect runts - Every packet will have at least 4 bytes (net.stn for each of src & dst) */

		if (econet_pkt_rx.ptr < 4) // Runt
		{
			printk (KERN_INFO "econet-gpio: Runt received (len %d) - jettisoning\n", econet_pkt_rx.ptr);
			econet_set_aunstate(EA_IDLE); // No harm even if not in AUN mode
			econet_set_read_mode();
			return;
		}

		/* 
		 * If the kfifo to userspace is full, 
		 * take something out of it and throw it away.
		 *
		 */

		if (kfifo_is_full(&econet_rx_queue))
		{
			int a;
			a = kfifo_out(&econet_rx_queue, &dump_pkt, sizeof(dump_pkt));
		}

		/*
		 * If in RAW (i.e. non-AUN) mode, put the
		 * received packet straight on the kernel fifo.
		 *
		 */

		if (!(econet_data->aun_mode)) 
		{

			/* ADLC back to read mode */

			econet_write_cr(ECONET_GPIO_CR2, C2_READ);

			/* Packet onto kfifo to userspace */

			kfifo_in(&econet_rx_queue, &(econet_pkt_rx.d.data), econet_pkt_rx.ptr); 

			/* Wake up poller */

			wake_up(&(econet_data->econet_read_queue)); 

#ifdef ECONET_GPIO_DEBUG_RX
			printk (KERN_INFO "econet-gpio: econet_irq_read(): Valid frame received, length %04x, %04x bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif

			/* Flag the ADLC as idle */

			econet_set_chipstate(EM_IDLE);
		}
		else /* We are in AUN mode - do much more complicated things. */
		{

			/* 
			 * First, work out if the received packet is one the userspace
			 * code wants to know about.
			 *
			 */


			if (ECONET_DEV_STATION(econet_stations, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn))
			{

				unsigned short aun_state;

				econet_pkt_rx.length = econet_pkt_rx.ptr;

				// If our last transmission was more than 0.8s ago, go back to EA_IDLE
				
				/* 
				 * If last tx was more than the timeout value, go back to read mode
				 * and dump any pending tx frame first.
				 *
				 * Allow twice the timeout if we are waiting to read an immediate reply, because
				 * some of those can be 20k+ and might take a while (e.g. a MODE 0 screen
				 * copy for *VIEW coming from a distant network over a bridge).
				 *
				 */

				if (
					(	((ktime_get_ns() - econet_data->aun_last_tx) > (2 * ECONET_4WAY_TIMEOUT)) &&
						(econet_get_aunstate() == EA_I_READREPLY)
					) 	||
					(
						((ktime_get_ns() - econet_data->aun_last_tx) > ECONET_4WAY_TIMEOUT) && 
						(econet_get_aunstate() != EA_IDLE)
					)
				) 
				{

					printk (KERN_INFO "econet-gpio: Last TX was too long ago. Moving back to AUN IDLE state. Packet from %d.%d to %d.%d, length 0x%04X\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn, econet_pkt_rx.length);

					econet_set_aunstate(EA_IDLE);
					econet_pkt_tx.length = 0; // Blank off any TX packet here
					econet_set_tx_status(ECONET_TX_SUCCESS);
				}

				// Set up the bones of a reply just in case

				econet_pkt_tx.d.p.dststn = econet_pkt_rx.d.p.srcstn;
				econet_pkt_tx.d.p.dstnet = econet_pkt_rx.d.p.srcnet;
				econet_pkt_tx.d.p.srcstn = econet_pkt_rx.d.p.dststn;
				econet_pkt_tx.d.p.srcnet = econet_pkt_rx.d.p.dstnet;

#ifdef ECONET_GPIO_DEBUG_AUN
				//printk (KERN_INFO "econet-gpio: AUN debug - packet from %d.%d, length = 0x%08x, Port %02x, Ctrl %02x\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.length, econet_pkt_rx.d.p.port, econet_pkt_rx.d.p.ctrl);
#endif
				/*
				 * Figure out what to do with the packet we've received
				 * by reference to the AUN state we are in.
				 *
				 */

				aun_state = econet_get_aunstate();

				/* 
				 * Catch a data packet that is so long after the scout that it mustn't be a data packet.
				 *
				 * If we are beyond the timeout, pretend we are in AUN idle state and are therefore 
				 * expecting a Scout.
				 *
				 */

				if ((econet_data->aun_mode) && (aun_state == EA_R_READDATA) && ((ktime_get_ns() - econet_data->aun_last_rx) > ECONET_AUN_DATA_TIMEOUT))
				{
							printk (KERN_ERR "econet-gpio: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting data packet from %d.%d and this was so late it couldn't be one\n", econet_pkt_rx.length, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn);
							econet_set_aunstate(EA_IDLE);
				}

				/* 
				 * Update our AUN reception timer.
				 *
				 */

				econet_data->aun_last_rx = ktime_get_ns();

				/* 
				 * Do work based on AUN state, as updated above if it has been.
				 *
				 */

				switch (aun_state)
				{

					/*
					 * EA_IDLE - we are expecting a new sequence of an exchange
					 *
					 */

					case EA_IDLE: // First in a sequence - see what it i
					{
unexpected_scout:
						// Is it an immediate?
						
						if (
								econet_pkt_rx.d.p.port == 0 /* Port 0 */
							&&	!(econet_pkt_rx.d.p.ctrl >= 0x82 && econet_pkt_rx.d.p.ctrl <= 0x85) /* port 0 ctrl 0x82 <= ctrl <= 0x85 are in fact done as special 4-way transactions with extra data on the 'scout' */
						   ) 
						{
#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "econet-gpio: Immediate received from %d.%d, Ctrl 0x%02x\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.ctrl);
#endif

							/* Copy Addressing, port & ctrl byte */

							aun_rx.d.p.srcstn = econet_pkt_rx.d.p.srcstn;
							aun_rx.d.p.srcnet = econet_pkt_rx.d.p.srcnet;
							aun_rx.d.p.dststn = econet_pkt_rx.d.p.dststn;
							aun_rx.d.p.dstnet = econet_pkt_rx.d.p.dstnet;
							aun_rx.d.p.port = econet_pkt_rx.d.p.port;
							aun_rx.d.p.ctrl = econet_pkt_rx.d.p.ctrl; // We don't strip the high bit for the bridge code. It can do it itself
							aun_rx.d.p.aun_ttype = ECONET_AUN_IMM;

							aun_rx.d.p.seq = (econet_data->aun_seq += 4);

							aun_rx.d.p.padding = 0x00;

							/* If there was extra data in the packet, put that into the aun version too. */

							if (econet_pkt_rx.length > 6)
								memcpy (&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), econet_pkt_rx.length - 6);

							aun_rx.length = econet_pkt_rx.length + 6; // AUN packets have 12 bytes before the data, econet packets have 6 (on a broadcast or immediate, anyway).
			
							/* Put the packet on the FIFO */

							kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
							wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "econet-gpio: econet_irq_read(): Valid frame received, length %04x, %04x AUN bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif
							/* Cleardown the RX, and go into flagfill pending us getting a reply from somewhere that we can transmit */

							econet_rx_cleardown();
							econet_flagfill();

							/* Flag AUN state as IDLE so that the reply can go out */

							econet_set_aunstate(EA_IDLE); // Wait and see what turns up next - probably an immediate reply

							/* Flag chip state as Flagfill so that we know we do not need to seize the line */

							econet_set_chipstate(EM_FLAGFILL);
						}

						/* Handle broadcasts - this works the same as immediate handling above, but doesn't go into flag fill */

						else if ((econet_pkt_rx.d.p.dststn == 0xff) && (econet_pkt_rx.d.p.dstnet == 0xff)) // Broadcast - dump to userspace
						{
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
				
							kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
							wake_up(&(econet_data->econet_read_queue)); // Wake up the poller

#ifdef ECONET_GPIO_DEBUG_RX
							printk (KERN_INFO "econet-gpio: econet_irq_read(): Valid frame received, length %04x, %04x AUN bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif

							econet_rx_cleardown();
							econet_set_chipstate(EM_IDLE);
						}

						/* Neither immediate nor broadcast, so it should be some sort of scout since we are idle */

						else 
						{

							/* 
							 * If length is not 6 (4 address bytes, port and ctrl) 
							 * *and* it isn't a special immediate, then dump it 
							 * because it's obviously out of sequence.
							 */ 

							if (econet_pkt_rx.ptr != 6 && !(econet_pkt_rx.d.p.port == 0 && (econet_pkt_rx.d.p.ctrl >= 0x82 && econet_pkt_rx.d.p.ctrl <= 0x85))) // Immediate ctrl 0x85 packets are done as 4-way handshakes, BUT there are 4 data bytes on the opening scout
							{
								econet_set_aunstate(EA_IDLE);
								printk (KERN_ERR "econet-gpio: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting Scout and this wasn't\n", econet_pkt_rx.ptr);
								econet_rx_cleardown();
								econet_set_chipstate(EM_IDLE);
							}
							
							/* 
							 * Looks like a potentially valid scout then
							 * Send an ACK and wait for the data by moving to EA_R_WRITEFIRSTACK
							 */
							else
							{
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "econet-gpio: econet_irq_read(): AUN: Scout received from %d.%d with port %02x, ctrl %02x. Acknowledging.\n", 
									econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.port, econet_pkt_rx.d.p.ctrl);
#endif

								// Set up our AUN RX block
								aun_rx.d.p.srcstn = econet_pkt_rx.d.p.srcstn;
								aun_rx.d.p.srcnet = econet_pkt_rx.d.p.srcnet;
								aun_rx.d.p.dststn = econet_pkt_rx.d.p.dststn;
								aun_rx.d.p.dstnet = econet_pkt_rx.d.p.dstnet;
								aun_rx.d.p.port = econet_pkt_rx.d.p.port;
								aun_rx.d.p.ctrl = econet_pkt_rx.d.p.ctrl;

								/*
								 * Immediate poke (Port &00, Ctrl &82) - has 8 data bytes 
								 * on the scout - move them to the AUN RX buffer
								 */

								if (aun_rx.d.p.port == 0 && aun_rx.d.p.ctrl == 0x82) 
									memcpy(&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), 8);

								/* 
								 * Other special 4-way immediates - these have
								 * 4 bytes on the scout, so move those to the AUN RX 
								 * buffer.
								 *
								 * &83 - HSR
								 * &84 - USRPROC
								 * &85 - OSPROC
								 *
								 */

								if (aun_rx.d.p.port == 0 && (aun_rx.d.p.ctrl >= 0x83 && aun_rx.d.p.ctrl <= 0x85))
									memcpy(&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), 4);

								/* Set up the ACK to send */

								econet_pkt_tx.ptr = 0;
								econet_pkt_tx.length = 4;
	
								/* Move state */

								econet_set_aunstate(EA_R_WRITEFIRSTACK);
	
								/* Flag fill so we are "listening" */

								econet_flagfill();

								/* Start write mode */

								econet_set_chipstate(EM_WRITE);
								econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
							}
						}

					}
				
					break;
						
					/* CLEANED UP TO HERE */

					case EA_W_READFIRSTACK: // This should be an ack to the Scout we have written.
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

							printk (KERN_ERR "econet-gpio: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting first ACK from %d.%d - got packet from %d.%d to %d.%d %02x %02x %02x %02x\n", econet_pkt_rx.ptr, aun_tx.d.p.dstnet, aun_tx.d.p.dststn, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn, econet_pkt_rx.d.p.data[0], econet_pkt_rx.d.p.data[1], econet_pkt_rx.d.p.data[2], econet_pkt_rx.d.p.data[3]);
	
							econet_set_aunstate(EA_IDLE);
							econet_rx_cleardown();
							econet_set_chipstate(EM_IDLE);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
						}
						else // It was an ACK from where we expected, so line up the data packet	
						{
							econet_flagfill();
							if (aun_tx.d.p.port != 0x00 || !(aun_tx.d.p.ctrl >= 0x82 && aun_tx.d.p.ctrl <= 0x85)) // Not one of those 0x85 immediate specials that in fact does a 4-way handshake
							{
								memcpy (&(econet_pkt_tx.d.p.ctrl), &(aun_tx.d.p.data), aun_tx.length-12); // Strip off the header - note, ctrl byte is first on the econet wire, and is where the data portion of a data packet starts
								econet_pkt_tx.length = 4 + (aun_tx.length - 12); // Data starts at byte 4 in a data packet to econet
							} 
							else // Else it WAS one of those funky i4-way immediates Immediate 0x85 specials which had 4 data bytes on the "Scout", so we only copy n-4 data bytes into the data packet
							{

								if (aun_tx.d.p.ctrl >= 0x83 && aun_tx.d.p.ctrl <= 0x85) // JSR or OSPROC, or USRPROC
								{
									memcpy (&(econet_pkt_tx.d.p.ctrl), &(aun_tx.d.p.data[4]), aun_tx.length-16); // Strip off the header - note, ctrl byte is first on the econet wire, and is where the data portion of a data packet starts
									econet_pkt_tx.length = 4 + (aun_tx.length - 16); // Data starts at byte 4 in a data packet to econet
								}
								else if (aun_tx.d.p.ctrl == 0x82) // POKE	
								{
									memcpy (&(econet_pkt_tx.d.p.ctrl), &(aun_tx.d.p.data[8]), aun_tx.length-24); // Strip off the header - note, ctrl byte is first on the econet wire, and is where the data portion of a data packet starts
									econet_pkt_tx.length = 4 + (aun_tx.length - 24); // Data starts at byte 8 in a data packet to econet
								}


							}

							econet_pkt_tx.ptr = 0;
							econet_set_aunstate(EA_W_WRITEDATA);
							econet_set_tx_status(ECONET_TX_DATAPROGRESS); // Flags to userspace that we received an Ack to our scout - so the userspace code will put the packet back on the queue for TX if it times out on transmission

							econet_set_chipstate(EM_WRITE);
							econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "econet-gpio: econet_irq_read(): AUN: Scout ACK received - sending data packet to %d.%d, after scout with port %02x, ctrl %02x\n", 
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
							printk (KERN_INFO "econet-gpio: econet_irq_read(): Valid frame received, length %04x, but was expecting final ACK from %d.%d\n", econet_pkt_rx.ptr, aun_tx.d.p.dstnet, aun_tx.d.p.dststn);
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
							econet_set_aunstate(EA_IDLE);
							// 20240630 to see if this fixes the RISC OS No Reply Errors
							goto unexpected_scout;
						}
						else // It was an ACK from where we expected, so flag completion to writefd
						{
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "econet-gpio: econet_irq_read(): AUN: Read final ACK from %d.%d, after scout with port %02x, ctrl %02x. Flag transmit success.\n", 
									econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, aun_tx.d.p.port, aun_tx.d.p.ctrl);
#endif
							econet_set_tx_status(ECONET_TX_SUCCESS);
						}

						// Either way, go back to idle.

						econet_rx_cleardown();
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
							printk (KERN_INFO "econet-gpio: econet_irq_read(): AUN: Data received from %d.%d, length wire %d - Sending final ack.\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn, econet_pkt_rx.ptr);
#endif
							if (aun_rx.d.p.port == 0 && (aun_rx.d.p.ctrl >= 0x83 && aun_rx.d.p.ctrl <= 0x85)) // Immediate 0x85 special four way. There will have been four important bytes on the Quasi-'Scout' which will have been put into the aun_rx data area already, so we copy to byte 5 onward; 0x83 (JSR) works the same way, as does USRPROC 0x84
								memcpy(&(aun_rx.d.p.data[4]), &(econet_pkt_rx.d.data[4]), econet_pkt_rx.ptr - 4);
							else if (aun_rx.d.p.port == 0 && aun_rx.d.p.ctrl == 0x82) // POKE - there are 8 bytes on the scout
								memcpy(&(aun_rx.d.p.data[8]), &(econet_pkt_rx.d.data[4]), econet_pkt_rx.ptr - 4);
							else
								memcpy(&aun_rx.d.p.data, &(econet_pkt_rx.d.data[4]), econet_pkt_rx.ptr - 4); // We copy from the raw data in the rx packet because at [4] is where the reply data actually is, but we copy to the ACTUAL data area in the AUN packet
							aun_rx.d.p.seq = (econet_data->aun_seq += 4);
							aun_rx.d.p.aun_ttype = ECONET_AUN_DATA;
							aun_rx.length = (econet_pkt_rx.ptr - 4 + 12) + 
								(aun_rx.d.p.port != 0 ? 0 :
								 	(aun_rx.d.p.ctrl == 0x82 ? 8 :
									((aun_rx.d.p.ctrl >= 0x83 && aun_rx.d.p.ctrl <= 0x85) ? 4 :
									 0 )));

							econet_flagfill();

							// If we are in 'resilience' mode where we do not
							// send the final ACK until we get an ACK from the distant
							// station over AUN (or spoofed from Pipe/Local/etc.)
							// then at this point we just go into flag fill, move
							// to the relevant state and sit & wait. The user space will
							// need a trigger to go back to read mode if the AUN state
							// machine persists in its 'WAITUSERACK' mode (or whatever
							// I am going to call it), and there can be an ioctl which
							// is called by userspace to move us into EA_R_WRITEFINALACK
							// if userspace detects the relevant ACK turning up.
							// Userspace probably needs to prioritize an ACK reply
							// to the current packet in the same way it does for
							// Immediate replies; and the timeout system can work
							// the same way too.

							// Send Final ACK
						
							econet_pkt_tx.ptr = 0;
							econet_pkt_tx.length = 4;

							if (!(econet_data->resilience))
							{
								econet_set_aunstate(EA_R_WRITEFINALACK);

								econet_set_chipstate(EM_WRITE);
								econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
							}
							else // resilience - stay in flag fill and wait
							{
								// Deliver to userspace
								kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
								wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
								econet_set_aunstate(EA_R_PENDINGFINALACK);
							}
						}
						else // Soemthing went wrong - clear down
						{
							printk (KERN_ERR "econet-gpio: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting data packet from %d.%d and this wasn't\n", econet_pkt_rx.length, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn);
							econet_rx_cleardown();
							econet_set_chipstate(EM_IDLE);
							econet_set_aunstate(EA_IDLE);
						}
					}
					break;
	
					case EA_R_PENDINGFINALACK: // Resilience mode - we shouldn't be getting IRQs in this mode!
					{
						printk (KERN_ERR "econet-gpio: econet_irq_read(): AUN: received IRQ in EA_R_PENDINGFINALACK! sr1=%02X, sr2=%02X\n", sr1, sr2);
					} break;

					case EA_I_READREPLY: // What we've received is a reply to an Immediate - dump to userspace
					{

						// Is it from the right place?
						// In this case, we are expecting a reply from the station held in aun_tx, the immediate packet we sent

						if (	(aun_tx.d.p.srcstn == econet_pkt_rx.d.p.dststn) &&
							(aun_tx.d.p.srcnet == econet_pkt_rx.d.p.dstnet) &&
							(aun_tx.d.p.dststn == econet_pkt_rx.d.p.srcstn) &&
							(aun_tx.d.p.dstnet == econet_pkt_rx.d.p.srcnet)	)
						{
							// Shouldn't be needed given the addresses are copied below // memcpy (&(aun_rx.d.raw), &econet_pkt_rx, 4); // Copy the addressing data over
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
							aun_rx.length = 12 + (econet_pkt_rx.ptr -4);

							kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
							wake_up(&(econet_data->econet_read_queue)); // Wake up the poller

#ifdef ECONET_GPIO_DEBUG_RX
							printk (KERN_INFO "econet-gpio: econet_irq_read(): AUN Immediate reply received from %d.%d - send to userspace, data portion length %d\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn, (econet_pkt_rx.ptr -4));
#endif
						}
			
						econet_rx_cleardown();
						econet_set_chipstate(EM_IDLE);
						econet_set_aunstate(EA_IDLE);
					}
					break;	
				}	
			}

		}
	
		econet_pkt_rx.ptr = 0; // Reset packet receive counter - flags the receive buffer as empty

	}

	/*
	 * SR2 Address present - new frame starting
	 *
	 */

	else if (sr2 & ECONET_GPIO_S2_AP) // New frame
	{
#ifdef ECONET_GPIO_DEBUG_RX
			printk (KERN_INFO "econet-gpio: econet_irq_read(): Address present and no errors. SR1 = 0x%02x\n", sr1);
#endif
			/* Put ourselves in read mode and reset packet counters */

			econet_set_chipstate(EM_READ);
			econet_pkt_rx.length = econet_pkt_rx.ptr = 0;

			/* Read the data off the FIFO & process it */

			d = econet_read_fifo(); 

			econet_process_rx(d);

	}

	/*
	 * SR1 Receiver Data Available - new byte arriving
	 *
	 */

	else if ((sr1 & ECONET_GPIO_S1_RDA))
	{
		/* 
		 * Are we at start of packet?
		 * If so, we shouldn't be here without AP set as well,
		 * which is caught above... so there's a problem.
		 *
		 */

		if (econet_pkt_rx.ptr == 0) // Shouldn't be getting here without AP set (caught above)
		{
			printk (KERN_INFO "econet-gpio: Received first byte of packet without AP flag set. Discontinuing. SR2=0x%02x.\n", sr2);
			econet_discontinue();
		}

		/* Otherwise read & process the data */

		else
		{
			d = econet_read_fifo(); 
			econet_process_rx(d);
		}
	}

	/* 
	 * Detect no clock and discontinue if need be
	 *
	 */

	else if ((sr2 = econet_read_sr(2)) & ECONET_GPIO_S2_DCD) // No clock all of a sudden
	{
		printk (KERN_INFO "econet-gpio: econet_irq_read(): RX No clock\n");
		econet_discontinue();
	}

	/* We shouldn't get here on an read IRQ so discontinue. */

	else
	{
		printk (KERN_INFO "econet-gpio: econet_irq_read(): Unhandled state - SR1 = 0x%02x, SR2 = 0x%02x\n", sr1, sr2);
		econet_discontinue();
	}

	/* 
	 * If we have more than 2 bytes in the RX buffer
	 * then we have destination net & stn. If in AUN mode,
	 * check to see if we are interested in receiving that
	 * traffic, and discontinue if not.
	 *
	 */

	if (econet_data->aun_mode && econet_pkt_rx.ptr > 1)
	{
		if (!ECONET_DEV_STATION(econet_stations, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn)) // Not a station we are interested in
		{
			econet_discontinue();
		}

	}

	return;

}

/*
 * econet_irq()
 *
 * Main IRQ handler for the module.
 *
 */

irqreturn_t econet_irq(int irq, void *ident)
{

	unsigned long 	flags;
	u8		chip_state, aun_state, tx_status;

	/* Prevent re-entry */

	spin_lock_irqsave(&econet_irq_spin, flags);

	/* Read SR1 only, for speed. SR2 read below if need be */

	sr1 = econet_read_sr(1);

	/* 
	 * Pick up our atomics once so we don't waste time
	 * reading them over and over.
	 *
	 */

	chip_state = econet_get_chipstate();

	if (econet_data->aun_mode)
	{
		aun_state = econet_get_aunstate();
		tx_status = econet_get_tx_status();
	}

#ifdef ECONET_GPIO_DEBUG_IRQ
	printk (KERN_INFO "econet-gpio: econet_irq(): IRQ in mode %d, SR1 = 0x%02x, SR2 = 0x%02x. RX len=%d,ptr=%d, TX len=%d,ptr=%d\n", econet_get_chipstate(), sr1, sr2, econet_pkt_rx.length, econet_pkt_rx.ptr, econet_pkt_tx.length, econet_pkt_tx.ptr);
#endif

	/*
	 * Is the ADLC actually flagging an IRQ? 
	 * We shouldn't be here if not, so record an error.
	 * We don't return IRQ_NONE because we should be the
	 * only thing on this IRQ.
	 *
	 */

	if (!(sr1 & ECONET_GPIO_S1_IRQ))
	{
		printk (KERN_INFO "econet-gpio: IRQ handler called but ADLC not flagging an IRQ. SR1=0x%02X, SR2=0x%02X, Chip State %d, AUN State %d\n", sr1, econet_read_sr(2), chip_state, aun_state);

		/* In heavy use, this seems to preclude a meltdown. 
		 * So let's do a cleardown & read mode
		 *
		 * TODO: Work out what these weird states are where we get SR1=0x65 and SR2=0x80 
		 * followed by a meltdown and loads of CRC errors. Suspect we are managing to
		 * read the SRs at the same time as writing them from userspace or some
		 * weird thing like that.
		 *
		 */

		econet_adlc_cleardown(1);
		econet_set_read_mode();
	}

	/*
	 * Are we in test mode? 
	 * We shouldn't get an IRQ if we are, so flag an error
	 * but do nothing.
	 *
	 */

	else if (chip_state == EM_TEST) /* IRQ in Test Mode - ignore */
	{
		printk (KERN_INFO "econet-gpio: IRQ in Test mode - how did that happen?");
	}

	/* 
	 * Detect line idle whilst reading final ACK when we are writing an AUN packet.
	 * Such a state indicates a handshake failure. We don't match on frame valid (FV)
	 * because sometimes you get both in one IRQ, and we treat that as a valid
	 * frame. (That sounds wrong. I'll think about that some more, but that's what
	 * the original comment said...
	 *
	 * Go back to read mode if we get that.
	 *
	 * TODO: Consider whether to set TX state to Net Error here.
	 *
	 */

	else if (((sr2 = econet_read_sr(2)) & ECONET_GPIO_S2_RX_IDLE) && !(sr2 & ECONET_GPIO_S2_VALID) && (econet_data->initialized) && (econet_data->aun_mode) && (aun_state == EA_W_READFINALACK)) 
	{


#ifdef ECONET_GPIO_DEBUG_LINEIDLE
		printk (KERN_INFO "econet-gpio: econet_irq(): Line idle IRQ waiting for final ACK - Handshake failed. aun state = %d, chip state = %d, tx_status = 0x%02x, rx ptr=%02X, sr1=0x%02X, sr2=%02X\n", aun_state, chip_state, tx_status, econet_pkt_rx.ptr, sr1, sr2);	
#endif
		econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
		econet_set_read_mode();
	}

	/* 
	 * Detect line idle without frame valid when either
	 * not in AUN mode or (if we are in AUN) not
	 * waiting for final ACK on a 4-way transmit
	 *
	 */

	else if ((sr2 & ECONET_GPIO_S2_RX_IDLE) && !(sr2 & ECONET_GPIO_S2_VALID) && (econet_data->initialized)) 
	{

#ifdef ECONET_GPIO_DEBUG_LINEIDLE
		if (econet_data->aun_mode && aun_state != EA_IDLE)	
			printk (KERN_INFO "econet-gpio: econet_irq(): Line idle IRQ waiting for reply - Handshake failed. aun state = %d, chip state = %d, tx_status = 0x%02x, rx ptr=%02X, sr1=0x%02X, sr2=%02X\n", aun_state, chip_state, tx_status, econet_pkt_rx.ptr, sr1, sr2);	
		else if ((!econet_data->aun_mode) && (chip_state != EM_TEST && chip_state != EM_IDLE && chip_state != EM_IDLEINIT))
			printk (KERN_INFO "econet-gpio: econet_irq(): Line idle IRQ - chip state = %d\n",  chip_state);
#endif
	
		/* This suggests whatever we were talking to wasn't listening.
		 * (Beecause otherwise it would have flag filled rather than
		 * gone idle.)
		 *
		 * Set status accordingly. Dump all tx and rx packets.
		 * Go back to read mode.
		 *
		 */

		econet_pkt_rx.length = econet_pkt_rx.ptr = econet_pkt_tx.length = econet_pkt_tx.ptr = 0;

		if (econet_data->aun_mode)
		{

			if (aun_state != EA_IDLE)
			{

				switch (aun_state)
				{
					case EA_W_WRITEBCAST:
						//econet_set_tx_status(ECONET_TX_NOTSTART);
						econet_aun_setidle_txstatus(ECONET_TX_NOTSTART);
						break;
					case EA_W_READFIRSTACK:
					case EA_I_READREPLY:
						econet_aun_setidle_txstatus(ECONET_TX_NECOUTEZPAS);
						break;
					case EA_R_READDATA:
					case EA_R_WRITEFIRSTACK:
					case EA_R_WRITEFINALACK:
					case EA_W_READFINALACK:
						econet_aun_setidle_txstatus(ECONET_TX_HANDSHAKEFAIL);
						break;

				}

				//econet_set_aunstate(EA_IDLE);

			}
			else
				econet_set_read_mode();

		}
		else
			econet_set_read_mode();
	}

	/* 
	 * Are we in the middle of writing a frame to the wire?
	 * If so, stick the next byte in the FIFO.
	 *
	 */

	else if (chip_state == EM_WRITE) /* Write mode - see what there is to do */
		econet_irq_write();

	/* 
	 * Are we at end of transmitting a frame and waiting for frame complete (FC)
	 * before returning to read mode? That's the EM_WRITE_WAIT state.
	 *
	 * If we've had an IRQ, we can move AUN state
	 *
	 */

	else if (chip_state == EM_WRITE_WAIT) /* IRQ on completion of frame */
	{
		if (econet_data->aun_mode) // What state are we in - do we need to move state?
		{

			/* Note time of packet reception to tell if we got stuck in a 4-way earlier on */

			econet_data->aun_last_tx = ktime_get_ns(); // Used to check if we have fallen out of bed on receiving a packet

			switch (aun_state)
			{
				// First, the states when we are writing a data packet from userspace
				case EA_W_WRITESCOUT: // We've just written the Scout successfully
				{
					econet_set_aunstate(EA_W_READFIRSTACK);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Written Scout to %d.%d, waiting for first ACK\n", aun_tx.d.p.dstnet, aun_tx.d.p.dststn);
#endif
					break;
				}
				case EA_W_WRITEDATA: // We've just written the data packet
				{
					econet_set_aunstate(EA_W_READFINALACK);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Written data, waiting for final ACK\n");
#endif
					break;
				}	
				case EA_W_WRITEBCAST: // We've successfully put a broadcast on the wire
				{
					econet_set_aunstate(EA_IDLE);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Written broadcast, signalling packet complete\n");
#endif
					econet_set_tx_status(ECONET_TX_SUCCESS);
					break;
				}

				// Now, the states when we are mid read of a 4-way handshake from the wire

				case EA_R_WRITEFIRSTACK: // Just written first ACK - wait for data packet
				{
#ifdef ECONET_GPIO_DEBUG_AUN	
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Scout ACK written to %d.%d, waiting for data\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn);
#endif
					econet_set_aunstate(EA_R_READDATA);
					break;
				}
				case EA_R_WRITEFINALACK: // Just written final ACK after a data packet - go back to IDLE & dump received packet to userspace
				{
					
					if (!(econet_data->resilience)) // Don't sent to userspace again if in resilience mode
					{
						kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
						wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
					}
					econet_set_aunstate(EA_IDLE);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Final ACK to %d.%d, packet delivered to userspace\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn);
#endif
					break;
				}

				// Now immediate handling

				case EA_I_WRITEIMM: // We receive an immediate from userspace and have just written it to the wire, so need to wait for the reply
				{
					econet_set_aunstate(EA_I_READREPLY);
					// Because this is an immediate, we need to flag transmit success to the tx user space
					// 20240606 No, don't do this - we want to detect line idle IRQ
					// 20240607 Reinstated. Userspace will need to wait a few ms after a succes to see if it got line idle / not listening status
					econet_set_tx_status(ECONET_TX_SUCCESS);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Written immediate query. Signal TX success but move to READREPLY\n");
#endif
					break;
				}
				case EA_I_WRITEREPLY: // We read an immediate from the wire and have just transmitted the reply
				{
					// We don't update tx_status here because the immediate reply will have been generated in-kernel
					econet_set_tx_status(ECONET_TX_SUCCESS);
					econet_set_aunstate(EA_IDLE);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Written immediate reply. Signal TX success. Return to IDLE\n");
#endif
					break;
				}
				default: // Which will apply for writing an immediate reply when not in spoof mode
				{
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "econet-gpio: econet_irq(): AUN: Default reached on write state machine. Return to IDLE. AUN state = %d\n", aun_state);
#endif
					econet_set_aunstate(EA_IDLE);
					break;
				}
						
			}
		}
		
		/*
		 * If not in AUN mode, all we needed to do
		 * was get one frame on the wire, which we
		 * have now done. Flag TX success and 
		 * clear the RX FIFO so that whatever arrives
		 * next is a reply to the packet we just sent.
		 *
		 */

		else 
		{
			econet_set_tx_status(ECONET_TX_SUCCESS);
#ifdef ECONET_GPIO_DEBUG_TX
			printk (KERN_INFO "econet-gpio: econet_irq(): Returning to IDLEINIT, flagging frame completed\n");
#endif
			kfifo_reset(&econet_rx_queue);
		}

		/*
		 * Go to read mode for whatever happens next - it
		 * certainly won't be us transmitting. Or if the user
		 * wants to, then we'll seize the line again and the
		 * AUN state machine can start again.
		 */

		econet_set_read_mode();
		
	}

	/* 
	 * Are we mid read (EM_READ) of a frame, 
	 * or have we got a valid received frame, 
	 * address present, or receiver data available ?
	 *
	 * If so, call the IRQ read routine.
	 *
	 */

	else if (chip_state == EM_READ || (sr2 & (ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_AP)) || (sr1 & ECONET_GPIO_S1_RDA))
		econet_irq_read();

	/*
	 * Sometimes we get odd IRQs when idle or in EM_IDLEINIT.
	 * Clear down if there is an RX error, else just clear whatever
	 * status was present.
	 */

	else if (chip_state == EM_IDLE || chip_state == EM_IDLEINIT)
	{
		if (chip_state == EM_IDLEINIT)
			econet_set_chipstate(EM_IDLE);

		if (sr2 & ~(ECONET_GPIO_S2_AP | ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_RDA)) // Errors
		{
			econet_rx_cleardown();
		}
		else
			econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Just clear status
	}

	/* 
	 * Everything else is an unknown state - flag an error.
	 *
	 */

	else
		printk (KERN_INFO "econet-gpio: IRQ received in unknown state - sr1=0x%02X, sr2=0x%02X, chip state %02X\n", sr1, sr2, econet_get_chipstate());


	/*
	 * Unlock IRQ spinlock prior to return.
	 *
	 */

	spin_unlock_irqrestore(&econet_irq_spin, flags);

	/* Return */

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



/*
 * econet_readfd()
 *
 * Device read routine from usespace
 *
 */

ssize_t econet_readfd(struct file *flip, char *buffer, size_t len, loff_t *offset) {

	int ret;
	unsigned int copied;

	/* 
	 * Whatever it is we have available, 
	 * put it into userspace.
	 *
	 * If kfifo_to_user returns 0, there was nothing, so
	 * return -EFAULT. 
	 *
	 * Else return bytes copied.
	 *
	 */

	ret = kfifo_to_user(&econet_rx_queue, buffer, len, &copied);

	if (ret == 0)
		return copied;
	else	return -EFAULT;


}


/* 
 * econet_aun_tx_statemachine()
 *
 * This routine works out what to do when we are ready to transmit in AUN mode, and
 * implements the AUN statemachine
 *
 * On entry, writefd should have put the packet we want to transmit in aun_tx 
 * ready for us
 *
 */

void econet_aun_tx_statemachine(void)
{
	
	unsigned short aun_state;

	/* 
	 * When in AUN mode, the writefd() routine should 
	 * have put the packet into aun_tx for us
	 *
	 */

	/* Copy address bytes to TX frame buffer */

	memcpy (&econet_pkt_tx_prepare, &aun_tx, 4);

	/* Find current state */

	aun_state = econet_get_aunstate();

	if (aun_state == EA_IDLE) // Fresh packet in, so set the tx_status to the rogue
		econet_set_tx_status(ECONET_TX_STARTWAIT);

	switch (aun_state)
	{
		/*
		 * We are not in the middle of any AUN
		 * operation, so set up initial packet of
		 * a sequence (or one-off for broadcast)
		 *
		 */

		case EA_IDLE: // This must be a write from userspace. Write a Scout, or Immediate if port = 0
		{
			if (aun_tx.d.p.aun_ttype == ECONET_AUN_BCAST) // Broadcast
			{
				/* 
				 * Set destination to &FF, &FF
				 * Source address set by the memcpy() up above.
				 */

				econet_pkt_tx_prepare.d.p.dstnet = econet_pkt_tx_prepare.d.p.dststn = 0xff;

				/* Copy ctrl byte. Userspace responsible for adding high bit */

				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl;

				/* Copy port number */

				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;

				/* 
				 * If there's any data in the packet, 
				 * copy it to TX frame buffer. AUN format has
				 * 12 header bytes (incl. our appended 4 address
				 * bytes) so con't copy those over.
				 *
				 */

				if (aun_tx.length > 12) 
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), (aun_tx.length - 12));

				/* 
				 * Packet length will be the AUN length less 6
				 *
				 * AUN is data + 12 bytes (with our extra 4 address bytes)
				 * But the wire packet is data + 6 (4 x address + port + ctrl)
				 * So the difference is 6. Just do a subtraction.
				 *
				 * E.g. if writefd() has given us a packet with no data at all,
				 * then we'll be sending 6 bytes. 12 -6 = 6. Every byte of
				 * data adds one to each - so the calculation works.
				 *
				 */

				econet_pkt_tx_prepare.length = aun_tx.length -6; 

				/* Move state to write a broadcast */

				econet_set_aunstate(EA_W_WRITEBCAST);
			}

			/* Writing an immediate query */

			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_IMM) // Immediate
			{

				/* Address bytes copied above; copy port & ctrl.
				 * Userspace responsible for adding high 
				 * bit to ctrl
				 */

				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl;

				/* 
				 * Copy any data that came with the immediate query
				 *
				 */

				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), (aun_tx.length - 12));

				/* Set TX frame length - see comment above about why this is aun length minus 6 */

				econet_pkt_tx_prepare.length = aun_tx.length -6; 

				/* Put us in the right state to transmit it */

				econet_set_aunstate(EA_I_WRITEIMM);
			}	

			/* Econet AUN Data - i.e. needs a 4-way, including the 'special' immediates &82 -- &85 */

			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_DATA)
			{

				/* Set up a scout in the TX frame buffer.
				 * Userspace will have ensured the high bit of
				 * ctrl is set
				 */

				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; 

				/*
				 * Copy the data portion of the scout into the frame
				 * buffer for the special immediates. 
				 *
				 * &82 has 8 bytes on the scout
				 * &83 - &85 have four each
				 *
				 */

				if (aun_tx.d.p.port == 0x00 && aun_tx.d.p.ctrl == 0x82)
				{
					econet_pkt_tx_prepare.length = 14;
					memcpy(&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), 8);
				}
				else if (aun_tx.d.p.port == 0x00 && (aun_tx.d.p.ctrl >= 0x83 && aun_tx.d.p.ctrl <= 0x85))
				{
					econet_pkt_tx_prepare.length = 10;
					memcpy(&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), 4);
				}
				else
					econet_pkt_tx_prepare.length = 6;

				/* Set tx frame pointer to 0 and move to AUN write scout state */

				econet_pkt_tx_prepare.ptr = 0;
				econet_set_aunstate(EA_W_WRITESCOUT);
			}

			/* 
			 * Finally, are we transmitting an immediate reply? 
			 *
			 * This should be a reply to an immediate we just 
			 * received moments ago and sent to userspace, following
			 * which we flag filled ready.
			 *
			 */

			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_IMMREP) 
			{
				/* 
				 * Copy any data that's on the immediate reply
				 * into the tx frame buffer
				 *
				 * An immediate reply appears not to have ctrl or port
				 * bytes in it, so the data is copied to the ctrl byte
				 * position.
				 *
				 */

				if (aun_tx.length > 12)
					memcpy (&(econet_pkt_tx_prepare.d.p.ctrl), &(aun_tx.d.p.data), (aun_tx.length - 12)); // Used to copy to d.p.data, but that's wrong on an immediate reply

				/* 
				 * Set the length of the frame up
				 *
				 * 4 address bytes + whatever data came on the reply 
				 *
				 */

				econet_pkt_tx_prepare.length = 4 + (aun_tx.length > 12 ? (aun_tx.length - 12) : 0); 

				econet_set_aunstate(EA_I_WRITEREPLY);
			}
		}
		break;

		default:	printk(KERN_INFO "econet-gpio: econet_aun_tx_statemachine() called in state 0x%02X", aun_state); break;
	}
}


/*
 * econet_writefd()
 *
 * Module write function on the device
 *
 */

ssize_t econet_writefd(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
	
	int c;
	unsigned short chipmode;
	unsigned short txstatus;
	unsigned short aunstate;


	/*
	 * Lock mutex so writefd is not entered
	 * twice at once.
	 *
	 */

	if (!mutex_trylock(&econet_writefd_mutex))
	{
		printk (KERN_INFO "econet-gpio: Flag busy because cannot get writefd mutex\n");
		econet_set_tx_status(ECONET_TX_BUSY);
		return -1;
	}

	/* 
	 * Disable IRQs.
	 *
	 * We don't do this outside the mutex because it causes kernel panics.
	 *
	 */

	econet_irq_mode(0);
	
	/* Lock the irq state as well */

	if (!spin_trylock(&econet_irqstate_spin))
	{
		/* If failed, complain, turn IRQs back on, unlock the mutex and return */

		printk (KERN_INFO "econet-gpio: Flag busy because cannot get IRQ spinlock\n");

		econet_irq_mode(1);

		econet_set_tx_status(ECONET_TX_BUSY);

		mutex_unlock(&econet_writefd_mutex);

		return -1;
	}

	/* Next see what we are doing at the moment and fudge our AUN state if necessary */

	txstatus = econet_get_tx_status();
	aunstate = econet_get_aunstate();

	/* Go back to EA_IDLE if not idle and last AUN-related TX was more than the timeout ago */

	if (econet_data->aun_mode && (aunstate != EA_IDLE) && (txstatus >= ECONET_TX_DATAPROGRESS) && ((ktime_get_ns() - econet_data->aun_last_writefd) >= ECONET_4WAY_TIMEOUT)) // The >= catches data progress, in progress, waiting to start
	{
		econet_set_tx_status(ECONET_TX_SUCCESS);
		econet_set_aunstate(EA_IDLE); 
		econet_set_chipstate(EM_IDLE);
		aunstate = EA_IDLE;
	}
	
	/* Timestamp this write */

	econet_data->aun_last_writefd = ktime_get_ns();

	/* 
	 * Go back to idle if last TX was more than 100ms ago and we are waiting for an RX frame to come in.
	 * Assume we are stuck.
	 *
	 * TODO: this might be a source of problems - should we lengthen this timeout ? 100ms is 0.1s, so at 
	 * 200kHz clock spead, 200,000 bits will move each second, so this is 20,000 bits, which is about
	 * 2.5kB. Most transfers will be less than that but some may be longer...
	 *
	 */

	if (econet_data->aun_mode && (aunstate == EA_W_READFIRSTACK || aunstate == EA_W_READFINALACK || aunstate == EA_I_READREPLY || aunstate == EA_R_READDATA) && ((ktime_get_ns() - econet_data->aun_last_tx) > 100000000))
	{

		if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: Return to AUN idle - more than 0.1s since we last tx'd and we are still waiting for read data to arrive - in AUN state 0x%02x\n", aunstate);
		econet_set_tx_status(ECONET_TX_SUCCESS);
		econet_set_aunstate(EA_IDLE); 
		econet_set_chipstate(EM_IDLE);
		aunstate = EA_IDLE;
	}

	// Next, see if we are idle

	/* 
	 * If not idle, tell user space we are busy and put IRQs back on.
	 * Unlock the mutex & spinlock along the way.
	 */

	if (econet_data->aun_mode && aunstate != EA_IDLE) // Not idle
	{
		if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: Flag busy because AUN state machine busy (state = 0x%02x)\n", aunstate);
		econet_set_tx_status(ECONET_TX_BUSY);
		spin_unlock(&econet_irqstate_spin);
		mutex_unlock(&econet_writefd_mutex);
		econet_irq_mode(1);
		return -1;
	}

	/*
	 * Is the ADLC receiving or transmitting?
	 *
	 * If so, tell userspace we're busy.
	 *
	 */

	chipmode = econet_get_chipstate();

	if (chipmode != EM_IDLE && chipmode != EM_IDLEINIT && chipmode != EM_FLAGFILL)
	{
		if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: Flag busy because chip state not idle / flagfill\n");
		econet_set_tx_status(ECONET_TX_BUSY);
		spin_unlock(&econet_irqstate_spin);
		mutex_unlock(&econet_writefd_mutex);
		econet_irq_mode(1);
		return -1;
	}

	/* 
	 * By here, we have:
	 * (i) Our writefd() mutex held.
	 * (ii) the IRQ spinlock held
	 * (iii) an idle statemachine and chip
	 *
	 * So look and see if we have a clock.
	 *
	 * If not, exit back to userspace.
	 *
	 * TODO: Not clear why we check it twice here...
	 *
	 */

	sr2 = econet_read_sr(2);

	if (sr2 & ECONET_GPIO_S2_DCD) // No clock
	{
		sr2 = econet_read_sr(2);
		if (sr2 & ECONET_GPIO_S2_DCD)
		{
			econet_set_tx_status(ECONET_TX_NOCLOCK);
			econet_set_read_mode();
			econet_set_aunstate(EA_IDLE);
			spin_unlock(&econet_irqstate_spin);
			mutex_unlock(&econet_writefd_mutex);
			econet_irq_mode(1);
			return -1;
		}
	}
	
	/* 
	 * By here, we've got a ready, willing and idle
	 * ADLC and AUN state machine. So pick up the packet
	 * from user space.
	 *
	 */

	if ((c = copy_from_user(&econet_pkt, buffer, len)))
	{
		econet_pkt.ptr = econet_pkt.length = 0; // Empty the packet 
		printk (KERN_ERR "econet-gpio: econet_writefd() Failed to copy %d bytes from userspace", c);
		econet_set_tx_status(ECONET_TX_NOCOPY);
		econet_set_read_mode();
		spin_unlock(&econet_irqstate_spin);
		mutex_unlock(&econet_writefd_mutex);
		econet_irq_mode(1);
		return  -1;
	}

	/* 
	 * If in AUN mode, 
	 *
	 * (i) Copy the packet to the aun_tx buffer
	 * (ii) Set up the buffer's length
	 * (iii) call the routine that sets up the AUN state machine (broadcast, immediate, data)
	 * (iv) Unlock the IRQ spinlock 
	 * (v) Tell the ADLC to start transmission loop.
	 *
	 */

	if (econet_data->aun_mode)
	{
		memcpy (&aun_tx, &econet_pkt, len); // Puts the four src/dst bytes into aun_tx. Line the rest up later.

		/* Do nothing and quit unless it's a packet we can actually transmit */

		if (	aun_tx.d.p.aun_ttype != ECONET_AUN_DATA 
		&&	aun_tx.d.p.aun_ttype != ECONET_AUN_BCAST
		&&	aun_tx.d.p.aun_ttype != ECONET_AUN_IMM
		&&	aun_tx.d.p.aun_ttype != ECONET_AUN_IMMREP
		)
		{

			econet_pkt.ptr = econet_pkt.length = 0; // Empty the packet 
			printk (KERN_ERR "econet-gpio: econet_writefd() - attempt to transmit AUN packet of type which cannot go on an Econet - type %02X", aun_tx.d.p.aun_ttype);
			econet_set_tx_status(ECONET_TX_INVALID);
			econet_set_read_mode();
			spin_unlock(&econet_irqstate_spin);
			mutex_unlock(&econet_writefd_mutex);
			econet_irq_mode(1);
			return  -1;

		}

		aun_tx.length = len;
		econet_aun_tx_statemachine(); // Sets up econet_pkt_tx_prepare
#ifdef ECONET_GPIO_DEBUG_AUN
		printk (KERN_INFO "econet-gpio: econet_writefd(): AUN: Packet from userspace from %d.%d to %d.%d, data length %d", aun_tx.d.p.srcnet, aun_tx.d.p.srcstn, aun_tx.d.p.dstnet, aun_tx.d.p.dststn, (len - 12));
#endif
		spin_unlock(&econet_irqstate_spin);

		/* Trigger TX */

		econet_set_write_mode (&econet_pkt_tx_prepare, econet_pkt_tx_prepare.length);
	}


	/* 
	 * Else we're in raw mode - unlock the IRQ lock and
	 * put us in write mode.
	 *
	 */

	else 
	{

		/* Consider unlocking the IRQ after going into write mode? */

		spin_unlock(&econet_irqstate_spin);
		econet_set_write_mode (&econet_pkt, len);
	}

	/*
	 * Turn IRQs on so that the ADLC will 
	 * generate one to start the frame write
	 * process
	 *
	 */

	econet_irq_mode(1);

	/* 
	 * Wait a while so that hopefully an IRQ has 
	 * happened, and then check the TX status to see if 
	 * we are transmitting.
	 *
	 * If not, someething has gone wrong - go back to idle.
	 *
	 */

	udelay(10); // Wait for IRQ

	if (econet_get_tx_status() != ECONET_TX_INPROGRESS) // Something failed in set_write_mode
	{
		econet_pkt_tx.length = 0; // Blank off the packet
		econet_set_read_mode();
		econet_set_aunstate(EA_IDLE);
		mutex_unlock(&econet_writefd_mutex);
		return -1;
	}
	
	/* Unlock the writefd mutex */

	mutex_unlock(&econet_writefd_mutex);

	return len; // Exit

}

/* Other than in the IRQ routine above, start CLEANUP here */

/* 
 * econet_led_state()
 *
 * Change state of one or other LED. See #defines in econet-gpio-consumer.h
 */

void econet_led_state(uint8_t arg)
{
	uint8_t pin;

	pin = (arg & ECONETGPIO_READLED) ? EGP_READLED : EGP_WRITELED;

	gpiod_set_value(ECOPIN(pin), (arg & ECONETGPIO_LEDON) ? 1 : 0);

}

/* 
 * econet_set_pwm()
 *
 * Change the PWM period/mark for the network clock (only initialized on v2 hardware)
 *
 * Remember we run the PWM clock at 4MHz to make sure we can do marks which are
 * fractions of a us - so multiply everything by 4!
 *
 */

void econet_set_pwm(uint8_t period, uint8_t mark)
{

	/* Return if on v1 hardware - not supported */

	if (econet_data->hwver < 2)	
		return; 

	/* Disable PWM and reconfigure */

	pwm_disable(econet_data->gpio18pwm);

	if (pwm_config(econet_data->gpio18pwm, mark * 250, period * 250)) // ( * 250 = (* 1000 / 4) )
	{
		printk (KERN_ERR "econet-gpio: Econet clock change failed!\n");
		return;
	}

	/* Re-enable PWM */

	if (pwm_enable(econet_data->gpio18pwm))
	{
		printk (KERN_ERR "econet-gpio: Econet clock enable failed!\n");
		return;
	}

	printk (KERN_INFO "econet-gpio: Econet clock set: period/mark = %d/%d ns\n", period * 250, mark * 250);

}

/* 
 * econet_open()
 *
 * Called when a process opens our device 
 *
 */

int econet_open(struct inode *inode, struct file *file) {

	/* If device is open, return busy */

	if (econet_data->open_count)
		return -EBUSY;

	/* Increment open_count so we know we are busy */

	econet_data->open_count++;

	/* TODO: Look up what this is and why we need it. */

	try_module_get(THIS_MODULE);
	
	/* Reset the ADLC, packet buffers, station set  */

	econet_reset(); 

	return 0;
}

/* 
 * econet_release()
 *
 * Called when a process closes our device
 *
 */

int econet_release(struct inode *inode, struct file *file) {

	/* Decrement the open counter and usage count. Without this, the module would not unload. */

	econet_data->open_count--;

	module_put(THIS_MODULE);

	return 0;
}

/* 
 * econet_poll()
 *
 * Poll routine from userspace
 *
 */

unsigned int econet_poll (struct file *filp, poll_table *wait)
{

	unsigned int mask = 0;

	/* Snooze on the read queue */

	poll_wait (filp, &(econet_data->econet_read_queue), wait);

	/* If there's data on the FIFO, tell the user */

	if (!kfifo_is_empty(&econet_rx_queue))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

/*
 * econet_ioctl()
 *
 * Handle ioctl() calls from userspace
 *
 */

long econet_ioctl (struct file *gp, unsigned int cmd, unsigned long arg)
{

#ifdef ECONET_GPIO_DEBUG_IOCTL
	printk (KERN_DEBUG "econet-gpio: IOCTL(%d, %lu)\n", cmd, arg);
#endif

	switch(cmd){

		/*
		 * Reset the module & ADLC 
		 *
		 */

		case ECONETGPIO_IOC_RESET:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(reset) called\n");
#endif
			econet_reset();
			break;

		/* 
		 * Return maximum allowed packet size
		 * to userspace.
		 *
		 */

		case ECONETGPIO_IOC_PACKETSIZE: 
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(max_packet_size) called\n");
#endif
			return ECONET_MAX_PACKET_SIZE;
			break;

		/* 
		 * Set ADLC back to read mode.
		 * This is used after an immediate query came
		 * off the wire but nothing responded to it.
		 * Clears the flag fill state that the module
		 * will put the ADLC into on receipt of 
		 * the immediate, so that the sending 
		 * station thinks something may be about
		 * to reply.
		 *
		 * Can also be useful at other times...
		 *
		 * Go back to AUN IDLE if AUN mode engaged.
		 *
		 */

		case ECONETGPIO_IOC_READMODE: 
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set read mode) called\n");
#endif
			econet_adlc_cleardown(0); // 0 = not in IRQ
			econet_set_read_mode(); // Required in addition to the cleadown, because this sets the ADLC up to read, where as cleardown doesn't.
			if (econet_data->aun_mode)
				econet_set_aunstate(EA_IDLE);

			break;

		/*
		 * Does the same as READMODE, above,
		 * but does it gently, in the sense that
		 * it doesn't do a full ADLC clear down.
		 *
		 * Go back to AUN IDLE if AUN mode engaged.
		 *
		 */

		case ECONETGPIO_IOC_READGENTLE: 
			econet_set_read_mode(); 

			if (econet_data->aun_mode)
				econet_set_aunstate(EA_IDLE);

			break;

		/*
		 * Update the station map.
		 *
		 * The station map is used by the receiver
		 * code to identify which stations on the wire
		 * we want to listen for. This enables
		 * the module to ignore traffic for destinations
		 * it does not need to handle. The station map
		 * is constructed in userspace and will include:
		 * (i) All stations on all distant networks over
		 *     bridges and trunks, including pools and
		 *     static and dynamic AUN networks.
		 * (ii) 0.n and local.n entries for all stations
		 *     on the local wire being emulated or handled
		 *     by userspace - e.g. FS, PS, IP Server, Pipe
		 *
		 * Since the map is not used in RAW mode, it is
		 * implicit in setting the station map that 
		 * userspace wants the kernel to turn on AUN
		 * mode.
		 *
		 */

		case ECONETGPIO_IOC_SET_STATIONS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set stations) called\n");
#endif
			/* Copy station bitmap from user memory */

			if ((!access_ok((void __user *) arg, 8192)) || copy_from_user(econet_stations, (void *) arg, 8192))
			{
				printk (KERN_INFO "econet-gpio: Unable to update station set.\n");
				return -EFAULT;
			}

			if (econet_data->extralogs) printk(KERN_INFO "econet-gpio: Station set updated - Switching on AUN mode\n");
			else if (econet_data->aun_mode != 1) printk (KERN_INFO "econet-gpio: AUN mode on\n");

			/* Enable AUN mode and set state to IDLE */

			if (econet_data->aun_mode) break; // Leave state alone in case mid transaction
			else
			{
				econet_data->aun_mode = 1;
				econet_set_aunstate(EA_IDLE);
			}

			break;

		/*
		 * No longer used. Was used in early versions to see what rx queue
		 * availability there was.
		 *
		 */

		case ECONETGPIO_IOC_AVAIL:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(rx queue availablity) called\n");
#endif
			return 0;

		/* 
		 * The following ioctl()s are for testing purposes only.
		 * They are intended for use by someone with an
		 * oscilloscope probing the GPIO lines...
		 *
		 * There are more ioctl()s that *are* in use further
		 * down, because they appear in numerical order in
		 * this source.
		 *
		 */

		/* 
		 * Set ADLC address lines as requested.
		 *
		 */

		case ECONETGPIO_IOC_SETA:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set address, %02lx) called\n", (arg & 0x03));
#endif

			/* Wait until we are not busy if on v2 */

			if (econet_data->hwver >= 2)
			{
				 while (econet_isbusy());
			}

			/* Set the lines */

			econet_set_addr((arg & 0x2) >> 1, (arg & 0x1));

			break;

		/* 
		 * Set ADLC RnW line
		 *
		 */

		case ECONETGPIO_IOC_WRITEMODE:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set write mode, %02lx) called\n", (arg & 0x01));
#endif
			econet_set_dir(arg & 0x01);
			break;

		/*
		 * Set Chip select line
		 *
		 */

		case ECONETGPIO_IOC_SETCS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set /CS, %02lx) called\n", (arg & 0x01));
#endif
			econet_set_cs(arg & 0x01);
			break;

		/*
		 * Set data bus to write
		 * and put data on it.
		 *
		 */

		case ECONETGPIO_IOC_SETBUS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set bus, %02lx) called\n", (arg & 0xff));
#endif
			econet_set_dir(ECONET_GPIO_WRITE);
			
#ifdef ECONET_GPIO_NEW

			// Set address & RnW & data

			gpiod_set_array_value (8, data_desc_array, NULL, &arg); // 11 because the address & RnW are in 8,9,10
#else

			// Put data on the bus
			
			iowrite32((arg << ECONET_GPIO_PIN_DATA), NGPSET0);
			iowrite32((~(arg << ECONET_GPIO_PIN_DATA)) & ECONET_GPIO_CLRMASK_DATA, NGPCLR0);
#endif
			break;

		/*
		 * Put the module into test mode.
		 *
		 * It will ignore any IRQs it receives.
		 *
		 */

		case ECONETGPIO_IOC_TEST:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set test mode) called\n");
#endif
			/* Reset the ADLC */

			econet_reset();

			/* Go to test mode */

			econet_set_chipstate(EM_TEST);

			/* Turn off IRQs */

			econet_irq_mode(0);

			break;


		/*
		 * These ioctl()s are not for testing,
		 * they are for production use.
		 *
		 */

		/*
		 * Obtain last transmit error code (incl. success)
		 *
		 */

		case ECONETGPIO_IOC_TXERR:
			{
				uint8_t s;

				s = econet_get_tx_status();
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(get last tx error) called - current status %02x\n", s);
#endif
			return ((long) s);
			}
			break;

		/* 
		 * Return current AUN state & tx buffer ptr
		 * to userspace.
		 *
		 * Enables userspace to report what happened
		 * on a failed transmission.
		 *
		 */

		case ECONETGPIO_IOC_GETAUNSTATE:
			return ((econet_pkt_tx.ptr << 16) | econet_get_aunstate());
			break;

		/*
		 * Go into flag fill or set read mode.
		 * Not clear why this is still here.
		 *
		 */

		case ECONETGPIO_IOC_FLAGFILL: 
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(set flag fill) called\n");
#endif
			if (arg)
				econet_flagfill();
			else    econet_set_read_mode();
			break;

		/* 
		 * Switch AUN mode on or off.
		 *
		 * The implied AUN mode 'on' when
		 * a station set is uploaded can be
		 * undone with this ioctl().
		 *
		 */

		case ECONETGPIO_IOC_AUNMODE:

			/* Check to see if the caller has given us a valid parameter */

			if (arg != 1 && arg != 0)
			{
				printk (KERN_ERR "econet-gpio: Invalid argument (%ld) to ECONETGPIO_IOC_AUNMODE ioctl()\n", arg);
				break;
			}

			/* Reset the ADLC & change AUN mode */

			econet_reset();

			econet_data->aun_mode = arg; // Must do this after econet_reset, because econet_reset turns AUN off.

			printk (KERN_INFO "econet-gpio: AUN mode turned %s by ioctl()\n", (arg == 1 ? "on" : "off"));

			break;

		/*
		 * This is the old ioctl() to enable or disable
		 * Immediate Reply spoofing, where the kernel will
		 * generate a reply to certain immediate requests.
		 *
		 * This is long since disused, and has been disabled.
		 *
		 */

		case ECONETGPIO_IOC_IMMSPOOF:
			printk (KERN_INFO "econet-gpio: Immediate spoofing no longer supported. ioctl(ECONETGPIO_IOC_IMMSPOOF) ignored.\n");
			break;

		/*
		 * Turn on extra logging in the live module.
		 * Or turn it off.
		 *
		 */

		case ECONETGPIO_IOC_EXTRALOGS:

			econet_data->extralogs = (arg == 0) ? 0 : 1;
			printk (KERN_INFO "econet-gpio: Extra logging turned %s\n", (arg == 0) ? "OFF" : "ON");
			break;

		/*
		 * Cause module to emit a test packet.
		 *
		 * The packet is a machine type query 
		 * spoofed from 0.254 to 0.1.
		 *
		 */

		case ECONETGPIO_IOC_TESTPACKET: 
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-gpio: ioctl(test packet) called\n");
#endif

			/* Wait for up to 0.5s for ADLC to become idle */

			{
				u64 timer;
		
				timer = ktime_get_ns() + 500000000; 
	
				while ((ktime_get_ns() < timer) && (econet_get_chipstate() != EM_IDLE));
				
			}

			/* Construct packet */

			econet_pkt.d.p.dststn = 1;
			econet_pkt.d.p.dstnet = 0; /* Station 1 on local network */
			econet_pkt.d.p.srcstn = 254;
			econet_pkt.d.p.srcnet = 0; /* Station 254 on local network */
			econet_pkt.d.p.ctrl = 0x88; /* Machine Type query */
			econet_pkt.d.p.port = 0x00; /* Immediate */

			/* Initialize length / ptr in the buffer */

			econet_pkt.length = 6;
			econet_pkt.ptr = 0; /* Start at the beginning */

			/* Trigger ADLC to write */

			econet_set_write_mode(&econet_pkt, 6);

			break;

		/* 
		 * Turn one of the LEDs on or off.
		 * Only does one at once. That was probably
		 * a lack of foresight.
		 *
		 */

		case ECONETGPIO_IOC_LED: 
			econet_led_state(arg);
			break;

		/*
		 * Change the period/mark of the PWM which
		 * drives the network clock off a v2
		 * bridge board.
		 *
		 * The period (in us) is the top 16 bits
		 * of the argument, mark (in us) is the bottom
		 * 16.
		 *
		 */

		case ECONETGPIO_IOC_NETCLOCK:

			/* 
			 * Check for v2 or greater hardware.
			 *
			 * Nothing to do here on v1.
			 *
			 */

			if (econet_data->hwver >= 2)
				econet_set_pwm (((arg & 0xffff0000) >> 16), (arg & 0xffff));

			break;

		/*
		 * Return Pi version (based on hardware address of GPIO)
		 * and HAT version (from the device tree)
		 *
		 */

		case ECONETGPIO_IOC_KERNVERS:
			{
				uint32_t version = 0;

				version |= (econet_data->hwver << 8);

				switch (econet_data->peribase)
				{
					case 0xFE000000: version |= 4; break;
					case 0x3F000000: version |= 3; break;
					case 0x20000000: version |= 2; break;
				}

				return version;
			} break; // Not executed

		/*
		 * Send a 4-way final ACK when we're in
		 * resilience mode, where we stick in flag fill
		 * after receiving a 4-way data segment (part 3 of 4)
		 * from a station on the wire, and wait for 
		 * userspace to tell us to send the ACK (which it will
		 * do when it gets an AUN ACK (or spoof of the same) from
		 * the reciving station. The effect of this is to 
		 * generate Net Error on the Econet client if the traffic
		 * isn't confirmed as reaching its destination. If
		 * userspace doesn't get an ACK in the relevant timeout,
		 * it will put the ADLC back into read mode, which 
		 * drops flag fill & causes Net Error. If it does get
		 * an ACK in time, it'll use this ioctl() to send a
		 * 4-way final ACK to the client and the client will
		 * then accept that the data got there. The point of 
		 * all this is more accurately to signal to an Econet
		 * station (or one via an Econet bridge / another Pi
		 * Bridge) whether the data it transmitted actually
		 * got received by the end station.
		 */

		case ECONETGPIO_IOC_RESILIENTACK:
			{
				econet_set_aunstate(EA_R_WRITEFINALACK);
				econet_set_chipstate(EM_WRITE);
				econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);

				if (econet_data->extralogs) printk (KERN_INFO "econet-gpio: Sent resilient 4-way final ACK\n");

			} break;

		case ECONETGPIO_IOC_RESILIENCEMODE:
			{
				econet_data->resilience = (arg & 0x01); // Strip all but low bit
				printk (KERN_INFO "econet-gpio: Resilience mdoe %s\n", ((arg & 0x01) == 0) ? "OFF" : "ON");

			} break;
		/*
		 * And if we get here, then something
		 * went wrong...
		 *
		 */

		default:
			return -ENOTTY;
	}

	return 0;

}

/*
 * econet_probe()
 *
 * Main probe routine for the driver.
 *
 * Sets up the GPIOs, ADLC clock,
 * and network clock PWM (if on v2
 * hardwre).
 *
 */

static int econet_probe (struct platform_device *pdev)
{

	int err;
	int result;
	u8	count;

	struct device *dev = &pdev->dev;
	struct device_node *econet_device;
	u8	version = 0;
	u32	gpio4clk_rate;

#ifdef ECONET_GPIO_NEW
	printk (KERN_INFO "econet-gpio: Module loading in new mode\n");
#else
	printk (KERN_INFO "econet-gpio: Module loading\n");
#endif

	/*
	 * Allocate our private data space,
	 * and complain bitterly if we can't do so.
	 *
	 */

	econet_data = kzalloc(sizeof(struct __econet_data), GFP_KERNEL);

	if (!econet_data)
	{
		printk (KERN_ERR "econet-gpio: Failed to allocate internal data storage.\n");
		return -ENOMEM;
	}

	/*
	 * Next, look for the econet-gpio entry in
	 * the device tree. Older versions of the module
	 * didn't require one, but it is now mandatory
	 * so that we can pick up the numbers of the GPIOs
	 * and request them, and also get the pinctrl
	 * subsystem to put GPIO4 and GPIO18 (ADLC clock
	 * and network PWM clock) into the right ALT
	 * mode without writing directly to the hardware,
	 * which the module now tries to restrict only
	 * to writing to the CRs / reading from the SRs
	 * in order to reduce latency.
	 *
	 */

	// Look for the device tree
	
	econet_device = of_find_compatible_node(NULL, NULL, "econet-gpio");

	/* If we've found it, look up the version number */

	if (econet_device && (of_property_read_u8_array(econet_device, "version", &version, 1) == 0))
		econet_data->hwver = version;

	of_node_put (econet_device); // Supports NULL parameter apparently, so doesn't need to be guarded by if()

	/*
	 * If we did not find the device in the tree,
	 * give up, and free our private data allocation.
	 *
	 */

	if (!econet_device)
	{
		printk (KERN_INFO "econet-gpio: No device tree entry found. Abort.\n");
		kfree(econet_data);
		return -ENODEV;
	}

	/*
	 * Or if we did find it, but it didn't have a version
	 * number in it, complain & abort, similarly 
	 * freeing up our data space.
	 *
	 */

	else if (version == 0)
	{
		printk (KERN_INFO "econet-gpio: No version found in device tree. Abort.\n");
		kfree(econet_data);
		return -ENODEV;
	}

	/* Report discovered hardware version to user in dmesg */

	printk (KERN_INFO "econet-gpio: Found version %d hardware\n", econet_data->hwver); 

	/*
	 * If we are in new mode, but we have found
	 * a version 1 board, then that won't work at 
	 * all, so give up.
	 *
	 */

#ifdef ECONET_GPIO_NEW
	if (econet_data->hwver < 2)
	{
		printk (KERN_ERR "econet-gpio: Hardware version incompatible with this module. Please compile module in old mode.\n");
		kfree(econet_data);
		return -ENODEV;
	}
#endif

	/* Main initialization routine */

	/* Start in test mode so the module has nothing to deal with */

	econet_set_chipstate(EM_TEST);

	/* Set level shifter & data direction to rogue so that
	 * first call to set direction forcibly changes it
	 */

	econet_data->current_dir = 0xff; // Rogue so first operation sets direction

	/* Set IRQ state to rogue so first change forcibly changes it */

	econet_set_irq_state(-1);

	/* Start with AUN mode off */

	econet_data->aun_mode = 0;

	/* Start with resilience mode off */

	econet_data->resilience = 0; // Rest of resilience not implemented yet! (20240317)

	/* Initialize base sequence number for traffic coming off the wire */

	econet_data->aun_seq = 0x4000;

	/* Initialize last AUN tx timer so that first packet causes switch
	 * to AUN idle mode in the state machine
	 */

	econet_data->aun_last_tx = 0;

	/* 
	 * Flag module as uninitialized. This
	 * gets changed when everything is ready to go.
	 *
	 */

	econet_data->initialized = 0; // Module not yet initialized.

	/* Initialize AUN state to idle.
	 * Doesn't matter if we are not in AUN mode, it'll
	 * just be ignored.
	 */

	econet_set_aunstate(EA_IDLE);

	/* 
	 * Start with no extra logging.
	 *
	 */

	econet_data->extralogs = 0;

	/* Set IRQ number to rogue so we can
	 * tell if initialized. This is set to the IRQ
	 * number given to us when we ask for the IRQ
	 * number associated with the IRQ GPIO during
	 * probe.
	 */

	econet_data->irq = 0;

	/* Initialize gpio4clk (a gpiodesc) to NULL
	 * so that we can tell if it didn't initialize.
	 */

	econet_data->gpio4clk = NULL;

	/* Clear the array of gpiodescs so that
	 * we know which ones were successfully obtained.
	 */

	memset (&(econet_data->econet_gpios), 0, sizeof(econet_data->econet_gpios));

	/* 
	 * Try to get the data line GPIOS.
	 *
	 */

	for (count = 0; count < 8; count++)
	{
		econet_data->econet_gpios[EGP_D0+count] = devm_gpiod_get_index(dev, "data", count, GPIOD_OUT_HIGH);
		ECONET_GPIOERR(EGP_D0+count);
#ifdef ECONET_GPIO_NEW
		/*
		 * The data_desc_array (and similar other arrays)
		 * are pre-setup here for use with the gpiod_array... functions.
		 *
		 * (Not that that really helped performance, it seems, but
		 * it was worth a try.)
		 *
		 */

		data_desc_array[count] = econet_data->econet_gpios[EGP_D0+count];
#endif
	}

	/*
	 * Next try to get the address line GPIOs
	 *
	 */

	for (count = 0; count < 2; count++)
	{
		econet_data->econet_gpios[EGP_A0+count] = devm_gpiod_get_index(dev, "addr", count, GPIOD_OUT_HIGH);
		ECONET_GPIOERR(EGP_A0+count);
#ifdef ECONET_GPIO_NEW
		a01rw_desc_array[count] = econet_data->econet_gpios[EGP_A0+count];
#endif
	}

	/* Get the /RST pin & set High (unreset) */

	ECONET_GETGPIO(EGP_RST, "rst", GPIOD_OUT_HIGH);

	/* Get the /CS pin and set High (unselected on
	 * v1 hardware, might be selected on v2) 
	 * 
	 * (TODO: consider whether this should be GPIOD_OUT_LOW
	 * on v2 hardware.)
	 */

	ECONET_GETGPIO(EGP_CS, "cs", GPIOD_OUT_HIGH);
	
	/*
	 * The /CSRETURN pin is used on v1 boards as feedback
	 * from the far side of the level shifter so that we
	 * know when /CS has made it to the ADLC. The v2 board
	 * was sensibly redesigned (credits: KL, Arg, others)
	 * to have a one-shot circuit. So the /CSRETURN pin 
	 * became disused. It was then redeployed in ALT5 mode
	 * to provide a PWM clock to v2 boards, from which 
	 * those boards provided a network clock through
	 * "traditional" circuitry similar to a conventional,
	 * external, Econet clock. So on a v1 board, we need
	 * to get the /CSRETURN GPIO, but we don't on a v2
	 * because the DT sets it up as PWM and we do the
	 * rest of that setup later.
	 *
	 */

	if (econet_data->hwver < 2) 
		ECONET_GETGPIO(EGP_CSRETURN, "csr", GPIOD_IN);

	/*
	 * Get the RnW pin
	 */

	ECONET_GETGPIO(EGP_RW, "rw", GPIOD_OUT_HIGH);
#ifdef ECONET_GPIO_NEW
	a01rw_desc_array[2] = econet_data->econet_gpios[EGP_RW];
#endif

	/* 
	 * Obtain the v2 busy pin. This pin is NC on v1 boards
	 * so grabbing the GPIO makes no odds.
	 */

	ECONET_GETGPIO(EGP_DIR, "busy", GPIOD_IN); // Only used on v2

	/*
	 * Obtain the IRQ pin from the ADLC. Set to input. 
	 */

	ECONET_GETGPIO(EGP_IRQ, "irq", GPIOD_IN);

	/* 
	 * Obtain the read & write LED pins - only used 
	 * on v2 boards, but NC on v1 so no harm in 
	 * grabbing them.
	 */

	ECONET_GETGPIO(EGP_READLED, "readled", GPIOD_OUT_HIGH); 
	ECONET_GETGPIO(EGP_WRITELED, "writeled", GPIOD_OUT_LOW); 

	/* 
	 * Complain if any of those GPIOs weren't obtained.
	 */

	for (count = 0; count < 19; count++)
		ECONET_GPIOERR(count);

	/* 
	 * If on v1 hardware, set CSRETURN to input.
	 *
	 * This is likely to be redundant given we do it above
	 * when grabbing the GPIO. Try commenting out.
	 */

	/*
	if (econet_data->hwver < 2)
		gpiod_direction_input(ECOPIN(EGP_CSRETURN));
	*/

#ifdef ECONET_GPIO_NEW
	/* 
	 * If in NEW mode, copy the A01RW array into positions 8-10
	 * of the data array so that the address & RW can be set
	 * at same time if necessary. On a read, we set the address & 
	 * RW first, and then lie to the gpiod_array...() function 
	 * there are only 8 descriptors in the array.
	 *
	 */

	memcpy (&(data_desc_array[8]), a01rw_desc_array, sizeof(a01rw_desc_array));
#endif

	/* Initialize some debug instrumentation */
	tx_packets = 0; 

	/* See if our ancient econet_ndelay code is disabled */
#ifdef ECONET_NO_NDELAY
	printk (KERN_INFO "econet-gpio: Old econet_ndelay() code disabled. This is Good.\n");
#endif

	/* Iniialize kfifos */

	result = kfifo_alloc(&econet_rx_queue, 65536, GFP_KERNEL);
	if (result)
	{
		printk (KERN_INFO "econet-gpio: Failed to allocate kernel RX fifo\n");
		return -ENOMEM;
	}

	econet_rx_queue_initialized = 1;

	result = kfifo_alloc(&econet_tx_queue, 65536, GFP_KERNEL);
	if (result)
	{
		printk (KERN_INFO "econet-gpio: Failed to allocate kernel TX fifo\n");
		return -ENOMEM;
	}

	econet_tx_queue_initialized = 1;

	/* Init spinlocks */

	spin_lock_init(&econet_irqstate_spin);
	spin_lock_init(&econet_tx_spin);

	/* See what sort of system we have.
	 *
	 * We still have to do this to get the
	 * peripheral base address, even though we 
	 * are trying to use gpiod_ functions. Since
	 * those functions introduce too much latency in
	 * the IRQ context, we must still write to the
	 * h/w directly, for which we need the base
	 * address.
	 */

	econet_data->peribase = 0xFE000000; // Assume Pi4-class unless we find otherwise
	// Disused: econet_data->clockdiv = ECONET_GPIO_CLOCKDIVFAST; // Larger divider default unless we're sure we don't want it

	if (of_machine_is_compatible("raspberrypi,4-model-b"))
		printk (KERN_INFO "econet-gpio: This appears to be a Pi4B\n");
	else if (of_machine_is_compatible("raspberrypi,400"))
		printk (KERN_INFO "econet-gpio: This appears to be a Pi400\n");
	else if (of_machine_is_compatible("raspberrypi,3-model-b"))
	{
		econet_data->peribase = 0x3F000000;
		printk (KERN_INFO "econet-gpio: This appears to be a Pi3\n");
	}
	else if (of_machine_is_compatible("raspberrypi,3-model-b-plus"))
	{
		econet_data->peribase = 0x3F000000;
		printk (KERN_INFO "econet-gpio: This appears to be a Pi3B+\n");
	}
	else if (of_machine_is_compatible("raspberrypi,model-zero-w") || of_machine_is_compatible("raspberrypi,model-zero"))
	{
		econet_data->peribase = 0x20000000;
		printk (KERN_INFO "econet-gpio: This appears to be a PiZero (reliability uncertain)\n");
	}
	else if (of_machine_is_compatible("raspberrypi,model-zero-2-w") || of_machine_is_compatible("raspberrypi,model-zero-2"))
	{
		econet_data->peribase = 0x3F000000;
		printk (KERN_INFO "econet-gpio: This appears to be a PiZero2\n");
	}
	else 
	{
		printk (KERN_INFO "econet-gpio: Machine compatibility uncertain - assuming Peripheral base at 0xFE000000\n");
	}

	request_region(GPIO_PERI_BASE, GPIO_RANGE, DEVICE_NAME);
	GPIO_PORT = ioremap(GPIO_PERI_BASE, GPIO_RANGE);

	if (!GPIO_PORT)
	{
		printk (KERN_INFO "econet-gpio: GPIO base remap failed.\n");
		return -ENODEV;
	}

	/* 
	 * If version 2 or greater hardware,
	 * set up the ADLC clock on GPIO4.
	 *
	 * This is not done on v1 hardware,
	 * because those boards have an
	 * on-board ADLC clock generator.
	 *
	 */

	if (econet_data->hwver >= 2)
	{

		int ret;
		int err;

		/*
		 * Obtain the clock
		 *
		 */

		econet_data->gpio4clk = devm_clk_get(dev, NULL);

		/*
		 * If we did not obtain the clock, complain
		 * and exit.
		 *
		 */

		if (IS_ERR(econet_data->gpio4clk))
		{
			printk (KERN_ERR "econet-gpio: Unable to obtain GPIO 4 clock (GPCLK0) for ADLC clock (%ld)\n", PTR_ERR(econet_data->gpio4clk));
			econet_remove(NULL);
			return PTR_ERR(econet_data->gpio4clk);
		}
	
		/* 
		 * Find the frequency from the DT.
		 * This is here to avoid hard coding, and so
		 * that if any future board revision needs
		 * a clock other than 8MHz, it can be 
		 * configured in the DT.
		 *
		 * If not defined in the DT, give up and quit.
		 *
		 */

		if ((ret = of_property_read_u32(dev->of_node, "clock-frequency", &gpio4clk_rate)))
		{
			printk (KERN_ERR "econet-gpio: Unable to find clock frequency for gpio4 (ADLC) clock in device tree\n");
			econet_remove(NULL);
			return ret;
		}
	
		/*
		 * Reassure the user that we are
		 * setting the clock, and to what
		 * frequency.
		 *
		 */

		printk (KERN_INFO "econet-gpio: Setting gpio4 ADLC clock (GPCLK0) to %dHz\n", gpio4clk_rate);
	
		/* 
		 * Set the rate & enable clock.
		 *
		 */

		clk_set_rate (econet_data->gpio4clk, gpio4clk_rate);
		clk_prepare (econet_data->gpio4clk);

	
		/* 
		 * Similarly, if we are on a v2 board, we
		 * set up a PWM on GPIO18 to enable those
		 * boards to provide a network clock to the
		 * Econet if desired.
		 *
		 */

		econet_data->gpio18pwm = devm_pwm_get(dev, "netclk");

		/*
		 * If we did not manage to get a handle
		 * to the PWM, give up and quit.
		 *
		 */

		if (IS_ERR(econet_data->gpio18pwm))
		{
			printk (KERN_ERR "econet-gpio: Unable to obtain BCM 18 PWM (PWM0) for Econet clock (Error %ld)\n", PTR_ERR(econet_data->gpio18pwm));
			econet_remove(NULL);
			return PTR_ERR(econet_data->gpio18pwm);
		}

		/*
		 * Attempt to configure the PWM to 
		 * 5us period, 1us mark.
		 *
		 * Give up & quit if we don't 
		 * succeed.
		 *
		 */

		if ((err = pwm_config(econet_data->gpio18pwm, 1000, 5000)))
		{
			printk (KERN_ERR "econet-gpio: Econet clock config failure during probe! (%d)\n", err);
			econet_remove(NULL);
			return (-ENODEV);
		}

		/* 
		 * Attempt to enable the PWM clock.
		 * Give up & quit if this fails.
		 *
		 */

		if ((err = pwm_enable(econet_data->gpio18pwm)))
		{
			printk (KERN_ERR "econet-gpio: Econet clock enable failure during probe! (%d)\n", err);
			econet_remove(NULL);
			return (-ENODEV);
		}

		/* 
		 * Announce our momentous success
		 * to the user via dmesg.
		 *
		 */

		printk (KERN_INFO "econet-gpio: Econet clock enabled on BCM 18 at 1us/5us\n");
	}

	/*
	 * Now create the device in /dev, since we're all set up 
	 *
	 */

	econet_data->major=register_chrdev(0, DEVICE_NAME, &econet_fops);

	/*
	 * If device create fails, give up & quit.
	 *
	 */

	if (econet_data->major < 0)
	{
		printk (KERN_INFO "econet-gpio: Failed to obtain major device number.\n");
		econet_remove(NULL);
		return econet_data->major;
	}

	/*
	 * Create the device class.
	 *
	 * It appears the class_create() semantics
	 * changed at Linux kernel 6.4.0 or thereabouts,
	 * so we detect the version & compile accordingly.
	 *
	 * If class creation fails, give up & quit.
	 *
	 */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,4,0)
	if (IS_ERR(econet_class = class_create(THIS_MODULE, CLASS_NAME)))
#else
	if (IS_ERR(econet_class = class_create(CLASS_NAME)))
#endif
	{
		printk (KERN_INFO "econet-gpio: Failed creating device class\n");
		econet_remove(NULL);
		return PTR_ERR(econet_class);
	}

	/*
	 * Flag class as initialized so that 
	 * econet_remove() can destroy it
	 * without error.
	 *
	 */

	econet_class_initialized = 1;

	/*
	 * Create device within class, 
	 * and give up & quit if that fails.
	 *
	 */

	if (IS_ERR(econet_data->dev = device_create(econet_class, NULL, MKDEV(econet_data->major, 0), NULL, DEVICE_NAME)))
	{
		printk (KERN_INFO "econet-gpio: Failed creating device\n");
		econet_remove(NULL);
		return PTR_ERR(econet_data->dev);
	}
		
	/*
	 * Flag device as created so that
	 * econet_remove() can destroy it without
	 * error.
	 *
	 */

	econet_device_created = 1;

	/* Initialize queue to userspace. */

	init_waitqueue_head(&(econet_data->econet_read_queue));

	/*
	 * Ensure ADLC in consistent state -
	 * put /RST into reset, wait, and then 
	 * unreset.
	 *
	 * The timer here used to be 100ms, but 
	 * it appears that was unnecessarily long
	 * (after I re-read the 68B54 specification
	 * with my glasses *on*), and so it was
	 * shortened. Considerably.
	 *
	 */

	econet_set_rst(ECONET_GPIO_RST_RST);
	udelay(10);
	econet_set_rst(ECONET_GPIO_RST_CLR);

	/*
	 * For v1 hardware, which is incompatible
	 * with 'new mode', we probe the hardware.
	 * The econet_probe_adapter() routine basically
	 * puts /CS active and looks to see if the
	 * return signal comes back on /CSRETURN. Then
	 * it puts it inactive and checks the return
	 * signal goes away. This was thought to be a 
	 * good enough way to see if there was a
	 * v1 board actually present.
	 *
	 * It does not test the ADLC itself...
	 *
	 * In the future, maybe we'll turn IRQs off,
	 * put the TXIE flag on, and see if we get an
	 * IRQ a bit later. Perhaps for v2.2...
	 *
	 * If the probe fails, give up & quit.
	 *
	 */

#ifndef ECONET_GPIO_NEW
	if (econet_data->hwver == 1 && !econet_probe_adapter())
	{
		econet_remove(NULL);
		return -ENODEV;
	}
#endif

	/*
	 * Starting to cook on gas now.
	 *
	 * Do a full reset, which will clear the station
	 * array set, and move to read mode in the 
	 * ADLC.
	 *
	 */

	econet_reset();

	econet_set_read_mode();

	/* 
	 * Read the SRs ready to report to userspace
	 * via dmesg as to clock status, and tell them
	 * what was in the SRs as well. This is handy 
	 * since an experienced user can tell whether 
	 * the SRs have actually read properly from the
	 * hardware. E.g. if you see SR1 & SR2 both 0x00,
	 * it will think there is a clock, but actually
	 * that's an indication that there's no hardware.
	 * Likewise, I once saw 0xa5 in both (which is
	 * wholly bogus) when I was accidentally reading
	 * the wrong IO port. So it's handy to see what
	 * state they are in when the module reloads.
	 *
	 */

	sr1 = econet_read_sr(1);
	sr2 = econet_read_sr(2);

	printk (KERN_ERR "econet-gpio: %s (SR1 = 0x%02x, SR2 = 0x%02x)\n", (sr2 & ECONET_GPIO_S2_DCD) ? "No clock!" : "Clock detected", sr1, sr2);

	/* 
	 * Get ready to start the engines:
	 *
	 * Grab the IRQ line and set IRQ state.
	 *
	 */

	econet_data->irq = gpiod_to_irq(ECOPIN(EGP_IRQ));

	econet_set_irq_state(1);

	/* Attempt to request IRQ and give up if unsuccessful.
	 * Without an IRQ into the module, there's nothing useful
	 * we can do.
	 *
	 */

	if (
			(econet_data->irq < 0) /* Didn't get IRQ */
		|| (	(err = request_irq(econet_data->irq, econet_irq, 
					((econet_data->hwver < 2) ? 
					 IRQF_TRIGGER_LOW :  /* /IRQ on v1 boards */
					 IRQF_TRIGGER_HIGH), /* IRQ high = interrupt on v2 baords */
					THIS_MODULE->name, 
					THIS_MODULE->name)) != 0
		   )
	   )
	{
		printk (KERN_INFO "econet-gpio: Failed to request IRQ\n");
		econet_remove(NULL);
		return err;
	}

	/* Turn IRQs off */

	econet_irq_mode(0);

	/* Show that we are ready for service */

	econet_data->initialized = 1;

	/* Return success */

	return 0;

}

/* 
 * econet_remove()
 *
 * Module exit routine 
 *
 */

static int econet_remove(struct platform_device *pdev)
{

	/* Turn off the read/write LEDs */

	if (ECOPIN(EGP_READLED))
		gpiod_direction_output(ECOPIN(EGP_READLED), GPIOD_OUT_LOW);

	if (ECOPIN(EGP_WRITELED))
		gpiod_direction_output(ECOPIN(EGP_WRITELED), GPIOD_OUT_LOW);

	/*
	 * If we have econet_data, clean up the other
	 * things which may be initialized
	 *
	 */

	if (econet_data)
	{

		/*
		 * If we created a device, destroy it
		 *
		 */

		if (econet_device_created)
		{
			device_destroy(econet_class, MKDEV(econet_data->major, 0));
			unregister_chrdev(econet_data->major, DEVICE_NAME);
		}

		/* 
		 * If we successfully obtained an IRQ, free it 
		 *
		 */

		if (econet_data->irq)
			free_irq(econet_data->irq, THIS_MODULE->name);

		/*
		 * Free private storage
		 *
		 */

		kfree(econet_data);

	}

	/*
	 * Destroy class if we have one
	 *
	 */

	if (econet_class_initialized)
		class_destroy(econet_class);
	
	/*
	 * Get rid of our rx & tx fifos
	 *
	 */

	if (econet_rx_queue_initialized) kfifo_free(&econet_rx_queue);
	if (econet_tx_queue_initialized) kfifo_free(&econet_tx_queue);

	/*
	 * Unmap IO port if we got one.
	 *
	 */

	if (GPIO_PORT)
	{
		iounmap(GPIO_PORT);
		GPIO_PORT = NULL;
	}

	/*
	 * Let the nice user know we have shut down
	 *
	 */

	printk(KERN_INFO "econet-gpio: Unprobed.\n");

	/*
	 * Return success
	 *
	 */

	return 0;

}

/* Register module functions and set up DT match */

const struct of_device_id econet_of_match[] = {
	{ .compatible = "econet-gpio" },
	{ }
};

MODULE_DEVICE_TABLE(of, econet_of_match);

static struct platform_driver econet_driver = {
	.driver = {
			.name = "econet-gpio",
			.of_match_table = of_match_ptr(econet_of_match),
			.owner = THIS_MODULE,
		},
	.probe = econet_probe,
	.remove = econet_remove,
};

module_platform_driver(econet_driver);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Royle");
MODULE_DESCRIPTION("Acorn Econet(R) to IP bridge");
MODULE_VERSION("2.10");
