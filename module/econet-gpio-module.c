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

/* LEVEL TRIGGERED CLEANED UP CODE */

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
#include <linux/version.h>

#include <asm/uaccess.h>

#include "../include/econet-gpio.h"

#define ECONET_GPIO_CLOCK_DUTY_CYCLE  1000   /* In nanoseconds - 2MHz clock is 500 ns duty cycle, 1MHz is 1us, or 1000ns */
#define ECONET_GPIO_CLOCK_US_DUTY_CYCLE	1	/* In uSecs - 1us is the cycle time on a 1MHz clock, which is what the existing hardware has built on */

unsigned long *GPIO_PORT;
unsigned GPIO_RANGE = 0x40;
unsigned long *GPIO_CLK;
unsigned GPIO_CLK_RANGE = 0xA8;
unsigned long *GPIO_PWM;
unsigned GPIO_PWM_RANGE = 0x28;

// This used to do an RX RESET as well, but now it doesn't.
#define econet_discontinue() \
		econet_pkt_rx.length = econet_pkt_rx.ptr = 0; \
		econet_set_chipstate(EM_IDLE); \
		econet_write_cr(ECONET_GPIO_CR2, C2_READ); \
		econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_DISC); /* Discontinue reception */ 

#define econet_rx_cleardown() \
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);  /* We use this here to clear the RX status */ 

#define econet_rx_cleardown_reset() \
			econet_write_cr(ECONET_GPIO_CR1, C1_READ | ECONET_GPIO_C1_RX_RESET); /* Maybe try commenting this out to see if we pick up receptions immediately after transmissions? */ \
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);  /* We use this here to clear the RX status */ \
			econet_write_cr(ECONET_GPIO_CR1, C1_READ)

#define econet_set_tx_status(x) \
	atomic_set(&(econet_data->tx_status), (x))

#define econet_set_irq_state(x) \
	atomic_set(&(econet_data->irq_state), (x))

#define econet_get_irq_state()	atomic_read(&(econet_data->irq_state))

#define econet_get_tx_status() atomic_read(&(econet_data->tx_status))

u8 sr1, sr2;
//long gpioset_value;
u32 gpioset_value;

u8 econet_gpio_reg_obtained[19];

u8 econet_gpio_pins[19];
	
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

/* WRitefd mutex */
struct mutex econet_writefd_mutex;

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
void econet_set_pwm(uint8_t, uint8_t);

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

/* This routine is no longer used in normal operations and only gets called for testing purposes */
/* All bus direction changes are now done inside econet_read_sr() or econet_write_cr() */

void econet_set_dir(short d)
{

	writel((readl(GPIO_PORT + (ECONET_GPIO_PIN_DATA / 10)) & ~ECONET_GPIO_DATA_PIN_MASK) | 
		(d == ECONET_GPIO_WRITE ? ECONET_GPIO_DATA_PIN_OUT : 0),
		GPIO_PORT + (ECONET_GPIO_PIN_DATA / 10));

	econet_set_rw(d);

	econet_data->current_dir = d;

}

#define econet_write_fifo(x) econet_write_cr(3, (x))
#define econet_write_last(x) econet_write_cr(4, (x))

/* econet_write_cr - write value to ADLC control register
 */
void econet_write_cr(unsigned short r, unsigned char d)
{
	//unsigned long gpioval, gpiomask;
	u32 gpioval, gpiomask;

	if (r > 4)
	{
		printk (KERN_ERR "ECONET-GPIO: Attempt to write to CR%d ! What is going on ?", r);
		return;
	}

	r--;

	gpiomask = ECONET_GPIO_CLRMASK_DATA | ECONET_GPIO_CLRMASK_RW | ECONET_GPIO_CLRMASK_ADDR;

	gpioval = (r & 0x03) << ECONET_GPIO_PIN_ADDR;
	gpioval |= (d << ECONET_GPIO_PIN_DATA);

	// No need to set RW because it will be 0 by virtue of the first assignment to gpioval above.

	if (econet_data->hwver >= 2)
		while (econet_isbusy());

	// Put that lot on the GPIO
	writel(gpioval, GPIO_PORT+GPSET0);
	writel((~gpioval) & gpiomask, GPIO_PORT + GPCLR0);

	// Now swing our own bus direction round

	if (econet_data->current_dir != ECONET_GPIO_WRITE)
	{
		writel((readl(GPIO_PORT + (ECONET_GPIO_PIN_DATA / 10)) & ~ECONET_GPIO_DATA_PIN_MASK) | ECONET_GPIO_DATA_PIN_OUT, GPIO_PORT + (ECONET_GPIO_PIN_DATA / 10));
		econet_data->current_dir = ECONET_GPIO_WRITE;
	}

	barrier();

	// Enable nCS
	econet_set_cs(ECONET_GPIO_CS_ON);

	// If v1 hardware, wait until we know CS has reached the ADLC
	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
		// 20220505 And wait a cycle before turning it off again
		barrier();
	}
	else
		barrier();

	// Disable nCS again
	econet_set_cs(ECONET_GPIO_CS_OFF);

	// Delay here to allow chip to settle. We had this in write_bus() because it appeared
	// to avoid duplicate writes

	barrier();

	if (econet_data->hwver < 2)
	{
		// ? Try a barrier() here to see if we get a suitable delay.
		econet_ndelay(ECONET_GPIO_CLOCK_DUTY_CYCLE);
	}
	else
		while (econet_isbusy()); // Wait until the ADLC has read our data. Not massively reliable yet.. SHouldn't be required, but seems to be!
}

/* econet_read_sr - read value from ADLC status register
 */

#define econet_read_fifo() econet_read_sr(3)

unsigned char econet_read_sr(unsigned short r)
{
	unsigned char d;
	//unsigned long gpioval, gpiomask;
	u32 gpioval, gpiomask;

	if (r > 4)
	{
		printk (KERN_ERR "ECONET-GPIO: Attempt to read SR%d ! What is going on ?\n", r);
		return 0;
	}

	r--;

	if (econet_data->hwver >= 2)
		while (econet_isbusy());

	// First, set the data pins to read if need be

	if (econet_data->current_dir != ECONET_GPIO_READ)
	{
		econet_data->current_dir = ECONET_GPIO_READ;
		writel(readl(GPIO_PORT + (ECONET_GPIO_PIN_DATA / 10)) & ~ECONET_GPIO_DATA_PIN_MASK, GPIO_PORT + (ECONET_GPIO_PIN_DATA / 10));
	}

	barrier(); // In case needed on a bus direction change

	// New code - sets up a single gpio value & mask and plonks it on the hardware in one go
	// And the mask, so that we can write the 0s properly
	gpiomask = ECONET_GPIO_CLRMASK_ADDR | ECONET_GPIO_CLRMASK_RW;

	// Next, put the address into our prepared value - Nothing has gone in this before, so a straigth = rather than |= will be fine
	gpioval = (r << ECONET_GPIO_PIN_ADDR) | ECONET_GPIO_CLRMASK_RW;

	// Now, put that on the hardware

	writel(gpioval, GPIO_PORT + GPSET0);
	writel((~gpioval) & gpiomask, GPIO_PORT + GPCLR0);
	
	// Shouldn't need a barrier here because apparently writel() has one in it.

	barrier();

	// Waggle nCS appropriately
	
	econet_set_cs(ECONET_GPIO_CS_ON);

	if (econet_data->hwver < 2)
	{
		econet_wait_pin_low(ECONET_GPIO_PIN_CSRETURN, (ECONET_GPIO_CLOCK_DUTY_CYCLE));
	}
	else
		barrier();

	econet_set_cs(ECONET_GPIO_CS_OFF);	

	barrier();

	if (econet_data->hwver < 2)
	{
		econet_ndelay(100);
	}
	else
		while (econet_isbusy());

	d = (readl(GPIO_PORT + GPLEV0) & ECONET_GPIO_CLRMASK_DATA) >> ECONET_GPIO_PIN_DATA;

	return d;	
}

/* Release the GPIO pins we successfully obtained */
void econet_gpio_release_pins(void)
{

	unsigned short counter;
	unsigned short add = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
	add = 512;
#endif	

	for (counter = 0; counter < 19; counter++)
		if(econet_gpio_reg_obtained[counter])
			gpio_free(econet_gpio_pins[counter]+add);

	return;

}

/* Probe the hardware, once GPIOs obtained */

int econet_probe_adapter(void)
{

	struct device_node *econet_device;

	if ((econet_device = of_find_compatible_node(NULL, NULL, "econet-gpio")))
		printk (KERN_INFO "ECONET-GPIO: Found hardware in device tree.");

	of_node_put (econet_device); // Supports NULL parameter apparently, so doesn't need to be guarded by if()

	// Do a reset to make sure IRQ line is clear

	econet_set_rst(ECONET_GPIO_RST_RST);
	msleep(100);
	econet_set_rst(ECONET_GPIO_RST_CLR);

	// Look at the IRQ line and see if it's high (v1) or low (v2 onwards), and if there's a device tree entry then
	// it will be because there was an EEPROM

	if (econet_device || (econet_gpio_pin(ECONET_GPIO_PIN_IRQ) == 0)) // Likely v2 hardware
	{

		// Set nCS active and we should see BUSY immediately
		econet_data->hwver = 2;
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

	//unsigned long t; /* Variable to read / write GPIO registers in this function */
	u32 t; /* Variable to read / write GPIO registers in this function */
	unsigned short counter;
	int err;
	u32 add = 0;


// This is an intermediate fix for the change in GPIO numbers. No postcards are required complaining about it, I know
// it needs updating so that we used the gpiod functions. Thanks. CR

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
	add = 512;
#endif	

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
	econet_gpio_pins[EGP_READLED] = ECONET_GPIO_PIN_LED_READ;
	econet_gpio_pins[EGP_WRITELED] = ECONET_GPIO_PIN_LED_WRITE;

	/* Zero out the pin request array */

	for (counter = 0; counter < 19; counter++)
		econet_gpio_reg_obtained[counter] = 0;
	
	/* Request the pins */

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "ECONET-GPIO: Requesting GPIOs\n");
#endif

	for (counter = 0; counter < 19; counter++)
	{
		//if (counter != EGP_RST)
		{
		if ((err = gpio_request(econet_gpio_pins[counter]+add, THIS_MODULE->name)) != 0)
		{
			printk (KERN_INFO "ECONET-GPIO: Failed to request GPIO BCM %d\n", econet_gpio_pins[counter]);
			econet_gpio_release_pins();
			return err;
		}
		else
		{
			econet_gpio_reg_obtained[counter] = 1;	
			//gpio_export(econet_gpio_pins[counter], false);
		}
		}
	}

	// Test gpiod_ interface for RST pin
	
	/*
	if (IS_ERR(gpiod_get(econet_data->dev, "rst", GPIOD_OUT_HIGH)))
		printk (KERN_INFO "ECONET-GPIO: gpiod_get() failed");
	*/

#ifdef ECONET_GPIO_DEBUG_SETUP
	printk (KERN_INFO "ECONET-GPIO: GPIOs successfully requested.\n");
	printk (KERN_INFO "ECONET-GPIO: Requesting IRQ on BCM pin %02d\n", econet_gpio_pins[EGP_IRQ]);
#endif

	gpio_direction_input(econet_gpio_pins[EGP_IRQ]);

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
	econet_set_dir(ECONET_GPIO_READ);

	INP_GPIO(ECONET_GPIO_PIN_ADDR);
	INP_GPIO(ECONET_GPIO_PIN_ADDR + 1);
	OUT_GPIO(ECONET_GPIO_PIN_ADDR);
	OUT_GPIO(ECONET_GPIO_PIN_ADDR + 1);

	/* THIS STOP EVERYTHING WORKING!
	INP_GPIO(ECONET_GPIO_PIN_BOARDSEL);
	INP_GPIO(ECONET_GPIO_PIN_BOARDSEL + 1);
	OUT_GPIO(ECONET_GPIO_PIN_BOARDSEL);
	OUT_GPIO(ECONET_GPIO_PIN_BOARDSEL + 1);
	*/

	INP_GPIO(ECONET_GPIO_PIN_RST);
	OUT_GPIO(ECONET_GPIO_PIN_RST);

	INP_GPIO(ECONET_GPIO_PIN_IRQ);

	INP_GPIO(ECONET_GPIO_PIN_CS);
	OUT_GPIO(ECONET_GPIO_PIN_CS);

	INP_GPIO(ECONET_GPIO_PIN_RW);
	OUT_GPIO(ECONET_GPIO_PIN_RW);

	if (econet_data->hwver < 2) // CS RETURN only used on v1 hardware boards. Used for network clock output on v2r3 onwards.
		INP_GPIO(ECONET_GPIO_PIN_CSRETURN);

	INP_GPIO(ECONET_GPIO_PIN_BUSY); // v2 hardware busy line

	gpio_direction_output(econet_gpio_pins[EGP_READLED], 1);
	gpio_direction_output(econet_gpio_pins[EGP_WRITELED], 0);

	// Ask for clock function on CLK pin

	t = (readl(GPIO_PORT) & ~(0x07 << (3 * ECONET_GPIO_PIN_CLK))) | (ECONET_GPIO_CLK_ALT_FUNCTION << (3 * ECONET_GPIO_PIN_CLK));
	writel (t, GPIO_PORT); /* Select alt function for clock output pin */

	// Now set the clock up on it

	request_region(CLOCK_PERI_BASE, GPIO_CLK_RANGE, DEVICE_NAME);

	GPIO_CLK = ioremap(CLOCK_PERI_BASE, GPIO_CLK_RANGE);

	if (GPIO_CLK)
	{
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "ECONET-GPIO: Clock base remapped to %p\n", GPIO_CLK);
#endif
	}
	else
	{
		printk (KERN_INFO "ECONET-GPIO: Clock base remap failed.\n");
		econet_gpio_release_pins();
		return 0;
	}
	
	writel ((readl(GPIO_CLK + ECONET_GPIO_CMCTL) & ~0xF0) | ECONET_GPIO_CLOCKDISABLE, GPIO_CLK + ECONET_GPIO_CMCTL); // Disable clock

	barrier();

	while (readl(GPIO_CLK + ECONET_GPIO_CMCTL) & 0x80); // Wait for not busy

	// Select speed

	writel(ECONET_GPIO_CLOCKSOURCEPLLD, GPIO_CLK + ECONET_GPIO_CMCTL); // Select PLLD

	barrier();
	
	writel(econet_data->clockdiv, GPIO_CLK + ECONET_GPIO_CMCTL + 1);

	barrier();

	writel(ECONET_GPIO_CLOCKENABLE, GPIO_CLK + ECONET_GPIO_CMCTL); // Turn the clock back on

	barrier();

	// Set up access to PWM control so we can put a network clock waveform out on pin 18 if someone wants us to

	request_region(PWM_PERI_BASE, GPIO_PWM_RANGE, DEVICE_NAME);

	GPIO_PWM = ioremap(PWM_PERI_BASE, GPIO_PWM_RANGE);

	if (GPIO_PWM)
	{
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "ECONET-GPIO: PWM base remapped to %p\n", GPIO_PWM);
#endif
	}
	else
	{
		printk (KERN_INFO "ECONET-GPIO: PWM base remap failed.\n");
		econet_gpio_release_pins();
		return 0;
	}
	
	if (!econet_probe_adapter())
	{
		econet_gpio_release_pins();
		printk (KERN_ERR "ECONET-GPIO: Hardware not found.\n");
		return -1;
	}

	if (econet_data->hwver >= 2) // Attempt to initialize PWM clock on /CSRETURN (unused on v2 and above)
	{
		
		uint32_t	clockdiv;

		// Ask for ALT5 function (PWM0) on pin 18

		t = (readl(GPIO_PORT + (ECONET_GPIO_PIN_NET_CLOCK / 10)) & ~(0x07 << (3 * (ECONET_GPIO_PIN_NET_CLOCK % 10)))) | (0x02 << (3 * (ECONET_GPIO_PIN_NET_CLOCK % 10))); // 0x02 is the sequence for ALT 5.
		writel (t, GPIO_PORT + (ECONET_GPIO_PIN_NET_CLOCK / 10)); /* Select alt function for clock output pin */

		// Put a default 5us period with 1us mark out but set it up on a 4MHz clock so that we can do quarter point marks

		while (readl(GPIO_CLK + ECONET_GPIO_PWM_CLKCTL) & 0x80) // Wait for not busy
		{
			writel ((readl(GPIO_CLK + ECONET_GPIO_PWM_CLKCTL) & ~0xF0) | ECONET_GPIO_CLOCKDISABLE, GPIO_CLK + ECONET_GPIO_PWM_CLKCTL); // Disable clock
			barrier();
		}

		// Select clock - PLLD
	
		writel(ECONET_GPIO_CLOCKSOURCEPLLD, GPIO_CLK + ECONET_GPIO_PWM_CLKCTL); // Select PLLD
	
		barrier();
		
		// Note, we run the PWM clock at 4MHz so that we can get quarter-us divisions for
		// Period and Mark.

		if ((of_machine_is_compatible("raspberrypi,4-model-b"))|| (of_machine_is_compatible("raspberrypi,400"))) // Bigger divider because PLLD is 750MHz
			clockdiv = (ECONET_GPIO_CLOCKPASSWD | (187 << 12) | 512); // 750 / 187.5 = 4
		else
			clockdiv = (ECONET_GPIO_CLOCKPASSWD | (125 << 12));
			
		writel(clockdiv, GPIO_CLK + ECONET_GPIO_PWM_CLKDIV);

		barrier();

		writel(ECONET_GPIO_CLOCKENABLE, GPIO_CLK + ECONET_GPIO_PWM_CLKCTL); // Turn the clock back on
	
		barrier();
	
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "ECONET-GPIO: Contents of PWMCTL = %lX, PWMRNG = %lX, PWMDAT = %lX\n", *(GPIO_PWM + PWM_CTL), *(GPIO_PWM + PWM_RNG1), *(GPIO_PWM + PWM_DAT1));
#endif

		// period 20 = 5us and mark 4 = 1us - Default clock setting. Change via ioctl from userspace

		econet_set_pwm(20, 4); 

	}

	econet_data->irq = gpio_to_irq(econet_gpio_pins[EGP_IRQ]+add);

	econet_set_irq_state(1);

	// 20210919 OLD if ((econet_data->irq < 0) || ((err = request_irq(econet_data->irq, econet_irq, IRQF_SHARED | ((econet_data->hwver < 2) ? IRQF_TRIGGER_FALLING : IRQF_TRIGGER_RISING), THIS_MODULE->name, THIS_MODULE->name)) != 0))
	if ((econet_data->irq < 0) || ((err = request_irq(econet_data->irq, econet_irq, IRQF_SHARED | ((econet_data->hwver < 2) ? IRQF_TRIGGER_LOW : IRQF_TRIGGER_HIGH), THIS_MODULE->name, THIS_MODULE->name)) != 0))
	{
		printk (KERN_INFO "ECONET-GPIO: Failed to request IRQ on pin BCM %d\n", econet_gpio_pins[EGP_IRQ]);
		econet_gpio_release_pins();
		return err;
	}

#ifdef ECONET_GPIO_DEBUG_IRQ
	printk (KERN_INFO "ECONET-GPIO: GPREN0(%d) = %s, GPFEN0(%d) = %s, GPHEN0(%d) = %s, GPLEN0(%d) = %s\n",
		ECONET_GPIO_PIN_IRQ,
		(readl(GPIO_PORT + GPREN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset",
		ECONET_GPIO_PIN_IRQ,
		(readl(GPIO_PORT + GPFEN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset",
		ECONET_GPIO_PIN_IRQ,
		(readl(GPIO_PORT + GPHEN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset",
		ECONET_GPIO_PIN_IRQ,
		(readl(GPIO_PORT + GPLEN0) & (1 << ECONET_GPIO_PIN_IRQ)) ? "Set" : "Unset");
#endif

	econet_irq_mode(0);

	return 1;
}

void econet_gpio_release(void)
{
	iounmap(GPIO_PORT);

	GPIO_PORT = 0;

	/* IRQs off */

	if (econet_get_chipstate() != EM_TEST)
		econet_irq_mode(0);

	econet_gpio_release_pins();
	free_irq(econet_data->irq, THIS_MODULE->name);
	//printk (KERN_INFO "ECONET-GPIO: Pins and IRQ released.\n");

}

/* Function just to clear the ADLC down - may help when we get repeated collisions */
void econet_adlc_cleardown(unsigned short in_irq)
{

	if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: Performing ADLC chip reset\n");

	if (!in_irq)
		econet_irq_mode(0);

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

	econet_set_chipstate(EM_IDLE);
	econet_set_aunstate(EA_IDLE);
	econet_set_tx_status(ECONET_TX_SUCCESS);
	econet_data->aun_last_writefd = 0;

	if (!in_irq)
		econet_irq_mode(1);
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

	printk (KERN_INFO "ECONET-GPIO: Module reset. AUN mode off. ADLC re-initialized.\n");

}

/* Puts us in read mode & enables IRQs */
/* NB doesn't change AUN state because this function is used *during* 4-way exchanges when moving between states */

void econet_set_read_mode(void)
{

	/* Blank the packet buffers */

	econet_pkt_rx.length = econet_pkt_rx.ptr = 0;

	econet_write_cr(ECONET_GPIO_CR2, C2_READ);
	econet_write_cr(ECONET_GPIO_CR1, C1_READ);

	econet_set_chipstate(EM_IDLEINIT); 

	last_data_rcvd = 0; // Last time we received data off the wire. Detect stuck in read mode when we want to write

	//econet_irq_mode(1);

}

/* Puts us in write mode & enables IRQs */
/* NB doesn't change AUN state because this function is used *during* 4-way exchanges when setting up a new part of the 4-way to transmit */

/* Needs updating so that it claims the line better */

/* Apart from testing, this is only ever called from econet_writefd() in circumstances
   where IRQs are off */

void econet_set_write_mode(struct __econet_pkt_buffer *prepared, int length)
{

	if (econet_pkt_tx.length != 0) // Already in progress
	{
		if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: Flag busy because length != 0\n");
		econet_set_tx_status(ECONET_TX_BUSY);
		return;
	}

	// Set the packet up
	memcpy(&econet_pkt_tx, prepared, length);
	econet_pkt_tx.length = length;
	econet_pkt_tx.ptr = 0;

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

	// if (!(econet_data->aun_mode)) econet_set_tx_status(ECONET_TX_STARTWAIT);

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

	//spin_lock(&econet_irqstate_spin);

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

	//spin_unlock(&econet_irqstate_spin);
}

/* 
 * econet_finish_tx()
 *
 * Routine called when the IRQ routine has put the last byte of a frame into the FIFO.
 * 
 * Signals to the ADLC that it can now put the checksum on the wire and then the closing flag.
 */

void econet_finish_tx(void)
{


#ifdef ECONET_GPIO_DEBUG_TX
	printk (KERN_INFO "ECONET-GPIO: econet_finish_tx(): Finished packet TX\n");
#endif
	/* Tell the 68B54 we've finished so it can end the frame */
	econet_set_chipstate(EM_WRITE_WAIT);
	//econet_write_cr(ECONET_GPIO_CR2, C2_WRITE_EOF);
	econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_TXLAST | ECONET_GPIO_C2_FC | ECONET_GPIO_C2_FLAGIDLE | ECONET_GPIO_C2_PSE); // No RX status reset
#ifdef ECONET_GPIO_DEBUG_TX
	econet_get_sr();
	printk (KERN_INFO "ECONET-GPIO: econet_finish_tx(): SR after C2_WRITE_EOF: SR1 = 0x%02x, SR2 = 0x%02x\n", sr1, sr2);
#endif

}

/* econet_aun_setidle_txstatus()
 * 
 * Puts the AUN state back to IDLE, sets the TX status, clears the TX length and goes back to read mode.
 *
 */

static inline void econet_aun_setidle_txstatus(int aunstate)
{
	econet_pkt_tx.length = 0;
	econet_set_tx_status(aunstate);
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

	if (sr2 & ECONET_GPIO_S2_DCD) // No clock. /* This shouldn't happen at this stage - consider removal - once we get going on a Tx, we can fairly assume the clock will stay around... */
	{
		//econet_pkt_tx.length = 0;
		//econet_set_tx_status(ECONET_TX_NOCLOCK);
		//econet_set_aunstate(EA_IDLE);
		//econet_set_read_mode();
		econet_aun_setidle_txstatus(ECONET_TX_NOCLOCK);
		return;

	}

	if (econet_pkt_tx.length < 4) // Runt
	{
		printk(KERN_INFO "ECONET-GPIO: Attempt to transmit runt frame (len = %d). Not bothering.\n", econet_pkt_tx.length);
		//econet_pkt_tx.length = 0; // Abandon
		//econet_set_tx_status(ECONET_TX_NOTSTART);
		econet_aun_setidle_txstatus(ECONET_TX_NOTSTART);
	}	
	else if (econet_pkt_tx.ptr <= econet_pkt_tx.length)
	{
		// Something to transmit

		int byte_counter;
		int tdra_counter;

		byte_counter = 0;

		econet_set_tx_status(ECONET_TX_INPROGRESS);

		while (byte_counter < 1)
		{

			// Check TDRA available.
	
			loopcount++;

			//printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): Registers on entry - SR1 = 0x%02x, SR2 = 0x%02x, ptr = %d, loopcount = %d\n", sr1, (sr2 = econet_read_sr(2)), econet_pkt_tx.ptr, loopcount);

			if (sr1 & ECONET_GPIO_S1_UNDERRUN) // Underrun
			{
				printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): TX Underrun at byte %02x - abort transmission\n", econet_pkt_tx.ptr);

				econet_aun_setidle_txstatus(ECONET_TX_UNDERRUN);

				//econet_pkt_tx.length = 0;
				//econet_set_tx_status(ECONET_TX_UNDERRUN);
				//econet_set_aunstate(EA_IDLE);
				//econet_set_read_mode();

				return;
			}

			tdra_flag = (sr1  & ECONET_GPIO_S1_TDRA);

#ifdef ECONET_GPIO_DEBUG_TX
			printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): Loop % 2d - TDRA FLAG IS %s. SR1 = 0x%02x, SR2 = 0x%02x\n", loopcount, (sr1 & ECONET_GPIO_S1_TDRA) ? "SET" : "UNSET", sr1, (sr2 = econet_read_sr(2)));

#endif 
			tdra_counter = 0;

			while (tdra_counter++ < 5 && (!tdra_flag)) // Clear down and see if it becomes available
			{
				// Next line reinstated 20211024 to see if it helps
				econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
					ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);
				udelay(20); // Shorter delay
				tdra_flag = ((sr1 = econet_read_sr(1)) & ECONET_GPIO_S1_TDRA); // Only read SR1. (get_sr now always reads both, but we aren't fussed about sr2 here)
			}

			if (!tdra_flag)
			{
				// ANFS 4.25 checks TDRA on IRQ. If not available, it clears RX & TX status and waits for another IRQ

				// Sub-clauses read sr2 beacuse we changed from econet_get_sr() in the loop above, so the sr2 value may be out of date by now.

				if (sr1 & ECONET_GPIO_S1_CTS) // Collision?
				{
					if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): /CTS - Collision? TDRA unavailable on IRQ - SR1 - 0x%02X, SR2 = 0x%02X, ptr = %d, loopcount = %d - abort tx\n", sr1, sr2, econet_pkt_tx.ptr, loopcount);
					econet_aun_setidle_txstatus(ECONET_TX_COLLISION);
					//econet_set_tx_status(ECONET_TX_COLLISION);
				}
				else	
				{
					if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: econet_irq_write(): TDRA not available on IRQ - SR1 = 0x%02x, SR2 = 0x%02x, ptr = %d, loopcount = %d - abort transmission\n", sr1, sr2, econet_pkt_tx.ptr, loopcount);
					econet_aun_setidle_txstatus(ECONET_TX_TDRAFULL);
					//econet_set_tx_status(ECONET_TX_TDRAFULL);
				}

				// Give up and go jettison the packet

				//econet_pkt_tx.length = 0;
				//econet_set_aunstate(EA_IDLE);
				//econet_set_read_mode();

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

			econet_write_fifo(econet_pkt_tx.d.data[econet_pkt_tx.ptr++]);

			/* Last byte of packet? If so, flag end of transmission and show an empty packet */
			if (econet_pkt_tx.ptr == econet_pkt_tx.length)
			{
				econet_finish_tx();
				econet_pkt_tx.length = 0;
				return;
			}
			else
			{

				/* Query whether this is necessary - possible TDRA is self-resetting */
				//econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_RX_STATUS | ECONET_GPIO_C2_CLR_TX_STATUS |
					//ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);
				econet_write_cr(ECONET_GPIO_CR2, ECONET_GPIO_C2_CLR_TX_STATUS |
					ECONET_GPIO_C2_PSE | ECONET_GPIO_C2_FLAGIDLE);
			}

			byte_counter++;

		}

		
	}

	return;

}

/* 
 * econet_process_rx(byte off fifo)
 *
 * DOes nothing more than stick the byte we got off the fifo into our reception buffer.
 *
 * If we are about to overrun, stop it. Update last data received time - used to detect
 * blockages!
 *
 */

static inline void econet_process_rx(unsigned char d)
{

	econet_pkt_rx.d.data[econet_pkt_rx.ptr++] = d;
	if (econet_pkt_rx.ptr == ECONET_MAX_PACKET_SIZE) econet_pkt_rx.ptr--; // We shouldn't be over the limit!
	last_data_rcvd = ktime_get_ns();

}

/* 
 * econet_irq_read() - called by the main IRQ handler when it thinks there is some data to read off the FIFO
 *
 */

void econet_irq_read(void)
{

	unsigned char d;
	unsigned short old_ptr;

//recv_more:


	old_ptr = econet_pkt_rx.ptr;

#ifdef ECONET_GPIO_DEBUG_RX
	printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): SR1 = %02x, SR2 = %02x, ptr = %d, c = %02x %c\n", sr1, sr2, econet_pkt_rx.ptr, d, (d < 32 || d >126) ? '.' : d);
#endif

	last_data_rcvd = ktime_get_ns();

	// Check for errors first, because we were getting RX ABort + Frame Valid at same time!

	if (sr2 & ECONET_GPIO_S2_RX_ABORT) // Abort RX
	{
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX Abort received at ptr = 0x%02x\n", econet_pkt_rx.ptr);
		econet_discontinue();
	}
	else if (sr2 & ECONET_GPIO_S2_OVERRUN) // Overrun RX
	{
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX Overrun at ptr = 0x%02x\n", econet_pkt_rx.ptr);
		econet_discontinue();
	}
	else if (sr2 & ECONET_GPIO_S2_ERR) // Checksum error
	{
		printk (KERN_INFO "ECONET-GPIO: CRC Error\n");
		econet_discontinue();
	}
	else if (sr2 & ECONET_GPIO_S2_VALID) // Frame valid received - i.e. end of frame received
	{
		d = econet_read_fifo(); 
		econet_process_rx(d); // Process the (final) incoming byte

		if (econet_pkt_rx.ptr < 4) // Runt
		{
			printk (KERN_INFO "ECONET-GPIO: Runt received (len %d) - jettisoning\n", econet_pkt_rx.ptr);
			econet_set_aunstate(EA_IDLE); // No harm even if not in AUN mode
			econet_set_read_mode();
			return;
		}

		// If kfifo is full, take something out of it before we shove this packet in.

		if (kfifo_is_full(&econet_rx_queue))
		{
			int a;
			a = kfifo_out(&econet_rx_queue, &dump_pkt, sizeof(dump_pkt));
		}

		if (!(econet_data->aun_mode)) // Raw mode - straight on the FIFO
		{
			// Put the packet on the kernel FIFO

			// Clear state
			econet_write_cr(ECONET_GPIO_CR2, C2_READ);

			kfifo_in(&econet_rx_queue, &(econet_pkt_rx.d.data), econet_pkt_rx.ptr); 
			wake_up(&(econet_data->econet_read_queue)); // Wake up the poller

#ifdef ECONET_GPIO_DEBUG_RX
			printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, %04x bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif

			econet_set_chipstate(EM_IDLE);
		}
		else
		{
			// Is the traffic for a station we bridge for?

			if (ECONET_DEV_STATION(econet_stations, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn))
			{

				unsigned short aun_state;

				econet_pkt_rx.length = econet_pkt_rx.ptr;

				// If our last transmission was more than 0.8s ago, go back to EA_IDLE
				
				if (
					(	((ktime_get_ns() - econet_data->aun_last_tx) > (2 * ECONET_4WAY_TIMEOUT)) &&
						(econet_get_aunstate() == EA_I_READREPLY)
					) 	||
					(
						((ktime_get_ns() - econet_data->aun_last_tx) > ECONET_4WAY_TIMEOUT) && 
						(econet_get_aunstate() != EA_IDLE)
					)
				) // If we are waiting for an immediate reply (which might be quite long), wait 2 x 4-way timeout (1.6s - ample for a 20k packet (e.g. MODE 0 screen dump on *VIEW) coming across from a station behind an onward bridge, and if not waiting for one of those and it's more than 0.8 seconds, then go back to idle.
				{
					printk (KERN_INFO "ECONET-GPIO: Last TX was too long ago. Moving back to AUN IDLE state. Packet from %d.%d to %d.%d, length 0x%04X\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn, econet_pkt_rx.length);
					econet_set_aunstate(EA_IDLE);
					econet_pkt_tx.length = 0; // Blank off any TX packet here
					econet_set_tx_status(ECONET_TX_SUCCESS);
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
				aun_state = econet_get_aunstate();

				/* Catch a data packet that is so long after the scout that it mustn't be a data packet */

				if ((econet_data->aun_mode) && (aun_state == EA_R_READDATA) && ((ktime_get_ns() - econet_data->aun_last_rx) > ECONET_AUN_DATA_TIMEOUT))
				{
							printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting data packet from %d.%d and this was so late it couldn't be one\n", econet_pkt_rx.length, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn);
							econet_set_aunstate(EA_IDLE);
				}

				econet_data->aun_last_rx = ktime_get_ns();

				switch (aun_state)
				{

					case EA_IDLE: // First in a sequence - see what it is.
					{
unexpected_scout:
						// Is it an immediate?
						if (econet_pkt_rx.d.p.port == 0 && !(econet_pkt_rx.d.p.ctrl >= 0x82 && econet_pkt_rx.d.p.ctrl <= 0x85)) // Ctrl 0x85 appears, from all the traffic sniffing, to in fact be done as a 4-way handshake even though it's port 0. It's used for notify, remote, view, etc.; ctrl &82 works similarly, but 8 bytes of data (being start and end addresses for the poked data); indeed, 0x82 to 0x85 are all 4-ways with various sorts of data on them
						{
#ifdef ECONET_GPIO_DEBUG_AUN
							printk (KERN_INFO "ECONET-GPIO: Immediate received from %d.%d, Ctrl 0x%02x\n", econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.ctrl);
#endif

							// Are we spoofing immediate replies to wire stations? If not, flagfill and deliver to userspace
							if (!(econet_data->spoof_immediate))
							{

								// Shouldn't be needed because of the 4 lines below ! // memcpy (&aun_rx, &econet_pkt_rx, 4); // Copy the addresses
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
				
								// Put it on the FIFO - just for now, only if it's empty
								//if (kfifo_is_empty(&econet_rx_queue))
								{
									kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
									wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
								}
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, %04x AUN bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif
								econet_rx_cleardown();
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
							// Shouldn't be needed because of the 4 lines below // memcpy (&aun_rx, &econet_pkt_rx, 4); // Copy the addresses
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
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Valid frame received, length %04x, %04x AUN bytes copied to kernel FIFO\n", econet_pkt_rx.ptr, copied_to_fifo);
#endif

							econet_rx_cleardown();
							econet_set_chipstate(EM_IDLE);
						}
						else // not immediate or broadcast - Should be a scout, unless it's a broadcast (And if it's not a scout, our state machine has gone wrong)
						{

							// Should be 6 bytes long. If not, drop it and go back to IDLE - we are obviously out of sequence.
							if (econet_pkt_rx.ptr != 6 && !(econet_pkt_rx.d.p.port == 0 && (econet_pkt_rx.d.p.ctrl >= 0x82 && econet_pkt_rx.d.p.ctrl <= 0x85))) // Immediate ctrl 0x85 packets are done as 4-way handshakes, BUT there are 4 data bytes on the opening scout
							{
								econet_set_aunstate(EA_IDLE);
								printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting Scout and this wasn't\n", econet_pkt_rx.ptr);
								econet_rx_cleardown();
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

								// Immediate Poke - has data on the scout
								if (aun_rx.d.p.port == 0 && aun_rx.d.p.ctrl == 0x82) // Copy the four data bytes onto the start of the aun_rx data buffer
									memcpy(&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), 8);

								// Is it immediate ctrl &85, which is done as a 4-way with 4 data bytes on the first Scout? ; 0x83 (JSR) also has 4 bytes on it, so does 0x84, USRPROC
								if (aun_rx.d.p.port == 0 && (aun_rx.d.p.ctrl >= 0x83 && aun_rx.d.p.ctrl <= 0x85)) // Copy the four data bytes onto the start of the aun_rx data buffer
									memcpy(&(aun_rx.d.p.data), &(econet_pkt_rx.d.p.data), 4);

								econet_pkt_tx.ptr = 0;
								econet_pkt_tx.length = 4;
	
								econet_set_aunstate(EA_R_WRITEFIRSTACK);
	
								econet_flagfill();
								econet_set_chipstate(EM_WRITE);
								econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
							}
						}

					}
				
					break;
						
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

							printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting first ACK from %d.%d - got packet from %d.%d to %d.%d %02x %02x %02x %02x\n", econet_pkt_rx.ptr, aun_tx.d.p.dstnet, aun_tx.d.p.dststn, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn, econet_pkt_rx.d.p.data[0], econet_pkt_rx.d.p.data[1], econet_pkt_rx.d.p.data[2], econet_pkt_rx.d.p.data[3]);
	
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
							econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
							econet_set_aunstate(EA_IDLE);
						}
						else // It was an ACK from where we expected, so flag completion to writefd
						{
#ifdef ECONET_GPIO_DEBUG_AUN
								printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN: Read final ACK from %d.%d, after scout with port %02x, ctrl %02x. Flag transmit success.\n", 
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
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN: Data received from %d.%d, length wire %d - Sending final ack.\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn, econet_pkt_rx.ptr);
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

							// Send Final ACK
						
							econet_pkt_tx.ptr = 0;
							econet_pkt_tx.length = 4;

							econet_set_aunstate(EA_R_WRITEFINALACK);

							econet_set_chipstate(EM_WRITE);
							econet_write_cr(ECONET_GPIO_CR1, C1_WRITE_INIT2);
						}
						else // Soemthing went wrong - clear down
						{
							printk (KERN_ERR "ECONET-GPIO: econet_irq_read(): AUN: Valid frame received, length %04x, but was expecting data packet from %d.%d and this wasn't\n", econet_pkt_rx.length, econet_pkt_rx.d.p.srcnet, econet_pkt_rx.d.p.srcstn);
							econet_rx_cleardown();
							econet_set_chipstate(EM_IDLE);
							econet_set_aunstate(EA_IDLE);
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
							printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): AUN Immediate reply received from %d.%d - send to userspace, data portion length %d\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn, (econet_pkt_rx.ptr -4));
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
	else if (sr2 & ECONET_GPIO_S2_AP) // New frame
	{
#ifdef ECONET_GPIO_DEBUG_RX
			printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Address present and no errors. SR1 = 0x%02x\n", sr1);
#endif
			econet_set_chipstate(EM_READ);
			econet_pkt_rx.length = econet_pkt_rx.ptr = 0;
			d = econet_read_fifo(); 
			econet_process_rx(d);
	}
	else if (sr1 & ECONET_GPIO_S1_RDA) // Ordinary data
	{
		if (econet_pkt_rx.ptr == 0) // Shouldn't be getting here without AP set (caught above)
		{
			printk (KERN_INFO "ECONET-GPIO: Received first byte of packet without AP flag set. Discontinuing. SR2=0x%02x.\n", sr2);
			econet_discontinue();
		}
		else // Data available
		{
			d = econet_read_fifo(); 
			econet_process_rx(d);
		}
	}
	else if ((sr2 = econet_read_sr(2)) & ECONET_GPIO_S2_DCD) // No clock all of a sudden
	{
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): RX No clock\n");
		econet_discontinue();
	}
	else
	{
		printk (KERN_INFO "ECONET-GPIO: econet_irq_read(): Unhandled state - SR1 = 0x%02x, SR2 = 0x%02x\n", sr1, sr2);
		econet_discontinue();
	}

	// Detect packets we are not interested in and discontinue them
	if (econet_data->aun_mode && econet_pkt_rx.ptr > 1) // If not in AUN mode, we receive everything and dump to userspace. Need ptr > 1 because that will mean destination address is in bytes 0, 1 of the received packet
	{
		if (!ECONET_DEV_STATION(econet_stations, econet_pkt_rx.d.p.dstnet, econet_pkt_rx.d.p.dststn)) // Not a station we are interested in
		{
			econet_discontinue();
		}

	}

	return;

}

irqreturn_t econet_irq(int irq, void *ident)
{

	unsigned long flags;

	spin_lock_irqsave(&econet_irq_spin, flags);

	sr1 = econet_read_sr(1);
	// Force read sr2 to get DCD if necessary
	sr2 = econet_read_sr(2);


#ifdef ECONET_GPIO_DEBUG_IRQ
	printk (KERN_INFO "ECONET-GPIO: econet_irq(): IRQ in mode %d, SR1 = 0x%02x, SR2 = 0x%02x. RX len=%d,ptr=%d, TX len=%d,ptr=%d\n", econet_get_chipstate(), sr1, sr2, econet_pkt_rx.length, econet_pkt_rx.ptr, econet_pkt_tx.length, econet_pkt_tx.ptr);
#endif

	if (!(sr1 & ECONET_GPIO_S1_IRQ)) // No IRQ actually present - return
	{
		printk (KERN_INFO "ECONET-GPIO: IRQ handler called but ADLC not flagging an IRQ. What?\n");
	}
	else if (econet_get_chipstate() == EM_TEST) /* IRQ in Test Mode - ignore */
	{
		printk (KERN_INFO "ECONET-GPIO: IRQ in Test mode - how did that happen?");
	}
	else if ((sr2 & ECONET_GPIO_S2_RX_IDLE) && !(sr2 & ECONET_GPIO_S2_VALID) && (econet_data->initialized) && (econet_data->aun_mode) && (econet_get_aunstate() == EA_W_READFINALACK)) // Line idle whilst waiting for final ack on a write = handshakefail. Don't match on frame valid in case we're getting FV & LINE IDLE in same IRQ, because we'll miss a valid frame then
	{

		unsigned short aun_state, chip_state, tx_status;

		chip_state = econet_get_chipstate();
		aun_state = econet_get_aunstate();
		tx_status = econet_get_tx_status();

#ifdef ECONET_GPIO_DEBUG_LINEIDLE
		printk (KERN_INFO "ECONET-GPIO: econet_irq(): Line idle IRQ waiting for final ACK - Handshake failed. aun state = %d, chip state = %d, tx_status = 0x%02x, rx ptr=%02X, sr1=0x%02X, sr2=%02X\n", aun_state, chip_state, tx_status, econet_pkt_rx.ptr, sr1, sr2);	
#endif

		econet_set_read_mode();
	}
	else if ((sr2 & ECONET_GPIO_S2_RX_IDLE) && !(sr2 & ECONET_GPIO_S2_VALID) && (econet_data->initialized)) 
	{

		unsigned short aun_state, chip_state, tx_status;

		chip_state = econet_get_chipstate();
		if (econet_data->aun_mode)
		{
			aun_state = econet_get_aunstate();
			tx_status = econet_get_tx_status();
		}

#ifdef ECONET_GPIO_DEBUG_LINEIDLE
		if (econet_data->aun_mode && aun_state != EA_IDLE)	
			printk (KERN_INFO "ECONET-GPIO: econet_irq(): Line idle IRQ waiting for final ACK - Handshake failed. aun state = %d, chip state = %d, tx_status = 0x%02x, rx ptr=%02X, sr1=0x%02X, sr2=%02X\n", aun_state, chip_state, tx_status, econet_pkt_rx.ptr, sr1, sr2);	
		else if ((!econet_data->aun_mode) && (chip_state != EM_TEST && chip_state != EM_IDLE && chip_state != EM_IDLEINIT))
			printk (KERN_INFO "ECONET-GPIO: econet_irq(): Line idle IRQ - chip state = %d\n",  chip_state);
#endif
	
	
		// If we get one of these interrupts and we're not idle (chip or AUN state) then give up and go back to read. If we were in TX (other than broadcast), set status to 'No listening', otherwise ECONET_TX_SUCCESS

		econet_pkt_rx.length = econet_pkt_rx.ptr = econet_pkt_tx.length = econet_pkt_tx.ptr = 0;

		if (econet_data->aun_mode)
		{

			if (aun_state != EA_IDLE)
			{

				switch (aun_state)
				{
					case EA_W_WRITEBCAST:
						econet_set_tx_status(ECONET_TX_NOTSTART);
						break;
					case EA_W_READFIRSTACK:
					case EA_I_READREPLY:
						econet_set_tx_status(ECONET_TX_NECOUTEZPAS);
						break;
					case EA_R_READDATA:
					case EA_R_WRITEFIRSTACK:
					case EA_R_WRITEFINALACK:
					case EA_W_READFINALACK:
						econet_set_tx_status(ECONET_TX_HANDSHAKEFAIL);
						break;

				}

				econet_set_aunstate(EA_IDLE);

			}

		}

		econet_set_read_mode();
	}
	// Are we in the middle of writing a packet?
	else if (econet_get_chipstate() == EM_WRITE) /* Write mode - see what there is to do */
		econet_irq_write();
	// Have we flagged end of transmission and are waiting for FC bit to be set before re-initializing read mode?
	else if (econet_get_chipstate() == EM_WRITE_WAIT) /* IRQ on completion of frame */
	{
		if (econet_data->aun_mode) // What state are we in - do we need to move state?
		{

			unsigned short aun_state;

			// Commented 25.07.21
			econet_data->aun_last_tx = ktime_get_ns(); // Used to check if we have fallen out of bed on receiving a packet

			aun_state = econet_get_aunstate();

			switch (aun_state)
			{
				// First, the states when we are writing a data packet from userspace
				case EA_W_WRITESCOUT: // We've just written the Scout successfully
				{
					econet_set_aunstate(EA_W_READFIRSTACK);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written Scout to %d.%d, waiting for first ACK\n", aun_tx.d.p.dstnet, aun_tx.d.p.dststn);
#endif
					break;
				}
				case EA_W_WRITEDATA: // We've just written the data packet
				{
					econet_set_aunstate(EA_W_READFINALACK);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written data, waiting for final ACK\n");
#endif
					break;
				}	
				case EA_W_WRITEBCAST: // We've successfully put a broadcast on the wire
				{
					econet_set_aunstate(EA_IDLE);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written broadcast, signalling packet complete\n");
#endif
					econet_set_tx_status(ECONET_TX_SUCCESS);
					break;
				}

				// Now, the states when we are mid read of a 4-way handshake from the wire

				case EA_R_WRITEFIRSTACK: // Just written first ACK - wait for data packet
				{
#ifdef ECONET_GPIO_DEBUG_AUN	
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Scout ACK written to %d.%d, waiting for data\n", aun_rx.d.p.srcnet, aun_rx.d.p.srcstn);
#endif
					econet_set_aunstate(EA_R_READDATA);
					break;
				}
				case EA_R_WRITEFINALACK: // Just written final ACK after a data packet - go back to IDLE & dump received packet to userspace
				{
					
					kfifo_in(&econet_rx_queue, &(aun_rx.d.raw), aun_rx.length); 
					wake_up(&(econet_data->econet_read_queue)); // Wake up the poller
					econet_set_aunstate(EA_IDLE);
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
					econet_set_tx_status(ECONET_TX_SUCCESS);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written immediate query. Signal TX success but move to READREPLY\n");
#endif
					break;
				}
				case EA_I_WRITEREPLY: // We read an immediate from the wire and have just transmitted the reply
				{
					// We don't update tx_status here because the immediate reply will have been generated in-kernel
					econet_set_tx_status(ECONET_TX_SUCCESS);
					econet_set_aunstate(EA_IDLE);
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Written immediate reply. Signal TX success. Return to IDLE\n");
#endif
					break;
				}
				default: // Which will apply for writing an immediate reply when not in spoof mode
				{
#ifdef ECONET_GPIO_DEBUG_AUN
					printk (KERN_INFO "ECONET-GPIO: econet_irq(): AUN: Default reached on write state machine. Return to IDLE. AUN state = %d\n", aun_state);
#endif
					econet_set_aunstate(EA_IDLE);
					break;
				}
						
			}
		}
		else // raw mode - flag transmit success
		{
			econet_set_tx_status(ECONET_TX_SUCCESS);
#ifdef ECONET_GPIO_DEBUG_TX
			printk (KERN_INFO "ECONET-GPIO: econet_irq(): Returning to IDLEINIT, flagging frame completed\n");
#endif
			// Clear the RX FIFO so that next read is whatever came back from this write
			kfifo_reset(&econet_rx_queue);
		}

		econet_set_read_mode();
		
	}
	// Are we either mid-read, or idle (in which case, this will be a receiver IRQ)
	else if (econet_get_chipstate() == EM_READ || (sr2 & (ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_AP)) || (sr1 & ECONET_GPIO_S1_RDA)) // In case we get address present or data or are already in read mode
		econet_irq_read();
	else if (econet_get_chipstate() == EM_IDLE || econet_get_chipstate() == EM_IDLEINIT) // We seem to get these when the chip gets its pants tangled. (With sr1=0 - but we've handled reading and writing above, so just clear status)
	{
		if (econet_get_chipstate() == EM_IDLEINIT)
			econet_set_chipstate(EM_IDLE);

		if (sr2 & ~(ECONET_GPIO_S2_AP | ECONET_GPIO_S2_VALID | ECONET_GPIO_S2_RDA)) // Errors
		{
			econet_rx_cleardown();
		}
		else
			econet_write_cr(ECONET_GPIO_CR2, C2_READ); // Just clear status
	}

	// Otherwise we are in test mode (which might not exist any more) and we shouldn't be getting IRQs at all!
	else
		printk (KERN_INFO "ECONET-GPIO: IRQ received in unknown state - sr1=0x%02X, sr2=0x%02X\n", sr1, sr2);

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
MODULE_VERSION("2.01");

/* Packet buffers */
struct __econet_pkt_buffer econet_pkt; /* Temporary buffer for incoming / outgoing packets */


const struct of_device_id econet_of_match[] = {
	{ .compatible = "econet-gpio" },
	{ }
};

MODULE_DEVICE_TABLE(of, econet_of_match);

static struct platform_driver econet_driver = {
	.driver = {
			.name = "econet-gpio",
			.of_match_table = of_match_ptr(econet_of_match),
		},
	.probe = econet_probe,
	.remove = econet_remove,
};

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
	
	unsigned short aun_state;

	// In AUN mode, the writefd routine should have put the packet into aun_tx for us. 

	memcpy (&econet_pkt_tx_prepare, &aun_tx, 4); // Source & Destination

	aun_state = econet_get_aunstate();

	if (aun_state == EA_IDLE) // Fresh packet in, so set the tx_status to the rogue
		econet_set_tx_status(ECONET_TX_STARTWAIT);

	switch (aun_state)
	{
		case EA_IDLE: // This must be a write from userspace. Write a Scout, or Immediate if port = 0
		{
			if (aun_tx.d.p.aun_ttype == ECONET_AUN_BCAST) // Broadcast
			{
				econet_pkt_tx_prepare.d.p.dstnet = econet_pkt_tx_prepare.d.p.dststn = 0xff;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	
				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), (aun_tx.length - 12));
				//econet_pkt_tx_prepare.length = 6 + (aun_tx.length > 12 ? (aun_tx.length -6) : 0); // i.e. up to the port byte and then any data that's around
				econet_pkt_tx_prepare.length = aun_tx.length -6; // aun_tx has a minimum length of 12, and a wire broadcast has a minimum length of 6 (if no data, but has ctrl + port). So if the writefd() packet was 12, this will give src, dst, ctrl and port. If it was 13, it'll have one data byte... so this calculation works.
				econet_set_aunstate(EA_W_WRITEBCAST);
			}
			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_IMM) // Immediate
			{
				// Send the packet and move to EA_I_WRITEIMM
				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	
				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.data), &(aun_tx.d.p.data), (aun_tx.length - 12));
				econet_pkt_tx_prepare.length = aun_tx.length -6; // aun_tx has a minimum length of 12, and a wire broadcast has a minimum length of 6 (if no data, but has ctrl + port). So if the writefd() packet was 12, this will give src, dst, ctrl and port. If it was 13, it'll have one data byte... so this calculation works.
				econet_set_aunstate(EA_I_WRITEIMM);
			}	
			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_DATA) // Data -- NB this will also be used for the "special" port 0 ctrl 0x85 "4-way immediate" for things like Notify, etc.
			{
				// Send a scout
				econet_pkt_tx_prepare.d.p.port = aun_tx.d.p.port;
				econet_pkt_tx_prepare.d.p.ctrl = aun_tx.d.p.ctrl; // IMMEDIATE MOD | 0x80; // Set high bit. It is apparently always clear in UDP space	

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

				// Set up to transmit

				econet_pkt_tx_prepare.ptr = 0;
				econet_set_aunstate(EA_W_WRITESCOUT);
			}
			else if (aun_tx.d.p.aun_ttype == ECONET_AUN_IMMREP) // Reply to an immediate we presumably collected off the wire & send to userspace some time ago
			{
				if (aun_tx.length > 12) // Otherwise there's no data to copy (AUN format packet has 12 header bytes incl. the sequence
					memcpy (&(econet_pkt_tx_prepare.d.p.ctrl), &(aun_tx.d.p.data), (aun_tx.length - 12)); // Used to copy to d.p.data, but that's wrong on an immediate reply

				econet_pkt_tx_prepare.length = 4 + (aun_tx.length > 12 ? (aun_tx.length - 12) : 0); // i.e. up to the port byte and then any data that's around WAS 6 + ...

				econet_set_aunstate(EA_I_WRITEREPLY);
			}
		}
		break;

/* Disable and see if it breaks, since we think this achieves nothing */
#if 0
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
#endif
		default:	printk(KERN_INFO "ECONET-GPIO: econet_aun_tx_statemachine() called in state 0x%02X", aun_state); break;
	}
}

// When defined, this printk's some timing information about writefd which was used for debugging why writing took so long.
// It turned out to be something in set_write_mode()
//#define ECONET_WRITE_INSTRUMENTATION

ssize_t econet_writefd(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
	
	int c;
	unsigned short chipmode;
	unsigned short txstatus;
	unsigned short aunstate;

	// We were getting kernel crashes during trying to turn off the IRQs here, so let's put
	// a mutex round it and see if that helps, in case we are trying to turn it off twice at the
	// same time somehow

	if (!mutex_trylock(&econet_writefd_mutex))
	{
		printk (KERN_INFO "ECONET-GPIO: Flag busy because cannot get writefd mutex\n");
		econet_set_tx_status(ECONET_TX_BUSY);
		return -1;
	}

	// IRQs off, see if we can get the lock
	econet_irq_mode(0);
	
	if (!spin_trylock(&econet_irqstate_spin))
	{
		printk (KERN_INFO "ECONET-GPIO: Flag busy because cannot get IRQ spinlock\n");
		econet_irq_mode(1);
		econet_set_tx_status(ECONET_TX_BUSY);
		mutex_unlock(&econet_writefd_mutex);
		return -1;
	}

	// Next, see if we are mid TX but it started so long ago that it must have stalled

	txstatus = econet_get_tx_status();
	aunstate = econet_get_aunstate();

	if (econet_data->aun_mode && (aunstate != EA_IDLE) && (txstatus >= ECONET_TX_DATAPROGRESS) && ((ktime_get_ns() - econet_data->aun_last_writefd) >= ECONET_4WAY_TIMEOUT)) // The >= catches data progress, in progress, waiting to start
	{
		econet_set_tx_status(ECONET_TX_SUCCESS);
		econet_set_aunstate(EA_IDLE); 
		econet_set_chipstate(EM_IDLE);
		aunstate = EA_IDLE;
	}
	
	econet_data->aun_last_writefd = ktime_get_ns();

	// Now go back to AUN idle if our last transmission was more than say 100ms ago and we seem to be stuck in state

	if (econet_data->aun_mode && (aunstate == EA_W_READFIRSTACK || aunstate == EA_W_READFINALACK || aunstate == EA_I_READREPLY || aunstate == EA_R_READDATA) && ((ktime_get_ns() - econet_data->aun_last_tx) > 100000000))
	{
		econet_set_tx_status(ECONET_TX_SUCCESS);
		econet_set_aunstate(EA_IDLE); 
		econet_set_chipstate(EM_IDLE);
		aunstate = EA_IDLE;
	}

	// Next, see if we are idle

	if (econet_data->aun_mode && aunstate != EA_IDLE) // Not idle
	{
		if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: Flag busy because AUN state machine busy (state = 0x%02x)\n", aunstate);
		econet_set_tx_status(ECONET_TX_BUSY);
		spin_unlock(&econet_irqstate_spin);
		mutex_unlock(&econet_writefd_mutex);
		econet_irq_mode(1);
		return -1;
	}

	chipmode = econet_get_chipstate();

	if (chipmode != EM_IDLE && chipmode != EM_IDLEINIT && chipmode != EM_FLAGFILL)
	{
		if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: Flag busy because chip state not idle / flagfill\n");
		econet_set_tx_status(ECONET_TX_BUSY);
		spin_unlock(&econet_irqstate_spin);
		mutex_unlock(&econet_writefd_mutex);
		econet_irq_mode(1);
		return -1;
	}

	// Here, we have the spinlock, and IRQs are off

	// Check Clock
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
	
	// Copy packet from userspace

	if ((c = copy_from_user(&econet_pkt, buffer, len)))
	{
		econet_pkt.ptr = econet_pkt.length = 0; // Empty the packet 
		printk (KERN_ERR "ECONET-GPIO: econet_writefd() Failed to copy %d bytes from userspace", c);
		econet_set_tx_status(ECONET_TX_NOCOPY);
		econet_set_read_mode();
		spin_unlock(&econet_irqstate_spin);
		mutex_unlock(&econet_writefd_mutex);
		econet_irq_mode(1);
		return  -1;
	}

	if (econet_data->aun_mode) // AUN Mode - this is an AUN format packet from userspace, put it in aun_tx
	{
		memcpy (&aun_tx, &econet_pkt, len); // Puts the four src/dst bytes into aun_tx. Line the rest up later.
		aun_tx.length = len;
		econet_aun_tx_statemachine(); // Sets up econet_pkt_tx_prepare
#ifdef ECONET_GPIO_DEBUG_AUN
		printk (KERN_INFO "ECONET-GPIO: econet_writefd(): AUN: Packet from userspace from %d.%d to %d.%d, data length %d", aun_tx.d.p.srcnet, aun_tx.d.p.srcstn, aun_tx.d.p.dstnet, aun_tx.d.p.dststn, (len - 12));
#endif
		spin_unlock(&econet_irqstate_spin);
		// Trigger TX
		econet_set_write_mode (&econet_pkt_tx_prepare, econet_pkt_tx_prepare.length);
	}
	else // Raw transmit
	{
		spin_unlock(&econet_irqstate_spin);
		econet_set_write_mode (&econet_pkt, len);
	}

	econet_irq_mode(1);

	// CR to consider shortening this delay considerably.

	//udelay(100); // Wait for an IRQ to have happened
	udelay(10); // Wait for IRQ

	if (econet_get_tx_status() != ECONET_TX_INPROGRESS) // Something failed in set_write_mode
	{
		econet_pkt_tx.length = 0; // Blank off the packet
		econet_set_read_mode();
		econet_set_aunstate(EA_IDLE);
		mutex_unlock(&econet_writefd_mutex);
		return -1;
	}
	
	mutex_unlock(&econet_writefd_mutex);
	return len; // Exit
	
}

/* Change state of one or other LED. See #defines in econet-gpio-consumer.h
 */

void econet_led_state(uint8_t arg)
{
	uint8_t pin;

	pin = (arg & ECONETGPIO_READLED) ? EGP_READLED : EGP_WRITELED;

	gpio_set_value(econet_gpio_pins[pin], (arg & ECONETGPIO_LEDON) ? 1 : 0);

}

/* Change the PWM period/mark for the network clock (only initialized on v2 hardware)
 *
 * Remember we run the PWM clock at 4MHz to make sure we can do marks which are
 * fractions of a us - so multiply everything by 4!
 */

void econet_set_pwm(uint8_t period, uint8_t mark)
{

	if (econet_data->hwver < 2)	return; // Not on v1 hardware!

	// First, reset the PWM

	writel(0, (GPIO_PWM + PWM_CTL));

	barrier();

	// Clear various error states

	writel(0xffffffff, (GPIO_PWM + PWM_STA));
	writel(0, (GPIO_PWM + PWM_DMAC));

	barrier();

	// Set range & data - constrain our parameters to 31/4 us period (7.something us), and
	// 15/4 us mark (3.something us)

	writel(period & 0x1f, (GPIO_PWM + PWM_RNG1));
	writel(mark & 0x0f, (GPIO_PWM + PWM_DAT1));

	// Enable the PWM

	if ((period & 0x1f) > (mark & 0x0f)) // If resulting mark is < resulting period, don't bother enabling the PWM because it'll be nonsence
	{
		writel(	(readl(GPIO_PWM + PWM_CTL) & ~(0xff)) | (PWM_CTL_MSEN1 | PWM_CTL_PWEN1),
			(GPIO_PWM + PWM_CTL)	);
#ifdef ECONET_GPIO_DEBUG_SETUP
		printk (KERN_INFO "ECONET-GPIO: PWM Clock period/mark set to %d, %d\n", (period & 0x1F), (mark & 0x0F));
#endif
	}

}

/* Called when a process opens our device */

int econet_open(struct inode *inode, struct file *file) {

	/* If device is open, return busy */

	if (econet_data->open_count)
		return -EBUSY;

	econet_data->open_count++;

	try_module_get(THIS_MODULE);
	
	econet_reset(); // Does the station array clear, resets the FIFOs etc.

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
			econet_adlc_cleardown(0); // 0 = not in IRQ
			econet_set_read_mode(); // Required in addition to the cleadown, because this sets the ADLC up to read, where as cleardown doesn't.
			if (econet_data->aun_mode)
				econet_set_aunstate(EA_IDLE);

			break;
		case ECONETGPIO_IOC_READGENTLE: /* Go back to read mode without the sledgehammer of a cleardown */
			econet_set_read_mode(); // Required in addition to the cleadown, because this sets the ADLC up to read, where as cleardown doesn't.
			if (econet_data->aun_mode)
				econet_set_aunstate(EA_IDLE);

			break;
		case ECONETGPIO_IOC_SET_STATIONS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(set stations) called\n");
#endif
			/* Copy station bitmap from user memory */
			if ((!access_ok((void __user *) arg, 8192)) || copy_from_user(econet_stations, (void *) arg, 8192))
			{
				printk (KERN_INFO "ECONET-GPIO: Unable to update station set.\n");
				return -EFAULT;
			}
			if (econet_data->extralogs) printk(KERN_INFO "ECONET-GPIO: Station set updated - Switching on AUN mode\n");
			econet_data->aun_mode = 1; // Turn this on if we get a station set
			econet_set_aunstate(EA_IDLE);
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
			econet_irq_mode(0);
			break;
		case ECONETGPIO_IOC_TXERR:

#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(get last tx error) called - current status %02x\n", econet_get_tx_status());
#endif
			return (econet_get_tx_status());
			break;
		case ECONETGPIO_IOC_GETAUNSTATE:
			return ((econet_pkt_tx.ptr << 16) | econet_get_aunstate());
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
			if (econet_data->extralogs) printk (KERN_INFO "ECONET-GPIO: Changing immediate spoof mode to %s\n", arg ? "ON" : "OFF");
			econet_data->spoof_immediate = arg ? 1 : 0;
			break;
		case ECONETGPIO_IOC_EXTRALOGS:
			econet_data->extralogs = (arg == 0) ? 0 : 1;
			printk (KERN_INFO "ECONET-GPIO: Extra logging turned %s\n", (arg == 0) ? "OFF" : "ON");
			break;
		case ECONETGPIO_IOC_TESTPACKET: /* Send test packet */
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "ECONET-GPIO: ioctl(test packet) called\n");
#endif
			// if there is anything being done, wait for it to go away
			{
				u64 timer;
		
				timer = ktime_get_ns() + 500000000; // Half a second. Probably too much...
	
				while ((ktime_get_ns() < timer) && (econet_get_chipstate() != EM_IDLE));
				
			}
			econet_pkt.d.p.dststn = 1;
			econet_pkt.d.p.dstnet = 0; /* Station 1 on local network */
			econet_pkt.d.p.srcstn = 254;
			econet_pkt.d.p.srcnet = 0; /* Station 254 on local network */
			econet_pkt.d.p.ctrl = 0x88; /* Machine Type query */
			econet_pkt.d.p.port = 0x00; /* Immediate */
			econet_pkt.length = 6;
			econet_pkt.ptr = 0; /* Start at the beginning */
			econet_set_write_mode(&econet_pkt, 6);
			break;
		case ECONETGPIO_IOC_LED: /* Turn one of the LEDs on or off - only does one at once */
			econet_led_state(arg);
			break;
		case ECONETGPIO_IOC_NETCLOCK: /* Set up the network clock on pin 18 via Hardware PWM */
			if (econet_data->hwver >= 2)
				econet_set_pwm (((arg & 0xffff0000) >> 16), (arg & 0xffff)); // Period in top 16 bits; mark in bottom 16.
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

	/* See what sort of system we have */


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

	econet_data->peribase = 0xFE000000; // Assume Pi4-class unless we find otherwise
	econet_data->clockdiv = ECONET_GPIO_CLOCKDIVFAST; // Larger divider default unless we're sure we don't want it

	if (of_machine_is_compatible("raspberrypi,4-model-b"))
		printk (KERN_INFO "ECONET-GPIO: This appears to be a Pi4B\n");
	else if (of_machine_is_compatible("raspberrypi,400"))
		printk (KERN_INFO "ECONET-GPIO: This appears to be a Pi400\n");
	else if (of_machine_is_compatible("raspberrypi,3-model-b"))
	{
		econet_data->peribase = 0x3F000000;
		econet_data->clockdiv = ECONET_GPIO_CLOCKDIVSET;
		printk (KERN_INFO "ECONET-GPIO: This appears to be a Pi3B\n");
	}
	else if (of_machine_is_compatible("raspberrypi,3-model-b-plus"))
	{
		econet_data->peribase = 0x3F000000;
		econet_data->clockdiv = ECONET_GPIO_CLOCKDIVSET;
		printk (KERN_INFO "ECONET-GPIO: This appears to be a Pi3B+\n");
	}
	else if (of_machine_is_compatible("raspberrypi,model-zero-w") || of_machine_is_compatible("raspberrypi,model-zero"))
	{
		econet_data->peribase = 0x20000000;
		econet_data->clockdiv = ECONET_GPIO_CLOCKDIVSET;
		printk (KERN_INFO "ECONET-GPIO: This appears to be a PiZero (reliability uncertain)\n");
	}
	else if (of_machine_is_compatible("raspberrypi,model-zero-2-w") || of_machine_is_compatible("raspberrypi,model-zero-2"))
	{
		econet_data->peribase = 0x3F000000;
		econet_data->clockdiv = ECONET_GPIO_CLOCKDIVSET;
		printk (KERN_INFO "ECONET-GPIO: This appears to be a PiZero2\n");
	}
	else printk (KERN_INFO "ECONET-GPIO: Machine compatibility uncertain - assuming Peripheral base at 0xFE000000");

	// printk (KERN_INFO "ECONET-GPIO: Peripheral base address set to 0x%08lX\n", econet_data->peribase);

	econet_set_chipstate(EM_TEST);
	econet_set_irq_state(-1);
	econet_data->aun_mode = 0;
	econet_data->aun_seq = 0x4000;
	econet_data->aun_last_tx = 0;
	econet_data->clock = 0; // Assume no clock to start with
	econet_data->initialized = 0; // Module not yet initialized.
	econet_set_aunstate(EA_IDLE);
	econet_data->spoof_immediate = 0;
	econet_data->extralogs = 0;
	
	// Assume hardware version 1 unless told otherwise
	econet_data->hwver = 1;

	econet_data->major=register_chrdev(0, DEVICE_NAME, &econet_fops);
	if (econet_data->major < 0)
	{
		printk (KERN_INFO "ECONET-GPIO: Failed to obtain major device number.\n");
		return econet_data->major;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,4,0)
	if (IS_ERR(econet_class = class_create(THIS_MODULE, CLASS_NAME)))
#else
	if (IS_ERR(econet_class = class_create(CLASS_NAME)))
#endif
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
		

	// printk(KERN_INFO "ECONET-GPIO: Loaded. Major number %d\n", econet_data->major);

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

	sr1 = econet_read_sr(1);
	sr2 = econet_read_sr(2);

	printk (KERN_ERR "ECONET-GPIO: %s (SR1 = 0x%02x, SR2 = 0x%02x)\n", (sr2 & ECONET_GPIO_S2_DCD) ? "No clock!" : "Clock detected", sr1, sr2);

	econet_data->initialized = 1;
	return 0;

}

/* This is known to be nasty. It should really pick all the GPIOs up from the DT - but that's the next stage... */

static int __init econet_probe (struct platform_device *pdev)
{

	return econet_init();

}

/* Exit routine */

static void econet_exit(void)
{

	gpio_direction_output(econet_gpio_pins[EGP_READLED], 0);
	gpio_direction_output(econet_gpio_pins[EGP_WRITELED], 0);

	econet_gpio_release();
	
	device_destroy(econet_class, MKDEV(econet_data->major, 0));
	class_destroy(econet_class);
	unregister_chrdev(econet_data->major, DEVICE_NAME);
	kfree(econet_data);
	kfifo_free(&econet_rx_queue);
	kfifo_free(&econet_tx_queue);
	printk(KERN_INFO "ECONET-GPIO: Unloaded.");

}

/* See comment above econet_probe() */

int econet_remove (struct platform_device *pdev)
{
	econet_exit();
	return 0;
}

/* Register module functions */
module_init(econet_init);
module_exit(econet_exit);
//module_platform_driver(econet_driver);
