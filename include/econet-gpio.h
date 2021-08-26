/*
  (c) 2020 Chris Royle
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

#ifndef __ECONETGPIOKERNEL_H__

#define __ECONETGPIOKERNEL_H__

#include <linux/version.h>
#include <linux/types.h>
#include <linux/module.h>  
#include <linux/kernel.h> 
#include <linux/init.h> 
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
#include <linux/gpio.h>

#include "econet-gpio-debug.h"
#include "econet-gpio-consumer.h"
#include "econet-gpio-chipctrl.h"

// Defining this turns off the old ktime_ns() wait routine.
// Implemented to try and make this work better on non-Pi4B. 
// If you remove this define, the code will ONLY work properly
// on a Pi4B.
//#define ECONET_NO_NDELAY

/* Set our device name */
#define DEVICE_NAME "econet-gpio"

/* The following defines are based on a GPIO BCM 4 clock speed of 550kHz */
/* There is a special fast bus write routine which has none of the delay of the slow one
 * whose purpose is to write data on the bus when it is going in the TX FIFO. The
 * slower routine is fine for writing to registers, because it doesn't matter if the chip
 * reads those multiple times. However, if it reads the TX FIFO multiple times then
 * unsurprisingly it transmits multiple copies of the same byte onto the wire, which is
 * unhelpful. However, even udelay(1) is too long to hold /CS low, and no udelay at all
 * is too short. On Linux ARM, there appears to be no ndelay(). So there is a loop
 * which uses asm("") to stop the compiler optimizing it out. This is the number of times
 * a for(;;) loop  'calls' asm("") to create the right delay.
 *
 * I am well aware that this is a total fiddle. The value will need to be less on slower
 * machines, probably more on faster machines. I developed on a 3B+.
 *
 * No postcards or other communications about how bad this is, *please*. */



#define ECONET_CHAR(d)	((d >= 32) && (d < 127)) ? d : '.'
#define CLASS_NAME "econetgpio"

/* Various defs */
#define ECONET_MAXQUEUE 10 /* max number of packets we can queue, in or outbound */

/* Timeouts for 4-way handshake */
#define ECONET_4WAY_TIMEOUT 300000000 /* 0.3s (in ns) - timeout beyond which we will decide that our last transmission as part of a 4-way handshake was so long ago that the data we just received cannot be part of it and must be a new incoming exchange */

/* Internal functions */

/* Function declarations */

int econet_probe(struct platform_device *);
int econet_remove(struct platform_device *);
int econet_open(struct inode *, struct file *);
int econet_release(struct inode *, struct file *);
long econet_ioctl (struct file *, unsigned int, unsigned long);
unsigned int econet_poll (struct file *, poll_table *);
ssize_t econet_readfd(struct file *, char *, size_t, loff_t *);
ssize_t econet_writefd(struct file *, const char *, size_t, loff_t *);

/* Abstracted functions to read SR / write CR  & FIFO */
unsigned char econet_read_sr(short);
void econet_write_fifo(unsigned char);
unsigned char econet_read_fifo(void);

/* IRQ */
irqreturn_t econet_irq(int, void *);
void econet_irq_mode(short);

/* Data handling */
void econet_copy_to_rx_queue(void); /* Copies the current packet into the userspace queue */

/* Chip reset function - also takes us out of test mode */
void econet_reset(void);

static const char econet_devname[] = "econet-gpio";

/* Internal state */

enum econet_modes {
	EM_TEST = 1,
	EM_READ,
	EM_WRITE_START,
	EM_WRITE,
	EM_WRITE_WAIT,
	EM_IDLE,
	EM_IDLEINIT,
	EM_FLAGFILL }; // EM_INIT exists because we get a stray IRQ on initialization which
			// was putting the module into EM_READ, and delaying writefd()
			// until it gave up waiting for EM_IDLE. So EM_INIT
			// just catches the first interrupt and puts us into EM_IDLE

enum econet_aunstate {
	EA_IDLE = 1, // Waiting for something to happen
	EA_W_WRITESCOUT, // Given a data packet by userspace. Writing the Scout
	EA_W_READFIRSTACK, // We've been given an AUN packet by userspace, and written the scout, now waiting for first ack from wire
	EA_W_WRITEDATA, // Given a data packet by userspace, done the scout, picked up the first ack, now writing the data packet
	EA_W_READFINALACK, // We've written the data packet to the wire, now waiting for final ack
	// Any read of a Data scout will happen in EA_IDLE, so first state is WRITEFIRSTACK
	EA_R_WRITEFIRSTACK, // We've read a scout from the wire, now transmitting first ack
	EA_R_READDATA, // We've read a scout from the wire, written the ack, now waiting for the data packet
	EA_R_WRITEFINALACK, // We've read a scout from the wire, written the first ack, read the data packet, now tx final ack
	EA_I_WRITEREPLY, // We've read an immediate from the wire; we are now writing out the response to the wire
	EA_I_WRITEIMM, // We got an immediate from userspace and are putting it on the wire
	EA_I_READREPLY, // We've written an immediate to the wire, we are now waiting for the response from the wire
	EA_I_IMMSENTTOAUN, // We've received an immediate off the wire and sent it to userspace. We are waiting for a reply to come back and will then transmit it
	EA_W_WRITEBCAST // Writing a broadcast. Don't hang about for a reply
};

struct __econet_data {

        int irq;
	short irq_state;
        struct device *dev;
        struct cdev c_dev;
        int major;
	dev_t majorminor;
        //struct mutex lock;
        short mode; // IRQ handler state machine IDLEINIT -> IDLE -> (READ / WRITE_START); WRITE_START -> WRITE -> WRITE_WAIT or IDLE. Only IRQ space writes to this.
	short userspacemode; // READ, WRITE or TEST. Tells the IRQ handler what it's supposed to be doing. Only userspace writes to this.
	short open_count;
	wait_queue_head_t econet_read_queue;
	short tx_status;
	short aun_mode;
	short aun_state;
	short spoof_immediate;
	long aun_seq;
	u64 aun_last_tx;
	u64 aun_last_statechange;
	short last_tx_user_error;
	unsigned char clock; // 0 = no clock; anything else = clock - set when reading registers
};

struct __econet_pkt_buffer {
        struct __econet_packet_wire d;
        unsigned int ptr;
        unsigned int length;
//	char tx_status;
};

struct __aun_pkt_buffer {
	struct __econet_packet_aun d;
	unsigned int length;
};

#define econet_set_aunstate(x) { \
	econet_data->aun_state = (x); \
	econet_data->aun_last_statechange = ktime_get_ns(); \
}

#endif
