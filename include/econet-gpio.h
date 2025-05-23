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
#include <linux/pwm.h>
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


#define ECONET_CHAR(d)	((d >= 32) && (d < 127)) ? d : '.'
#define CLASS_NAME "econetgpio"

/* Various defs */
#define ECONET_MAXQUEUE 10 /* max number of packets we can queue, in or outbound */

/* Timeouts for 4-way handshake */
#define ECONET_4WAY_TIMEOUT 200000000000 /* 2s (in ns) - timeout beyond which we will decide that our last transmission as part of a 4-way handshake was so long ago that the data we just received cannot be part of it and must be a new incoming exchange */

#define ECONET_AUN_DATA_TIMEOUT 500000000 /* 0.5s - if the data packet after a received scout turns up after this length of time, we assume it can't be the data packet and reset the statemachine */

/* Internal functions */

/* Function declarations */

static int econet_probe(struct platform_device *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,20)
static void econet_remove(struct platform_device *);
#else
static int econet_remove(struct platform_device *);
#endif
int econet_open(struct inode *, struct file *);
int econet_release(struct inode *, struct file *);
long econet_ioctl (struct file *, unsigned int, unsigned long);
unsigned int econet_poll (struct file *, poll_table *);
ssize_t econet_readfd(struct file *, char *, size_t, loff_t *);
ssize_t econet_writefd(struct file *, const char *, size_t, loff_t *);
static inline void econet_process_rx(unsigned char);
static inline void econet_aun_setidle_txstatus(int);
static inline void econet_process_rx(unsigned char);



/* Abstracted functions to read SR / write CR  & FIFO */
unsigned char econet_read_sr(unsigned short);

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

/* Pin numbering index */

enum econet_gpio_pin_index {
        EGP_D0 = 0,
        EGP_D1,
        EGP_D2,
        EGP_D3,
        EGP_D4,
        EGP_D5,
        EGP_D6,
        EGP_D7,
        EGP_A0,
        EGP_A1,
        EGP_RST,
        EGP_CS,
        EGP_CLK,
        EGP_RW,
        EGP_DIR,
        EGP_IRQ,
        EGP_CSRETURN,
        EGP_READLED,
        EGP_WRITELED };

struct __econet_data {

	int irq;
	atomic_t irq_state;
	struct device *dev;
	struct cdev c_dev;
	int major;
	dev_t majorminor;
	atomic_t mode; // IRQ handler state machine IDLEINIT -> IDLE -> (READ / WRITE_START); WRITE_START -> WRITE -> WRITE_WAIT or IDLE. Only IRQ space writes to this.
	short userspacemode; // READ, WRITE or TEST. Tells the IRQ handler what it's supposed to be doing. Only userspace writes to this.
	short open_count;
	wait_queue_head_t econet_read_queue;
	atomic_t tx_status;
	u8 aun_mode;
	u8 plain_mode; // Plain tx/rx type
	u16 plain_ptr; // PTR to plain packet
	u16 plain_length; // Length of plain packet
	atomic_t aun_state;
	long aun_seq;
	u64 aun_last_tx;
	u64 aun_last_rx;
	u64 aun_last_writefd;
	u64 aun_last_statechange;
	short last_tx_user_error;
	struct gpio_desc	*econet_gpios[20];
	unsigned char hwver;
	unsigned char current_dir; // Current databus direction
	unsigned char initialized; // Whether module is actually initialized
	unsigned char extralogs; // If 1, extra dmesg logging happens (e.g. collisions, rx aborts, etc.)
	unsigned long peribase; // Peripheral base address
	u8 resilience; // 0 = off; 1 = in AUN mode, will just flag fill after receipt of data from station when reading a 4-way instead of sending final ACK. (Not implemented yet.) Userspace will use ioctl() to signal the ACK has arrived and that the wire ACK can then be sent. In this mode, userspace will have set a thread going which waits for a timeout, checks to see if the kernel is still in EA_R_PENDINGFINALACK and if it is then puts it back into read mode. This will generate net error on the sending wire station, which is the best we can do if destination station fails to respond (perhaps over trunk) when the module has to convert 4-way traffic to AUN.
	struct clk		*gpio4clk;
	struct pwm_device	*gpio18pwm;
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

#endif
