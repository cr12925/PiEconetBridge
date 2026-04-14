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

/* 
 * Max packet buffers for module-fast - maximum 32
 */

#define ECONET_GPIO_MAX_BUFFERS 8
#define ECONET_GPIO_MAX_WORK_BUFFERS 8


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

#define ECONET_GPIO_TIMING

#include <linux/version.h>
#include <linux/types.h>
#include <linux/module.h>  
#include <linux/kernel.h> 
#include <linux/fs.h>
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
#include <asm/uaccess.h>
#include <linux/workqueue.h>

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
#define DEVICE_NAME_MONITOR "econet-monitor"

/* Turn on timing code */

#define ECONET_GPIO_TIMING

#define ECONET_CHAR(d)	((d >= 32) && (d < 127)) ? d : '.'
#define CLASS_NAME "econetgpio"
#define CLASS_NAME_MONITOR "econetmonitor"

/* Various defs */
#define ECONET_MAXQUEUE 10 /* max number of packets we can queue, in or outbound */

/* Timeouts for 4-way handshake */
#define ECONET_4WAY_TIMEOUT 200000000000 /* 2s (in ns) - timeout beyond which we will decide that our last transmission as part of a 4-way handshake was so long ago that the data we just received cannot be part of it and must be a new incoming exchange */

#define ECONET_AUN_DATA_TIMEOUT 500000000 /* 0.5s - if the data packet after a received scout turns up after this length of time, we assume it can't be the data packet and reset the statemachine */

#define ECONET_AUN_RX_TO_TX_GAP	2000	/* Module will flag writefd() as busy if the last reception in AUN mode was less than this many ns ago */

#define ECONET_TX_STAMP(n)	econet_data->pt.n = ktime_get_ns()

/* Workqueue typedef */

typedef struct {
	struct work_struct	econet_work;
	struct __econet_packet	*p;
	u8	wb_index; /* Index so econet_free_workbuf knows which one to free */
} eco_work_t;

/* Packet buffer definitions - only used in old module */

struct __econet_pkt_buffer {
	struct __econet_packet_wire d;
	unsigned int ptr;
	unsigned int length;
	unsigned int final_status; // Bitmask of various status indicators
};

struct __aun_pkt_buffer {
	struct __econet_packet_aun d;
	unsigned int length;
};

/* Internal functions */

/* Function declarations */

int econet_probe(struct platform_device *);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,20)
int econet_remove(struct platform_device *);
#else
void econet_remove(struct platform_device *);
#endif
int econet_open(struct inode *, struct file *);
int econet_release(struct inode *, struct file *);
long econet_ioctl (struct file *, unsigned int, unsigned long);
unsigned int econet_poll (struct file *, poll_table *);
ssize_t econet_readfd(struct file *, char *, size_t, loff_t *);
ssize_t econet_writefd(struct file *, const char *, size_t, loff_t *);
void econet_set_read_mode(void);
u8 econet_seize(void);
void econet_free_txrx(void);
void econet_netclock_set(uint8_t, uint8_t);
int econet_netclock_init(struct device *);
int econet_probe_adapter(void);
void econet_adlc_cleardown(unsigned short);
void econet_finish_tx(void);
void econet_irq_write(void);
void econet_irq_read(void);
void econet_aun_tx_statemachine(void);
void econet_led_state (uint8_t);
inline void econet_aun_setidle_txstatus(int);
int econet_rwdevice_init(void);
int econet_monitor_init(void);
int econet_monitor_open(struct inode *, struct file *);
int econet_monitor_release(struct inode *, struct file *);
long econet_monitor_ioctl (struct file *, unsigned int, unsigned long);
unsigned int econet_monitor_poll (struct file *, poll_table *);
ssize_t econet_monitor_readfd(struct file *, char *, size_t, loff_t *);
void econet_led_off(void);
void econet_workqueue_handler (struct work_struct *);

/*
 * Some variables in the sources
 */

// extern unsigned char econet_stations[8192];
extern u8 sr1, sr2, econet_class_initialized, econet_device_initialized;
extern u32 gpioset_value;
extern void __iomem *GPIO_PORT;
extern unsigned GPIO_RANGE;
extern spinlock_t econet_irq_spin, econet_tx_spin, econet_irqstate_spin;
extern u64 last_data_rcvd;
extern struct __econet_packet dump_pkt;
extern struct __econet_pkt_buffer econet_pkt, econet_pkt_tx, econet_pkt_tx_prepare, econet_pkt_rx, pkt_copy;
extern struct __aun_pkt_buffer	aun_rx, aun_tx;
extern struct __econet_data *econet_data;
extern struct class *econet_class;
extern struct class *monitor_class;

extern u8 econet_class_initialized, econet_device_created;
extern u8 monitor_class_initialized, monitor_device_created;

extern unsigned long tx_packets;
extern struct file_operations econet_fops, monitor_fops;

/* FIFO externs */

extern struct kfifo_rec_ptr_2 econet_rx_queue;
extern struct kfifo_rec_ptr_2 econet_tx_queue;
extern u8 econet_rx_queue_initialized, econet_tx_queue_initialized, monitor_rx_queue_initialized;

/* Mutex externs */

extern spinlock_t econet_irq_spin, econet_tx_spin, econet_irqstate_spin;

extern struct __econet_packet * econet_alloc_pbuf(void);
extern void econet_free_pbuf(struct __econet_packet *);
extern eco_work_t * econet_alloc_workbuf(void);
extern void econet_free_workbuf(eco_work_t *);

/*
 * Some macros to make the code
 * easier to read when reading the
 * list of gpios.
 *
 */

#define ECOPIN(a)       econet_data->econet_gpios[(a)]
#define ECONET_GETGPIO(i,n,d)   econet_data->econet_gpios[(i)] = devm_gpiod_get(dev, n, (d))
#define ECONET_GPIOERR(i) if (IS_ERR(econet_data->econet_gpios[(i)])) { printk (KERN_INFO "econet-gpio: Failed to obtain GPIO ref %d\n", (i)); return PTR_ERR(econet_data->econet_gpios[(i)]); }

/*
 * Some constants used for the nasty
 * timing loops on v1 hardware.
 */

#define ECONET_GPIO_CLOCK_DUTY_CYCLE  1000   /* In nanoseconds - 2MHz clock is 500 ns duty cycle, 1MHz is 1us, or 1000ns */


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

/* Defines for the global module busy flag */

#define ECONET_IS_BUSY()	atomic_read(&(econet_data->busy))
#define ECONET_SET_BUSY()	atomic_set(&(econet_data->busy), 1)
#define ECONET_NOT_BUSY()	atomic_set(&(econet_data->busy), 0)

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

#define econet_stations	(econet_data->station_map)

/* Kernel module state */

struct __econet_data {

	/* IRQ state information */
	int irq;
	atomic_t irq_state;

	/* Module type */
	u8	module_type;

	/* Module platform device */
	struct device *module_dev;

	/* Main Econet device */
	struct device *dev;
	struct cdev c_dev;
	int major;
	dev_t majorminor;
	short open_count;
	wait_queue_head_t rx_queue;
	wait_queue_head_t econet_read_queue; /* Old module compat */
	wait_queue_head_t tx_queue;
	struct kfifo_rec_ptr_2 readfd_fifo;
	u8 readfd_fifo_initialized;

	/* Econet monitor device */
	struct device *monitor_dev;
	struct cdev monitor_c_dev;
	int monitor_major;
	dev_t monitor_majorminor;
	short monitor_count; /* Number of open monitor connections */
	wait_queue_head_t monitor_queue;
	struct kfifo_rec_ptr_2 monitor_fifo;
	u8 monitor_fifo_initialized;

	/* AUN Packet storage - sending AUN data between readfd()/writefd() and the workqueue handler */
	/* Signalling between writefd() and the workqueue */
	struct __econet_packet_aun aun_packet_rx;
	u16 aun_packet_len_rx; /* Number of AUN data bytes inside aun_packet_rx */
	struct __econet_packet_aun aun_packet_tx;
	u16 aun_packet_len_tx; /* Number of AUN data bytes inside aun_packet_tx */

	/* Main module state */
	atomic_t mode; // IRQ handler state machine IDLEINIT -> IDLE -> (READ / WRITE_START); WRITE_START -> WRITE -> WRITE_WAIT or IDLE. Only IRQ space writes to this.
	atomic_t tx_status;
	volatile u16 tx_status_valid;
	u8 aun_mode;
	atomic_t aun_state;
	unsigned char initialized; // Whether module is actually initialized
	unsigned char extralogs; // If 1, extra dmesg logging happens (e.g. collisions, rx aborts, etc.)
	unsigned char auntransitionlogs; // If 1, extra dmesg logging from aun state machine changes
	unsigned char chipstatelogs; // If 1, extra dmesg logging from chip state changes
	u8 resilience; // 0 = off; 1 = in AUN mode, will just flag fill after receipt of data from station when reading a 4-way instead of sending final ACK. (Not implemented yet.) Userspace will use ioctl() to signal the ACK has arrived and that the wire ACK can then be sent. In this mode, userspace will have set a thread going which waits for a timeout, checks to see if the kernel is still in EA_R_PENDINGFINALACK and if it is then puts it back into read mode. This will generate net error on the sending wire station, which is the best we can do if destination station fails to respond (perhaps over trunk) when the module has to convert 4-way traffic to AUN.

	/* Do not flag fill - gets set when we transmit a two way, or data packet of 4-way, so the module knows
	 * not to FF on receipt of next packet. Gets reset on line idle */

	u8 no_flag_fill;

	/* How many Packets since idle - we don't flag fill on receipt if this is two! */
	u8 pkt_since_idle;

	/* Clock detection state */
	u8 clock_state;

	/* Whether module busy */
	atomic_t busy;

	/* AUN flags */
	long aun_seq;
	u64 aun_last_tx;
	u64 aun_last_rx;
	u64 aun_last_writefd;
	u64 aun_last_statechange;
	atomic64_t	last_aun_rx_complete;

	/* Raw Econet stuff */
	short last_tx_user_error;

	/* GPIO, hardware version etc. */
	struct gpio_desc	*econet_gpios[20];
	unsigned char hwver;

	/* ADLC Information */
	unsigned char current_dir; // Current databus direction
	unsigned long peribase; // Peripheral base address
	u8 twobytemode; // 0 = 1 byte per IRQ; 1 = 2 bytes per IRQ like a Beeb does.

	/* Clocks */

		/* ADLC clock */
	
		struct clk		*gpio4clk;
	
		/* Network clock */
	
		struct pwm_device	*gpio18pwm;

	/* Timing info */

	struct __econet_packet_timings	pt; // Packet timing data - gets reset to 0 each time we start a tx

	/* Workqueue */

	struct workqueue_struct *workqueue; // Process-side packet manipulation workqueue

	/* Econet packet buffers */
	/* Each of rxp and txp below will point to one of these
	 * buffer array entries, so we don't alloc/free 
	 * in IRQ
	 */

	struct __econet_packet *pbuf[ECONET_GPIO_MAX_BUFFERS];
	u32	pbuf_inuse; /* 1 bit per entry - bit 0 is pbuf[0] */
	struct mutex pbuf_mutex;

	/* Econet workqueue buffers */
	eco_work_t *workbuf[ECONET_GPIO_MAX_WORK_BUFFERS];
	u32 workbuf_inuse;
	struct mutex workbuf_mutex;

	/* RX Buffer pointer, suitable for putting on a workqueue */

	struct __econet_packet *rxp;

	/* TX Buffer pointer, which is set up either by writefd() or the workqueue depending
	 * on where we are in the state machine, suitable for returning to the workqueue
	 * on completion of transmission, whether successful or not.
	 */

	struct __econet_packet *txp;

	/* Station map */
	u8	station_map[8192];
};

extern struct __econet_packet_aun	aun_tmp; /* Used by writefd() in module-fast to avoid a copy_from_user whilst IRQ locked */

/* Macro to calculate mem allocation needed for a packet with n bytes in it */

#define ECONET_PACKET_SIZE(n)	(sizeof(struct __econet_packet) - ECONET_MAX_PACKET_SIZE + n)

/* Macro to calculate mem allocation needed for 3rd phase packet where AUN data is n bytes */

#define ECONET_DATA_PACKET_SIZE(n) (ECONET_PACKET_SIZE(n+4))

/* Macro to calculate mem allocation needed for scout packet where scout data length is n bytes */

#define ECONET_SCOUT_PACKET_SIZE(n) (ECONET_PACKET_SIZE(n+6))

/* Macro to calcualte mem allocation needed for ACK packet */

#define ECONET_ACK_PACKET_SIZE (ECONET_PACKET_SIZE(4))

/* emalloc - shortens some devm_kzmalloc code */

#define emalloc(n) devm_kzalloc(econet_data->module_dev, n, GFP_KERNEL);

/* Extern for main driver data */

extern struct __econet_data *econet_data;


/*
 * Macros which abstract econet_write_cr()
 * to write to the FIFO and write to
 * FIFO and signal last data byte
 */

#define econet_write_fifo(x) econet_write_cr(3, (x))
#define econet_write_last(x) econet_write_cr(4, (x))
#define econet_read_fifo() econet_read_sr(3)

#endif
