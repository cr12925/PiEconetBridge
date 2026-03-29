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
 * Monitor operations
 */

struct file_operations monitor_fops = {
	.open = econet_monitor_open,
	.release = econet_monitor_release,
	.unlocked_ioctl = econet_monitor_ioctl,
	.poll = econet_monitor_poll,
	.read = econet_monitor_readfd
};

/*
 * econet_monitor_readfd()
 *
 * Monitor read routine from usespace
 *
 */

ssize_t econet_monitor_readfd(struct file *flip, char *buffer, size_t len, loff_t *offset) {

	int ret = -1;

	struct __econet_packet	*p;

#if 0
	if (econet_data->extralogs)
		printk (KERN_INFO "econet-fast: Monitor device read, buffer at %p length %02X\n", buffer, len);
#endif

	if (!kfifo_initialized(&(econet_data->monitor_fifo)))
	{
		printk (KERN_ERR "econet-fast: Attempt to read monitor fifo before it was initialized\n");
		return -EFAULT;
	}

	/* Read from a FIFO */

	if (kfifo_out (&(econet_data->monitor_fifo), &p, sizeof(struct __econet_packet *)))
	{
		// printk (KERN_INFO "econet-fast: econet_packet struct off fifo at %p\n", p);

		if (p)
		{
			// printk (KERN_INFO "econet-fast: copy packet at %p to user on read()\n", p);
			ret = copy_to_user(buffer, p, sizeof(struct __econet_packet) - (ECONET_MAX_PACKET_SIZE - p->ptr)); /* Only copy the used bytes */
			//printk (KERN_INFO "econet-fast: free()ing packet pointer at %p\n", p);
			devm_kfree (econet_data->module_dev, p); /* This is what had been allocated to econet_data->rxp at init and whenever an RX packet or signalling is put on the workqueue */
		}
	}

	if (ret == 0)
		return sizeof(struct __econet_packet) - (ECONET_MAX_PACKET_SIZE - p->ptr);
	else	return -EFAULT;

}

/* 
 * econet_monitor_open()
 *
 * Called when a process opens our device 
 *
 */

int econet_monitor_open(struct inode *inode, struct file *file) {

	/* If device is open, return busy */

	if (econet_data->monitor_count)
		return -EBUSY;

	try_module_get(THIS_MODULE);

	/* Increment open_count so we know we are busy */

	econet_data->monitor_count++;

	if (econet_data->extralogs)
		printk (KERN_INFO "econet-fast: Monitor device opened\n");

	if (!econet_data->open_count || econet_get_chipstate() == EM_TEST)
		econet_reset();

	// econet_irq_mode(1); /* Turn IRQs on if not before */

	return 0;
}

/* 
 * econet_monitor_release()
 *
 * Called when a process closes our device
 *
 */

int econet_monitor_release(struct inode *inode, struct file *file) {

	/* Decrement the open counter and usage count. Without this, the module would not unload. */

	econet_data->monitor_count--;

	kfifo_reset(&(econet_data->monitor_fifo));

	module_put(THIS_MODULE);

	if (econet_data->extralogs)
		printk (KERN_INFO "econet-fast: Montior device closed\n");

	return 0;
}

/* 
 * econet_monitor_poll()
 *
 * Poll routine from userspace
 *
 */

unsigned int econet_monitor_poll (struct file *filp, poll_table *wait)
{

	unsigned int mask = 0;

	if (!kfifo_initialized(&(econet_data->monitor_fifo)))
	{
		printk (KERN_ERR "econet-fast: Attempt to poll monitor before fifo was initialized\n");
		return -EFAULT;
	}

	/* Snooze on the read queue */

	poll_wait (filp, &(econet_data->monitor_queue), wait);

	/* If there's data on the FIFO, tell the user */

	if (!kfifo_is_empty(&(econet_data->monitor_fifo)))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

MODULE_LICENSE("GPL");
