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

/* Prototypes */

u8 econet_writefd_transmit(void);

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

	ret = kfifo_to_user(&(econet_data->readfd_fifo), buffer, len, &copied);

	if (ret == 0)
		return copied;
	else	return -EFAULT;


}


/* 
 * Transmit handler
 *
 * Returns 1 for success; 0 for failure (and status in the tx status)
 */

u8 econet_writefd_transmit(void)
{

	u8 	seize_result = 0;

	econet_set_tx_status(ECONET_TX_NOTSTART);

	if (econet_data->aun_mode)
	{
		u16	scout_data_len = 0;
		u8	data_position = 6; /* For an ordinary scout */

		/* Check for invalid AUN packet types. */

		if (	econet_data->aun_packet.p.aun_ttype > 6 
			|| econet_data->aun_packet.p.aun_ttype == 0 
			|| econet_data->aun_packet.p.aun_ttype == 3 
			|| econet_data->aun_packet.p.aun_ttype == 4
	   	)
		{
			econet_set_tx_status (ECONET_TX_INVALID); /* Can't put that packet type on the wire */
			return 0;
		}

		/* Is it a 4-way transaction we're starting ? */

		else if (__IS_AUN_FOURWAY(econet_data->aun_packet))
		{
			/* We cheat and put the number of extra data bytes in the scout into the AUN padding field 
		 	* which saves the IRQ routine calculating it all the time
		 	*/
	
			scout_data_len = __AUN_SCOUTBYTES(econet_data->aun_packet);

			if (!econet_data->aun_packet_len || scout_data_len >= econet_data->aun_packet_len)
			{
				/* There is either insufficient data to make a valid scout, or there would be no data left to go in the data phase, so this must be an invalid packet */
				econet_set_tx_status (ECONET_TX_INSUFFICIENTDATA); 
				return 0;
			}
		}
		else	scout_data_len = econet_data->aun_packet_len; /* Send all the data - so for 2-way immediates and broadcasts */
	
		econet_data->aun_packet.p.padding = scout_data_len; /* Used later when the AUN statemachine receives a first ACK - enables it to work out how much storage to allocate for the subsequent data frame */

		/* Copy packet data */

		econet_data->txp = emalloc(ECONET_SCOUT_PACKET_SIZE(scout_data_len));
		
		if (!econet_data->txp)
		{
			printk (KERN_ERR "econet-fast: Failed to allocate memory for AUN mode TX packet!\n");
			econet_set_tx_status (ECONET_TX_NOMEM);
			return 0;
		}

		/* First, copy addressing */

		memcpy(&(econet_data->txp->data), &(econet_data->aun_packet.p.dststn), 4);

		if (econet_data->aun_packet.p.aun_ttype == ECONET_AUN_IMMREP)
			data_position = 4; /* No port/ctrl on an immrep */

		/* Then port & ctrl - these get overwritten below if it's an immrep */

		__PORT(econet_data->txp) = econet_data->aun_packet.p.port;
		__CTRL(econet_data->txp) = econet_data->aun_packet.p.ctrl | 0x80; /* May as well set high bit here */

		/* Then scout data */

		if (scout_data_len > 0)
			memcpy(&(econet_data->txp->data[data_position]), &(econet_data->aun_packet.p.data), scout_data_len);

		/* Tell the IRQ routine how many bytes to send */

		econet_data->txp->txlen = data_position + scout_data_len;

		/* Set AUN status to WRITESCOUT.
		 * In this version of the kernel module, all first
		 * packets are seen as a scout. The state machine
		 * then works out based on what arrived in response
		 * whether to do anything else like move to a 2-way
		 * or 4-way state.
		 */

		if (econet_data->aun_packet.p.aun_ttype != ECONET_AUN_IMMREP) /* Only change state if not an immediate reply, because we'll be in EA_I_WRITEREPLY if that's the case */
			econet_set_aunstate (EA_W_WRITESCOUT); 
	}
	else /* Not AUN mode - i.e. raw */
	{
		/* Copy packet data */	

		/* This will be a raw frame in non-AUN mode, so
		 * just copy the lot
		 */

		econet_data->txp = emalloc(ECONET_PACKET_SIZE(econet_data->aun_packet_len));

		if (!econet_data->txp)
		{
			printk (KERN_ERR "econet-fast: Failed to allocate memory for raw mode tx packet!\n");
			econet_set_tx_status (ECONET_TX_NOMEM);
			return 0;
		}

		printk (KERN_INFO "econet-fast: Copying 0x%04X bytes into txp->data\n", econet_data->aun_packet_len);

		memcpy(&(econet_data->txp->data), &(econet_data->aun_packet.raw), econet_data->aun_packet_len);

		econet_data->txp->txlen = econet_data->aun_packet_len;

	}

	/* Trigger TX */

	if ((seize_result = econet_seize()))
	{
		printk (KERN_INFO "econet-fast: Line seize failed!\n");

		econet_set_tx_status(seize_result);
		devm_kfree(econet_data->module_dev, econet_data->txp);

		ECONET_NOT_BUSY();

		return 0;
	}

	/* Set our status to startwait, though in this version of
	 * the module, userspace will never see it.
	 */

	econet_set_tx_status (ECONET_TX_STARTWAIT); /* ADLC has not yet started transmitting */

	/* Flag module busy */

	ECONET_IS_BUSY();

	return 1;
}

/*
 * econet_writefd()
 *
 * Module write function on the device
 *
 */

ssize_t econet_writefd(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{

	unsigned long flags;
	int happens;

	econet_data->tx_status_valid = 0; /* High bit set means valid */

	/* If length cannot be right, barf */

	if (len > (ECONET_MAX_PACKET_SIZE + (econet_data->aun_mode ? 12 : 0)))
		return -EPROTO;

	/* Attempt to seize the line, and return error on failure. 
	 * If successful, copy packet to the econet_data->aun_packet and econet_data->aun_packet_length
	 * fields.
	 *
	 * Then set up the first packet in econet_data->txp
	 *
	 * Set up AUN state machine, and let the IRQ handler do the rest. 
	 * Wait on econet_data->tx_queue. We'll be woken up when TX has
	 * ended one way or another, and can return to user.
	 *
	 */

	/* Grab IRQ spinlock and see if the module is busy */

	spin_lock_irqsave(&econet_irq_spin, flags);

	if (ECONET_IS_BUSY())
	{
		econet_set_tx_status (ECONET_TX_BUSY);
		spin_unlock_irqrestore(&econet_irq_spin, flags);
		return -EFAULT;
	}

	// econet_irq_mode(0); /* Turn IRQs off */

	/* Copy buffer from userspace to aun_packet
	 * (which is used for raw transmissions as well
	 */

	if (!access_ok((void __user *) buffer, len) ||
		copy_from_user(&(econet_data->aun_packet), (void *) buffer, len)
	   )
	{
		printk (KERN_INFO "econet-fast: Unable to copy packet from userspace\n");
		return -EFAULT;
	}

	/* Set AUN packet length - data bytes only if AUN mode,
	 * otherwise whole length
	 */

	econet_data->aun_packet_len = len - (econet_data->aun_mode ? 12 : 0);

	if (!econet_writefd_transmit()) /* Sort out the packet data to transmit */
	{
		/* Failed! */

		econet_set_read_mode();
		spin_unlock_irqrestore(&econet_irq_spin, flags);
		// econet_irq_mode(1);
		return -EFAULT;
	}

	/* If we get here, we're actually going to start transmit. */

	ECONET_SET_BUSY();

	/* Turn IRQs back on */

	spin_unlock_irqrestore(&econet_irq_spin, flags); /* Let the ADLC and the IRQ routine run */
	
	// econet_irq_mode(1);

	/* Wait on the write_queue - the work queue will tell us when the transaction ends, good bad or indifferent */

	happens = wait_event_interruptible_timeout(econet_data->tx_queue, (econet_data->tx_status_valid & 0x8000), 4 * HZ);

	if (happens >= 1) /* TX VAlid - because either that happened before or after elapse of timeout */
		return len; /* We accepted the whole packet, userspace can work out what happened by getting the status */
	else /* Timeout and condition not true */
	{
		printk (KERN_INFO "econet-fast: writefd() wait timeout expired\n");
		return -EFAULT;
	}
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

	printk (KERN_INFO "econet-fast: Read/Write device opened\n");

	/* Decrement the module use count */

	try_module_get(THIS_MODULE);
	
	/* Reset the ADLC, packet buffers, station set  */

	econet_reset(); 

	// econet_irq_mode(1); /* IRQs on, if they weren't before */

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

#if 0
	if (!econet_data->monitor_count)
	{
		econet_irq_mode(0);
	}
#endif

#if 0 /* Don't do this. Because if your client goes away mid transaction, the work queue does a RAW mode AUN statemachine */
	/* Turn off AUN mode */

	econet_data->aun_mode = 0;

	econet_set_aunstate(EA_IDLE);
#endif

	module_put(THIS_MODULE);

	printk (KERN_INFO "econet-fast: Read/Write device closed\n");

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

	poll_wait (filp, &(econet_data->rx_queue), wait);

	/* If there's data on the FIFO, tell the user */

	if (!kfifo_is_empty(&econet_data->readfd_fifo))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

MODULE_LICENSE("GPL");
