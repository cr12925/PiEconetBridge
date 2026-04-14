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
 * econet_ioctl()
 *
 * Handle ioctl() calls from userspace
 *
 */

long econet_ioctl (struct file *gp, unsigned int cmd, unsigned long arg)
{

#ifdef ECONET_GPIO_DEBUG_IOCTL
	printk (KERN_DEBUG "econet-fast: IOCTL(%d, %lu)\n", cmd, arg);
#endif

	switch(cmd){

		/*
		 * Reset the module & ADLC 
		 *
		 */

		case ECONETGPIO_IOC_RESET:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-fast: ioctl(reset) called\n");
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
			printk (KERN_INFO "econet-fast: ioctl(max_packet_size) called\n");
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
			printk (KERN_INFO "econet-fast: ioctl(set read mode) called\n");
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
			printk (KERN_INFO "econet-fast: ioctl(set stations) called\n");
#endif
			/* Copy station bitmap from user memory */

			if ((!access_ok((void __user *) arg, 8192)) || copy_from_user(econet_stations, (void *) arg, 8192))
			{
				printk (KERN_INFO "econet-fast: Unable to update station set.\n");
				return -EFAULT;
			}

			if (econet_data->extralogs) printk(KERN_INFO "econet-fast: Station set updated - Switching on AUN mode\n");
			else if (econet_data->aun_mode != 1) printk (KERN_INFO "econet-fast: AUN mode on\n");

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
			printk (KERN_INFO "econet-fast: ioctl(rx queue availablity) called\n");
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
			printk (KERN_INFO "econet-fast: ioctl(set address, %02lx) called\n", (arg & 0x03));
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
			printk (KERN_INFO "econet-fast: ioctl(set write mode, %02lx) called\n", (arg & 0x01));
#endif
			econet_set_dir(arg & 0x01);
			break;

		/*
		 * Set Chip select line
		 *
		 */

		case ECONETGPIO_IOC_SETCS:
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-fast: ioctl(set /CS, %02lx) called\n", (arg & 0x01));
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
			printk (KERN_INFO "econet-fast: ioctl(set bus, %02lx) called\n", (arg & 0xff));
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
			printk (KERN_INFO "econet-fast: ioctl(set test mode) called\n");
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
				uint8_t s = econet_data->tx_status_valid & 0xFF;

#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-fast: ioctl(get last tx error) called - current status %02x\n", s);
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
		 * Module fast no longer returns the tx ptr
		 *
		 */

		case ECONETGPIO_IOC_GETAUNSTATE:
			return (econet_get_aunstate());
			break;

		/*
		 * Go into flag fill or set read mode.
		 * Not clear why this is still here.
		 *
		 */

		case ECONETGPIO_IOC_FLAGFILL: 
#ifdef ECONET_GPIO_DEBUG_IOCTL
			printk (KERN_INFO "econet-fast: ioctl(set flag fill) called\n");
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
				printk (KERN_ERR "econet-fast: Invalid argument (%ld) to ECONETGPIO_IOC_AUNMODE ioctl()\n", arg);
				break;
			}

			/* Reset the ADLC & change AUN mode */

			econet_reset();

			econet_data->aun_mode = arg; // Must do this after econet_reset, because econet_reset turns AUN off.

			printk (KERN_INFO "econet-fast: AUN mode turned %s\n", (arg == 1 ? "on" : "off"));

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
			printk (KERN_INFO "econet-fast: Immediate spoofing no longer supported. ioctl(ECONETGPIO_IOC_IMMSPOOF) ignored.\n");
			break;

		/*
		 * Turn on extra logging in the live module.
		 * Or turn it off.
		 *
		 */

		case ECONETGPIO_IOC_EXTRALOGS:

			econet_data->extralogs = (arg == 0) ? 0 : 1;
			printk (KERN_INFO "econet-fast: Extra logging turned %s\n", (arg == 0) ? "OFF" : "ON");
			break;

		/*
		 * Cause module to emit a test packet.
		 *
		 * The packet is a machine type query 
		 * spoofed from 0.254 to 0.1.
		 *
		 */

		case ECONETGPIO_IOC_TESTPACKET: 
			printk (KERN_INFO "econet-fast: ioctl(test packet) not implemented in this version\n");
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
				econet_netclock_set (((arg & 0xffff0000) >> 16), (arg & 0xffff));

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

		case ECONETGPIO_IOC_MODULEVERS:
			if (econet_data)
				return econet_data->module_type;
			else	return 0;
			break;
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

				if (econet_data->extralogs) printk (KERN_INFO "econet-fast: Sent resilient 4-way final ACK\n");

			} break;

		case ECONETGPIO_IOC_RESILIENCEMODE:
			{
				econet_data->resilience = (arg & 0x01); // Strip all but low bit
				printk (KERN_INFO "econet-fast: Resilience mode %s\n", ((arg & 0x01) == 0) ? "OFF" : "ON");

			} break;
		/*
		 * And if we get here, then something
		 * went wrong...
		 *
		 */

		case ECONETGPIO_IOC_TWOBYTEMODE:
			{
				econet_data->twobytemode = (arg & 0x01); 
				if (econet_data->extralogs) printk (KERN_INFO "econet-fast: Two byte transfer mode set\n");
			} break;

		/* 
		 * Copy packet transmission timings to user space
		 */

		case ECONETGPIO_IOC_GETTIMINGS:
			{
				if (copy_to_user((struct __econet_packet_timings *) arg, &(econet_data->pt), sizeof (struct __econet_packet_timings)))
					printk (KERN_ERR "econet-fast: unable to write kernel tx timings in response to ioctl()!");
			} break;

		default:
			return -ENOTTY;
	}

	return 0;

}

MODULE_LICENSE("GPL");
