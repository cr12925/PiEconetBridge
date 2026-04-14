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

/* Internal data */
struct __econet_data *econet_data = NULL;

#ifdef ECONET_GPIO_NEW
struct gpio_desc *a01rw_desc_array[3];
struct gpio_desc *data_desc_array[11]; // Top 3 are the address & RnW lines in case of need
#endif

/* Prototypes */

int econet_init_vars(void);

/* econet_init_vars 
 *
 * set up various globals and state
 *
 */

int econet_init_vars (void)
{

	int result;
	u8	pbuf_count;

        /* Main initialization routine */

        /* Start in test mode so the module has nothing to deal with */

        econet_set_chipstate(EM_IDLE);

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

        /* Iniialize kfifos */

        result = kfifo_alloc(&(econet_data->readfd_fifo), 65536, GFP_KERNEL);

        if (result)
        {
                printk (KERN_INFO "econet-fast: Failed to allocate kernel RX fifo\n");
                return -ENOMEM;
        }

        econet_data->readfd_fifo_initialized = 1;

	result = kfifo_alloc(&(econet_data->monitor_fifo), 65536, GFP_KERNEL);

	if (result)
	{
		printk (KERN_INFO "econet-fast: Failed to allocate kernel monitor fifo\n");
		return -ENOMEM;
	}

	econet_data->monitor_fifo_initialized = 1;

	/* Initialize process-side workqueue */

	econet_data->workqueue = alloc_ordered_workqueue("econet_workqueue", WQ_MEM_RECLAIM);

	if (!econet_data->workqueue)
	{
		printk (KERN_ERR "econet-fast: Failed to create Econet workqueue");
		return -ENOMEM;
	}

        /* Init spinlocks */

        spin_lock_init(&econet_irqstate_spin);
        spin_lock_init(&econet_tx_spin);

	/* Packet buffer init */

	for (pbuf_count = 0; pbuf_count < ECONET_GPIO_MAX_BUFFERS; pbuf_count++)
	{
		econet_data->pbuf[pbuf_count] = devm_kzalloc(econet_data->module_dev, sizeof(struct __econet_packet), GFP_KERNEL);
		if (!econet_data->pbuf[pbuf_count]) /* Failed */
		{
			printk (KERN_ERR "econet-fast: Unable to allocate packet buffer memory, entry %d\n", pbuf_count);
			return -ENOMEM;
		}
	}

	econet_data->pbuf_inuse = 0;

	mutex_init(&(econet_data->pbuf_mutex));

	/* And now the workqueue buffers */

	for (pbuf_count = 0; pbuf_count < ECONET_GPIO_MAX_WORK_BUFFERS; pbuf_count++)
	{
		econet_data->workbuf[pbuf_count] = devm_kzalloc(econet_data->module_dev, sizeof(eco_work_t), GFP_KERNEL);

		if (!econet_data->workbuf[pbuf_count])
		{
			printk (KERN_ERR "econet-fast: Unable to allocate workqueue buffer, entry %d\n", pbuf_count);
			return -ENOMEM;
		}
	}

	econet_data->workbuf_inuse = 0;

	mutex_init(&(econet_data->workbuf_mutex));

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

int econet_probe (struct platform_device *pdev)
{

	int result, err;
	u8	count;

	struct device *dev = &pdev->dev;
	struct device_node *econet_device;
	u8	version = 0;
	u32	gpio4clk_rate;

#ifdef ECONET_GPIO_NEW
	printk (KERN_INFO "econet-fast: Module loading in new mode\n");
#else
	printk (KERN_INFO "econet-fast: Module loading\n");
#endif

	/*
	 * Allocate our private data space,
	 * and complain bitterly if we can't do so.
	 *
	 */

	econet_data = devm_kzalloc(&(pdev->dev), sizeof(struct __econet_data), GFP_KERNEL);

	if (!econet_data)
	{
		printk (KERN_ERR "econet-fast: Failed to allocate internal data storage.\n");
		return -ENOMEM;
	}

	econet_data->module_dev = &(pdev->dev);

	/* 20260326 TEMP */

	econet_data->auntransitionlogs = 0;
	// econet_data->chipstatelogs = 1;

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

	/*
	 * If we did not find the device in the tree,
	 * give up, and free our private data allocation.
	 *
	 */

	if (!econet_device)
	{
		printk (KERN_INFO "econet-fast: No device tree entry found. Abort.\n");
		econet_data = NULL;
		return -ENODEV;
	}

	/* If we've found it, look up the version number */

	if (of_property_read_u8_array(econet_device, "version", &version, 1) == 0)
		econet_data->hwver = version;

	/*
	 * Or if we did find it, but it didn't have a version
	 * number in it, complain & abort, similarly 
	 * freeing up our data space.
	 *
	 */

	else if (version == 0)
	{
		printk (KERN_INFO "econet-fast: No version found in device tree. Do you need to load an overlay? Abort.\n");
		econet_data = NULL;
		return -ENODEV;
	}

	of_node_put (econet_device); // Supports NULL parameter apparently, so doesn't need to be guarded by if()

	/* Initialize various important variables */

	if ((result = econet_init_vars()))
	{
		printk (KERN_INFO "econet-fast: Unable to initialize main module variables. Abort.\n");
		econet_data = NULL;
		return result;
	}

	/* Next set up initial storage for an incoming packet */

	econet_data->rxp = econet_alloc_pbuf();

	if (!econet_data->rxp)
	{
		printk (KERN_ERR "econet-fast: Failed to allocate rx packet storage.\n");
		return -ENOMEM;
	}

	result = 0;

	/*
	 * If we are in new mode, but we have found
	 * a version 1 board, then that won't work at 
	 * all, so give up.
	 *
	 */

#ifdef ECONET_GPIO_NEW
	if (econet_data->hwver < 2)
	{
		printk (KERN_ERR "econet-fast: Hardware version (%d) incompatible with this module. Please compile module in old mode.\n", econet_data->hwver);
		econet_data = NULL;
		return -ENODEV;
	}
#endif

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
	printk (KERN_INFO "econet-fast: Old econet_ndelay() code disabled. This is Good.\n");
#endif

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
		printk (KERN_INFO "econet-fast: Hardware v%d on a Pi4B\n", econet_data->hwver);
	else if (of_machine_is_compatible("raspberrypi,400"))
		printk (KERN_INFO "econet-fast: Hardware v%d on a Pi400\n", econet_data->hwver);
	else if (of_machine_is_compatible("raspberrypi,3-model-b"))
	{
		econet_data->peribase = 0x3F000000;
		printk (KERN_INFO "econet-fast: Hardware v%d on a Pi3\n", econet_data->hwver);
	}
	else if (of_machine_is_compatible("raspberrypi,3-model-b-plus"))
	{
		econet_data->peribase = 0x3F000000;
		printk (KERN_INFO "econet-fast: Hardware v%d on a Pi3B+\n", econet_data->hwver);
	}
	else if (of_machine_is_compatible("raspberrypi,model-zero-w") || of_machine_is_compatible("raspberrypi,model-zero"))
	{
		econet_data->peribase = 0x20000000;
		printk (KERN_INFO "econet-fast: Hardware v%d on a PiZero (reliability uncertain)\n", econet_data->hwver);
	}
	else if (of_machine_is_compatible("raspberrypi,model-zero-2-w") || of_machine_is_compatible("raspberrypi,model-zero-2"))
	{
		econet_data->peribase = 0x3F000000;
		printk (KERN_INFO "econet-fast: Hardware v%d on a PiZero2\n", econet_data->hwver);
	}
	else 
	{
		printk (KERN_INFO "econet-fast: Hardware v%d, Machine compatibility uncertain - assuming Peripheral base at 0xFE000000\n", econet_data->hwver);
	}

	request_region(GPIO_PERI_BASE, GPIO_RANGE, DEVICE_NAME);
	GPIO_PORT = ioremap(GPIO_PERI_BASE, GPIO_RANGE);

	if (!GPIO_PORT)
	{
		printk (KERN_INFO "econet-fast: GPIO base remap failed.\n");
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
			printk (KERN_ERR "econet-fast: Unable to obtain GPIO 4 clock (GPCLK0) for ADLC clock (%ld)\n", PTR_ERR(econet_data->gpio4clk));
			result = PTR_ERR(econet_data->gpio4clk);
			econet_remove(NULL);
			return result;
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
			printk (KERN_ERR "econet-fast: Unable to find clock frequency for gpio4 (ADLC) clock in device tree\n");
			econet_remove(NULL);
			return ret;
		}
	
		/*
		 * Reassure the user that we are
		 * setting the clock, and to what
		 * frequency.
		 *
		 */

		printk (KERN_INFO "econet-fast: Setting gpio4 ADLC clock (GPCLK0) to %dkHz\n", gpio4clk_rate/1000);
	
		/* 
		 * Set the rate & enable clock.
		 *
		 */

		clk_set_rate (econet_data->gpio4clk, gpio4clk_rate);
		clk_prepare (econet_data->gpio4clk);

	
		if ((result = econet_netclock_init(dev)))
		{
			econet_remove(NULL);
			return (-ENODEV);
		}
		
	}

	result = econet_rwdevice_init();

	if (result)
	{
		econet_remove(NULL);
		return result;
	}

	result = econet_monitor_init();

	if (result)
	{
		econet_remove(NULL);
		return result;
	}

	result = 0;

	init_waitqueue_head(&(econet_data->rx_queue));
	init_waitqueue_head(&(econet_data->tx_queue));
	init_waitqueue_head(&(econet_data->monitor_queue));

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
		printk (KERN_INFO "econet-fast: Failed to request IRQ\n");
		econet_remove(NULL);
		return err;
	}

	/* Turn IRQs off */

	econet_irq_mode(0);

	/*
	 * Starting to cook on gas now.
	 *
	 * Do a full reset, which will clear the station
	 * array set, and move to read mode in the 
	 * ADLC.
	 *
	 */

	econet_reset();

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

	if (sr2 & ECONET_GPIO_S2_DCD)
	{
		printk (KERN_ERR "econet-fast: No clock! (SR1 = 0x%02x, SR2 = 0x%02x)\n", sr1, sr2);
		econet_data->clock_state = 0;
	}
	else	
	{
		econet_data->clock_state = 1;
		if (econet_data->extralogs) printk (KERN_INFO "econet-fast: Clock detected\n"); /* Don't bother unless the user wants to know! */
	}

	/* Show that we are ready for service */

	econet_data->initialized = 1;

	/* IRQs are off at this stage */

	econet_irq_mode(1);

	/* Return success */

	return 0;

}

/* 
 * econet_remove()
 *
 * Module exit routine 
 *
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,20)
int econet_remove(struct platform_device *pdev)
#else
void econet_remove(struct platform_device *pdev)
#endif
{

	/*
	 * If we have econet_data, clean up the other
	 * things which may be initialized
	 *
	 */

	if (econet_data)
	{

		/* Turn the LEDs off - must be within the if (econet_data) otherwise there's a null ptr deref to econet_data in the macros in econet_led_off() */

		econet_led_off();

		/*
		 * If we created a device, destroy it
		 *
		 */

		if (econet_device_created)
		{
			device_destroy(econet_class, MKDEV(econet_data->major, 0));
			unregister_chrdev(econet_data->major, DEVICE_NAME);
		}

		if (monitor_device_created)
		{
			device_destroy(monitor_class, MKDEV(econet_data->monitor_major, 0));
			unregister_chrdev(econet_data->monitor_major, DEVICE_NAME_MONITOR);
		}

		/* 
		 * If we successfully obtained an IRQ, free it 
		 *
		 */

		if (econet_data->irq)
		{
			econet_irq_mode(0);
			free_irq(econet_data->irq, THIS_MODULE->name);
		}

		/* Empty the workqueue */

		if (econet_data->workqueue)
		{
			flush_workqueue(econet_data->workqueue);
			destroy_workqueue(econet_data->workqueue);
		}

		/*
	 	* Get rid of our fifos
	 	*
	 	*/
	
		if (econet_data->readfd_fifo_initialized) kfifo_free(&(econet_data->readfd_fifo));

		if (econet_data->monitor_fifo_initialized) kfifo_free(&(econet_data->monitor_fifo));

		/* PWM clock is under device management - shouldn't need to put/free it */

	}

	/*
	 * Destroy class if we have one
	 *
	 */

	if (econet_class_initialized)
		class_destroy(econet_class);
	
	if (monitor_class_initialized)
		class_destroy(monitor_class);

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

	printk(KERN_INFO "econet-fast: Module unloaded\n");

	/*
	 * Return success
	 *
	 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,20)
	return 0;
#endif

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
