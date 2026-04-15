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

struct class *econet_class = NULL;
u8 econet_class_initialized = 0;
u8 econet_device_created = 0;

struct class *monitor_class = NULL;
u8 monitor_class_initialized = 0;
u8 monitor_device_created = 0;

/*
 * econet_rwdevice_init()
 *
 * Initialize the main /dev/econet-gpio device
 * for the userspace code to interact with to
 * RX/TX packets on the network.
 *
 */

int econet_rwdevice_init(void)
{

	int result;

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
                printk (KERN_INFO "econet-fast: Failed to obtain major device number.\n");
                result = econet_data->major;
                econet_remove(NULL);
                return result;
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
                printk (KERN_INFO "econet-fast: Failed creating device class\n");
                result = PTR_ERR(econet_class);
                econet_remove(NULL);
                return result;
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
                printk (KERN_INFO "econet-fast: Failed creating device\n");
                result = PTR_ERR(econet_data->dev);
                econet_remove(NULL);
                return result;
        }

        /*
         * Flag device as created so that
         * econet_remove() can destroy it without
         * error.
         *
         */

        econet_device_created = 1;

	return 0; /* Success */
}

/* 
 * econet_monitor_init()
 *
 * Initialize the /dev/econet-monitor device
 * (which is read-only) and which spits raw
 * packets out with copies of SRs and direction
 * (because it will give you packets transmitted
 * by the kernel as well as just receiving)
 *
 */

int econet_monitor_init(void)
{

	int result = -1;

        econet_data->monitor_major=register_chrdev(0, DEVICE_NAME_MONITOR, &monitor_fops);

        if (econet_data->monitor_major < 0)
        {
                printk (KERN_INFO "econet-fast: Failed to obtain major device number for monitor device.\n");
                result = econet_data->monitor_major;
                econet_remove(NULL);
                return result;
        }

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,4,0)
        if (IS_ERR(monitor_class = class_create(THIS_MODULE, CLASS_NAME_MONITOR)))
#else
        if (IS_ERR(monitor_class = class_create(CLASS_NAME_MONITOR)))
#endif
        {
                printk (KERN_INFO "econet-fast: Failed creating monitor device class\n");
                result = PTR_ERR(monitor_class);
                econet_remove(NULL);
                return result;
        }

        /*
         * Flag class as initialized so that 
         * econet_remove() can destroy it
         * without error.
         *
         */

        monitor_class_initialized = 1;

	econet_data->monitor_count = 0;

	econet_data->extralogs = 0;

        /*
         * Create device within class, 
         * and give up & quit if that fails.
         *
         */

        if (IS_ERR(econet_data->monitor_dev = device_create(monitor_class, NULL, MKDEV(econet_data->monitor_major, 0), NULL, DEVICE_NAME_MONITOR)))
        {
                printk (KERN_INFO "econet-fast: Failed creating monitor device\n");
                result = PTR_ERR(econet_data->monitor_dev);
                econet_remove(NULL);
                return result;
        }

        /*
         * Flag device as created so that
         * econet_remove() can destroy it without
         * error.
         *
         */

        monitor_device_created = 1;

	return 0; /* Success */

}

