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
 * econet_init_netclock()
 *
 * Returns 0 for successful initialization
 */

int econet_netclock_init(struct device *dev)
{
	int result = -1;
	int err;

	/* 
	 * If we are on a v2 board, we
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
		printk (KERN_ERR "econet-fast: Unable to obtain BCM 18 PWM (PWM0) for Econet clock (Error %ld)\n", PTR_ERR(econet_data->gpio18pwm));
		result = PTR_ERR(econet_data->gpio18pwm);
		return result;
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
		printk (KERN_ERR "econet-fast: Econet clock config failure during probe! (%d)\n", err);
		return (-ENODEV);
	}

	/* 
	 * Attempt to enable the PWM clock.
	 * Give up & quit if this fails.
	 *
	 */

	if ((err = pwm_enable(econet_data->gpio18pwm)))
	{
		printk (KERN_ERR "econet-fast: Econet clock enable failure during probe! (%d)\n", err);
		return err;
	}

	/* 
	 * Announce our momentous success
	 * to the user via dmesg.
	 *
	 */

	printk (KERN_INFO "econet-fast: Econet clock enabled on BCM 18 at 1us/5us\n");

	return 0;
}

/* 
 * econet_netclock_set()
 *
 * Change the PWM period/mark for the network clock (only initialized on v2 hardware)
 *
 * Remember we run the PWM clock at 4MHz to make sure we can do marks which are
 * fractions of a us - so multiply everything by 4!
 *
 */

void econet_netclock_set(uint8_t period, uint8_t mark)
{

	/* Return if on v1 hardware - not supported */

	if (econet_data->hwver < 2)	
		return; 

	/* Disable PWM and reconfigure */

	pwm_disable(econet_data->gpio18pwm);

	if (pwm_config(econet_data->gpio18pwm, mark * 250, period * 250)) // ( * 250 = (* 1000 / 4) )
	{
		printk (KERN_ERR "econet-fast: Econet clock change failed!\n");
		return;
	}

	/* Re-enable PWM */

	if (pwm_enable(econet_data->gpio18pwm))
	{
		printk (KERN_ERR "econet-fast: Econet clock enable failed!\n");
		return;
	}

	printk (KERN_INFO "econet-fast: Econet clock set: period/mark = %d/%d ns\n", period * 250, mark * 250);

}

MODULE_LICENSE("GPL");
