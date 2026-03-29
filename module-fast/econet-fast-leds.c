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
 * econet_led_state()
 *
 * Change state of one or other LED. See #defines in econet-gpio-consumer.h
 */

void econet_led_state(uint8_t arg)
{
	uint8_t pin;

	if (!econet_data) return; // Otherwise null pointer deref in code below

	pin = (arg & ECONETGPIO_READLED) ? EGP_READLED : EGP_WRITELED;

	gpiod_set_value(ECOPIN(pin), (arg & ECONETGPIO_LEDON) ? 1 : 0);

}

/* 
 * econet_led_off()
 *
 * Turn the LEDs off - used in econet_remove()
 *
 */

void econet_led_off(void)
{
        /* Turn off the read/write LEDs */

	if (!econet_data) return; // Otherwise null pointer deref in code below

        if (ECOPIN(EGP_READLED))
                gpiod_direction_output(ECOPIN(EGP_READLED), GPIOD_OUT_LOW);

        if (ECOPIN(EGP_WRITELED))
                gpiod_direction_output(ECOPIN(EGP_WRITELED), GPIOD_OUT_LOW);
}

MODULE_LICENSE("GPL");
