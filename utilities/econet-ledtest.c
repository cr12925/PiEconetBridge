/*
  (c) 2021 Chris Royle
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

/* Test the read/write LEDs */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <endian.h>
#include <regex.h>
#include "../include/econet-gpio-consumer.h"

int econet_fd;
int dumpmode_brief = 0;

void econet_test(void)
{

	printf("Press a key to turn both LEDs on (whatever state they may presently be in)...");

	fgetc(stdin);

	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_READLED | ECONETGPIO_LEDON);
	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_WRITELED | ECONETGPIO_LEDON);

	printf("\nPress a key to turn the write LED off...");
	fgetc(stdin);

	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_WRITELED | ECONETGPIO_LEDOFF);

	printf("\nPress a key to turn the write LED back on, and the read LED off...");
	fgetc(stdin);

	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_WRITELED | ECONETGPIO_LEDON);
	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_READLED | ECONETGPIO_LEDOFF);

	printf("\nPress a key to turn the read LED back on...");
	fgetc(stdin);

	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_READLED | ECONETGPIO_LEDON);

	printf("\nPress a key to turn both LEDs off...");
	fgetc(stdin);

	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_READLED | ECONETGPIO_LEDOFF);
	ioctl (econet_fd, ECONETGPIO_IOC_LED, ECONETGPIO_WRITELED | ECONETGPIO_LEDOFF);

	printf("Tests completed.\n\n");


}

void main(void)
{
	/* The open() call will do an econet_reset() in the kernel */
	econet_fd = open("/dev/econet-gpio", O_RDWR);

	if (econet_fd < 0)
	{
		fprintf(stderr, "Unable to open econet device. You may need to be root?\n");
		exit (EXIT_FAILURE);
	}

	econet_test();

	exit(EXIT_SUCCESS);

}
