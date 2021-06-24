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

        printf("Issuing ioctl() to go into test mode, in case not already there.\n");
        ioctl(econet_fd, ECONETGPIO_IOC_TEST);

        printf("Setting Address lines to A1A0 = 10. Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETA, 0x2);
        fgetc(stdin);

        printf("Setting Address lines to A1A0 = 11. Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETA, 0x3);
        fgetc(stdin);

        printf("Setting Address lines to A1A0 = 01. Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETA, 0x1);
        fgetc(stdin);

        printf("Setting Bus Write Mode (R/W and DIR LOW.) Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_WRITEMODE, ECONET_GPIO_WRITE);
        fgetc(stdin);

        printf("Setting Bus Read Mode. (R/W and DIR HIGH.) Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_WRITEMODE, ECONET_GPIO_READ);
        fgetc(stdin);

        printf("Setting Chip Select to Selected (/CS LOW.) Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETCS, ECONET_GPIO_CS_ON);
        fgetc(stdin);

        printf("Setting Chip Select to UnSelected (/CS HIGH.) Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETCS, ECONET_GPIO_CS_OFF);
        fgetc(stdin);

        printf("Setting Data Lines to 10011001. Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETBUS, 0x99);
        fgetc(stdin);

        printf("Setting Data Lines to 01100110. Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETBUS, 0x66);
        fgetc(stdin);

        printf("Setting Data Lines to D7-0 10101010. Test & press a key.");
        ioctl(econet_fd, ECONETGPIO_IOC_SETBUS, 0xaa);
        fgetc(stdin);

        printf("Going into flag fill mode for oscilloscope check. Test & press a key");
        ioctl(econet_fd, ECONETGPIO_IOC_FLAGFILL, 1);
        fgetc(stdin);

        printf("Calling test packet ioctl(). Press Q to quit. Any other key to retransmit.");
        do {
                ioctl(econet_fd, ECONETGPIO_IOC_TESTPACKET);
        } while (fgetc(stdin) != 'Q');

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
