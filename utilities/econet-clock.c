/*
  (c) 2022 Chris Royle
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

void econet_usage(char *name)
{

				fprintf(stderr, " \n\
Copyright (c) 2022 Chris Royle\n\
This program comes with ABSOLUTELY NO WARRANTY; for details see\n\
the GPL v3.0 licence at https://www.gnu.org/licences/ \n\
\n\
A utility to cause the econet-gpio kernel module to alter the\n\
PWM clock output to Broadcom pin 18 on an @KenLowe Econet\n\
Bridge HAT (v2r3 upwards ONLY) so as to provide a network\n\
clock to the Econet. NB, *not* a clock to the ADLC on the\n\
board, which is on Broadcom pin 4.\n\
\n\
Usage: %s -p <period> -m <mark>\n\n\
NOTE: the period and mark parameters are in microseconds\n\
with granularity 0.25us. The kernel will by default use\n\
5us period and 1us mark, which was a typical configuration\n\
for a BBC B/Master network.\n\
\n\
NOTE: This utility will silently do nothing if you do not have\n\
a version 2 Bridge HAT. Please do not complain that your\n\
sub-v2r3 board is not producing a clock.\n\
\n\n\
", name);
	exit (EXIT_FAILURE);

}

void main(int argc, char **argv)
{
	uint8_t		period, mark;
	uint32_t	param;
	int		opt, econet_fd;

	period = mark = 0;

	// Note - parameters given can be fractional. The kernel runs the PWM clock
	// at 4MHz to facilitate sub-microsecond period / mark settings - e.g. where
	// a longer period is required because there are BBCs on the network using
	// second processors, for which Acorn recommended a 5.5us period.

	while ((opt = getopt(argc, argv, "hp:m:")) != -1)
	{
		switch (opt) {
			case 'h':	
				econet_usage(argv[0]); break;
			case 'p':
				period = (uint8_t) (atof(optarg) * 4);
				break;
			case 'm':
				mark = (uint8_t) (atof(optarg) * 4);
				break;
		}
	}

	if (period == 0 || mark == 0)
	{
		fprintf (stderr, "Cannot set clock: must set both period and mark. Try '-h' ?\n");
		exit(EXIT_FAILURE);
	}

	param = (period << 16) | mark;

	/* The open() call will do an econet_reset() in the kernel */
	econet_fd = open("/dev/econet-gpio", O_RDWR);

	if (econet_fd < 0)
	{
		fprintf(stderr, "Unable to open econet device. You may need to be root?\n");
		exit (EXIT_FAILURE);
	}

	ioctl (econet_fd, ECONETGPIO_IOC_NETCLOCK, param);

	exit(EXIT_SUCCESS);

}
