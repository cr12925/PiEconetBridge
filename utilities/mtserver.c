#define _GNU_SOURCE
#include "econet-hpbridge.h"

void * displaythread(void *p)
{
	int	socket, poll_return;
	struct pollfd	pfd;

	socket = *((int *) p);

	fprintf (stderr, "Thread started on socket %d\n", socket);

	memset (&pfd, 0, sizeof(struct pollfd));

	while (1)
	{
		uint16_t	counter;

		pfd.fd = socket;
		pfd.events = POLLIN;

		poll_return = poll(&pfd, 1, 10000);

		if (poll_return < 0)
		{
			fprintf (stderr, "poll() in displaythread() returned an error!\n");
			exit(-1);
		}
		else if (poll_return == 0)
			fprintf (stderr, "poll() in displaythread() timed out\n");
		else
		{
			uint8_t	buffer[1024];
			int	read_result;

			read_result = read(socket, buffer, 1023);

			fprintf (stderr, "read_result = %d\n", read_result);

			if (read_result == 0) /* Closed */
			{
				fprintf (stderr, "Socket closed?\n");
				exit (0);
			}

			if (read_result == -1)
			{
				fprintf (stderr, "read() returned error\n");
				exit (-1);
			}

			for (counter = 0; counter < read_result; counter++)
				fprintf (stderr, "%c", buffer[counter]);

			fprintf (stderr, "\n");
		}
	}
			
	return NULL;
			
}

int main ()
{
	struct pollfd	*fds, *fds_initial;
	uint16_t	numfds = 0;
	int	ga_return, poll_return;
	struct addrinfo	hints, *mt_addresses, *mt_iterate;

	memset (&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	ga_return = EAI_AGAIN;

	while (ga_return == EAI_AGAIN)
	{
		ga_return = getaddrinfo("bridge3.econet.royle.org", "35010", &hints, &mt_addresses);

		if (ga_return == EAI_AGAIN)
		{
			fprintf (stderr, "Name resolution temporary failure... sleeping\n");
			sleep(5);
		}
	}

	if (ga_return != 0)
	{
		fprintf (stderr, "Name resolution error: %s\n", gai_strerror(ga_return));
		exit (-1);
	}

	if (!mt_addresses)
	{
		fprintf (stderr, "Name resolution returned no addresses!\n");
		exit (-1);
	}

	for (mt_iterate = mt_addresses; mt_iterate != NULL; mt_iterate = mt_iterate->ai_next)
	{
		int mt_socket;
		int on = 1;
		unsigned int timeout = 5000; // 5s

		mt_socket = socket (mt_iterate->ai_family, mt_iterate->ai_socktype | SOCK_NONBLOCK, mt_iterate->ai_protocol);

		if (mt_socket == -1)
		{
			fprintf (stderr, "Failed to create socket!\n");
			exit (-1);
		}

		if (setsockopt(mt_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
		{
			fprintf (stderr, "Failed to set SO_REUSEADDR on socket!\n");
			exit (-1);
		}

		if (setsockopt(mt_socket, SOL_SOCKET, SO_REUSEPORT, (char *) &on, sizeof(on)) < 0)
		{
			fprintf (stderr, "Failed to set SO_REUSEPORT on socket!\n");
			exit (-1);
		}

		if (timeout > 0 && (setsockopt(mt_socket, SOL_SOCKET, TCP_USER_TIMEOUT, (char *) &(timeout), sizeof(timeout)) < 0))
		{
			fprintf (stderr, "Failed to set TCP_USER_TIMEOUT on socket!\n");
			exit (-1);
		}

		if (bind(mt_socket, mt_iterate->ai_addr, mt_iterate->ai_addrlen) != 0)
		{
			fprintf (stderr, "Failed to bind socket!\n");
			exit (-1);
		}

		if (listen(mt_socket, 10) < 0)
		{
			fprintf (stderr, "Failed to listen on socket!\n");
			exit (-1);
		}

		if (numfds == 0) // *fds_initial won't point to anything yet
			fds_initial = malloc(sizeof(struct pollfd));
		else
			fds_initial = realloc(fds_initial, (numfds + 1) * sizeof(struct pollfd));

		if (!fds_initial)
		{
			fprintf (stderr, "Failed to allocate memory for fds_initial at numfds = %d\n", numfds);
			exit (-1);
		}

		memset (&(fds_initial[numfds]), 0, sizeof(struct pollfd));

		fds_initial[numfds].fd = mt_socket;
		fds_initial[numfds].events = POLLIN;
		numfds++;
	}

	fprintf (stderr, "Opened %d listeners\n", numfds);

	freeaddrinfo(mt_addresses);

	fds = malloc(numfds * sizeof(struct pollfd));

	memcpy (fds, fds_initial, sizeof(struct pollfd) * numfds);

	while (1) /* Wait for connections */
	{
		poll_return = poll(fds, numfds, 10000);

		if (poll_return > 0)
		{
			uint16_t	count;
			int		newconn;
			int		flag = 1, flags;

			for (count = 0; count < numfds; count++)
			{
				if (fds[count].revents & POLLIN)
				{
					newconn = accept4(fds[count].fd, NULL, NULL, SOCK_NONBLOCK);

					if (newconn >= 0)
					{
						pthread_t	mtc;
						int 		thread_err;
						int		*thread_data;

						if (setsockopt(newconn, SOL_SOCKET, SO_KEEPALIVE, (char *) &flag, sizeof (int)) < 0)
						{
							fprintf (stderr, "Failed to set SO_KEEPALIVE on incoming connection\n");
							exit (-1);
						}

						flags = fcntl(newconn, F_GETFL);
						if (flags == -1)
						{
							fprintf (stderr, "Unable to get flags on socket\n");
							exit (-1);
						}

						if (fcntl (newconn, F_SETFL, (flags | O_RDWR)) == -1)
						{
							fprintf (stderr, "Unable to set flags on socket\n");
							exit (-1);
						}
					
						thread_data = malloc(sizeof(int));

						if (!thread_data)
						{
							fprintf (stderr, "Unable to malloc(int) for thread data");
							exit (-1);
						}

						*thread_data = newconn;
						fprintf (stderr, "Starting thread on socket %d\n", *thread_data);

						thread_err = pthread_create(&mtc, NULL, displaythread, thread_data);

						if (thread_err != 0)
						{
							fprintf (stderr, "Thread creation failed!\n");
							exit(-1);
						}

						pthread_detach(mtc);
					}
				}
			}
		}
	}
}
