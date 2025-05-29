/* 
 * *FAST new handler - test harness
 */

#include "econet-hpbridge.h"
#include "econet-fs-hpbridge-common.h"
#include "fs.h"
#include <sys/wait.h>

/*
#define FAST_TEST_DEBUG 1
*/

/* Now in econet-hpbridge.h
#define EB_FAST_BUFSIZE 1024
#define EB_FAST_SHRINKTHRESHOLD 512
#define EB_FAST_TO_SERVER 0
#define EB_FAST_TO_NETWORK 1
#define EB_FAST_WAKE_SERVER(m) pthread_cond_signal(&(m->fast_wake[EB_FAST_TO_SERVER]))
#define EB_FAST_WAKE_NETWORK(m) pthread_cond_signal(&(m->fast_wake[EB_FAST_TO_NETWORK]))
*/

/*
 * eb_fast_find_conn
 *
 * Locate an active connection in the connections list. Usually used to kill it off.
 */

struct __eb_fast_client * eb_fast_find_conn (struct __eb_device *device, uint8_t net, uint8_t stn)
{

	struct __eb_fast_client *fc;

#ifndef FAST_TEST
	pthread_mutex_lock(&(device->local.fast_client_list_lock));
	fc = device->local.fast_client_list;

	while (fc && (fc->net != net && fc->stn != stn))
		fc = fc->next;
	pthread_mutex_unlock(&(device->local.fast_client_list_lock));
#else
	fc = NULL;
#endif

	return fc;
}

/* 
 * eb_fast_flag_disconnect
 *
 * Called by the bridge when it gets a disconnect request
 */

void eb_fast_flag_disconnect (struct __eb_device *device, uint8_t net, uint8_t stn)
{

	struct __eb_fast_client *fc;

	pthread_mutex_lock(&(device->local.fast_io_mutex));
#ifndef FAST_TEST
	fc = eb_fast_find_conn (device, net, stn);
	if (fc)
		pthread_cancel(fc->fast_server); /* Kill the server on disconnect and all else will tidy up. Theoretically. */
#endif
	pthread_mutex_unlock(&(device->local.fast_io_mutex));

}

/* eb_fast_flag_datarq
 *
 * Called by the bridge when we get a data request from client.
 *
 * Wake the to_network io handler.
 */

void eb_fast_flag_datarq (struct __eb_device * device, uint8_t net, uint8_t stn)
{
	struct __eb_fast_client *fc;

	fc = eb_fast_find_conn (device, net, stn);

	if (fc)
	{
		fc->fast_client_ready = 1;
		pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_NETWORK]));
	}
}

struct __eb_fast_client * eb_fast_mkclient (struct __eb_device *device, uint8_t net, uint8_t stn)
{

	struct __eb_fast_client		*fc;

	/* Find any existing connection and kill it */

#ifndef FAST_TEST
	pthread_mutex_lock(&(device->local.fast_client_list_lock));
	if ((fc = eb_fast_find_conn(device, net, stn))) /* We found a match - kill its server off */
		pthread_cancel(fc->fast_server); /* It should now clean itself up */
	pthread_mutex_unlock(&(device->local.fast_client_list_lock));
#endif

	fc = eb_malloc(__FILE__, __LINE__, "FAST", "New FAST client structure", sizeof(struct __eb_fast_client));

	if (!fc)
		return NULL;

	fc->parent = device;
	fc->fast_output_ctrl = fc->fast_input_ctrl = 0;
	fc->fast_thread_ended = 0;
#ifdef FAST_TEST
	fc->fast_client_ready = 1;
#else
	fc->fast_client_ready = 0;
#endif
	fc->fast_client_disconnected = 0;
	fc->pending[EB_FAST_TO_SERVER] = eb_malloc(__FILE__, __LINE__, "FAST", "New pending_to_server buffer 1k", EB_FAST_BUFSIZE);
	fc->pending[EB_FAST_TO_NETWORK] = eb_malloc(__FILE__, __LINE__, "FAST", "New pending_to_network buffer 1k", EB_FAST_BUFSIZE);
	fc->pt_len[EB_FAST_TO_SERVER] = fc->pt_len[EB_FAST_TO_NETWORK] = 0; /* Nothing in the buffers */
	fc->pt_sz[EB_FAST_TO_SERVER] = fc->pt_sz[EB_FAST_TO_NETWORK] = EB_FAST_BUFSIZE;

	if (pthread_mutex_init(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]), NULL) == -1)
	{
		eb_free(__FILE__, __LINE__, "FAST", "Free FAST client when mutex init failed (to network)", fc);
		eb_debug(0, 1, "FAST", "Creation of FAST client mutex failed");
		return NULL;
	}

	if (pthread_mutex_init(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]), NULL) == -1)
	{
		eb_free(__FILE__, __LINE__, "FAST", "Free FAST client when mutex init failed (to server)", fc);
		eb_debug(0, 1, "FAST", "Creation of FAST client mutex failed");
		return NULL;
	}

	if (pthread_cond_init(&(fc->fast_wake[EB_FAST_TO_NETWORK]), NULL) == -1)
	{
		eb_free(__FILE__, __LINE__, "FAST", "Free FAST client when condition init failed (to network)", fc);
		eb_debug(0, 1, "FAST", "Creation of FAST client condition failed");
		return NULL;
	}

	if (pthread_cond_init(&(fc->fast_wake[EB_FAST_TO_SERVER]), NULL) == -1)
	{
		eb_free(__FILE__, __LINE__, "FAST", "Free FAST client when condition init failed (to server)", fc);
		eb_debug(0, 1, "FAST", "Creation of FAST client condition failed");
		return NULL;
	}

	if (pipe(fc->fc_socket[EB_FAST_TO_NETWORK]) != 0)
	{
		eb_free(__FILE__, __LINE__, "FAST", "Free FAST client when pipe to network", fc);
		eb_debug(0, 1, "FAST", "Creation of FAST client pipe to network failed");
		return NULL;
	}

	if (pipe(fc->fc_socket[EB_FAST_TO_SERVER]) != 0)
	{
		eb_free(__FILE__, __LINE__, "FAST", "Free FAST client when pipe to server", fc);
		eb_debug(0, 1, "FAST", "Creation of FAST client pipe to server failed");
		return NULL;
	}

	/* Success */

	fc->next = NULL; /* Will be device->local.fast_clients */
	fc->prev = NULL; /* Going on head of list */

#ifndef FAST_TEST
	pthread_mutex_lock(&(device->local.fast_client_list_lock));
	fc->next = device->local.fast_client_list;
	device->local.fast_client_list = fc;
	pthread_mutex_unlock(&(device->local.fast_client_list_lock));
#endif
	return fc;
}

/* Make a new menu with the given name, and return its struct */

struct __eb_fast_menu *	eb_fast_mkmenu(char *menu_heading, char *menu_name, struct __eb_fast_menu **mlist)
{
	struct __eb_fast_menu *m, *ms;

	if (!menu_name)
		eb_debug (1, 0, "FAST", "Attempt to create menu with no reference name!");

	if (!menu_heading)
		eb_debug (1, 0, "FAST", "Attempt to create menu with no heading!");

	m = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu structure", sizeof(struct __eb_fast_menu));

	m->item = NULL;
	m->next = NULL;

	m->menu_name = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu name buffer", (menu_name ? strlen(menu_name) + 1 : 15));
	strcpy((char *) m->menu_name, menu_name);

	m->menu_heading = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu name buffer", strlen(menu_heading)+1);
	strcpy(m->menu_heading, menu_heading);

	ms = *mlist;

	if (ms)
	{
		while (ms->next)
			ms = ms->next;
		ms->next = m;
	}
	else
	{
		*mlist = m;
	}

	return m;
}

/* Make a menu item, put it on the end of the list and return its struct address */

struct __eb_fast_menu_item * eb_fast_mkmenuitem(struct __eb_fast_menu *menu, char * description, uint16_t timeout, uint8_t menutype, unsigned char keypress)
{
	/* Caller needs to populate priv, priv2 (which are initialized as 0 - anyone can see/use)
	 * and viewdata flag + any other entries in the union.
	 */

	struct __eb_fast_menu_item *mi, *mi_find;

	mi = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu item structure", sizeof(struct __eb_fast_menu_item));

	mi->fm_timeout = timeout;
	mi->fm_type = menutype;
	mi->priv_mask = mi->priv2_mask = 0;
	mi->keypress = keypress;
	mi->is_viewdata = 0;
	mi->next = NULL;

	if (!description)
		eb_debug (1, 0, "FAST", "Attempt to create menu item without a description!");

	mi->fm_description = eb_malloc(__FILE__, __LINE__, "FAST", "Create new buffer for menu description", strlen(description)+1);
	strcpy((char *) mi->fm_description, description);

	if (menu->item)
	{
		mi_find = menu->item;

		while (mi_find->next)
			mi_find = mi_find->next;

		mi_find->next = mi;
	}
	else
		menu->item = mi;

	return mi;
}


int f_printf (struct __eb_fast_client *fc, char *fmt, ...)
{

        va_list ap;
        char str[16384];
	int written;

        va_start(ap, fmt);

        vsnprintf (str, 16382, fmt, ap);

        va_end(ap);

        written = write (fc->fc_socket[EB_FAST_TO_NETWORK][1], str, strlen(str));

	// Needed? pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_NETWORK]));

	return written;
}

/* Send *FAST control packet
 */

void eb_fast_send_control (struct __eb_fast_client *fc, uint8_t msg)
{
#ifndef FAST_TEST
	struct __econet_packet_aun *p;

	struct __eb_device *d;

	/* If we are in FAST_TEST, we have no network to talk to... so don't do this */

	d = fc->parent;

	p = eb_malloc(__FILE__, __LINE__, "FAST", "Allocate fast output packet", 20);

	if (!p)
		eb_debug (1, 0, "FAST", "Unable to allocate memory for *FAST output packet");

	p->p.srcstn = d->local.stn;

	p->p.srcnet = d->net;
	p->p.dststn = fc->stn;
	p->p.dstnet = fc->net;
	p->p.aun_ttype = ECONET_AUN_DATA;
	p->p.port = 0x00;
	p->p.ctrl = 0x84; /* JSR */
	p->p.seq = eb_get_local_seq(d);
	p->p.data[0] = 0xFF;  /* JSR to &FFFF */
	p->p.data[1] = 0xFF;
	p->p.data[2] = 0xFF;
	p->p.data[3] = 0xFF;
	p->p.data[4] = d->local.stn;
	p->p.data[5] = d->net; /* Might need to translate this to 0 for local network? Hopefully done elsewhere... */
	p->p.data[6] = msg; /* Message code */

	eb_debug (0, 3, "FAST", "%-8s %d.%d Fast Handler Loop - Send control message %d", eb_type_str(d->type), fc->net, fc->stn, msg);
	eb_enqueue_output(d, p, 8, NULL);
	pthread_cond_signal(&(d->qwake));

	eb_free(__FILE__, __LINE__, "FAST", "Free fast output packet", p);

#endif
}

/* 
 * Send *FAST data packet
 */

void eb_fast_send_data (struct __eb_fast_client *fc, uint8_t *data, uint16_t length)
{

#ifndef FAST_TEST
	struct __econet_packet_aun *p;

	struct __eb_device *d;

	/* If we are in FAST_TEST, we have no network to talk to... so don't do this */

	d = fc->parent;

	p = eb_malloc(__FILE__, __LINE__, "FAST", "Allocate fast output packet", ECONET_MAX_PACKET_SIZE);

	if (!p)
		eb_debug (1, 0, "FAST", "Unable to allocate memory for *FAST output packet");

	p->p.srcstn = d->local.stn;
	p->p.srcnet = d->net;
	p->p.dststn = fc->stn;
	p->p.dstnet = fc->net;
	p->p.aun_ttype = ECONET_AUN_DATA;
	p->p.port = EB_FAST_PORT;
	p->p.ctrl = 0x80 | fc->fast_output_ctrl; fc->fast_output_ctrl ^= 0x01;
	p->p.seq = eb_get_local_seq(d);
	memcpy(&(p->p.data), data, length);

	eb_debug (0, 3, "FAST", "Fast Handler Loop - if(ready) succeeded - transmitting output to device %p, packet at %p, length %d to %d.%d", d, p, length, p->p.dstnet, p->p.dststn);
	eb_enqueue_output(d, p, length, NULL);
	pthread_cond_signal(&(d->qwake));

	eb_free(__FILE__, __LINE__, "FAST", "Free fast output packet", p);

#endif

}

/*
 * Connect the user to /bin/login
 *
 * (or scriptname if not null)
 *
 */

void eb_fast_bin_login(struct __eb_fast_client *fc, struct __eb_fast_menu_item *mi)
{

	//struct termios		login_t;
	pid_t	child;

	//tcgetattr (STDIN_FILENO, &login_t);
	//tcsetattr (STDIN_FILENO, TCSANOW, &fc->old_t);

	child = fork();

	if (child < 0)
	{
		f_printf(fc, "Failed to fork().\n");
		return;
	}

	if (child == 0)
	{
		char	hostname[20];

#ifdef FAST_TEST
		snprintf (hostname, 19, "0.0.econet");
#else
		snprintf (hostname, 19, "%d.%d.econet", fc->parent->local.stn, fc->parent->net);
#endif

		/* Display banner if there is one */

		if (mi->fm_type == EB_FAST_MENU_BIN_LOGIN && mi->fm_binlogin.fm_banner)
		{
			int h;
			int r;

			h = open(mi->fm_binlogin.fm_banner, O_RDONLY);

			if (h >= 0)
			{
				char	buf[128];

				while  ((r = read(h, buf, 128) > 0) > 0)
					write (fc->fc_socket[EB_FAST_TO_NETWORK][1], buf, r);

				close(h);
			}
		}

		dup2(fc->fc_socket[EB_FAST_TO_NETWORK][1], STDOUT_FILENO);
		dup2(fc->fc_socket[EB_FAST_TO_NETWORK][1], STDERR_FILENO);
		dup2(fc->fc_socket[EB_FAST_TO_SERVER][0], STDIN_FILENO);

		if (mi->fm_type == EB_FAST_MENU_BIN_LOGIN)
		{
			seteuid(0); /* Root for this - then login manages stuff */
			execl("/bin/login", "/bin/login", "-h", hostname, mi->fm_binlogin.fm_username, (char *) NULL);
		}
		else if (mi->fm_type == EB_FAST_MENU_SCRIPT)
			execl("/bin/bash", "-c", mi->fm_script.fm_script, (char *) NULL); /* For now. Add parameter capability later */
	}
	else
	{
		waitpid(child, NULL, 0);
	}

	//tcsetattr (STDIN_FILENO, TCSANOW, &login_t);
}

void eb_fast_display_menu(struct __eb_fast_client *fc)
{

	struct __eb_fast_menu_item *mi;
	char	valid_keys[20];
	uint8_t	vk_count;
	uint8_t fm_exit = 0;

	/* Drop privs just in case */

	if (seteuid(getuid()) != 0)
	{
		eb_debug (0, 1, "FAST", "Unable to drop privileges for handler");
		f_printf (fc, "System error! Cannot drop privileges.");
		close (fc->fc_socket[EB_FAST_TO_NETWORK][1]);
		return;
	}

	fc->from_client = fdopen(fc->fc_socket[EB_FAST_TO_SERVER][0], "rb");

	if (!fc->from_client)
	{
		eb_debug (0, 1, "FAST", "FAST server thread - error on fdopen(in)");
		return;
	}


#ifdef FAST_TEST
	eb_debug (0, 1, "FAST", "FAST display menu routine begun - in = %p, out = %d", fc->from_client, fc->fc_socket[EB_FAST_TO_SERVER][1]);
#endif

	eb_debug (0, 1, "FAST", "FAST display menu routine sending introductory pleasantries");


	while (!fm_exit)
	{
		mi = fc->menu_current->item;
	
		f_printf (fc, "%c%s\n\n", 0x12, fc->menu_current->menu_heading); /* Clear screen */
		memset(valid_keys, 0, sizeof(valid_keys));	
		vk_count = 0;

		while (mi && (vk_count < (sizeof(valid_keys)-1)))
		{
			if (mi->fm_type == EB_FAST_MENU_BLANKLINE)
				f_printf (fc, "\n");
			else if (mi->fm_type != EB_FAST_MENU_HEADING)
			{
				f_printf (fc, "%c. %s\n", mi->keypress, mi->fm_description);
				valid_keys[vk_count++] = mi->keypress;
			}
			else	f_printf (fc, "\n%s\n", mi->fm_description);
	
			mi = mi->next;
		}

		f_printf (fc, "\nSelect? ");

		char	key;

		key = fgetc(fc->from_client);

		if (key >= 'a' && key <= 'z')
			key &= 0xDF; /* To caps */

		if (strchr(valid_keys, key))
		{
			struct __eb_fast_menu_item 	*i;

			f_printf (fc, "%c\n\n", key);

			/* Process */

			i = fc->menu_current->item;

			while (i && i->keypress != key)
				i = i->next;

			if (i)
			{
				if (i->is_viewdata)
					eb_fast_send_control (fc, EB_FAST_OP_VIEWDATA_ON);

				switch (i->fm_type)
				{
					case EB_FAST_MENU_SUBMENU: /* Move to submenu */
						{
							fc->menu_current = i->fm_submenu.fm_submenu;
						} break;
					case EB_FAST_MENU_BIN_LOGIN: /* Spawn login shell */
						{
							eb_fast_bin_login(fc, i);
						} break;
					case EB_FAST_MENU_SCRIPT: /* Run local script */
						{
							eb_fast_bin_login(fc, i);
						} break;
					case EB_FAST_MENU_DISCONNECT: /* Quit! */
						{
							fm_exit = 1;
						} break;
					/* Unimplemented functions */
					case EB_FAST_MENU_SERIAL: /* Connect to serial port */
					case EB_FAST_MENU_TCP: /* Connect to TCP port */
					case EB_FAST_MENU_SSH: /* Connect over SSH */
					case EB_FAST_MENU_FSSTOPSTART: /* Fileserver function */
						{
							f_printf(fc, "Not yet implemented.\n\n");
							sleep(3);
						} break;
					default:
						{
							f_printf(fc, "Unknown menu action! (This should not happen.)\n\n");
							sleep(3);
						} break;
				}
				if (i->is_viewdata)
					eb_fast_send_control (fc, EB_FAST_OP_VIEWDATA_OFF);


			}
			else
			{
				f_printf(fc, "Error finding what to do with that keypress!\n(This shouldn't happen.)\n");
				sleep(3);
			}
		}
	}

	close (fc->fc_socket[EB_FAST_TO_NETWORK][1]);

}

/* Cleanup function when fast handler exits */

void eb_fast_client_cleanup(struct __eb_fast_client *fc)
{
#ifndef FAST_TEST
	if (fc->parent)
	{
		pthread_mutex_lock(&(fc->parent->local.fast_client_list_lock));
		pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]));
		pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));
	}
#endif

	if (fc->dest_host)
		eb_free (__FILE__, __LINE__, "FAST", "Fast cleanup: free dest_host", fc->dest_host);
	
	if (fc->pending[EB_FAST_TO_NETWORK])
		eb_free (__FILE__, __LINE__, "FAST", "Fast cleanup: free pending data to network", fc->pending[EB_FAST_TO_NETWORK]);

	if (fc->pending[EB_FAST_TO_SERVER])
		eb_free (__FILE__, __LINE__, "FAST", "Fast cleanup: free pending data to network", fc->pending[EB_FAST_TO_SERVER]);

	if (fc->prev) /* Splice out from prev */
	{
		fc->prev->next = fc->next;
		fc->prev = NULL;
	}
	else
	{
		/* We were first on the list - update parent->fast_client_list if we are not in test mode */
#ifndef FAST_TEST
		fc->parent->local.fast_client_list = fc->next;
#endif
	}

	if (fc->next) /* Splice out from next */
	{
		fc->next->prev = fc->prev;
		fc->next = NULL;
	}

#ifndef FAST_TEST
	if (fc->parent)
	{
		pthread_mutex_unlock(&(fc->parent->local.fast_client_list_lock));
		pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]));
		pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));
	}
#endif

	/* Free the client struct */

	eb_free (__FILE__, __LINE__, "FAST", "Free client struct on handler exit", fc);
}

/* Displays menu */

void *	eb_fast_server_thread(void * fc)
{

	struct __eb_fast_client		*me;

	me = (struct __eb_fast_client *) fc;

	eb_debug (0, 1, "FAST", "FAST server thread started for %d.%d", me->net, me->stn);

	eb_fast_display_menu(me);

	/* IO handlers will kill this thread if IO dies, so no cleanup here */

	eb_debug (0, 4, "FAST", "FAST server thread exiting");

	return NULL;

}

/*
 * Mediates traffic from server to network
 */

void * eb_fast_io_handler_to_network (void * fc)
{

	struct __eb_fast_client		*me;
	struct pollfd			p;

	me = (struct __eb_fast_client *) fc;

	eb_debug (0, 1, "FAST", "FAST IO thread to network started for %d.%d", me->net, me->stn);

	pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));

	while (1)
	{
		int pollreturn;
		struct timespec t;

		/* Wait for request for data from remote end - we get signalled here from both the 
		 * server end, and the receiver when more data is requested
		 */

		t.tv_nsec = 1000000 * EB_FAST_OUTPUTWAIT;
		t.tv_sec = 0;

		pthread_cond_timedwait (&(me->fast_wake[EB_FAST_TO_NETWORK]), &(me->fast_io_mutex[EB_FAST_TO_NETWORK]), &t);

		/* Poll to-network socket */

		p.fd = me->fc_socket[EB_FAST_TO_NETWORK][0];
		p.revents = 0;
		p.events = POLLIN | POLLHUP;

		eb_debug (0, 4, "FAST", "FAST IO thread to network polling data from to_network fd");

		if (me->fast_client_ready && (pollreturn = poll(&p, 1, 0)) > 0)
		{
			eb_debug (0, 4, "FAST", "FAST IO thread network polling data from to_network fd - poll() return was positive");

			//pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK])); /* Now done in the condition wait */

			if (p.revents & POLLHUP)
			{
				/* Clean up and exit */

				break;
			}

			if (p.revents & POLLIN)
			{
				int	read_result;
				uint8_t	buffer[128];

				eb_debug (0, 4, "FAST", "FAST IO thread to network polling data from to_network fd - reading data after positive poll()");

				read_result = read(me->fc_socket[EB_FAST_TO_NETWORK][0], buffer, 128);

				eb_debug (0, 4, "FAST", "FAST IO thread to network polling data from to_network fd - read data returned %d", read_result);

				if (read_result < 0)
					eb_debug (0, 1, "FAST", "IO handler to network received error on read() from server thread: %s", strerror(errno));
				else if (read_result > 0) /* Data available */
				{
					/* Put in our buffer. Next bit of function works out whether to send on to client */

					eb_debug (0, 4, "FAST", "FAST IO to network thread polling data from to_network fd - putting received data into to_network buffer");

					if ((me->pt_len[EB_FAST_TO_NETWORK] + read_result) > me->pt_sz[EB_FAST_TO_NETWORK]) /* Need to expand buffer */
					{
						eb_debug (0, 4, "FAST", "FAST IO to network thread polling data from to_network fd - buffer expansion required");

						me->pending[EB_FAST_TO_NETWORK] = realloc(me->pending[EB_FAST_TO_NETWORK], (me->pt_sz[EB_FAST_TO_NETWORK] + EB_FAST_BUFSIZE));
						me->pt_sz[EB_FAST_TO_NETWORK] += EB_FAST_BUFSIZE;
					}

					eb_debug (0, 4, "FAST", "FAST IO thread to network polling data from to_network fd - copying data to buffer");

					memcpy (&(me->pending[EB_FAST_TO_NETWORK][me->pt_len[EB_FAST_TO_NETWORK]]), buffer, read_result);

					me->pt_len[EB_FAST_TO_NETWORK] += read_result;
				}
			}

			// pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));
		}
		else if (pollreturn < 0)
		{
			eb_debug (0, 1, "FAST", "FAST IO thread to netowkr: error on read from socket: %s", strerror(errno));
			return NULL;
		}

		/* Process output - 32 byte chunks we think */

		if (me->pt_len[EB_FAST_TO_NETWORK] > 0)
		{
			int	sz = (me->pt_len[EB_FAST_TO_NETWORK] > 32 ? 32 : me->pt_len[EB_FAST_TO_NETWORK]);

			eb_debug (0, 4, "FAST", "FAST IO thread to network checking for data to send to network");

			// pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));

			me->fast_client_ready = 0;

#ifdef FAST_TEST
			/* for test purposes, write to stdout  - when in production, check client is ready and send a packet */

			write(STDOUT_FILENO, me->pending[EB_FAST_TO_NETWORK], sz);

			me->fast_client_ready = 1; /* Fudge for testing */

#else
			/* Stuff here to write to network */
			eb_fast_send_data (me, me->pending[EB_FAST_TO_NETWORK], sz);
#endif

			eb_debug (0, 4, "FAST", "FAST IO thread to network send %d bytes to network", sz);

			memmove(me->pending[EB_FAST_TO_NETWORK], &(me->pending[EB_FAST_TO_NETWORK][sz]), me->pt_len[EB_FAST_TO_NETWORK]);

			me->pt_len[EB_FAST_TO_NETWORK] -= sz;

			eb_debug (0, 4, "FAST", "FAST IO thread to network checking to see if it can shrink the buffer: current to_network size = %d, len = %d, diff = %d", 
					me->pt_sz[EB_FAST_TO_NETWORK],
					me->pt_len[EB_FAST_TO_NETWORK],
					(me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]));

			if ((me->pt_sz[EB_FAST_TO_NETWORK] > EB_FAST_BUFSIZE) && (me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]) >= (EB_FAST_SHRINKTHRESHOLD))
			{
				uint32_t	new_sz;

				/* Shrink the buffer, but not below BUFSIZE */
			
				eb_debug (0, 4, "FAST", "FAST IO thread to network shrinking the to_network buffer");

				new_sz = ((me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]) / EB_FAST_BUFSIZE) * EB_FAST_BUFSIZE;

				if (new_sz == 0)
					new_sz = EB_FAST_BUFSIZE;

				eb_debug (0, 4, "FAST", "FAST IO thread to network shrinking the to_network buffer to size %d bytes", new_sz);

				me->pending[EB_FAST_TO_NETWORK] = realloc(me->pending[EB_FAST_TO_NETWORK], new_sz);

				me->pt_sz[EB_FAST_TO_NETWORK] = new_sz;
			}

			// pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));
		}

		/* Snooze off again */

		eb_debug (0, 4, "FAST", "FAST IO thread (to network) dozing off again");
	}

	eb_debug (0, 3, "FAST", "FAST IO handler (to network) detected server hangup - exiting");

	pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));

	/* Kill the server thread */

	pthread_cancel(me->fast_server); /* Don't kill the other IO thread - the server cleaup does it */

	while (1)
		sleep(60); // Sleep and wait to be killed

	return NULL;

}

/* Mediates traffic destined to the server end */

void * eb_fast_io_handler_to_server (void * fc)
{

	struct __eb_fast_client		*me;

	me = (struct __eb_fast_client *) fc;

	eb_debug (0, 1, "FAST", "FAST IO thread to server started for %d.%d", me->net, me->stn);

	/* Sleep on the condition and, when woken, process data in the buffers as necessary. For test purposes, to_network gets written to stdout */

	pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_SERVER]));

	while (1)
	{
		int l;

		/* Wait for something to do */

		pthread_cond_wait (&(me->fast_wake[EB_FAST_TO_SERVER]), &(me->fast_io_mutex[EB_FAST_TO_SERVER]));

		eb_debug (0, 4, "FAST", "FAST IO thread woken up (to server)");

		/* Have we had the disconnect signal? */

		if (me->fast_client_disconnected) /* Exit loop and clean up - but we might just get the bridge to kill the server thread which will cause an exit and cleaup */
			break;

		/* Process stuff going to server */

		if (me->pt_len[EB_FAST_TO_SERVER] > 0)
		{
			l = write (me->fc_socket[EB_FAST_TO_SERVER][1], me->pending[EB_FAST_TO_SERVER], me->pt_len[EB_FAST_TO_SERVER]);
	
			eb_debug (0, 4, "FAST", "FAST IO thread wrote %d byte(s) to the server", l);
	
			if (me->pt_sz[EB_FAST_TO_SERVER] > EB_FAST_BUFSIZE)
			{
				me->pending[EB_FAST_TO_SERVER] = realloc(me->pending[EB_FAST_TO_SERVER], EB_FAST_BUFSIZE);
				me->pt_sz[EB_FAST_TO_SERVER] = EB_FAST_BUFSIZE;
				eb_debug (0, 4, "FAST", "FAST IO thread shrunk to_server buffer to EB_FAST_BUFSIZE");
			}
	
			me->pt_len[EB_FAST_TO_SERVER] = 0; /* Emtpy buffer */
		}

		eb_fast_send_control (fc, EB_FAST_OP_DATARQ); /* Please, Sir, can I have some more? */

		/* Snooze off again */

		eb_debug (0, 4, "FAST", "FAST IO thread (to server) dozing off again");

	}

	eb_debug (0, 3, "FAST", "FAST IO handler (to server) detected server hangup - exiting");

	pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_SERVER]));
	
	pthread_cancel(me->fast_server); /* Don't kill the other IO thread - the server cleaup does it */

	while (1)
		sleep(60); // Sleep and wait to be killed

	return NULL;

}

/* When a login request happens, the HPB spawns a thread running this. */

void * eb_fast_start_fast_service (void *data)
{

	struct __eb_fast_client *fc = (struct __eb_fast_client *) data;

	/* Spawn a server thread */

	if (pthread_create(&(fc->fast_server), NULL, eb_fast_server_thread, fc))
	{
		eb_debug (0, 1, "FAST", "Fast server thread failed to start");
		exit (1);
	}

	/* Spawn an IO thread */

	if (pthread_create(&(fc->fast_io_handler[EB_FAST_TO_SERVER]), NULL, eb_fast_io_handler_to_server, fc))
	{
		eb_debug (0, 1, "FAST", "Fast server thread to server failed to start");
		exit (1);
	}

	if (pthread_create(&(fc->fast_io_handler[EB_FAST_TO_NETWORK]), NULL, eb_fast_io_handler_to_network, fc))
	{
		eb_debug (0, 1, "FAST", "Fast server thread to server failed to start");
		exit (1);
	}

	pthread_detach(fc->fast_io_handler[EB_FAST_TO_SERVER]);
	pthread_detach(fc->fast_io_handler[EB_FAST_TO_NETWORK]);

	/* The fast_server thread will return when an IO thread loses a connection, or the server exits */

	pthread_join(fc->fast_server, NULL);

	/* Kill the IO threads */

	pthread_cancel(fc->fast_io_handler[EB_FAST_TO_NETWORK]);
	pthread_cancel(fc->fast_io_handler[EB_FAST_TO_SERVER]);

	/* Clean up */

	eb_fast_client_cleanup(fc);

	return NULL;
}


/* Process received data on port &A0 */

void eb_port_a0_handler (struct __econet_packet_aun *p, uint16_t length, void *client)
{
	struct __eb_fast_client * fc = (struct __eb_fast_client *) client;

	pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));

	if ((p->p.ctrl & 0x01) != fc->fast_input_ctrl)
	{
		eb_debug (0, 1, "FAST", "%-8s %3d.%3d *FAST handler ignored traffic with duplicate control", eb_type_str(fc->parent->type), fc->net, fc->stn);
		pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));
		return;
	}

	if ((fc->pt_len[EB_FAST_TO_SERVER] + length) > fc->pt_sz[EB_FAST_TO_SERVER]) /* Buffer full */
	{
		fc->pending[EB_FAST_TO_SERVER] = realloc(fc->pending[EB_FAST_TO_SERVER], fc->pt_sz[EB_FAST_TO_SERVER] + EB_FAST_BUFSIZE); /* Expand by 1k */
		fc->pt_sz[EB_FAST_TO_SERVER] += EB_FAST_BUFSIZE;
	}

	memcpy (&(fc->pending[EB_FAST_TO_SERVER][fc->pt_len[EB_FAST_TO_SERVER]]), p->p.data, length);

	fc->pt_len[EB_FAST_TO_SERVER] += length;

	eb_debug (0, 4, "FAST", "FAST added %d characters to pending(server) buffer, size now %d, occupancy now %d", length, fc->pt_sz[EB_FAST_TO_SERVER], fc->pt_len[EB_FAST_TO_SERVER]);

	pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));

	EB_FAST_WAKE_SERVER(fc); /* Wake up the IO thread */
}

#ifdef FAST_TEST

struct timeval	start;

/* Memory management debug
 * Both these *were* static inline, but changed to support FS
*/

void eb_free (char *file, int line, char *module, char *purpose, void *ptr)
{

	eb_debug (0, 2, "MEM MGT", "%-8s	 %s:%d freeing %p for purpose %s", module, file, line, ptr, purpose);

	free (ptr);

}

void * eb_malloc (char *file, int line, char *module, char *purpose, size_t size)
{

	void *r;

	r = calloc(1, size);

	eb_debug (0, 2, "MEM MGT", "%-8s	 %s:%d sought  malloc(%d) for purpose %s (r = %p)", module, file, line, size, purpose, r);

	return r;

}

/* Calculate ms difference between two times
*/

unsigned long timediffmsec(struct timeval *s, struct timeval *d)
{
	return (((d->tv_sec - s->tv_sec) * 1000) + ((d->tv_usec - s->tv_usec) / 1000));
}
/* Return a float for seconds since bridge start time
*/

float timediffstart()
{

	struct timeval  now;

	gettimeofday (&now, 0);

	return (float) timediffmsec(&start, &now) / 1000;

}

void eb_debug_fmt (uint8_t quit, uint8_t level, char *module, char *formatted)
{

	fprintf (stdout, "[+%15.6f] %7ld %-8s: %s\n", timediffstart(), syscall(SYS_gettid), module, formatted);

	if (quit)
		exit (EXIT_FAILURE);
}

/* Format a varargs debug string and send it off to the debug output
*/

void eb_debug (uint8_t quit, uint8_t level, char *module, char *fmt, ...)
{

#ifdef FAST_TEST_DEBUG
	va_list ap;
	char str[16384];

	va_start(ap, fmt);

	vsnprintf (str, 16382, fmt, ap);

	va_end(ap);
 
	eb_debug_fmt (quit, level, module, str);
#endif

}

void * main_io_routine (void * input)
{

	struct __eb_fast_client 	*fc = (struct __eb_fast_client *) input;
	struct termios			old_t;
	unsigned char			c;
	int				res;

	/* For test purposes, collect stuff from stdin and put it in the pending_to_server buffer, update the buffer length, and wake the io handler */

	/* Also for test purposes, set STDIN to non-line-buffered */

	memcpy(&old_t, &fc->old_t, sizeof (struct termios));
	old_t.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(STDIN_FILENO, TCSANOW, &old_t);

	while ((res = read(STDIN_FILENO, &c, 1)))
	{
		struct __econet_packet_aun	p;

		p.p.data[0] = c;

		if (res < 0)
			break;

		/* Put it on the queue */

		eb_port_a0_handler (&p, 1, fc);

	}

	/* Stop the server and everything else will magically clean up */

	pthread_cancel(fc->fast_server);

	return NULL;
}

int main (void)
{

	struct __eb_fast_client		*fc;
	struct __eb_fast_menu		*fm = NULL, *fm_list = NULL;
	struct __eb_fast_menu_item	*mi;
	pthread_t			fastthread, iothread;

	printf ("*FAST test handler starting\n\n");

	gettimeofday (&start, 0);

	fm = eb_fast_mkmenu("Connections menu", "CONNECTIONS", &fm_list);

	mi = eb_fast_mkmenuitem(fm, "Log in to local host", 300, EB_FAST_MENU_BIN_LOGIN, '1');

	mi->fm_binlogin.fm_banner = "/etc/econet-gpio/login.banner";
	mi->fm_binlogin.fm_username = NULL;

	mi = eb_fast_mkmenuitem(fm, "Connect to Phoenix viewdata", 300, EB_FAST_MENU_TCP, '2');

	mi->fm_tcp.fm_host = "phoenix.server.royle.org";
	mi->fm_tcp.fm_port = 6854;
	mi->fm_tcp.fm_address = NULL;
	mi->is_viewdata = 1;

	mi = eb_fast_mkmenuitem(fm, "", 300, EB_FAST_MENU_BLANKLINE, 0xFF);

	mi = eb_fast_mkmenuitem(fm, "Execute test script", 300, EB_FAST_MENU_SCRIPT, '3');

	mi->fm_script.fm_script = "/etc/econet-gpio/test.script";

	mi = eb_fast_mkmenuitem(fm, "", 300, EB_FAST_MENU_BLANKLINE, 0xFF);
	
	mi = eb_fast_mkmenuitem(fm, "Disconnect", 300, EB_FAST_MENU_DISCONNECT, 'Q');

	fc = eb_fast_mkclient(NULL, 1, 1);

	fc->menu_home = fc->menu_current = fm;

	tcgetattr(STDIN_FILENO, &fc->old_t);

	/* Spawn a fast thread */

	if (pthread_create(&(fastthread), NULL, eb_fast_start_fast_service, fc))
	{
		eb_debug (0, 1, "FAST", "Fast server thread failed to start");
		exit (1);
	}

	pthread_create (&iothread, NULL, main_io_routine, fc);
	pthread_join (fastthread, NULL);
	pthread_cancel (iothread);

	tcsetattr(STDIN_FILENO, TCSANOW, &fc->old_t);

	return(0);

}

#endif
