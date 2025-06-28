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

/* Fast input routines */

int eb_fast_getc(struct __eb_fast_client *fc, uint32_t timeout)
{

	struct pollfd	p;
	int		pollreturn;
	uint8_t		key;

	p.fd = fc->fc_socket[EB_FAST_TO_SERVER][0];
	p.revents = 0;
	p.events = POLLIN | POLLHUP;

	pollreturn = poll(&p, 1, fc->fast_timeout);

	if (pollreturn)
	{
		read(fc->fc_socket[EB_FAST_TO_SERVER][0], &key, 1);
		return key;
	}
	else if (p.revents & POLLHUP)
		return -2; /* Hang up */
	else	return -1; /* Timeout */
}

/* Input string of max length with timeout */
int eb_fast_gets(struct __eb_fast_client *fc, char *ptr, uint8_t maxlen, uint32_t chartimeout, uint8_t is_password)
{
	int k;
	uint8_t int_ptr = 0;

	int_ptr = strlen(ptr);

	if (int_ptr > 0) /* String not empty */
		f_printf(fc, ptr);
	
	while (1)
	{
		k = eb_fast_getc(fc, chartimeout);

		if (k < 0) /* Disconnect or timeout */
			break;

		if ((k == 0x7F || k == 0x08)) /* Delete or left cursor */
		{
			if (int_ptr > 0) /* Inside the other if() so that a delete at start of input does nothing */
			{
				f_printf(fc, "%c%c%c", 0x08, ' ', 0x08);
				int_ptr--;
			}
		}
		else if (k == 0x0D || k == 0x0A) /* End of line possibilities */
			break;
		else if (k < ' ' || k > 0x7f) /* Invalid */
		{ }
		else if (k > 0 && int_ptr < maxlen)
		{
			*(ptr + int_ptr++) = k;
			*(ptr + int_ptr) = '\0';
			f_printf(fc, "%c", (is_password) ? '*' : k);
		}

	}

	return k;
}

/* Fileserver interaction functions */

// Print FS disc names in order (for *FAST handler)

uint8_t eb_fast_printdiscs (struct __eb_fast_client *fc)
{

        uint8_t         count;
        uint8_t         max_discs;
	struct __eb_device	*d = fc->parent;

        max_discs = fs_get_maxdiscs();

	f_printf (fc, "\n\rCurrently configured discs:\n\r\n\r");

        for (count = 0; count < max_discs; count++)
        {
                unsigned char   discname[128];

                fsop_get_disc_name (d->local.fs.server, count, discname);

                if (discname[0]) f_printf (fc, "%1x: %02d - %s\r\n", count, count, discname);
        }

	f_printf (fc, "\r\n");

        return max_discs;
}

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

	while (fc)
	{
		if (fc->net == net && fc->stn == stn)
			break;
		fc = fc->next;
	}
	pthread_mutex_unlock(&(device->local.fast_client_list_lock));
#else
	fc = NULL;
#endif

	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST search returning %p",
		eb_type_str(device->type), device->net, device->local.stn, net, stn, fc);

	if (fc)
	{
		eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST search result has net %d, stn %d",
			eb_type_str(device->type), device->net, device->local.stn, net, stn, fc->net, fc->stn);
	}

	return fc;
}

/* 
 * eb_fast_flag_disconnect
 *
 * Called by the bridge when it gets a disconnect request
 */

void eb_fast_flag_disconnect (struct __eb_device *device, uint8_t net, uint8_t stn)
{

#ifndef FAST_TEST
	struct __eb_fast_client *fc;

	fc = eb_fast_find_conn (device, net, stn);

	if (fc)
	{
		/* Kill the server thread */

		pthread_cancel(fc->fast_server); /* Kill the server on disconnect and all else will tidy up. Theoretically. */

		fc->fast_exit = 1; /* Request exit */ /* TO DO: The server thread may not exit in response to this! */

		eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST disconnect received - server thread cancelled",
			eb_type_str(device->type), device->net, device->local.stn, fc->net, fc->stn);
	}
	else
		eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST disconnect received from unknown client", 
			eb_type_str(device->type), device->net, device->local.stn, net, stn);
#endif

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
		pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]));
		fc->fast_client_ready = 1;
		pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]));
		pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_NETWORK]));
		pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_SERVER]));
	}
	else
		eb_debug (0, 1, "FAST", "FAST     %3d.%3d from %3d.%3d *FAST data request from unknown client",
				device->net,
				device->local.stn,
				net, stn);
}

struct __eb_fast_client * eb_fast_mkclient (struct __eb_device *device, uint8_t net, uint8_t stn)
{

	struct __eb_fast_client		*fc;

	/* Find any existing connection and kill it */

#ifndef FAST_TEST
	while ((fc = eb_fast_find_conn(device, net, stn))) /* We found a match - kill its server off */
	{
		pthread_cancel(fc->fast_server); /* It should now clean itself up */
	}
#endif

	fc = eb_malloc(__FILE__, __LINE__, "FAST", "New FAST client structure", sizeof(struct __eb_fast_client));

	if (!fc)
		return NULL;

	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client struct created",
			eb_type_str(device->type), device->net, device->local.stn, net, stn);

	fc->net = net;
	fc->stn = stn;
	fc->parent = device;
	fc->fast_output_ctrl = fc->fast_input_ctrl = 0;
	fc->fast_exit = 0;
#ifdef FAST_TEST
	fc->fast_client_ready = 1;
#else
	fc->fast_client_ready = 0;
#endif
	fc->fast_client_disconnected = 0;
	fc->fast_child = 0; /* Child PID */
	fc->pending[EB_FAST_TO_SERVER] = eb_malloc(__FILE__, __LINE__, "FAST", "New pending_to_server buffer 1k", EB_FAST_BUFSIZE);
	fc->pending[EB_FAST_TO_NETWORK] = eb_malloc(__FILE__, __LINE__, "FAST", "New pending_to_network buffer 1k", EB_FAST_BUFSIZE);
	fc->pt_len[EB_FAST_TO_SERVER] = fc->pt_len[EB_FAST_TO_NETWORK] = 0; /* Nothing in the buffers */
	fc->pt_sz[EB_FAST_TO_SERVER] = fc->pt_sz[EB_FAST_TO_NETWORK] = EB_FAST_BUFSIZE;
	fc->fast_timeout = 300 * 1000; /* 5 mins */

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
	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server starting new server: parent->fast_client_list = %p, next = %p, next->prev = %p (if any)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, fc->parent->local.fast_client_list, fc->next, (fc->next ? fc->next->prev : NULL));
	pthread_mutex_lock(&(device->local.fast_client_list_lock));
	fc->next = device->local.fast_client_list;
	if (fc->next)
		fc->next->prev = fc;
	device->local.fast_client_list = fc;
	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server started new server: parent->fast_client_list = %p, fc = %p, next = %p, next->prev = %p (if any)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, fc->parent->local.fast_client_list, fc, fc->next, (fc->next ? fc->next->prev : NULL));

	pthread_mutex_unlock(&(device->local.fast_client_list_lock));
#endif
	return fc;
}

/* Make a new menu with the given name, and return its struct */

struct __eb_fast_menu *	eb_fast_mkmenu(char *menu_heading, char *menu_name, struct __eb_fast_menu **mlist)
{
	struct __eb_fast_menu *m;

	if (!menu_name)
		eb_debug (1, 0, "FAST", "Attempt to create menu with no reference name!");

	if (!menu_heading)
		eb_debug (1, 0, "FAST", "Attempt to create menu with no heading!");

	m = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu structure", sizeof(struct __eb_fast_menu));

	m->item = NULL; /* No items initially */

	m->menu_name = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu name buffer", (menu_name ? strlen(menu_name) + 1 : 15));
	strcpy((char *) m->menu_name, menu_name);

	m->menu_heading = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu name buffer", strlen(menu_heading)+1);
	strcpy(m->menu_heading, menu_heading);

	m->next = *mlist;
	*mlist = m;

	return m;
}

/* Make a menu item, put it on the end of the list and return its struct address */

struct __eb_fast_menu_item * eb_fast_mkmenuitem(struct __eb_fast_menu *menu, char * description, uint16_t timeout, uint8_t menutype, unsigned char keypress, uint8_t priv_mask, uint8_t priv2_mask)
{
	struct __eb_fast_menu_item *mi, *mi_find;

	mi = eb_malloc(__FILE__, __LINE__, "FAST", "Create new menu item structure", sizeof(struct __eb_fast_menu_item));

	mi->fm_timeout = timeout;
	mi->fm_type = menutype;
	mi->fm_priv_mask = priv_mask;
	mi->fm_priv2_mask = priv2_mask;
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

/* Writes to the network pipe, but puts carriage returns in where it
 * finds a line feed, to appease the BBC.
 */

int eb_fast_write_to_network(struct __eb_fast_client *fc, char *data, int len)
{
	char	carriage_return = 0x0D;
	int	written = 0;

	while (written < len)
	{
		if (data[written] == 0x0A)
			write (fc->fc_socket[EB_FAST_TO_NETWORK][1], &carriage_return, 1);
		write (fc->fc_socket[EB_FAST_TO_NETWORK][1], &(data[written]), 1);
		written++;
	}

	return written;
}

int f_printf (struct __eb_fast_client *fc, char *fmt, ...)
{

        va_list ap;
        char str[16384];

        va_start(ap, fmt);

        vsnprintf (str, 16382, fmt, ap);

        va_end(ap);

        return write (fc->fc_socket[EB_FAST_TO_NETWORK][1], str, strlen(str));
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

	//fprintf (stderr, "\n\n*** fc = %p, d->type = %s, msg = %02X, dev = %p\n\n", fc, eb_type_str(d->type), msg, d);

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
	p->p.data[4] = msg; /* Message code */

	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d Fast Handler Loop - Send control message %02X", eb_type_str(d->type), d->net, d->local.stn, fc->net, fc->stn, msg);
	eb_enqueue_output(d, p, 5, NULL);
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

	p = eb_malloc(__FILE__, __LINE__, "FAST", "Allocate fast output packet", 12 + length);

	if (!p)
		eb_debug (1, 0, "FAST", "Unable to allocate memory for *FAST output packet");

	p->p.srcstn = d->local.stn;
	p->p.srcnet = d->net;
	p->p.dststn = fc->stn;
	p->p.dstnet = fc->net;
	p->p.aun_ttype = ECONET_AUN_DATA;
	p->p.port = EB_PORT_FAST;
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

	pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));
	child = fc->fast_child = fork();
	pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));

	if (child < 0)
	{
		f_printf(fc, "Failed to fork().\n\r");
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
					eb_fast_write_to_network (fc, buf, r);

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
			execl("/bin/bash", "/bin/bash", "-c", mi->fm_script.fm_script, (char *) NULL); /* For now. Add parameter capability later */
	}
	else
	{
		waitpid(child, NULL, 0);
		pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));
		fc->fast_child = 0;
		pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));

	}

	//tcsetattr (STDIN_FILENO, TCSANOW, &login_t);
}

#define EB_FAST_SSH_CONNECT_OK 0
#define EB_FAST_SSH_CONNECT_CANNOTRESOLVE 1
#define EB_FAST_SSH_CONNECT_NOSOCKET 2
#define EB_FAST_SSH_CONNECT_FAILED 3
#define EB_FAST_SSH_CONNECT_INITFAILED 4
#define EB_FAST_SSH_CONNECT_ESTABLISHFAILED 5
#define EB_FAST_SSH_CONNECT_AUTHFAIL_PW 6
#define EB_FAST_SSH_CONNECT_AUTHFAIL_KEYBOARD 7
#define EB_FAST_SSH_CONNECT_AUTHFAIL_PUBKEY 8
#define EB_FAST_SSH_CONNECT_AUTHFAIL_NOMETHODS 9
#define EB_FAST_SSH_CONNECT_CONNECTFAIL_CREATESESSION 10
#define EB_FAST_SSH_CONNECT_PTYFAIL 11
#define EB_FAST_SSH_CONNECT_SHELLFAIL 12
#define EB_FAST_SSH_CONNECT_UNKNOWNERROR 255

/* Establish SSH connection */

uint8_t eb_fast_ssh_connect(struct __eb_fast_client *fc, struct __eb_fast_menu_item *i)
{

	int	rc, c, auth_pw = 0;
	LIBSSH2_SESSION *session = NULL;
	struct addrinfo *addr, hints, *rp;
	char	service[10];
	char	host_int[128], username_int[21], password_int[21];
	uint16_t	port = i->fm_ssh.fm_port;
	char	*host = i->fm_ssh.fm_host;
	char	*username = i->fm_ssh.fm_username;
	char	*password = i->fm_ssh.fm_password;
	char 	*pubkeyfile = i->fm_ssh.fm_pubkey;
	char	*privkeyfile = i->fm_ssh.fm_privkey;
	uint8_t	ret = 255;

	memset (host_int, 0, sizeof(host_int));
	memset (username_int, 0, sizeof(username_int));
	memset (password_int, 0, sizeof(password_int));

	snprintf (service, 6, "%d", port);

	if (!host)
	{
		f_printf (fc, "Host: ");
		eb_fast_gets(fc, host_int, 127, fc->fast_timeout, 0);
		f_printf (fc, "\n\r");
	}
	else	strncpy(host_int, host, 127);

	if (!username)
	{
		f_printf (fc, "Username: ");
		eb_fast_gets(fc, username_int, 20, fc->fast_timeout, 0);
		f_printf (fc, "\n\r");
	}
	else	strncpy(username_int, username, 20);

	if (!password)
	{
		f_printf (fc, "Password: ");
		eb_fast_gets(fc, password_int, 20, fc->fast_timeout, 1);
		f_printf (fc, "\n\r");
	}
	else	strncpy(password_int, password, 20);

	/* Needs updating for name resolution & IPV6 */

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if (getaddrinfo(host_int, service, &hints, &addr) < 0)
		return EB_FAST_SSH_CONNECT_CANNOTRESOLVE;

	rp = addr;

	while (rp)
	{
    		fc->ssh_sock = socket(AF_INET, SOCK_STREAM, 0);
    		if(fc->ssh_sock < 0) 
		{
        		rc = 1;
			freeaddrinfo(addr);
			return EB_FAST_SSH_CONNECT_NOSOCKET;
    		}

		if (connect(fc->ssh_sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(fc->ssh_sock);

		rp = rp->ai_next;
 
	}

	freeaddrinfo(addr);

	if (!rp)
	{
		close (fc->ssh_sock);
		return EB_FAST_SSH_CONNECT_FAILED;
	}
 
	if (!host)
		f_printf (fc, "Connecting to: %s\n\r", host_int);

    	/* Create a session instance and start it up. This will trade welcome
     	* banners, exchange keys, and setup crypto, compression, and MAC layers
     	*/ 

    	fc->ssh_session = libssh2_session_init();

    	if(!fc->ssh_session) 
	{
		ret = EB_FAST_SSH_CONNECT_INITFAILED;
        	goto shutdown;
    	}
 
    	/* Enable all debugging when libssh2 was built with debugging enabled */ 
    	libssh2_trace(fc->ssh_session, ~0);

    	rc = libssh2_session_handshake(fc->ssh_session, fc->ssh_sock);
	
    	if(rc) 
	{
		ret = EB_FAST_SSH_CONNECT_ESTABLISHFAILED;
        	goto shutdown;
    	}
	 
    	rc = 1;
	 
    	/* At this point we have not yet authenticated.  The first thing to do
     	* is check the hostkey's fingerprint against our known hosts Your app
     	* may have it hard coded, may go to a file, may present it to the
     	* user, that's your call
     	*/ 

    	fc->ssh_fingerprint = libssh2_hostkey_hash(fc->ssh_session, LIBSSH2_HOSTKEY_HASH_SHA1);
	
    	f_printf(fc, "Fingerprint: ");

    	for (c = 0; c < 20; c++) 
        	f_printf(fc, "%02X ", (unsigned char)fc->ssh_fingerprint[c]);

    	f_printf(fc, "\n\r");
	 
    	/* check what authentication methods are available */ 

    	fc->ssh_userauthlist = libssh2_userauth_list(fc->ssh_session, username_int, (unsigned int)strlen(username_int));
	
    	if(fc->ssh_userauthlist) 
	{
        	f_printf(fc, "Authentication methods: %s\n\r", fc->ssh_userauthlist);

        	if(strstr(fc->ssh_userauthlist, "password")) auth_pw |= 1;

        	if(strstr(fc->ssh_userauthlist, "keyboard-interactive")) auth_pw |= 2;

        	if(strstr(fc->ssh_userauthlist, "publickey")) auth_pw |= 4;
	 
        	if (auth_pw & 1) /* Password authentication */
		{
            		if(libssh2_userauth_password(fc->ssh_session, username_int, password_int) != 0) 
			{
				ret = EB_FAST_SSH_CONNECT_AUTHFAIL_PW;
                		goto shutdown;
            		}
            	}
#if 0
        else if (auth_pw & 2) {
            /* Or via keyboard-interactive */ 
            if(libssh2_userauth_keyboard_interactive(fc->ssh_session, username, &kbd_callback) ) {
                fprintf(stderr,
                        "Authentication by keyboard-interactive failed.\n");
		ret = EB_FAST_SSH_CONNECT_AUTHFAIL_KEYBOARD;
                goto shutdown;
            }
        }
#endif
        	else if (auth_pw & 4 && pubkeyfile && privkeyfile) 
		{
            		size_t fn1sz, fn2sz;
            		char *fn1, *fn2;
            		char const *h = getenv("HOME");

            		if(!h || !*h)
                		h = ".";

            		fn1sz = strlen(h) + strlen(pubkeyfile) + 2;
            		fn2sz = strlen(h) + strlen(privkeyfile) + 2;

            		fn1 = eb_malloc(__FILE__, __LINE__, "FAST", "SSH public key file", fn1sz);
            		fn2 = eb_malloc(__FILE__, __LINE__, "FAST", "SSH private key file", fn2sz);

			if (!fn1 || !fn2)
				eb_debug (1, 0, "FAST", "Out of memory allocating SSH key file");

            /* Avoid false positives */ 
#if defined(__GNUC__) && __GNUC__ >= 7
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wformat-truncation=1"
#endif
            		snprintf(fn1, fn1sz, "%s/%s", h, pubkeyfile);
            		snprintf(fn2, fn2sz, "%s/%s", h, privkeyfile);
#if defined(__GNUC__) && __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif
 
            		if(libssh2_userauth_publickey_fromfile(fc->ssh_session, username, fn1, fn2, password)) 
	    		{
                		f_printf(fc, "Authentication by public key failed.\n\r");
				eb_free (__FILE__, __LINE__, "FAST", "Free public key file", fn1);
				eb_free (__FILE__, __LINE__, "FAST", "Free private key file", fn1);
				ret = EB_FAST_SSH_CONNECT_AUTHFAIL_PUBKEY;
                		goto shutdown;
            		}

			eb_free (__FILE__, __LINE__, "FAST", "Free public key file", fn1);
			eb_free (__FILE__, __LINE__, "FAST", "Free private key file", fn1);
		}
        }
        else 
	{
            f_printf(fc, "No supported authentication methods found.\n\r");
	    ret = 9;
            goto shutdown;
        }
 
    /* Request a session channel on which to run a shell */ 

    	fc->ssh_channel = libssh2_channel_open_session(fc->ssh_session);

    	if(!fc->ssh_channel) 
	{
		ret = EB_FAST_SSH_CONNECT_CONNECTFAIL_CREATESESSION;
        	goto shutdown;
    	}
 
    	libssh2_channel_setenv(fc->ssh_channel, "PIECONETBRIDGE", "yes");
 
    /* Request a terminal with 'vanilla' terminal emulation
     * See /etc/termcap for more options. This is useful when opening
     * an interactive shell.
     */ 

    	if (libssh2_channel_request_pty(fc->ssh_channel, "vanilla")) 
	{
		ret = EB_FAST_SSH_CONNECT_PTYFAIL;
		goto shutdown;
	}
 
#if 0
    if(libssh2_channel_exec(channel, "/bin/sh")) {

         fprintf(stderr, "Unable to request command on channel\n");
         goto shutdown;
#endif

        /* Instead of just running a single command with libssh2_channel_exec,
         * a shell can be opened on the channel instead, for interactive use.
         * You usually want a pty allocated first in that case (see above). */ 

        if(libssh2_channel_shell(fc->ssh_channel)) 
	{
	    ret = EB_FAST_SSH_CONNECT_SHELLFAIL;
	    goto shutdown;
        }
 
	/* Set non-blocking */
	libssh2_channel_set_blocking(fc->ssh_channel, 0);

	return EB_FAST_SSH_CONNECT_OK;
 
shutdown:
 
    	if(session) 
	{
        	libssh2_session_disconnect(session, "Normal Shutdown");
        	libssh2_session_free(session);
    	}
 
    	if(fc->ssh_sock != LIBSSH2_INVALID_SOCKET) 
	{
        	shutdown(fc->ssh_sock, 2);
		close(fc->ssh_sock);
    	}
 
    	libssh2_exit();

	return ret;

}

char * eb_fast_ssh_strerr(uint8_t res)
{
	return
		res == EB_FAST_SSH_CONNECT_OK ? "Successful connection" :
		res == EB_FAST_SSH_CONNECT_CANNOTRESOLVE ? "Host unknown" :
		res == EB_FAST_SSH_CONNECT_NOSOCKET ? "Cannot open socket" :
		res == EB_FAST_SSH_CONNECT_FAILED ? "Cannot connect SSH" :
		res == EB_FAST_SSH_CONNECT_INITFAILED ? "Cannot initialize SSH" :
		res == EB_FAST_SSH_CONNECT_AUTHFAIL_PW ? "Password authentication failed" :
		res == EB_FAST_SSH_CONNECT_AUTHFAIL_KEYBOARD ? "Keyboard interactive authentication failed" :
		res == EB_FAST_SSH_CONNECT_AUTHFAIL_PUBKEY ? "Public key authentication failed":
		res == EB_FAST_SSH_CONNECT_AUTHFAIL_NOMETHODS ? "No available authentication methods" :
		res == EB_FAST_SSH_CONNECT_CONNECTFAIL_CREATESESSION ? "Could not create SSH session" :
		res == EB_FAST_SSH_CONNECT_PTYFAIL ? "Could not create PTY" :
		res == EB_FAST_SSH_CONNECT_SHELLFAIL ? "Could not create shell" : "Unknown error";
}
/* Mediate traffic between sock -> fc->fc_socket[EB_FAST_TO_NETWORK][1]   and fc->fc_socket[EB_FAST_TO_SERVER][0] -> sock */

void eb_fast_run_connection (struct __eb_fast_client *fc, int sock, uint8_t is_ssh)
{

	struct pollfd	p[2];
	int	pollres;

	fcntl(fc->fc_socket[EB_FAST_TO_SERVER][0], F_SETFL, fcntl(fc->fc_socket[EB_FAST_TO_SERVER][0], F_GETFL) | O_NONBLOCK);
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);

	while (1)
	{

		p[0].fd = sock;
		p[0].revents = 0;
		p[0].events = POLLIN | POLLHUP;
	
		p[1].fd = fc->fc_socket[EB_FAST_TO_SERVER][0];
		p[1].revents = 0;
		p[1].events = POLLIN | POLLHUP;

		pollres = poll (p, 2, 500);

		if (pollres < 0)
		{	
			eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server error in run connection (%s)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, strerror(errno));
			return;
		}

		if (p[0].revents & POLLHUP)
		{	
			eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server detected hangup on TCP connection", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn);
			return;
		}
		
		if (p[1].revents & POLLHUP)
		{	
			eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server detected hangup on pipe to server", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn);
			return;
		}
		
		for (int count = 0; count < 2; count++)
		{
			if (p[count].events & POLLIN)
			{
				char 	data[128];
				char	data_ssh_stderr[128];
				int	res = 0, res_ssh_stderr = 0;
		
				if (count == 0)
				{
					if (is_ssh)
					{
						res = libssh2_channel_read(fc->ssh_channel, data, 128);
						res_ssh_stderr = libssh2_channel_read_stderr(fc->ssh_channel, data_ssh_stderr, 128-res);
					}
					else
						res = read(sock, data, 128);
				}
				else
					res = read(fc->fc_socket[EB_FAST_TO_SERVER][0], data, 128);
	
				if (res > 0 || (is_ssh && res_ssh_stderr > 0))
				{
					int	writeres = 0, writeres_ssh_stderr = 0;

					if (count == 0)
					{
						if (res > 0)
							writeres = write(fc->fc_socket[EB_FAST_TO_NETWORK][1], data, res);

						if (res_ssh_stderr > 0)
							writeres_ssh_stderr = write(fc->fc_socket[EB_FAST_TO_NETWORK][1], data_ssh_stderr, res_ssh_stderr);

						pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_NETWORK]));
						pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_SERVER])); /* In case this helps it look for more stuff from the other end */
					}
					else
					{
						if (is_ssh)
							writeres = libssh2_channel_write(fc->ssh_channel, data, res);
						else
						{
							writeres = write(sock, data, res);
							fprintf (stderr, "\n\n*** Wrote %d bytes to destination (result %d)\n\n", res, writeres);
						}
					}

					if (writeres < 0 || writeres_ssh_stderr < 0)
						eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server encoutered error writing to %s (%s)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, (count == 0 ? "Econet" : "distant"), strerror(errno));
				}
				else if (res < 0 && errno == EWOULDBLOCK)
				{
					/* do nothing */
				}
				else if (res < 0 || res_ssh_stderr < 0)
				{	
					eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server encoutered error reading %s (%s)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, (count == 0 ? "distant" : "Econet"), strerror(errno));
					return;
				}
			}
		}
			
		if (is_ssh && libssh2_channel_eof(fc->ssh_channel))
			break;

	}

	fcntl(fc->fc_socket[EB_FAST_TO_SERVER][0], F_SETFL, fcntl(fc->fc_socket[EB_FAST_TO_SERVER][0], F_GETFL) & ~O_NONBLOCK);
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK);

	return;
}

/* Repeatedly display menu until quit */

void eb_fast_display_menu(struct __eb_fast_client *fc)
{

	struct __eb_fast_menu_item *mi;
	char	valid_keys[20];
	uint8_t	vk_count;
	uint8_t fm_exit = 0;

#ifndef FAST_TEST
	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server display starting - parent is %p", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, fc->parent);
#endif
	/* Drop privs just in case */

	/*
	 *
	if (seteuid(getuid()) != 0)
	{
		eb_debug (0, 1, "FAST", "Unable to drop privileges for handler");
		f_printf (fc, "System error! Cannot drop privileges.\n\r");
		close (fc->fc_socket[EB_FAST_TO_NETWORK][1]);
		return;
	}
	*/

	fc->from_client = fdopen(fc->fc_socket[EB_FAST_TO_SERVER][0], "rb");

	if (!fc->from_client)
	{
		eb_debug (0, 1, "FAST", "FAST server thread - error on fdopen(in)");
		return;
	}

	if (!fc->menu_current)
	{
		eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server quitting: no menu", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn);
		return;
	}

	if (!fc->menu_current->item)
	{
		eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server quitting: %s has no menu items!", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, fc->menu_current->menu_name);
		return;
	}


#ifdef FAST_TEST
	eb_debug (0, 1, "FAST", "FAST display menu routine begun - in = %p, out = %d", fc->from_client, fc->fc_socket[EB_FAST_TO_SERVER][1]);
#else
	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST display menu begins", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn);
#endif


		while (!fm_exit)
		{
			uint8_t		key;
			uint8_t		priv, priv2;
			struct		__fs_station *s;

			priv = priv2 = 0;

			s = fc->parent->local.fs.server;

			if (s)
			{
				struct __fs_active	*a;
				a = fsop_stn_logged_in(s, fc->net, fc->stn);

				if (a)
				{
					priv = a->user->priv;
					priv2 = a->user->priv2;
				}
			}

			if (ECONET_DEV_STATION(fc->parent->local.fast_priv_stns, fc->net, fc->stn))
				priv2 |= FS_PRIV2_BRIDGE;

			mi = fc->menu_current->item;
		
			if (!fc->menu_current->item->next) /* Only one item */
				fm_exit = 1; /* Force exit */

			if (fc->menu_current->item->next) /* More than one item */
				f_printf (fc, "\n\n\r%s\n\n\r", fc->menu_current->menu_heading); /* Clear screen */

			memset(valid_keys, 0, sizeof(valid_keys));	
			vk_count = 0;
	
			while (mi && (vk_count < (sizeof(valid_keys)-1)))
			{
				if (
					(priv & mi->fm_priv_mask) == mi->fm_priv_mask
				&&	(priv2 & mi->fm_priv2_mask) == mi->fm_priv2_mask
				) /* Only display if we have the right privs */
				{
					
					if (mi->fm_type == EB_FAST_MENU_BLANKLINE)
					
					{
						if (fc->menu_current->item->next)  /* This is checking if this is a one-item menu */
							f_printf (fc, "\r\n");
					}
					else if (mi->fm_type != EB_FAST_MENU_HEADING)
					{
						if (fc->menu_current->item->next)
							f_printf (fc, "%c. %s\r\n", mi->keypress, mi->fm_description);
						valid_keys[vk_count++] = mi->keypress;
					}
					else if (fc->menu_current->item->next)
						f_printf (fc, "\r\n%s\r\n", mi->fm_description);
				}
		
				mi = mi->next;
			}
	
			if (fc->menu_current->item->next) 
			{
				int		k; 

				f_printf (fc, "\r\nSelect? ");

				k = eb_fast_getc(fc, fc->fast_timeout);

				if (k == -2) /* Disconnect */
				{
					eb_fast_send_control(fc, EB_FAST_OP_DISCONNECT);
					fm_exit = 1;
				}
				else if (k > 0) /* Key, not timeout */
					key = k;
			}
			else
			{
				fm_exit = 1; /* Quit out after one go */
				key = fc->menu_current->item->keypress;
			}
	
			if (key >= 'a' && key <= 'z')
			{
				key &= 0xDF; /* To caps */
			}

			if (fm_exit)
				continue; /* Causes loop exit */

			if (strchr(valid_keys, key))
			{
	
				struct __eb_fast_menu_item 	*i;
	
				if (fc->menu_current->item->next) 
					f_printf (fc, "%c\r\r\n", key);
	
				/* Process */
	
				i = fc->menu_current->item;
	
				while (i && i->keypress != key)
					i = i->next;
	
				if (i)
				{
					/* Enable viewdata if we need it */

					if (i->is_viewdata)
						eb_fast_send_control (fc, EB_FAST_OP_VIEWDATA_ON);
	
					switch (i->fm_type)
					{
						case EB_FAST_MENU_SUBMENU: /* Move to submenu */
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - new menu %s", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_submenu.fm_submenu->menu_name);
								fc->menu_current = i->fm_submenu.fm_submenu;
							} break;
						case EB_FAST_MENU_BIN_LOGIN: /* Spawn login shell */
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Local login", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn);
								eb_fast_bin_login(fc, i);
							} break;
						case EB_FAST_MENU_SCRIPT: /* Run local script */
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Run script (%s)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_script.fm_script);
								eb_fast_bin_login(fc, i);
							} break;
						case EB_FAST_MENU_DISCONNECT: /* Quit! */
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Request disconnect", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn);
								eb_fast_send_control(fc, EB_FAST_OP_DISCONNECT);
								fm_exit = 1;
							} break;
						case EB_FAST_MENU_TCP: /* Connect to TCP port */
							{
								int	ga_res;
								struct addrinfo	hints, *rp;
								char	portname[7];

								memset (&hints, 0, sizeof(struct addrinfo));

								hints.ai_family = i->fm_tcp.fm_family;
								hints.ai_socktype = SOCK_STREAM;
								hints.ai_protocol = IPPROTO_TCP;
								hints.ai_flags = 0;

								snprintf(portname, 6, "%d", i->fm_tcp.fm_port);

								ga_res = getaddrinfo(i->fm_tcp.fm_host, portname, &hints, &(i->fm_tcp.fm_address));

								if (ga_res != 0)
								{
									eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Request TCP connection %s:%d - cannot resolve hostname", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_tcp.fm_host, i->fm_tcp.fm_port);
									f_printf (fc, "\n\rUnknown host: %s\n\r\n", i->fm_tcp.fm_host);
								}
								else
								{
									rp = i->fm_tcp.fm_address;

									while (rp)
									{

										i->fm_tcp.fm_socket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

										if (i->fm_tcp.fm_socket != -1)
										{
											if (connect(i->fm_tcp.fm_socket, rp->ai_addr, rp->ai_addrlen) == 0)
												break; /* Success */

											eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Request TCP connection %s:%d - cannot open socket (%s) - trying next addrinfo entry", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_tcp.fm_host, i->fm_tcp.fm_port, strerror(errno));
											close(i->fm_tcp.fm_socket);
											i->fm_tcp.fm_socket = -1;
										}

										rp = rp->ai_next;
									}

									if (!rp)
									{
										eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Request TCP connection %s:%d - cannot open socket", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_tcp.fm_host, i->fm_tcp.fm_port);
										f_printf (fc, "\n\rUnable to connect: %s\n\r\n", i->fm_tcp.fm_host);
									}
									else
									{
										uint8_t	option=1;
										/* Connection open */

										eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Connected to %s:%d", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_tcp.fm_host, i->fm_tcp.fm_port);
										setsockopt (i->fm_tcp.fm_socket, SOL_SOCKET, SOCK_NONBLOCK, &option, 1);
										eb_fast_run_connection (fc, i->fm_tcp.fm_socket, 0);

									}

									freeaddrinfo(i->fm_tcp.fm_address);
											
								}




							} break;
						case EB_FAST_MENU_SERIAL: /* Connect to serial port */
							{
								int	conn;
								struct termios	t;
								char	connstring[64];

								conn = open(i->fm_serial.fm_device, O_RDWR | O_NONBLOCK);

								if (conn < 0)
								{
									eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Serial connection to %s - unable to open port (%s)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_serial.fm_device, strerror(errno));
									return;
								}

								/* Set speed & termios */

								tcgetattr(conn, &t);
								
								/* Echo etc. */

								t.c_lflag &= ~(ISIG | ICANON | ECHO);

								/* Parity */

								t.c_cflag &= ~ (PARENB | PARODD); /* None is the default */
								if (i->fm_serial.fm_parity == PAR_ODD)
									t.c_cflag |= PARENB | PARODD;
								else if (i->fm_serial.fm_parity == PAR_EVEN)
									t.c_cflag |= PARENB;

								/* Word length */

								t.c_cflag &= ~CSIZE;

								if (i->fm_serial.fm_wordlength == BIT_SEVEN)
									t.c_cflag |= CS7;
								else	t.c_cflag |= CS8;

								/* Stop bits */

								t.c_cflag &= ~CSTOPB;

								if (i->fm_serial.fm_stopbits == 2)
									t.c_cflag |= CSTOPB;

								t.c_oflag = 0; // No remap
								t.c_cc[VMIN] = 0; // No block
								t.c_cc[VTIME] = 5; // 0.5s timeout

								t.c_cflag &= ~CRTSCTS; // Disable RTS/CTS

								/* Baud rate */

								switch (i->fm_serial.fm_speed) {
									case 1200:
										cfsetspeed(&t, B1200);
										break;
									case 2400:
										cfsetspeed(&t, B2400);
										break;
									case 4800:
										cfsetspeed(&t, B4800);
										break;
									case 9600:
										cfsetspeed(&t, B9600);
										break;
									case 19200:
										cfsetspeed(&t, B19200);
										break;
									case 38400:
										cfsetspeed(&t, B38400);
										break;
									case 57600:
										cfsetspeed(&t, B57600);
										break;
									case 115200:
										cfsetspeed(&t, B115200);
										break;
									case 230400:
										cfsetspeed(&t, B230400);
										break;
									default: cfsetspeed(&t, B1200); /* Default */
										 break;
								} 

								tcsetattr(conn, TCSANOW, &t);

								sprintf (connstring, "(%d baud, %1d%c%1d)", i->fm_serial.fm_speed, (i->fm_serial.fm_wordlength == BIT_SEVEN ? 7 : 8),
										(i->fm_serial.fm_parity == PAR_ODD) ? 'O' :
										(i->fm_serial.fm_parity == PAR_EVEN) ? 'E' : 'N',
										i->fm_serial.fm_stopbits);

								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Serial connection to %s opened %s", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_serial.fm_device, connstring);

								f_printf (fc, "Connected to %s\n\r", i->fm_serial.fm_device);
								eb_fast_run_connection (fc, conn, 0);

								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Serial connection to %s closed", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_serial.fm_device);

							} break;
						case EB_FAST_MENU_HOMEMENU: /* Back to top level menu */
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - go to home menu %s", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_submenu.fm_submenu->menu_name);
								fc->menu_current = fc->menu_home;

							} break;
						case EB_FAST_MENU_SSH: /* Connect over SSH */
							{
								uint8_t res;
								if (!(res = eb_fast_ssh_connect(fc, i)))
								{
									eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - SSH connection to %s",
											eb_type_str(fc->parent->type),
											fc->parent->net,
											fc->parent->local.stn,
											fc->net, 
											fc->stn,
											i->fm_ssh.fm_host);
									eb_fast_run_connection (fc, fc->ssh_sock, 1);
									libssh2_channel_close(fc->ssh_channel);
									if (fc->ssh_channel)
									{
										libssh2_channel_free(fc->ssh_channel);
										fc->ssh_channel = NULL;
									}
								}
								else
								{
									eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - FAILED SSH connection to %s (%s)",
											eb_type_str(fc->parent->type),
											fc->parent->net,
											fc->parent->local.stn,
											fc->net, 
											fc->stn,
											i->fm_ssh.fm_host,
											eb_fast_ssh_strerr(res));
									f_printf (fc, "\n\rUnable to connect: %s\n\r\n", eb_fast_ssh_strerr(res));
								}

							} break;
						/* Unimplemented functions */
						case EB_FAST_MENU_FSSTOPSTART: /* Fileserver function */
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Request unimplemented function %02X", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_type);
								f_printf(fc, "Not yet implemented.\r\n\n");
								sleep(3);
							} break;
						default:
							{
								eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST client - Request unknown function %02X", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, i->fm_type);
								f_printf(fc, "Unknown menu action! (This should not happen.)\r\n\n");
								sleep(3);
							} break;
					}

					/* Turn viewdata off if it was turned on */

					if (i->is_viewdata)
						eb_fast_send_control (fc, EB_FAST_OP_VIEWDATA_OFF);
	
	
				}
				else
				{
					f_printf(fc, "Error finding what to do with that keypress!\r\n(This shouldn't happen.)\r\n");
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
		pthread_mutex_lock(&(fc->parent->local.fast_client_list_lock));
#endif

	if (fc->dest_host)
		eb_free (__FILE__, __LINE__, "FAST", "Fast cleanup: free dest_host", fc->dest_host);
	
	if (fc->pending[EB_FAST_TO_NETWORK])
		eb_free (__FILE__, __LINE__, "FAST", "Fast cleanup: free pending data to network", fc->pending[EB_FAST_TO_NETWORK]);

	if (fc->pending[EB_FAST_TO_SERVER])
		eb_free (__FILE__, __LINE__, "FAST", "Fast cleanup: free pending data to network", fc->pending[EB_FAST_TO_SERVER]);

	if (fc->prev) /* Splice out from prev */
		fc->prev->next = fc->next;
	else
	{
		/* We were first on the list - update parent->fast_client_list if we are not in test mode */
#ifndef FAST_TEST
		fc->parent->local.fast_client_list = fc->next;
#endif
	}

	if (fc->next) /* Splice out from next */
		fc->next->prev = fc->prev;

	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server cleaned up: parent->fast_client_list = %p, next->prev = %p (if any)", eb_type_str(fc->parent->type), fc->parent->net, fc->parent->local.stn, fc->net, fc->stn, fc->parent->local.fast_client_list, (fc->next ? fc->next->prev : NULL));

#ifndef FAST_TEST
	if (fc->parent)
		pthread_mutex_unlock(&(fc->parent->local.fast_client_list_lock));
#endif

	/* Free the client struct */

	eb_free (__FILE__, __LINE__, "FAST", "Free client struct on handler exit", fc);
}

/* Displays menu */

void *	eb_fast_server_thread(void * fc)
{

	struct __eb_fast_client		*me;

	me = (struct __eb_fast_client *) fc;

#ifndef FAST_TEST
	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server thread starting", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
	eb_debug (0, 4, "FAST", "FAST server thread exiting");
#endif
	eb_fast_send_control (me, EB_FAST_OP_DATARQ); /* Please, Sir, can I have some more? */

	me->menu_current = me->menu_home;

	eb_fast_display_menu(me);

	me->fast_exit = 1;

#ifndef FAST_TEST
	eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST server disconnecting client", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
	eb_debug (0, 4, "FAST", "FAST server thread exiting");
#endif
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

#ifndef FAST_TEST
	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network starting", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
	eb_debug (0, 2, "FAST", "FAST IO thread to network starting");
#endif

	pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));

	while (1)
	{
		int pollreturn;
		struct timespec t, t2;
		struct timeval last_tx, now;

		/* Wait for request for data from remote end - we get signalled here from both the 
		 * server end, and the receiver when more data is requested
		 */

		clock_gettime(CLOCK_REALTIME, &t);
		clock_gettime(CLOCK_REALTIME, &t2);

		t.tv_nsec += 1000000 * EB_FAST_OUTPUTWAIT; // 100ms
		if (t2.tv_nsec < t.tv_nsec)
			t.tv_sec++;

		/* We do a timed wait here because if there's more data in the buffer
		 * to go to the network, we'll wakt up and see if we can send some
		 * more
		 */

		gettimeofday(&now, 0);
		last_tx.tv_sec = last_tx.tv_usec = 0;

		if (!(me->pt_len[EB_FAST_TO_NETWORK] > 0 && me->fast_client_ready))
		{	
			if (pthread_cond_timedwait(&(me->fast_wake[EB_FAST_TO_NETWORK]), &(me->fast_io_mutex[EB_FAST_TO_NETWORK]), &t) < 0)
			{
				eb_debug (1, 0, "FAST", "Fatal error doing timewait on fast_wake[TO_NETWORK]");
			}
		}

		if (me->fast_exit) /* quit */
			break;

		/* Process output - 32 byte chunks we think */

		if (me->fast_client_ready && me->pt_len[EB_FAST_TO_NETWORK] > 0)
		{
			int	sz = (me->pt_len[EB_FAST_TO_NETWORK] > 32 ? 32 : me->pt_len[EB_FAST_TO_NETWORK]);

			gettimeofday(&last_tx, 0);

			eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network: checking for data to send to network", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);

			// pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));


#ifdef FAST_TEST
			/* for test purposes, write to stdout  - when in production, check client is ready and send a packet */

			write(STDOUT_FILENO, me->pending[EB_FAST_TO_NETWORK], sz);

			me->fast_client_ready = 1; /* Fudge for testing */

#else
			/* Stuff here to write to network */
			eb_fast_send_data (me, me->pending[EB_FAST_TO_NETWORK], sz);
			me->fast_client_ready = 0;
#endif

			eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network: send %d bytes to network", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, sz);

			memmove(me->pending[EB_FAST_TO_NETWORK], &(me->pending[EB_FAST_TO_NETWORK][sz]), me->pt_len[EB_FAST_TO_NETWORK]);

			me->pt_len[EB_FAST_TO_NETWORK] -= sz;

#ifndef FAST_TEST
			eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network checking whether can shrink buffer: current len/size/diff  %d/%d/%d", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, me->pt_len[EB_FAST_TO_NETWORK], me->pt_sz[EB_FAST_TO_NETWORK], (me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]));
#else
			eb_debug (0, 4, "FAST", "FAST IO thread to network checking to see if it can shrink the buffer: current to_network size = %d, len = %d, diff = %d", 
					me->pt_sz[EB_FAST_TO_NETWORK],
					me->pt_len[EB_FAST_TO_NETWORK],
					(me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]));
#endif

			if ((me->pt_sz[EB_FAST_TO_NETWORK] > EB_FAST_BUFSIZE) && (me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]) >= (EB_FAST_SHRINKTHRESHOLD))
			{
				uint32_t	new_sz;

				/* Shrink the buffer, but not below BUFSIZE */
			
				new_sz = ((me->pt_sz[EB_FAST_TO_NETWORK] - me->pt_len[EB_FAST_TO_NETWORK]) / EB_FAST_BUFSIZE) * EB_FAST_BUFSIZE;

				if (new_sz == 0)
					new_sz = EB_FAST_BUFSIZE;

#ifndef FAST_TEST
				eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network shrunk buffer now used/len %d/%d", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, me->pt_len[EB_FAST_TO_NETWORK], new_sz);
#else
				eb_debug (0, 4, "FAST", "FAST IO thread shrunk buffer now used/len %d/%d", me->pt_len[EB_FAST_TO_NETWORK], new_sz);
#endif

				me->pending[EB_FAST_TO_NETWORK] = realloc(me->pending[EB_FAST_TO_NETWORK], new_sz);

				me->pt_sz[EB_FAST_TO_NETWORK] = new_sz;
			}

		}

		/* Poll to-network socket */

		p.fd = me->fc_socket[EB_FAST_TO_NETWORK][0];
		p.revents = 0;
		p.events = POLLIN | POLLHUP;

#ifndef FAST_TEST
		eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network polling queue", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
		eb_debug (0, 4, "FAST", "FAST IO thread polling to-network queue");
#endif

		if (me->fast_client_ready && ((pollreturn = poll(&p, 1, 0)) > 0))
		{
			eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread network polling data from to_network fd - poll() return was positive, p.revents = %0008X, pollreturn = %d", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, p.revents, pollreturn);

			if (p.revents & POLLHUP)
			{
#ifndef FAST_TEST
				eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network got POLLHUP - exiting", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
				eb_debug (0, 2, "FAST", "FAST IO thread to network got POLLHUP - exiting");
#endif
				/* Clean up and exit */

				me->fast_exit = 1;
				break;
			}

			if (p.revents & POLLIN)
			{
				int	read_result;
				uint8_t	buffer[128];

				eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network polling data from to_network fd - reading data after positive poll()", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);

				read_result = read(me->fc_socket[EB_FAST_TO_NETWORK][0], buffer, 128);

				eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network polling data from to_network fd - read data returned %d", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, read_result);

				if (read_result < 0)
					eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network received error on read() from server thread (%s)", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, strerror(errno));
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

			p.fd = me->fc_socket[EB_FAST_TO_NETWORK][0];
			p.revents = 0;
			p.events = POLLIN | POLLHUP;

			// pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));
		}
		else if (pollreturn < 0)
		{
			eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network: error on read from socket (%s)", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn, strerror(errno));
			return NULL;
		}
		else
			eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network: nothing to process into buffer", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);

		/* Snooze off again */

#ifndef FAST_TEST
		eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network dozing off", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
		eb_debug (0, 4, "FAST", "FAST IO thread to network dozing off");
#endif
	}

#ifndef FAST_TEST
	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to network exiting (detected hangup)", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
	eb_debug (0, 2, "FAST", "FAST IO thread to network exiting (detected hangup)");
#endif

	pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_NETWORK]));

	me->fast_exit = 1;

	while (1)
		sleep(60); // Sleep and wait to be killed

	return NULL;

}

/* Mediates traffic destined to the server end */

void * eb_fast_io_handler_to_server (void * fc)
{

	struct __eb_fast_client		*me;

	me = (struct __eb_fast_client *) fc;

#ifndef FAST_TEST
	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to server starting", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
#else
	eb_debug (0, 4, "FAST", "FAST IO thread to server exiting");
#endif

	/* Sleep on the condition and, when woken, process data in the buffers as necessary. For test purposes, to_network gets written to stdout */

	pthread_mutex_lock(&(me->fast_io_mutex[EB_FAST_TO_SERVER]));

	while (1)
	{
		int l;
		struct timespec t, t2;

		/* Wait for something to do */

		clock_gettime(CLOCK_REALTIME, &t);
		memcpy(&t2, &t, sizeof(struct timespec));

		t.tv_nsec += 1000000 * EB_FAST_OUTPUTWAIT; // 100ms
		/* Skip this. We might get a short timeout but so what 
		if (t2.tv_nsec < t.tv_nsec)
			t.tv_sec++;
			*/

		if (me->pt_len[EB_FAST_TO_SERVER] == 0) /* Snooze off, otherwise, send more */
			pthread_cond_timedwait (&(me->fast_wake[EB_FAST_TO_SERVER]), &(me->fast_io_mutex[EB_FAST_TO_SERVER]), &t);

		if (me->fast_exit)
			break; /* Get out */

		eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread (to server) woken", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);

		/* Have we had the disconnect signal? */

		if (me->fast_client_disconnected) /* Exit loop and clean up - but we might just get the bridge to kill the server thread which will cause an exit and cleaup */
		{
			me->fast_exit = 1;
			break;
		}

		/* Process stuff going to server */

		if (me->pt_len[EB_FAST_TO_SERVER] > 0)
		{
			l = write (me->fc_socket[EB_FAST_TO_SERVER][1], me->pending[EB_FAST_TO_SERVER], me->pt_len[EB_FAST_TO_SERVER]);
	
			if (l > 0)
			{
				eb_debug (0, 4, "FAST", "FAST IO thread wrote %d byte(s) to the server", l);
		
				if (me->pt_sz[EB_FAST_TO_SERVER] > EB_FAST_BUFSIZE)
				{
					me->pending[EB_FAST_TO_SERVER] = realloc(me->pending[EB_FAST_TO_SERVER], EB_FAST_BUFSIZE);
					me->pt_sz[EB_FAST_TO_SERVER] = EB_FAST_BUFSIZE;
					eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread shrunk to_server buffer to EB_FAST_BUFSIZE", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);
				}
		
				me->pt_len[EB_FAST_TO_SERVER] = 0; /* Empty buffer - assumes we wrote everything we asked to - need to sort */

				eb_fast_send_control (fc, EB_FAST_OP_DATARQ); /* Please, Sir, can I have some more? */
			}
		}


		/* Snooze off again */

		eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to server dozing off", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);

	}

	eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST IO thread to server exiting (detected hangup)", eb_type_str(me->parent->type), me->parent->net, me->parent->local.stn, me->net, me->stn);

	pthread_mutex_unlock(&(me->fast_io_mutex[EB_FAST_TO_SERVER]));
	
	while (1)
		sleep(60); // Sleep and wait to be killed

	return NULL;

}

/* When a login request happens, the HPB spawns a thread running this. */

void * eb_fast_start_fast_service (void *data)
{

	struct __eb_fast_client *fc = (struct __eb_fast_client *) data;
	uint8_t net, stn;

	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread starting", 
			eb_type_str(fc->parent->type),
			fc->parent->net,
			fc->parent->local.stn,
			fc->net, fc->stn);

	/* Send the startup control */

	eb_fast_send_control (fc, EB_FAST_OP_WELCOME);
	
	/* Spawn the IO threads */

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

	/* Spawn a server thread */

	if (pthread_create(&(fc->fast_server), NULL, eb_fast_server_thread, fc))
	{
		eb_debug (0, 1, "FAST", "Fast server thread failed to start");
		exit (1);
	}

	eb_debug (0, 3, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread started", 
			eb_type_str(fc->parent->type),
			fc->parent->net,
			fc->parent->local.stn,
			fc->net, fc->stn);

	/* The fast_server thread will return when an IO thread loses a connection, or the server exits */

	pthread_join(fc->fast_server, NULL);

	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread detected end of server thread", 
		eb_type_str(fc->parent->type),
		fc->parent->net,
		fc->parent->local.stn,
		fc->net, fc->stn
		);

	fc->fast_exit = 1;

	/* Kill any child we might have */

	pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]));
	if (fc->fast_child)
	{
		kill(fc->fast_child, SIGKILL);
		eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread killed off child pid %d", 
			eb_type_str(fc->parent->type),
			fc->parent->net,
			fc->parent->local.stn,
			fc->net, fc->stn,
			fc->fast_child);
	}
	pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_NETWORK]));
	
	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread detected waiting for join of IO handler to network", 
		eb_type_str(fc->parent->type),
		fc->parent->net,
		fc->parent->local.stn,
		fc->net, fc->stn
		);

	/* Wait for IO threads to exit */

	pthread_cancel(fc->fast_io_handler[EB_FAST_TO_NETWORK]);
	pthread_join(fc->fast_io_handler[EB_FAST_TO_NETWORK], NULL);

	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread detected join of IO handler to network", 
		eb_type_str(fc->parent->type),
		fc->parent->net,
		fc->parent->local.stn,
		fc->net, fc->stn
		);


	pthread_cancel(fc->fast_io_handler[EB_FAST_TO_SERVER]);
	pthread_join(fc->fast_io_handler[EB_FAST_TO_SERVER], NULL);

	eb_debug (0, 4, "FAST", "%-8s %3d.%3d from %3d.%3d FAST service thread detected join of IO handler to server", 
		eb_type_str(fc->parent->type),
		fc->parent->net,
		fc->parent->local.stn,
		fc->net, fc->stn
		);

	/* Clean up */

	net = fc->net;
	stn = fc->stn;

	eb_fast_client_cleanup(fc);

	eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d FAST connection ended", 
		eb_type_str(fc->parent->type),
		fc->parent->net,
		fc->parent->local.stn,
		net, stn
		);

	return NULL;
}


/* Process received data on port &A0 */

void eb_port_a0_handler (struct __econet_packet_aun *p, uint16_t length, void *d)
{
	struct __eb_device * device = (struct __eb_device *) d, * source;
	struct __econet_packet_aun *ack;

	struct __eb_fast_client * fc;

	uint16_t	data_length = length - 12;

	source = eb_find_station(1, p);

	if (!source) /* We can't talk to whatever it is */
		return;

	ack = eb_malloc (__FILE__, __LINE__, "FAST", "Allocate ACK packet for *FAST data", 12);

	ack->p.srcstn = p->p.dststn;
	ack->p.srcnet = p->p.dstnet;
	ack->p.dststn = p->p.srcstn;
	ack->p.dstnet = p->p.srcnet;
	ack->p.seq = p->p.seq;
	ack->p.aun_ttype = ECONET_AUN_ACK;
	ack->p.port = p->p.port;
	ack->p.ctrl = p->p.ctrl;

	if (device->type != EB_DEF_LOCAL || !device->local.fast_menu)
	{
		/* Either not a local device, or it is but there's no menu defined */
		return; /* Ignore! */
	}

	if (p->p.aun_ttype != ECONET_AUN_DATA && p->p.aun_ttype != ECONET_AUN_NAK) /* Dump everything else */
		return;

	/* Potential connection, so find the client */

	pthread_mutex_lock(&(device->local.fast_client_list_lock));
	fc = device->local.fast_client_list;
	while (fc)
	{
		if (fc->net == p->p.srcnet && fc->stn == p->p.srcstn)
			break;
		fc = fc->next;
	}
	pthread_mutex_unlock(&(device->local.fast_client_list_lock));
	
	if (p->p.aun_ttype == ECONET_AUN_NAK) /* NAK */
	{
		if (fc) /* Existing client - dump it */
			pthread_cancel(fc->fast_server);
		return; /* And ignore NAKs generally */
	}

	if (!fc) /* Not found */
	{
		if (p->p.aun_ttype != ECONET_AUN_ACK && p->p.aun_ttype != ECONET_AUN_NAK)
			eb_debug (0, 1, "FAST", "%-8s %3d.%3d from %3d.%3d Unexpected *FAST data traffic",
				eb_type_str(device->type),
				device->net, device->local.stn,
				p->p.srcnet, p->p.srcstn);

		ack->p.aun_ttype = ECONET_AUN_NAK;	
		eb_enqueue_output(source, ack, 0, NULL);
		eb_free (__FILE__, __LINE__, "FAST", "Free *FAST ACK/NAK packet", ack);
		return;
	}

	/* Send ACK */

	eb_enqueue_output(source, ack, 0, NULL);
	eb_free (__FILE__, __LINE__, "FAST", "Free *FAST ACK/NAK packet", ack);

	pthread_mutex_lock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));

	if ((p->p.ctrl & 0x01) != fc->fast_input_ctrl)
	{
		eb_debug (0, 2, "FAST", "%-8s %3d.%3d from %3d.%3d *FAST handler ignored traffic with duplicate control", eb_type_str(fc->parent->type), device->net, device->local.stn, fc->net, fc->stn);
		pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));
		return;
	}

	fc->fast_input_ctrl ^= 0x01; /* Toggle bit */

	if ((fc->pt_len[EB_FAST_TO_SERVER] + data_length) > fc->pt_sz[EB_FAST_TO_SERVER]) /* Buffer full */
	{
		fc->pending[EB_FAST_TO_SERVER] = realloc(fc->pending[EB_FAST_TO_SERVER], fc->pt_sz[EB_FAST_TO_SERVER] + EB_FAST_BUFSIZE); /* Expand by 1k */
		fc->pt_sz[EB_FAST_TO_SERVER] += EB_FAST_BUFSIZE;
	}

	memcpy (&(fc->pending[EB_FAST_TO_SERVER][fc->pt_len[EB_FAST_TO_SERVER]]), p->p.data, data_length);

	fc->pt_len[EB_FAST_TO_SERVER] += data_length;

	eb_debug (0, 4, "FAST", "FAST added %d characters to pending(server) buffer, size now %d, occupancy now %d", length, fc->pt_sz[EB_FAST_TO_SERVER], fc->pt_len[EB_FAST_TO_SERVER]);

	pthread_mutex_unlock(&(fc->fast_io_mutex[EB_FAST_TO_SERVER]));

	eb_fast_send_control(fc, EB_FAST_OP_DATARQ); /* Ask client for more data */

	//EB_FAST_WAKE_SERVER(fc); /* Wake up the IO thread */
	pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_NETWORK]));
	pthread_cond_signal(&(fc->fast_wake[EB_FAST_TO_SERVER]));
}

