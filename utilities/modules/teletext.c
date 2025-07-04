/*
  (c) 2025 Chris Royle
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

#include "econet-hpbridge.h"

#define EB_TELETEXT_CTRL_VERS		0x80
#define EB_TELETEXT_CTRL_PAGEREQ	0x81
#define EB_TELETEXT_CTRL_CANCEL_PAGEREQ	0x82
#define EB_TELETEXT_CTRL_MAXUSERS	0x83 /* Per channel */
#define EB_TELETEXT_CTRL_DATETIME	0x84
#define EB_TELETEXT_CTRL_LOGOFF		0x85
#define EB_TELETEXT_CTRL_DELAY_PAGEREQ	0x86
#define EB_TELETEXT_CTRL_PORTVAL_REQ	0x87

#define EB_TELETEXT_ERR_BADPAGE		0x01
#define EB_TELETEXT_ERR_BADCHANNEL	0x02
#define EB_TELETEXT_ERR_CHANBUSY	0x03
#define EB_TELETEXT_ERR_TIMEUNAV	0x04
#define EB_TELETEXT_ERR_BADPORT		0x05

/* Teletext server module.
 *
 * Root directory contains one directory per channel (e.g. "1", "2", ...)
 *
 * Within those directories, there are files containing the
 * teletext pages for the relevant channel. They are named
 * e.g. 100, 101, 102. For the time being we do not support
 * sub-pages.
 */

void eb_port_teletext_handler (struct __econet_packet_aun *, uint16_t, void *);

/* Teletext thread */

void * eb_teletext_server (void *i)
{
	struct __eb_device *d = (struct __eb_device *) i;
	struct timespec when;

	if (pthread_mutex_init(&(d->local.teletext_queue_mutex), NULL) != 0)
		eb_debug (1, 0, "DESPATCH", "Teletext %3d.%3d Failed to initialize queue mutex", d->net, d->local.stn);

	if (pthread_cond_init(&(d->local.teletext_queue_cond), NULL) != 0)
		eb_debug (1, 0, "DESPATCH", "Teletext %3d.%3d Failed to initialize queue condition", d->net, d->local.stn);

	EB_PORT_SET(d, ports, EB_PORT_TELETEXT_S_CMD, eb_port_teletext_handler, d);

	pthread_mutex_lock (&(d->local.teletext_queue_mutex));

	while (1)
	{
		clock_gettime(CLOCK_REALTIME, &when);
		when.tv_sec++;

		pthread_cond_timedwait (&(d->local.teletext_queue_cond),
				&(d->local.teletext_queue_mutex), &when);

		/* Broadcast next page */

		/* Process queue */

	}

	return NULL;

}

/* teletext_init - starts up the server thread */

void teletext_init (struct __eb_device *d)
{

	if (d->local.teletext_active == 1)
	{
		eb_debug (1, 0, "DESPATCH", "Teletext %3d.%3d Attempt to start teletext server when already active", d->net, d->local.stn);
		return;
	}

	if (pthread_create(&(d->local.teletext_thread), NULL, eb_teletext_server, d) != 0)
		eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Thread creation for teletext server failed", d->net, d->local.stn);

	pthread_detach(d->local.teletext_thread);

	d->local.teletext_active = 1;

}

/* teletext_shutdown - stop the server thread */

void teletext_shutdown (struct __eb_device *d)
{
	if (d->local.teletext_active == 0)
	{
		eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Attempt to stop teletext server when not active", d->net, d->local.stn);
		return;
	}

	d->local.teletext_active = 0;
	pthread_cancel(d->local.teletext_thread);
}

/* Data handler thread */

void eb_port_teletext_handler (struct __econet_packet_aun *p, uint16_t length, void *i)
{

	struct __eb_device *d = (struct __eb_device *) i;

	pthread_mutex_lock (&(d->local.teletext_queue_mutex));

	switch (p->p.ctrl)
	{

		case EB_TELETEXT_CTRL_VERS:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Request server version", d->net, d->local.stn);
			} break;
		case EB_TELETEXT_CTRL_DELAY_PAGEREQ: /* Fall through */
		case EB_TELETEXT_CTRL_PAGEREQ:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Request page XXX%s", d->net, d->local.stn, (p->p.ctrl == EB_TELETEXT_CTRL_DELAY_PAGEREQ ? " (delayed)" : ""));
			} break;
		case EB_TELETEXT_CTRL_CANCEL_PAGEREQ:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Cancel page request", d->net, d->local.stn);
			} break;
		case EB_TELETEXT_CTRL_MAXUSERS:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Request max users", d->net, d->local.stn);
			} break;
		case EB_TELETEXT_CTRL_DATETIME:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Request date and time", d->net, d->local.stn);
			} break;
		case EB_TELETEXT_CTRL_LOGOFF:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Station logoff", d->net, d->local.stn);
			} break;
		case EB_TELETEXT_CTRL_PORTVAL_REQ:
			{
				eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Port value request", d->net, d->local.stn);
			} break;
		default:
			eb_debug (0, 1, "DESPATCH", "Teletext %3d.%3d Unknown request code %02X", d->net, d->local.stn, p->p.ctrl);
			break;
	}

	pthread_mutex_unlock (&(d->local.teletext_queue_mutex));

}

