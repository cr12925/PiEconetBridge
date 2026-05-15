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

/* Now converted to a module */

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

uint8_t teletext_exit(void *device, struct __eb_device_module *m);
uint8_t teletext_init (void *device, struct json_object *j);
uint8_t teletext_start(void *device, struct __eb_device_module *me);
uint8_t teletext_stop (void *device, struct __eb_device_module *module);

struct eb_teletext_private {
	char *	directory;
	uint8_t	header_broadcast;
	uint8_t running;
	uint16_t channel_entries[10]; /* Valid entries per channel in teletext_channels; signed because it stores the return val from scandir */
	struct dirent           **channels[10]; /* Files matching [1-9][0-9]{2} in each channel dir */
	int16_t                 channel_topbit[10]; /* Which bit number in teletext_broadcast is the last one for this channel */
	int16_t                 channel_startbit[10]; /* First bit number in teletext_broadcast which is part of this channel */
	uint32_t                channel_broadcast[320]; /* Bitfield of broadcast frames - see teletext.c in eb_teletext_server */
	struct __eb_teletext_queue	*queue; /* Queue of station requests */
};

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

/* Teletext filename filter  return non-zero if it's a page */

int eb_teletext_pagename_filter(const struct dirent *file)
{
	if (strlen(file->d_name) != 3)
		return 0;

	if (	(file->d_name[0] >= '1' && file->d_name[0] <= '9')
	&&	(file->d_name[1] >= '0' && file->d_name[1] <= '9')
	&&	(file->d_name[2] >= '0' && file->d_name[2] <= '9')
	)	return 1;

	return 0;
}

/* Teletext directory re-scan - Can only be called under mutex lock, and on the 
 * basis that the dirent struct has been free'd() if previously used
 * before this function is called.
 */

uint16_t eb_teletext_rescan (struct __eb_device *d)
{
	uint8_t		channel;
	char		filename[1024];
	uint32_t	total_pages = 0;
	struct __eb_device_module *m = eb_module_get_data(d, "TELETEXT");
	struct eb_teletext_private *tt = (struct eb_teletext_private *) m->module_ws;

	eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanning %s", d->net, d->local.stn, tt->directory);

	/* First, set the broadcast flags */

	memset (&(tt->channel_broadcast), 0xFF, 320 * sizeof(uint32_t));

	/* Now the counters */

	memset (&(tt->channel_entries), 0, 10 * sizeof(uint16_t));

	tt->channel_startbit[0] = 0;

	for (channel = 0; channel < 9; channel++)
	{
		DIR 	*directory;

		snprintf (filename, 1023, "%s/%c", tt->directory, (char) (channel + '1'));

		eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanning channel %c directory %s", d->net, d->local.stn, channel + '1', filename);

		directory = opendir(filename);

		/* Init */

		tt->channels[channel] = NULL;
		tt->channel_entries[channel] = 0;

		if (directory) /* Exists */
		{
			closedir(directory);
			tt->channel_entries[channel] = scandir (filename,
										&(tt->channels[channel]),
										eb_teletext_pagename_filter,
										alphasort);
			eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanning channel %c directory %s - found %d entries", d->net, d->local.stn, channel + '1', filename, tt->channel_entries[channel]);
		}

		if (tt->channel_entries[channel] == -1)
			tt->channel_entries[channel] = 0;

		if (channel > 0)
			tt->channel_startbit[channel] = tt->channel_topbit[channel-1] + tt->channel_entries[channel];
		else
			tt->channel_startbit[0] = 0;

		tt->channel_topbit[channel] = tt->channel_startbit[channel] + tt->channel_entries[channel]; /* So if topbit[channel] == startbit[channel] then there are 0 entries for this channel */

		eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Scanned channel %c directory %s - found %d entries, first bit %d, last bit %d", d->net, d->local.stn, channel + '1', filename, tt->channel_entries[channel],
				tt->channel_startbit[channel],
				tt->channel_topbit[channel]);

		total_pages += tt->channel_entries[channel];
	}
	
	/* Clear the broadcast flags for the number of pages we have */

	if (total_pages > 0)
	{
		uint16_t 	whole_words = (total_pages / 32);

		if (whole_words > 0)
			memset (&(tt->channel_broadcast[0]), 0, whole_words * 4);

		if ((total_pages % 32) > 0)
		{
			uint64_t		bits;

			/* Then set the  rest of the bits */

			bits = (1 << (total_pages % 32)) - 1;

			bits = ~bits; /* Invert */

			tt->channel_broadcast[whole_words] = (bits & 0xFFFFFFFF);
		 }

	}

	eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanned %s - total pages found %d", d->net, d->local.stn, tt->directory, total_pages);

	return total_pages;
}

/* Teletext thread */

void * eb_teletext_server (void *i)
{
	struct __eb_device 		*d = (struct __eb_device *) i;
	struct __eb_device_module	*m;
	struct timespec 		when;
	struct	__econet_packet_aun 	*p;
	struct dirent			*directory_pointer;
	struct __eb_teletext_queue	*q, *qprev;
	struct eb_teletext_private	*tt;

	uint16_t	total_pages, search_count;
	uint8_t		channel;
	uint16_t	page;

	eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server thread starting", d->net, d->local.stn);

	m = eb_module_get_data(d, "TELETEXT");

	if (!m)
		return NULL;

	tt = (struct eb_teletext_private *) m->module_ws;

	p = eb_malloc (__FILE__, __LINE__, "TELETEXT", "New teletext broadcast or frame packet", 12 + 1024); /* 12 header + 1024 max frame length */

	/* The number of pages per channel we find on disc are added up - say there are 2000(!). 
					  This bitfield has 1 bit per page. When we search the dir, all the bits for pages which
					  don't exist are set to 1. When we broadcast a page number, its bit is set to 1 too.
					  Thus when all the pages have been broadcast, this value will be &FFFF. At which point
					  we zero it, free all the channel file lists, and re-scan. 
					  
					  Thus, if channels[0] (which is channel 1 in reality) has 195 entries/pages, the 
					  filenames of which are in channels[0], the first 195 bits of this bitfield
					  will be initially 0 and set to 1 when the header has been broadcast.
					  
					  If there are, say 195 pages on channel 1, 205 on channel 2, then the first 400
					  bits of this bitfield are valid. Having counted the number of files in total,
					  the balance of the bits are then set to 1 at the start so the system can compare
					  with &FFFF x however many and detect that it has broadcast every page.

					  At that stage, it re-scans the directories.

					  As there are a maximum of 10 channels with 900 pages, that's 9000 pages maximum.
					  Round that up to 10240 bits, which is 320 x 32 bit values
					  */

	if (pthread_mutex_init(&(m->module_mutex), NULL) != 0)
		eb_debug (1, 0, "TELETEXT", "Local    %3d.%3d Failed to initialize queue mutex", d->net, d->local.stn);

	if (pthread_cond_init(&(m->module_cond), NULL) != 0)
		eb_debug (1, 0, "TELETEXT", "Local    %3d.%3d Failed to initialize queue condition", d->net, d->local.stn);

	EB_PORT_SET(d, ports, EB_PORT_TELETEXT_S_CMD, eb_port_teletext_handler, d);

	pthread_mutex_lock (&(m->module_mutex));

	total_pages = eb_teletext_rescan (d);

	while (!(m->module_exiting))
	{
		uint16_t	next_page;

		clock_gettime(CLOCK_REALTIME, &when);
		when.tv_sec++;

		pthread_cond_timedwait (&(m->module_cond),
				&(m->module_mutex), &when);

		if (m->module_exiting) /* Die if we are being asked to shut down */
			break;

		/* Re-scan if appropriate - use next_page temporarily */

		for (next_page = 0 ; next_page < 320 ; next_page++)
		{
			if (tt->channel_broadcast[next_page] != 0xFFFFFFFF) /* Not all broadcast, or unuused */
				break;
		}

		if (next_page >= 320) /* Rescan - everything has been broadcast */
		{
			/* Free up the lists */

			for (uint8_t c = 0; c < 10; c++)
			{
				uint16_t entries = tt->channel_entries[c];

				while (entries--)
					free(tt->channels[c][entries]);
				free(tt->channels[c]);
			}

			total_pages = eb_teletext_rescan (d);
		}

		if (total_pages > 0)
		{
			uint16_t	word_bit;
			uint32_t	bit_bit;

			/* Broadcast next page */
	
			next_page = random() % tt->channel_topbit[8]; /* topbit[9] will contain the last bit number */
	
			/* See if that page has already been broadcast and, if so, pick the next one */
	
			search_count = 0;
	
			while (search_count < total_pages)
			{
				if ((tt->channel_broadcast[next_page / 32] & (1 << (next_page % 32))) == 0x00)
					break;
	
				search_count++;
				next_page++;
				if (next_page >= total_pages)
					next_page = 0;
			}
	
			/* By here, next_page is in the rante 0 .. total_pages - 1 */
	
			channel = 0;
	
			while (tt->channel_topbit[channel] < next_page)
				channel++;
	
			page = tt->channel_startbit[channel] + (next_page - (channel == 0 ? 0 : tt->channel_topbit[channel-1]));
	
			directory_pointer = tt->channels[channel][page];
	
			// eb_debug (0, 2, "TELETEXT", "Local    %3d.%3d Broadcasting channel %c page %s (master index %d)", d->net, d->local.stn, channel + '1', directory_pointer->d_name, next_page);
	
			p->p.srcstn = d->local.stn;
			p->p.srcnet = d->net;
			p->p.dststn = 0xFF;
			p->p.dstnet = 0xFF;
			p->p.aun_ttype = ECONET_AUN_BCAST;
			p->p.port = EB_PORT_TELETEXT_HEADER;
			p->p.ctrl = 0x80;
			p->p.data[0] = channel + '1';
			memcpy (&(p->p.data[1]), directory_pointer->d_name, 3);
	
			if (tt->header_broadcast)
				eb_broadcast_handler(d, p, 4);
	
			/* Flag that page as having been broadcast */

			word_bit = next_page / 32;

			bit_bit = (1 << (next_page % 32));

			tt->channel_broadcast[word_bit] |= bit_bit;

			/* Process queue */

			q = tt->queue;
			qprev = NULL;

			while (q)
			{
				char	filename[1024];

				p->p.srcstn = d->local.stn;
				p->p.srcnet = d->net;
				p->p.dstnet = q->net;
				p->p.dststn = q->stn;
				p->p.aun_ttype = ECONET_AUN_DATA;
				p->p.port = EB_PORT_TELETEXT_DATA;
				p->p.ctrl = 0x80;

				snprintf (filename, 1023, "%s/%c/%s",
						tt->directory,
						q->channel,
						q->page);

				if (access(filename, R_OK) == 0)
				{
					int f;

					f = open(filename, O_RDONLY);
					read(f, &(p->p.data), 0x400);
					close(f);
					p->p.data[0x3FE] = p->p.data[0x3FF] = 0x00; /* Sub page number - not implemented for now */

					eb_raw_send (d, p, 0x400);

					eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Send channel %c page %s to %3d.%3d", d->net, d->local.stn, q->channel, q->page, q->net, q->stn);
				}

				if (qprev)
					eb_free (__FILE__, __LINE__, "TELETEXT", "Free queue entry", qprev);

				qprev = q->prev;
				q = q->next;

			}

			if (qprev)
				eb_free (__FILE__, __LINE__, "TELETEXT", "Free queue entry", qprev);

			tt->queue = NULL;
		}

	}

	m->module_has_exited = 1;

	pthread_mutex_unlock (&(m->module_mutex));

	return NULL;

}

/* teletext_init - starts up the server thread */

uint8_t teletext_init (void *device, struct json_object *j)
{

	struct __eb_device *d = (struct __eb_device *) device;
	struct __eb_device_module *me;
	struct eb_teletext_private *tt;
	char	root_directory[256];
	char	*root_ptr;
	uint8_t	header_broadcast = 1, autostart = 1;
	struct json_object *jo;

	eb_debug (0, 2, "TELETEXT", "Local    %3d.%3d Server initializing", d->net, d->local.stn);

	/* First check the JSON to see if it's valid, otherwise no point doing anything else */

	if (json_object_object_get_ex(j, "directory", &jo)) /* directory key */
	{
		strncpy (root_directory, json_object_get_string(jo), 255);
		root_ptr = eb_malloc(__FILE__, __LINE__, "TELETEXT", "Root directory storage", strlen(root_directory)+1);
		if (!root_ptr)
		{
			eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server failed to initialize - no directory provided in config", d->net, d->local.stn);
			return 1;
		}
		strcpy(root_ptr, root_directory);
	}
	else
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server failed to initialize - no directory provided in config", d->net, d->local.stn);
		return 1;
	}

	if (json_object_object_get_ex(j, "autostart", &jo))
	{
		if (json_object_get_boolean(jo))
			autostart = 1;
		else	autostart = 0;
	}

	if (json_object_object_get_ex(j, "header-broadcast", &jo))
	{
		if (json_object_get_boolean(jo))
			header_broadcast = 1;
		else	header_broadcast = 0;
	}
		
	me = eb_module_register(d, "TELETEXT", NULL, sizeof(struct eb_teletext_private));

	if (!me)
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server failed to initialize - module did not register", d->net, d->local.stn);
		return 1;
	}

	me->module_init = teletext_init;
	me->module_start = teletext_start;
	me->module_stop = teletext_stop;
	me->module_exit = teletext_exit;
	me->module_autostart = autostart;
	me->module_port = EB_PORT_TELETEXT_S_REPLY;
	me->module_queue = NULL; /* Empty packet queue */
	me->module_started = 0;
	
	tt = (struct eb_teletext_private *) me->module_ws;

	tt->running = 0;
	tt->header_broadcast = header_broadcast;
	tt->directory = root_ptr;
	
	/* Reserve our port */

	EB_PORT_SET(d, reserved_ports, EB_PORT_TELETEXT_S_CMD, NULL, NULL); /* Teletext commands from clients */

	return 0; /* Success */

}

/* 
 * Start the server if initialized 
 */

uint8_t teletext_start(void *device, struct __eb_device_module *me)
{

	struct eb_teletext_private *tt = (struct eb_teletext_private *) me->module_ws;
	struct __eb_device *d = (struct __eb_device *) device;

	me->module_has_exited = 0;

	if (tt->running)
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Unable to start teletext server - already running", d->net, d->local.stn);
		return 1;
	}

	if (pthread_create(&(me->module_thread), NULL, eb_teletext_server, d) != 0) /* non-zero is failure */
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Unable to start teletext server - thread creation failed", d->net, d->local.stn);
		return 1;
	}

	pthread_detach(me->module_thread);

	tt->running = 1;

	EB_PORT_SET(d, ports, EB_PORT_TELETEXT_S_CMD, eb_port_teletext_handler, d);

	eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server started", d->net, d->local.stn);

	return 0;

}

/* teletext_stop - stop the server thread */

uint8_t teletext_stop (void *device, struct __eb_device_module *module)
{
	struct __eb_device *d = (struct __eb_device *) device;
	struct eb_teletext_private *tt = (struct eb_teletext_private *) module->module_ws;

	if (tt->running == 0) /* Not running - can't stop */
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Attempt to stop teletext server when not active", d->net, d->local.stn);
		return 1;
	}

	eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server shutting down", d->net, d->local.stn);

	/* Can't be in critical section because _stop is called under lock */

	pthread_cancel(module->module_thread);

	/* Flag not running */

	tt->running = 0;

	for (uint8_t c = 0; c < 10; c++)
	{
		uint16_t entries = tt->channel_entries[c];

		while (entries--)
			free(tt->channels[c][entries]);
		free(tt->channels[c]);
	}

	EB_PORT_CLR(d, ports, EB_PORT_TELETEXT_S_CMD);

	return 0;
}

uint8_t teletext_exit(void *device, struct __eb_device_module *m)
{
	struct eb_teletext_private *tt = (struct eb_teletext_private *) m->module_ws;
	struct __eb_device *d = (struct __eb_device *) device;

	if (tt->running)
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server module exit called, but server is running", d->net, d->local.stn);
		return 1;
	}

	EB_PORT_CLR(d, reserved_ports, EB_PORT_TELETEXT_S_CMD);

	eb_module_deregister(d, m);

	eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server module exited", d->net, d->local.stn);

	return 0;
}

/* 
 * Check if a given page on a given channel exists.
 *
 * Return 0 if not, 1 if so.
 *
 * Note that *page has 3 bytes and will not be null terminated 
 */

uint8_t	eb_teletext_page_exists (struct __eb_device_module *m, uint8_t channel, char *page)
{

	struct eb_teletext_private *tt = (struct eb_teletext_private *) m->module_ws;

	unsigned char	pathname[1024];

	snprintf (pathname, 1023, "%s/%c/%c%c%c",
			tt->directory,
			channel,
			*(page),
			*(page+1),
			*(page+2));

	return !access(pathname, R_OK);
}

/* Data handler thread */

void eb_port_teletext_handler (struct __econet_packet_aun *p, uint16_t length, void *i)
{

	struct __eb_device *d = (struct __eb_device *) i;
	struct __eb_device_module *m = eb_module_get_data(d, "TELETEXT");
	struct eb_teletext_private *tt = (struct eb_teletext_private *) m->module_ws;

	struct __econet_packet_aun	*reply;

	if (!m) /* No module data! */
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Traffic handler called without module data present", d->net, d->local.stn);
		return;
	}

	reply = eb_malloc(__FILE__, __LINE__, "TELETEXT", "Reply packet", 12 + 18); // Max data length given

	reply->p.srcstn = d->local.stn;
	reply->p.srcnet = d->net;
	reply->p.dststn = p->p.srcstn;
	reply->p.dstnet = p->p.srcnet;
	reply->p.port = EB_PORT_TELETEXT_S_REPLY;
	reply->p.aun_ttype = ECONET_AUN_DATA;
	reply->p.ctrl = p->p.ctrl; /* Always mirrors the request ctrl */
	/* pad & seq filled in by sender routing */

	pthread_mutex_lock (&(m->module_mutex));

	switch (p->p.ctrl)
	{

		case EB_TELETEXT_CTRL_VERS:
			{
				unsigned char	verstring[64];

				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Request server version", d->net, d->local.stn);
				snprintf (verstring, 63, "Pi Econet HP Bridge Teletext Server %d.%02d%c",
						(EB_VERSION & 0xf0) >> 4,
						EB_VERSION & 0x0f,
						0x0D);
				reply->p.data[0] = 0x00;
				strcpy (&(reply->p.data[1]), verstring);
				eb_raw_send (d, reply, strlen(verstring)+1);
			} break;

		case EB_TELETEXT_CTRL_DELAY_PAGEREQ: /* Fall through */
		case EB_TELETEXT_CTRL_PAGEREQ:
			{
				struct __eb_teletext_queue 	*q, *prev;
				uint16_t			index = 0;
				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d from %3d.%3d Request Channel %c page %c%c%c%s", d->net, d->local.stn, p->p.srcnet, p->p.srcstn, 
						p->p.data[0],
						p->p.data[1],
						p->p.data[2],
						p->p.data[3],
						(p->p.ctrl == EB_TELETEXT_CTRL_DELAY_PAGEREQ ? " (delayed)" : ""));

				if (!eb_teletext_page_exists(m, p->p.data[0], &p->p.data[1]))
				{
					reply->p.data[0] = EB_TELETEXT_ERR_BADPAGE;
					reply->p.data[1] = 0;
					sprintf (&(reply->p.data[2]), "Page not found%c", 0x0D);
					eb_raw_send (d, reply, 2 + 15);
					break;
				}

				/* See if we can find an existing request from this station, overwrite it if there is. */

				q = tt->queue;

				prev = NULL;

				while (q)
				{
					index++;
					if (q->net == p->p.srcnet && q->stn == p->p.srcstn)
						break;
					prev = q;
					q = q->next;
				}

				if (!q) /* Not found */
				{
					q = eb_malloc(__FILE__, __LINE__, "TELETEXT", "New station request", sizeof(struct __eb_teletext_queue));
					q->next = NULL;
					q->prev = prev;

					if (prev)
						prev->next = q;
					else
						tt->queue = q;

					index++;
				}

				q->net = p->p.srcnet;
				q->stn = p->p.srcstn;
				q->channel = p->p.data[0];
				q->ctrl = p->p.ctrl;
				memcpy (q->page, &(p->p.data[1]), 3);

				reply->p.data[0] = 0x00;
				reply->p.data[1] = index & 0xff;

				eb_raw_send (d, reply, 2);

			} break;

		case EB_TELETEXT_CTRL_LOGOFF: /* Fall through - just delete request */
		case EB_TELETEXT_CTRL_CANCEL_PAGEREQ:
			{
				struct __eb_teletext_queue 	*q;

				q = tt->queue;

				while (q)
				{
					if (q->net == p->p.srcnet && q->stn == p->p.srcstn)
						break;

					q = q->next;
				}

				if (p->p.ctrl == EB_TELETEXT_CTRL_CANCEL_PAGEREQ)
					eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Cancel page request", d->net, d->local.stn);
				else
					eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Log off", d->net, d->local.stn);

				if (!q)
				{
					reply->p.data[0] = EB_TELETEXT_ERR_BADPAGE;
				}
				else
				{
					reply->p.data[0] = 0x00;

					if (q->prev) /* Not first in line */
						q->prev->next = q->next;
					else /* First in line */
						tt->queue = q->next;

					if (q->next) /* Not last in line - update next one */
						q->next->prev = q->prev;

					eb_free (__FILE__, __LINE__, "TELETEXT", "Free request struct", q);
				}

				reply->p.data[0] = 0;
				reply->p.data[1] = 0;

				eb_raw_send (d, reply, 2);

			} break;
		case EB_TELETEXT_CTRL_MAXUSERS:
			{
				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Request max users", d->net, d->local.stn);
				reply->p.data[0] = 0x00;
				reply->p.data[1] = 0xff; // 255 users per channel
				eb_raw_send (d, reply, 2);
			} break;

		case EB_TELETEXT_CTRL_DATETIME:
			{
				struct	tm	now;
				time_t		t;

				t = time(NULL);
				localtime_r (&t, &now);

				sprintf (&(p->p.data[1]), "%02d:%02d:%02d%02d/%02d/%04d",
						now.tm_hour,
						now.tm_min,
						now.tm_sec,
						now.tm_mday,
						now.tm_mon+1,
						now.tm_year+1900);

				p->p.data[0] = 0x00;

				eb_raw_send (d, reply, 19);

				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Request date and time", d->net, d->local.stn);
			} break;

		case EB_TELETEXT_CTRL_PORTVAL_REQ:
			{
				/* Don't know what this is supposed to do... */

				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Port value request", d->net, d->local.stn);

			} break;

		default:
			{
				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Unknown request code %02X", d->net, d->local.stn, p->p.ctrl);
			} break;

	}

	pthread_mutex_unlock (&(m->module_mutex));

	if (p->p.ctrl == EB_TELETEXT_CTRL_DELAY_PAGEREQ || p->p.ctrl == EB_TELETEXT_CTRL_PAGEREQ) /* Wake up the main loop */
		pthread_cond_signal(&(m->module_cond));

	eb_free(__FILE__, __LINE__, "TELETEXT", "Free reply packet", reply);

}

