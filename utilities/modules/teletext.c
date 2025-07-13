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

	eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanning %s", d->net, d->local.stn, d->local.teletext_root);

	/* First, set the broadcast flags */

	memset (&(d->local.teletext_broadcast), 0xFF, 320 * sizeof(uint32_t));

	/* Now the counters */

	memset (&(d->local.teletext_channel_entries), 0, 10 * sizeof(uint16_t));

	d->local.teletext_channel_startbit[0] = 0;

	for (channel = 0; channel < 9; channel++)
	{
		DIR 	*directory;

		snprintf (filename, 1023, "%s/%c", d->local.teletext_root, (char) (channel + '1'));

		eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanning channel %c directory %s", d->net, d->local.stn, channel + '1', filename);

		directory = opendir(filename);

		/* Init */

		d->local.teletext_channels[channel] = NULL;
		d->local.teletext_channel_entries[channel] = 0;

		if (directory) /* Exists */
		{
			closedir(directory);
			d->local.teletext_channel_entries[channel] = scandir (filename,
										&(d->local.teletext_channels[channel]),
										eb_teletext_pagename_filter,
										alphasort);
			eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanning channel %c directory %s - found %d entries", d->net, d->local.stn, channel + '1', filename, d->local.teletext_channel_entries[channel]);
		}

		if (d->local.teletext_channel_entries[channel] == -1)
			d->local.teletext_channel_entries[channel] = 0;

		if (channel > 0)
			d->local.teletext_channel_startbit[channel] = d->local.teletext_channel_topbit[channel-1] + d->local.teletext_channel_entries[channel];
		else
			d->local.teletext_channel_startbit[0] = 0;

		d->local.teletext_channel_topbit[channel] = d->local.teletext_channel_startbit[channel] + d->local.teletext_channel_entries[channel]; /* So if topbit[channel] == startbit[channel] then there are 0 entries for this channel */

		eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Scanned channel %c directory %s - found %d entries, first bit %d, last bit %d", d->net, d->local.stn, channel + '1', filename, d->local.teletext_channel_entries[channel],
				d->local.teletext_channel_startbit[channel],
				d->local.teletext_channel_topbit[channel]);

		total_pages += d->local.teletext_channel_entries[channel];
	}
	
	/* Clear the broadcast flags for the number of pages we have */

	if (total_pages > 0)
	{
		uint16_t 	whole_words = (total_pages / 32);

		if (whole_words > 0)
			memset (&(d->local.teletext_broadcast[0]), 0, whole_words * 4);

		if ((total_pages % 32) > 0)
		{
			uint64_t		bits;

			/* Then set the  rest of the bits */

			bits = (1 << (total_pages % 32)) - 1;

			bits = ~bits; /* Invert */

			d->local.teletext_broadcast[whole_words] = (bits & 0xFFFFFFFF);
		 }

	}

	eb_debug (0, 3, "TELETEXT", "Local    %3d.%3d Rescanned %s - total pages found %d", d->net, d->local.stn, d->local.teletext_root, total_pages);

	return total_pages;
}

/* Teletext thread */

void * eb_teletext_server (void *i)
{
	struct __eb_device 		*d = (struct __eb_device *) i;
	struct timespec 		when;
	struct	__econet_packet_aun 	*p;
	struct dirent			*directory_pointer;
	struct __eb_teletext_queue	*q, *qprev;

	uint16_t	total_pages, search_count;
	uint8_t		channel;
	uint16_t	page;

	eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server starting", d->net, d->local.stn);

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

	if (pthread_mutex_init(&(d->local.teletext_queue_mutex), NULL) != 0)
		eb_debug (1, 0, "TELETEXT", "Local    %3d.%3d Failed to initialize queue mutex", d->net, d->local.stn);

	if (pthread_cond_init(&(d->local.teletext_queue_cond), NULL) != 0)
		eb_debug (1, 0, "TELETEXT", "Local    %3d.%3d Failed to initialize queue condition", d->net, d->local.stn);

	EB_PORT_SET(d, ports, EB_PORT_TELETEXT_S_CMD, eb_port_teletext_handler, d);

	pthread_mutex_lock (&(d->local.teletext_queue_mutex));

	total_pages = eb_teletext_rescan (d);

	while (1)
	{
		uint16_t	next_page;

		clock_gettime(CLOCK_REALTIME, &when);
		when.tv_sec++;

		pthread_cond_timedwait (&(d->local.teletext_queue_cond),
				&(d->local.teletext_queue_mutex), &when);

		/* Re-scan if appropriate - use next_page temporarily */

		for (next_page = 0 ; next_page < 320 ; next_page++)
		{
			//fprintf (stderr, "\nteletext_broadcast[%d] = 0x%08X\n", next_page, d->local.teletext_broadcast[next_page]);

			if (d->local.teletext_broadcast[next_page] != 0xFFFFFFFF) /* Not all broadcast, or unuused */
				break;
		}

		if (next_page >= 320) /* Rescan - everything has been broadcast */
		{
			/* Free up the lists */

			for (uint8_t c = 0; c < 10; c++)
			{
				uint16_t entries = d->local.teletext_channel_entries[c];

				while (entries--)
					free(d->local.teletext_channels[c][entries]);
				free(d->local.teletext_channels[c]);
			}

			total_pages = eb_teletext_rescan (d);
		}

		if (total_pages > 0)
		{
			uint16_t	word_bit;
			uint32_t	bit_bit;

			/* Broadcast next page */
	
			next_page = random() % d->local.teletext_channel_topbit[8]; /* topbit[9] will contain the last bit number */
	
			/* See if that page has already been broadcast and, if so, pick the next one */
	
			search_count = 0;
	
			while (search_count < total_pages)
			{
				if ((d->local.teletext_broadcast[next_page / 32] & (1 << (next_page % 32))) == 0x00)
					break;
	
				search_count++;
				next_page++;
				if (next_page >= total_pages)
					next_page = 0;
			}
	
			/* By here, next_page is in the rante 0 .. total_pages - 1 */
	
			channel = 0;
	
			while (d->local.teletext_channel_topbit[channel] < next_page)
				channel++;
	
			page = d->local.teletext_channel_startbit[channel] + (next_page - (channel == 0 ? 0 : d->local.teletext_channel_topbit[channel-1]));
	
			directory_pointer = d->local.teletext_channels[channel][page];
	
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
	
			if (d->local.teletext_hdr_broadcast)
				eb_broadcast_handler(d, p, 4);
	
			/* Flag that page as having been broadcast */

			word_bit = next_page / 32;

			bit_bit = (1 << (next_page % 32));

			d->local.teletext_broadcast[word_bit] |= bit_bit;

			/* Process queue */

			q = d->local.teletext_queue;
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
						d->local.teletext_root,
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

			d->local.teletext_queue = NULL;
		}

	}

	return NULL;

}

/* teletext_init - starts up the server thread */

void teletext_init (struct __eb_device *d)
{

	if (d->local.teletext_active == 1)
	{
		eb_debug (1, 0, "TELETEXT", "Local    %3d.%3d Attempt to start teletext server when already active", d->net, d->local.stn);
		return;
	}

	if (pthread_create(&(d->local.teletext_thread), NULL, eb_teletext_server, d) != 0)
		eb_debug (1, 0, "TELETEXT", "Local    %3d.%3d Thread creation for teletext server failed", d->net, d->local.stn);

	pthread_detach(d->local.teletext_thread);

	d->local.teletext_active = 1;

	eb_debug (0, 2, "TELETEXT", "Local    %3d.%3d Server initializing", d->net, d->local.stn);
}

/* teletext_shutdown - stop the server thread */

void teletext_shutdown (struct __eb_device *d)
{
	if (d->local.teletext_active == 0)
	{
		eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Attempt to stop teletext server when not active", d->net, d->local.stn);
		return;
	}

	d->local.teletext_active = 0;
	pthread_cancel(d->local.teletext_thread);

	eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Server shutting down", d->net, d->local.stn);

	for (uint8_t c = 0; c < 10; c++)
	{
		uint16_t entries = d->local.teletext_channel_entries[c];

		while (entries--)
			free(d->local.teletext_channels[c][entries]);
		free(d->local.teletext_channels[c]);
	}
}

/* 
 * Check if a given page on a given channel exists.
 *
 * Return 0 if not, 1 if so.
 *
 * Note that *page has 3 bytes and will not be null terminated 
 */

uint8_t	eb_teletext_page_exists (struct __eb_device *d, uint8_t channel, char *page)
{

	unsigned char	pathname[1024];

	snprintf (pathname, 1023, "%s/%c/%c%c%c",
			d->local.teletext_root,
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

	struct __econet_packet_aun	*reply;

	//if (p->p.srcnet == 0)
		//p->p.srcnet = d->net;

	reply = eb_malloc(__FILE__, __LINE__, "TELETEXT", "Reply packet", 12 + 18); // Max data length given

	reply->p.srcstn = d->local.stn;
	reply->p.srcnet = d->net;
	reply->p.dststn = p->p.srcstn;
	reply->p.dstnet = p->p.srcnet;
	reply->p.port = EB_PORT_TELETEXT_S_REPLY;
	reply->p.aun_ttype = ECONET_AUN_DATA;
	reply->p.ctrl = p->p.ctrl; /* Always mirrors the request ctrl */
	/* pad & seq filled in by sender routing */

	pthread_mutex_lock (&(d->local.teletext_queue_mutex));

	switch (p->p.ctrl)
	{

		case EB_TELETEXT_CTRL_VERS:
			{
				unsigned char	verstring[64];

				eb_debug (0, 1, "TELETEXT", "Local    %3d.%3d Request server version", d->net, d->local.stn);
				snprintf (verstring, 63, "Pi Econet Bridge Teletext Server %d.%02d%c",
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

				if (!eb_teletext_page_exists(d, p->p.data[0], &p->p.data[1]))
				{
					reply->p.data[0] = EB_TELETEXT_ERR_BADPAGE;
					reply->p.data[1] = 0;
					sprintf (&(reply->p.data[2]), "Page not found%c", 0x0D);
					eb_raw_send (d, reply, 2 + 15);
					break;
				}

				/* See if we can find an existing request from this station, overwrite it if there is. */

				q = d->local.teletext_queue;

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
						d->local.teletext_queue = q;

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

				q = d->local.teletext_queue;

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
						d->local.teletext_queue = q->next;

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

	pthread_mutex_unlock (&(d->local.teletext_queue_mutex));

	if (p->p.ctrl == EB_TELETEXT_CTRL_DELAY_PAGEREQ || p->p.ctrl == EB_TELETEXT_CTRL_PAGEREQ) /* Wake up the main loop */
		pthread_cond_signal(&(d->local.teletext_queue_cond));

	eb_free(__FILE__, __LINE__, "TELETEXT", "Free reply packet", reply);

}

