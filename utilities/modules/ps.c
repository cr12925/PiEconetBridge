/*
  (c) 2024 Chris Royle
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

/* Print server module - separated out from main bridge code 20250610 
 * Unlike the FS module, this is relatively lightweight, so we don't
 * put it in its own thread.
 */

#include "econet-hpbridge.h"
#include "econet-pserv.h"
#include "econet-fs-hpbridge-common.h"
#include "fs.h"

/* eb_ps_send - put outbound traffic on dest device
 * input queue because if we put on output, we have 
 * no means from here of setting the new_output flag in the
 * despatcher, where this bulk of code originally came from.
 * This is a straight copy of the code in the FS - we
 * probably ought to streamline that.
 */

#define eb_ps_send	eb_raw_send

void send_printjob (char *handler, uint8_t fs_net, uint8_t fs_stn, uint8_t clt_net, uint8_t clt_stn, char *username, char *acorn_printer, char *unix_printer, char *file)
{

	char	command_string[1024];

	snprintf (command_string, 1023, "%s %d %d %d %d %s %s %s %s",
		handler == NULL ? PRN_DEFAULT_HANDLER : handler,
		fs_net, fs_stn,
		clt_net, clt_stn,
		username,
		unix_printer,
		acorn_printer,
		file);

	if (!fork())
		execl("/bin/sh", "sh", "-c", command_string, (char *) 0);

}

char * get_user_print_handler (uint8_t net, uint8_t stn, uint8_t printer_index, char *unixprinter, char *acornprinter)
{

	struct __eb_device	*d;
	struct __eb_printer	*printer;
	uint8_t			index;

	d = eb_find_station_internal (net, stn);

	if (!d)
		return NULL;

	if (d->type != EB_DEF_LOCAL)
		return NULL; // Not a local device

	printer = d->local.printers;

	index = printer_index;

	if (index != 0xff)
		while ((index-- > 0) && printer)
			printer = printer->next;	

	if (!printer)
		return NULL;
	else
	{
		strcpy(unixprinter, printer->unix_name);
		strcpy(acornprinter, printer->acorn_name);
		if (printer->handler[0] == '\0')
			return PRN_DEFAULT_HANDLER;
		else
			return printer->handler;
	}

}

void eb_handle_ps_traffic (struct __econet_packet_aun *p, uint16_t length, void *param)
{
	struct __eb_device *d = (struct __eb_device *) param;
	
	if (p->p.aun_ttype == ECONET_AUN_DATA)
		eb_send_ack (d, p, ECONET_AUN_ACK);

	if (p->p.aun_ttype != ECONET_AUN_DATA && p->p.aun_ttype != ECONET_AUN_BCAST) /* Unwanted - dump */
		return;

	/* Handle traffic */

	if (p->p.port == EB_PORT_PS_QUERY) /* Can be either DATA or BCAST by this point, and we don't care - this is a PS query */
	{
		uint8_t		querytype;
		unsigned char	pname[7];
		uint8_t		count, found;
		struct __econet_packet_aun	*reply;
		struct __eb_printer *printer;
			
		reply = eb_malloc (__FILE__, __LINE__, "PRINTER", "Allocate status query reply packet", 18);

		if (!reply)
			eb_debug (1, 0, "PRINTER", "Unable to malloc() new printer status reply packet");

		querytype = p->p.data[6]; // See #defines for the types

		for (count = 0; count < 6; count++) // Copy printer name
			pname[count] = p->p.data[count];

		pname[6] = '\0'; // NULL terminate

		eb_debug (0, 2, "PRINTER", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s", 
			d->net, d->local.stn,
			p->p.srcnet, p->p.srcstn,	
			(querytype == PRN_QUERY_STATUS) ? "status" : "name",
			pname);

		reply->p.srcnet = d->net;
		reply->p.srcstn = d->local.stn;
		reply->p.dstnet = p->p.srcnet;
		reply->p.dststn = p->p.srcstn;
		reply->p.aun_ttype = ECONET_AUN_DATA;
		reply->p.port = EB_PORT_PS;
		reply->p.ctrl = 0x80;
		reply->p.seq = eb_get_local_seq(d);
		reply->p.data[0] = reply->p.data[1] = reply->p.data[2] = 0;

		if (reply->p.dstnet == 0)
			reply->p.dstnet = d->net;

		if (querytype == PRN_QUERY_STATUS)
		{
			found = 0;

			printer = d->local.printers;

			while (printer && !found)
			{
				if (!strcasecmp(printer->acorn_name, (char *) pname) || !strcasecmp("PRINT ", (char *) pname))
					found = 1;
				else printer = printer->next;
			}

			if (found) 
			{
				eb_debug (0, 3, "PRINTER", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s - found at %p", 
					d->net, d->local.stn,
					p->p.srcnet, p->p.srcstn,	
					(querytype == PRN_QUERY_STATUS) ? "status" : "name",
					pname, printer);

				eb_ps_send (d, reply, 3);
			}
			else eb_debug (0, 2, "PRINTER", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s NOT FOUND",
                               	d->net, d->local.stn,
                              	p->p.srcnet, p->p.srcstn,
                              	(querytype == PRN_QUERY_STATUS) ? "status" : "name",
                              	pname);

		}
		else if (querytype == PRN_QUERY_NAME)
		{
			printer = d->local.printers;

			while (printer)
			{
				snprintf ((char * restrict) &(reply->p.data[0]), 7, "%6s", printer->acorn_name);
				eb_ps_send (d, reply, 6);
				printer = printer->next;
				reply->p.seq = eb_get_local_seq(d);
			}

		}

		eb_free (__FILE__, __LINE__, "PRINTER", "Freeing printer reply packet", reply);
	}

	else if (p->p.aun_ttype == ECONET_AUN_BCAST) /* No more broadcasts acceptable after here */
		return;
							
	else if (p->p.port == EB_PORT_PS_DATA) // Print server data
	{
		struct __eb_printjob	*job;
		struct __eb_printer	*printer;
		uint8_t 		found;

		printer = d->local.printers;
		found = 0;

		job = NULL;

		// First, see if this is an extant print job

		// ctrl = 0xfe/ff means new print job

		while (((p->p.ctrl & 0xfe) != 0x82) && !found && printer)
		{
			uint8_t		jobfound;

			jobfound = 0;
			job = printer->printjobs;

			while (!jobfound && job)
			{
				if (job->net == p->p.srcnet && job->stn == p->p.srcstn)
					jobfound = found = 1;
				else job = job->next;
			}

			if (!jobfound)
				printer = printer->next;
				
		}
			
		if (!job) // No job found - create a new one
		{
			char		template[128];
			int		spooldescriptor;

			strncpy (template, PRN_SPOOL_TEMPLATE, 126);

			spooldescriptor = mkstemp(template);

			if (spooldescriptor == -1)
				eb_debug (0, 1, "PRINTER", "Local    %3d.%3d Unable to make temporary print spool file for new job", d->net, d->local.stn);
			else
			{
				int8_t		printerindex;
				char *		space;
				struct __fs_active	*a;

				job = eb_malloc (__FILE__, __LINE__, "PRINTER", "Create new printjob", sizeof (struct __eb_printjob));

				if (!job)
					eb_debug (1, 0, "PRINTER", "Local    %3d.%3d Unable to malloc() for new printjob", d->net, d->local.stn);

				job->spoolfile = fdopen(spooldescriptor, "w");

				if (!job->spoolfile) // fdopen failed
					eb_debug (1, 0, "PRINTER", "Local    %3d.%3d Unable to obtain stream for new printjob (%s)", d->net, d->local.stn, strerror(errno));

				strncpy (job->spoolfilename, template, 126);

				job->net = p->p.srcnet;
				job->stn = p->p.srcstn;
				job->ctrlbit = (p->p.ctrl & 0x01) ^ 0x01; // Stores what we're expecting next time round

				printerindex = 0xff;

				if (fsop_is_enabled(d->local.fs.server) && (a = fsop_stn_logged_in_lock(d->local.fs.server, (job->net == d->net ? 0 : job->net), job->stn))) // Is fileserver
				{
					fsop_get_username_lock(a, job->username);
					printerindex = fsop_get_user_printer(a);
				}
				else	
					strcpy(job->username, "ANONYMOUS");
				
				if ((space = strchr(job->username, ' ')))
					*space = '\0';

				printer = d->local.printers;

				if (printerindex != 0xff)
					while ((printerindex-- > 0) && printer)
						printer = printer->next;	

				if (printer) // Splice this job in
				{
					job->next = printer->printjobs;
					if (job->next) job->next->parent = job;
						printer->printjobs = job;
					job->parent = NULL; // On head of queue
				}

			}
		}
	
		if (job && printer) // Only do this if there's a viable print job
		{
			struct __econet_packet_aun	*reply;

			reply = eb_malloc (__FILE__, __LINE__, "PRINTER", "Malloc() reply packet for spool data", 13);

			if (!reply)
				eb_debug (1, 0, "PRINTER", "Local    %3d.%3d Cannot malloc() print data reply packet", d->net, d->local.stn);

			reply->p.srcnet = d->net;
			reply->p.srcstn = d->local.stn;
			reply->p.dstnet = p->p.srcnet;
			reply->p.dststn = p->p.srcstn;
			reply->p.aun_ttype = ECONET_AUN_DATA;
			reply->p.port = EB_PORT_PS_DATA;
			reply->p.ctrl = p->p.ctrl;
			reply->p.seq = eb_get_local_seq(d);

			if (reply->p.dstnet == 0)
				reply->p.dstnet = d->net;

			reply->p.data[0] = p->p.data[0];

			if ((p->p.ctrl & 0x01) == job->ctrlbit)
			{

				job->ctrlbit ^= 0x01;

				fwrite (&(p->p.data), length - 12 - (((p->p.ctrl & 0xfe) == 0x86) ? 1 : 0), 1, job->spoolfile); // Last byte on last packet is always garbage apparently

				if ((p->p.ctrl & 0xfe) == 0x86) // Final packet, despatch to handler and close the printjob
				{

					char 	handler[128];

					if (printer->handler[0] == -'\0')
						strncpy (handler, PRN_DEFAULT_HANDLER, 126);
					else	strncpy (handler, printer->handler, 126);

					fclose (job->spoolfile);
	
					send_printjob (handler, reply->p.srcnet, reply->p.srcstn, 
						reply->p.dstnet, reply->p.dststn,
						job->username,
						printer->acorn_name,
						printer->unix_name,
						job->spoolfilename);

					eb_debug (0, 1, "PRINTER", "Local    %3d.%3d %s at %d.%d sent print job to printer %s/%s (%s)", reply->p.srcnet, reply->p.srcstn, job->username, reply->p.dstnet, reply->p.dststn, printer->acorn_name, printer->unix_name, job->spoolfilename);

					// Tidy up the structs
	
					if (job->parent)
					{
						job->parent->next = job->next;
						if (job->next)
							job->next->parent = job->parent;
					}
					else	
					{
						printer->printjobs = job->next;
						if (job->next)
							job->next->parent = NULL;
					}
		
					eb_free (__FILE__, __LINE__, "PRINTER", "Freeing completed printjob", job);
				}
			}

			eb_ps_send (d, reply, 1);

		}

	}
}
