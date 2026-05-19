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

/* Prototypes */

void ps_handle_traffic_internal (struct __eb_device *, struct __eb_device_module *, struct __econet_packet_aun *, uint16_t);
uint8_t ps_init_private (struct __eb_device *, struct __eb_device_module *, struct json_object *);
void ps_cleanup_onejob (struct __eb_printjob *, uint8_t, uint8_t);
void ps_cleanup_jobs (struct __eb_printjob *, uint8_t, uint8_t);
uint8_t ps_exit (void *, struct __eb_device_module *);
uint8_t ps_start(void *, struct __eb_device_module *);
void ps_stop_cleanup (struct __eb_device *, struct __eb_device_module *);

/* Standard module templates */

/* NB we are using two ports, so we will reserve EB_PORT_PS_DATA in ps_init_private, and provide our own start & stop functions that claim/release it */

eb_module_handle_traffic("PS",ps_module_handle_traffic);
eb_module_thread_def("PS",ps_thread_main,ps_handle_traffic_internal);
eb_module_drain_queue("PS",ps_queue_drain);
eb_module_stop_def("PS",ps_stop,EB_PORT_PS_QUERY,ps_queue_drain,ps_stop_cleanup);
eb_module_init_def("PS",ps_init,struct __eb_printer,EB_PORT_PS_QUERY,ps_init_private,ps_start,ps_stop,ps_exit);

/* More defined below */

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
	struct __eb_device_module *m;

	d = eb_find_station_internal (net, stn);

	if (!d)
		return NULL;

	if (d->type != EB_DEF_LOCAL)
		return NULL; // Not a local device

	m = eb_module_get_data(d, "PS");

	if (!m) return NULL;

	//printer = d->local.printers;
	printer = (struct __eb_printer *) m->module_ws;

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

//void eb_handle_ps_traffic (struct __econet_packet_aun *p, uint16_t length, void *param)
void ps_handle_traffic_internal (struct __eb_device *d, struct __eb_device_module *m, struct __econet_packet_aun *p, uint16_t length)
{
	// struct __eb_device *d = (struct __eb_device *) param;
	struct __eb_printer *printers = (struct __eb_printer *) m->module_ws;
	
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
			
		reply = eb_malloc (__FILE__, __LINE__, "PRINT", "Allocate status query reply packet", 18);

		if (!reply)
			eb_debug (1, 0, "PRINT", "Unable to malloc() new printer status reply packet");

		querytype = p->p.data[6]; // See #defines for the types

		for (count = 0; count < 6; count++) // Copy printer name
			pname[count] = p->p.data[count];

		pname[6] = '\0'; // NULL terminate

		eb_debug (0, 2, "PRINT", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s", 
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

			//printer = d->local.printers;
			printer = printers;

			while (printer && !found)
			{
				if (!strcasecmp(printer->acorn_name, (char *) pname) || !strcasecmp("PRINT ", (char *) pname))
					found = 1;
				else printer = printer->next;
			}

			if (found) 
			{
				eb_debug (0, 3, "PRINT", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s - found at %p", 
					d->net, d->local.stn,
					p->p.srcnet, p->p.srcstn,	
					(querytype == PRN_QUERY_STATUS) ? "status" : "name",
					pname, printer);

				eb_ps_send (d, reply, 3);
			}
			else eb_debug (0, 2, "PRINT", "Local    %3d.%3d from %3d.%3d Printer %s query for printer %s NOT FOUND",
				d->net, d->local.stn,
			      	p->p.srcnet, p->p.srcstn,
			      	(querytype == PRN_QUERY_STATUS) ? "status" : "name",
			      	pname);

		}
		else if (querytype == PRN_QUERY_NAME)
		{
			//printer = d->local.printers;
			printer = printers;

			while (printer)
			{
				snprintf ((char * restrict) &(reply->p.data[0]), 7, "%6s", printer->acorn_name);
				eb_ps_send (d, reply, 6);
				printer = printer->next;
				reply->p.seq = eb_get_local_seq(d);
			}

		}

		eb_free (__FILE__, __LINE__, "PRINT", "Freeing printer reply packet", reply);
	}

	else if (p->p.aun_ttype == ECONET_AUN_BCAST) /* No more broadcasts acceptable after here */
		return;
							
	else if (p->p.port == EB_PORT_PS_DATA) // Print server data
	{
		struct __eb_printjob	*job;
		struct __eb_printer	*printer;
		uint8_t 		found;

		//printer = d->local.printers;
		printer = printers;
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
				eb_debug (0, 1, "PRINT", "Local    %3d.%3d Unable to make temporary print spool file for new job", d->net, d->local.stn);
			else
			{
				int8_t		printerindex;
				char *		space;
				struct __fs_active	*a;

				job = eb_malloc (__FILE__, __LINE__, "PRINT", "Create new printjob", sizeof (struct __eb_printjob));

				if (!job)
					eb_debug (1, 0, "PRINT", "Local    %3d.%3d Unable to malloc() for new printjob", d->net, d->local.stn);

				job->spoolfile = fdopen(spooldescriptor, "w");

				if (!job->spoolfile) // fdopen failed
					eb_debug (1, 0, "PRINT", "Local    %3d.%3d Unable to obtain stream for new printjob (%s)", d->net, d->local.stn, strerror(errno));

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

				//printer = d->local.printers;
				printer = printers;

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

			reply = eb_malloc (__FILE__, __LINE__, "PRINT", "Malloc() reply packet for spool data", 13);

			if (!reply)
				eb_debug (1, 0, "PRINT", "Local    %3d.%3d Cannot malloc() print data reply packet", d->net, d->local.stn);

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
				fflush (job->spoolfile);

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

					eb_debug (0, 1, "PRINT", "Local    %3d.%3d %s at %d.%d sent print job to printer %s/%s (%s)", reply->p.srcnet, reply->p.srcstn, job->username, reply->p.dstnet, reply->p.dststn, printer->acorn_name, printer->unix_name, job->spoolfilename);

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
		
					eb_free (__FILE__, __LINE__, "PRINT", "Freeing completed printjob", job);
				}
			}

			eb_ps_send (d, reply, 1);

		}
		else
			eb_debug (0, 1, "PRINT", "Local    %3d.%3d %s at %d.%d failed to find either printer or print job - not spooled", d->net, d->local.stn, p->p.srcnet, p->p.srcstn);

	}
}

/* Private part of initialization - read JSON and reserve EB_PORT_PS_DATA (because the standard definition only takes one port */

uint8_t ps_init_private (struct __eb_device *d, struct __eb_device_module *me, struct json_object *j)
{
	struct __eb_printer *printer;
	uint8_t	net = d->net, stn = d->local.stn;
	uint16_t	pcount, plength;

	/* Because of the way the template _init definition works, on entry
	 * me->module_ws will contain one empty printer struct. Thus, if no printers
	 * are defined, we should refuse to initialize and the module will get
	 * deregistered by that template function.
	 *
	 * If we *are* initializing more printers, however, we need to fill that struct
	 * first and create more as needed.
	 */

	if (!j || !json_object_is_type(j, json_type_array) || json_object_array_length(j) == 0)
	{
		eb_debug (0, 0, "PRINT", "Local    %3d.%3d Printer configuration missing or empty - not initializing", d->net, d->local.stn);
		return 1;
	}

	/* Set findserver name */

	strncpy (me->module_findserver_name, "PRINT   ", 9);

	/* Reserve our second port */

	EB_PORT_SET (d, reserved_ports, EB_PORT_PS_DATA, NULL, NULL);

	/* By this time, the main template _init() will have allocated us workspace in module_ws */

	pcount = 0;

	plength = json_object_array_length(j);

	printer = (struct __eb_printer *) me->module_ws;

	while (pcount < plength)
	{
		struct json_object      *jprinter, *jacorn, *junix, *jpriority, *jdefault, *jhandler, *jusers, *juser, *jptype;
		uint8_t	 priority = 1, pdefault = 1, printertype = EB_PRINTER_OTHER;

		jprinter = json_object_array_get_idx(j, pcount);

		if (!json_object_object_get_ex(jprinter, "acorn-name", &jacorn))
eb_debug (1, 0, "JSON", "Malformed printer definition on station %d.%d, index %d, has no Acorn name", net, stn, pcount);

		if (!json_object_object_get_ex(jprinter, "unix-name", &junix))
eb_debug (1, 0, "JSON", "Malformed printer definition on station %d.%d, index %d, has no Unix printer name", net, stn, pcount);

		if (json_object_object_get_ex(jprinter, "priority", &jpriority))
priority = json_object_get_int(jpriority);

		if (json_object_object_get_ex(jprinter, "parallel", &jptype) && json_object_get_boolean(jptype))
printertype = EB_PRINTER_PARALLEL;
		else if (json_object_object_get_ex(jprinter, "serial", &jptype) && json_object_get_boolean(jptype))
printertype = EB_PRINTER_SERIAL;


		if (json_object_object_get_ex(jprinter, "default", &jdefault) && !json_object_get_boolean(jdefault))
pdefault = 0;

		/* This handles only the first user for now - but the users list is an array so in the future
		 * we can support more than one user.
		 */

		juser = NULL;
	
		if (json_object_object_get_ex(jprinter, "users", &jusers))
		{
			if (json_object_array_length(jusers) >= 1)
			juser = json_object_array_get_idx(jusers, 0);
		}

		printer->priority = priority;
		printer->isdefault = pdefault;
		strcpy (printer->acorn_name, json_object_get_string(jacorn));
		strcpy (printer->unix_name, json_object_get_string(junix));
		printer->status = PRN_IN_READY | PRN_OUT_READY;
		printer->control = PRNCTRL_DEFAULT;
		printer->printjobs = NULL;
		printer->printertype = printertype;
		printer->next = NULL; // Terminate list for now - we'll add another entry below if need be
		strcpy (printer->user, juser ? json_object_get_string(juser) : ""); // 'user' is zero-length string if not restricted, so we just copy it

		if (json_object_object_get_ex(jprinter, "handler", &jhandler))
			strncpy (printer->handler, json_object_get_string(jhandler), 126);
		else	strcpy (printer->handler, ""); /* NULL handler */

		pcount++;

		if (pcount != plength) /* More to come, create another struct */
		{
			printer->next = eb_malloc(__FILE__, __LINE__, "PRINT", "Create printer struct", sizeof(struct __eb_printer));

			if (!printer->next) /* Failed malloc */
				eb_debug (1, 0, "PRINT", "Unable to malloc() for printer on %d.%d", d->net, d->local.stn); /* Die flag set */

			printer = printer->next; /* All ready for next entry */
		}
	}

	return 0;
}

/* Clean up a single print job */

void ps_cleanup_onejob (struct __eb_printjob *pj, uint8_t net, uint8_t stn)
{
	if (!pj) return;

	fclose (pj->spoolfile);
	unlink (pj->spoolfilename);

	eb_debug (0, 1, "PRINT", "Local    %3d.%3d from %3d.%3d Terminating print job in file %s on service stop", net, stn, pj->net, pj->stn, pj->spoolfilename);

	return;
}

/* Clean up jobs from *pj onwards, freeing structs as we go */

void ps_cleanup_jobs (struct __eb_printjob *pj, uint8_t net, uint8_t stn)
{

	struct __eb_printjob *n;

	while (pj)
	{
		ps_cleanup_onejob (pj, net, stn);
		n = pj->next;
		eb_free (__FILE__, __LINE__, "PRINT", "Free print job structure", pj);
		pj = n;
	}

	eb_debug (0, 1, "PRINT", "Local    %3d.%3d               Terminating print jobs", net, stn);

	return;

}

uint8_t ps_exit (void *device, struct __eb_device_module *m)
{
	struct __eb_printer *printer;
	struct __eb_device *d = (struct __eb_device *) device;

	/* Assume we are stopped, which will clear out pending jobs, so we just need to release
	 * our reserved memory & ports, though out of prudence we'll check for jobs and clean
	 * them up.
	 */

	pthread_mutex_lock (&(m->module_mutex));

	if (m->module_started)
	{
		eb_debug (0, 1, "PRINT", "Local    %3d.%3d Print server exit function called, but module still running", d->net, d->local.stn);
		pthread_mutex_unlock (&(m->module_mutex));
		return 1;
	}

	printer = (struct __eb_printer *) m->module_ws;

	while (printer)
	{
		struct __eb_printer *n;

		if (printer->printjobs)
			ps_cleanup_jobs(printer->printjobs, d->net, d->local.stn);

		/* Just to be tidy */
		printer->printjobs = NULL;

		n = printer->next;

		eb_free (__FILE__, __LINE__, "PRINT", "Free printer definition", printer);

		printer = n;
	}

	m->module_ws = NULL; /* Again, just to be tidy - because the m struct gets freed on deregister */

	pthread_mutex_unlock (&(m->module_mutex));

	EB_PORT_CLR(d, reserved_ports, EB_PORT_PS_DATA);
	EB_PORT_CLR(d, reserved_ports, EB_PORT_PS_QUERY);

	eb_module_deregister (d, m);

	eb_module_debug (1, "PRINT", d, "Server module exiting");

	return 0;

}

/* Start function */

uint8_t ps_start(void *device, struct __eb_device_module *me)
{
	struct __eb_device *d = (struct __eb_device *) device; 
	
	if (me->module_started) /* Already running! */ 
	{ 
		eb_module_debug (1, "PRINT", d, "Attempt to start when already running"); 
		return 1; /* Failure */ 
	} 
	
	/* Create thread */ 
	
	if (pthread_create(&(me->module_thread), NULL, ps_thread_main, d) != 0) /* Non-zero is failure */ 
	{ 
		eb_module_debug (1, "PRINT", d, "Unable to start server - thread creation failed"); 
		return 1; 
	} 
	
	pthread_detach(me->module_thread); 
	
	EB_PORT_SET(d, ports, EB_PORT_PS_DATA, ps_module_handle_traffic, d); /* Make port active */ 
	EB_PORT_SET(d, ports, EB_PORT_PS_QUERY, ps_module_handle_traffic, d); /* Make port active */ 
	
	eb_module_debug (1, "PRINT", d, "Server started"); 
	
	return 0; 

}

/* Cleanup function */

void ps_stop_cleanup (struct __eb_device *d, struct __eb_device_module *me)
{ 
	struct __eb_printer *printer;
	
	/* Clear out extra port */
	EB_PORT_CLR(d, ports, EB_PORT_PS_DATA); 
	
	printer = (struct __eb_printer *) me->module_ws;

	while (printer)
	{
		ps_cleanup_jobs(printer->printjobs, d->net, d->local.stn);
		printer->printjobs = NULL; /* Clear for next time */
		printer = printer->next;
	}
	
	return; 
} 


