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

#include "fs.h"

/* Implements:
 *
 * FSOP &02 - LOAD
 * FSOP &05 - RUNAS (Includes a library search)
 * FSOP &28 - 32bit LOAD
 */

FSOP(02)
{
	FS_R_DATA(0x80);

        unsigned char 		command[256];
        struct path 		p;

        //FILE 			*fl;

        uint8_t 		data_port = *(f->data+2);
        uint8_t 		relative_to = FSOP_CWD;
	uint8_t 		loadas = (*(f->data+1) == 0x05 ? 1 : 0);
	uint8_t 		is_32bit = (*(f->data+1) == 0x28 ? 1 : 0);
	//uint8_t			ctrl = FSOP_CTRL;

        uint16_t		result;
	int8_t			err;

        struct __fs_file 	*internal_handle;

        //uint32_t        	sequence; // Used to track the seq number sent to the load enqueuer

	struct __fs_active_load_queue	*alq;

        fs_copy_to_cr(command, f->data+5, 256);

        if (loadas) // End the command at first space if there is one - BBC Bs seem to send the whole command line
        {
                int ptr;
                ptr = 0;
                while (ptr < strlen((const char *) command))
                {
                        if (command[ptr] == ' ') command[ptr] = 0x00;
                        ptr++;
                }
        }

        fs_debug_full (0, 1, f->server, f->net, f->stn, "%s%s %s", (loadas ? "RUN" : "LOAD"), (is_32bit ? "32" : ""), command);

        if (!(result = fsop_normalize_path(f, command, relative_to, &p)) && !loadas) // Try and find the file first, but don't barf here if we are trying to *RUN it.
        {
                fsop_error(f, 0xD6, "Not found");
                return;
        }

	/*
	 * TODO:
	 *
	 * It may be we should search the lib handle provided in the packet, as opposed
	 * to our most recently cached one.
	 */

	/* 20250315 Now searches lib if sjfunc enabled - apparently MDFS does this! You can *LOAD something from the library... */

        if ((!result || (p.ftype == FS_FTYPE_NOTFOUND)) && (loadas || (FS_CONFIG(f->server,fs_sjfunc))) && !fsop_normalize_path(f, command, f->active->lib, &p))   // Either in current, or lib if loadas set
        {
                fsop_error(f, 0xFE, "Bad command");
                return;
        }

        if (p.ftype != FS_FTYPE_FILE)
        {
                if (loadas)
                        fsop_error(f, 0xFE, "Bad command");
                else
                        fsop_error(f, 0xD6, "Not found");
                return;
        }

        // Check permissions

        if (!((FS_ACTIVE_SYST(f->active)) || (p.my_perm & FS_PERM_OWN_R))) // Note: my_perm has all the relevant privilege bits in the bottom 4
        {
                fsop_error(f, 0xBD, "Insufficient access");
                return;
        }

	if (!(FS_ACTIVE_SYST(f->active)) && !loadas && (p.perm & FS_PERM_EXEC)) // Execute only bit set, and not SYST
	{
		fsop_error(f, 0xFF, "Execute only");
		return;
	}

        internal_handle = fsop_open_interlock(f, p.unixpath, 1, &err, 0, p.is_tape, p.tape_drive, p.disc, p.owner);

        if (err < 0)
        {
                fsop_error(f, 0xFE, "Already open");
                return;
        }

        // fl = internal_handle->handle;

        r.p.data[2] = (p.load & 0xff);
        r.p.data[3] = (p.load & 0xff00) >> 8;
        r.p.data[4] = (p.load & 0xff0000) >> 16;
        r.p.data[5] = (p.load & 0xff000000) >> 24;
        r.p.data[6] = (p.exec & 0xff);
        r.p.data[7] = (p.exec & 0xff00) >> 8;
        r.p.data[8] = (p.exec & 0xff0000) >> 16;
        r.p.data[9] = (p.exec & 0xff000000) >> 24;
        r.p.data[10] = p.length & 0xff;
        r.p.data[11] = (p.length & 0xff00) >> 8;
        r.p.data[12] = (p.length & 0xff0000) >> 16;
	if (is_32bit)
		r.p.data[13] = (p.length & 0xff000000) >> 24;
        r.p.data[13+is_32bit] = p.perm;
        r.p.data[14+is_32bit] = p.day; // TODO - Change to create day/month/year
        r.p.data[15+is_32bit] = p.monthyear;
        r.p.seq = eb_get_local_seq(f->server->fs_device);

        // sequence = r.p.seq; // Forces enqueuer to start new queue, and sets up the ack trigger for the packet we are about to send so that when that ACK turns up, we send the first packet in the queue.

        // Use the noseq variant so we can force the load_enqueue routine to start a new queue and trigger on the right sequence number.

	FS_LIST_MAKENEW(struct __fs_active_load_queue,f->active->load_queue,1,alq,"FS","Create new active load queue structure for load operation");

	/* Populate active load queue trigger data */

	alq->queue_type = FS_ENQUEUE_LOAD;
	alq->internal_handle = internal_handle;
	alq->user_handle = 0; /* There isn't one */
	alq->mode = 1; /* Always just read for a *LOAD */
	alq->ctrl = f->ctrl; /* So that the close packet can echo it */
	alq->client_dataport = data_port;
	alq->client_finalackport = FSOP_REPLY_PORT;
	alq->ack_seq_trigger = r.p.seq;
	alq->last_ack_rx = time(NULL); /* now */
	alq->start_ptr = 0;
	alq->send_bytes = p.length;
	alq->sent_bytes = 0; /* Initialize */
	alq->cursor = 0; /* Initialize */
	alq->valid_bytes = 0; /* Initialize */
	alq->pasteof = 0; /* Initialize */
	alq->chunk_size = f->active->chunk_size; /* Copy from login process */
	alq->is_32bit = is_32bit;

	/* Send OK response and wait to see what happens */

        if (fsop_aun_send_noseq(&r, 16+is_32bit, f))
        {


#if 0
		/* Old databurst heavyweight queue code */
                // Send data burst

                int collected;

		struct load_queue 	*enqueue_result;

                r.p.ctrl = 0x80;
                r.p.port = data_port;

                fseek (fl, 0, SEEK_SET);

                while (!feof(fl))
                {
                        collected = fread(&(r.p.data), 1, 1280, fl);

                        if (collected > 0) enqueue_result = fsop_load_enqueue(f, &r, collected, internal_handle, 1, sequence, FS_ENQUEUE_LOAD, 0, 0, 0x80); 

                        if (collected < 0)
                        {
                                fs_debug_full (0, 1, f->server, f->net, f->stn, "Data burst enqueue failed (fread() error)");
                                return; // Failed in some way
                        }

                        sequence = 0; // Set to 0 so that enqueuer doesn't create a new queue.

                }

		/* fsop_load_enqueue will give us the load_queue entry back, not the packet queue. 
		 * That's so we can update it with the start, length and so forth ready
		 * for when we read on a dequeue rather than dequeuing a stored packet.
		 */

		enqueue_result->start_ptr = 0; /* Load operation - always start of file */
		enqueue_result->send_len = p.length;
		enqueue_result->sent_len = 0; /* Nothing sent yet */

                // Send the tail end packet

                r.p.data[0] = r.p.data[1] = 0x00;
                r.p.port = FSOP_REPLY_PORT;
                r.p.ctrl = ctrl;

                fsop_load_enqueue(f, &r, 2, internal_handle, 1, sequence, FS_ENQUEUE_LOAD, 0, 0, 0);

#endif
        }

	return;

}

FSOP(05)
{
	fsop_02(f);
}

FSOP(28)
{
	fsop_02(f);
}
