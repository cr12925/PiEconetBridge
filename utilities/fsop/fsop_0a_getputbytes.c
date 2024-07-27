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

/* Implements
 *
 * FSOP &0A - Getbytes
 * FSOP &0B - Putbytes
 * FSOP &3B - Getbytes 32 bit
 * FSOP &3C - Putbytes 32 bit
 */

FSOP(0a)
{

	FS_R_DATA(0x80);
	uint32_t		bytes, offset;
	uint8_t			txport, offsetstatus;
	uint8_t			handle; //, ctrl;
	off_t			length; // sent;
	struct __fs_file	*internal_handle;
	struct __fs_active	*a;
	FILE 			*h;
	uint8_t			eofreached; //, fserroronread;
	//int			received, total_received;

	//uint8_t 		readbuffer[FS_MAX_BULK_SIZE];

	uint32_t		seq;

	struct __fs_active_load_queue	*alq;

	a = f->active;

	handle = FS_DIVHANDLE(a,*(f->data+5));
	//ctrl = FSOP_CTRL;
	txport = FSOP_URD; /* Takes URD slot */
	offsetstatus = *(f->data+6);
	bytes = (((*(f->data+7))) + ((*(f->data+8)) << 8) + (*(f->data+9) << 16));
	offset = (((*(f->data+10))) + ((*(f->data+11)) << 8) + (*(f->data+12) << 16));

	if (handle < 1 || handle > FS_MAX_OPEN_FILES || !a->fhandles[handle].handle)
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	fs_debug_full (0, 2, f->server, f->net, f->stn, "OSGBPB Get %04lX from offset %04lX (%s) by user %04x on handle %02X", bytes, offset, (offsetstatus ? "ignored - using current ptr" : "being used"), f->userid, handle);

	internal_handle = a->fhandles[handle].handle;

	if (f->datalen < 13)
	{
		fsop_error(f, 0xFF, "Bad server request");
		return;
	}

	if (offsetstatus) // Read from current position
		offset = a->fhandles[handle].cursor;

	// Seek to end to detect end of file
	
	h = internal_handle->handle;

	fseek(h, 0, SEEK_END);
	length = ftell(h);

	if (length == -1) // Error
	{
		char error_str[128];

		strerror_r(errno, error_str, 127);

		fsop_error(f, 0xFF, "Cannot find file length");
		fs_debug_full (0, 1, f->server, f->net, f->stn, "OSGBPB Get on channel %02X - error on finding length of file: %s", handle, error_str);
		return;
	}

	if (offset >= length) // At or eyond EOF
		eofreached = 1;
	else
		eofreached = 0;

	fs_debug_full (0, 2, f->server, f->net, f->stn, "OSGBPB Get offset %06lX, file length %06lX, beyond EOF %s", offset, length, (eofreached ? "Yes" : "No"));

	// Send acknowledge

	// Set the sequence number so we can trigger on it

	seq = eb_get_local_seq(f->server->fs_device);

	r.p.seq = seq;

	r.p.ctrl = FSOP_CTRL;

        FS_LIST_MAKENEW(struct __fs_active_load_queue,f->active->load_queue,1,alq,"FS","Create new active load queue structure for GetBytes operation");

        /* Populate active load queue trigger data */

        alq->queue_type = FS_ENQUEUE_GETBYTES;
        alq->internal_handle = internal_handle;
        alq->user_handle = handle; /* There isn't one */
        alq->mode = f->active->fhandles[handle].mode; 
        alq->ctrl = f->ctrl; /* So that the close packet can echo it */
        alq->client_dataport = txport;
        alq->client_finalackport = FSOP_REPLY_PORT;
        alq->ack_seq_trigger = r.p.seq;
        alq->last_ack_rx = time(NULL); /* now */
        alq->start_ptr = offset;
        alq->send_bytes = bytes;
        alq->sent_bytes = 0; /* Initialize */
        alq->cursor = offset; /* Initialize */
        alq->valid_bytes = 0; /* Initialize */
        alq->pasteof = eofreached; /* Initialize */
        alq->chunk_size = f->active->chunk_size;  /* Copy from login process */

	fsop_aun_send_noseq(&r, 2, f);

	return;

}

FSOP(0b)
{

	FS_R_DATA(0x80);

	off_t		bytes, offset, length;
	uint8_t		txport, offsetstatus;
	struct __fs_file	*internal_handle;
	uint8_t		incoming_port;
	struct __fs_active	*a;
	FILE		*h;
	struct __fs_bulk_port	*bp;

	struct tm 	t;
	uint8_t		day, monthyear;
	time_t		now;

	uint8_t		handle;

	now = time(NULL);
	t = *localtime(&now);
	a = f->active;

	handle = FS_DIVHANDLE(a,*(f->data + 5));
	txport = *(f->data+2);
	offsetstatus = *(f->data+6);
	bytes = (((*(f->data+9)) << 16) + ((*(f->data+8)) << 8) + (*(f->data+7)));
	offset = (((*(f->data+12)) << 16) + ((*(f->data+11)) << 8) + (*(f->data+10)));

	fs_date_to_two_bytes(t.tm_mday, t.tm_mon+1, t.tm_year, &monthyear, &day);

	if ((handle < 1) || (handle > FS_MAX_OPEN_FILES) || !(a->fhandles[handle].handle))
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	internal_handle = a->fhandles[handle].handle;
	h = internal_handle->handle;

	if (f->datalen < 13)
	{
		fsop_error(f, 0xFF, "Bad server request");
		return;
	}

	fseek(h, 0, SEEK_END);
	length = ftell(h);

	if (offsetstatus) // write to current position
		offset = a->fhandles[handle].cursor;

	fs_debug_full (0, 2, f->server, f->net, f->stn, "OSGBPB Put %06lX at offset %06lX by user %04X on handle %02X",
			bytes, offset, f->userid,  handle);

	if (offset > length) // Beyond EOF
	{
		off_t	count;

		fs_debug_full (0, 3, f->server, f->net, f->stn, "OSGBPB Put Attempt to write at offset %06X beyond file end (length %06X) - padding with nulls", offset, length);

		fseek(h, 0, SEEK_END);

		while (count++ < (offset-length))
			fputc('\0', h);
	}

	fseek(h, offset, SEEK_SET);

	// Update cursor_old
	// 20240102 Test update
	if (a->fhandles[handle].cursor != a->fhandles[handle].cursor_old)
		a->fhandles[handle].cursor_old = a->fhandles[handle].cursor;

	// Update sequence
	a->fhandles[handle].sequence = (FSOP_CTRL & 0x01);

	// 20240102 Update cursor to offset. If it's moved because we picked a particular start position for write, we don't seem to update it(!)
	a->fhandles[handle].cursor = offset;

	// We should be the only writer, so doing the seek here should be fine

	// Set up a bulk transfer here.

	if ((incoming_port = fsop_find_bulk_port(f->server)))
	{
		FS_LIST_MAKENEW(struct __fs_bulk_port,f->server->bulkports,1,bp,"FS","New FS bulk port for GetBytes()");
		bp->handle = internal_handle;
		bp->ack_port = txport; // Could be wrong
		bp->length = bytes;
		bp->received = 0; // Initialize counter
		bp->reply_port = FSOP_REPLY_PORT;
		bp->rx_ctrl = FSOP_CTRL; // Gets added to final close packet
		bp->mode = a->fhandles[handle].mode;
		bp->active = a; // So that the cursor can be updated as we receive
		bp->user_handle = handle; 
		bp->bulkport = incoming_port;
		bp->last_receive = (unsigned long long) time(NULL);
		bp->is_gbpb = 1; /* Flags to the dequeuer not to close the file at the end */
		fs_store_tail_path(bp->acornname, a->fhandles[handle].acornfullpath);

		// Send acknowledge
		r.p.ctrl = FSOP_CTRL;
		r.p.data[2] = incoming_port;
		r.p.data[3] = (FS_CONFIG(f->server,fs_bigchunks) ? FS_MAX_BULK_SIZE : 0x500) & 0xff; // Max trf size
		r.p.data[4] = ((FS_CONFIG(f->server,fs_bigchunks) ? FS_MAX_BULK_SIZE : 0x500) & 0xff00) >> 8; // High byte of max trf

		fsop_aun_send(&r, 5, f);
	}
	else    fsop_error(f, 0xFF, "No channels available");

	if (bytes == 0) // No data expected
	{
		FS_LIST_SPLICEFREE(f->server->bulkports,bp,"FS","Freeing unused bulk port struct on a zero-byte transfer");
		r.p.ctrl = FSOP_CTRL;
		r.p.data[2] = FS_PERM_OWN_R | FS_PERM_OWN_W;
		r.p.data[3] = day;
		r.p.data[4] = monthyear;

		fsop_aun_send (&r, 5, f);
	}

	return;

}

FSOP(2b)
{

	fsop_error(f, 0xFF, "Not implemented (yet)");
}

FSOP(2c)
{

	fsop_error(f, 0xFF, "Not implemented (yet)");

}
