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
	uint8_t			handle, ctrl;
	off_t			sent, length;
	struct __fs_file	*internal_handle;
	struct __fs_active	*a;
	FILE 			*h;
	uint8_t			eofreached, fserroronread;
	int			received, total_received;

	uint8_t 		readbuffer[FS_MAX_BULK_SIZE];

	uint32_t		seq;

	a = f->active;

	handle = FS_DIVHANDLE(a,*(f->data+5));
	ctrl = FSOP_CTRL;
	txport = FSOP_URD; /* Takes URD slot */
	offsetstatus = *(f->data+6);
	bytes = (((*(f->data+7))) + ((*(f->data+8)) << 8) + (*(f->data+9) << 16));
	offset = (((*(f->data+10))) + ((*(f->data+11)) << 8) + (*(f->data+12) << 16));

	if (handle < 1 || handle > FS_MAX_OPEN_FILES || !a->fhandles[handle].handle)
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() %04lX from offset %04lX (%s) by user %04x on handle %02X", "", f->net, f->stn, bytes, offset, (offsetstatus ? "ignored - using current ptr" : "being used"), f->userid, handle);

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
		fs_debug (0, 1, "%12s from %3d.%3d fs_getbytes() on channel %02X - error on finding length of file: %s", "", f->net, f->stn, handle, error_str);
		return;
	}

	if (offset >= length) // At or eyond EOF
		eofreached = 1;
	else
		eofreached = 0;

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() offset %06lX, file length %06lX, beyond EOF %s", "", f->net, f->stn, offset, length, (eofreached ? "Yes" : "No"));

	fseek(h, offset, SEEK_SET);
	a->fhandles[handle].cursor_old = offset; // Store old cursor
	a->fhandles[handle].cursor = offset;

	// Send acknowledge

	// Set the sequence number so we can trigger on it

	seq = eb_get_local_seq(f->server->fs_device);

	r.p.seq = seq;

	fsop_aun_send_noseq(&r, 2, f);

	fserroronread = 0;
	sent = 0;
	total_received = 0;

	while (sent < bytes)
	{
		unsigned short readlen;

		readlen = ((bytes - sent) > sizeof(readbuffer) ? sizeof(readbuffer) : (bytes - sent));

		received = fread(readbuffer, 1, readlen, h);

		fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() bulk transfer: bytes required %06lX, bytes already sent %06lX, buffer size %04X, ftell() = %06lX, bytes to read %06X, bytes actually read %06X", "", f->net, f->stn, bytes, sent, (uint16_t) sizeof(readbuffer), ftell(h), readlen, received);

		if (received != readlen) // Either FEOF or error
		{
			if (feof(h)) eofreached = 1;
			else
			{
				if (ferror(h))
				{
					clearerr(h);
					#ifndef __NO_LIBEXPLAIN
						// explain_ferror() is not threadsafe - so it requires the global fs mutex
						fs_debug (0, 2, "%12sfrom %3d.%3d short file read returned %d, expected %d but not end of file - error flagged: %s", "", f->net, f->stn, received, readlen, explain_ferror(h));
					#else
						fs_debug (0, 2, "%12sfrom %3d.%3d short file read returned %d, expected %d but not end of file - error flagged: %s", "", f->net, f->stn, received, readlen, "Unknown (no libexplain)");
					#endif

				}
				fserroronread = 1;
			}
		}

		// Always send packets which total up to the amount of data the station requested, even if all the data is past EOF (because the station works that out from the closing packet)
		
		r.p.ptype = ECONET_AUN_DATA;
		r.p.port = txport;
		r.p.ctrl = 0x80;

		if (received > 0)
			memcpy(&(r.p.data), readbuffer, received);
		if (received < readlen) // Pad rest of data
			memset (&(r.p.data[received]), 0, readlen - received);

		// The real FS pads a short packet to the length requested, but then sends a completion message (below) indicating how many bytes were actually valid

		// Now put them on a load queue

		fsop_load_enqueue(f, &(r), readlen, internal_handle, a->fhandles[handle].mode, seq, FS_ENQUEUE_GETBYTES, 0 /* delay */); 

		seq = 0; // seq != 0 means start a new load queue, so always set to 0 here to add to same queue
		sent += readlen;
		total_received += received;

	}

	a->fhandles[handle].cursor += total_received; // And update the cursor
	a->fhandles[handle].sequence = (ctrl & 0x01); // Store this ctrl byte, whether it was right or wrong

	if (eofreached) a->fhandles[handle].pasteof = 1; // Since we've read the end of the file, make sure getbyte() doesn't offer more data

	if (fserroronread)
		fsop_error(f, 0xFF, "FS Error on read");
	else
	{
		// Send a completion message

		fs_debug (0, 2, "%12sfrom %3d.%3d fs_getbytes() Acknowledging %04lX tx bytes, cursor now %06lX", "", f->net, f->stn, sent, a->fhandles[handle].cursor);

		r.p.port = FSOP_REPLY_PORT;
		r.p.ctrl = ctrl; // Send the ctrl byte back to the station - MDFS does this on the close packet
		r.p.data[0] = r.p.data[1] = 0;
		r.p.data[2] = (eofreached ? 0x80 : 0x00);
		r.p.data[3] = (total_received & 0xff);
		r.p.data[4] = ((total_received & 0xff00) >> 8);
		r.p.data[5] = ((total_received & 0xff0000) >> 16);

		fsop_load_enqueue(f, &(r), 6, internal_handle, a->fhandles[handle].mode, seq, FS_ENQUEUE_GETBYTES, 0);
	}

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

	fs_debug (0, 2, "%12sfrom %3d.%3d fs_putbytes() %06lX at offset %06lX by user %04X on handle %02X",
			"", f->net, f->stn,
			bytes, offset, f->userid,  handle);

	if (offset > length) // Beyond EOF
	{
		off_t	count;

		fs_debug (0, 2, "%12s %3d.%3d fs_putbytes() Attempt to write at offset %06X beyond file end (length %06X) - padding with nulls", "", f->net, f->stn, offset, length);

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
