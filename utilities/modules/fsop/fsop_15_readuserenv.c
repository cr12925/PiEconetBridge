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

FSOP(15)
{

	FS_R_DATA(0x80);

	int replylen = 2, count, termfound;
	unsigned short disclen;
	unsigned char   discname[17];
	struct __fs_active      *a;

	a = f->active;

	//fs_debug (0, 2, "%12sfrom %3d.%3d Read user environment - current user handle %d, current lib handle %d", "", f->net, f->stn, f->active->current, f->active->lib);
	fs_debug_full (0, 2, f->server, f->net, f->stn, "Read user environment - current user handle %d (dir:%c ptr:%p), current lib handle %d (dir:%c ptr:%p)", f->cwd, a->fhandles[a->current].is_dir ? 'Y' : 'N',
				a->fhandles[a->current].handle, f->lib, a->fhandles[a->lib].is_dir ? 'Y' : 'N', a->fhandles[a->lib].handle);

	// If either current or library handle is invalid, barf massively.


	if (!(a->fhandles[a->current].is_dir)
	||  !(a->fhandles[a->lib].is_dir)
	||  !(a->fhandles[a->current].handle)
	||  !(a->fhandles[a->lib].handle))
	{
		fsop_error(f, 0xDE, "Channel ?");
		return;
	}

	disclen = r.p.data[replylen++] = 16; // strlen(fs_discs[server][active[server][active_id].disc].name);

	if (a->fhandles[a->current].handle->is_tape)
		sprintf (&(r.p.data[replylen]), "%%TAPE%-11d", a->fhandles[a->current].handle->tape_drive);
	else
	{
		fsop_get_disc_name(f->server, a->current_disc, discname);

		sprintf (&(r.p.data[replylen]), "%-16s", discname);
	}

	replylen += disclen;

	memcpy(&(r.p.data[replylen]), &(a->fhandles[a->current].acorntailpath), 10);

	termfound = 0;

	for (count = 0; count < 10; count++)
		if (termfound || r.p.data[replylen+count] == 0)
		{
			r.p.data[replylen+count] = ' ';
			termfound = 1;
		}

	replylen += 10;

	memcpy(&(r.p.data[replylen]), &(a->fhandles[a->lib].acorntailpath), 10);

	termfound = 0;

	for (count = 0; count < 10; count++)
	if (termfound || r.p.data[replylen+count] == 0)
	{
		r.p.data[replylen+count] = ' ';
		termfound = 1;
	}

	replylen += 10;

	fsop_aun_send (&r, replylen, f);

	return;

}

