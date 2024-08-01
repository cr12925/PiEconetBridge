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

FSOP(03)
{

	FS_REPLY_DATA(0x80);

	uint8_t relative_to, arg, start, n;
	unsigned char path[1024]; // Was 256 before long filenames
	struct path pt;
	struct path_entry *e;
	int replylen, replyseglen;
	unsigned short examined, dirsize;
	char acornpathfromroot[1024];

	relative_to = FSOP_CWD;
	arg = FSOP_ARG;
	start = *(f->data + 6);
	n = *(f->data + 7);

	fs_copy_to_cr(path, (f->data + 8), 255);

	fs_debug_full (0, 2, f->server, f->net, f->stn, "Examine %s relative to %d (%s), start %d, extent %d, arg = %d", path, relative_to, f->active->fhandles[relative_to].acornfullpath, start, n, arg);

	replylen = 2;

	examined = reply.p.data[replylen++] = 0; // Repopulate data[2] at end
	dirsize = reply.p.data[replylen++] = 0; // Dir size (but this might be wrong). Repopulate later if correct

	if (!fsop_normalize_path_wildcard(f, path, relative_to, &pt, 1) || pt.ftype == FS_FTYPE_NOTFOUND)
	{

		if (arg == 0)
		{
			reply.p.data[replylen++] = 0x80;
			fsop_aun_send(&reply, replylen, f);
		}
		else
			fsop_error(f, 0xD6, "Not found");
		return;

	}

	// Add final entry onto path_from_root (because normalize doesn't do it on a wildcard call)

	if (strlen(pt.path_from_root) != 0)
		strcat(pt.path_from_root, ".");
	if (pt.paths != NULL)
		strcat (pt.path_from_root, pt.paths->acornname);

	fs_free_wildcard_list(&pt); // We'll just use the first one it found, which will be in the main path struct

	if (pt.ftype != FS_FTYPE_DIR)
	{
		fsop_error(f, 0xAF, "Types don't match");
		return;
	}


	// Wildcard code

	strcpy(acornpathfromroot, path);

	if (strlen(acornpathfromroot) != 0) strcat(acornpathfromroot, ".");

	strcat(acornpathfromroot, "*"); // It should already have $ on it if root.

	// Wildcard renormalize - THE LONG FILENAMES MODS CAUSE THIS TO RETURN NOT FOUND ON AN EMPTY DIRECTORY

	if (!fsop_normalize_path_wildcard(f, acornpathfromroot, relative_to, &pt, 1)) // || p.ftype == FS_FTYPE_NOTFOUND)
	{
		if (arg == 0)
		{
			reply.p.data[replylen++] = 0x80;
			fsop_aun_send(&reply, replylen, f);
		}
		else
			fsop_error(f, 0xD6, "Not found");
		return;
	}

	e = pt.paths;

	while (dirsize < start && (e != NULL))
	{
		if ((e->perm & FS_PERM_H) == 0 || (e->owner == f->userid)) // not hidden
			dirsize++;

		e = e->next;
	}

	/* Add a check here to make sure we don't tip over a 255 byte packet */

	switch (arg)
	{
		case 0: replyseglen = 27; break;
		case 1: replyseglen = ECONET_MAX_FILENAME_LENGTH + 57; break;
		case 2: replyseglen = ECONET_MAX_FILENAME_LENGTH + 1; break;
		case 3: replyseglen = ECONET_MAX_FILENAME_LENGTH + 9; break;
		case 4: replyseglen = 34; break; /* 32 bit machine-readable, but 10 character FN */
	}

	while (examined < n && (e != NULL) && (replylen < (255-replyseglen)))
	{
		if (FS_ACTIVE_SYST(f->active) || (e->perm & FS_PERM_H) == 0 || (e->owner == f->userid)) // not hidden or we are the owner
		{
			switch (arg)
			{
				case 0: // Machine readable format
				{

					int le_count;

					snprintf(&(reply.p.data[replylen]), 11, "%-10.10s", e->acornname); // 11 because the 11th byte (null) gets overwritten two lines below because we only add 10 to replylen.

					replylen += 10;

					for (le_count = 0; le_count <= 3; le_count++)
					{
						reply.p.data[replylen + le_count] = ((e->ftype == FS_FTYPE_DIR ? 0 : htole32(e->load)) >> (8 * le_count)) & 0xff;
						reply.p.data[replylen + 4 + le_count] = ((e->ftype == FS_FTYPE_DIR ? 0 : htole32(e->exec)) >> (8 * le_count)) & 0xff;
					}

					replylen += 8; // Skip past the load / exec that we just filled in

					reply.p.data[replylen++] = fsop_perm_to_acorn(f->server, e->perm, e->ftype);
					reply.p.data[replylen++] = e->day;
					reply.p.data[replylen++] = e->monthyear;

					if (f->server->config->fs_sjfunc) // Next three bytes are ownership information - main & aux. We always set aux to 0 for now.
					{
						reply.p.data[replylen++] = (e->owner & 0xff);
						reply.p.data[replylen++] = ((e->owner & 0x700) >> 3);
						reply.p.data[replylen++] = 0; // Aux account number
					}
					else
					{
						reply.p.data[replylen++] = e->internal & 0xff;
						reply.p.data[replylen++] = (e->internal & 0xff00) >> 8;
						reply.p.data[replylen++] = (e->internal & 0xff0000) >> 16;
					}

					if (e->ftype == FS_FTYPE_DIR)   e->length = 0x200; // Dir length in FS3

					reply.p.data[replylen++] = e->length & 0xff;
					reply.p.data[replylen++] = (e->length & 0xff00) >> 8;
					reply.p.data[replylen++] = (e->length & 0xff0000) >> 16;

				} break;
				case 1: // Human readable format
				{
					unsigned char tmp[256];
					unsigned char permstring_l[10], permstring_r[10];
					unsigned char permstring_both[20];
					unsigned char hr_fmt_string[80];
					uint8_t	 is_owner;

					is_owner = FS_PERM_EFFOWNER(f->active, e->owner);

					if (f->server->config->fs_mask_dir_wrr && e->ftype == FS_FTYPE_DIR && (e->perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
						e->perm &= ~(FS_ACORN_DIR_MASK);

					sprintf(permstring_l, "%s%s%s%s",
						(e->ftype == FS_FTYPE_DIR ? "D" : e->ftype == FS_FTYPE_SPECIAL ? "S" : (e->ftype == FS_FTYPE_FILE && (e->perm & FS_PERM_EXEC)) ? "E" : ""),
						((e->perm & FS_PERM_L) ? "L" : ""),
						((e->perm & FS_PERM_OWN_W) ? (is_owner ? "W" : FS_CONFIG(f->server,fs_mdfsinfo) ? "w": "W") : ""),
						((e->perm & FS_PERM_OWN_R) ? (is_owner ? "R" : FS_CONFIG(f->server,fs_mdfsinfo) ? "r" : "R") : "") );

					sprintf(permstring_r, "%s%s",
						((e->perm & FS_PERM_OTH_W) ? (FS_CONFIG(f->server,fs_mdfsinfo) ? (is_owner ? "w" : "W") : "W") : ""),
						((e->perm & FS_PERM_OTH_R) ? (FS_CONFIG(f->server,fs_mdfsinfo) ? (is_owner ? "r" : "R") : "R") : "") );

					sprintf(permstring_both, "%s/%s", permstring_l, permstring_r);

					sprintf (hr_fmt_string, "%%-%ds %%08lX %%08lX   %%06lX   %%-7s     %%02d/%%02d/%%02d %%06lX", ECONET_MAX_FILENAME_LENGTH);

					sprintf (tmp, hr_fmt_string,
						e->acornname,
						e->load, e->exec, e->length,
						permstring_both,
						fs_day_from_two_bytes(e->day, e->monthyear),
						fs_month_from_two_bytes(e->day, e->monthyear),
						fs_year_from_two_bytes(e->day, e->monthyear),
						e->internal
						);

					strcpy((char * ) &(reply.p.data[replylen]), (const char * ) tmp);
					replylen += strlen(tmp);
					reply.p.data[replylen++] = '\0';

				} break;

				case 2: // 10 character filename format (short)
				{
					unsigned char hr_fmt_string[20];

					sprintf(hr_fmt_string, "%%-%d.%ds", ECONET_MAX_FILENAME_LENGTH, ECONET_MAX_FILENAME_LENGTH);

					reply.p.data[replylen++] = ECONET_MAX_FILENAME_LENGTH;
					sprintf((char *) &(reply.p.data[replylen]), hr_fmt_string, e->acornname);
					replylen += ECONET_MAX_FILENAME_LENGTH;

				} break;

				case 3: // 10 character filename format (long) - this can only do 10 characters according to the spec, but FS4 exceeds this, and it causes problems with RISC OS but Acorn didn't seem that bothered...!
				{
					char tmp[256];
					char permstring_l[10], permstring_r[10];
					uint8_t	 is_owner;

					is_owner = FS_PERM_EFFOWNER(f->active, e->owner);

					if (f->server->config->fs_mask_dir_wrr && e->ftype == FS_FTYPE_DIR && (e->perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
						e->perm &= ~(FS_ACORN_DIR_MASK);

					sprintf(permstring_l, "%s%s%s%s",
						(e->ftype == FS_FTYPE_DIR ? "D" : e->ftype == FS_FTYPE_SPECIAL ? "S" : (e->ftype == FS_FTYPE_FILE && (e->perm & FS_PERM_EXEC)) ? "E" : ""),
						((e->perm & FS_PERM_L) ? "L" : ""),
						((e->perm & FS_PERM_OWN_W) ? (is_owner ? "W" : f->server->config->fs_mdfsinfo ? "w": "W") : ""),
						((e->perm & FS_PERM_OWN_R) ? (is_owner ? "R" : f->server->config->fs_mdfsinfo ? "r" : "R") : "") );

					sprintf(permstring_r, "%s%s",
						((e->perm & FS_PERM_OTH_W) ? (f->server->config->fs_mdfsinfo ? (is_owner ? "w" : "W") : "W") : ""),
						((e->perm & FS_PERM_OTH_R) ? (f->server->config->fs_mdfsinfo ? (is_owner ? "r" : "R") : "R") : "") );

					sprintf (tmp, "%-10s %4s/%-2s", e->acornname,
						permstring_l, permstring_r
						);

					strcpy((char * ) &(reply.p.data[replylen]), (const char * ) tmp);
					replylen += strlen(tmp) + 1; // +1 for the 0 byte

				} break;

				case 4: /* 32-bit machine readable */
				{
#define FSOP_03_STORE32(n) reply.p.data[replylen++] = e->n & 0xff; \
			reply.p.data[replylen++] = (e->n & 0xff00) >> 8; \
			reply.p.data[replylen++] = (e->n & 0xff0000) >> 16; \
			reply.p.data[replylen++] = (e->n & 0xff000000) >> 24;

					FSOP_03_STORE32(load);
					FSOP_03_STORE32(exec);
					FSOP_03_STORE32(length);

					if (f->server->config->fs_mask_dir_wrr && e->ftype == FS_FTYPE_DIR && (e->perm & (FS_ACORN_DIR_MASK | FS_PERM_OTH_W)) == FS_ACORN_DIR_MASK)
						e->perm &= ~(FS_ACORN_DIR_MASK);

					reply.p.data[replylen++] = fsop_perm_to_acorn(f->server, e->perm, (e->ftype == FS_FTYPE_DIR ? 1 : 0));
					reply.p.data[replylen++] = 0x00;
					reply.p.data[replylen++] = e->day;
					reply.p.data[replylen++] = e->monthyear;

					FSOP_03_STORE32(internal);

					memset(&(reply.p.data[replylen]), 0, 4);
					replylen += 4;

					fs_copy_padded(&(reply.p.data[replylen]), e->acornname, 10);

					replylen += 10;
				}
			}

			examined++;
			dirsize++;
		}

		e = e->next;

	}

	fs_free_wildcard_list(&pt);

	reply.p.data[replylen++] = 0x80;
	reply.p.data[2] = (examined & 0xff);
	reply.p.data[3] = (dirsize & 0xff); // Can't work out how L3 is calculating this number

	fsop_aun_send(&reply, replylen, f);


	return;

}

