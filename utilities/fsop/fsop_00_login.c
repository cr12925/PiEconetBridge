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

/* 
 * Implements *I AM (and its aliases)
 * together with *SDISC
 *
 * Provides a utility routine to get a user mounted on 
 * a specified disc
 */

/* Open and map a directory handle 
 * Error codes as per fsop_move_disc, but bottom nybble is 0
 */

uint8_t fsop_openmap_dir(struct fsop_data *f, unsigned char *input_path, struct __fs_disc *d, unsigned char *which, uint8_t *handle, struct __fs_file **internal_handle, unsigned char *unixpath)
{

	//struct __fs_user	*user;
	struct __fs_active	*a;
	struct __fs_file	*h;
	struct path		p;
	unsigned char		full_path[1024];
	int8_t			err;

	a = f->active;

	//user = &(a->server->users[a->userid]);

	strcpy (full_path, input_path);

	if (*handle) /* Non-Zero - ie there's an existing handle */
	{
		//fsop_close_dir_handle(f->server, a->fhandles[*handle].handle);
		fsop_close_interlock(f->server, a->fhandles[*handle].handle, 1);
		fsop_deallocate_user_dir_channel (a, *handle);
	}

	strcpy (unixpath, ""); /* initialize */

	if (!(fsop_normalize_path(f, full_path, -1, &p)) || p.ftype == FS_FTYPE_NOTFOUND) // NOTE: because fs_normalize might look up current or home directory, home must be a complete path from $
	{
		/* If not found, map $ instead */

		fs_debug_full (0, 1, f->server, f->net, f->stn, "Select disc - %s %s not found, attempting to map $ for user id %04X", which, full_path, f->userid);
		snprintf(full_path, 1023, ":%s.$", d->name);

		if (!fsop_normalize_path(f, full_path, -1, &p))
			return (FSOP_MOVE_DISC_UNREADABLE);
	}

	if (p.ftype != FS_FTYPE_DIR) // Root wasn't a directory!
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "Select disc - bad %s %s for userid %d", which, full_path, f->userid);
		return (FSOP_MOVE_DISC_NOTDIR);
	}

	if ((p.owner == a->userid && (p.perm & FS_PERM_OWN_R) == 0) && ((p.perm & FS_PERM_OTH_R) == 0)) // Unreadable directory
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "Select disc - unreadable %s %s for userid %d", which, full_path, f->userid);
		return (FSOP_MOVE_DISC_UNREADABLE);
	}

	if (f->server->config->fs_acorn_home && !strcasecmp(which, "URD"))
	{
		struct objattr oa;

		fsop_read_xattr(p.unixpath, &oa, f);

		if (oa.homeof == 0)
			fsop_write_xattr(p.unixpath, oa.owner, oa.perm, oa.load, oa.exec, f->userid, f);
	}

	//h = fsop_get_dir_handle(f, p.unixpath);
	h = fsop_open_interlock(f, p.unixpath, 1, &err, 1);

	if (err < 0)
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "Select disc - unmappable %s %s for userid %04X", which, full_path, f->userid);
		return (FSOP_MOVE_DISC_UNMAPPABLE);
	}

	*internal_handle = h;

	if ((*handle = fsop_allocate_user_dir_channel(a, h)) == 0) /* Cannot get a handle */
	{
		fsop_close_interlock(f->server, h, 1);
		fs_debug_full (0, 1, f->server, f->net, f->stn, "Sellect disc - no channel for %s %s for userid %04X", which, full_path, f->userid);
		return (FSOP_MOVE_DISC_CHANNEL);
	}

	strcpy(unixpath, p.unixpath);

	a->fhandles[*handle].mode = 1;
	strcpy(a->fhandles[*handle].acornfullpath, p.acornfullpath);
	fs_store_tail_path(a->fhandles[*handle].acorntailpath, p.acornfullpath);

	fs_debug_full (0, 1, f->server, f->net, f->stn, "Map dir successful - handle %02X for user %04X, full path %s, tail path %s", *handle, f->userid, a->fhandles[*handle].acornfullpath, a->fhandles[*handle].acorntailpath);

	return FSOP_MOVE_DISC_SUCCESS;
}

/* 
 * fsop_move_disc (active, disc)
 *
 * Returns uint8_t
 *
 * Low 4 bits
 * 0 - Success
 * 1 - Root problem
 * 2 - CWD problem
 * 3 - LIB problem
 * 4 - Disc not visible
 *
 * High 4 bits
 * 0 - Success
 * 1 - Dir not found
 * 2 - Not a directory
 * 3 - Unreadable directory
 */

uint8_t fsop_move_disc (struct fsop_data *f, uint8_t index)
{
	unsigned char	urd[256], lib[256]; /* urd will also be cwd */
	unsigned char	homedir[97], libdir[97];
	unsigned char	unixpath[1024];
	//unsigned char	padded[ECONET_ABS_MAX_FILENAME_LENGTH+1];
	uint8_t		count;
	uint8_t		res;

	struct __fs_user	*user;
	struct __fs_active	*a;
	struct __fs_disc	*d;
	struct __fs_file	*h;

	a = f->active;

	user = &(a->server->users[a->userid]);

	/* Find the disc */

	d = f->server->discs;

	while (d)
	{
		if (d->index == index)
			break;
		else d = d->next;
	}

	/* 
	 * First, is the disc visible to this user?
	 */

	if (!FS_DISC_VIS(a->server, a->userid, d->index))
		return FSOP_MOVE_DISC_INVIS;

	if (user->home[0] != '$' && user->home[0] != ' ')
	{
		homedir[0] = '$';
		homedir[1] = ' ';
		memcpy((homedir+2), user->home, 80);
	}
	else
		memcpy(homedir, user->home, 80);

	memcpy(libdir, user->lib, 80);

	for (count = 0; count < 80; count++)
	{
		if (homedir[count] == ' ')
		{
			homedir[count] = 0x00;
			break;
		}
	}

	for (count = 0; count < 80; count++)
	{
		if (libdir[count] == ' ')
		{
			libdir[count] = 0x00;
			break;
		}
	}

	if (strlen(homedir) == 0)	strcpy(homedir, "$");
	if (strlen(libdir) == 0)	strcpy(libdir, "$.Library");

	snprintf(urd, 255, ":%s.%s", d->name, homedir);
	snprintf(lib, 255, ":%s.%s", d->name, libdir);

	res = fsop_openmap_dir(f, urd, d, "URD", &(a->root), &h, unixpath);

	if (res != FSOP_MOVE_DISC_SUCCESS)
	{
		if ((res & 0xF0) == FSOP_MOVE_DISC_CHANNEL) /* A system handle will have been allocated */
			fsop_close_interlock(f->server, h, 1);

		a->root = a->current = a->lib = 0;

		return (res | FSOP_MOVE_DISC_URD);

	}

	strncpy ((char *) a->root_dir, a->fhandles[a->root].acornfullpath, 1023);
	fs_copy_padded(a->root_dir_tail, a->fhandles[a->root].acorntailpath, f->server->config->fs_fnamelen);

	if ((a->user->priv2 & FS_PRIV2_CHROOT) && (d->index == a->user->home_disc))
		strcpy(a->urd_unix_path, unixpath);
	else	strcpy(a->urd_unix_path, "");

	/* Open URD as current */

	res = fsop_openmap_dir(f, urd, d, "CWD", &(a->current), &h, unixpath);

	if (res != FSOP_MOVE_DISC_SUCCESS)
	{
		if ((res & 0xF0) == FSOP_MOVE_DISC_CHANNEL) /* A system handle will have been allocated */
		{
			fsop_close_interlock(f->server, a->fhandles[a->root].handle, 1);
			fsop_deallocate_user_dir_channel(a, a->root);
			fsop_close_interlock(f->server, h, 1);
		}

		a->root = a->current = a->lib = 0;

		return (res | FSOP_MOVE_DISC_URD);

	}

	strncpy ((char *) a->current_dir, a->fhandles[a->current].acornfullpath, 1023);
	fs_copy_padded(a->current_dir_tail, a->fhandles[a->current].acorntailpath, f->server->config->fs_fnamelen);

	/*
	a->current = fsop_allocate_user_dir_channel(a, a->fhandles[a->root].handle);

	if (!a->current)
	{
		fsop_close_interlock(f->server, a->fhandles[a->root].handle, 1);
		fsop_close_interlock(f->server, a->fhandles[a->current].handle, 1);
		fsop_close_interlock(f->server, h, 1);
		fsop_deallocate_user_dir_channel(a, a->root);
		fsop_deallocate_user_dir_channel(a, a->current);

		a->root = a->current = a->lib = 0;

		return (FSOP_MOVE_DISC_CHANNEL | FSOP_MOVE_DISC_CWD);
	}

	strcpy(a->fhandles[a->current].acornfullpath, a->fhandles[a->root].acornfullpath);
	strcpy(a->fhandles[a->current].acorntailpath, a->fhandles[a->root].acorntailpath);
	strncpy ((char *) a->current_dir, a->fhandles[a->current].acornfullpath, 1023);
	fs_copy_padded(a->current_dir_tail, a->fhandles[a->current].acorntailpath, f->server->config->fs_fnamelen);
	a->fhandles[a->current].mode = 1;
	a->fhandles[a->current].is_dir = 1;
	*/

	/* Open LIB */

	res = fsop_openmap_dir(f, lib, d, "LIB", &(a->lib), &h, unixpath);

	if (res != FSOP_MOVE_DISC_SUCCESS)
	{
		fsop_close_interlock(f->server, a->fhandles[a->root].handle, 1);
		fsop_deallocate_user_dir_channel(a, a->root);

		fsop_close_interlock(f->server, a->fhandles[a->current].handle, 1);
		fsop_deallocate_user_dir_channel(a, a->current);

		if ((res & 0xF0) == FSOP_MOVE_DISC_CHANNEL) /* A system handle will have been allocated */
			fsop_close_interlock(f->server, h, 1);

		a->root = a->current = a->lib = 0;

		return (res | FSOP_MOVE_DISC_LIB);
	}

	strncpy ((char *) a->lib_dir, a->fhandles[a->lib].acornfullpath, 1023);
	fs_copy_padded(a->lib_dir_tail, a->fhandles[a->lib].acorntailpath, f->server->config->fs_fnamelen);

	a->current_disc = d->index;

	fs_debug_full (0, 1, f->server, f->net, f->stn, "Select disc - Handles allocated for URD for userid %d - URD (%02X), CWD (%02X), LIB (%02X)", f->userid, a->root, a->current, a->lib);

	return FSOP_MOVE_DISC_SUCCESS;

}

FSOP_00(LOGIN)
{
	FS_REPLY_DATA(0x80);

	char username[11], username_extract[11];
	char password[11], password_extract[11];

	uint16_t counter;
	uint8_t found = 0;

	struct __fs_machine_peek_reg *stnpeek;
	struct timespec peek_timeout;
	uint32_t	mtype;
	uint8_t		skip_first = 0; /* Skip first parameter if it's not the only one and it consists of net.stn or just stn */

	// Notify not privileged on any login attempt, successful or otherwise. It'll get set to 1 below if need be

	eb_fast_priv_notify(f->server->fs_device, f->net, f->stn, 0);

	/* Send machine peek and snooze a second or two */

	/* Needs to be a different lock here, otherwise other FS traffic could turn up ... */

	FS_LIST_MAKENEW(struct __fs_machine_peek_reg,f->server->peeks,1,stnpeek,"FS","New machinepeek probe structure");

	stnpeek->net = f->net;
	stnpeek->stn = f->stn;
	stnpeek->mtype = 0x0000;
	stnpeek->s = f->server;

	reply.p.port = 0x00;
	reply.p.ptype = ECONET_AUN_IMM;
	reply.p.ctrl = 0x88;

	memset(&(reply.p.data[0]), 0, 4);
	reply.p.data[1] = 0xDB; // Seems to be what acorn things do...

	fsop_aun_send (&reply, 4, f);

	clock_gettime(CLOCK_REALTIME, &peek_timeout);
	peek_timeout.tv_sec +=2 ; /* 2 second wait max */

	/* Uses separate mutex in case there are consistency issues with using the main fs_mutex */

	pthread_mutex_lock(&(f->server->fs_mpeek_mutex));
	pthread_cond_timedwait(&(f->server->fs_condition), &(f->server->fs_mpeek_mutex), &peek_timeout);
	pthread_mutex_unlock(&(f->server->fs_mpeek_mutex));

	mtype = stnpeek->mtype; /* If we got no reply, it'll be 0x0000 */

	fs_debug_full (0, 1, f->server, f->net, f->stn, "Machine type received by login task %08X", mtype);

	FS_LIST_SPLICEFREE(f->server->peeks, stnpeek, "FS", "Freeing machinepeek probe structure");

	fsop_00_oscli_extract(f->data, p, 0, username_extract, 10, param_start);

	if (num > 1 && (atof(username_extract) > 0))
	{
		skip_first = 1;
		fsop_00_oscli_extract(f->data, p, 1, username_extract, 10, param_start);
	}

	if (num > (1 + skip_first))
		fsop_00_oscli_extract(f->data, p, 1+skip_first, password_extract, 10, param_start);
	else
		strcpy(password_extract, "");

	fs_copy_padded(username, username_extract, 10);
	fs_copy_padded(password, password_extract, 10);
	fs_toupper(username);
	fs_toupper(password);
			
	counter = 0;

	while (counter < f->server->total_users && !found)
	{
		unsigned char	pwuser[11];

		memcpy (pwuser, &(f->server->users[counter].username), 10);
		pwuser[10] = '\0';

		//fprintf (stderr, "Looking at user %d - '%s' vs '%s'\n", counter, pwuser, username);

		if (!strncasecmp(pwuser, username, 10) && (f->server->users[counter].priv != 0))
			found = 1;
		else
			counter++;
	}

	if (found)
	{
		if (strncasecmp((const char *) f->server->users[counter].password, password, 10))
		{
			unsigned char pw1[11];
			memcpy (pw1, f->server->users[counter].password, 10);
			pw1[10] = '\0';
			fsop_error(f, 0xBC, "Wrong password");
			fs_debug_full(0, 1, f->server, f->net, f->stn, "Login attempt - username '%s' - Wrong password ('%s' vs '%s')", username, password, pw1);
		}
		else if (f->server->users[counter].priv & FS_PRIV_LOCKED)
		{
			fsop_error(f, 0xBC, "Account locked");
			fs_debug_full (0, 1, f->server, f->net, f->stn, "Login attempt - username '%s' - Account locked", username);
		}
		else
		{
			FS_REPLY_DATA(0x80);

			struct __fs_active *a;

			uint8_t err;
			uint8_t	count;
			uint16_t	machine, ver;

			a = f->server->actives;

			// Find a spare slot

			while (a)
			{
				if ((a->net == f->net && a->stn == f->stn)) // Allows us to overwrite an existing handle if the station is already logged in
					break;

				a = a->next;
			}

			if (a) // Log off
			{
				fsop_bye_internal(a, 0, 0); // Silent
			}

			FS_LIST_MAKENEW(struct __fs_active,f->server->actives,1,a,"FS","Login making new active struct");

			a->net = (f->net == 0 ? f->server->net : f->net);
			a->stn = f->stn;
			a->printer = 0xff; // No current printer selected
			a->userid = counter;
			a->user = &(f->server->users[counter]);
			a->bootopt = f->server->users[counter].bootopt;
			a->priv = f->server->users[counter].priv;
			a->userid = counter;
			a->current_disc = f->server->users[counter].home_disc; // Need to set here so that first normalize for URD works.
			a->machinepeek = mtype;
			machine = (mtype & 0xFF000000) >> 24;
			ver = (mtype & 0xFF);
			a->manyhandles = 0;
			if (	(machine == 0x07) // Archimedes
			||	(ver >= 4 && (machine == 0x05 || machine == 0x0A || machine == 0x0C)) // M128, Master ET, Master Compact & ANFS or greater
			)
			{
				a->manyhandles = 1;
				fs_debug_full(0, 1, f->server, a->net, a->stn, "32 Handle mode enabled");
			}

			a->server = f->server;
			a->root = a->current = a->lib = 0; /* Rogue so things don't get closed when they aren't open */
			f->active = a;
			f->userid = counter;

			for (count = 0; count < FS_MAX_OPEN_FILES; count++) a->fhandles[count].handle = NULL; // Flag unused for files

			err = fsop_move_disc (f, a->current_disc);

			if (err != FSOP_MOVE_DISC_SUCCESS)
			{
				/* fsop_move_disc will have cleared down the handles */

				unsigned char   which[5],       error[30];
				unsigned char   errstr[40];

				switch((err & 0x0F))
				{
					case FSOP_MOVE_DISC_URD:	strcpy(which, "URD"); break;
					case FSOP_MOVE_DISC_CWD:	strcpy(which, "CWD"); break;
					case FSOP_MOVE_DISC_LIB:	strcpy(which, "LIB"); break;
				}

				switch ((err & 0xF0))
				{
					case FSOP_MOVE_DISC_NOTFOUND:   strcpy(error, "Not found"); break;
					case FSOP_MOVE_DISC_NOTDIR:     strcpy(error, "Not a directory"); break;
					case FSOP_MOVE_DISC_UNREADABLE: strcpy(error, "Unreadable"); break;
					case FSOP_MOVE_DISC_UNMAPPABLE: strcpy(error, "Unmappable"); break;
					case FSOP_MOVE_DISC_CHANNEL:    strcpy(error, "No available channel"); break;
					case FSOP_MOVE_DISC_INVIS:      strcpy(error, "Disc invisible to user"); break;
				}

				fs_debug (0, 1, "from %3d.%3d Login attempt - %s %s for userid %04X", f->net, f->stn, which, error, a->userid);

				sprintf(errstr, "%s %s", which, error);
				fsop_error (f, 0xFF, errstr);
				FS_LIST_SPLICEFREE(f->server->actives, a, "FS", "Freeing active struct when cannot mount disc");
				return;
			}

			if (a->user->priv2 & FS_PRIV2_CHROOT) // Fudge the root directory information so that $ maps to URD
			{
				char *dollar;

				sprintf(a->root_dir_tail, "$	 ");
				snprintf(a->root_dir, 2600, "$.");
				fs_store_tail_path(a->fhandles[a->root].acorntailpath, "$");
				dollar = strchr(a->fhandles[a->root].acornfullpath, '$');

				*(dollar+1) = 0; // Drop everything after the '.' after the dollar sign

				strcpy(a->current_dir_tail, a->root_dir_tail);
				strcpy(a->current_dir, a->root_dir);
				fs_store_tail_path(a->fhandles[a->current].acorntailpath, "$");
				strcpy(a->fhandles[a->current].acornfullpath, a->fhandles[a->root].acornfullpath);

			}

			// Notify bridge if we have a Bridge priv user

			if (a->user->priv2 & FS_PRIV2_BRIDGE) // Bridge priv user
			{
				eb_fast_priv_notify(a->server->fs_device, f->net, f->stn, 1);
				fs_debug_full (0, 1, a->server, f->net, f->stn, "User %s has bridge privileges", username);
			}

			fs_debug_full (0, 1, a->server, f->net, f->stn, "Login as %s, id %04X, disc %d, URD %s, CWD %s, LIB %s, priv 0x%02x", username, a->userid, a->current_disc, a->root_dir, a->current_dir, a->lib_dir, a->user->priv);

			// Tell the station

			reply.p.data[0] = 0x05;
			reply.p.data[2] = FS_MULHANDLE(a,a->root);
			reply.p.data[3] = FS_MULHANDLE(a,a->current);
			reply.p.data[4] = FS_MULHANDLE(a,a->lib);
			reply.p.data[5] = a->bootopt;

			fsop_aun_send(&reply, 6, f);
		}
	}
	else
	{
		fs_debug_full (0, 1, f->server, f->net, f->stn, "Login attempt - username '%s' - Unknown user", username_extract);
		fsop_error(f, 0xBC, "User not known");
	}
}

FSOP_00(SDISC)
{
	FS_R_DATA(0x80);

	unsigned char	disc[17];
	uint8_t		err, found;
	int		disc_no;
	struct __fs_disc	*d;
	struct __fs_active	*a;

	a = f->active;
	
	if (num == 0) /* *SDISC without a parameter */
		disc_no = f->server->users[f->userid].home_disc;
	else
	{
		fsop_00_oscli_extract(f->data, p, 0, disc, 16, param_start);
	
		disc_no = 0;
	
		if (disc[0] != '0' && disc[1] != '\n')
		{
			disc_no = atoi(disc);
	
			if (disc_no == 0)
			{
				disc_no = fsop_get_discno(f, disc);
			}
		}
	}	

	if (disc_no < 0)
	{
		fsop_error(f, 0xFF, "No such disc");
		return;
	}

	/* Ensure the disc exists */
	
	found = 0;

	d = f->server->discs;

	while (d && !found)
	{
		if (d->index == disc_no)
			found = 1;
		else
			d = d->next;
	}

	if (!found || !FS_DISC_VIS(f->server, f->userid, disc_no))
	{
		fsop_error(f, 0xFF, "No such disc");
		return;
	}

	err = fsop_move_disc (f, f->active->current_disc);

	if (err != FSOP_MOVE_DISC_SUCCESS)
	{
		/* fsop_move_disc will have cleared down the handles */

		unsigned char   which[5],       error[30];
		unsigned char   errstr[40];

		switch((err & 0x0F))
		{
			case FSOP_MOVE_DISC_URD:	strcpy(which, "URD"); break;
			case FSOP_MOVE_DISC_CWD:	strcpy(which, "CWD"); break;
			case FSOP_MOVE_DISC_LIB:	strcpy(which, "LIB"); break;
		}

		switch ((err & 0xF0))
		{
			case FSOP_MOVE_DISC_NOTFOUND:   strcpy(error, "Not found"); break;
			case FSOP_MOVE_DISC_NOTDIR:     strcpy(error, "Not a directory"); break;
			case FSOP_MOVE_DISC_UNREADABLE: strcpy(error, "Unreadable"); break;
			case FSOP_MOVE_DISC_UNMAPPABLE: strcpy(error, "Unmappable"); break;
			case FSOP_MOVE_DISC_CHANNEL:    strcpy(error, "No available channel"); break;
			case FSOP_MOVE_DISC_INVIS:      strcpy(error, "Disc invisible to user"); break;
		}

		fs_debug (0, 1, "%12sfrom %3d.%3d *SDISC to disc %d - %s %s for userid %04X", "", f->net, f->stn, disc_no, which, error, f->userid);

		sprintf(errstr, "%s %s", which, error);
		fsop_error (f, 0xFF, errstr);
		FS_LIST_SPLICEFREE(f->server->actives, f->active, "FS", "Freeing active struct when cannot mount disc");
		return;
	}

	if (f->server->users[f->userid].priv2 & FS_PRIV2_CHROOT) // Fudge the root directory information so that $ maps to URD
	{
		char *dollar;

		sprintf(a->root_dir_tail, "$	 ");
		snprintf(a->root_dir, 2600, "$.");
		fs_store_tail_path(a->fhandles[a->root].acorntailpath, "$");
		dollar = strchr(a->fhandles[a->root].acornfullpath, '$');

		*(dollar+1) = 0; // Drop everything after the '.' after the dollar sign

		strcpy(a->current_dir_tail, a->root_dir_tail);
		strcpy(a->current_dir, a->root_dir);
		fs_store_tail_path(a->fhandles[a->current].acorntailpath, "$");
		strcpy(a->fhandles[a->current].acornfullpath, a->fhandles[a->root].acornfullpath);

	}

	r.p.data[0] = 0x06; /* SDISC Return */
        r.p.data[2] = FS_MULHANDLE(a,a->root);
        r.p.data[3] = FS_MULHANDLE(a,a->current);
        r.p.data[4] = FS_MULHANDLE(a,a->lib);
        r.p.data[5] = a->bootopt;

        fsop_aun_send(&r, 6, f);

}

