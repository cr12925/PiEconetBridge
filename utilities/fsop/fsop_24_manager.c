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
 * Read currently logged on users (extended)
 */

FSOP(21)
{

	FS_REPLY_DATA(0x80);
	FS_REPLY_COUNTER();

	uint8_t		start, number;
	uint16_t	count;
	struct __fs_active	*a;

	start = *(f->data + 5);
	number = *(f->data + 6);

	fs_debug_full(0, 1, f->server, f->net, f->stn, "Read logged on users (extended) start:%d, end:%d - not yet implemented", start, number);

	if (number == 0 || number > 15)
		number = 15; /* Max packet size if a Beeb calls this, which it probably won't, but ... */

	count = 0;
	a = f->server->actives;

	while (count < start && a)
	{
		a = a->next;
		if (a) count++;
	}

	if (!a)
	{
		FS_PUTR8(2, 0); /* Zero entries returned */
		FS_TXR(3);
	}

	/* By here, a points to the first logged on user we're interested in */

	__rcounter = 3;

	count = 1;

	while (count <= number && a)
	{
		unsigned char	username[11];
		uint8_t		un_len;

		memcpy(username, f->server->users[a->userid].username, 10);
		for (uint8_t un_ptr = 0; un_ptr < 10; un_ptr++)
			if (username[un_ptr] == 0x20)
				username[un_ptr] = 0x00;
		username[10] = 0x00;
		un_len = strlen(username);
		username[un_len] = 0x0D; // Acorn termination

		FS_CPUT8(a->stn);
		FS_CPUT8(a->net);
		FS_CPUT8(1); /* Task number again... */
		FS_CPUTD(username, un_len+1);
	}

	FS_PUTR8(2, count);

	FS_CSEND();
}

/*
 * Read single user information (extended)
 */

FSOP(22)
{

	FS_REPLY_DATA(0x80);
	unsigned char	username[11];
	int16_t		uid;
	struct __fs_active	*a;

	fs_copy_to_cr(username, f->data + 5, 10);

	fs_debug_full(0, 1, f->server, f->net, f->stn, "Read user information (extended): user %s  - not yet implemented", username);

	uid = fsop_get_uid(f->server, username);

	if (uid < 0)
	{
		fsop_error (f, 0xBC, "User not known");
		return;
	}

	a = f->server->actives;

	while (a)
	{
		if (a->userid == uid)
			break;
		a = a->next;
	}

	if (!a)
	{
		fsop_error (f, 0xFF, "Not logged on");
		return;
	}

	switch (FS_UINFOU(uid).priv)
	{
		case FS_PRIV_LOCKED:
			FS_PUTR8(2, 0x00);
			break;
		case FS_PRIV_NOPASSWORDCHANGE:
			FS_PUTR8(2, 0x40);
			break;
		case FS_PRIV_USER:
			FS_PUTR8(2, 0x80);
			break;
		case FS_PRIV_SYSTEM:
			FS_PUTR8(2, 0xFF);
			break;
	}

	FS_PUTR8(3, a->stn);
	FS_PUTR8(4, a->net);
	FS_PUTR8(5, 1); /* What IS a task number? */

	FS_TXR(6);

}

uint16_t fsop_24_acorn_active_to_uid (struct fsop_data *f, uint16_t a)
{
	uint16_t 	count = 0;
	uint16_t	number = a;

	while (number > 0 && count < f->server->total_users)
	{
		if (f->server->users[count].priv != FS_PRIV_INVALID)
			number--;
		count++;
	}

	if (count == f->server->total_users) // Not found
		return 0xFFFF;

	return count;
}

/*
 * Manager interface
 */

FSOP(24)
{

	uint8_t		arg = FSOP_ARG;

	FS_REPLY_DATA(0x80);

	switch (arg)
	{
		case 0x00: /* Read number of entries in password file */
		{

			uint16_t	total;
			uint16_t	count;

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - read number of password file entries");

			total = 0;

			count = 0;

			while (count < f->server->total_users)
			{
				if (f->server->users[count].priv != FS_PRIV_INVALID)
					total++;
				count++;
			}

			FS_PUTR32(2, total);
			FS_TXR(6);

		} break;

		case 0x01: /* Read entry from password file */
		{
			uint16_t	uid, number;
			uint8_t		acorn_priv;
			unsigned char	username[11], password[11];
			struct __fs_active	*a;
			uint8_t		net, stn;
			unsigned char	urd[81];
			uint16_t	urd_length;
			char *		space;

			number = *(f->data + 6) + (*(f->data + 7) << 8);

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - read entry %04X from password file", number);

			uid = fsop_24_acorn_active_to_uid (f, number);

			if (uid == 0xFFFF) /* Rogue for not found */
			{
				fsop_error (f, 0xBC, "User not known");
				return;
			}

			if (uid > f->server->total_users)
			{
				fsop_error(f, 0xBC, "User not known");
				return;
			}

			acorn_priv = 0x80; /* Acorn normal priv */

			switch (f->server->users[uid].priv)
			{
				case FS_PRIV_LOCKED:
					acorn_priv = 0x00; break;
				case FS_PRIV_SYSTEM:
					acorn_priv = 0xFF; break;
				case FS_PRIV_NOPASSWORDCHANGE:
					acorn_priv = 0x40; break;
			}

			a = f->server->actives;
			net = stn = 0;

			while (a)
			{
				if (a->userid == uid)
				{
					net = a->net;
					stn = a->stn;
					break;
				}

				a = a->next;
			}

			fs_copy_to_cr (username, f->server->users[uid].username, 10);
			fs_copy_to_cr (password, f->server->users[uid].password, 10);

			if (strchr(username, ' '))
				*(strchr(username, ' ')) = 0x0D;
			else	username[10] = 0x0D;

			if (strchr(password, ' '))
				*(strchr(password, ' ')) = 0x0D;
			else	password[10] = 0x0D;

			memcpy(urd, FS_UINFOU(uid).home, 80);
			urd[80] = 0x00;
			space = strchr(urd, ' ');
			if (!space)
			{
				urd[80] = 0x0D;
				urd_length = 81; /* As we didn't find a space, we'll put 0x0D at character 80 (the 81st entry in the array) because we need to 0x0D-terminate the URD. Then it's 81 characters long. */
			}
			else
			{
				*space = 0x00; /* Terminate with NULL at the first space */
				urd_length = strlen(urd)+1; /* Find the length using standard function. Add 1 so we copy the 0x0D below */
				*space = 0x0D; /* Turn it into a 0x0D for acorn */
			}

			FS_PUTR32(2, 1);
			FS_PUTR8(6, acorn_priv);
			FS_PUTR8(7,FS_UINFOU(uid).bootopt);
			FS_PUTR32(8, 0x20202020); /* The spec wants 4 spaces, so a 32-bit where each byte is 0x20... */
			FS_PUTR8(12, stn);
			FS_PUTR8(13, net);
			if (FS_UINFOU(uid).priv == FS_PRIV_LOCKED)
			{
				FS_PUTR8(14, 0);
			}
			else	{ FS_PUTR8(14, 1); }
			FS_PUTRD(15, username, 11);
			FS_PUTRD(37, password, 11);
			FS_PUTRD(60, urd, urd_length+1);

			FS_TXR(60+urd_length+1);

		} break;

		case 0x02: /* Write user profile in password file */
		{
			unsigned char	username[11]; 
			unsigned char	password[24];
			unsigned char	urd[81];
			uint8_t	 	priv;
			int16_t		uid;
			uint8_t		count;
			struct __fs_user	*u;
			
			fs_copy_to_cr (username, f->data+19, 10);
			fs_toupper(username);

			fs_copy_to_cr (password, f->data+41, 23);

			fs_copy_to_cr (urd, f->data+64, 80);
			fs_toupper(urd);

			/* Pad password */

			for (count = strlen(password); count < 10; count++)
				password[count] = 0x20; // Space

			/* Pad URD */

			for (count = strlen(urd); count < 80; count++)
				urd[count] = 0x20;

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - write entry for %s to password file", username);
	
			uid = fsop_get_uid (f->server, username);

			if (uid < 0)
			{
				fsop_error (f, 0xBC, "User not known");
				return;
			}

			u = &(f->server->users[uid]);

			if (strlen(password) > 10)
			{
				fsop_error (f, 0xFF, "Password too long");
				return;
			}	

			u->bootopt = *(f->data + 11);

			priv = *(f->data + 10); // Uppercase, just in case...

			switch (priv)
			{
				case 0x00:
					u->priv = FS_PRIV_LOCKED;
					break;
				case 0xFF:
					u->priv = FS_PRIV_SYSTEM;
					break;
				case 0x40:
					u->priv = FS_PRIV_NOPASSWORDCHANGE;
					break;
				case 0x80:
					u->priv = FS_PRIV_USER;
					break;
				default:
					fsop_error (f, 0xFF, "Bad privilege");
					return;
					break;
			}

			memcpy(&(u->home), urd, 80);
			memcpy(&(u->password), password, 10);
			
			fsop_reply_ok(f);

		} break;

		case 0x03: /* Add new user - some code need turning into a function as between this and *NEWUSER */
		{
			unsigned char	username[11]; 
			int16_t		userid;
			struct __fs_user	*user;
			uint8_t		disc_index;
			struct __fs_disc	*disc, *disc_found;
			
			fs_copy_to_cr (username, f->data+6, 10);
			fs_toupper(username);

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - add new user %s", username);

			/* This doesn't create a home directory... */

			if ((userid = fsop_get_uid(f->server, username)) >= 0)
			{
				fsop_error(f, 0xFF, "User exists");
				return;
			}

			userid = 0;

			/* Find spare user */

			while (userid < f->server->total_users) /* *NEWUSER has 32768, but I think that'll maybe segfault when we go beyond the endo f the file ! */
			{
				if (f->server->users[userid].priv == 0)
					break;
				userid++;
			}

			if (userid == f->server->total_users)
			{
				fsop_error (f, 0xFF, "Password file full");
				return;
			}

			/* Find first disc */

			disc = f->server->discs;
			disc_index = 255;

			disc_found = NULL;

			while (disc)
			{
				if (disc->index < disc_index)
				{
					disc_index = disc->index;
					disc_found = disc;
				}

				disc = disc->next;
			}

			if (!disc_found)
			{
				fsop_error (f, 0xFF, "No discs found");
				return;
			}

			user = &(f->server->users[userid]);

		        snprintf((char * ) user->username, 11, "%-10s", username);
		        snprintf((char * ) user->password, 11, "%-10s", "");
        		snprintf((char * ) user->home, 97, "$.%s", username);
        		snprintf((char * ) user->lib, 97, "$.%s", "Library");
        		user->home_disc = disc_index;
			user->priv = FS_PRIV_USER;
        		user->priv2 = 0x00; // clear priv2 byte
        		user->quota_free[0] = (f->server->fs_device->local.fs.new_user_quota & 0xff);
        		user->quota_free[1] = (f->server->fs_device->local.fs.new_user_quota & 0xff00) >> 8;
        		user->quota_free[2] = (f->server->fs_device->local.fs.new_user_quota & 0xff0000) >> 16;
        		user->quota_free[3] = (f->server->fs_device->local.fs.new_user_quota & 0xff000000) >> 24;
			
			fsop_reply_ok(f);

		} break;

		case 0x04: /* Remove user */
		{

			unsigned char	username[11]; 
			int16_t		uid;
			
			fs_copy_to_cr (username, f->data+6, 10);
			fs_toupper(username);

			uid = fsop_get_uid(f->server, username);

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - remove user %s", username);

			if (uid < 0)
			{
				fsop_error(f, 0xBC, "User not known");
				return;
			}

			f->server->users[uid].priv = 0x00;

			fsop_reply_ok(f);

		} break;

		case 0x05: /* Set privilege */
		{
			unsigned char	username[11]; 
			uint8_t		priv;
			uint8_t		ptr = 5;
			int16_t		uid;
			
			fs_copy_to_cr (username, f->data+5, 10);
			fs_toupper(username);

			while ((ptr < f->datalen) && (*(f->data + ptr) != 0x0d))
				ptr++;

			if (ptr == f->datalen) /* Ran out of packet! */
			{
				fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - set privilege for user %s (no privilege byte found)", username);
				fsop_error(f, 0xFF, "No privilege byte found");
				return;
			}

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - set privilege for user %s to '%c'", username, (priv == 0x00) ? 'N' : priv);

			uid = fsop_get_uid(f->server, username);

			if (uid < 0)
			{
				fsop_error(f, 0xBC, "User not known");
				return;
			}
			
			ptr++;
			priv = *(f->data + ptr); /* 0x00 = Locked, 0x40 = Fixed, 0x80 = Normal, 0xFF = System */
			
			switch (priv)
			{
				case 0xFF : FS_UINFOU(uid).priv = FS_PRIV_SYSTEM; break;
				case 0x00 : FS_UINFOU(uid).priv = FS_PRIV_LOCKED; break;
				case 0x40 : FS_UINFOU(uid).priv = FS_PRIV_NOPASSWORDCHANGE; break;
				case 0x80: FS_UINFOU(uid).priv = FS_PRIV_USER; break;
				default:
					   {
						   fsop_error(f, 0xFF, "Bad privilege");
						   return;
					   } break;
			}

			fsop_reply_ok(f);


		} break;

		case 0x06: /* Logoff user */
		{
			unsigned char	username[11]; 
			int16_t 	uid;
			struct	__fs_active	*a;
			uint8_t		success = 0;

			a = f->server->actives;
			
			fs_copy_to_cr (username, f->data+5, 10);
			fs_toupper(username);

			uid = fsop_get_uid(f->server, username);

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - force log off user %s (%s)", username, (uid < 0 ? "unknown" : "found"));

			if (uid < 0)
			{
				fsop_error (f, 0xBC, "User not known");
				return;
			}

			while (a)
			{
				struct __fs_active *n;

				n = a->next;

				if (a->userid == uid)
				{
					fsop_bye_internal(a, 0, 0);
					success = 1;
				}

				a = n;
			}

			if (success)
				fsop_reply_ok(f);
			else	fsop_error(f, 0xFF, "Not logged on");

		} break;

		case 0x07: /* Shut down server */
		{

			fs_debug_full(0, 1, f->server, f->net, f->stn, "Manager interface - shut down server");
			fsop_error(f, 0xFF, "Bad argument");

		} break;

		default:
		{
			fsop_error(f, 0xFF, "Bad argument");
			return;
		} break;
	}
	
	return;

}

