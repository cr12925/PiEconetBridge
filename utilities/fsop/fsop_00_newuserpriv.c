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
 * Implements
 *
 * *BRIDGEUSER <username>
 * *NEWUSER <username> (<priv-string>)
 * *PRIV <username> (<priv-string>)
 * *REMUSER <username>
 *
 * If priv-string is omitted in either case, privilege
 * will be set to that of an ordinary user.
 *
 * Where
 * 
 * <priv-string> = (<+->)<privs>(<+-><privs>)+
 *
 * <privs> =
 * D - Delete user (deletes whether in + or - mode)
 * S - System user
 * L - Locked normal user
 * N - Unlocked user but cannot change password
 * C - Chroot user
 * R - Normal root (= -C)
 * H - Hide other users
 * V - Show other users (= -H)
 * A - ANFS Name Bodge
 * B - Turn off ANFS Name Bodge (= -A)
 * O - Cannot change boot opt
 */

void fsop_set_priv_byte(struct __fs_user *u, uint8_t priv, uint8_t priv2)
{
	u->priv = priv;
	u->priv2 = priv2;
}

uint8_t fsop_parse_priv(char *str, uint8_t *priv, uint8_t *priv2)
{
	uint8_t		direction = 1; /* 1 = +, 0 = - */
	uint8_t		count = 0;
	uint8_t		priv_set, priv2_set;

	priv_set = *priv;
	priv2_set = *priv2;

	while (count < strlen(str))
	{
		if ((*(str+count) >= 'a') && (*(str+count) <= 'z')) *(str+count) &= 0xDF; /* Capitalize */

		switch (*(str+count))
		{
			case '+': direction = 1; break;
			case '-': direction = 0; break;
			case 'S': { if (direction) { priv_set = FS_PRIV_SYSTEM; } else { priv_set = FS_PRIV_USER; } }; break;
			case 'U': { if (direction) { priv_set = FS_PRIV_USER; } else { return 0; } }; break;
			case 'L': { if (direction) { priv_set = FS_PRIV_LOCKED; } else { priv_set = FS_PRIV_USER; } }; break;
			case 'N': { if (direction) { priv_set = FS_PRIV_NOPASSWORDCHANGE; } else { priv_set = FS_PRIV_USER; } }; break;
			case 'D': { if (direction) { priv_set = 0; } else { return 0; } }; break;
			case 'C': { if (direction) { priv2_set |= FS_PRIV2_CHROOT; } else { priv2_set &= ~FS_PRIV2_CHROOT; } }; break;
			case 'R': { if (direction) { priv2_set &= ~FS_PRIV2_CHROOT; } else { return 0; } }; break;
			case 'H': { if (direction) { priv2_set |= FS_PRIV2_HIDEOTHERS; } else { priv2_set &= ~FS_PRIV2_HIDEOTHERS; } }; break;
			case 'V': { if (direction) { priv2_set &= ~FS_PRIV2_HIDEOTHERS; } else { return 0; } }; break;
			case 'A': { if (direction) { priv2_set |= FS_PRIV2_ANFSNAMEBODGE; } else { priv2_set &= ~FS_PRIV2_ANFSNAMEBODGE; } }; break;
			case 'B': { if (direction) { priv2_set &= ~FS_PRIV2_ANFSNAMEBODGE; } else { return 0; } }; break;
			case 'O': { if (direction) { priv2_set |= FS_PRIV2_FIXOPT; } else { priv2_set &= ~FS_PRIV2_FIXOPT; } }; break;
			default: return 0; break;
		}

		count++;
	}

	*priv = priv_set;
	*priv2 = priv2_set;

	return 1;

}

FSOP_00(NEWUSER)
{
	unsigned char		username[11];
	unsigned char		priv_string[30];
	uint8_t			priv, priv2;
	int16_t			userid;
	char 			homepath[300];
	char 			acorn_homepath[300];
	struct __fs_user	*user;
	uint8_t			disc_index;
	struct __fs_disc	*disc, *disc_found;
	uint8_t			ftype;

	priv = priv2 = 0;

	FSOP_EXTRACT(f,0,username,10);

	fs_toupper(username);

	if ((userid = fsop_get_uid(f->server, username)) >= 0)
	{
		fsop_error(f, 0xFF, "User exists");
		return;
	}

	priv = FS_PRIV_USER;

	if (num == 2)
	{
		FSOP_EXTRACT(f,1,priv_string,29);
		if (!fsop_parse_priv(priv_string, &priv, &priv2))
		{
			fsop_error (f, 0xFF, "Bad privilege");
			return;
		}
	}

	/* Find a spare user */

	userid = 0;

	while (userid < 32768)
	{
		if (f->server->users[userid].priv == 0)
			break;
		else	userid++;
	}

	if (userid == 32768)
	{
		fsop_error (f, 0xFF, "No available users");
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
	user->priv2 = priv2; // clear priv2 byte
	user->quota_free[0] = (f->server->fs_device->local.fs.new_user_quota & 0xff);
	user->quota_free[1] = (f->server->fs_device->local.fs.new_user_quota & 0xff00) >> 8;
	user->quota_free[2] = (f->server->fs_device->local.fs.new_user_quota & 0xff0000) >> 16;
	user->quota_free[3] = (f->server->fs_device->local.fs.new_user_quota & 0xff000000) >> 24;

	sprintf(homepath, "%s/%1x%s/%s", f->server->directory, 0, disc_found->name, username);
	sprintf(acorn_homepath, ":%s.$.%s", disc_found->name, username);

	ftype = fsop_exists(f, acorn_homepath);

	if (ftype == FS_FTYPE_NOTFOUND)
	{
		if (mkdir((const char *) homepath, 0770) != 0)
			fsop_error(f, 0xff, "Unable to create home directory");
		else
			ftype = FS_FTYPE_DIR; // Successfully created the dir
	}

	if (ftype != FS_FTYPE_DIR)
	{
		fs_debug (0, 1, "%12sfrom %3d.%3d New user %s's home path exists and is not a directory - fs_exists() returned %d", "", f->net, f->stn, username, ftype);
		fsop_error(f, 0xff, "Home path exists and is wrong type");
	}
	else
	{
		user->priv = priv;

		fsop_write_xattr(homepath, userid, FS_PERM_OWN_W | FS_PERM_OWN_R, 0, 0, userid, f); // Set home ownership. Is there a mortgage?

		fs_debug (0, 1, "%12sfrom %3d.%3d New User %s, id = %04X", "", f->net, f->stn, username, userid);

		fsop_reply_ok(f);
	}

}

FSOP_00(PRIV)
{
	unsigned char		username[11];
	unsigned char		priv_string[30];
	uint8_t			priv, priv2;
	int16_t			userid;
	
	FSOP_EXTRACT(f,0,username,10);

	userid = fsop_get_uid(f->server, username);

	if (userid < 0)
		fsop_error(f, 0xFF, "Unknown user");
	else
	{
		priv = f->server->users[userid].priv;
		priv2 = f->server->users[userid].priv2;

		if (num < 1)
		{
			priv = FS_PRIV_USER;
			priv2 = 0;
		}
		else
		{
			FSOP_EXTRACT(f,1,priv_string,29);
			if (!fsop_parse_priv(priv_string, &priv, &priv2))
			{
				fsop_error(f, 0xFF, "Bad privilege");
				return;
			}
		}

		fsop_set_priv_byte(&(f->server->users[userid]), priv, priv2); 
		fsop_reply_ok(f);
	}
}

FSOP_00(REMUSER)
{

	unsigned char		username[11];
	int16_t			userid;

	FSOP_EXTRACT(f,0,username,10);

	userid = fsop_get_uid(f->server, username);

	if (userid < 0)
		fsop_error(f, 0xFF, "Unknown user");
	else
	{
		fsop_set_priv_byte(&(f->server->users[userid]), 0, 0); 
		fsop_reply_ok(f);
	}
}

FSOP_00(BRIDGEUSER)
{

	unsigned char		username[11];
	int16_t			userid;

	FSOP_EXTRACT(f,0,username,10);

	userid = fsop_get_uid(f->server, username);

	if (userid < 0)
		fsop_error(f, 0xFF, "Unknown user");
	else
	{
		fsop_set_priv_byte(&(f->server->users[userid]), f->server->users[userid].priv, (f->server->users[userid].priv2 | FS_PRIV2_BRIDGE)); 
		fsop_reply_ok(f);
	}
}
