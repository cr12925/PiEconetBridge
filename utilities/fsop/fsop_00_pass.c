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

/* Implements *PASS <oldpw> <newpw>
 */

FSOP_00(PASS)
{
	unsigned char pw_cur[11], pw_new[13], pw_new_unq[11], pw_old[11]; // pw_new is 13 to cope with 10 character password in quotes
	unsigned char pw_new_padded[11];

	if (f->server->users[f->userid].priv & FS_PRIV_NOPASSWORDCHANGE)
	{
		fsop_error(f, 0xBA, "Insufficient privilege");
		return;
	}

	memcpy(pw_cur, f->server->users[f->userid].password, 10);
	pw_cur[10] = '\0';

	FSOP_EXTRACT(f,0,pw_old,10);
	if (num > 1)
		FSOP_EXTRACT(f,1,pw_new,12);
	else
		strcpy(pw_new, "          ");

	if (pw_new[0] == '\"' && pw_new[strlen(pw_new)-1] == '\"')
	{
		memcpy(pw_new_unq, &(pw_new[1]), strlen(pw_new)-2);
		pw_new_unq[strlen(pw_new)-2] = '\0';
	}
	else if (
			(pw_new[0] == '\"' && pw_new[strlen(pw_new)-1] != '\"')
		||	
			(pw_new[0] != '\"' && pw_new[strlen(pw_new)-1] == '\"')
		)
		fsop_error(f, 0xB9, "Bad password"); // Because it's quotes are unbalanced
	else
		strcpy(pw_new_unq, pw_new);

	fs_copy_padded(pw_new_padded, pw_new_unq, 10);

	fprintf (stderr, "pw_old = '%s', pw_new = '%s', pw_new_unq = '%s', pw_new_padded = '%s'\n", pw_old, pw_new, pw_new_unq, pw_new_padded);

	if (
			(!strcmp(pw_old, "\"\"") && !strcmp(pw_cur, "          "))
		||	(!strncasecmp(pw_cur, pw_old, 10))
	) /* Old password verified */
	{
		unsigned char username[10];
		unsigned char blank_pw[11];

		strcpy ((char * ) blank_pw, (const char * ) "          ");

		// Correct current password
		
		memcpy(&(f->server->users[f->userid].password), pw_new_padded, 10);

		fsop_reply_success(f, 0, 0);

		strncpy((char *) username, (const char *) f->server->users[f->userid].username, 10);
		username[10] = 0;
		fs_debug_full (0, 1, f->server, f->net, f->stn, "User %s changed password", username);
	}
	else    
		fsop_error(f, 0xB9, "Bad password");

}

FSOP_00(SETPASS)
{
	unsigned char   username[11], password[13];
	unsigned char	password_padded[11];
	uint16_t	count;

	int16_t		userid;

	FSOP_EXTRACT(f, 0, username, 10);
	FSOP_EXTRACT(f, 1, password, 12); /* In case of quotes */

	userid = fsop_get_uid(f->server, username);

	if (userid < 0)
	{
		fs_debug (0, 1, "%12sfrom %3d.%3d *SETPASS %s %s (user UNKNOWN)", "", f->net, f->stn, username, password);
		fsop_error (f, 0xfF, "Unknown user");
		return;
	}

	fs_debug (0, 1, "%12sfrom %3d.%3d *SETPASS %s %s (user ID %d)", "", f->net, f->stn, username, password, userid);

	if (password[0] == '"' && password[strlen(password)-1] == '"')
		strncpy(password_padded, &(password[1]), 10);
	else if (strlen(password) > 10)
	{
		fsop_error (f, 0xFF, "Password too long");
		return;
	}
	else
		strcpy(password_padded, password);

	count = 0;

	if (strlen(password_padded) < 10)
		for (count = strlen(password_padded); count < 10; count++)
			password_padded[count] = 0x20;

	password_padded[10] = '\0';

	memcpy (&(f->server->users[userid].password), password_padded, 10);

	fsop_reply_ok(f);

}
