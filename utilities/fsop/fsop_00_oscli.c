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

struct fsop_00_cmd	*fsop_00_cmds = NULL, *fsop_00_cmds_tail = NULL;

/* List of externs, by macro */

/*
 * fsop_00_addcmd (struct fsop_00_cmd *c)
 *
 * Add command to linked list
 */

void fsop_00_addcmd (struct fsop_00_cmd *c)
{

	if (fsop_00_cmds)
	{
		fsop_00_cmds_tail->next = c;
		c->next = NULL;
	}
	else /* List empty */
		fsop_00_cmds = c;

	/* Always - both cases */

	fsop_00_cmds_tail = c;

	return;

}

/* 
 * fsop_00_mkcmd
 *
 * mallocs a fsop_00_cmd structure
 * and populates it. Returns pointer to struct
 */

struct fsop_00_cmd * fsop_00_mkcmd (unsigned char *cmd, uint8_t flags, uint8_t p_min, uint8_t p_max, uint8_t abbrev, oscli_func func)
{
	struct fsop_00_cmd *r;

	r = eb_malloc(__FILE__, __LINE__, "FSOSCLI", "fsop_00_cmd buffer ", sizeof(struct fsop_00_cmd));

	r->next = NULL;
	r->cmd = cmd;
	r->flags = flags;
	r->p_min = p_min;
	r->p_max = p_max;
	r->abbrev = abbrev;
	r->func = func;

	return r;
}

/* 
 * fsop_00_cmdmatch (cmd)
 *
 * Locate (abbreviated) command and return struct or NULL
 *
 * Returns *fsop_00_cmd to show which command, and index in *nextchar is the next character after the command end
 */

struct fsop_00_cmd * fsop_00_match (unsigned char *c, uint8_t *nextchar)
{
	struct fsop_00_cmd 	*t = fsop_00_cmds;

	*nextchar = 0;

	while (t)
	{
		uint8_t		count = 0;

		//fprintf (stderr, "fsop_00_match: Looking at %s (len %d) at %p...", t->cmd, strlen(t->cmd), t);

		// 20241017
		//while (count < strlen(t->cmd))
		while ((count < strlen(t->cmd)) && (*(c+5+count) != 0x0D)) // Catch end of command in packet
		{
			/* Uppercase-ify the command */

			if (*(c+5+count) >= 'a' && *(c+5+count) <= 'z')	*(c+5+count) &= ~0x20;

			/* Compare */

			if (
				!(*(c+5+count) == 0x20 && (*(t->cmd+count)) == 0x80) // Match 0x80 as space
			&&	(*(c+5+count) != (*(t->cmd+count))) 
			) /* No match */
			{
				/* Not matched. Character 0x80 in the table matches space - for *I AM */
				//fprintf (stderr, "%c XXX Failed at character %d\n", *(c+5+count), count+1);
				count = strlen(t->cmd)+1; // Exit this loop
			}
			else
			{
				/* Character matched */
					
				if (
					((count + 1) < strlen(t->cmd)) /* Might be a '.' next - if there is... */
				&&	(*(c+5+count+1) == '.')
				&&	((count+1) >= t->abbrev)
				) /* Found abbreviation */
				
				{
					*nextchar = count+5+2;
					//fprintf (stderr, "%c +++ Abbreviation found, returning nextchar = %d\n", *(c+count), *nextchar);
					return t;
				}

				/* If we're here, we've matched and there are characters still to go */
				//fprintf (stderr, "%c", *(c+5+count));

				count++;
			}
		}

		if (count == strlen(t->cmd)) // NB it will be strlen(t->cmd)+1 if no match
		{
			*nextchar = count+5;

			//fprintf (stderr, " +++ Matched in full, returning nextchar = %d\n", *nextchar);
			return t; /* Must have matched */
		}

		count = 0;
		t = t->next;
	}

	//fprintf (stderr, "XXX End of list - Not found\n");
	return NULL;
}


/*
 * fsop_00_oscli_parse
 *
 * Take a null-terminated or 0x0d string s and fill in *p with
 * an array of start and end points of the parameters
 * in that string, a bit like getopt - but return val = 0 means
 * Command but no parameters
 *
 */

uint8_t fsop_00_oscli_parse(unsigned char *s, struct oscli_params *p, uint8_t start)
{
	uint8_t		count = 0; // String pointer in s
	uint8_t		index = 0; // Last valid entry in the *p array returned + 1 - so if returns 1 then last valid entry is [0]
	uint8_t		len;
	char		*str;

	//fprintf (stderr, "fsop_00_oscli_parse: param_start = %d\n", start);

	str = s + start;

	/* str will already be 0-terminated from the main parser */

	len = strlen(str);

	//fprintf (stderr, "fsop_00_oscli_parse: strlen(%s) = %d\n", str, strlen(str));

	/* Search the string for something which isn't a space, marking each start and end as we go */
	
	while (count < len)
	{
		while (count < len)
		{
			if (*(str+count) == ' ') count++;
			else break;
		}

		if (count < len) /* We've skipped the spaces, mark start and look for end */
		{
			p->op_s = count + start;

			while (count < len && *(str+count) != ' ') count++;

			p->op_e = count - 1 + start;
	
			//fprintf (stderr, "fsop_00_oscli_parse: Parse %s element %d found at %d-%d\n", str, index, p->op_s, p->op_e);
			p++;
			index++;
		}
		else // At end
		{
			return index; // Nothing here
		}

		count++;
	}

	return index; // I.e. number of entries in oscli_params array (returning 1 means entry 0 is valid)

}

/*
 * fsop_00_oscli_extract()
 *
 * Copy a parameter to the string pointer given, up to maximum length specified
 * Resulting string will be null terminated
 *
 * NB: No bounds checking on whether there is a valid index entry in *p!
 *
 */

void fsop_00_oscli_extract(unsigned char *s, struct oscli_params *p, uint8_t index, char *output, uint8_t maxlen, uint8_t param_start)
{
	uint8_t		count = 0;
	uint8_t		real_length;
	char *		start = s; // s+5;

	p += index;

	real_length = (p->op_e - p->op_s) + 1;

	//fprintf (stderr, "fsop_00_oscli_extract from %s index %d between %d and %d\n", start+5, index, p->op_s, p->op_e);

	while (count < maxlen && count < real_length)
	{
		*(output + count) = *(start + count + p->op_s);
		count++;
	}

	*(output + count) = '\0';

	//fprintf (stderr, "fsop_00_oscli_extract returning '%s'\n", output);

	return;

}

/* Hex parameter parser 
 *
 * Returns <>0 for success, 0 for parse failure
 */

uint8_t	 fsop_00_hexparse(char *s, uint8_t maxlen, uint32_t *r)
{
	unsigned char 	c;
	uint32_t	result = 0;
	uint8_t		count = 0;

	while (count < maxlen && count < strlen(s))
	{
		c = *(s+count);

		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'A' && c <= 'F')
			c = c - 'A' + 10;
		else if (c >= 'a' && c <= 'f')
			c = c - 'a' + 10;
		else
			return 0;

		result = (result << 4) + (c);

		count++;
	}

	*r = result;

	return 1;

}

/* Utility routine to put up to a 32-bit value into a reply block, LSB first */

void fsop_lsb_reply (char *source, uint8_t bytes, uint32_t value)
{

	uint8_t count = 0;

	while (count < bytes)
	{
		*(source + count) = (value & (0xff << (count * 8))) >> (count * 8);
		count++;
	}

}

/* Not presently used unless it's a command in the new structure */

FSOP(00)
{

	FS_REPLY_DATA(0x80);
	struct oscli_params p[10]; /* Max 10 things on a command */
	char *	cr;
	struct fsop_00_cmd	*cmd;

	uint8_t		num;
	uint8_t		param_start;

	char *		crptr;

	cr = f->data + f->datalen - 1;
	if (*cr == 0x0d) 	*cr = 0x00; /* Null terminate instead of 0x0d */	

	// 20241017 Need a fix here. Sometimes there is stray data after the 0x0d, eg from an Atom
	
	crptr = memchr(f->data, 0x0d, f->datalen);
	if (crptr)
		*crptr = 0x00;

	if ((cmd = fsop_00_match(f->data, &param_start)))
	{
		//fs_debug (0, 2, "FS Parser found %s", cmd->cmd);

		if (param_start < f->datalen)
			num = fsop_00_oscli_parse(f->data, &p[0], param_start);
		else	num = 0;

		//fs_debug (0, 2, "FS Parser found %s with %d parameters", cmd->cmd, num);
		
		/* If there are parameters, they can't start in the character after the end of a complete command */

		/*
		if (param_start - 5 == strlen(cmd->cmd) && num > 0 && *(f->data + 5 + param_start) != ' ')
			fsop_error (f, 0xff, "Bad command");
			*/

		if ((cmd->flags & FSOP_00_LOGGEDIN) && (!f->user))
			fsop_error (f, 0xff, "Who are you?");
		else if ((cmd->flags & FSOP_00_SYSTEM) && !(f->user->priv & FS_PRIV_SYSTEM))
			fsop_error (f, 0xff, "Insufficient privilege");
		else if ((cmd->flags & FSOP_00_BRIDGE) && !(f->user->priv2 & FS_PRIV2_BRIDGE))
			fsop_error (f, 0xff, "No bridge privilege");
		else if ((cmd->flags & FSOP_00_MDFS) && !(FS_CONFIG(f->server,fs_sjfunc)))
			fsop_error (f, 0xff, "Bad command");
		else if (cmd->p_min > num)
			fsop_error (f, 0xff, "Not enough parameters");
		else if (cmd->p_max < num)
			fsop_error (f, 0xff, "Too many parameters");
		else
			(cmd->func)(f, &p[0], num, param_start);
	}
	else
	{
		reply.p.data[0] = 0x08; // Unknown command
		memcpy(&(reply.p.data[2]), (f->data + 5), f->datalen - 5);
		reply.p.data[f->datalen-5 + 2] = 0x0D;
		fsop_aun_send(&reply,f->datalen-5+2,f);
	}


	return;

}


