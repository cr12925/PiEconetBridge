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
 */

struct fsop_00_cmd * fsop_00_match (unsigned char *c)
{
	struct fsop_00_cmd 	*t = fsop_00_cmds;

	while (t)
	{
		uint8_t		count = 0;

		//fprintf (stderr, "fsop_00_match: Looking at %s (len %d) at %p...", t->cmd, strlen(t->cmd), t);

		while (count < strlen(t->cmd))
		{
			/* Uppercase-ify the command */

			if (*(c+count) >= 'a' && *(c+count) <= 'z')	*(c+count) &= ~0x20;

			/* Compare */

			if (
				!(*(c+count) == 0x20 && (*(t->cmd+count)) == 0x80) // Match 0x80 as space
			&&	(*(c+count) != (*(t->cmd+count))) 
			) /* No match */
			{
				/* Not matched. Character 0x80 in the table matches space - for *I AM */
				//fprintf (stderr, "%c XXX Failed at character %d\n", *(c+count), count+1);
				count = strlen(t->cmd)+1; // Exit this loop
			}
			else
			{
				/* Character matched */
	
				if (
					((count + 1) < strlen(t->cmd)) /* Might be a '.' next - if there is... */
				&&	(*(c+count+1) == '.')
				&&	((count+1) >= t->abbrev)
				) /* Found abbreviation */
				
				{
					//fprintf (stderr, "%c +++ Abbreviation found\n", *(c+count));
					return t;
				}

				/* If we're here, we've matched and there are characters still to go */
				//fprintf (stderr, "%c", *(c+count));

				count++;
			}
		}

		if (count == strlen(t->cmd)) // NB it will be strlen(t->cmd)+1 if no match
		{
			//fprintf (stderr, " +++ Matched in full\n");
			return t; /* Must have matched */
		}

		count = 0;
		t = t->next;
	}

	//fprintf (stderr, " XXX End of list - Not found\n");
	return NULL;
}


/*
 * fsop_00_oscli_parse
 *
 * Take a null-terminated or 0x0d string s and fill in *p with
 * an array of start and end points of the parameters (including
 * the first) in that string, a bit like getopt.
 *
 */

uint8_t fsop_00_oscli_parse(unsigned char *s, struct oscli_params *p)
{
	uint8_t		count = 0; // String pointer in s
	uint8_t		index = 0; // Last valid entry in the *p array returned + 1 - so if returns 1 then last valid entry is [0]
	uint8_t		len;

	len = strlen(s);

	if (len > 0 && s[len-1] == 0x0d)
	{
		s[len-1] = 0x00;
		len--; // Ignore a training 0x0d in beeb world
	}

	/* Search the string for something which isn't a space, marking each start and end as we go */
	
	while (count < len)
	{
		while (count < len)
		{
			if (*(s+count) == ' ') count++;
			else break;
		}

		if (count < len) /* We've skipped the spaces, mark start and look for end */
		{
			p->op_s = count;

			while (count < len && *(s+count) != ' ') count++;

			p->op_e = count-1;
	
			//fprintf (stderr, "fsop_oscli_parse: Parse %s element %d found at %d-%d\n", s, index, p->op_s, p->op_e);
			p++;
			index++;
		}
		else // At end
		{
			return index; // Nothing here
		}
	}

	return index;

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

void fsop_00_oscli_extract(unsigned char *s, struct oscli_params *p, uint8_t index, char *output, uint8_t maxlen)
{
	uint8_t		count = 0;
	uint8_t		real_length;

	p += index;

	real_length = (p->op_e - p->op_s) + 1;
	//fprintf (stderr, "fsop_00_oscli_extract from %s index %d between %d and %d\n", s, index, p->op_s, p->op_e);

	while (count < maxlen && count < real_length)
	{
		*(output + count) = *(s + count + p->op_s);
		count++;
	}

	*(output + count) = '\0';

	return;

}

/* Not presently used unless it's a command in the new structure */

FSOP(00)
{

	struct oscli_params p[10]; /* Max 10 things on a command */

	uint8_t		num;

	num = fsop_00_oscli_parse(f->data, &p[0]);

	if (!num)
	{
		fsop_error(f, 0xFF, "Bad command");
	}

	return;

}


