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

#include <json.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "econet-hpbridge.h"

uint8_t eb_readconfig_json(char *path)
{
	struct json_object	*conf, *econets, *virtuals, *trunks, *aun_remotes, *exposures, *pools, *filters, *general;
	struct json_object_iterator	it, itEnd;

	if (access(path, R_OK))
		eb_debug (1, 0, "JCONFIG", "Unable to open config file: %s", path);

	conf = json_object_from_file(path);

	if (!conf) /* Something went wrong */
		eb_debug (1, 0, "JCONFIG", "JSON config failed to parse");

	it = json_object_iter_begin(conf);
	itEnd = json_object_iter_end(conf);

	/* For some reason, 0.12 of json-c in PiOS doesn't have the json_pointer stuff :( */
	/* So we have to iterate... */

	econets = virtuals = trunks = general = NULL;

	while (!json_object_iter_equal(&it, &itEnd))
	{
		char	name[128];

		strncpy(name, json_object_iter_peek_name(&it), 128);

		if (!strcasecmp(name, "econets"))
		{
			fprintf (stderr, "Econets object found\n");
			econets = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "virtuals"))
		{
			fprintf (stderr, "Virtuals object found\n");
			virtuals = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "aun_remotes"))
		{
			fprintf (stderr, "AUNs object found\n");
			aun_remotes = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "exposures"))
		{
			fprintf (stderr, "Exposures object found\n");
			exposures = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "trunks"))
		{
			fprintf (stderr, "Trunks object found\n");
			trunks = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "pools"))
		{
			fprintf (stderr, "Pools object found\n");
			pools = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "filterss"))
		{
			fprintf (stderr, "Filterss object found\n");
			filters = json_object_iter_peek_value(&it);
		}
		else if (!strcasecmp(name, "config"))
		{
			fprintf (stderr, "Config object found\n");
			general = json_object_iter_peek_value(&it);
		}
		else
			eb_debug (1, 0, "CONFIG", "Unknown JSON configuration item: %s", name);

		json_object_iter_next(&it);
	}

	return 1;

}
