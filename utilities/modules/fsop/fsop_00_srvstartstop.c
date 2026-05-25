/*
  (c) 2026 Chris Royle
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
 * Implements *SRVSTART [<server>] <modulename>
 * and
 * *SRVSTOP (likewise)
 */

struct __eb_device * srv_parse_stn (char *station)
{
	struct __eb_device *d = NULL;
	uint8_t	net, stn;

	if (
		isdigit(*station)
	&& 	(sscanf(station, "%hhd.%hhd", &net, &stn) == 2)
	&&	!(net == 0 || net > 254 || stn == 0 || stn > 254)
	)
	{
		d = eb_find_station_internal (net, stn);

		if (d->type != EB_DEF_LOCAL)
			d = NULL; /* Only return local stations */
	}

	return d;
}

FSOP_00(SRVSTART)
{
	unsigned char 	station[8], module[9];
	struct __eb_device *device = f->server->fs_device;

	if (num == 2) /* Parse station number */
	{
		FSOP_EXTRACT(f,0,station,7);

		if (!(device = srv_parse_stn(station)))
		{
			fsop_error(f, 0xff, "Bad station number");
			return;
		}
	}

	if (num == 1)
		FSOP_EXTRACT(f,0,module,8);
	else	FSOP_EXTRACT(f,1,module,8);

	fs_debug_full (0, 1, f->server, f->active->net, f->active->stn, "Requested start up of %s module on %d.%d", module, device->net, device->local.stn);

	if (eb_module_start_byname(device,module))
		fsop_error(f, 0xff, "Service failed to start");
	else	fsop_reply_ok(f);
}


FSOP_00(SRVSTOP)
{
	unsigned char 	station[8], module[9];
	struct __eb_device *device = f->server->fs_device;

	if (num == 2) /* Parse station number */
	{
		FSOP_EXTRACT(f,0,station,7);

		if (!(device = srv_parse_stn(station)))
		{
			fsop_error(f, 0xff, "Bad station number");
			return;
		}
	}

	if (num == 1)
		FSOP_EXTRACT(f,0,module,8);
	else	FSOP_EXTRACT(f,1,module,8);

	fs_debug_full (0, 1, f->server, f->active->net, f->active->stn, "Requested stop of %s module on %d.%d", module, device->net, device->local.stn);

	if (device == f->server->fs_device && !strcasecmp(module,"FS")) /* Attempt to stop local fileserver */
	{
		struct __eb_device_module *m;

		/* Don't call eb_module_stop on our own server - it
		 * will try to take module_mutex, which we already hold.
		 */

		if ((m = eb_module_get_data(device, "FS")))
		{
			m->module_exiting = 1;
			fs_debug_full (0, 1, f->server, 0, 0, "Requested shutdown of local fileserver");
			fsop_reply_ok(f);
		}
		else	fsop_error(f, 0xff, "Internal error");
	}
	else
	{
		if (eb_module_stop_byname(device,module))
			fsop_error(f, 0xff, "Service failed to stop");
		else	fsop_reply_ok(f);
	}
}

