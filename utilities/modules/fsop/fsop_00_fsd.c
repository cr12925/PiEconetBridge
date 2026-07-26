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
 * Implements *FSDTEST <drivername> <parameters>
 *
 */

/* Manually defined because this is used for both *. and *CAT */

FSOP_00(FSDTEST)
{
	uint8_t	res, count;
	unsigned char	drivername[24], parameters[1024];

	if (num < 2)
	{
		fsop_error(f, 0xFF, "Insufficient parameters");
		return;
	}

	fsop_00_oscli_extract(f->data, p, 0, drivername, 23, param_start);

	fsop_00_oscli_extract(f->data, p, 1, parameters, 127, param_start);

	count = 2;

	while (count < num)
	{
		char	param[128];

		fsop_00_oscli_extract(f->data, p, count, param, 127, param_start);
		strcat(parameters, " ");
		strcat(parameters,param);
		count++;
	}

	fs_debug_full(0, 1, f->server, f->net, f->stn, "*FSDTEST %s %s", drivername, parameters);

	res = fsd_test_harness(f->server, drivername, parameters);

	if (!res)
		fsop_reply_ok(f);
	else
		fsop_error(f, 0xFF, "Test harness failed");
}

FSOP_00(FSDCMD)
{

	int	res;
	unsigned char	drivername[24];
	fs_device_instance	* instance;
	fs_device_local		* local;
	char 			* fsd_params;

	if (num < 2)
	{
		fsop_error(f, 0xFF, "Insufficient parameters");
		return;
	}

	fsop_00_oscli_extract(f->data, p, 0, drivername, 23, param_start);

	fsd_params = f->data + param_start + strlen(drivername) + 1;

	while (*(fsd_params) == ' ')
		fsd_params++;

	fs_debug_full(0, 1, f->server, f->net, f->stn, "*FSDCMD %s %s", drivername, fsd_params);

	local = fsd_find_local(f->server, drivername);

	if (!local)
		fsop_error(f, 0xFF, "Unknown device driver");
	else
	{
		instance = local->instance;
		res = fsd_cli(instance, fsd_params);

		fs_debug_full(0, 2, f->server, f->net, f->stn, "CLI call to %s driver instance (%p) with string '%s'",
				drivername,
				instance,
				fsd_params);

		switch (res)
		{
			case FSD_SUCCESS:
				fsop_reply_ok(f);
				break;
			case FSD_CLI_UNKNOWN:
				fsop_error(f, 0xFF, "Command unknown to device driver");
				break;
			case FSD_BADPARAMS:
				fsop_error(f, 0xFF, "Bad parameters");
				break;
			default:
				fsop_error(f, 0xFF, "Server error");
				break;
		}
	}
}

