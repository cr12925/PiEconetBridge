/*
  (c) 2025 Chris Royle
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

#include "econet-hpbridge.h"

char * eb_module_to_upper(char *c)
{
	unsigned char *l, *p;

	p = eb_malloc (__FILE__, __LINE__, "MODULE", "Space for module name in uppercase", strlen(c)+1);

	memcpy (p, c, strlen(c)+1);

	l = p;

	while (*l != '\0')
	{
		if (*l >= 'a' && *l <= 'z')
			*l &= 0xDF;
		l++;
	}

	return p;
}

/* eb_module_register
 *
 * Called by a module's init function to obtain private workspace and register the module
 */

struct __eb_device_module * eb_module_register (void *d_in, unsigned char *modname, uint32_t ws_size)
{
	struct __eb_device_module *workspace = NULL;
	unsigned char		ucmodname[9];
	struct __eb_device *	d = (struct __eb_device *) d_in;
	uint8_t			modname_len;
	char *			u;

	if (d->type != EB_DEF_LOCAL)
	{
		eb_debug (1, 0, "MODULE", "Attempt by module %s to register itself on a non-local device", modname);
		return NULL;
	}

	modname_len = strlen(modname);

	eb_debug (0, 2, "MODULE", "         %3d.%3d Registering module name %s", d->net, d->local.stn, modname);

	if (modname_len == 0 || modname_len > 8)
		return NULL;

	snprintf (ucmodname, 9, "%-8s", (u = eb_module_to_upper(modname)));
	eb_free (__FILE__, __LINE__, "MODULE", "Free uppercase module name", u);

	pthread_mutex_lock(&(d->local.modules_mutex));

	/* Check to see if exists */

	workspace = d->local.modules;

	while (workspace)
	{
		if (!strcmp(workspace->module_name, ucmodname))
		{
			eb_debug (0, 1, "MODULE", "      %3d.%3d Attempt to register module %s which is already registered", modname);
			return NULL;
		}

		workspace = workspace->next;
	}

	workspace = eb_malloc(__FILE__, __LINE__, ucmodname, "Allocate module space", sizeof (struct __eb_device_module));

	snprintf (workspace->module_name, 9, "%-8s", ucmodname);

	workspace->module_ws = NULL;

	if (ws_size > 0)
		workspace->module_ws = eb_malloc(__FILE__, __LINE__, modname, "Allocate private workspace for module", ws_size);

	workspace->module_started = 0;
	workspace->module_autostart = 1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	workspace->module_init = workspace->module_start = workspace->module_stop = workspace->module_exit = NULL;
#pragma GCC diagnostic pop

	workspace->module_thread = 0;

	if (pthread_mutex_init(&(workspace->module_mutex), NULL)) // !0 = fail
		eb_debug (1, 0, "MODULE", "Failed to initialize module mutex for %s module", workspace->module_name);

	if (pthread_cond_init(&(workspace->module_cond), NULL)) // !0 = fail
		eb_debug (1, 0, "MODULE", "Failed to initialize module condition for %s module", workspace->module_name);
	
	workspace->next = d->local.modules;
	d->local.modules = workspace;
	pthread_mutex_unlock(&(d->local.modules_mutex));

	return workspace;

}

/* Deregistration */

void eb_module_deregister (void *d_in, struct __eb_device_module *m)
{

	struct __eb_device_module *p, *pprev = NULL;
	struct __eb_device *	d = (struct __eb_device *) d_in;

	eb_debug (0, 2, "MODULE", "      %3d.%3d Atetmpting to deregister module %s", m->module_name);

	if (d->type != EB_DEF_LOCAL)
	{
		eb_debug (0, 1, "MODULE", "      %3d.X   Attempt to deregister a module from device not of type local", d->net);
		return;
	}

	pthread_mutex_lock (&(d->local.modules_mutex));

	p = d->local.modules;

	if (!p)
	{
		eb_debug (0, 1, "MODULE", "      %3d.%3d Attempt to deregister module %s failed: module not regsitered on this device", d->net, d->local.stn, m->module_name);
		pthread_mutex_unlock (&(d->local.modules_mutex));
		return;
	}

	while (p != m)
	{
		pprev = p;
		p = p->next;
	}

	if (!p)
	{
		eb_debug (0, 1, "MODULE", "      %3d.%3d Attempt to deregister module %s failed: module not regsitered on this device", d->net, d->local.stn, m->module_name);
		pthread_mutex_unlock (&(d->local.modules_mutex));
		return;
	}

	if (p == d->local.modules)
		d->local.modules = p->next;
	else
		pprev->next = p->next;

	eb_free (__FILE__, __LINE__, "MODULE", "Free module private workspace", m);

	pthread_mutex_unlock (&(d->local.modules_mutex));

	return;

}

/* Find workspace address */

struct __eb_device_module * eb_module_get_data (void *d_in, unsigned char *modname)
{

	unsigned char		ucmodname[9];
	char *			u;
	struct __eb_device_module	*workspace;
	struct __eb_device *	d = (struct __eb_device *) d_in;
	uint8_t			modname_len;

	modname_len = strlen(modname);

	if (modname_len == 0 || modname_len > 8)
		return NULL;

	u = eb_module_to_upper(modname);

	snprintf (ucmodname, 9, "%-8s", u);
	eb_free (__FILE__, __LINE__, "MODULE", "Free uppercase module name", u);

	if (d->type != EB_DEF_LOCAL)
		return NULL;

	/* Check to see if exists */

	pthread_mutex_lock(&(d->local.modules_mutex));

	workspace = d->local.modules;

	while (workspace && strcmp(workspace->module_name, ucmodname))
		workspace = workspace->next;

	pthread_mutex_unlock(&(d->local.modules_mutex));

	return workspace;

}

