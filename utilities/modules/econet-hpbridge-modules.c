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

struct __eb_device_module * eb_module_register (void *d_in, unsigned char *modname, unsigned char *findserver_name, uint32_t ws_size)
{
	struct __eb_device_module *workspace = NULL;
	unsigned char		ucmodname[9];
	unsigned char		ucfindservername[9];
	struct __eb_device *	d = (struct __eb_device *) d_in;
	uint8_t			modname_len;
	char *			u;

	if (d->type != EB_DEF_LOCAL)
	{
		eb_debug (1, 0, "MODULE", "Attempt by module %s to register itself on a non-local device", modname);
		return NULL;
	}

	if (strlen(modname) > 8 || strlen(modname) == 0)
	{
		if (strlen(modname) > 8)
			eb_debug (1, 0, "MODULE", "Attempt to register module name which was too long: %s", modname);
		else
			eb_debug (1, 0, "MODULE", "Attempt to register module name which empy");
		return NULL;
	}

	if (findserver_name && strlen(findserver_name) > 8)
	{
		eb_debug (1, 0, "MODULE", "Attempt to register module with findserver name which was too long: %s", findserver_name);
		return NULL;
	}

	modname_len = strlen(modname);

	if (modname_len > 8)
	{
		eb_debug (1, 0, "MODULE", "Attempt to register module with name which was too long: %s", modname);
		return NULL;
	}

	eb_debug (0, 2, "MODULE", "         %3d.%3d Registering module name %s", d->net, d->local.stn, modname);

	snprintf (ucmodname, 9, "%-8s", (u = eb_module_to_upper(modname)));
	eb_free (__FILE__, __LINE__, "MODULE", "Free uppercase module name", u);

	if (findserver_name)
	{
		snprintf(ucfindservername, 9, "%-8s", (u = eb_module_to_upper(findserver_name)));
		eb_free (__FILE__, __LINE__, ucmodname, "Free uppercase findserver name", u);
	}
	else
		strncpy(ucfindservername, ucmodname, 8); /* Duplicate if no separate findserver name given */

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

	strcpy (workspace->module_name, ucmodname);
	strcpy (workspace->module_findserver_name, ucfindservername);

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

	if (m->module_ws) /* Free module workspace */
		eb_free (__FILE__, __LINE__, "MODULE", "Free module private space", m->module_ws);

	eb_free (__FILE__, __LINE__, "MODULE", "Free module workspace", m);

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

/* Find workspace address but only return it if module started, leave module locked if specified */

struct __eb_device_module * eb_module_get_data_started_internal (void *d_in, unsigned char *modname, uint8_t leavelocked)
{
	struct __eb_device_module *m;

	m = eb_module_get_data(d_in, modname);

	if (!m) return NULL; /* Not found */

	pthread_mutex_lock(&(m->module_mutex));

	if (!(m->module_started)) /* Not started - unlock & return */
	{
		pthread_mutex_unlock(&(m->module_mutex));
		return NULL;
	}

	if (!leavelocked)
		pthread_mutex_unlock(&(m->module_mutex));

	return m;
}

void eb_module_unlock (struct __eb_device_module *m)
{
	pthread_mutex_unlock(&(m->module_mutex));
}

/*
 * eb_module_start
 *
 * Start a module by its pointer
 *
 * Returns 0 (success) or else failure
 */

uint8_t eb_module_start (void *device, struct __eb_device_module *m)
{
	uint8_t	ret;
	struct __eb_device *d = (struct __eb_device *) device;

	if (!device || !m) return 1;

	pthread_mutex_lock (&(m->module_mutex));

	m->module_exiting = 0;
	m->module_has_exited = 0;

	/* Re-initialize ? We may previously have killed the thread whilst it was sleeping ? */

	if (pthread_cond_init(&(m->module_cond), NULL)) // !0 = fail
		eb_debug (1, 0, m->module_name, "Failed to initialize module condition on startup");
	
	ret = (m->module_start) ? (m->module_start)(device, m) : 1;

	if (ret)
		eb_module_debug (1, m->module_name, d, "Module start requested, but module failed to start");
	else
	{
		m->module_started = 1;
		eb_module_debug (3, m->module_name, d, "Module started");
	}

	pthread_mutex_unlock (&(m->module_mutex));

	return ret;
}

/* 
 * eb_module_start_byname
 *
 * Start a module by its name rather than module pointer
 *
 * Returns 0 (success), else failure
 */

uint8_t eb_module_start_byname (void *device, unsigned char *name)
{
	struct __eb_device_module *m;

	if (!name || !device) return 1;

	m = eb_module_get_data (device, name);

	if (m)
		return eb_module_start (device, m);
	else	return 1;
}

/* eb_module_stop - same principle as _start */

uint8_t eb_module_stop (void *device, struct __eb_device_module *m)
{
	uint8_t	ret;
	struct __eb_device *d = (struct __eb_device *) device;

	if (!device || !m) return 1;

	pthread_mutex_lock (&(m->module_mutex));

	m->module_exiting = 1; 

	pthread_mutex_unlock (&(m->module_mutex));

	pthread_cond_signal (&(m->module_cond)); /* Wake the thread so it can exit */

	pthread_mutex_lock (&(m->module_mutex));

	while (!(m->module_has_exited))
	{
		pthread_mutex_unlock (&(m->module_mutex));
		usleep(100);
		pthread_mutex_lock (&(m->module_mutex));
	}

	ret = (m->module_stop) ? (m->module_stop)(device, m) : 1;

	if (ret)
		eb_module_debug (1, m->module_name, d, "Module stop requested, but module failed to stop");
	else
	{
		m->module_started = 0;
		eb_module_debug (3, m->module_name, d, "Module stopped");
	}

	pthread_mutex_unlock (&(m->module_mutex));

	return ret;
}

/* eb_module_stop_byname - same principle as _stop */

uint8_t eb_module_stop_byname (void *device, unsigned char *name)
{
	struct __eb_device_module *m;

	if (!name || !device) return 1;

	m = eb_module_get_data (device, name);

	if (m)
		return eb_module_stop (device, m);
	else	return 1;
}

/* JSON string copier - see header for return values */

uint8_t eb_module_json_copy_string(struct json_object *j, char *key, char *dest, uint32_t maxlen)
{
	uint8_t	ret = 2; /* Not present */
	struct json_object *jo;
	char *str;

	if (json_object_object_get_ex(j, key, &jo) && json_object_is_type(jo, json_type_string))
	{
		/* Key exists */
		if ((str = (char *) json_object_get_string(jo)))
		{
			/* Is a string */

			strncpy (dest, str, maxlen);

			if (strlen(str) > maxlen) ret = 1;
			else ret = 0;
		}
	}

	return ret;
}

/* JSON boolean copier - see header for return values */

uint8_t eb_module_json_copy_boolean(struct json_object *j, char *key, uint8_t *r)
{
	uint8_t ret = 2; /* Not present */
	struct json_object *jo;

	if (json_object_object_get_ex(j, key, &jo) && json_object_is_type (jo, json_type_boolean))
	{
		/* Key exists */

		*r = json_object_get_boolean(jo);

		ret = 0;
	}

	return ret;
}

/* Similarly for integers */

uint8_t eb_module_json_copy_int(struct json_object *j, char *key, uint32_t *r)
{
	uint8_t ret = 2; /* Not present */
	struct json_object *jo;

	if (json_object_object_get_ex(j, key, &jo) && json_object_is_type (jo, json_type_int))
	{
		/* Key exists */

		*r = json_object_get_int(jo);

		ret = 0;
	}

	return ret;
}
