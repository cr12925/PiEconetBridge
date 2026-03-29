
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

#ifndef __ECONETBRIDGEMODULES_H__
#define __ECONETBRIDGEMODULES_H__

//extern uint8_t eb_module_fooserver_init(void *, struct json_object *);
extern uint8_t setp_module_init(void *, struct json_object *);

/* Please see struct definition in econet-hpbridge.h */
/* Essentially first entry is the name of an object which must exist in the diverts[] array for a virtual server to which the module is attached, the second is 
 * the init() function for the module as described in the econet-hpbridge.h header, which the bridge will call if it discovers the relevant key in the
 * diverts[] object.
 *
 * NULL string for the JSON key terminates the list. Remove at your peril.
 */

static struct __eb_module_table eb_module_table[] = {
//	{	"fooserv", 	eb_module_fooserver_init },
	{	"setpserv",	setp_module_init },
	{	NULL, NULL }
};

#endif

