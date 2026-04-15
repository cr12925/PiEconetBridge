
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

/* econet-fast-pbuf.c
 *
 * Contains mutex locked operations for obtaining spare workqueue entries and
 * packet buffers
 */

#define ECONETGPIO_KERNEL
// #define ECONET_PBUF_DEBUG

#include "../include/econet-gpio.h"

/* 
 * Find a spare pbuf and return it, or NULL for failure.
 */

inline struct __econet_packet * econet_alloc_pbuf(void)
{
	u8	pbuf_count;
	struct __econet_packet *r = NULL;

	mutex_lock(&(econet_data->pbuf_mutex));

	for (pbuf_count = 0; pbuf_count < ECONET_GPIO_MAX_BUFFERS; pbuf_count++)
	{
		if (!(econet_data->pbuf_inuse & (1 << pbuf_count)))
		{
			/* Found */

			r = econet_data->pbuf[pbuf_count];
			r->pbuf_index = pbuf_count;
			econet_data->pbuf_inuse |= (1 << pbuf_count);
			r->ptr = 0; /* Reset pointer */
			r->sr1 = r->sr2 = r->tx = r->tx_flags = 0;

			break;
		}

	}

	mutex_unlock(&(econet_data->pbuf_mutex));

#ifdef ECONET_PBUF_DEBUG
	printk (KERN_ERR "econet-fast: Allocate pbuf    %d at %p\n", pbuf_count, r);
#endif

	return r;
}

/* 
 * Find a spare workqueue entry - same logic as above
 */

inline eco_work_t * econet_alloc_workbuf(void)
{
	u8 wb_count;
	eco_work_t *r = NULL;

	mutex_lock(&(econet_data->workbuf_mutex));

	for (wb_count = 0; wb_count < ECONET_GPIO_MAX_WORK_BUFFERS; wb_count++)
	{
		if (!(econet_data->workbuf_inuse & (1 << wb_count)))
		{
			r = econet_data->workbuf[wb_count];
			r->wb_index = wb_count;
			econet_data->workbuf_inuse |= (1 << wb_count);
			r->p = NULL;
			break;
		}
	}

	mutex_unlock(&(econet_data->workbuf_mutex));

#ifdef ECONET_PBUF_DEBUG
	printk (KERN_ERR "econet-fast: Allocate workbuf %d at %p\n", wb_count, r);
#endif

	return r;
}

/* Free an allocated packet buf */

inline void econet_free_pbuf(struct __econet_packet *p)
{

#ifdef ECONET_PBUF_DEBUG
	printk (KERN_ERR "econet-fast: Free     pbuf    %d at %p\n", p->pbuf_index, p);
#endif
	if (econet_data->pbuf[p->pbuf_index] != p) /* Address mismatch */
		printk (KERN_ERR "econet-fast: ERROR: Address mismatch freeing pbuf %d: address given is %p, but address of pbuf[%d] is %p!\n",
			p->pbuf_index, 
			p,
			p->pbuf_index,
			econet_data->pbuf[p->pbuf_index]
		);

	mutex_lock(&(econet_data->pbuf_mutex));

	econet_data->pbuf_inuse &= ~(1<< (p->pbuf_index));

	mutex_unlock(&(econet_data->pbuf_mutex));
}

/* And likewise an eco_work_t */

inline void econet_free_workbuf(eco_work_t *e)
{

#ifdef ECONET_PBUF_DEBUG
	printk (KERN_ERR "econet-fast: Free     workbuf %d at %p\n", e->wb_index, e);
#endif

	if (econet_data->workbuf[e->wb_index] != e) /* Address mismatch */
		printk (KERN_ERR "econet-fast: ERROR: Address mismatch freeing workbuf %d: address given is %p, but address of workbuf[%d] is %p!\n",
			e->wb_index, 
			e,
			e->wb_index, 
			econet_data->workbuf[e->wb_index]
		);

	mutex_lock(&(econet_data->workbuf_mutex));

	econet_data->workbuf_inuse &= ~(1<<(e->wb_index));

	mutex_unlock(&(econet_data->workbuf_mutex));
}
