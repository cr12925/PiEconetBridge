
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
 * Contains spin locked operations for obtaining spare workqueue entries and
 * packet buffers
 */

#define ECONETGPIO_KERNEL
// #define ECONET_PBUF_DEBUG

#include "../include/econet-gpio.h"

void econet_dump_pbuf_inner(u8, char *);

/* 
 * Find a spare pbuf and return it, or NULL for failure.
 */

inline struct __econet_packet * __econet_alloc_pbuf(u8 file, uint32_t line)
{
	u8	pbuf_count;
	u32	inverse;
	u64 	staletime;
	struct __econet_packet *r = NULL;
	unsigned long	flags;

	spin_lock_irqsave(&(econet_data->pbuf_spinlock), flags);

	staletime = (u64) (ktime_get_ns() - 15000000000);

	for (pbuf_count = 0; pbuf_count < ECONET_GPIO_MAX_BUFFERS; pbuf_count++)
	{
		if ((econet_data->pbuf_inuse & (1 << pbuf_count)) && econet_data->pbuf[pbuf_count]->alloc_time < staletime) /* Stale if more than 15s old */
		{
			econet_dump_pbuf_inner(pbuf_count, "garbage collecting ");
			inverse = ~(1 << pbuf_count);
			econet_data->pbuf_inuse &= inverse;
		}

		if (!(econet_data->pbuf_inuse & (1 << pbuf_count)))
		{
			/* Found */

			r = econet_data->pbuf[pbuf_count];
			r->pbuf_index = pbuf_count;
			econet_data->pbuf_inuse |= (1 << pbuf_count);
			r->ptr = 0; /* Reset pointer */
			r->sr1 = r->sr2 = r->tx = r->tx_flags = 0;
			r->file = file;
			r->line = line;
			r->alloc_time = ktime_get_ns();
			r->lastseen = 0;
			r->flagfill = 0;

			break;
		}

	}

	spin_unlock_irqrestore(&(econet_data->pbuf_spinlock), flags);

#ifdef ECONET_PBUF_DEBUG
	printk (KERN_ERR "econet-fast: Allocate pbuf    %d at %p\n", pbuf_count, r);
#endif

	if (!r) econet_dump_pbuf(); /* Tell the user what leaked */

	return r;
}

/* Dump pbuf usage to ring buffer in case we run out - we can see what leaked */

void econet_dump_pbuf(void)
{

	u8	pbuf_count;

	for (pbuf_count = 0; pbuf_count < ECONET_GPIO_MAX_BUFFERS; pbuf_count++)
		econet_dump_pbuf_inner(pbuf_count, "");

}

void econet_dump_pbuf_inner(u8 pbuf_count, char *tag)
{
	printk (KERN_INFO "econet-fast: %spbuf[%d] (%p) allocated by %s:%d %lld ns ago, last seen in %s\n",
		tag,
		pbuf_count,
		econet_data->pbuf[pbuf_count],
		(econet_data->pbuf[pbuf_count]->file == EMF_PBUF_OPS ? "module-ops" :
		 econet_data->pbuf[pbuf_count]->file == EMF_PBUF_RWF ? "rw-fops" : 
		 econet_data->pbuf[pbuf_count]->file == EMF_PBUF_IRQ ? "irq" : 
		 econet_data->pbuf[pbuf_count]->file == EMF_PBUF_AUN ? "aun" : "unknown"),
		econet_data->pbuf[pbuf_count]->line,
		(ktime_get_ns() - econet_data->pbuf[pbuf_count]->alloc_time),
		(
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_WORKQUEUE_EXIT ? "workqueue exit" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_WORKQUEUE_ENTRY ? "workqueue entry" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_HARD ? "irq hard" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_SOFT ? "irq soft" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_SOFT_WRITER_LASTBYTE ? "irq soft writer last byte" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_SOFT_UNDERRUN ? "irq soft underrun" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_SOFT_WRITER ? "irq soft writer" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_SOFT_WRITE_WAIT ? "irq soft write wait" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_HARD_WRITE_WAIT ? "irq hard write wait" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_HARD_WRITER ? "irq hard writer" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_HARD_WRITER_LASTBYTE ? "irq hard writer last byte" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_HARD_WRITER_LASTBYTE_NEXTIRQ ? "irq hard writer last byte next irq" :
		econet_data->pbuf[pbuf_count]->lastseen == EMF_PBUF_LASTSEEN_IRQ_HARD_WRITER_LASTBYTE_NEXTIRQ_NOFC ? "irq hard writer last byte next irq but no fc" :
		"unknown"
		)
	);
}

/* 
 * Find a spare workqueue entry - same logic as above
 */

inline eco_work_t * econet_alloc_workbuf(void)
{
	u8 wb_count;
	eco_work_t *r = NULL;
	unsigned long flags;

	spin_lock_irqsave(&(econet_data->workbuf_spinlock), flags);

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

	spin_unlock_irqrestore(&(econet_data->workbuf_spinlock), flags);

#ifdef ECONET_PBUF_DEBUG
	printk (KERN_ERR "econet-fast: Allocate workbuf %d at %p\n", wb_count, r);
#endif

	return r;
}

/* Free an allocated packet buf */

inline void econet_free_pbuf(struct __econet_packet *p)
{

	unsigned long flags;

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

	spin_lock_irqsave(&(econet_data->pbuf_spinlock), flags);

	econet_data->pbuf_inuse &= ~(1<< (p->pbuf_index));

	spin_unlock_irqrestore(&(econet_data->pbuf_spinlock), flags);
}

/* And likewise an eco_work_t */

inline void econet_free_workbuf(eco_work_t *e)
{

	unsigned long flags; 

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

	spin_lock_irqsave(&(econet_data->workbuf_spinlock), flags);

	econet_data->workbuf_inuse &= ~(1<<(e->wb_index));

	spin_unlock_irqrestore(&(econet_data->workbuf_spinlock), flags);
}

/* Forcibly free all pbufs */

void econet_reset_pbuf(void)
{
	econet_data->workbuf_inuse = 0;
}
