#include "../include/fs.h"

/* Create new struct of type t, put it on l, put it on the head (1) or tail (0) of the queue of such structs at l, and put the pointer (or null) in p,
 * use module & descr as parameters to eb_malloc()
 */ 

#define FS_LIST_MAKENEW(t,l,head,p,module,descr) \
	p = eb_malloc(__FILE__, __LINE__, module, descr, sizeof(t)); \
	memset (p, 0, sizeof(t)); \
	if (head) \
	{ \
		p->next = l; \
		p->prev = NULL; \
		l = p; \
	} \
	else \
	{ \
		t 	*tmp; \
		tmp = l; \
		if (!tmp) \
		{ \
			l = p; \
			p->next = NULL; \
			p->prev = NULL; \
		} \
		else \
		{ \
			while (tmp->next) tmp=tmp->next;\
			p->prev = tmp; \
			tmp->next = p;\
			p->next = NULL; \
		} \
	} \

#define FS_LIST_SPLICEFREE(l,p,module,descr) \
	if (p->prev) \
		p->prev->next = p->next; \
	else \
		l = p->next; \
	\
	if (p->next) \
		p->next->prev = p->prev; \
	\
	eb_free (__FILE__, __LINE__, module, descr, p)


FS_LIST_MAKENEW(struct __fs_active,f->server->actives,1,n,"FS","Allocate new active");
FS_LIST_SPLICEFREE(f->server->actives,n,"FS","Free active user");

		
