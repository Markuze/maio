/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REF_H
#define _LINUX_PAGE_REF_H

#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/tracepoint-defs.h>

#include <linux/maio.h>

extern struct tracepoint __tracepoint_page_ref_set;
extern struct tracepoint __tracepoint_page_ref_mod;
extern struct tracepoint __tracepoint_page_ref_mod_and_test;
extern struct tracepoint __tracepoint_page_ref_mod_and_return;
extern struct tracepoint __tracepoint_page_ref_mod_unless;
extern struct tracepoint __tracepoint_page_ref_freeze;
extern struct tracepoint __tracepoint_page_ref_unfreeze;

#ifdef CONFIG_DEBUG_PAGE_REF

/*
 * Ideally we would want to use the trace_<tracepoint>_enabled() helper
 * functions. But due to include header file issues, that is not
 * feasible. Instead we have to open code the static key functions.
 *
 * See trace_##name##_enabled(void) in include/linux/tracepoint.h
 */
#define page_ref_tracepoint_active(t) static_key_false(&(t).key)

extern void __page_ref_set(struct page *page, int v);
extern void __page_ref_mod(struct page *page, int v);
extern void __page_ref_mod_and_test(struct page *page, int v, int ret);
extern void __page_ref_mod_and_return(struct page *page, int v, int ret);
extern void __page_ref_mod_unless(struct page *page, int v, int u);
extern void __page_ref_freeze(struct page *page, int v, int ret);
extern void __page_ref_unfreeze(struct page *page, int v);

#else

#define page_ref_tracepoint_active(t) false

static inline void __page_ref_set(struct page *page, int v)
{
}
static inline void __page_ref_mod(struct page *page, int v)
{
}
static inline void __page_ref_mod_and_test(struct page *page, int v, int ret)
{
}
static inline void __page_ref_mod_and_return(struct page *page, int v, int ret)
{
}
static inline void __page_ref_mod_unless(struct page *page, int v, int u)
{
}
static inline void __page_ref_freeze(struct page *page, int v, int ret)
{
}
static inline void __page_ref_unfreeze(struct page *page, int v)
{
}

#endif
static inline void set_maio_is_io(struct page *page)
{
	page = __compound_head(page, 0);
	//page[1].uaddr |= IS_MAIO_MASK;
}

static inline void set_maio_uaddr(struct page *page, u64 uaddr)
{
#if 0
	if (page[1].uaddr)
		pr_err("Double call to set_maio_uaddr was %lx now %llx\n", page[1].uaddr, uaddr);
#endif
	page[1].uaddr = uaddr;
}

static inline u64 get_maio_uaddr(struct page *page)
{
	page = __compound_head(page, 0);
	return page[1].uaddr;
}

static inline void set_maio_uarg(struct page *page, void *uarg)
{
	page[1].uarg = uarg;
}

static inline void *get_maio_uarg(struct page *page)
{
	page = __compound_head(page, 0);
	return page[1].uarg;
}

static inline void set_maio_elem_order(struct page *page, unsigned int order)
{
	page[1].elem_order = order;
}

static inline u16 get_maio_elem_order(struct page *page)
{
	page = __compound_head(page, 0);
	return page[1].elem_order;
}

static inline bool is_maio_page(struct page *page)
{
	if (!PageCompound(page))
		return 0;

	/* We exclude Head Pages from I/O */
	if (PageHead(page)) {
		return 0;
	}
	return get_maio_uaddr(page) ? 1 : 0;
	//return (get_maio_uaddr(page) & IS_MAIO_MASK) ? 1 : 0;
}


static inline int page_ref_count(struct page *page)
{
	return atomic_read(&page->_refcount);
}

static inline int page_count(struct page *page)
{
	return atomic_read(&compound_head(page)->_refcount);
}

static inline void set_page_count(struct page *page, int v)
{
	atomic_set(&page->_refcount, v);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_set))
		__page_ref_set(page, v);
}

/*
 * Setup the page count before being freed into the page allocator for
 * the first time (boot or memory hotplug)
 */
static inline void init_page_count(struct page *page)
{
	set_page_count(page, 1);
}

static inline void page_ref_add(struct page *page, int nr)
{
	atomic_add(nr, &page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, nr);
}

static inline void page_ref_sub(struct page *page, int nr)
{
	atomic_sub(nr, &page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, -nr);
}

static inline void page_ref_inc(struct page *page)
{
	if (is_maio_page(page))
		maio_trace_page_inc(page);

	atomic_inc(&page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, 1);
}

static inline void page_ref_dec(struct page *page)
{
	atomic_dec(&page->_refcount);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod))
		__page_ref_mod(page, -1);
}

static inline int page_ref_sub_and_test(struct page *page, int nr)
{
	int ret = atomic_sub_and_test(nr, &page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_test))
		__page_ref_mod_and_test(page, -nr, ret);
	return ret;
}

static inline int page_ref_inc_return(struct page *page)
{
	int ret = atomic_inc_return(&page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_return))
		__page_ref_mod_and_return(page, 1, ret);
	return ret;
}

static inline int page_ref_dec_and_test(struct page *page)
{
	int ret = atomic_dec_and_test(&page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_test))
		__page_ref_mod_and_test(page, -1, ret);
	return ret;
}

static inline int page_ref_dec_return(struct page *page)
{
	int ret = atomic_dec_return(&page->_refcount);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_and_return))
		__page_ref_mod_and_return(page, -1, ret);
	return ret;
}

static inline int page_ref_add_unless(struct page *page, int nr, int u)
{
	int ret = atomic_add_unless(&page->_refcount, nr, u);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_mod_unless))
		__page_ref_mod_unless(page, nr, ret);
	return ret;
}

static inline int page_ref_freeze(struct page *page, int count)
{
	int ret = likely(atomic_cmpxchg(&page->_refcount, count, 0) == count);

	if (page_ref_tracepoint_active(__tracepoint_page_ref_freeze))
		__page_ref_freeze(page, count, ret);
	return ret;
}

static inline void page_ref_unfreeze(struct page *page, int count)
{
	VM_BUG_ON_PAGE(page_count(page) != 0, page);
	VM_BUG_ON(count == 0);

	atomic_set_release(&page->_refcount, count);
	if (page_ref_tracepoint_active(__tracepoint_page_ref_unfreeze))
		__page_ref_unfreeze(page, count);
}

#endif
