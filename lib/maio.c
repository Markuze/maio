#include <linux/init.h>
#include <linux/magazine.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/rbtree.h>
#include <linux/ctype.h> /*isdigit*/
#include <linux/ip.h>	/*iphdr*/
#include <linux/tcp.h>	/*tcphdr*/

#include "io_md.h"

#ifndef assert
#define assert(expr) 	do { \
				if (unlikely(!(expr))) { \
					trace_printk("Assertion failed! %s, %s, %s, line %d\n", \
						   #expr, __FILE__, __func__, __LINE__); 	\
					pr_alert("Assertion failed! %s, %s, %s, line %d\n", 	\
						   #expr, __FILE__, __func__, __LINE__); 	\
					dump_all_stats(NULL);					\
					panic("ASSERT FAILED: %s (%s)", __FUNCTION__, #expr); 	\
				} \
			} while (0)

#endif

#define __line__	pr_err("%s:%d\n", __FUNCTION__, __LINE__);
#if defined MAIO_DEBUG
#define trace_debug trace_printk
#else
#define trace_debug(...)
#endif

struct maio_tx_threads {
	struct maio_tx_thread tx_thread[NUM_MAX_RINGS];
	//struct napi_struct napi;
};

/* GLOBAL MAIO FLAG*/
static bool maio_dev_configured[MAX_DEV_NUM];

maio_filter_func_p maio_filter;
EXPORT_SYMBOL(maio_filter);
//TODO: collect this shite in a struct

/* get_user_pages */
static struct page* umem_pages[1<<HUGE_ORDER];
static struct page* mtrx_pages[1<<HUGE_ORDER];

static struct proc_dir_entry *maio_dir;
static struct maio_magz global_maio;

static struct memory_stats 	memory_stats;
static struct err_stats 	err_stats;
static u64 last_comp;

struct user_matrix *global_maio_matrix[MAX_DEV_NUM];
EXPORT_SYMBOL(global_maio_matrix);

static unsigned last_dev_idx;

static u16 maio_headroom	= (0x800 -512 -192); 	//This should make a zero gap between vc_pckt and headroom + data

static struct kmem_cache *misc_cache;

/* Head Page Cache */
/* A workaround, Head Pages Refcounts may go up/down due to new process mapping or old processes leaving.
   We use the first 4K pages for copy RX allocations and TX which doesnt use refcounts.
*/
static LIST_HEAD(head_cache);
DEFINE_SPINLOCK(head_cache_lock);
static unsigned long head_cache_size;

/*TODO: Clean up is currently leaking this */
static struct maio_tx_threads	maio_tx_threads[MAX_DEV_NUM] __read_mostly;
static struct net_device *maio_devs[MAX_DEV_NUM] __read_mostly;
static struct maio_dev_map dev_map;

DEFINE_PER_CPU(struct percpu_maio_dev_qp, maio_dev_qp);
/* TODO:
	For multiple reg ops a tree is needed
		1. For security and rereg need owner id and mmap to specific addr.
*/
static struct rb_root mtt_tree = RB_ROOT;
static struct umem_region_mtt *cached_mtt;

static DEFINE_PER_CPU(struct page_frag_cache, tx_page_frag);

#ifdef MAIO_ASYNC_TX
static int maio_post_tx_task(void *);
static int (*threadfn)(void *data) = maio_post_tx_task;
#endif

static int maio_post_napi_page(struct maio_tx_thread *tx_thread/*, struct napi_struct *napi*/);

bool maio_configured(int idx)
{
	if (idx > MAX_DEV_NUM || idx < 0)
		return false;
	return maio_dev_configured[idx];
}
EXPORT_SYMBOL(maio_configured);

//#define dump_io_md(...)

#ifndef dump_io_md
#define dump_io_md	__dump_io_md
#endif
static inline void __dump_io_md(struct io_md *md, const char *txt)
{
	pr_err("%s: state %llx: len %x : poison %x: vlan %x flags %x\n",
		txt, md->state, md->len, md->poison, md->vlan_tci, md->flags);
}

static void dump_err_stats(struct seq_file *m)
{
	int i = 0;

	for (i = 0; i < NR_MAIO_ERR_STATS; i++)
		if (m) {
			seq_printf(m, "%s\t: %ld\n", err_stat_names[i],
					atomic_long_read(&err_stats.array[i]));
		} else {
			pr_err("%s\t: %ld\n", err_stat_names[i],
					atomic_long_read(&err_stats.array[i]));
		}


	if (m) {
		seq_printf(m, "%s\t: %llx\n", "Last Comp", last_comp);
	} else {
		pr_err("%s\t: %llx\n", "Last Comp", last_comp);
	}

}

static void dump_memory_stats(struct seq_file *m)
{
	int i = 0;
	long long int delta;

	delta = atomic_long_read(&memory_stats.nr_page_initial) - atomic_long_read(&memory_stats.page_free)
		-atomic_long_read(&memory_stats.page_rx) -atomic_long_read(&memory_stats.page_network_stack)
		-atomic_long_read(&memory_stats.page_head);

	if (m)
		seq_printf(m, " Mags: %d (%d) delta %lld)\n",
			mag_get_full_count(&global_maio.mag[0]),
			mag_get_full_count(&global_maio.mag[0]) * MAG_DEPTH,
			delta);
	else
		pr_err(" Mags: %d (%d) delta %lld)\n",
			mag_get_full_count(&global_maio.mag[0]),
			mag_get_full_count(&global_maio.mag[0]) * MAG_DEPTH,
			delta);


	for (i = 0; i < NR_MAIO_STATS; i++)
		if (m) {
			seq_printf(m, "%s\t: %ld\n", maio_stat_names[i],
					atomic_long_read(&memory_stats.array[i]));
		} else {
			pr_err("%s\t: %ld\n", maio_stat_names[i],
					atomic_long_read(&memory_stats.array[i]));
		}
}

static inline void dump_all_stats(struct seq_file *m)
{
	dump_memory_stats(m);
	dump_err_stats(m);
	dump_mag_stats(m, &global_maio.mag[0]);
}

static inline void dec_state(u64 state)
{
	if (likely(state)) {
		u8 idx  = ffs(state >> 9);
		atomic_long_dec(&memory_stats.array[idx]);
	}
}


static inline void inc_state(u64 state)
{
	if (likely(state)) {
		u8 idx = ffs(state >> 9);
		atomic_long_inc(&memory_stats.array[idx]);
	}
}

static inline u64 get_err(u64 state)
{
	u8 idx = ffs(state >> 1);
	if (idx > NR_MAIO_ERR_STATS)
		pr_err("wtf?! %d (%llx)",idx,state);
	return atomic_long_read(&err_stats.array[idx]);
}

static inline void inc_err(u64 state)
{
	u8 idx = ffs(state >> 1);
	if (idx > NR_MAIO_ERR_STATS)
		pr_err("wtf?! %d (%llx)",idx,state);
	atomic_long_inc(&err_stats.array[idx]);
}

static inline void *kaddr2shadow(void *kaddr)
{
	u64 shadow = (u64)kaddr;
	shadow &= PAGE_MASK;
	shadow += SHADOW_OFF;
	return (void *)shadow;
}
#define page2shadow(p)	kaddr2shadow(page_address(p))

static inline struct io_md* virt2io_md(void *va)
{
	uint64_t addr = (uint64_t)va & PAGE_MASK;
	return (void *)(addr + IO_MD_OFF);
}

static inline struct io_md* page2io_md(struct page *page)
{
	return virt2io_md(page_address(page));
/*
	struct io_track *track;
	int idx;

	if (likely(get_maio_uaddr(page) & IS_MAIO_MASK))
		track = page_address((__compound_head(page, 0)));
	else

	idx 	= (((u64)page_address(page)) & HUGE_OFFSET) >> PAGE_SHIFT;//0-512

	assert(idx <= 512);
	return &track->map[idx];
*/
}

static inline void __set_page_state(struct io_md *md,u64 new_state, u32 line, u8 rc)
{
	dec_state(md->state);
	inc_state(new_state);

	md->prev_state = md->state;
	md->prev_line  = md->line;
	md->state = new_state;
	md->line = line;
}
#define set_page_state(p,s)	__set_page_state(page2io_md(p),s, __LINE__, page_ref_count(p))

static inline u64 get_page_state(struct page *page)
{
	struct io_md *md = page2io_md(page);
	return md->state;
}

static inline void trace_page_state(struct page *page)
{
	struct io_md *md = page2io_md(page);

	trace_printk("ERROR: Page %llx state %llx uaddr %llx\n", (u64)page, get_page_state(page), get_maio_uaddr(page));
	trace_printk("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
	trace_printk("%ps] page %llx(state %llx [%u]<%llx>[%u] )[%d] addr %llx\n"
		"%ps] transit %d transitcnt %u [%d/%d]\n",
		__builtin_return_address(0),
		(u64)page, get_page_state(page), md->line,
		md->prev_state, md->prev_line, page_ref_count(page), (u64)page_address(page),
		__builtin_return_address(0),
		md->in_transit, md->in_transit_dbg, md->tx_cnt, md->tx_compl);

}

static inline void dump_page_rc(struct page *page)
{
	union shadow_state	*shadow = page2shadow(page);
	struct io_md		*md = page2io_md(page);

	u32 idx	= atomic_read(&md->idx);
	int i;
//	int cntr = 0;

	for (i = 0; i < NR_SHADOW_LOG_ENTIRES; ++i, ++idx) {
		//int len;
		idx = idx & (NR_SHADOW_LOG_ENTIRES - 1);

		if (!shadow->entry[idx].addr) {
			pr_err("%-2d:----------\n",
					idx);
			continue;
		}

		pr_err("%-2d:%-2d:%-2d [0x%x]:%ps:..%ps\n",
				idx,
				shadow->entry[idx].core,
				(shadow->entry[idx].rc)& 0x3,
				(shadow->entry[idx].rc)>>2,
				(void *)shadow->entry[idx].addr,
				(void *)shadow->entry[idx].addr2);
/*
		len = snprintf(&buffer[cntr], size, "%-2d:%-2d:%-2d:%ps\n",
				idx,
				shadow->core[idx],
				shadow->rc[idx],
				(void *)shadow->addr[idx]);
		size -= len;
		cntr += len;
*/
	}
	return;
}

static inline void __dump_page_state(struct page *page, int line)
{
	struct io_md *md = page2io_md(page);

	pr_err("ERROR[%d]: Page %llx state %llx uaddr %llx\n", line, (u64)page, get_page_state(page), get_maio_uaddr(page));
	pr_err("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
	pr_err("%ps] page %llx(state %llx [%u]<%llx>[%u] )[%d] addr %llx\n"
		"%ps] transit %d transitcnt %u [%d/%d]\n",
		__builtin_return_address(0),
		(u64)page, get_page_state(page), md->line,
		md->prev_state, md->prev_line, page_ref_count(page), (u64)page_address(page),
		__builtin_return_address(0),
		md->in_transit, md->in_transit_dbg, md->tx_cnt, md->tx_compl);

	dump_page_rc(page);
	dump_all_stats(NULL);
}
#define dump_page_state(p)	__dump_page_state(p, __LINE__)

static inline void flush_all_mtts(void)
{
	struct rb_node *node = mtt_tree.rb_node;

	while (node) {
		int i = 0;
		struct umem_region_mtt *mtt = container_of(node, struct umem_region_mtt, node);

		/* Current implememntation 5.4 is enough to put only the head page */
		pr_err("%s:freeing MTT [0x%llx - 0x%llx) len %d\n", __FUNCTION__, mtt->start, mtt->end, mtt->len);
		for (; i < mtt->len; i++) {
			set_maio_uaddr(mtt->mapped_pages[i].page, 0);
			trace_debug("%llx rc: %d\n", (unsigned long long)mtt->mapped_pages[i].page,
							page_ref_count(mtt->mapped_pages[i].page));
			put_user_page(mtt->mapped_pages[i].page);
		}

		rb_erase(node, &mtt_tree);
		kfree(mtt);
		node = mtt_tree.rb_node;
	}
}

static inline struct umem_region_mtt *find_mtt(u64 addr)
{
	struct rb_node *node = mtt_tree.rb_node;

	if (likely(cached_mtt && (addr <= cached_mtt->end || addr >= cached_mtt->start)))
		return cached_mtt;

	while (node) {
		struct umem_region_mtt *mtt = container_of(node, struct umem_region_mtt, node);

		if  (addr < mtt->start)
			node = node->rb_left;
		else if (addr > mtt->end)
			node = node->rb_right;
		else {
			cached_mtt = mtt;
			return mtt;
		}
	}
	return NULL;
}

static inline bool add_mtt(struct umem_region_mtt *mtt)
{

	struct rb_node **new = &(mtt_tree.rb_node), *parent = NULL;

	while (*new) {
		struct umem_region_mtt *this = container_of(*new, struct umem_region_mtt, node);

		parent = *new;

		if  (mtt->end < this->start)
			new = &((*new)->rb_left);
		else if (mtt->start > this->end)
			new = &((*new)->rb_right);
		else
			return false;

	}
	cached_mtt = mtt;
	rb_link_node(&mtt->node, parent, new);
	rb_insert_color(&mtt->node, &mtt_tree);

	trace_printk("%s [%llx - %llx)\n",__FUNCTION__, mtt->start, mtt->end);
	return true;
}

static inline u64 uaddr2idx(const struct umem_region_mtt *mtt, u64 uaddr)
{
	u64 idx;

	if (unlikely(uaddr > mtt->end || uaddr < mtt->start))
		return -EINVAL;

	idx = uaddr - mtt->start;
	return idx >> (HUGE_SHIFT);
}

static inline void *uaddr2addr(u64 addr)
{
	struct umem_region_mtt *mtt = find_mtt(addr);
	int i = uaddr2idx(mtt, addr);
	u64 offset = (u64)addr;
	offset &=  HUGE_OFFSET;

	if (i < 0)
		return NULL;
	return page_address(mtt->mapped_pages[i].page) + offset;
}

static inline u64 addr2uaddr(void *addr)
{
	u64 offset = (u64)addr;
	offset &=  HUGE_OFFSET;

	//if (unlikely(!is_maio_page(virt_to_page(addr))))
	//	return 0;
	return (get_maio_uaddr(virt_to_head_page(addr)) & ~IS_MAIO_MASK) + offset;
}

static inline void maio_cache_head(struct page *page)
{
	unsigned long flags;
	struct misc_data *buf = kmem_cache_alloc(misc_cache, GFP_KERNEL|__GFP_ZERO);

	if (unlikely(!buf)) {
		inc_err(MAIO_ERR_UBUF_ERR);
		return;
	}
	buf->ctx = page;

	spin_lock_irqsave(&head_cache_lock, flags);
	list_add(&buf->list, &head_cache);
	++head_cache_size;
	spin_unlock_irqrestore(&head_cache_lock, flags);
}

static inline struct page *maio_get_cached_head(void)
{
	unsigned long flags;
	struct page *page = NULL;
	struct misc_data *buffer;

	//TODO: Add counter
	spin_lock_irqsave(&head_cache_lock, flags);

	buffer = list_first_entry_or_null(&head_cache,
						struct misc_data, list);
	if (likely(buffer)) {
		list_del(&buffer->list);
		page = buffer->ctx;
		buffer->ctx = NULL;
		kmem_cache_free(misc_cache, buffer);
		--head_cache_size;
	}
	spin_unlock_irqrestore(&head_cache_lock, flags);

	return page;
}

static inline int order2idx(size_t order)
{
	/* With multiple sizes this will change*/
	return 0;
}

static inline void maio_free_elem(void *elem, u16 order)
{
	mag_free_elem(&global_maio.mag[order2idx(order)], elem);
}

//put_page
static inline void put_buffers(void *elem, u16 order)
{
	/*TODO: order may make sense some day in case of e.g., 2K buffers
		order also makes sense for multipage allocs.
	*/
	maio_free_elem(elem, order);
}

static inline void __maio_free(struct page *page, void *addr)
{
	assert(is_maio_page(page));
	assert(page_ref_count(page) == 0);

	if (unlikely(! (get_page_state(page) & MAIO_PAGE_IO))) {
		inc_err(MAIO_ERR_BAD_FREE_PAGE);

		dump_io_md(virt2io_md(addr), "MD");
		dump_page_state(page);
		panic("Illegal page state Non IO Page! \n");

		set_page_state(page, MAIO_PAGE_USER);
		init_page_count(page);
		maio_trace_page_rc(page, (0xF1<<2));
		return;
	}
	if (unlikely(virt2io_md(addr)->state == MAIO_PAGE_TX)) {
		pr_err("%s Zero refcount page %llx(state %llx) rc %d\n", __FUNCTION__,
			(u64)page, get_page_state(page), page_ref_count(page));
		panic("Illegal page state! \n");
	}
	//trace_printk("should I be here? page %llx(state %llx)[%d] rc %d\n",
	//	(u64)page, get_page_state(page), page_ref_count(page),page_ref_count(page));
	assert(get_page_state(page) & MAIO_PAGE_IO);

	maio_trace_page_rc(page, MAIO_PAGE_RC_FREE);
	set_page_state(page, MAIO_PAGE_FREE);

	smp_wmb();
	put_buffers(addr, get_maio_elem_order(page));
}

void maio_trace_page_rc(struct page *page, int i)
{
	union shadow_state	*shadow = page2shadow(page);
	struct io_md		*md = page2io_md(page);

	u64 idx	= atomic_inc_return(&md->idx);
	idx = (idx -1) & (NR_SHADOW_LOG_ENTIRES -1);

	shadow->entry[idx].core  	= smp_processor_id();
	shadow->entry[idx].rc		= i + page_ref_count(page);
	shadow->entry[idx].addr		=(u64)__builtin_return_address(1);
	shadow->entry[idx].addr2	=(u64)__builtin_return_address(4);
}
EXPORT_SYMBOL(maio_trace_page_rc);

void maio_page_free(struct page *page)
{
	__maio_free(page, page_address(page));
	return;
}
EXPORT_SYMBOL(maio_page_free);

void maio_frag_free(void *addr)
{
	/*
	struct page *page = virt_to_head_page(addr);
		1. get idx
		2. mag free...
	*/
	struct page* page = virt_to_page(addr); /* TODO: Align on elem order*/
	__maio_free(page, addr);
}
EXPORT_SYMBOL(maio_frag_free);

#if 0
static inline void replenish_from_cache(size_t order)
{
	int i;
	struct page *page = maio_get_cached_hp();

	trace_printk("%d: %s page:%llx [cache size=%lu]\n",
			smp_processor_id(), __FUNCTION__, (u64)page, hp_cache_size);
	if (unlikely(!page))
		return;

	assert(compound_order(page) == HUGE_ORDER);
	for (i = 0; i < PAGES_IN_HUGE; i++) {
		set_page_count(page, 0);
		put_buffers(page_address(page), order);
		page++;
	}
}
#endif
//TODO: Its possible to store headroom per page.
u16 maio_get_page_headroom(struct page *page)
{
	return maio_headroom;
}
EXPORT_SYMBOL(maio_get_page_headroom);

u16 maio_get_page_stride(struct page *page)
{
	return PAGE_SIZE;
}
EXPORT_SYMBOL(maio_get_page_stride);

struct page *__maio_alloc_pages(size_t order)
{
	struct page *page;
	void *buffer;


	buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);

	/* should happen on init when mag is empty.*/
	if (unlikely(!buffer)) {
		/*
			TODO:
			replenish_from_user(order);
			buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);
		*/
		pr_err("Failed to alloc from MAIO mag [%ps]\n", __builtin_return_address(0));
		dump_all_stats(NULL);
		panic("WTF?!?!");
		return NULL;
	}
	assert(buffer != NULL);//should not happen
	page =  (buffer) ? virt_to_page(buffer) : ERR_PTR(-ENOMEM);
	if (likely( ! IS_ERR_OR_NULL(page))) {
		assert(is_maio_page(page));

		if (unlikely(get_page_state(page) != MAIO_PAGE_FREE)) {
			if (unlikely(get_page_state(page) != MAIO_PAGE_REFILL)) {
				dump_page_state(page);
				panic("P %llx: %llx  has %d refcnt\n", (u64)page, (u64)page_address(page), page_ref_count(page));
			}
		} else {
			assert(get_page_state(page) == MAIO_PAGE_FREE);

			if (unlikely((page_ref_count(page) != 0))) {
				trace_printk("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
				trace_printk("%d:%s:%llx[%d]%llx\n", smp_processor_id(),
						__FUNCTION__, (u64)page, page_ref_count(page), (u64)page_address(page));
				dump_page_state(page);
				panic("P %llx: %llx  has %d refcnt\n", (u64)page, (u64)page_address(page), page_ref_count(page));
			}
		}
		init_page_count(page);
		set_page_state(page, MAIO_PAGE_RX);
		maio_trace_page_rc(page, MAIO_PAGE_RC_ALLOC);
	}
	//trace_debug("%d:%s: %pS\n", smp_processor_id(), __FUNCTION__, __builtin_return_address(0));
	//trace_debug("%d:%s:%llx\n", smp_processor_id(), __FUNCTION__, (u64)page);

	return page;
}
#define __maio_alloc_page()	__maio_alloc_pages(0)

struct page *maio_alloc_pages(size_t order)
{
	struct page *page;

	page = __maio_alloc_pages(order);
	if (!page)
		return alloc_page(GFP_KERNEL|GFP_ATOMIC);

	return page;
}
EXPORT_SYMBOL(maio_alloc_pages);

/*
static inline void init_user_rings_kmem(void)
{
	struct page *hp = maio_get_cached_hp();

	trace_printk("%d: %s page:%llx [cache size=%lu]\n",
			smp_processor_id(), __FUNCTION__, (u64)hp, hp_cache_size);
	if (unlikely(!hp))
		return;

	assert(compound_order(hp) == HUGE_ORDER);

	global_maio_matrix = (struct user_matrix *)page_address(hp);
	pr_err("Set user matrix to %llx[%llx] - %llx\n",
		(u64)global_maio_matrix, (u64)hp, addr2uaddr(global_maio_matrix));
	memset(global_maio_matrix, 0, HUGE_SIZE);

}
*/
#if 0
static inline bool ring_full(u64 p, u64 c)
{
	return (((p + 1) & UMAIO_RING_MASK) == (c & UMAIO_RING_MASK));
}
#endif

#if 0
static inline char* alloc_copy_buff(struct percpu_maio_qp *qp)
{
	char *data;
#if 0
	if (qp->cached_mbuf) {
		data = qp->cached_mbuf;
		qp->cached_mbuf = NULL;
		/*TODO: ASSERT on Refcount values...*/
	} else {
#endif
		void *buffer = mag_alloc_elem(&global_maio.mag[order2idx(0)]);
		struct page *page;

		if (!buffer)
			return NULL;
		page = virt_to_page(buffer);

		if (!(page_ref_count(page) == 0)) {
			trace_printk("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
			trace_printk("%d:%s:%llx[%d]%llx\n", smp_processor_id(),
					__FUNCTION__, (u64)page, page_ref_count(page), (u64)page_address(page));
			panic("P %llx: %llx  has %d refcnt\n", (u64)page, (u64)page_address(page), page_ref_count(page));
		}
		assert(is_maio_page(page));
		init_page_count(page);

		/* get_page as this page will houses two mbufs */
		get_page(page);
		data = buffer + maio_get_page_headroom(NULL);
#if 0
		qp->cached_mbuf = data + maio_get_page_stride(NULL);
	}
#endif
	return data;
}
#endif

static inline int get_rx_qp_idx(struct net_device *netdev)
{
	return dev_map.on_rx[netdev->ifindex];
}

static inline int get_tx_netdev_idx(u64 dev_idx)
{
	static int prev;

	if (unlikely(dev_map.on_tx[dev_idx] != prev)) {
		prev = dev_map.on_tx[dev_idx];
		pr_err("%s) %llx -> %d\n", __FUNCTION__, dev_idx, prev);
	}
	return dev_map.on_tx[dev_idx];
}

static inline int setup_dev_idx(unsigned dev_idx)
{
	struct net_device *dev, *iter_dev;
	struct list_head *iter;

	if ( !(dev = dev_get_by_index(&init_net, dev_idx)))
		return -ENODEV;

	if (netif_is_bond_slave(dev))
		return -EINVAL;

//TODO: rm on_tx
	dev_map.on_tx[dev_idx] = dev_idx;
	dev_map.on_rx[dev_idx] = dev_idx;

	netdev_for_each_lower_dev(dev, iter_dev, iter) {
		trace_printk("[%s:%d]lower: device %s [%d]added\n", iter_dev->name, iter_dev->ifindex, iter_dev->name, iter_dev->ifindex);
		pr_err("[%s:%d]lower: device %s [%d]added\n", iter_dev->name, iter_dev->ifindex, iter_dev->name, iter_dev->ifindex);

		if (dev_map.on_tx[dev_idx] != dev_idx) {
			//In case of multiple slave devs; on TX use the master dev.
			dev_map.on_tx[dev_idx] = dev_idx;
		} else  {
			//on TX use the slave dev.
			dev_map.on_tx[dev_idx] = iter_dev->ifindex;
		}
		//On RX choose the correct  QP
		dev_map.on_rx[iter_dev->ifindex] = dev_idx;
		//maio_dev_configured[iter_dev->ifindex] = true;
		maio_devs[iter_dev->ifindex] = iter_dev;
	}

	maio_devs[dev_idx] = dev;
	return 0;
}

#define show_io(...)

#ifndef show_io
#define show_io	__show_io
#endif
static inline void __show_io(void *addr, const char *str)
{
	struct io_md 	*md 	= virt2io_md(addr);
	struct ethhdr   *eth    = addr;
	struct iphdr    *iphdr  = (struct iphdr *)&eth[1];

	trace_printk("%s>\t SIP: %pI4 DIP: %pI4\n"
			"\t len %d [%x] (vlan %d [%d]): state %llx\n"
			,str, &iphdr->saddr, &iphdr->daddr,
			md->len, md->poison, md->vlan_tci, md->flags, md->state);
}

static inline bool test_maio_filter(void *addr)
{
       struct ethhdr   *eth    = addr;
       struct iphdr    *iphdr  = (struct iphdr *)&eth[1];

       /* network byte order of loader machine */
       int trgt = (10|5<<8|3<<16|4<<24);


       if (trgt == iphdr->saddr) {
               trace_debug("SIP: %pI4 N[%x] DIP: %pI4 N[%x]\n", &iphdr->saddr, iphdr->saddr, &iphdr->daddr, iphdr->daddr);
               return 0;
       }

       trgt = (10|5<<8|3<<16|9<<24);

       if (trgt == iphdr->saddr) {
               trace_debug("SIP: %pI4 N[%x] DIP: %pI4 N[%x]\n",
				&iphdr->saddr, iphdr->saddr, &iphdr->daddr, iphdr->daddr);
               return 0;
       }
       return 1;
}

/* Capture all but ssh traffic */
static inline bool default_maio_filter(void *addr)
{
	struct ethhdr   *eth    = addr;
	struct iphdr    *iphdr  = (struct iphdr *)&eth[1];
	struct tcphdr	*tcphdr = (struct tcphdr *)&iphdr[1];

	if (ntohs(tcphdr->dest) == 22) {
		return 1;
	}

	return 0;
}

void reset_maio_default_filter(void)
{
	maio_filter = test_maio_filter;
}
EXPORT_SYMBOL(reset_maio_default_filter);


static inline int filter_packet(void *addr)
{
	return maio_filter(addr);
}

#define rx_ring_enrty(qp)	(qp)->rx_ring[(qp)->rx_counter & ((qp)->rx_sz -1)]
#define clear_rx_ring_entry(qp)	(qp)->rx_ring[(qp)->rx_counter & ((qp)->rx_sz -1)] = 0
#define post_rx_ring(qp, val)	(qp)->rx_ring[(qp)->rx_counter++ & ((qp)->rx_sz -1)] = val

static inline void collect_rx_refill_page(u64 addr)
{
	void *kaddr = uaddr2addr(addr & PAGE_MASK);
	struct io_md *md = virt2io_md(kaddr);
	struct page *page = virt_to_page(kaddr);

	inc_state(MAIO_PAGE_REFILL);

	if (PageHead(page)) {
		md->state = MAIO_PAGE_USER;
		set_page_state(page, MAIO_PAGE_HEAD);
		assert(!is_maio_page(page));
		inc_err(MAIO_ERR_REFILL_HEAD);

		smp_wmb();
		maio_cache_head(page);
	} else {

		assert(is_maio_page(page));
		assert(get_maio_elem_order(__compound_head(page, 0)) == 0);
		if (get_page_state(page) != MAIO_PAGE_REFILL) {
			dump_page_state(page);
			panic("Illegal state\n");
		}
		maio_trace_page_rc(page, MAIO_PAGE_RC_REFILL);
		/* page refill is set by user */
		md->state = MAIO_PAGE_USER;
		set_page_count(page, 0);
		set_page_state(page, MAIO_PAGE_FREE);

		smp_wmb();
		maio_free_elem(kaddr, 0);
	}
}
static inline int prep_rx_ring_entry(struct percpu_maio_qp *qp)
{
	u64 ring_entry = rx_ring_enrty(qp);

	if (unlikely(!ring_entry)) {
		inc_err(MAIO_ERR_REFILL_MISSING);
	}

	if (likely(ring_entry & 0x1)) {
		clear_rx_ring_entry(qp);
		collect_rx_refill_page(ring_entry);
	}

	ring_entry = rx_ring_enrty(qp);
	if (ring_entry) {
		inc_err(MAIO_ERR_RX_SLOW);
		return 1;
	}

	return 0;
}

//TODO: Add support for vlan detection __vlan_hwaccel
static inline int __maio_post_rx_page(struct net_device *netdev, struct page *page,
					void *addr, u32 len, u16 vlan_tci, u16 flags)
{
	u64 qp_idx = get_rx_qp_idx(netdev);
	struct io_md *md;
	struct percpu_maio_dev_qp *dev_qp = this_cpu_ptr(&maio_dev_qp);
	struct percpu_maio_qp *qp;

	if (qp_idx == -1) {
		return 0;
	}

	if (unlikely(!maio_configured(qp_idx)))
		return 0;

	qp = &dev_qp->qp[qp_idx];

	if (filter_packet(addr)) {
		//trace_printk("skiping...\n");
		return 0;
	}

	if (unlikely(prep_rx_ring_entry(qp))) {
		if (page) {
			/* its a MAIO page and we consume it */
			set_page_state(page, MAIO_PAGE_CONSUMED);
			smp_wmb();
			put_page(page);
		}
		return 1;
	}

	trace_debug("kaddr %llx, len %d\n", (u64)addr, len);

#define HP_CACHE_LIM 64
	if (unlikely(head_cache_size > HP_CACHE_LIM)) {
		if (page) {
			inc_err(MAIO_ERR_HEAD_RETURNED);
			put_page(page);
			page = NULL;
		}
	}

	if (!page) {
		void *buff;

		if (head_cache_size) {
			page = maio_get_cached_head();
		}

		if (!page)
			page = __maio_alloc_page();

		if (unlikely(!page)) {
			inc_err(MAIO_ERR_RX_ALLOC);
			return 0;
		}

		buff = page_address(page);

		buff = (void *)((u64)buff + maio_get_page_headroom(NULL));

		memcpy(buff, addr, len);
		addr = buff;
		trace_debug("RX: copy to page %llx addr %llx\n", (u64)page, (u64)addr);

		/* the orig copy is not used so ignore */
	}
#if 0
	/*
		This is the right thing to do, but hv_net someties panics here wtf?!
		Shitty M$ paravirt implementation. Thats why maio_post_rx_page looks like shit.
	*/
	else {
		get_page(page);
	}
#endif

	if (unlikely( ! (get_page_state(page) & (MAIO_PAGE_RX|MAIO_PAGE_HEAD)))) {
		dump_page_state(page);
		assert(get_page_state(page) & (MAIO_PAGE_RX|MAIO_PAGE_HEAD));
	}

	set_page_state(page, MAIO_PAGE_USER);
	assert(uaddr2addr(addr2uaddr(addr)) == addr);
	md = virt2io_md(addr);
	md->len 	= len;
	md->poison	= MAIO_POISON;
	md->vlan_tci	= vlan_tci;
	md->flags	= flags;

	show_io(addr, "RX");
#if 1
	smp_wmb();
	post_rx_ring(qp, addr2uaddr(addr));
	trace_debug("%d:RX %s:%llx[%u]%llx{%d}\n", smp_processor_id(),
			page ? "COPY" : "ZC",
			(u64)addr, len,
			addr2uaddr(addr), page_ref_count(page));
#else
/***************
	Testing NAPI code:
		1. post to napi ring.
		2. schedule/call.
**************/


	/** debugging napi rx **/
	if (1) {
		struct maio_tx_thread *tx_thread;
		static long unsigned tx_counter;
		tx_thread = &maio_tx_threads[netdev->ifindex].tx_thread[NAPI_THREAD_IDX];
		//maio_post_napi_page(tx_thread/*, napi*/);
		tx_thread->tx_ring[tx_counter & (tx_thread->tx_sz -1)] = addr2uaddr(addr);
		++tx_counter;
		trace_debug("%d:RX[%lu] %s:%llx[%u]%llx{%d}\n", smp_processor_id(),
			tx_counter & (tx_thread->tx_sz -1),
			page ? "COPY" : "ZC",
			(u64)addr, len,
			addr2uaddr(addr), page_ref_count(page));

		maio_post_napi_page(tx_thread/*, napi*/);
	}
#endif
	return 1; //TODO: When buffer taken. put page of orig.
}

int maio_post_rx_page_copy(struct net_device *netdev, void *addr, u32 len, u16 vlan_tci, u16 flags)
{
	/* NULL means copy data to MAIO page*/
	return __maio_post_rx_page(netdev, NULL, addr, len, vlan_tci, flags);
}
EXPORT_SYMBOL(maio_post_rx_page_copy);

int maio_post_rx_page(struct net_device *netdev, void *addr, u32 len, u16 vlan_tci, u16 flags)
{
	struct page* page = virt_to_page(addr);

	if (is_maio_page(page))
		get_page(page);
	else
		page = NULL;

	if ( ! __maio_post_rx_page(netdev, page, addr, len, vlan_tci, flags)) {
		if (page) {
			inc_err(MAIO_ERR_NS);
			set_page_state(page, MAIO_PAGE_NS);
			smp_wmb();
			put_page(page);
		}
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(maio_post_rx_page);

//TODO: Loop inside lock
// use dev_direct_xmit / xsk_generic_xmit
#define is_dev_busy(dev) netif_xmit_frozen_or_drv_stopped(netdev_get_tx_queue(dev, smp_processor_id()))
int maio_xmit(struct net_device *dev, struct sk_buff **skb, int cnt)
{
	int err = 0, i = 0, more = cnt;
        struct netdev_queue *txq = netdev_get_tx_queue(dev, smp_processor_id());

	if (unlikely(!skb)) {
		err = -ENOMEM;
                goto unlock;
        }
        local_bh_disable();
        HARD_TX_LOCK(dev, txq, smp_processor_id());

        if (unlikely(netif_xmit_frozen_or_drv_stopped(txq))) {
		err = -EBUSY;
		inc_err(MAIO_ERR_TX_BUSY);

		goto unlock;
        }
        //refcount_add(burst, &pkt_dev->skb->users);

	for ( i = 0; i < cnt; i++) {

		err = netdev_start_xmit(skb[i], dev, txq, --more);
		if (!dev_xmit_complete(err)) {
			const skb_frag_t *frag = &skb_shinfo(skb[i])->frags[0];
			inc_err(MAIO_ERR_TX_ERR_NETDEV);
			maio_trace_page_rc(frag->bv_page, (0xFF<<2));
			consume_skb(skb[i]);
		}
	}
	err = 0;

unlock:
        HARD_TX_UNLOCK(dev, txq);
        local_bh_enable();

	return err;
}

//Uaddr in TX ring is valid when lsb is set.
static inline u64 tx_ring_entry(struct maio_tx_thread *tx_thread)
{
	u16 idx = tx_thread->tx_counter & (tx_thread->tx_sz -1);
	u64 uaddr = tx_thread->tx_ring[idx];
	return  (uaddr & 0x1) ? (uaddr & (~0x1)) : 0;
}

//Zero out LSB and advance counter.
static inline void advance_tx_ring(struct maio_tx_thread *tx_thread)
{
	u16 idx = tx_thread->tx_counter & (tx_thread->tx_sz -1);
	tx_thread->tx_ring[idx] = (tx_thread->tx_ring[idx] & (~0x1));
	++tx_thread->tx_counter;
}

#define MAIO_OWNED_SKB	0xA1000000
static inline void maio_skb_get(struct sk_buff *skb)
{
	skb->mark++;
}

static inline void maio_skb_put(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int i = 0;

	if (!(skb->mark & 0xff)) {
		pr_err("skb mark :: 0x%x\n", skb->mark);
		for (i = 0; i < shinfo->nr_frags; i++) {
			const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			dump_page_state(frag->bv_page);
		}
		panic("double free\n");
	} else {
		skb->mark--;
	}
}

void maio_skb_free(struct sk_buff *skb)
{
	static int verbose;

	if (unlikely(!verbose++))
		trace_printk("%s!! [0x%x] \n", __FUNCTION__, skb->mark);
	maio_skb_put(skb);
}

#define MAIO_TX_SKB_SIZE	64
static inline struct sk_buff *maio_alloc_skb(struct net_device *netdev)
{
	struct page_frag_cache *nc;
	struct sk_buff *skb;
	bool pfmemalloc;
	unsigned int len;
	void *data;
	gfp_t	gfp_mask = GFP_KERNEL;

	len = SKB_DATA_ALIGN(MAIO_TX_SKB_SIZE + sizeof(struct skb_shared_info));

	if (sk_memalloc_socks())
		gfp_mask |= __GFP_MEMALLOC;

	nc = this_cpu_ptr(&tx_page_frag);
	data = page_frag_alloc(nc, len, gfp_mask);
	pfmemalloc = nc->pfmemalloc;

	if (unlikely(!data))
		return NULL;

	skb = __build_skb(data, len);
	if (unlikely(!skb)) {
		skb_free_frag(data);
		return NULL;
	}

	if (pfmemalloc)
		skb->pfmemalloc = 1;
	skb->head_frag = 1;
	skb->dev = netdev;

	skb->mark = MAIO_OWNED_SKB;
	skb->destructor = maio_skb_free;
	return skb;
}

struct sk_buff *maio_build_linear_rx_skb(struct net_device *netdev, void *va, size_t size)
{
	void *page_address = (void *)((u64)va & PAGE_MASK);
	struct sk_buff *skb = build_skb(page_address, IO_MD_OFF);

	if (unlikely(!skb))
		return NULL;

	trace_debug(">>> va %llx offset %llu size %lu shinfo %llx marker %llx [%lld]\n", (u64)va,
			(u64)(va - page_address), size, (u64)skb_shinfo(skb), (u64)page2track(virt_to_page(va)),
			(u64)skb_shinfo(skb) - (u64)page2track(virt_to_page(va)));
	skb_reserve(skb, va - page_address);
	skb_put(skb, size);

	skb->mac_len = ETH_HLEN;

	//skb_record_rx_queue(skb, 0);
	skb->protocol = eth_type_trans(skb, netdev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->dev = netdev;

	return skb;
}

struct sk_buff *maio_build_linear_tx_skb(struct net_device *netdev, void *va, size_t size)
{
	void *page_address = (void *)((u64)va & PAGE_MASK);
	struct sk_buff *skb = build_skb(page_address, IO_MD_OFF);

	if (unlikely(!skb))
		return NULL;

	trace_debug(">>> va %llx offset %llu size %lu shinfo %llx marker %llx [%lld]\n", (u64)va,
			(u64)(va - page_address), size, (u64)skb_shinfo(skb), (u64)page2track(virt_to_page(va)),
			(u64)skb_shinfo(skb) - (u64)page2track(virt_to_page(va)));
	skb_reserve(skb, va - page_address);
	skb_put(skb, size);
	skb->dev = netdev;

	return skb;
}

static void maio_zc_tx_callback(struct ubuf_info *ubuf, bool zc_success)
{
	struct io_md *md = ubuf->ctx;
	struct page *page = virt_to_page(md);
	int in_transit = 1;

	assert(get_maio_uaddr(page));
	if (unlikely(!(get_page_state(page) & (MAIO_PAGE_TX|MAIO_PAGE_NAPI)))) {
		dump_page_state(page);
	}
	assert(get_page_state(page) & (MAIO_PAGE_TX|MAIO_PAGE_NAPI));

	maio_trace_page_rc(page, MAIO_PAGE_RC_COMP);

	if (refcount_dec_and_test(&ubuf->refcnt)) {
		set_page_state(page, MAIO_PAGE_USER);
		inc_err(MAIO_ERR_TX_COMP);
		in_transit = 0;
		assert(get_err(MAIO_ERR_TX_COMP) <= get_err(MAIO_ERR_TX_START));
	} else {
		inc_err(MAIO_ERR_TX_COMP_TRANS);
	}

	last_comp = addr2uaddr(md);
	md->in_transit = in_transit;
	md->in_transit_dbg++;
	//trace_printk("%s: %llx TX in_transit %s [%d]<%d>\n", __FUNCTION__, (u64)ubuf,
	//		in_transit ? "YES": "NO", refcount_read(&ubuf->refcnt), md->in_transit_dbg);
	//trace_page_state(page);
}

# if 0
static inline void maio_clear_ubuf_cache(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ubuf_cache_lock, flags);
	while (ubuf_cache_head) {
		struct ubuf_info *ubuf = ubuf_cache_head;
		struct io_md *md = ubuf->ctx;

		ubuf_cache_head = (void *)ubuf->mmp.user;

		if (likely(md->in_transit == 0)) {
			/* This shouldnt happen -- better leak this */
			//TODO: Add counter.
			kmem_cache_free(ubuf_cache, ubuf);
		}
		--ubuf_cache_size;
	}
	spin_unlock_irqrestore(&ubuf_cache_lock, flags);
}

static inline struct ubuf_info *maio_ubuf_alloc(void)
{
	unsigned long flags;
	struct ubuf_info *ubuf = kmem_cache_alloc(ubuf_cache, GFP_KERNEL|__GFP_ZERO);

	if (unlikely(!ubuf))
		return NULL;

	memset(ubuf, 0, sizeof(struct ubuf_info));
	spin_lock_irqsave(&ubuf_cache_lock, flags);
	ubuf->mmp.user =  (void *)ubuf_cache_head;
	ubuf_cache_head = ubuf;
	++ubuf_cache_size;
	spin_unlock_irqrestore(&ubuf_cache_lock, flags);

	return ubuf;
}

static inline void set_maio_page_uarg(struct page *page, struct ubuf_info *uarg)
{
	struct ubuf_info **arr = get_maio_uarg(page);

	assert(arr);

	arr[(int)(page - compound_head(page))] = uarg;
}
# endif

static inline void flush_all_memcaches(void)
{
	while (maio_get_cached_head());
	pr_err("Flushed misc_cache %lu\n", head_cache_size);
}

static inline struct ubuf_info *get_maio_page_uarg(struct page *page)
{
	struct page_priv_ctx *ctx = get_maio_uarg(page);

	return &ctx->ubuf[(int)(page - compound_head(page))];
}

static inline int maio_set_comp_handler(struct sk_buff *skb, struct io_md *md)
{
	struct page *page = virt_to_page(md);
	struct ubuf_info *uarg = get_maio_page_uarg(page);

	md->in_transit		= 1;
	uarg->callback		= maio_zc_tx_callback;
	uarg->ctx 		= md;
	/* ctx, and callback should always be the same */

	uarg->desc		= (unsigned long)(skb);
	refcount_inc(&uarg->refcnt);

	/* make sure the uarg is correct before its visible */
	smp_wmb();
# if 0
	trace_printk("%s: %llx TX in_transit %s [%d]\n", __FUNCTION__, (u64)uarg,
			md->in_transit ? "YES": "NO", refcount_read(&uarg->refcnt));
	trace_page_state(page);
#endif
	skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
	skb_shinfo(skb)->destructor_arg = uarg;
	return 1;
}

#if 0
static inline void collect_refill_page(struct page *page, void *kaddr)
{
	trace_debug("TX] Zero refcount page %llx(state %llx [%u]<%llx>[%u] )[%d] addr %llx -- PANIC\n"
			"TX] transit %d transitcnt %u [%d/%d]\n",
			(u64)page, get_page_state(page), md->line,
			md->prev_state, md->prev_line, page_ref_count(page), (u64)kaddr,
			md->in_transit, md->in_transit_dbg, md->tx_cnt, md->tx_compl);

	//set_page_state(page, MAIO_PAGE_RX);
	//put_page(page); /*TODO:  Is this Valid?*/

	inc_state(MAIO_LWM_PAGE);
	set_page_count(page, 0);
	set_page_state(page, MAIO_PAGE_FREE);
	maio_free_elem(kaddr, 0);
}
#endif

static inline void *common_egress_handling(void *kaddr, struct page *page, u64 uaddr)
{
	unsigned len;
	struct io_md *md = NULL;

	if (unlikely(IS_ERR_OR_NULL(kaddr))) {
		trace_printk("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
		pr_err("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
		return NULL;
	}

	if (unlikely( ! page_ref_count(page))) {
		/* This check only makes sense if pages are zeroed out (?) */
		if (unlikely(get_page_state(page))) {
			md = virt2io_md(kaddr);

			pr_err("%ps] Zero refcount page %llx(state %llx [%u]<%llx>[%u] )[%d] addr %llx"
				"%ps] transit %d transitcnt %u [%d/%d]\n",
				__builtin_return_address(0),
				(u64)page, get_page_state(page), md->line,
				md->prev_state, md->prev_line, page_ref_count(page), (u64)kaddr,
				__builtin_return_address(0),
				md->in_transit, md->in_transit_dbg, md->tx_cnt, md->tx_compl);
			panic("Illegal page state\n");
		}
		init_page_count(page);
	}

	md = virt2io_md(kaddr);

	if (unlikely(!is_maio_page(page))) {

		if (!PageHead(page)) {
			pr_err("This shit cant happen!\n"); //uaddr2addr would fail first
			return NULL;
		}
#if 0
		else {
			trace_printk("%s with HeadPage\n", __FUNCTION__);
# Now with zc-callback we dont care about HeadPages on TX.
			void *buff;

			//set_maio_is_io(page);
			set_page_state(page, MAIO_PAGE_HEAD); // Need to add on NEW USER pages.

			/* Head Pages cant be used for refill */
			if (!md->len)
				return NULL;

			page = __maio_alloc_page();
			if (!page)
				return NULL;
			buff = page_address(page);

			buff = (void *)((u64)buff + maio_get_page_headroom(NULL));

			md = virt2io_md(kaddr);

			len = md->len;

			trace_debug("%ps] :COPY %u [%u] to page %llx[%d] addr %llx\n",
					__builtin_return_address(0),
					len, maio_get_page_headroom(NULL),
					(u64)page, page_ref_count(page), (u64)kaddr);
			assert(len <= (PAGE_SIZE - maio_get_page_headroom(NULL)));

			memcpy(buff, kaddr, len);
			memcpy(virt2io_md(buff), md, sizeof(struct io_md));
			/* For the assert */
			set_page_state(page, MAIO_PAGE_USER);

			kaddr = buff;
		} else {
#endif
	}

	if (unlikely(md->poison != MAIO_POISON)) {
		pr_err("NO MAIO-POISON <%x>Found [%llx] -- Please make sure to put the buffer\n"
			"page %llx: %s:%s %llx ",
			md->poison, uaddr, (u64)page,
			is_maio_page(page)?"MAIO":"OTHER",
			PageHead(page)?"HEAD":"Tail",
			get_maio_uaddr(page));

		panic("This should not happen\n");
		return NULL;
	}

//TODO: Consider adding ERR flags to ring entry.

	len 	= md->len + SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	trace_debug("%ps %llx/%llx [%d]from user %llx [#%d]\n",
			__builtin_return_address(0),
			(u64)kaddr, (u64)page, page_ref_count(page),
			(u64)uaddr, cnt);

	if (unlikely(((uaddr & (~PAGE_MASK)) + len) > PAGE_SIZE)) {
		pr_err("Buffer to Long [%llx] len %u klen = %u\n", uaddr, md->len, len);
		return NULL;
	}
	return md;
}

static inline void maio_free_skb_batch(struct sk_buff **skb, int cnt)
{
	while (cnt--) {
		const skb_frag_t *frag = &skb_shinfo(*skb)->frags[0];
		maio_trace_page_rc(frag->bv_page, (0xFE<<2));
		consume_skb(*skb);
		++skb;
	}
}

#define __min(a, b) ((a) < (b) ? (a) : (b))
static inline int maio_skb_add_frags(struct sk_buff *skb, char *kaddr)
{
	struct io_md *md = virt2io_md(kaddr);
	int len = __min(MAIO_TX_SKB_SIZE, md->len);
	int nr_frags = 0;

	memcpy(skb->data, kaddr, len);
	skb_put(skb, len);

	if (unlikely(md->len > MAIO_TX_SKB_SIZE)) {
		kaddr 	+= MAIO_TX_SKB_SIZE;
		md->len -= MAIO_TX_SKB_SIZE;
	 } else
		kaddr = (md->next_frag) ? uaddr2addr(md->next_frag) : NULL;

	while (kaddr) {
		struct page *page = virt_to_page(kaddr);
		size_t offset = ((u64)kaddr & (~PAGE_MASK));

		/*TODO: Leaking skb */
		if (unlikely(nr_frags >= MAX_SKB_FRAGS)) {
			pr_err("Packet exceeds the number of skb frags(%lu)\n",
			       MAX_SKB_FRAGS);
			return -EFAULT;
		}

		get_page(page);
		md = virt2io_md(kaddr);

		skb_fill_page_desc(skb, nr_frags, page, offset, md->len);
		skb->data_len += md->len;
		skb->truesize += md->len;
		skb->len += md->len;
		++nr_frags;
		if (nr_frags > 1)
			trace_printk("Ehh? %d %llx\n", nr_frags, (u64)page);

		kaddr = (md->next_frag) ? uaddr2addr(md->next_frag) : NULL;
	};
	//skb->ip_summed = CHECKSUM_PARTIAL;

	return 0;
}

#define TX_BATCH_SIZE	64
int maio_post_tx_page(void *state)
{
	struct maio_tx_thread *tx_thread = state;
	struct sk_buff *skb_batch[TX_BATCH_SIZE];
	struct io_md *md;
	u64 uaddr = 0;
	int rc = 0, cnt = 0;
	u64 netdev_idx = tx_thread->dev_idx;

	assert(netdev_idx != -1);

	if (unlikely(is_dev_busy(tx_thread->netdev))) {
		inc_err(MAIO_ERR_TX_BUSY_EARLY);
		return 0;
	}
	trace_debug("[%d]Starting\n",smp_processor_id());

	while ((uaddr = tx_ring_entry(tx_thread))) {
		struct sk_buff *skb;
		void 		*kaddr	= uaddr2addr(uaddr);
		struct page     *page	= virt_to_page(kaddr);

		if ((md = common_egress_handling(kaddr, page, uaddr)) == NULL) {
			inc_err(MAIO_ERR_TX_ERR);
			advance_tx_ring(tx_thread);
			continue;
		}

		skb = maio_alloc_skb(tx_thread->netdev); //kaddr, md->len);
		if (unlikely(!skb)) {
			pr_err("%s) Failed to alloc skb\n", __FUNCTION__);
			inc_err(MAIO_ERR_TX_ERR);
			advance_tx_ring(tx_thread);
			continue;
		}

		if (maio_skb_add_frags(skb, kaddr)) {
			pr_err("%s) Failed to add frags\n", __FUNCTION__);
			inc_err(MAIO_ERR_TX_FRAG_ERR);
			advance_tx_ring(tx_thread);
			continue;
		}
		maio_trace_page_rc(page, MAIO_PAGE_RC_TX);

		if (md->flags & MAIO_STATUS_VLAN_VALID)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), md->vlan_tci);

		if (likely(maio_set_comp_handler(skb, md))) {
			skb_batch[cnt++] = skb;
			maio_skb_get(skb);
			set_page_state(page, MAIO_PAGE_TX);
			inc_err(MAIO_ERR_TX_START);
		} else {
			pr_err("ubuf_info alloc failure");
			inc_err(MAIO_ERR_TX_ERR);
		}

		advance_tx_ring(tx_thread);

		if (unlikely(cnt >= TX_BATCH_SIZE))
			break;
	}

	trace_debug("%d: Sending %d buffers. counter %lu\n", smp_processor_id(), cnt, tx_thread->tx_counter);
	if (likely(cnt))
		if (unlikely(rc = maio_xmit(tx_thread->netdev, skb_batch, cnt)))
			maio_free_skb_batch(skb_batch, cnt);

	return cnt;
}

#define MAIO_TX_KBUFF_SZ	64
static inline ssize_t maio_tx(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{
	char	kbuff[MAIO_TX_KBUFF_SZ], *cur;
	struct maio_tx_thread *tx_thread;
	size_t 	dev_idx, ring_id;
#ifdef MAIO_ASYNC_TX
	struct task_struct *thread;
#endif

	if (unlikely(size < 1 || size >= MAIO_TX_KBUFF_SZ))
	        return -EINVAL;

	if (copy_from_user(kbuff, buf, size)) {
		return -EFAULT;
	}

	dev_idx = simple_strtoull(kbuff, &cur, 10);
	ring_id = simple_strtoull(cur + 1, &cur, 10);

	if (unlikely(!maio_configured(dev_idx)))
		return 0;

	if (unlikely(!global_maio_matrix[dev_idx])) {
		pr_err("global matrix not configured!!!");
		return -ENODEV;
	}

	tx_thread	= &maio_tx_threads[dev_idx].tx_thread[ring_id];

#ifdef MAIO_ASYNC_TX
	thread		= tx_thread->thread;

	if (thread->state & TASK_NORMAL) {
		unsigned long  val;
	        val = wake_up_process(thread);
	        trace_debug("[%d]wake up thread[state %0lx][%s]\n", smp_processor_id(), thread->state, val ? "WAKING":"UP");
	}
#else
	while( maio_post_tx_page(tx_thread));
#endif

	return size;
}

static inline ssize_t maio_napi(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{
	struct maio_tx_thread *tx_thread;
	char	kbuff[MAIO_TX_KBUFF_SZ], *cur;
	size_t 	dev_idx, ring_id;

	if (unlikely(size < 1 || size >= MAIO_TX_KBUFF_SZ))
	        return -EINVAL;

	if (copy_from_user(kbuff, buf, size)) {
		return -EFAULT;
	}

	dev_idx = simple_strtoull(kbuff, &cur, 10);
	ring_id = simple_strtoull(cur + 1, &cur, 10);

	if (unlikely(!maio_configured(dev_idx)))
		return 0;

	if (unlikely(ring_id != NAPI_THREAD_IDX)) {
		pr_err("wrong NAPI_THREAD_IDX %lu != %u\n", ring_id, NAPI_THREAD_IDX);
		return -ENODEV;
	}

	if (unlikely(!global_maio_matrix[dev_idx])) {
		pr_err("global matrix not configured!!!");
		return -ENODEV;
	}

	trace_debug("scheduling NAPI for dev %lu\n", dev_idx);
	tx_thread = &maio_tx_threads[dev_idx].tx_thread[ring_id];
	maio_post_napi_page(tx_thread/*, napi*/);
	//TODO: consider napi_schedule_irqoff -- is this rentrant
	//napi_schedule(napi);
	return size;
}

#ifdef MAIO_ASYNC_TX
static int maio_post_tx_task(void *state)
{

        while (!kthread_should_stop()) {
		trace_debug("[%d]Running...\n", smp_processor_id());
		while (maio_post_tx_page(state)); // XMIT as long as there is work to be done.

		trace_debug("[%d]sleeping...\n", smp_processor_id());
                set_current_state(TASK_UNINTERRUPTIBLE);
                if (!kthread_should_stop()) {
                        schedule();
                }
                __set_current_state(TASK_RUNNING);
        }
        return 0;
}
#endif

static inline int create_threads(void)
{
#if 0
	if (maio_tx_thread[dev_idx])
		return 0;

	maio_tx_thread[dev_idx] = kthread_create(threadfn, <dev_idx>, "maio_tx_thread");
	if (IS_ERR(maio_tx_thread[dev_iddev_idx]))
		return -ENOMEM;
	pr_err("maio_tx_thread created\n");
#endif
	return 0;
}

static inline size_t __maio_change_state(size_t val, size_t dev_idx)
{
	pr_err("%s: dev %lu:: Now: [%s] was %s\n", __FUNCTION__, dev_idx, val ? "Configured" : "Off", maio_configured(dev_idx) ? "Configured" : "Off");
	trace_printk("%s: dev %lu:: Now: [%s] was %s\n", __FUNCTION__, dev_idx, val ? "Configured" : "Off", maio_configured(dev_idx) ? "Configured" : "Off");


	if (val == 0 || val == 1) {
		struct net_device *dev, *iter_dev;
		struct list_head *iter;
		//const struct net_device_ops *ops;

		if ( !(dev = dev_get_by_index(&init_net, dev_idx)))
			return -ENODEV;

		if (netif_is_bond_slave(dev))
			return -EINVAL;

		maio_dev_configured[dev_idx] = val;

		netdev_for_each_lower_dev(dev, iter_dev, iter) {
			maio_dev_configured[iter_dev->ifindex] = val;
#ifdef FLUSH_ON_STATE_CHANGE
			ops = iter_dev->netdev_ops;

			pr_err("%s: Flushing mem from [%d] %s (%s)\n", __FUNCTION__, iter_dev->ifindex, iter_dev->name, ops->ndo_dev_reset ? "Flush" : "NOP");

			if (ops->ndo_dev_reset) {
				ops->ndo_dev_reset(dev);
			}
#endif
		}
	} else
		return -EINVAL;
#if 0
	if (val)
		napi_enable(&maio_tx_threads[dev_idx].napi);
	else
		napi_disable(&maio_tx_threads[dev_idx].napi);
#endif
	return 0;
}

static inline ssize_t maio_enable(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{	char	*kbuff, *cur;
	size_t 	val, dev_idx, rc;

	if (size < 1 || size >= PAGE_SIZE)
	        return -EINVAL;

	kbuff = memdup_user_nul(buf, size);
	if (IS_ERR(kbuff))
	        return PTR_ERR(kbuff);

	val 	= simple_strtoull(kbuff, &cur, 10);
	dev_idx = simple_strtoull(cur + 1, &cur, 10);

	if (unlikely(!global_maio_matrix[dev_idx])) {
		pr_err("global matrix not configured!!!");
		return -ENODEV;
	}

	kfree(kbuff);

	rc = __maio_change_state(val, dev_idx);
	return rc ? rc : size;
}

/*x86/boot/string.c*/
static unsigned int atou(const char *s)
{
	unsigned int i = 0;

	while (isdigit(*s))
		i = i * 10 + (*s++ - '0');
	return i;
}

static int maio_post_napi_page(struct maio_tx_thread *tx_thread/*, struct napi_struct *napi*/)
{
	struct io_md *md;
	u64 uaddr = 0;
	int cnt = 0;
	u64 netdev_idx = tx_thread->dev_idx;

	assert(netdev_idx != -1);

	trace_debug("[%d]Starting <%lu>\n",smp_processor_id(), tx_thread->tx_counter & ((tx_thread)->tx_sz -1));

	while ((uaddr = tx_ring_entry(tx_thread))) {
		struct sk_buff *skb;
		void 		*kaddr	= uaddr2addr(uaddr);
		struct page     *page	= virt_to_page(kaddr);

		if ((md = common_egress_handling(kaddr, page, uaddr)) == NULL) {
			advance_tx_ring(tx_thread);
			inc_err(MAIO_ERR_TX_ERR);
			continue;
		}

		skb = maio_build_linear_rx_skb(tx_thread->netdev, kaddr, md->len);
		if (unlikely(!skb)) {
			inc_err(MAIO_ERR_TX_ERR);
			pr_err("Failed to alloc napi skb\n");
			put_page(page);
			advance_tx_ring(tx_thread);
			continue;
		}
		cnt++;
		//TODO: set completion handler.
		if (likely(maio_set_comp_handler(skb, md))) {
			get_page(page);
			set_page_state(page, MAIO_PAGE_NAPI);
			inc_err(MAIO_ERR_NAPI);
		} else {
			pr_err("Leaking a TX buffer due to ubuf_info alloc failure");//TODO: HAndle this
			inc_err(MAIO_ERR_TX_ERR);
		}

		//OPTION: Use non napi API: netif_rx but lose GRO.
		netif_rx(skb);
		//napi_gro_receive(napi, skb);

		advance_tx_ring(tx_thread);

		if (unlikely(cnt >= NAPI_BATCH_SIZE))
			break;
	}

	/*
		No need to check rc, we have no IRQs to arm.
		The user process is not running time slice is used here.
	*/
	//napi_complete_done(napi, cnt);
	trace_debug("poll complete %d\n", cnt);
	return cnt;
}


int maio_napi_poll(struct napi_struct *napi, int budget)
{
#if 0
	struct maio_tx_threads *threads = container_of(napi, struct maio_tx_threads, napi);

	return maio_post_napi_page(&threads->tx_thread[NAPI_THREAD_IDX]/*, napi*/);
#else
	return 0;
#endif
}

static inline void setup_maio_napi(unsigned long dev_idx)
{
	struct maio_tx_thread *tx_thread = &maio_tx_threads[dev_idx].tx_thread[NAPI_THREAD_IDX];

	tx_thread->tx_counter 	= 0;
	tx_thread->tx_sz	= global_maio_matrix[dev_idx]->info.nr_tx_sz;
	tx_thread->tx_ring	= uaddr2addr(global_maio_matrix[dev_idx]->info.tx_rings[NAPI_THREAD_IDX]);
	tx_thread->dev_idx	= dev_idx;
	tx_thread->ring_id	= NAPI_THREAD_IDX;
	tx_thread->netdev 	= maio_devs[dev_idx];

        //netif_napi_add(maio_devs[dev_idx], &maio_tx_threads[dev_idx].napi, maio_napi_poll, NAPI_BATCH_SIZE);
}

/*
We accept a USER provided MTRX
	*	Maybe provide a kernel matrix?

*/
static inline ssize_t init_user_rings(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{
	char	*kbuff, *cur;
	void 	*kbase;
	size_t 	len;
	long 	rc = 0, i;
	unsigned dev_idx = -1;
	u64	base;

	if (size <= 1 || size >= PAGE_SIZE)
	        return -EINVAL;

	kbuff = memdup_user_nul(buf, size);
	if (IS_ERR(kbuff))
	        return PTR_ERR(kbuff);

	base 		= simple_strtoull(kbuff, &cur, 16);
	len		= simple_strtol(cur + 1, &cur, 10);
	dev_idx 	= atou(cur + 1);

	pr_err("%s: Got: [0x%llx: %ld] dev idx %u\n", __FUNCTION__, base, len, dev_idx);
	if ( dev_idx > MAX_DEV_NUM)
		return -EINVAL;

	if (setup_dev_idx(dev_idx) < 0)
		return -ENODEV;

	last_dev_idx = dev_idx;

	trace_printk("device %s [%d]added\n", maio_devs[dev_idx]->name, dev_idx);

	kbase = uaddr2addr(base);
	if (!kbase) {
		/*TODO: Is this a thing ? */
		pr_err("WARNING: Uaddr %llx is not found in MTT [0x%llx - 0x%llx) len %ld\n",
			base, cached_mtt->start, cached_mtt->end, len);
		if ((rc = get_user_pages(base, ((PAGE_SIZE -1 + len) >> PAGE_SHIFT),
						FOLL_LONGTERM, &mtrx_pages[0], NULL)) < 0) {
			pr_err("ERROR on get_user_pages %ld\n", rc);
			return rc;
		}
		kbase = page_address(mtrx_pages[0]) + (base & (PAGE_SIZE -1));
		//put_user_pages - follow MTT.
	}
	pr_err("MTRX is set to %llx[%llx] user %llx order [%d] rc = %ld\n",
			(u64)kbase, (u64)page_address(mtrx_pages[0]),
			base, compound_order(virt_to_head_page(kbase)), rc);

	global_maio_matrix[dev_idx] = (struct user_matrix *)kbase;

	pr_err("Set user matrix to %llx [%ld]: RX %d [%d] TX %d [%d]\n", (u64)global_maio_matrix[dev_idx], len,
				global_maio_matrix[dev_idx]->info.nr_rx_rings,
				global_maio_matrix[dev_idx]->info.nr_rx_sz,
				global_maio_matrix[dev_idx]->info.nr_tx_rings,
				global_maio_matrix[dev_idx]->info.nr_tx_sz);

	for_each_possible_cpu(i) {
		struct percpu_maio_dev_qp *dev_qp = per_cpu_ptr(&maio_dev_qp, i);
		struct percpu_maio_qp *qp = &dev_qp->qp[dev_idx];
		struct maio_tx_thread *tx_thread = &maio_tx_threads[dev_idx].tx_thread[i];

		pr_err("[%ld]Ring: RX:%llx  - %llx:: TX: %llx - %llx\n", i,
				global_maio_matrix[dev_idx]->info.rx_rings[i],
				(u64)uaddr2addr(global_maio_matrix[dev_idx]->info.rx_rings[i]),
				global_maio_matrix[dev_idx]->info.tx_rings[i],
				(u64)uaddr2addr(global_maio_matrix[dev_idx]->info.tx_rings[i]));

		qp->rx_counter = 0;
		tx_thread->tx_counter = qp->tx_counter = 0;
		qp->rx_sz = global_maio_matrix[dev_idx]->info.nr_rx_sz;
		tx_thread->tx_sz = qp->tx_sz = global_maio_matrix[dev_idx]->info.nr_tx_sz;
		qp->rx_ring = uaddr2addr(global_maio_matrix[dev_idx]->info.rx_rings[i]);
		tx_thread->tx_ring = qp->tx_ring = uaddr2addr(global_maio_matrix[dev_idx]->info.tx_rings[i]);

		tx_thread->dev_idx = dev_idx;
		tx_thread->ring_id = i;
//#define MAIO_DIRECT_DEV_TX
#ifdef MAIO_DIRECT_DEV_TX
		tx_thread->netdev = maio_devs[dev_map.on_tx[dev_idx]];//maio_devs[dev_idx];
#else
		tx_thread->netdev = maio_devs[dev_idx];
#endif
		pr_err("tx_netdev for %d is %s\n", dev_idx, tx_thread->netdev->name);
#ifdef MAIO_ASYNC_TX
		tx_thread->thread = kthread_create(threadfn, tx_thread, "maio_tx_%d_thread_%ld", dev_idx, i);
		if (IS_ERR(tx_thread->thread)) {
			pr_err("Failed to create maio_tx_%d_thread_%ld\n", dev_idx, i);
			/* Clean teardown */
			return -ENOMEM;
		}
#endif
	}

	setup_maio_napi(dev_idx);
	return size;
}

static inline ssize_t maio_add_pages_0(struct file *file, const char __user *buf,
					    size_t size, loff_t *_pos)
{
	void *kbuff;
	struct meta_pages_0 *meta;
	size_t len;

	if (size <= 1 )//|| size >= PAGE_SIZE)
	        return -EINVAL;

	kbuff = memdup_user_nul(buf, size);
	if (IS_ERR(kbuff))
	        return PTR_ERR(kbuff);

	meta = kbuff;
	pr_err("%s:meta: [%u: 0x%x %u 0x%x]\n", __FUNCTION__, meta->nr_pages, meta->stride, meta->headroom, meta->flags);
	assert(maio_headroom >= meta->headroom);

	for (len = 0; len < meta->nr_pages; len++) {
		void *kbase = uaddr2addr(meta->bufs[len]);
		struct page *page;

		if (!kbase) {
			pr_err("Received an illegal address %0llx\n", meta->bufs[len]);
			return -EINVAL;
		}

		page = virt_to_page(kbase);
		kbase = (void *)((u64)kbase  & PAGE_MASK);

		if (PageHead(page)) {
			set_page_state(page, MAIO_PAGE_HEAD);
			maio_cache_head(page);
			assert(!is_maio_page(page));
		} else {
			trace_debug("[%ld]Adding %llx [%llx]  - P %llx[%d] <%d - %zu>\n", len, (u64 )kbase, meta->bufs[len],
					(u64)page, page_ref_count(page), (int)(page - compound_head(page)), len);
			set_page_count(page, 0);
			set_page_state(page, MAIO_PAGE_FREE);
			assert(get_maio_elem_order(__compound_head(page, 0)) == 0);
			assert(is_maio_page(page));
			maio_free_elem(kbase, 0);
		}
		inc_state(MAIO_PAGE_NEW);
	}
	kfree(kbuff);

	dump_all_stats(NULL);
	return 0;
}

static inline void reset_global_maio_state(void)
{
	int i = 0;
	//memset(&dev_map, -1, sizeof(struct maio_dev_map));
	for (i = 0; i < MAX_DEV_NUM; i++) {
		dev_map.on_tx[i] = -1;
		dev_map.on_rx[i] = -1;
	}

	memset(&memory_stats, 0, sizeof(memory_stats));
	memset(maio_devs, 0, sizeof(maio_devs));
}

/* TODO: stop works globaly - make per dev */
static inline void maio_stop(void)
{
	//maio_disable
	int i = 0, cpu = 0;

	pr_err("%s\n", __FUNCTION__);
	//ndo_dev_stop for each
	for (i = 0; i < MAX_DEV_NUM; i++) {
		struct net_device *dev;
		const struct net_device_ops *ops;

		dev = maio_devs[i];
		if (! maio_devs[i])
			continue;

		__maio_change_state(0, i);
		ops = dev->netdev_ops;
#ifdef MAIO_ASYNC_TX
		for_each_possible_cpu(cpu) {
			int rc;
			char task_comm[TASK_COMM_LEN];
			struct maio_tx_thread *tx_thread = &maio_tx_threads[i].tx_thread[cpu];



			if (IS_ERR_OR_NULL(tx_thread->thread))
				continue;

			get_task_comm(task_comm, tx_thread->thread);
			rc = kthread_stop(tx_thread->thread);

			trace_printk("stopping task %s [%d]\n", task_comm, rc);
		}
#endif
#ifndef FLUSH_ON_STATE_CHANGE
		pr_err("Fluishing mem from [%d:%d] %s (%s)\n", i, dev->ifindex, dev->name, ops->ndo_dev_reset ? "Flush" : "NOP");
		if (ops->ndo_dev_reset) {
			ops->ndo_dev_reset(dev);
		}
#endif
	}

	//magazine empty
	//drain the global full magz, the unsafe alloc_on_cpu only drains core local magz
	i = 0;
	while (mag_alloc_elem(&global_maio.mag[order2idx(0)])) {i++;}

	pr_err("flushed %d local buffers\n", i);
	//drain the local per core magz
	i = 0;
	for_each_possible_cpu(cpu) {
		 while (mag_alloc_elem_on_cpu(&global_maio.mag[order2idx(0)], cpu));
	}
	pr_err("flushed %d remote buffers\n", i);

	//mtt destroy and put_user_pages
	//while root.node; 1.put_pages 2.rb_erase

	pr_err("flushing MTTS");
	flush_all_mtts();

	pr_err("Flushing memcaches");
	flush_all_memcaches();
	//reset globals
	//TODO: Validate -- go over all globals
	reset_global_maio_state();
}

static inline ssize_t maio_map_page(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos, bool cache)
{
	static struct umem_region_mtt *mtt;
	char *kbuff, *cur;
	u64   base;
	size_t len;
	long rc, i = 0;

	if (size <= 1 || size >= PAGE_SIZE)
	        return -EINVAL;

	kbuff = memdup_user_nul(buf, size);
	if (IS_ERR(kbuff))
	        return PTR_ERR(kbuff);

	base	= simple_strtoull(kbuff, &cur, 16);
	len	= simple_strtol(cur + 1, &cur, 10);
	pr_err("%s:Got: [%llx: %ld]\n", __FUNCTION__, base, len);
	kfree(kbuff);

	if (!(mtt = kzalloc(sizeof(struct umem_region_mtt)
				+ (len * sizeof(struct maio_page_map)), GFP_KERNEL))) {
		goto mem_err;
	}

	for (i = 0; i < len; i++) {
		if ( ! (mtt->mapped_pages[i].priv = kzalloc(sizeof(struct page_priv_ctx), GFP_KERNEL)))
			goto mem_err;
	}
	mtt->start	= base;
	mtt->end 	= base + (len * HUGE_SIZE) -1;
	mtt->len	= len;
	mtt->order	= HUGE_ORDER;


	pr_err("MTT [0x%llx - 0x%llx) len %d\n", mtt->start, mtt->end, mtt->len);
	add_mtt(mtt);

	for (i = 0; i < len; i++) {
		u64 uaddr = base + (i * HUGE_SIZE);
		//rc = get_user_pages(uaddr, (1 << HUGE_ORDER), FOLL_LONGTERM, &umem_pages[0], NULL);
		//its enough to get the compound head
		rc = get_user_pages(uaddr, 1 , FOLL_LONGTERM, &umem_pages[0], NULL);
		trace_debug("[%ld]%llx[%llx:%d] rc: %d\n", rc, uaddr, (unsigned long long)umem_pages[0],
							compound_order(__compound_head(umem_pages[0], 0)),
							page_ref_count(umem_pages[0]));

		assert(compound_order(__compound_head(umem_pages[0], 0)) == HUGE_ORDER);
		/*
			set_maio_page. K > V.
			record address. V > K.
			Set pages into buffers. Magazine.

		*/
		mtt->mapped_pages[i].page =	umem_pages[0];
		if (i != uaddr2idx(mtt, uaddr))
			pr_err("Please Fix uaddr2idx: %ld != %llx\n", i, uaddr2idx(mtt, uaddr));
		if (uaddr2addr(uaddr) != page_address(umem_pages[0]))
			pr_err("Please Fix uaddr2addr: %llx:: %llx != %llx [ 0x%0x]\n", uaddr,
				(u64)page_address(umem_pages[0]), (u64)uaddr2addr(uaddr), HUGE_OFFSET);

		assert(!(uaddr & HUGE_OFFSET));
		set_maio_uaddr(umem_pages[0], uaddr);
		set_maio_uarg(umem_pages[0], mtt->mapped_pages[i].priv);

	}
	pr_err("%d: %s maio_maped U[%llx-%llx) K:[%llx-%llx)\n", smp_processor_id(), __FUNCTION__,
			mtt->start, mtt->end, (u64)uaddr2addr(mtt->start), (u64)uaddr2addr(mtt->end));
/*
	init_user_rings();
	maio_configured = true;
*/
	return size;
mem_err:
	pr_err("Failed to allocate MTT mameory (%p, %ld)\n", mtt, i);
	if (mtt) {
		while (i) {
			kfree(mtt->mapped_pages[i].priv);
		}
		kfree(mtt);
	}
	return -ENOMEM;
}

static ssize_t maio_mtrx_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return init_user_rings(file, buffer, count, pos);
}

static ssize_t maio_pages_0_write(struct file *file,
				const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_add_pages_0(file, buffer, count, pos);
}

static ssize_t maio_pages_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_map_page(file, buffer, count, pos, true);
}

static ssize_t maio_stop_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
	maio_stop();
	return count;
}

static ssize_t maio_map_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_map_page(file, buffer, count, pos, false);
}

static ssize_t maio_enable_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_enable(file, buffer, count, pos);
}

static ssize_t maio_tx_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_tx(file, buffer, count, pos);
}

static ssize_t maio_napi_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_napi(file, buffer, count, pos);
}

static int maio_enable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", maio_configured(last_dev_idx) ? 1 : 0);
        return 0;
}

static int maio_map_show(struct seq_file *m, void *v)
{
	/* TODO: make usefull */
	if (global_maio_matrix[last_dev_idx]) {
		dump_all_stats(m);
	} else {
		seq_printf(m, "NOT CONFIGURED\n");
	}

        return 0;
}

#define MAIO_VERSION	"v1.1-performance"
static int maio_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", MAIO_VERSION);
	return 0;
}

static int maio_version_open(struct inode *inode, struct file *file)
{
        return single_open(file, maio_version_show, PDE_DATA(inode));
}

static int maio_enable_open(struct inode *inode, struct file *file)
{
        return single_open(file, maio_enable_show, PDE_DATA(inode));
}

static int maio_map_open(struct inode *inode, struct file *file)
{
        return single_open(file, maio_map_show, PDE_DATA(inode));
}

static const struct file_operations maio_version_fops = {
        .owner          = THIS_MODULE,
        .open           = maio_version_open,
        .read           = seq_read,
        .release        = single_release,
};

static const struct file_operations maio_mtrx_ops = {
        .open      = maio_map_open,
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_mtrx_write,
};

static const struct file_operations maio_page_0_ops = {
        .open      = maio_map_open, /* TODO: Change to func that prints the mapped user pages */
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_pages_0_write,
};

static const struct file_operations maio_page_ops = {
        .open      = maio_map_open, /* TODO: Change to func that prints the mapped user pages */
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_pages_write,
};

static const struct file_operations maio_stop_ops = {
        .open      = maio_enable_open, /* TODO: Change to func that prints the mapped user pages */
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_stop_write,
};

static const struct file_operations maio_map_ops = {
        .open      = maio_map_open, /* TODO: Change to func that prints the mapped user pages */
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_map_write,
};

static const struct file_operations maio_enable_ops = {
        .open      = maio_enable_open,
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_enable_write,
};

static const struct file_operations maio_tx_ops = {
        .open      = maio_map_open,
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_tx_write,
};

static const struct file_operations maio_napi_ops = {
        .open      = maio_map_open,
        .read      = seq_read,
        .llseek    = seq_lseek,
        .release   = single_release,
        .write     = maio_napi_write,
};

static inline void proc_init(void)
{
	reset_global_maio_state();
	maio_dir = proc_mkdir_mode("maio", 00555, NULL);
	proc_create_data("map", 00666, maio_dir, &maio_map_ops, NULL);
	proc_create_data("stop", 00666, maio_dir, &maio_stop_ops, NULL);
	proc_create_data("mtrx", 00666, maio_dir, &maio_mtrx_ops, NULL);
	proc_create_data("pages", 00666, maio_dir, &maio_page_ops, NULL);
	proc_create_data("pages_0", 00666, maio_dir, &maio_page_0_ops, NULL);
	proc_create_data("enable", 00666, maio_dir, &maio_enable_ops, NULL);
	proc_create_data("tx", 00666, maio_dir, &maio_tx_ops, NULL);
	proc_create_data("napi", 00666, maio_dir, &maio_napi_ops, NULL);
	proc_create_data("version", 00444, maio_dir, &maio_version_fops, NULL );
}

static __init int maio_init(void)
{
	int i = 0;

	maio_filter = test_maio_filter;
	//maio_configured = false;
	for (;i< NUM_MAIO_SIZES; i++)
		mag_allocator_init(&global_maio.mag[i]);

	proc_init();

	misc_cache = KMEM_CACHE(misc_data, SLAB_HWCACHE_ALIGN);
	return 0;
}
late_initcall(maio_init);
