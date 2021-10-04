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
						   #expr, __FILE__, __func__, __LINE__); \
					pr_alert("Assertion failed! %s, %s, %s, line %d\n", \
						   #expr, __FILE__, __func__, __LINE__); \
					panic("ASSERT FAILED: %s (%s)", __FUNCTION__, #expr); \
				} \
			} while (0)

#endif

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

struct user_matrix *global_maio_matrix[MAX_DEV_NUM];
EXPORT_SYMBOL(global_maio_matrix);

static unsigned last_dev_idx;

static u16 maio_headroom	= (0x800 -512 -192); 	//This should make a zero gap between vc_pckt and headroom + data

/* HP Cache */
static LIST_HEAD(hp_cache);
DEFINE_SPINLOCK(hp_cache_lock);
static unsigned long hp_cache_size;

/* Head Page Cache */
/* A workaround, Head Pages Refcounts may go up/down due to new process mapping or old processes leaving.
   We use the first 4K pages for internal MAIO uses (e.g., magazine alloc, copied I/O)
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

static unsigned long maio_mag_lwm  __read_mostly = 1024;
static unsigned long maio_mag_hwm  __read_mostly = ULONG_MAX;
static bool lwm_triggered;

#ifdef MAIO_ASYNC_TX
static int maio_post_tx_task(void *state);
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

static inline bool maio_hwm_crossed(void)
{
	return (mag_get_full_count(&global_maio.mag[0]) > maio_mag_hwm);
}

//#define dump_io_md(...)

#ifndef dump_io_md
#define dump_io_md	__dump_io_md
#endif
static inline void __dump_io_md(struct io_md *md, const char *txt)
{
	pr_err("%s: state %llx: len %x : poison %x: vlan %x flags %x\n",
		txt, md->state, md->len, md->poison, md->vlan_tci, md->flags);
}

static inline bool maio_lwm_crossed(void)
{
	/* We should not spam the user with lwm triggers */
	if (lwm_triggered)
		return false;

	if (mag_get_full_count(&global_maio.mag[0]) < maio_mag_lwm) {
		lwm_triggered = true;
	}
	return lwm_triggered;
}

static inline struct io_md *kaddr2shadow_md(void *kaddr)
{
	u64 shadow = (u64)kaddr;
	shadow &= PAGE_MASK;
	shadow += SHADOW_OFF;
	return (void *)shadow;
}

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

static inline void set_page_state(struct page *page, u64 new_state)
{
	struct io_md *md = page2io_md(page);
	md->state = new_state;
}

static inline u64 get_page_state(struct page *page)
{
	struct io_md *md = page2io_md(page);
	return md->state;
}

static inline void flush_all_mtts(void)
{
	struct rb_node *node = mtt_tree.rb_node;

	while (node) {
		int i = 0;
		struct umem_region_mtt *mtt = container_of(node, struct umem_region_mtt, node);

		/* Current implememntation 5.4 is enough to put only the head page */
		pr_err("%s:freeing MTT [0x%llx - 0x%llx) len %d\n", __FUNCTION__, mtt->start, mtt->end, mtt->len);
		for (; i < mtt->len; i++) {
			set_maio_uaddr(mtt->pages[i], 0);
			trace_debug("%llx rc: %d\n", (unsigned long long)mtt->pages[i],
							page_ref_count(mtt->pages[i]));
		}

		put_user_pages(mtt->pages, mtt->len);
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
	return page_address(mtt->pages[i]) + offset;
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
	struct maio_cached_buffer *buffer = page_address(page);
	unsigned long head_cache_flags;

	spin_lock_irqsave(&head_cache_lock, head_cache_flags);
	list_add(&buffer->list, &head_cache);
	++head_cache_size;
	spin_unlock_irqrestore(&head_cache_lock, head_cache_flags);
}

static inline struct page *maio_get_cached_head(void)
{
	struct maio_cached_buffer *buffer;
	unsigned long head_cache_flags;

	spin_lock_irqsave(&head_cache_lock, head_cache_flags);

	buffer = list_first_entry_or_null(&head_cache,
						struct maio_cached_buffer, list);
	if (likely(buffer)) {
		list_del(&buffer->list);
		--head_cache_size;
	}
	spin_unlock_irqrestore(&head_cache_lock, head_cache_flags);

	return (buffer) ? virt_to_page(buffer): NULL;
}

static inline void maio_cache_hp(struct page *page)
{
	struct maio_cached_buffer *buffer = page_address(page);
	unsigned long hp_cache_flags;

	/* The text is not where you expect: use char* buffer to use 16.... *facepalm* */
	snprintf((char *)&buffer[1], 64, "heya!! %llx:%llx\n", (u64)buffer, addr2uaddr(buffer));
	trace_debug("Written text to %llx:%llx\n", (u64)&buffer[1], addr2uaddr(buffer));
	spin_lock_irqsave(&hp_cache_lock, hp_cache_flags);
	list_add(&buffer->list, &hp_cache);
	++hp_cache_size;
	spin_unlock_irqrestore(&hp_cache_lock, hp_cache_flags);
}

static inline struct page *maio_get_cached_hp(void)
{
	struct maio_cached_buffer *buffer;
	unsigned long hp_cache_flags;

	spin_lock_irqsave(&hp_cache_lock, hp_cache_flags);

	buffer = list_first_entry_or_null(&hp_cache,
						struct maio_cached_buffer, list);
	if (likely(buffer)) {
		list_del(&buffer->list);
		--hp_cache_size;
	} else {
		panic("Exhausted page cache!");
	}
	spin_unlock_irqrestore(&hp_cache_lock, hp_cache_flags);

	return (buffer) ? virt_to_page(buffer): NULL;
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
		pr_err("ERROR: Page %llx state %llx uaddr %llx\n", (u64)page, get_page_state(page), get_maio_uaddr(page));
		pr_err("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page_address(page), PageHead(page)?"HEAD":"Tail");
		dump_io_md(virt2io_md(addr), "MD");
		dump_io_md(kaddr2shadow_md(addr), "SHADOW");
		if (kaddr2shadow_md(addr)->state == MAIO_PAGE_NAPI) {
			// Corruption detected on NAPI flow update from shadow
			pr_err("Corruption detected on NAPI flow update from shadow\n");
			memcpy(virt2io_md(addr), kaddr2shadow_md(addr), sizeof(struct io_md));
		}
	}
	assert(get_page_state(page) & MAIO_PAGE_IO);

	set_page_state(page, MAIO_PAGE_FREE);
	put_buffers(addr, get_maio_elem_order(page));
}

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
	void *buffer;
	struct page *page;

	buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);

	page = (buffer) ? virt_to_page(buffer) : NULL;
	if (!page)
		return NULL;

	init_page_count(page);
	assert(get_page_state(page) == MAIO_PAGE_FREE);
	set_page_state(page, MAIO_PAGE_RX);

	return page;
}
#define __maio_alloc_page()	__maio_alloc_pages(0)

struct page *maio_alloc_pages(size_t order)
{
	struct page *page;
	void *buffer;


	buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);

	/* should happen on init when mag is empty.*/
	if (unlikely(!buffer)) {
		/*
		replenish_from_cache(order);
		buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);
		*/
		pr_err("Failed to alloc from MAIO mag [%ps]\n", __builtin_return_address(0));
		return alloc_page(GFP_KERNEL|GFP_ATOMIC);
	}
	assert(buffer != NULL);//should not happen
	page =  (buffer) ? virt_to_page(buffer) : ERR_PTR(-ENOMEM);
	if (likely( ! IS_ERR_OR_NULL(page))) {
		if (unlikely((page_ref_count(page) != 0))) {
			trace_printk("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
			trace_printk("%d:%s:%llx[%d]%llx\n", smp_processor_id(),
					__FUNCTION__, (u64)page, page_ref_count(page), (u64)page_address(page));
			panic("P %llx: %llx  has %d refcnt\n", (u64)page, (u64)page_address(page), page_ref_count(page));
		}
		init_page_count(page);
		assert(is_maio_page(page));
		if (unlikely(get_page_state(page) != MAIO_PAGE_FREE)) {
			pr_err("ERROR: Page %llx state %llx uaddr %llx\n", (u64)page, get_page_state(page), get_maio_uaddr(page));
			pr_err("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
		}
		assert(get_page_state(page) == MAIO_PAGE_FREE);
		set_page_state(page, MAIO_PAGE_RX);
	}
	//trace_debug("%d:%s: %pS\n", smp_processor_id(), __FUNCTION__, __builtin_return_address(0));
	//trace_debug("%d:%s:%llx\n", smp_processor_id(), __FUNCTION__, (u64)page);

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

//TODO: Add support for vlan detection __vlan_hwaccel
static inline int __maio_post_rx_page(struct net_device *netdev, struct page *page,
					void *addr, u32 len, u16 vlan_tci, u16 flags)
{
	u64 qp_idx = get_rx_qp_idx(netdev);
	struct page *refill = NULL;
	struct io_md *md;
	struct percpu_maio_dev_qp *dev_qp = this_cpu_ptr(&maio_dev_qp);
	struct percpu_maio_qp *qp;

	if (unlikely(!maio_configured(qp_idx)))
		return 0;

	if (qp_idx == -1) {
		return 0;
	}

	qp = &dev_qp->qp[qp_idx];

	if (filter_packet(addr)) {
		//trace_printk("skiping...\n");
		return 0;
	}

send_the_page:
	if (qp->rx_ring[qp->rx_counter & (qp->rx_sz -1)]) {
		trace_printk("[%d]User to slow. dropping post of %llx:%llx\n",
				smp_processor_id(), (u64)addr, addr2uaddr(addr));
		return 0;
	}

	/* LWM crossed ask user to return some mem via TX */
	if (unlikely(maio_lwm_crossed() && !refill)) {
		trace_debug("LWM crossed [%d], sending request\n", mag_get_full_count(&global_maio.mag[0]));
		refill = (void *)MAIO_POISON;

		/*
		user should check if address is MAIO_POISON,
		this means that this is a request for a refill packet.
		*/
		qp->rx_ring[qp->rx_counter & (qp->rx_sz -1)] = MAIO_POISON;
		++qp->rx_counter;

		goto send_the_page;
	}

	/* HWM crossed return some mem to user */
	if (unlikely(maio_hwm_crossed() && !refill)) {
		void *buff;
		trace_debug("HWM crossed [%d], sending page to user\n", mag_get_full_count(&global_maio.mag[0]));
		//if hwm was crossed
		refill = __maio_alloc_page();
		if (!unlikely(!refill))
			goto send_the_page;
		/* For the assert */
		set_page_state(refill, MAIO_PAGE_USER);

		buff = page_address(refill);

		/*
		user should check if address is page aligned, then md is not present
		this means that this is a refill packet.
		*/
		qp->rx_ring[qp->rx_counter & (qp->rx_sz -1)] = addr2uaddr(buff);
		++qp->rx_counter;

		goto send_the_page;
	}

	trace_debug("kaddr %llx, len %d\n", (u64)addr, len);
	if (!page) {
		void *buff;

		page = __maio_alloc_page();
		if (unlikely(!page)) {
			return 0;
		}

		/* For the assert */
		set_page_state(page, MAIO_PAGE_RX);

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
	if (unlikely(get_page_state(page) != MAIO_PAGE_RX)) {
		pr_err("ERROR: Page %llx state %llx uaddr %llx\n", (u64)page, get_page_state(page), get_maio_uaddr(page));
	}

	assert(get_page_state(page) == MAIO_PAGE_RX);
	set_page_state(page, MAIO_PAGE_USER);
	assert(uaddr2addr(addr2uaddr(addr)) == addr);
	md = virt2io_md(addr);
	md->len 	= len;
	md->poison	= MAIO_POISON;
	md->vlan_tci	= vlan_tci;
	md->flags	= flags;

	show_io(addr, "RX");
#if 1
	qp->rx_ring[qp->rx_counter & (qp->rx_sz -1)] = addr2uaddr(addr);
	++qp->rx_counter;
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
		if (page)
			put_page(page);
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(maio_post_rx_page);

//TODO: Loop inside lock
// use dev_direct_xmit / xsk_generic_xmit
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
                goto unlock;
        }
        //refcount_add(burst, &pkt_dev->skb->users);

	for ( i = 0; i < cnt; i++) {
		err = netdev_start_xmit(skb[i], dev, txq, --more);
		if (unlikely(err != NETDEV_TX_OK)) {
			pr_err("netdev_start_xmit failed with %0xx\n", err);
			consume_skb(skb[i]);
		}
	}

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

//Zero our LSB and advance counter.
static inline void advance_tx_ring(struct maio_tx_thread *tx_thread)
{
	u16 idx = tx_thread->tx_counter & (tx_thread->tx_sz -1);
	tx_thread->tx_ring[idx] = (tx_thread->tx_ring[idx] & (~0x1));
	++tx_thread->tx_counter;
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
	struct io_md *md = container_of(ubuf, struct io_md, uarg);
	int in_transit = 1;

	if (!refcount_dec_and_test(&ubuf->refcnt)) {
		in_transit = 0;
	}

	md->in_transit = in_transit;
	trace_printk("%s: TX in_transit %s [%d]\n", __FUNCTION__,
			in_transit ? "YES": "NO", refcount_read(&ubuf->refcnt));
}
//skb_zcopy_clear
static inline void maio_set_comp_handler(struct sk_buff *skb, struct io_md *md)
{
	md->in_transit = 1;
	md->uarg.callback = maio_zc_tx_callback;
	refcount_inc(&md->uarg.refcnt);

	trace_printk("%s: TX in_transit %s [%d]\n", __FUNCTION__,
			md->in_transit ? "YES": "NO", refcount_read(&md->uarg.refcnt));

	skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
	skb_shinfo(skb)->destructor_arg = &md->uarg;
}

#define TX_BATCH_SIZE	32
int maio_post_tx_page(void *state)
{
	struct maio_tx_thread *tx_thread = state;
	struct sk_buff *skb_batch[TX_BATCH_SIZE];
	struct io_md *md;
	u64 uaddr = 0;
	int copy = 0, cnt = 0;
	bool local_lwm = lwm_triggered;
	u64 netdev_idx = tx_thread->dev_idx;

	assert(netdev_idx != -1);

	trace_debug("[%d]Starting\n",smp_processor_id());

	while ((uaddr = tx_ring_entry(tx_thread))) {
		struct sk_buff *skb;
		unsigned len;
		void 		*kaddr	= uaddr2addr(uaddr);
		struct page     *page	= virt_to_page(kaddr);

		advance_tx_ring(tx_thread);

		if (unlikely(IS_ERR_OR_NULL(kaddr))) {
			trace_printk("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
			pr_err("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
			continue;
		}

		if (unlikely( ! page_ref_count(page))) {
			/* This check only makes sense if pages are zeroed out (?) */
			if (unlikely(get_page_state(page))) {
				pr_err("TX] Zero refcount page %llx(state %llx)[%d] addr %llx -- reseting \n",
					(u64)page, get_page_state(page), page_ref_count(page), (u64)kaddr);
				panic("Illegal page state\n");
			}
			init_page_count(page);
		}

		if (unlikely(!is_maio_page(page))) {

			if (PageHead(page)) {
				void *buff;

				set_maio_is_io(page);
				set_page_state(page, MAIO_POISON); // Need to add on NEW USER pages.

				page = __maio_alloc_page();
				if (!page)
					return 0;
				buff = page_address(page);

				buff = (void *)((u64)buff + maio_get_page_headroom(NULL));

				md = virt2io_md(kaddr);

				len = md->len;

				trace_debug("TX] :COPY %u [%u] to page %llx[%d] addr %llx\n", len,
						maio_get_page_headroom(NULL),
						(u64)page, page_ref_count(page), (u64)kaddr);
				assert(len <= (PAGE_SIZE - maio_get_page_headroom(NULL)));

				memcpy(buff, kaddr, len);
				memcpy(virt2io_md(buff), md, sizeof(struct io_md));
				/* For the assert */
				set_page_state(page, MAIO_PAGE_USER);

				kaddr = buff;
			} else {
				panic("This shit cant happen!\n"); //uaddr2addr would fail first
			}
		}

		md = virt2io_md(kaddr);

		if (unlikely(md->state > MAIO_PAGE_USER)) {
			pr_err("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"Tail");
			pr_err("ERROR: Page %llx %s state %llx uaddr %llx\n", (u64)page, page == virt_to_page(md) ? "": "EHH... A PROBLEM HUSTON", get_page_state(page), get_maio_uaddr(page));
			dump_io_md(md, "txMD");
		}

		set_page_state(page, MAIO_PAGE_TX);

		if (unlikely(md->poison != MAIO_POISON)) {
			pr_err("NO MAIO-POISON <%x>Found [%llx] -- Please make sure to put the buffer\n"
				"page %llx: %s:%s %llx ",
				md->poison, uaddr, (u64)page,
				is_maio_page(page)?"MAIO":"OTHER",
				PageHead(page)?"HEAD":"Tail",
				get_maio_uaddr(page));

			panic("This should not happen\n");
			continue;
		}

		/* A refill page from user following an lwm crosss */
		if (unlikely(!md->len)) {
			trace_debug(" Received page from user [%d](%d)\n", mag_get_full_count(&global_maio.mag[0]), page_ref_count(page));
			put_page(page);
			local_lwm = false;

			continue;
		}
//TODO: Consider adding ERR flags to ring entry.

		len 	= md->len + SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

		show_io(kaddr, "TX");
		trace_debug("TX %llx/%llx [%d]from user %llx [#%d]\n",
				(u64)kaddr, (u64)page, page_ref_count(page),
				(u64)uaddr, cnt);
		if (unlikely(((uaddr & (~PAGE_MASK)) + len) > PAGE_SIZE)) {
			pr_err("Buffer to Long [%llx] len %u klen = %u\n", uaddr, md->len, len);
			continue;
		}

		skb = maio_build_linear_tx_skb(tx_thread->netdev, kaddr, md->len);
		if (unlikely(!skb)) {
			pr_err("%s) Failed to alloc skb\n", __FUNCTION__);
			put_page(page);
			continue;
		}

		if (md->flags & MAIO_STATUS_VLAN_VALID)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), md->vlan_tci);
		get_page(page);
		skb_batch[cnt++] = skb;
		maio_set_comp_handler(skb, md);

		if (unlikely(cnt >= TX_BATCH_SIZE))
			break;
	}

	trace_debug("%d: Sending %d buffers. counter %lu\n", smp_processor_id(), cnt, tx_thread->tx_counter);
	if (cnt)
		copy = maio_xmit(tx_thread->netdev, skb_batch, cnt);

	trace_debug("%d: Sending %d buffers. rc %d\n", smp_processor_id(), cnt, copy);

	lwm_triggered = local_lwm;

	//TODO: return #sent
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
	maio_post_tx_page(tx_thread);
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

		if ( !(dev = dev_get_by_index(&init_net, dev_idx)))
			return -ENODEV;

		if (netif_is_bond_slave(dev))
			return -EINVAL;

		maio_dev_configured[dev_idx] = val;

		netdev_for_each_lower_dev(dev, iter_dev, iter) {
			maio_dev_configured[iter_dev->ifindex] = val;
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
	bool local_lwm = lwm_triggered;
	u64 netdev_idx = tx_thread->dev_idx;

	assert(netdev_idx != -1);

	trace_debug("[%d]Starting <%lu>\n",smp_processor_id(), tx_thread->tx_counter & ((tx_thread)->tx_sz -1));

	while ((uaddr = tx_ring_entry(tx_thread))) {
		struct sk_buff *skb;
		unsigned	len;
		void 		*kaddr	= uaddr2addr(uaddr);
		struct page     *page	= virt_to_page(kaddr);

		advance_tx_ring(tx_thread);

		if (unlikely(IS_ERR_OR_NULL(kaddr))) {
			trace_debug("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
			pr_err("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
			continue;
		}

		if (unlikely( ! page_ref_count(page))) {
			if (unlikely(get_page_state(page))) {
				pr_err("TX] Zero refcount page %llx(state %llx)[%d] addr %llx -- reseting \n",
					(u64)page, get_page_state(page), page_ref_count(page), (u64)kaddr);
				panic("Illegal page state\n");
			}
			init_page_count(page);
		}

		if (unlikely(!is_maio_page(page))) {

			if (PageHead(page)) {
				void *buff;

				set_maio_is_io(page);
				set_page_state(page, MAIO_POISON); // Need to add on NEW USER pages.

				page = __maio_alloc_page();
				if (!page)
					return 0;

				buff = page_address(page);
				buff = (void *)((u64)buff + maio_get_page_headroom(NULL));

				md = virt2io_md(kaddr);

				len = md->len;

				trace_debug("TX] :COPY %u [%u] to page %llx[%d] addr %llx\n", len,
						maio_get_page_headroom(NULL),
						(u64)page, page_ref_count(page), (u64)kaddr);
				assert(len <= (PAGE_SIZE - maio_get_page_headroom(NULL)));

				memcpy(buff, kaddr, len);
				memcpy(virt2io_md(buff), md, sizeof(struct io_md));
				/* For the assert */
				set_page_state(page, MAIO_PAGE_USER);

				kaddr = buff;
			} else {
				panic("This shit cant happen!\n"); //uaddr2addr would fail first
			}
		}

		if (unlikely(get_page_state(page) > MAIO_PAGE_USER)) {
			pr_err("ERROR: Page %llx state %llx uaddr %llx\n", (u64)page, get_page_state(page), get_maio_uaddr(page));
			pr_err("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
		}

		set_page_state(page, MAIO_PAGE_NAPI);
		md = virt2io_md(kaddr);

		if (unlikely(md->poison != MAIO_POISON)) {
			pr_err("NO MAIO-POISON <%x>Found [%llx] -- Please make sure to put the buffer\n"
				"page %llx: %s:%s %llx ",
				md->poison, uaddr, (u64)page,
				is_maio_page(page)?"MAIO":"OTHER",
				PageHead(page)?"HEAD":"Tail",
				get_maio_uaddr(page));

			panic("This should not happen\n");
			continue;
		}

		/* A refill page from user following an lwm crosss */
		if (unlikely(!md->len)) {
			trace_debug(" Received page from user [%d](%d)\n", mag_get_full_count(&global_maio.mag[0]), page_ref_count(page));
			put_page(page);
			local_lwm = false;

			continue;
		}

		len 	= md->len;// + SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

		trace_debug("NAPI %llx/%llx [%d]from user %llx [#%d] len %d\n",
				(u64)kaddr, (u64)page, page_ref_count(page),
				(u64)uaddr, cnt, len);
		if (unlikely(((uaddr & (PAGE_SIZE -1)) + len) > PAGE_SIZE)) {
			pr_err("Buffer to Long [%llx] len %u klen = %u\n", uaddr, md->len, len);
			continue;
		}
		skb = maio_build_linear_rx_skb(tx_thread->netdev, kaddr, len);
		if (unlikely(!skb)) {
			pr_err("Failed to alloc napi skb\n");
			put_page(page);
			continue;
		}
		cnt++;

		//*********************//
		// DEBUG

		md = kaddr2shadow_md(kaddr);
		memcpy(md, virt2io_md(kaddr), sizeof(struct io_md));

		//********************//
		//OPTION: Use non napi API: netif_rx but lose GRO.
		netif_rx(skb);
		//napi_gro_receive(napi, skb);

		if (unlikely(cnt >= NAPI_BATCH_SIZE))
			break;
	}
	lwm_triggered = local_lwm;

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
		tx_thread->netdev = maio_devs[dev_idx];
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
			//trace_debug("[%ld]Caching %llx [%llx]  - P %llx[%d]\n", len, (u64 )kbase, meta->bufs[len],
			//	(u64)page, page_ref_count(page));
			//maio_cache_head(page);
			set_maio_is_io(page);
			set_page_state(page, MAIO_POISON); // Need to add on NEW USER pages.
			assert(!is_maio_page(page));
			//memset(page_address(page), 0, PAGE_SIZE);
		} else {
			//trace_debug("[%ld]Adding %llx [%llx]  - P %llx[%d]\n", len, (u64 )kbase, meta->bufs[len],
			//		(u64)page, page_ref_count(page));
			set_page_count(page, 0);
			set_page_state(page, MAIO_PAGE_FREE);
			assert(get_maio_elem_order(__compound_head(page, 0)) == 0);
			assert(is_maio_page(page));
			maio_free_elem(kbase, 0);
		}
	}
	kfree(kbuff);
	maio_mag_hwm = mag_get_full_count(&global_maio.mag[0]);
	maio_mag_hwm += (maio_mag_hwm >> 3); //+12% of initial

	pr_err("%s} HWM %ld LWM %ld lwm trigger %s\n", __FUNCTION__, maio_mag_hwm, maio_mag_lwm, lwm_triggered ? "OFF": "ON");
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

		pr_err("Fluishing mem from [%d:%d] %s (%s)\n", i, dev->ifindex, dev->name, ops->ndo_dev_reset ? "Flush" : "NOP");
		if (ops->ndo_dev_reset) {
			ops->ndo_dev_reset(dev);
		}
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
	long rc, i;

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
				+ (len * sizeof(struct page*)), GFP_KERNEL)))
		return -ENOMEM;

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
		mtt->pages[i] =	umem_pages[0];
		if (i != uaddr2idx(mtt, uaddr))
			pr_err("Please Fix uaddr2idx: %ld != %llx\n", i, uaddr2idx(mtt, uaddr));
		if (uaddr2addr(uaddr) != page_address(umem_pages[0]))
			pr_err("Please Fix uaddr2addr: %llx:: %llx != %llx [ 0x%0x]\n", uaddr,
				(u64)page_address(umem_pages[0]), (u64)uaddr2addr(uaddr), HUGE_OFFSET);

		assert(!(uaddr & HUGE_OFFSET));
		set_maio_uaddr(umem_pages[0], uaddr);

		/* Allow for the Allocator to get elements on demand, flexible support for variable sizes
		if (cache)
			maio_cache_hp(umem_pages[0]);
		*/
		//trace_debug("Added %llx:%llx (umem %llx:%llx)to MAIO\n", uaddr, (u64)page_address(umem_pages[0]),
		//			get_maio_uaddr(umem_pages[0]), (u64)uaddr2addr(uaddr));
	}
	pr_err("%d: %s maio_maped U[%llx-%llx) K:[%llx-%llx)\n", smp_processor_id(), __FUNCTION__,
			mtt->start, mtt->end, (u64)uaddr2addr(mtt->start), (u64)uaddr2addr(mtt->end));
/*
	init_user_rings();
	maio_configured = true;
*/
	return size;
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
		seq_printf(m, "%llx %ld (%d [%lu-%lu])\n",
			get_maio_uaddr(virt_to_head_page(global_maio_matrix[last_dev_idx])),
			hp_cache_size, mag_get_full_count(&global_maio.mag[0]),
			maio_mag_lwm, maio_mag_hwm);
	} else {
		seq_printf(m, "NOT CONFIGURED\n");
	}

        return 0;
}

#define MAIO_VERSION	"v0.95-zc-retarnsmit"
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
	return 0;
}
late_initcall(maio_init);
