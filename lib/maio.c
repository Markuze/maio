#include <linux/init.h>
#include <linux/magazine.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/rbtree.h>
#include <linux/ctype.h>	/*isdigit*/
#include <linux/ip.h>		/*iphdr*/
#include <linux/tcp.h>  	/*tcphdr*/

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

/* GLOBAL MAIO FLAG*/
volatile bool maio_configured;
EXPORT_SYMBOL(maio_configured);

maio_filter_func_p maio_filter;
EXPORT_SYMBOL(maio_filter);
//TODO: collect this shite in a struct

/* get_user_pages */
static struct page* umem_pages[1<<HUGE_ORDER];

static struct proc_dir_entry *maio_dir;
static struct maio_magz global_maio;

/* User matrix : No longer static as the threads should be in a module */
struct user_matrix *global_maio_matrix;
EXPORT_SYMBOL(global_maio_matrix);

/*TODO: Remove*/
static u64 maio_rx_post_cnt;

static u16 maio_headroom = 192;
static u16 maio_stride = 0x800;//2K

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

static u64 min_pages_0 = ULLONG_MAX;
static u64 max_pages_0;

static struct net_device *maio_devs[32] __read_mostly;
static	unsigned default_dev_idx = -1;

DEFINE_PER_CPU(struct percpu_maio_qp, maio_qp);
/* TODO:
	For multiple reg ops a tree is needed
		1. For security and rereg need owner id and mmap to specific addr.
*/
static struct rb_root mtt_tree = RB_ROOT;
static struct umem_region_mtt *cached_mtt;

static struct task_struct *maio_tx_thread;

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

	if (unlikely(!is_maio_page(virt_to_page(addr))))
		return 0;
	return get_maio_uaddr(virt_to_head_page(addr)) + offset;
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
	trace_printk("Written text to %llx:%llx\n", (u64)&buffer[1], addr2uaddr(buffer));
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

void maio_page_free(struct page *page)
{
	/* Need to make sure we dont get only head pages here...*/
	//trace_printk("%d:%s: %llx %pS\n", smp_processor_id(), __FUNCTION__, (u64)page, __builtin_return_address(0));
	assert(is_maio_page(page));
	assert(min_pages_0 <= (u64)page);
	assert(max_pages_0 >= (u64)page);
	assert(page_ref_count(page) == 0);
	put_buffers(page_address(page), get_maio_elem_order(page));
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
	//trace_printk("%d:%s: %llx %pS\n", smp_processor_id(), __FUNCTION__, (u64)page, __builtin_return_address(0));
	assert(is_maio_page(page));
	assert(min_pages_0 <= (u64)page);
	assert(max_pages_0 >= (u64)page);
	assert(page_ref_count(page) == 0);
	put_buffers(page_address(page), get_maio_elem_order(page));

	return;
}
EXPORT_SYMBOL(maio_frag_free);

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

//TODO: Its possible to store headroom per page.
u16 maio_get_page_headroom(struct page *page)
{
	return maio_headroom;
}
EXPORT_SYMBOL(maio_get_page_headroom);

u16 maio_get_page_stride(struct page *page)
{
	return maio_stride;
}
EXPORT_SYMBOL(maio_get_page_stride);


struct page *maio_alloc_pages(size_t order)
{
	struct page *page;
	void *buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);

	/* should happen on init when mag is empty.*/
	if (unlikely(!buffer)) {
		/*
		replenish_from_cache(order);
		buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);
		*/
		pr_err("Failed to alloc from MAIO mag\n");
		return alloc_page(GFP_KERNEL|GFP_ATOMIC);
	}
	assert(buffer != NULL);//should not happen
	page =  (buffer) ? virt_to_page(buffer) : ERR_PTR(-ENOMEM);
	if (likely( ! IS_ERR_OR_NULL(page))) {
		if (!(page_ref_count(page) == 0)) {
			trace_printk("%d:%s:%llx :%s\n", smp_processor_id(), __FUNCTION__, (u64)page, PageHead(page)?"HEAD":"");
			trace_printk("%d:%s:%llx[%d]%llx\n", smp_processor_id(),
					__FUNCTION__, (u64)page, page_ref_count(page), (u64)page_address(page));
			panic("P %llx: %llx  has %d refcnt\n", (u64)page, (u64)page_address(page), page_ref_count(page));
		}
		assert(is_maio_page(page));
		init_page_count(page);
	}
	//trace_printk("%d:%s: %pS\n", smp_processor_id(), __FUNCTION__, __builtin_return_address(0));
	//trace_printk("%d:%s:%llx\n", smp_processor_id(), __FUNCTION__, (u64)page);

	return page;
}
EXPORT_SYMBOL(maio_alloc_pages);

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

#if 0
static inline bool ring_full(u64 p, u64 c)
{
	return (((p + 1) & UMAIO_RING_MASK) == (c & UMAIO_RING_MASK));
}
#endif

static inline char* alloc_copy_buff(struct percpu_maio_qp *qp)
{
	char *data;

	if (qp->cached_mbuf) {
		data = qp->cached_mbuf;
		qp->cached_mbuf = NULL;
		/*TODO: ASSERT on Refcount values...*/
	} else {
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
		qp->cached_mbuf = data + maio_get_page_stride(NULL);
	}
	return data;
}

/* Capture all but ssh traffic */
static inline bool default_maio_filter(void *addr)
{
	struct ethhdr   *eth    = addr;
	struct iphdr    *iphdr  = (struct iphdr *)&eth[1];
	struct tcphdr	*tcphdr = (struct tcphdr *)&iphdr[1];

	if (ntohs(tcphdr->dest) == 22) {
		return 0;
	}

	return 1;
}

void reset_maio_default_filter(void)
{
	maio_filter = default_maio_filter;
}
EXPORT_SYMBOL(reset_maio_default_filter);


static inline int filter_packet(void *addr)
{
	return maio_filter(addr);
}

static inline int __maio_post_rx_page(void *addr, u32 len, int copy)
{
	struct page *page = virt_to_page(addr);
	struct io_md *md;
	struct percpu_maio_qp *qp = this_cpu_ptr(&maio_qp);
	int rc;

	if (unlikely(!maio_configured))
		return 0;

	if (unlikely(!global_maio_matrix)) {
		pr_err("global matrix not configured!!!");
		return 0;
	}

	if (qp->rx_ring[qp->rx_counter & (qp->rx_sz -1)]) {
		trace_printk("[%d]User to slow. dropping post of %llx:%llx\n",
				smp_processor_id(), (u64)addr, addr2uaddr(addr));
		//TODO: put_page(virt_to_page(addr)) if 1 returned.
		return 0;
	}

	if (!(rc = filter_packet(addr))) {
		//trace_printk("skiping...\n");
		return 0;
	}

	trace_debug("using page %llx addr %llx, len %d [%d]\n", (u64)page, (u64)addr, len, copy);
	if (copy) {
		char *buff = alloc_copy_buff(qp);
		if (!buff) {
			trace_printk("Failed to alloc copy_buff!!!\n");
			return 0;
		}
		page = virt_to_page(buff);
		memcpy(buff, addr, len);
		addr = buff;
		trace_debug("copy to using page %llx addr %llx\n", (u64)page, (u64)addr);

		/* the orig copy is not used so ignore */
	} else {
		/* We are using it so get*/
		get_page(page);
	}

	assert(uaddr2addr(addr2uaddr(addr)) == addr);
	md = addr;
	md--;
	md->len 	= len;
	md->poison	= MAIO_POISON;

	qp->rx_ring[qp->rx_counter & (qp->rx_sz -1)] = addr2uaddr(addr);
	++qp->rx_counter;

	trace_debug("%d:Posting[%lu] %s:%llx[%u]%llx{%d} %s\n", smp_processor_id(),
			qp->rx_counter & (qp->rx_sz -1),
			copy ? "COPY" : "ZC",
			(u64)addr, len,
			addr2uaddr(addr), page_ref_count(page),
			(rc) ? "MAIO RX":"PT" );

	return 1; //TODO: When buffer taken. put page of orig.
}

int maio_post_rx_page_copy(void *addr, u32 len)
{
	return __maio_post_rx_page(addr, len, 1);
}
EXPORT_SYMBOL(maio_post_rx_page_copy);

int maio_post_rx_page(void *addr, u32 len)
{
	struct page* page = virt_to_page(addr);
	return __maio_post_rx_page(addr, len, !is_maio_page(page));
}
EXPORT_SYMBOL(maio_post_rx_page);

//pktgen xmit
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
			trace_printk("netdev_start_xmit failed with %0xx\n", err);
			consume_skb(skb[i]);
		}
	}

unlock:
        HARD_TX_UNLOCK(dev, txq);
        local_bh_enable();

	return err;
}

#define tx_ring_entry(qp) 	(qp)->tx_ring[(qp)->tx_counter & ((qp)->tx_sz -1)]
#define advance_tx_ring(qp)	(qp)->tx_ring[(qp)->tx_counter++ & ((qp)->tx_sz -1)] = 0

#define TX_BATCH_SIZE	64
int maio_post_tx_page(void *unused)
{
	struct io_md *md;
	struct sk_buff *skb_batch[TX_BATCH_SIZE];
	struct percpu_maio_qp *qp = this_cpu_ptr(&maio_qp);
	int copy = 0, cnt = 0;
	u64 uaddr = 0;
	static unsigned tx_counter;

	/* NOTICE: This works only for a single TX - no concurency!!! AND a single TX Ring */
	(qp)->tx_counter = tx_counter;
	trace_debug("[%d]Starting <%d>\n",smp_processor_id(), tx_counter & ((qp)->tx_sz -1));

	while ((uaddr = tx_ring_entry(qp))) {
		struct sk_buff *skb;
		unsigned len, size;
		void *kaddr = uaddr2addr(uaddr);

		advance_tx_ring(qp);

		if (unlikely(IS_ERR_OR_NULL(kaddr))) {
			trace_debug("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
			pr_err("Invalid kaddr %llx from user %llx\n", (u64)kaddr, (u64)uaddr);
			continue;
		}

		if (unlikely(!is_maio_page(virt_to_page(kaddr)))) {
#if 0
	#TODO: Add the copy option.
			char *buff = alloc_copy_buff(qp);
			if (!buff) {
				pr_err("Failed to alloc copy_buff!!!\n");
				return 0;
			}
			memcpy(buff, kaddr, len);
			kaddr = buff;
			copy = 1;
#endif
			pr_err("NON MAIO page sent [%llx]\n", uaddr);
			continue;
		}
		md = kaddr;
		md--;

		if (unlikely(md->poison != MAIO_POISON)) {
			pr_err("NO MAIO-POISON Found [%llx] -- Please make sure to put the buffer\n", uaddr);
			put_page(virt_to_page(kaddr));
			continue;
		}
//TODO: Consider adding ERR flags to ring entry.

		len 	= md->len + SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		size 	= 0x800 - ((u64)kaddr & (0x800 -1));
/*
		trace_debug("Sending kaddr %llx [%d]from user %llx: len %d[size %d] poison %0x\n",
				(u64)kaddr, page_ref_count(virt_to_page(kaddr)),
				(u64)uaddr, md->len, size, md->poison);
*/
		trace_debug("Sending %llx [%d]from user %llx [%d]\n",
				(u64)kaddr, page_ref_count(virt_to_page(kaddr)),
				(u64)uaddr, cnt);
		if (unlikely(((uaddr & (PAGE_SIZE -1)) + len) > PAGE_SIZE)) {
			pr_err("Buffer to Long [%llx] len %u klen = %u\n", uaddr, md->len, len);
			continue;
		}
		skb = build_skb(kaddr, size);//TODO:
		skb_put(skb, md->len);
		skb->dev = maio_devs[default_dev_idx];
		//get_page(virt_to_page(kaddr));
		skb_batch[cnt++] = skb;

		if (unlikely(cnt >= TX_BATCH_SIZE))
			break;
	}
	trace_debug("%d: Sending %d buffers. counter %d\n", smp_processor_id(), cnt, tx_counter);
	if (cnt)
		copy = maio_xmit(maio_devs[default_dev_idx], skb_batch, cnt);

	tx_counter = qp->tx_counter;
	trace_debug("%d: Sending %d buffers. rc %d\n", smp_processor_id(), cnt, copy);

	//TODO: return #sent
	return cnt;
}

#define MAIO_TX_KBUFF_SZ	64

static inline ssize_t maio_tx(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{
	char	kbuff[MAIO_TX_KBUFF_SZ], *cur;
	size_t 	val;
	static size_t prev = -1;

	if (unlikely(!maio_configured))
		return -ENODEV;

	if (unlikely(!global_maio_matrix)) {
		pr_err("global matrix not configured!!!");
		return -ENODEV;
	}

	if (unlikely(size < 1 || size >= MAIO_TX_KBUFF_SZ))
	        return -EINVAL;

	if (copy_from_user(kbuff, buf, size)) {
		return -EFAULT;
	}

	val 	= simple_strtoull(kbuff, &cur, 10);

#if 0
	/* Make sure the I/O was posted on the correct Ring */
	if (unlikely(val =! smp_processor_id())) {
		trace_printk("%s: WARNING Sender Usess wrong Core ID: [%ld] Core %d\n", __FUNCTION__, val, smp_processor_id());
	}
	if (unlikely(prev == smp_processor_id())) {
		trace_printk("%s: WARNING Sender switched Cores: [%ld] Core %d\n", __FUNCTION__, prev, smp_processor_id());
		prev = smp_processor_id();
	}
#endif

#if 0
	if (maio_tx_thread->state & TASK_NORMAL) {
		val = wake_up_process(maio_tx_thread);
		trace_debug("[%d]wake up thread[state %0lx][%s]\n", smp_processor_id(), maio_tx_thread->state, val ? "WAKING":"UP");
	}
#endif
	maio_post_tx_page(NULL);
	return size;
}
static int maio_post_tx_task(void *unused)
{

        while (!kthread_should_stop()) {
		trace_debug("[%d]Running...\n", smp_processor_id());
		while (maio_post_tx_page(unused)); // XMIT as long as there is work to be done.

		trace_debug("[%d]sleeping...\n", smp_processor_id());
                set_current_state(TASK_UNINTERRUPTIBLE);
                if (!kthread_should_stop()) {
                        schedule();
                }
                __set_current_state(TASK_RUNNING);
        }
        return 0;
}

static int (*threadfn)(void *data) = maio_post_tx_task;

static inline int create_threads(void)
{
	if (maio_tx_thread)
		return 0;

	maio_tx_thread = kthread_create(threadfn, NULL, "maio_tx_thread");
	if (IS_ERR(maio_tx_thread))
		return -ENOMEM;

	pr_err("maio_tx_thread created\n");
	return 0;
}

static inline ssize_t maio_enable(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{	char	*kbuff, *cur;
	size_t 	val;

	if (size < 1 || size >= PAGE_SIZE)
	        return -EINVAL;

	kbuff = memdup_user_nul(buf, size);
	if (IS_ERR(kbuff))
	        return PTR_ERR(kbuff);

	val 	= simple_strtoull(kbuff, &cur, 10);
	pr_err("%s: Now: [%s] was %s\n", __FUNCTION__, val ? "Configured" : "Off", maio_configured ? "Configured" : "Off");
	trace_printk("%s: Now: [%s] was %s\n", __FUNCTION__, val ? "Configured" : "Off", maio_configured ? "Configured" : "Off");

	kfree(kbuff);

	if (val == 0 || val == 1)
		maio_configured = val;
	else
		return -EINVAL;

	if (create_threads()) {
		pr_err("ERROR: Failed to create TX threads\n!!!");
		return -ENOMEM;
	}

	return size;
}

/*x86/boot/string.c*/
static unsigned int atou(const char *s)
{
	unsigned int i = 0;
	while (isdigit(*s))
		i = i * 10 + (*s++ - '0');
	return i;
}

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
	if ( dev_idx > 31)
		return -EINVAL;

	if ( !(maio_devs[dev_idx] = dev_get_by_index(&init_net, dev_idx)))
		return -ENODEV;

	default_dev_idx = dev_idx;
	trace_printk("device %s [%d]added\n", maio_devs[dev_idx]->name, dev_idx);

	kbase = uaddr2addr(base);
	if (!kbase) {

		pr_err("Uaddr %llx is not found in MTT [0x%llx - 0x%llx)\n", base, cached_mtt->start, cached_mtt->end);
		if ((rc = get_user_pages(base, (len >> PAGE_SHIFT), FOLL_LONGTERM, &umem_pages[0], NULL)) < 0) {
			pr_err("ERROR on get_user_pages %ld\n", rc);
			return rc;
		}
		kbase = page_address(umem_pages[0]) + (base & (PAGE_SIZE -1));
	}
	pr_err("MTRX is set to %llx[%llx] user %llx order [%d] rc = %ld\n", (u64)kbase, (u64)page_address(umem_pages[0]),
			base, compound_order(virt_to_head_page(kbase)), rc);
	global_maio_matrix = (struct user_matrix *)kbase;
	pr_err("Set user matrix to %llx [%ld]: RX %d [%d] TX %d [%d]\n", (u64)global_maio_matrix, len,
				global_maio_matrix->info.nr_rx_rings,
				global_maio_matrix->info.nr_rx_sz,
				global_maio_matrix->info.nr_tx_rings,
				global_maio_matrix->info.nr_tx_sz);

	for_each_possible_cpu(i) {
		struct percpu_maio_qp *qp = per_cpu_ptr(&maio_qp, i);

		pr_err("[%ld]Ring: RX:%llx  - %llx:: TX: %llx - %llx\n", i,
				global_maio_matrix->info.rx_rings[i],
				(u64)uaddr2addr(global_maio_matrix->info.rx_rings[i]),
				global_maio_matrix->info.tx_rings[i],
				(u64)uaddr2addr(global_maio_matrix->info.tx_rings[i]));

		qp->rx_counter = 0;
		qp->tx_counter = 0;
		qp->rx_sz = global_maio_matrix->info.nr_rx_sz;
		qp->tx_sz = global_maio_matrix->info.nr_tx_sz;
		qp->rx_ring = uaddr2addr(global_maio_matrix->info.rx_rings[i]);
		/* TODO: Singe TX ring  NOTICE: each Ring has a different counter... */
		qp->tx_ring = uaddr2addr(global_maio_matrix->info.tx_rings[0]);
	}

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
	pr_err("meta: [%u: 0x%x %u 0x%x]\n", meta->nr_pages, meta->stride, meta->headroom, meta->flags);
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

		if (min_pages_0  > (u64)page)
			min_pages_0 = (u64)page;

		if (max_pages_0  < (u64)page)
			max_pages_0 = (u64)page;

		if (PageHead(page)) {
			//trace_printk("[%ld]Caching %llx [%llx]  - P %llx[%d]\n", len, (u64 )kbase, meta->bufs[len],
			//	(u64)page, page_ref_count(page));
			maio_cache_head(page);
		} else {
			//trace_printk("[%ld]Adding %llx [%llx]  - P %llx[%d]\n", len, (u64 )kbase, meta->bufs[len],
			//		(u64)page, page_ref_count(page));
			set_page_count(page, 0);

			assert(get_maio_elem_order(__compound_head(page, 0)) == 0);
			maio_free_elem(kbase, 0);
		}
	}
	kfree(kbuff);

	return 0;
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
	pr_err("Got: [%llx: %ld]\n", base, len);
	kfree(kbuff);

	if (!(mtt = kzalloc(sizeof(struct umem_region_mtt)
				+ len * sizeof(struct page*), GFP_KERNEL)))
		return -ENOMEM;

	mtt->start	= base;
	mtt->end 	= base + (len * HUGE_SIZE) -1;
	mtt->len	= len;
	mtt->order	= HUGE_ORDER;

	pr_err("MTT [0x%llx - 0x%llx)\n", mtt->start, mtt->end);
	add_mtt(mtt);

	for (i = 0; i < len; i++) {
		u64 uaddr = base + (i * HUGE_SIZE);
		rc = get_user_pages(uaddr, (1 << HUGE_ORDER), FOLL_LONGTERM, &umem_pages[0], NULL);
		//trace_printk("[%ld]%llx[%llx:%d] \n", rc, uaddr, (unsigned long long)umem_pages[0],
		//					compound_order(__compound_head(umem_pages[0], 0)));

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
		set_maio_uaddr(umem_pages[0], uaddr);
		/* Allow for the Allocator to get elements on demand, flexible support for variable sizes */
		if (cache)
			maio_cache_hp(umem_pages[0]);
		//trace_printk("Added %llx:%llx (umem %llx:%llx)to MAIO\n", uaddr, (u64)page_address(umem_pages[0]),
		//			get_maio_uaddr(umem_pages[0]), (u64)uaddr2addr(uaddr));
	}
	pr_err("%d: %s maio_maped U[%llx-%llx) K:[%llx-%llx)\n", smp_processor_id(), __FUNCTION__, mtt->start, mtt->end,
			(u64)uaddr2addr(mtt->start), (u64)uaddr2addr(mtt->end));
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

static int maio_enable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", maio_configured ? 1 : 0);
        return 0;
}

static int maio_map_show(struct seq_file *m, void *v)
{

	if (global_maio_matrix) {
		seq_printf(m, "%llx %ld (%llx)\n",
			get_maio_uaddr(virt_to_head_page(global_maio_matrix)),
			hp_cache_size, maio_rx_post_cnt);
	} else {
		seq_printf(m, "NOT CONFIGURED\n");
	}

        return 0;
}

static int maio_enable_open(struct inode *inode, struct file *file)
{
        return single_open(file, maio_enable_show, PDE_DATA(inode));
}

static int maio_map_open(struct inode *inode, struct file *file)
{
        return single_open(file, maio_map_show, PDE_DATA(inode));
}

static const struct file_operations maio_mtrx_ops = {
        .open      = maio_map_open,
        .read      = seq_read,
        .llseek     = seq_lseek,
        .release   = single_release,
        .write     = maio_mtrx_write,
};

static const struct file_operations maio_page_0_ops = {
        .open      = maio_map_open, /* TODO: Change to func that pirnts the mapped user pages */
        .read      = seq_read,
        .llseek     = seq_lseek,
        .release   = single_release,
        .write     = maio_pages_0_write,
};

static const struct file_operations maio_page_ops = {
        .open      = maio_map_open, /* TODO: Change to func that pirnts the mapped user pages */
        .read      = seq_read,
        .llseek     = seq_lseek,
        .release   = single_release,
        .write     = maio_pages_write,
};

static const struct file_operations maio_map_ops = {
        .open      = maio_map_open, /* TODO: Change to func that pirnts the mapped user pages */
        .read      = seq_read,
        .llseek     = seq_lseek,
        .release   = single_release,
        .write     = maio_map_write,
};

static const struct file_operations maio_enable_ops = {
        .open      = maio_enable_open,
        .read      = seq_read,
        .llseek     = seq_lseek,
        .release   = single_release,
        .write     = maio_enable_write,
};

static const struct file_operations maio_tx_ops = {
        .open      = maio_map_open,
        .read      = seq_read,
        .llseek     = seq_lseek,
        .release   = single_release,
        .write     = maio_tx_write,
};

static inline void proc_init(void)
{
	maio_dir = proc_mkdir_mode("maio", 00555, NULL);
	proc_create_data("map", 00666, maio_dir, &maio_map_ops, NULL);
	proc_create_data("mtrx", 00666, maio_dir, &maio_mtrx_ops, NULL);
	proc_create_data("pages", 00666, maio_dir, &maio_page_ops, NULL);
	proc_create_data("pages_0", 00666, maio_dir, &maio_page_0_ops, NULL);
	proc_create_data("enable", 00666, maio_dir, &maio_enable_ops, NULL);
	proc_create_data("tx", 00666, maio_dir, &maio_tx_ops, NULL);
}

static __init int maio_init(void)
{
	int i = 0;

	maio_filter = default_maio_filter;
	maio_configured = false;
	for (;i< NUM_MAIO_SIZES; i++)
		mag_allocator_init(&global_maio.mag[i]);

	proc_init();
	return 0;
}
late_initcall(maio_init);
