#include <linux/init.h>
#include <linux/magazine.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

#ifndef assert
#define assert(expr) 	do { \
				if (unlikely(!(expr))) { \
					trace_printk("Assertion failed! %s, %s, %s, line %d\n", \
						   #expr, __FILE__, __func__, __LINE__); \
					panic("ASSERT FAILED: %s (%s)", __FUNCTION__, #expr); \
				} \
			} while (0)

#endif

#define show_line pr_err("%s:%d\n",__FUNCTION__, __LINE__)

#define NUM_MAIO_SIZES	1
#define HUGE_ORDER	9 /* compound_order of 2MB HP */
#define HUGE_SHIFT	(HUGE_ORDER + PAGE_SHIFT)
#define HUGE_SIZE	(1 << (HUGE_SHIFT))
#define PAGES_IN_HUGE	(1<<HUGE_ORDER)

struct maio_cached_buffer {
	struct list_head list;
};

struct umem_region_mtt {
	u64 start;	/* userland start region [*/
	u64 end;	/* userland end region   ]*/
	int len;	/* Number of HP */
	int order;	/* Not realy needed as HUGE_ORDER is defined today */
	struct page *pages[0];
};

struct maio_magz {
	struct mag_allocator 	mag[NUM_MAIO_SIZES];
	u32			num_pages;
};
/* GLOBAL MAIO FLAG*/
bool maio_configured;
EXPORT_SYMBOL(maio_configured);
/* get_user_pages */
static struct page* umem_pages[1<<HUGE_ORDER];

static struct proc_dir_entry *maio_dir;
static struct maio_magz global_maio;

static LIST_HEAD(hp_cache);
static unsigned long hp_cache_flags;
DEFINE_SPINLOCK(hp_cache_lock);
/*
	For multiple reg ops a tree is needed
		1. For security and rereg need owner id and mmap to specific addr.
*/
static struct umem_region_mtt *mtt;

static inline u64 uaddr2idx(const struct umem_region_mtt *mtt, u64 uaddr)
{
	u64 idx;

	if (unlikely(uaddr > mtt->end || uaddr < mtt->start))
		return -EINVAL;

	idx = uaddr - mtt->start;
	return idx >> (HUGE_SHIFT);
}

static inline void maio_cache_hp(struct page *page)
{
	spin_lock_irqsave(&hp_cache_lock, hp_cache_flags);
	list_add(page_address(page), &hp_cache);
	spin_unlock_irqrestore(&hp_cache_lock, hp_cache_flags);
}

static inline struct page *maio_get_cached_hp(void)
{
	struct maio_cached_buffer *buffer;
	spin_lock_irqsave(&hp_cache_lock, hp_cache_flags);

	buffer = list_first_entry_or_null(&hp_cache,
						struct maio_cached_buffer, list);
	spin_unlock_irqrestore(&hp_cache_lock, hp_cache_flags);

	return (buffer) ? virt_to_page(buffer): NULL;
}

static inline ssize_t maio_add_page(struct file *file, const char __user *buf,
                                    size_t size, loff_t *_pos)
{
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

	for (i = 0; i < len; i++) {
		u64 uaddr = base + (i * HUGE_SIZE);
		rc = get_user_pages(uaddr, (1 << HUGE_ORDER), FOLL_LONGTERM, &umem_pages[0], NULL);
		pr_err("[%ld]%llx[%llx:%d] \n", rc, uaddr, (unsigned long long)umem_pages[0],
							compound_order(umem_pages[0]));
		/*
			set_maio_page. K > V.
			record address. V > K.
			Set pages into buffers. Magazine.

		*/
		mtt->pages[i] =	umem_pages[0];
		if (i != uaddr2idx(mtt, uaddr))
			pr_err("Please Fix uaddr2idx: %ld != %llx\n", i, uaddr2idx(mtt, uaddr));
		set_maio_uaddr(umem_pages[0], uaddr);
		/* Allow for the Allocator to get elements on demand, flexible support for variable sizes */
		maio_cache_hp(umem_pages[0]);
		pr_err("Added %llx:%llx to MAIO\n", uaddr, (unsigned long long)umem_pages[0]);
	}
	return size;
}

static ssize_t maio_proc_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
        return maio_add_page(file, buffer, count, pos);
}

static int maio_proc_show(struct seq_file *m, void *v)
{
	char *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);

	show_line;
        seq_printf(m, "Heya!");
	memcpy(buffer, "HelloCopy!\0", 12);
	if (!buffer)
		return -ENOMEM;
	show_line;

	seq_puts(m, buffer);
	show_line;
        kfree(buffer);
	show_line;
        seq_printf(m, "Heya!");
	show_line;
        return 0;
}

static inline int order2idx(size_t order)
{
	/* With multiple sizes this will change*/
	return 0;
}

static int maio_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, maio_proc_show, PDE_DATA(inode));
}

void maio_frag_free(void *addr)
{
	/*
	struct page *page = virt_to_head_page(addr);
		1. get idx
		2. mag free...
	*/
	panic("FUNCTION NOT IMPLEMENTED (%s)", __FUNCTION__); \
	return;
}
EXPORT_SYMBOL(maio_frag_free);

static inline void maio_free_elem(void *elem, u16 order)
{
	mag_free_elem(&global_maio.mag[order2idx(order)], elem);
}

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
	/* ref_count local - when 0 reached free all elemnts... - maio_frag_free*/
	trace_printk("%d: %s <- %pS\n", smp_processor_id(), __FUNCTION__, __builtin_return_address(0));
	put_buffers(page_address(page), get_maio_elem_order(page));
	return;
}
EXPORT_SYMBOL(maio_page_free);

static inline void replenish_from_cache(size_t order)
{
	int i;
	struct page *page = maio_get_cached_hp();

	trace_printk("%d: %s page:%llx\n", smp_processor_id(), __FUNCTION__, (u64)page);
	if (unlikely(!page))
		return;

	assert(compound_order(page) == HUGE_ORDER);
	for (i = 0; i < PAGES_IN_HUGE; i++) {
		put_buffers(page_address(page), order);
		page++;
	}
}

struct page *maio_alloc_pages(size_t order)
{
	void *buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);

	/* should happen on init when mag is empty.*/
	if (unlikely(!buffer)) {
		replenish_from_cache(order);
		buffer = mag_alloc_elem(&global_maio.mag[order2idx(order)]);
	}
	trace_printk("%d: %s <- %pS\n", smp_processor_id(), __FUNCTION__, __builtin_return_address(0));

	return (buffer) ? virt_to_page(buffer) : ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(maio_alloc_pages);

static const struct proc_ops maio_proc_ops = {
        .proc_open      = maio_proc_open,
        .proc_read      = seq_read,
        .proc_lseek     = seq_lseek,
        .proc_release   = single_release,
        .proc_write     = maio_proc_write,
};

static inline void proc_init(void)
{
	maio_dir = proc_mkdir_mode("maio", 00555, NULL);
        proc_create_data("pages", 00666, maio_dir, &maio_proc_ops, NULL);
}

static __init int maio_init(void)
{
	int i = 0;
	maio_configured = false;
	for (;i< NUM_MAIO_SIZES; i++)
		mag_allocator_init(&global_maio.mag[i]);

	proc_init();
	return 0;
}
late_initcall(maio_init);
