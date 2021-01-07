#ifndef  __MAIO__H
#define  __MAIO__H

#include <linux/magazine.h>
#include <linux/rbtree.h>

#define NUM_MAIO_SIZES	1
#define HUGE_ORDER	9 /* compound_order of 2MB HP */
#define HUGE_SHIFT	(HUGE_ORDER + PAGE_SHIFT)
#define HUGE_SIZE	(1 << (HUGE_SHIFT))
#define HUGE_OFFSET	(HUGE_SIZE -1)
#define PAGES_IN_HUGE	(1<<HUGE_ORDER)

#define UMAIO_HEADROOM	256 	//TODO: Figure out why 256 results in 4K stride in mlx5e
#define UMAIO_STRIDE	0x1000
#define UMAIO_RING_SZ	512
#define NUM_MAX_RINGS	16
#define UMAIO_RING_MASK	(UMAIO_RING_SZ -1)

#define show_line pr_err("%s:%d\n",__FUNCTION__, __LINE__)

extern volatile bool maio_configured;
extern struct user_matrix *global_maio_matrix;

/********* Caution: Should be same as user counterpart ************************/

#define MAIO_POISON (0xFEA20FDAU)

struct io_md {
        u32 len;
        u32 poison;
};

struct common_ring_info {
        u32 nr_rx_rings;
        u32 nr_tx_rings;
        u32 nr_rx_sz;
        u32 nr_tx_sz;

	/* uaddr for {R|T}X tings*/
        u64 rx_rings[NUM_MAX_RINGS];
        u64 tx_rings[NUM_MAX_RINGS];
};

struct meta_pages_0 {
	u16 nr_pages;
	u16 stride;
	u16 headroom;
	u16 flags;
	u64 bufs[UMAIO_RING_SZ];
};

struct user_matrix {
	struct common_ring_info info;
	u64 entries[0] ____cacheline_aligned_in_smp;
};

/*****************************************************************************/

struct maio_cached_buffer {
	char headroom[256];
	struct list_head list;
};

struct umem_region_mtt {
	struct rb_node node;
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

struct percpu_maio_qp {
	unsigned long rx_counter;
	unsigned long tx_counter;

	u32 rx_sz;
	u32 tx_sz;

        u64 *rx_ring;
        u64 *tx_ring;

	void *cached_mbuf;
};

u16 maio_get_page_headroom(struct page *page);
int maio_post_rx_page(void *addr, u32 len);
void maio_frag_free(void *addr);
void maio_page_free(struct page *page);
void *maio_kalloc(void);
struct page *maio_alloc_pages(size_t order);

static inline struct page *maio_alloc_page(void)
{
	return maio_alloc_pages(0);
}

#endif //__MAIO_H
