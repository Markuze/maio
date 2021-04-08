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

#define IS_MAIO_MASK	0x1	//probably have 21 bits.
#define MAIO_MASK_MAX	HUGE_OFFSET

#define NUM_MAX_RINGS	16
#define MAX_DEV_NUM 	16

#if 0
//TODO: Take these at init and change to __read_mostly var
#define UMAIO_STRIDE		0x1000
#define UMAIO_STRIDE_MASK	(0x1000-1)
#define UMAIO_HEADROOM	256 	//TODO: Figure out why 256 results in 4K stride in mlx5e
#define UMAIO_RING_SZ	512
#define UMAIO_RING_MASK	(UMAIO_RING_SZ -1)
#endif

#define show_line pr_err("%s:%d\n",__FUNCTION__, __LINE__)

typedef bool (*maio_filter_func_p)(void *);

extern maio_filter_func_p maio_filter;
extern volatile bool maio_configured;
extern struct user_matrix *global_maio_matrix[MAX_DEV_NUM];

/******** MAIO PAGE PRIVATE FLAGS ****************/
#define MAIO_PAGE_HEAD 0xF000
#define MAIO_PAGE_MBUF 0xF00
#define MAIO_PAGE_FREE 0x800   // storred in the magz
#define MAIO_PAGE_IO   0x600   // TX|RX
#define MAIO_PAGE_TX   0x400   // sent by user
#define MAIO_PAGE_RX   0x200   // alloced from magz - usualy RX
#define MAIO_PAGE_USER 0x100   // page in user space control
/*************************************************/

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
	u32 nr_pages;
	u32 stride;
	u32 headroom;
	u32 flags;
	u64 bufs[0];
};

struct user_matrix {
	struct common_ring_info info;
	u64 entries[0] ____cacheline_aligned_in_smp;
};

/*****************************************************************************/
struct io_track {
	u64	map[512]; //4K
};

/******************************************************************************/
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

struct percpu_maio_dev_qp {
	struct percpu_maio_qp qp[MAX_DEV_NUM];
};

/* on RX use the mtrx of the upper dev */
/* on TX use the netdev of the lower(i.e., slave) dev */
struct maio_dev_map {
	int on_tx[MAX_DEV_NUM];
	int on_rx[MAX_DEV_NUM];
};

void reset_maio_default_filter(void);
u16 maio_get_page_headroom(struct page *page);
int maio_post_rx_page(struct net_device *net, void *addr, u32 len);
int maio_post_rx_page_copy(struct net_device *net, void *addr, u32 len);
void maio_frag_free(void *addr);
void maio_page_free(struct page *page);
void *maio_kalloc(void);
struct page *maio_alloc_pages(size_t order);

static inline struct page *maio_alloc_page(void)
{
	return maio_alloc_pages(0);
}

#endif //__MAIO_H
