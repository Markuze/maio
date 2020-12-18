#ifndef  __MAIO__H
#define  __MAIO__H

#define UMAIO_RING_SZ	512
#define NUM_MAX_RINGS	16
#define UMAIO_RING_MASK	(UMAIO_RING_SZ -1)

extern volatile bool maio_configured;
extern struct user_matrix *global_maio_matrix;

/* Caution: Should be same as user counterpart */
struct common_ring_info {
        u32 nr_rx_rings;
        u32 nr_tx_rings;
        u32 nr_rx_sz;
        u32 nr_tx_sz;

	/* uaddr for {R|T}X tings*/
        u64 rx_rings[NUM_MAX_RINGS];
        u64 tx_rings[NUM_MAX_RINGS];
};


struct percpu_maio_qp {
	unsigned long rx_counter;
	unsigned long tx_counter;

	u32 rx_sz;
	u32 tx_sz;

        u64 *rx_ring;
        u64 *tx_ring;
};

struct user_matrix {
	struct common_ring_info info;
	u64 entries[0] ____cacheline_aligned_in_smp;
};

struct meta_pages_0 {
	u16 nr_pages;
	u16 stride;
	u16 headroom;
	u16 flags;
	u64 bufs[UMAIO_RING_SZ];
};

u16 maio_get_page_headroom(struct page *page);
int maio_post_rx_page(void *addr);
void maio_frag_free(void *addr);
void maio_page_free(struct page *page);
void *maio_kalloc(void);
struct page *maio_alloc_pages(size_t order);

static inline struct page *maio_alloc_page(void)
{
	return maio_alloc_pages(0);
}

#endif //__MAIO_H
