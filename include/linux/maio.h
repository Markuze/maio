#ifndef  __MAIO__H
#define  __MAIO__H

#define UMAIO_RING_SZ	512
#define UMAIO_RING_MASK	(UMAIO_RING_SZ -1)

extern volatile bool maio_configured;
extern struct user_matrix *global_maio_matrix;

struct user_ring {
	u64 cons;
	u64 addr[UMAIO_RING_SZ]; //should be TLV for multipage buffers.
	u64 prod;
};

struct user_matrix {
	struct user_ring ring[0];
};

struct meta_pages_0 {
	u16 nr_pages;
	u16 stride;
	u16 headroom;
	u16 flags;
	u64 bufs[UMAIO_RING_SZ];
};

u16 maio_get_page_headroom(struct page *page);
void maio_post_rx_page(void *addr);
void maio_frag_free(void *addr);
void maio_page_free(struct page *page);
void *maio_kalloc(void);
struct page *maio_alloc_pages(size_t order);

static inline struct page *maio_alloc_page(void)
{
	return maio_alloc_pages(0);
}

#endif //__MAIO_H
