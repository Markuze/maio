#ifndef  __MAIO__H
#define  __MAIO__H

#define UMAIO_RING_SZ	512

extern bool maio_configured;

struct user_ring {
	u64 cons;
	u64 addr[UMAIO_RING_SZ]; //should be TLV for multipage buffers.
	u64 prod;
};

struct user_matrix {
	struct user_ring ring[0];
};

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
