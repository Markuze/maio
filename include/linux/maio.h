#ifndef  __MAIO__H
#define  __MAIO__H


void maio_frag_free(void *addr);
void maio_page_free(struct page *page);
void *maio_kalloc(void);
struct page *maio_alloc_pages(size_t order);

#endif //__MAIO_H
