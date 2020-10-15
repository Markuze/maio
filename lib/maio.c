#include <linux/init.h>
#include <linux/magazine.h>
#include <linux/mm.h>

#define NUM_MAIO_SIZES	1

struct maio_magz {
	struct mag_allocator 	mag[NUM_MAIO_SIZES];
	u32			num_pages;
};

struct maio_magz global_maio;

void maio_frag_free(void *addr)
{
	struct page *page = virt_to_head_page(addr);
	/*
		1. get idx
		2. mag free...
	*/
	return;
}
EXPORT_SYMBOL(maio_frag_free);

void maio_page_free(struct page *page)
{
	/* Need to make sure we dont get only head pages here...*/
	/* ref_count local - when 0 reached free all elemnts... - maio_frag_free*/
	return;
}
EXPORT_SYMBOL(maio_page_free);

static __init int maio_init(void)
{
	int i = 0;

	for (;i< NUM_MAIO_SIZES; i++)
		mag_allocator_init(&global_maio.mag[i]);
}
late_initcall(maio_init);
