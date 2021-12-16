#ifndef  __MAGAZINE__H
#define  __MAGAZINE__H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define MAG_COUNT	2
#define MAG_DEPTH	64//TODO: Make an init time variable

//
struct magazine {
	struct list_head 	list;
	void 			*stack[MAG_DEPTH];
};

struct mag_pair {
	union {
		struct magazine *mags[MAG_COUNT];
		uint64_t 	mag_ptr[MAG_COUNT];
	};
	u32		count[MAG_COUNT];
};

struct percpu_mag_pair {
	struct mag_pair	pair[2]; //Per Core instance x 2 (normal , and _bh)
};

struct mag_allocator {
	spinlock_t 				lock;
	u64 					lock_state;
	struct list_head 			empty_list;
	struct list_head 			full_list;
	uint32_t 				empty_count;
	uint32_t 				full_count;
	struct percpu_mag_pair	__percpu 	*pcp_pair; //Per Core instance x 2 (normal , and _bh)
};

static inline uint32_t mag_get_full_count(struct mag_allocator *allocator)
{
	return allocator->full_count;
}

void *mag_alloc_elem(struct mag_allocator *allocator);

/*unsafe version -- to be used ONLY in a teardown scenario*/
void *mag_alloc_elem_on_cpu(struct mag_allocator *allocator, int cpu);

void mag_free_elem(struct mag_allocator *allocator, void *elem);

void mag_allocator_init(struct mag_allocator *allocator);

//Need free and GC

/******** MAGAZINE STATE COUNTERS ****************/
static char* mag_stat_names[] = {
	"alloc in task				",
#define MAG_ALLOC_TASK				0x0
	"alloc in soft_bh			",
#define MAG_ALLOC_SOFT_BH			0x1
	"free in task				",
#define MAG_FREE_TASK				0x2
	"free in soft_bh			",
#define MAG_FREE_SOFT_BH			0x3
/* WARNING: the numbers of the first four elemnts must not change */
	"swap empty				",
#define MAG_SWAP_EMPTY				0x4
	"swap empty bh				",
#define MAG_SWAP_EMPTY_BH			0x5
	"swap full				",
#define MAG_SWAP_FULL				0x6
	"swap full bh				",
#define MAG_SWAP_FULL_BH			0x7
};

#define NR_MAGAZINE_STATS	(sizeof(mag_stat_names)/sizeof(char *))

struct mag_stats {
	atomic64_t	array[NR_MAGAZINE_STATS];
};

void dump_mag_stats(struct seq_file *m, struct mag_allocator *allocator);

#endif //__MAGAZINE__H
