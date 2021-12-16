#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/magazine.h>
#include <linux/seq_file.h>

#ifndef assert
#define assert(expr) 	do { \
				if (unlikely(!(expr))) { \
					trace_printk("Assertion failed! %s, %s, %s, line %d\n", \
						   #expr, __FILE__, __func__, __LINE__); \
					panic("ASSERT FAILED: %s (%s)", __FUNCTION__, #expr); \
				} \
			} while (0)

#endif
#ifndef TRACE_DEBUG
#define TRACE_DEBUG(...)
#endif

#define CACHE_MASK      (BIT(INTERNODE_CACHE_SHIFT) - 1)

static struct mag_stats 	mag_stats;

static inline void inc_mag_stat(u8 idx)
{
	if (likely(idx < NR_MAGAZINE_STATS))
		atomic_long_inc(&mag_stats.array[idx]);
}

#define put_line(m, fmt, ...)				\
	if (m) {					\
		seq_printf(m, fmt, ##__VA_ARGS__);	\
	} else {					\
		pr_err(fmt, ##__VA_ARGS__);		\
	}

void dump_mag_stats(struct seq_file *m, struct mag_allocator *allocator)
{
	int i = 0;

	for (i = 0; i < NR_MAGAZINE_STATS; i++)
			put_line(m, "%s\t: %ld\n", mag_stat_names[i],
					atomic_long_read(&mag_stats.array[i]));

	put_line(m, "Full count\t%d\n", allocator->full_count);
	put_line(m, "Empty count\t%d\n", allocator->empty_count);
}

// page_to_nid - validate copy and mag alloc/free.

static inline void mag_lock(struct mag_allocator *allocator)
{
	spin_lock_bh(&allocator->lock);
}

static inline void mag_unlock(struct mag_allocator *allocator)
{
	spin_unlock_bh(&allocator->lock);
}

static inline u32 mag_pair_count(struct mag_pair *pair)
{
	return pair->count[0] + pair->count[1];
}

static inline struct mag_pair *get_cpu_mag_pair(struct mag_allocator *allocator, int *idx)
{
	struct percpu_mag_pair *pcp;

	*idx = ((in_softirq()) ? 1 : 0);
	get_cpu();

	pcp = this_cpu_ptr(allocator->pcp_pair);
	return &pcp->pair[*idx];
}

static inline void put_cpu_mag_pair(void)
{
	put_cpu();
}

static inline void swap_mags(struct mag_pair *pair)
{
	pair->mag_ptr[0] ^= pair->mag_ptr[1];
	pair->mag_ptr[1] ^= pair->mag_ptr[0];
	pair->mag_ptr[0] ^= pair->mag_ptr[1];

	pair->count[0] ^= pair->count[1];
	pair->count[1] ^= pair->count[0];
	pair->count[0] ^= pair->count[1];
}

static void *mag_pair_alloc(struct mag_pair *pair)
{
	void *elem;

	if (unlikely(pair->count[0] == 0))
		return NULL;

	--pair->count[0];
	elem = pair->mags[0]->stack[pair->count[0]];

	/* Make sure that, if there are elems in the pair, idx 0 has them*/
	if (pair->count[0] == 0) {
		swap_mags(pair);
	}
	return elem;
}

static void mag_pair_free(struct mag_pair *pair, void *elem)
{
	u32 idx = 0;

	assert(pair->count[0] < MAG_DEPTH || pair->count[1] < MAG_DEPTH);

	if (pair->count[0] == MAG_DEPTH)
		idx = 1;

	pair->mags[idx]->stack[pair->count[idx]] = elem;
	++pair->count[idx];
}

static void mag_allocator_switch_full(struct mag_allocator *allocator, struct mag_pair *pair)
{
	u32 idx = (pair->count[1] == MAG_DEPTH) ? 1 : 0;
	assert(pair->count[idx] == MAG_DEPTH);

	mag_lock(allocator);

	list_add(&pair->mags[idx]->list, &allocator->full_list);
	++allocator->full_count;

	if (allocator->empty_count) {
		pair->mags[idx] = list_entry(allocator->empty_list.next, struct magazine, list);
		list_del_init(allocator->empty_list.next);
		--allocator->empty_count;
	} else {
		void *ptr = kzalloc(sizeof(struct magazine) + L1_CACHE_BYTES -1, GFP_ATOMIC|__GFP_COMP|__GFP_NOWARN);

		pair->mags[idx]	= (void *)ALIGN((u64)ptr, L1_CACHE_BYTES);
	}
	mag_unlock(allocator);

	pair->count[idx] = 0;
}

static void mag_allocator_switch_empty(struct mag_allocator *allocator, struct mag_pair *pair)
{
	int idx = (pair->count[0]) ? 1 : 0;

	mag_lock(allocator);
	if (allocator->full_count) {
		list_add(&pair->mags[idx]->list, &allocator->empty_list);
		++allocator->empty_count;

		pair->mags[idx] = list_entry(allocator->full_list.next, struct magazine, list);
		list_del_init(allocator->full_list.next);
		pair->count[idx] = MAG_DEPTH;
		--allocator->full_count;
	}
	mag_unlock(allocator);
}

void *mag_alloc_elem_on_cpu(struct mag_allocator *allocator, int cpu)
{
	struct percpu_mag_pair *pcp = per_cpu_ptr(allocator->pcp_pair, cpu);
	struct mag_pair	*pair = &pcp->pair[0];
	void 		*elem;

	if (unlikely(mag_pair_count(pair) == 0 )) {
		pair = &pcp->pair[1];
	}

	elem = mag_pair_alloc(pair);
	return elem;
}

void *mag_alloc_elem(struct mag_allocator *allocator)
{
	int in_bh;
	struct mag_pair	*pair = get_cpu_mag_pair(allocator, &in_bh);
	void 		*elem;

	inc_mag_stat(MAG_ALLOC_TASK + in_bh);
	if (unlikely(mag_pair_count(pair) == 0 )) {
		/*may fail, it's ok.*/
		inc_mag_stat(MAG_SWAP_EMPTY + in_bh);
		mag_allocator_switch_empty(allocator, pair);
	}

	elem = mag_pair_alloc(pair);
	put_cpu_mag_pair();
	return elem;
}

void mag_free_elem(struct mag_allocator *allocator, void *elem)
{
	int in_bh;
	struct mag_pair	*pair = get_cpu_mag_pair(allocator, &in_bh);


	inc_mag_stat(MAG_FREE_TASK + in_bh);
	mag_pair_free(pair, elem);

	/* If both mags are full */
	if (unlikely(mag_pair_count(pair) == (MAG_DEPTH << 1))) {
		inc_mag_stat(MAG_SWAP_FULL + in_bh);
		mag_allocator_switch_full(allocator, pair);
	}
	put_cpu_mag_pair();
}

/*Allocating a new pair of empty magazines*/
static inline void init_mag_pair(struct mag_pair *pair)
{
	int i;
	struct magazine *mag = kzalloc((sizeof(struct magazine) * MAG_COUNT) + L1_CACHE_BYTES -1, __GFP_COMP|__GFP_NOWARN);
	assert(mag);

	mag = (void *)ALIGN((u64)mag, L1_CACHE_BYTES);
	for (i = 0; i < MAG_COUNT; i++) {
		pair->mags[i] = &mag[i];
	}
	assert(pair->mags[0]);
}

void mag_allocator_init(struct mag_allocator *allocator)
{
	int cpu;
//1.	alloc_struct + pair per core x 2;
//2.	alloc empty mag x2 per idx (init mag_pair, init_mag)

	allocator->pcp_pair = alloc_percpu(struct percpu_mag_pair);
	for_each_possible_cpu(cpu) {
		struct percpu_mag_pair *pcp = per_cpu_ptr(allocator->pcp_pair, cpu);
		init_mag_pair(&pcp->pair[0]);
		init_mag_pair(&pcp->pair[1]);
	}

//3.	init spin lock.
	spin_lock_init(&allocator->lock);

//4. 	init all lists.
	INIT_LIST_HEAD(&allocator->empty_list);
	INIT_LIST_HEAD(&allocator->full_list);
//5. 	init all alloc func. /* Removed untill last_idx removed */
//6.    Counters allocated.
/* Noop */
}
