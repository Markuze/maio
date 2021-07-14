/**
	MAIO user-space lib
**/
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "user_maio.h"

/* Only ia64 requires this */
#ifdef __ia64__
#define ADDR (void *)(0x8000000000000000UL)
#define FLAGS (MAP_SHARED | MAP_FIXED)
#else
#define ADDR (void *)(0x0UL)
#define FLAGS (MAP_SHARED)
#endif

#define WRITE_BUFF_LEN 64

#define MAX_TCP_THREADS 16
static struct ring_md ring_md[MAX_TCP_THREADS];
/*
	Allocate HP Memory
		name: file name for hugepagefile
		nr_pages: number of 2MB huge pages
		base_addr : the user address of mapped region start

		*cb to create heap -- return heap instead of fd*

*/
static int __init_hp_memory(char *name, void **base_addr, int nr_pages)
{
	int fd, map_proc, len;
	char write_buffer[WRITE_BUFF_LEN] = {0};

	/* create hp file */
	fd  = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
	if (fd < 0) {
		perror("Open failed (please use sudo)");
		exit -1;
	}

	/* mmap hp file */
	*base_addr = mmap(ADDR, LENGTH, PROTECTION, FLAGS, fd, 0);
	if (*base_addr == MAP_FAILED) {
		printf("Error Mapping %llu [%llu]\n", LENGTH, NR_PAGES);
		perror("mmap");
		unlink(FILE_NAME);
		return -1;
	}

	/* Create MTT for MAIO */
        if ((map_proc = open(MAP_PROC_NAME, O_RDWR)) < 0) {
                printf("Failed to init internals %d\n", __LINE__);
                return -ENODEV;
        }

        printf(">>> base_addr %p len %lld [2MB pages]\n", *base_addr, NR_PAGES);
        len  = snprintf(write_buffer, 64, "%llx %llu\n", (unsigned long long)*base_addr, NR_PAGES);
        len = write(map_proc, write_buffer, len);

        printf(">>> Sent %s [2MB = %x]\n", write_buffer, (1<<21));

        close(map_proc);

	return fd;
}

static inline int add_2MB_HP(struct page_cache *cache, void *addr)
{
	static int	quiet;
	int i;
	size_t chunk_log_step	= PAGE_SHIFT + cache->chunk_log;
	size_t nr_chunks	= (1 << (HP_SIZE_LOG - chunk_log_step));

	if (((uint64_t)addr) & HP_MASK) {
		printf("(%s)Error bad address given %p\n", __FUNCTION__, addr);
		return -1;
	}

	if (!quiet) {
		quiet = 1;
		printf("nr_chunks = %ld log_step %ld chunk_size %d KB\n", nr_chunks, chunk_log_step, (1 << chunk_log_step) >> 10);
	}

	//head page is not used for I/O. It holds the external page state
	// next 15 go into a page pool
	for (i = 1; i < cache->chunk_sz; i++) {
		struct single_list *list = addr + (i << PAGE_SHIFT);

		list->next = cache->page_list;
		cache->page_list = list;
	}

	for (i = i; i < nr_chunks; i++) {
		struct single_list *list = addr + (i << chunk_log_step);

		list->next = cache->comp_page_list;
		cache->comp_page_list = list;
	}
	return 0;
}

void *alloc_page(struct page_cache *cache)
{
	void *tmp, *buffer;

	if (!cache->page_list)
		return NULL;

	tmp = cache->page_list->next;
	buffer = cache->page_list;
	cache->page_list = tmp;

	return buffer;
}

void *alloc_chunk(struct page_cache *cache)
{
	void *tmp, *buffer;

	if (!cache->comp_page_list)
		return NULL;

	tmp = cache->comp_page_list->next;
	buffer = cache->comp_page_list;
	cache->comp_page_list = tmp;

	return buffer;
}

static struct page_cache *heap_from_hp_memory(void *base, int nr_pages)
{
	struct page_cache cache  = {0};
	struct page_cache *new;
	unsigned long offset = 0;

	cache.chunk_sz 		= 4;
	cache.chunk_log 	= 2;

	while (nr_pages--) {
		if (add_2MB_HP(&cache, base + offset))
			return NULL;
		offset += (1<<21);
	}
	new = alloc_page(&cache);
	memcpy(new, &cache, sizeof(struct page_cache));

	return new;
}

struct page_cache *init_hp_memory(int nr_pages)
{
	void *base;
	struct page_cache *cache;
	int hp_fd = __init_hp_memory(NULL, &base, nr_pages);

	cache = heap_from_hp_memory(base, NR_PAGES);
}

int init_tcp_ring(int idx, struct page_cache *cache)
{
	static int tx_fd, state_fd;
	int len;
	int ring_fd;
	char write_buffer[WRITE_BUFF_LEN] = {0};
	struct ring_md *ring = &ring_md[idx];
	void *buffer = alloc_chunk(cache);

	if ((ring_fd = open(TCP_RING_PROC_NAME, O_RDWR)) < 0) {
		printf("Failed to init internals %d\n", __LINE__);
		return -ENODEV;
        }

	len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%llx %u %d\n", (unsigned long long)buffer,
						(cache->chunk_sz << PAGE_SHIFT),
						idx);

	len = write(ring_fd, write_buffer, len);
	close(ring_fd);

	printf("%s: [%d] ring fd %d state  %d\n", __FUNCTION__, idx, tx_fd, state_fd);
	if (len != len)
		printf("ERROR [%d] writing to %s\n", len, TCP_RING_PROC_NAME);

	if (!tx_fd) {
		if ((tx_fd = open(TCP_TX_PROC_NAME, O_RDWR)) < 0) {
			printf("Failed to init internals %d\n", __LINE__);
			return -ENODEV;
		}
	}
	if (!state_fd) {
		if ((state_fd = open(STATE_PROC_NAME, O_RDWR)) < 0) {
			printf("Failed to init internals %d\n", __LINE__);
			return -ENODEV;
		}
	}

	printf("%s: [%d] ring fd %d state  %d\n", __FUNCTION__, idx, tx_fd, state_fd);

	ring->fd 	= tx_fd;
	ring->state_fd 	= state_fd;
	ring->tx_idx	= 0;
	ring->ring_sz	= (cache->chunk_sz << PAGE_SHIFT)/sizeof(struct sock_md);
	ring->sock_md	= buffer;
	ring->batch_count = 0;

	memset(buffer, 0, (cache->chunk_sz << PAGE_SHIFT));
	return 0;
}

int create_connected_socket(uint32_t ip, uint16_t port)
{
	int sock_fd, len, idx;
	char write_buffer[WRITE_BUFF_LEN] = {0};

	if ((sock_fd = open(TCP_SOCK_PROC_NAME, O_RDWR)) < 0) {
		printf("Failed to init internals %d\n", __LINE__);
		return -ENODEV;
        }

	len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%d %d\n", ip, port);

	idx = write(sock_fd, write_buffer, len);
	close(sock_fd);

	if (idx < 0)
		printf("ERROR [%d] writing to %s\n", len, TCP_RING_PROC_NAME);
	return idx;

}

static inline void dump_sock_md(struct sock_md *md, int idx)
{
	printf("sock_md[%d]: uaddr %lu len %u state/flags [%u|%u]\n",
		idx, md->uaddr, md->len, md->state, md->flags);
}

#define IDK_RANDOM_MAGIC_NUMBER	(128 << 10) //128KB
#define valid_entry(md)	((md)->sock_md[(md)->tx_idx  & ((md)->ring_sz -1)].state != MAIO_KERNEL_BUFFER)
#define ring_entry(md)	&((md)->sock_md[(md)->tx_idx  & ((md)->ring_sz -1)])
#define dump_current_smd(md) dump_sock_md(ring_entry(md), (md)->tx_idx  & ((md)->ring_sz -1));

int send_buffer(int idx, void *buffer, int len, int more)
{
	char write_buffer[WRITE_BUFF_LEN] = {0};
	struct ring_md *ring = &ring_md[idx];
	int rc = 0, send = !more;

	if (valid_entry(ring)) {
		struct sock_md *md = ring_entry(ring);

		md->uaddr	= (uint64_t)buffer;
		md->len 	= len;
		md->state	= MAIO_KERNEL_BUFFER;
		//dump_current_smd(ring);
		ring->batch_count += len;
		++(ring->tx_idx);
	} else {
		//printf("sleeping %u\n", ring->tx_idx);
		rc = -EAGAIN;
	}

/*
	if (!(ring->tx_idx & 0xfffff)) {
		printf("tx_idx %u\n", ring->tx_idx);
	}
*/
	send |= !!rc;
	if (send || ring->batch_count >= IDK_RANDOM_MAGIC_NUMBER) {
		//printf("sending %dKB\n", ring->batch_count >> 10);
		len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%d %d\n", idx, (rc) ? 1 : 0);
		write(ring->fd, write_buffer, len);
		ring->batch_count = 0;
	}
	return rc;
}

int get_state(void *uaddr, int idx)
{
	int len;
	struct ring_md *ring = &ring_md[idx];
	char write_buffer[WRITE_BUFF_LEN] = {0};

	printf("get satte %p [%d]\n", uaddr, idx);
	len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%p\n", uaddr);
	return write(ring->state_fd, write_buffer, len);
}
