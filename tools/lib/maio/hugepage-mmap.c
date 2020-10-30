// SPDX-License-Identifier: GPL-2.0
/*
 * hugepage-mmap:
 *
 * Example of using huge page memory in a user application using the mmap
 * system call.  Before running this application, make sure that the
 * administrator has mounted the hugetlbfs filesystem (on some directory
 * like /mnt) using the command mount -t hugetlbfs nodev /mnt. In this
 * example, the app is requesting memory of size 256MB that is backed by
 * huge pages.
 *
 * For the ia64 architecture, the Linux kernel reserves Region number 4 for
 * huge pages.  That means that if one requires a fixed address, a huge page
 * aligned address starting with 0x800000... will be required.  If a fixed
 * address is not required, the kernel will select an address in the proper
 * range.
 * Other architectures, such as ppc64, i386 or x86_64 are not so constrained.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "user_maio.h"

//#define NR_PAGES (1536ULL)
#define NR_PAGES (256ULL)
#define HP_SIZE (1<<21)	//2MB Files
#define FILE_NAME "/media/huge/hugepagefile"
#define LENGTH (NR_PAGES * HP_SIZE)
#define PROTECTION (PROT_READ | PROT_WRITE)

/* Only ia64 requires this */
#ifdef __ia64__
#define ADDR (void *)(0x8000000000000000UL)
#define FLAGS (MAP_SHARED | MAP_FIXED)
#else
#define ADDR (void *)(0x0UL)
#define FLAGS (MAP_SHARED)
#endif

static void check_bytes(char *addr)
{
	printf("First hex is %x\n", *((unsigned int *)addr));
}

static void write_bytes(char *addr)
{
	unsigned long i;

	for (i = 0; i < LENGTH; i++)
		*(addr + i) = (char)i;
}

static int read_bytes(char *addr)
{
	unsigned long i;

	check_bytes(addr);
	for (i = 0; i < LENGTH; i++)
		if (*(addr + i) != (char)i) {
			printf("Mismatch at %lu\n", i);
			return 1;
		}
	return 0;
}


static inline int check_ring(struct user_ring *ring)
{
	int pack = 0;
	char *addr;
	char buffer[16] = {0};

	while (ring->cons != ring->prod) {
		++pack;
		addr = (void *)ring->addr[ring->cons++ & UMAIO_RING_MASK];
		snprintf(buffer, 16, "%c:%c:%c:%c:%c:%c", addr[0], addr[1], addr[2], addr[3],addr[4], addr[5]);
		snprintf(&buffer[7], 16, "%c:%c:%c:%c:%c:%c", addr[6], addr[7], addr[8], addr[9], addr[10], addr[11]);
		printf("Addr: %p %s::%s::%d\n", addr, buffer, &buffer[7], *((int *)&addr[12]));
	}

	return pack;
}

static inline void poll_rings(struct user_matrix *mtrx)
{
	int pack = 0;

	printf("Checking matrix @ %p\n", mtrx);
	for (int i = 0; i < 8; i++) {
		struct user_ring *ring = &mtrx->ring[i];
		printf("\tChecking ring @ %p\n", ring);
	}
retry:
	for (int i = 0; i < 8; i++) {
		struct user_ring *ring = &mtrx->ring[i];
		pack += check_ring(ring);
	}
	goto retry;

	return;
}

int main(void)
{
	char *addr;
	int fd, ret, proc;
	char write_buffer[64];

	fd = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
	if (fd < 0) {
		perror("Open failed");
		exit(1);
	}

	addr = mmap(ADDR, LENGTH, PROTECTION, FLAGS, fd, 0);
	if (addr == MAP_FAILED) {
		printf("Error Mapping %llu [%llu]\n", LENGTH, NR_PAGES);
		perror("mmap");
		unlink(FILE_NAME);
		exit(1);
	}

	printf("Returned address is %p > [%s]\n", addr, (char *)&addr[16]);
	check_bytes(addr);
	write_bytes(addr);
	ret = read_bytes(addr);

	printf("writing to maio/pages\n");
	proc = open("/proc/maio/pages", O_RDWR);
	if (proc < 0) {
		perror("Open failed");
	} else {
		struct user_matrix *mt = NULL;
		int len = snprintf(write_buffer, 64, "%p %llu\n", addr, NR_PAGES);
		len = write(proc, write_buffer, len);
		memset(write_buffer, 0, 64);
		printf("rechecking returned %p > [%s]\n", &addr[16], (char *)&addr[16]);
		len = read(proc, write_buffer, 64);
		mt = (void *)strtoull(write_buffer, NULL, 16);
		printf("read[%d] %s: %p\n", len, write_buffer, mt);

		poll_rings(mt);
	}

	if (!(proc < 0))
		close(proc);
	munmap(addr, LENGTH);
	close(fd);
	unlink(FILE_NAME);

	return ret;
}
