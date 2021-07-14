/****
An example of creating a TCP socket and sending Zero-Copy I/O
***/

#include <stdio.h>
#include "user_maio.h"

#include <unistd.h>

#define PAGE_CNT	512
#define CHUNK_NUM	2048	

const int K_CLIENTS = 1;
uint32_t port = 8080;

const int K_CHUNK_SIZE = 4<<12;
void *chunk[CHUNK_NUM];

int main(void)
{
	uint32_t dip = STR_IP(10,128,0,3);
	int idxs[K_CLIENTS];

	/* Init Mem*/
	void *cache = init_hp_memory(PAGE_CNT);
	printf("init memory and get page %p\n", cache);

	/* create + connect */
	for(int i = 0; i < K_CLIENTS; ++i) {
		int idx = create_connected_socket(dip, port);
		printf("Connected maio sock =%d to port %d\n", idx, port);
		idxs[i] = idx;
		init_tcp_ring(idx, cache);
		++port;
	}


	/* init ring */
	// init_tcp_ring(idx, cache);
	// init_tcp_ring(idx2, cache);

	/* prep mem for I/O */
	for (int i = 0; i < CHUNK_NUM; ++i) {
		chunk[i] = alloc_chunk(cache);
	}

	printf("send loop [%d]\n", K_CHUNK_SIZE);
	int next_chunk = 0;
	while (1) {
		for(int i = 0; i < K_CLIENTS; ++i) {
			send_buffer(idxs[i], chunk[next_chunk++], K_CHUNK_SIZE, 1);
			if(next_chunk == CHUNK_NUM)
				next_chunk = 0;
		}
	};

	return 0;
}
