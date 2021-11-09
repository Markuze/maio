#ifndef  __IO_MD__H
#define  __IO_MD__H

#include <linux/skbuff.h>

/* Current mem layout
	4K [64|128 |640   |512      |2KB  |256B 	    |320B       |128B		   ]
	   [ dpdk  |vc_pkt| headroom| data| hole <shadow md>| skb_shinfo| io_md + ubuf_info]
*/
/********* Caution: Should be same as user counterpart ************************/

/******** MAIO PAGE STATE FLAGS ****************/
#define MAIO_PAGE_NEW		0x10000
#define MAIO_PAGE_REFILL	0x8000
#define MAIO_PAGE_HEAD 		0x4000
#define MAIO_PAGE_FREE		0x2000
#define MAIO_PAGE_IO   		(MAIO_PAGE_TX|MAIO_PAGE_RX|MAIO_PAGE_NAPI|MAIO_PAGE_NS)   // TX|RX|NAPI
#define MAIO_PAGE_NS		0x1000   // storred in the magz
#define MAIO_PAGE_NAPI		0x800   // storred in the magz
#define MAIO_PAGE_TX   		0x400   // sent by user
#define MAIO_PAGE_RX   		0x200   // alloced from magz - usualy RX
#define MAIO_PAGE_USER 		0x100   // page in user space control
/*************************************************/

static char* maio_stat_names[] = {
	"User page	",
	"RX Page  	",
	"TX Page  	",
	"NAPI Page	",
	"Network Stack	",
	"Free Page	",
	"HEAD Page	",
	"Refill Page	",
	"Pushed Pages	",
};

typedef atomic64_t maio_cntr;

struct memory_stats {
	union {
		struct {
			maio_cntr	page_user;
			maio_cntr	page_rx;
			maio_cntr	page_tx;
			maio_cntr	page_napi;
			maio_cntr	page_network_stack;
			maio_cntr	page_free;
			maio_cntr	page_head;
			maio_cntr	page_refill;
			maio_cntr	nr_page_initial;
		};
		maio_cntr	array[0];
	};
};

#define NR_MAIO_STATS	(sizeof(struct memory_stats)/sizeof(maio_cntr))

/******** MAIO STATE COUNTERS ****************/
static char* err_stat_names[] = {
	"TX Send		",
#define MAIO_ERR_TX_START	0x1
	"TX Completion		",
#define MAIO_ERR_TX_COMP	0x2
	"NAPI Send		",
#define MAIO_ERR_NAPI  		0x4
	"TX Error		",
#define MAIO_ERR_TX_ERR		0x8
	"NS packet		",
#define MAIO_ERR_NS		0x10
	"RX user slow		",
#define MAIO_ERR_RX_SLOW	0x20
	"ubuf alloc err		",
#define MAIO_ERR_UBUF_ERR	0x40
	"HeadPage on RX		",
#define MAIO_ERR_REFILL_HEAD	0x80
	"Alloc Error on RX	",
#define MAIO_ERR_RX_ALLOC	0x100
	"Missing Refill		",
#define MAIO_ERR_REFILL_MISSING	0x200
	"HeadPage returned	",
#define MAIO_ERR_HEAD_RETURNED	0x400
	"TX Error on netdev	",
#define MAIO_ERR_TX_ERR_NETDEV	0x800
	"Non I/O Page released	",
#define MAIO_ERR_BAD_FREE_PAGE	0x1000
	"Bad RC on page		",
#define MAIO_ERR_BAD_RC		0x2000
};

#define NR_MAIO_ERR_STATS	(sizeof(err_stat_names)/sizeof(char *))

struct err_stats {
		maio_cntr	array[NR_MAIO_ERR_STATS];
};

struct io_md {
	u64 state;

	u32 len;
	u32 poison;
	u16 vlan_tci;
	u16 flags;

	union {
		u32 user_bits;
		struct {
			u16 tx_cnt;
			u16 tx_compl;
		};
	};
	volatile u16 in_transit;
	volatile u16 in_transit_dbg;
	u32 line;
	u64 prev_state;
	u32 prev_line;
	struct ubuf_info *uarg;
} ____cacheline_aligned_in_smp;

#define IO_MD_OFF      (PAGE_SIZE - SKB_DATA_ALIGN(sizeof(struct io_md)))
#define SHADOW_OFF     (IO_MD_OFF - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) \
                                       - SKB_DATA_ALIGN(sizeof(struct io_md)))

struct skb_inline_data {
	union {
		u8	data[SMP_CACHE_BYTES];
		struct {
			struct list_head	list;
			void *ctx;
		};
	};
	struct skb_shared_info shinfo ____cacheline_aligned_in_smp;
};

#endif //__IO_MD_H
