#ifndef  __IO_MD__H
#define  __IO_MD__H

#include <linux/skbuff.h>

/* Current mem layout
	4K [64|128 |640   |512      |2KB  |320B 	    |320B       |64	]
	   [ dpdk  |vc_pkt| headroom| data| hole <shadow md>| skb_shinfo| io_md ]
*/
/********* Caution: Should be same as user counterpart ************************/

/******** MAIO PAGE STATE FLAGS ****************/
#define MAIO_PAGE_CONSUMED	0x20000
#define MAIO_PAGE_NEW		0x10000
#define MAIO_PAGE_REFILL	0x8000
#define MAIO_PAGE_HEAD 		0x4000
#define MAIO_PAGE_FREE		0x2000
#define MAIO_PAGE_IO   		(MAIO_PAGE_TX|MAIO_PAGE_RX|MAIO_PAGE_NAPI|MAIO_PAGE_NS|MAIO_PAGE_CONSUMED|MAIO_PAGE_REFILL)   // TX|RX|NAPI
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
	"TX Completion			",
#define MAIO_ERR_TX_COMP	0x1
	"NAPI Send			",
#define MAIO_ERR_NAPI  		0x2
	"TX Send			",
#define MAIO_ERR_TX_START	0x4
	"TX Error			",
#define MAIO_ERR_TX_ERR		0x8
	"NS packet			",
#define MAIO_ERR_NS		0x10
	"RX user slow			",
#define MAIO_ERR_RX_SLOW	0x20
	"ubuf alloc err			",
#define MAIO_ERR_UBUF_ERR	0x40
	"HeadPage on RX			",
#define MAIO_ERR_REFILL_HEAD	0x80
	"Alloc Error on RX		",
#define MAIO_ERR_RX_ALLOC	0x100
	"Missing Refill			",
#define MAIO_ERR_REFILL_MISSING	0x200
	"HeadPage returned		",
#define MAIO_ERR_HEAD_RETURNED	0x400
	"TX Error on netdev		",
#define MAIO_ERR_TX_ERR_NETDEV	0x800
	"Non I/O Page released		",
#define MAIO_ERR_BAD_FREE_PAGE	0x1000
	"Bad RC on page			",
#define MAIO_ERR_BAD_RC		0x2000
	"TX Completion in transit	",
#define MAIO_ERR_TX_COMP_TRANS	0x4000
	"TX Dev Busy			",
#define MAIO_ERR_TX_BUSY	0x8000
	"TX Dev Busy early		",
#define MAIO_ERR_TX_BUSY_EARLY	0x10000
	"TX Add Frag Err		",
#define MAIO_ERR_TX_FRAG_ERR	0x20000
	"New page on Refill		",
#define MAIO_ERR_REFILL_NEW	0x40000
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
		u32	user_bits1;
		struct {
			u16 tx_cnt;
			u16 tx_compl;
		};
	};

	u64	next_frag;	//User addr
	union {
		u64	user_bits2;
		struct {
			void *next;
		};
	};

	volatile u16 in_transit;
	volatile u16 in_transit_dbg;
	u32 line;
	u64 prev_state;
	atomic_t	idx;
	u32 prev_line;
} ____cacheline_aligned_in_smp;

#define NR_SHADOW_LOG_ENTIRES	16
union shadow_state {
	u8 __size[320];
	struct {
		u8 core_rc;
		u8 mark;
		u16 unused;
		u64 addr;
		u64 addr2;
	} entry[NR_SHADOW_LOG_ENTIRES];
} ____cacheline_aligned_in_smp;

#define IO_MD_OFF      (PAGE_SIZE - SKB_DATA_ALIGN(sizeof(struct io_md)))
#define SHADOW_OFF     (IO_MD_OFF - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) \
                                       - SKB_DATA_ALIGN(sizeof(union shadow_state)))
struct page_priv_ctx {
	struct ubuf_info	ubuf[PAGES_IN_HUGE];
};

struct maio_page_map {
	struct page *page;
	struct  page_priv_ctx *priv;
};

struct umem_region_mtt {
	struct rb_node node;
	u64 start;	/* userland start region [*/
	u64 end;	/* userland end region   ]*/
	int len;	/* Number of HP */
	int order;	/* Not realy needed as HUGE_ORDER is defined today */
	struct maio_page_map mapped_pages[0];
};

struct misc_data {
	struct list_head	list;
	void *ctx;
};

struct skb_inline_data {
	union {
		u8	data[SMP_CACHE_BYTES];
	};
	struct skb_shared_info shinfo ____cacheline_aligned_in_smp;
};

#endif //__IO_MD_H
