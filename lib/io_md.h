#ifndef  __IO_MD__H
#define  __IO_MD__H

#include <linux/skbuff.h>

/* Current mem layout
	4K [64|128 |640   |512      |2KB  |256B 	    |320B       |128B		   ]
	   [ dpdk  |vc_pkt| headroom| data| hole <shadow md>| skb_shinfo| io_md + ubuf_info]
*/
/********* Caution: Should be same as user counterpart ************************/

/******** MAIO PAGE STATE FLAGS ****************/
#define MAIO_PAGE_REFILL	0x4000
#define MAIO_PAGE_HEAD 		0x2000
#define MAIO_PAGE_FREE		0x1000
#define MAIO_PAGE_IO   		(MAIO_PAGE_TX|MAIO_PAGE_RX|MAIO_PAGE_NAPI)   // TX|RX|NAPI
#define MAIO_PAGE_NAPI		0x800   // storred in the magz
#define MAIO_PAGE_TX   		0x400   // sent by user
#define MAIO_PAGE_RX   		0x200   // alloced from magz - usualy RX
#define MAIO_PAGE_USER 		0x100   // page in user space control
/*************************************************/

struct memory_stats {
	u64	page_user;
	u64	page_rx;
	u64	page_tx;
	u64	page_napi;
	u64	page_free;
	u64	page_refill;
	u64	page_head;
	u64	nr_page_initial;
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
	//struct ubuf_info uarg ;
} ____cacheline_aligned_in_smp;

#define IO_MD_OFF      (PAGE_SIZE - SKB_DATA_ALIGN(sizeof(struct io_md)))
#define SHADOW_OFF     (IO_MD_OFF - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) \
                                       - SKB_DATA_ALIGN(sizeof(struct io_md)))


#endif //__IO_MD_H
