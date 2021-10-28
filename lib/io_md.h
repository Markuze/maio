#ifndef  __IO_MD__H
#define  __IO_MD__H

#include <linux/skbuff.h>

/* Current mem layout
	4K [64|128 |640   |512      |2KB  |256B 	    |320B       |128B		   ]
	   [ dpdk  |vc_pkt| headroom| data| hole <shadow md>| skb_shinfo| io_md + ubuf_info]
*/
/********* Caution: Should be same as user counterpart ************************/

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
	struct ubuf_info uarg ____cacheline_aligned_in_smp;
};

#define IO_MD_OFF      (PAGE_SIZE - SKB_DATA_ALIGN(sizeof(struct io_md)))
#define SHADOW_OFF     (IO_MD_OFF - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) \
                                       - SKB_DATA_ALIGN(sizeof(struct io_md)))


#endif //__IO_MD_H
