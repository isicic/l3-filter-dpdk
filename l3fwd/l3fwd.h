/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __L3_FWD_H__
#define __L3_FWD_H__

#include <rte_vect.h>

// #define DO_RFC_1812_CHECKS
#define UNUSED(x) (void)(x)

#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1

#if !defined(NO_HASH_MULTI_LOOKUP) && defined(RTE_MACHINE_CPUFLAG_NEON)
#define NO_HASH_MULTI_LOOKUP 1
#endif

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MAX_RX_QUEUE_PER_LCORE 16

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST (MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

/* Used to mark destination port as 'invalid'. */
#define BAD_PORT ((uint16_t)-1)

#define FWDSTEP 4

/* replace first 12B of the ethernet header. */
#define MASK_ETH 0x3f

/* Hash parameters. */
#ifdef RTE_ARCH_64
/* default to 8 million hash entries max (approx) */
#define L3FWD_HASH_ENTRIES (1024 * 1024 * 1024 - 1 + 1024 * 1024 * 1024)
#else
/* 32-bit has less address-space for hugepage memory, limit to 1M entries */
#define L3FWD_HASH_ENTRIES (1024 * 1024 * 1)
#endif
#define HASH_ENTRY_NUMBER_DEFAULT 4

#define NB_CYCLE_READINGS 1024 * 512

#ifndef KEY_SIZE
#define KEY_SIZE 8
#endif

#ifndef EM_HASH_LOOKUP_COUNT
#define EM_HASH_LOOKUP_COUNT 8
#endif

#ifndef COUNT_BULK
#define COUNT_BULK 0
#endif

#ifndef COUNT_CYCLES
#define COUNT_CYCLES 0
#endif
struct mbuf_table
{
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue
{
	uint16_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf
{
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	void *ipv4_lookup_struct;
	void *ipv6_lookup_struct;
	struct rte_ring *ring;
#if COUNT_CYCLES == 1
	uint16_t cycle_count_single[NB_CYCLE_READINGS];
	uint16_t cycle_count_bulk[NB_CYCLE_READINGS];
	int count_index_single;
	int count_index_bulk;
#endif
#if COUNT_BULK == 1
	uint32_t bulk_match_count;
	int bulk_pkt_count;
#endif
} __rte_cache_aligned;

typedef union {
#if KEY_SIZE == 2
	struct
	{
		uint16_t port_dst;
	};
	uint16_t key;

#elif KEY_SIZE == 4
	struct
	{
		uint32_t ip_dst;
	};
	uint32_t key;

#elif KEY_SIZE == 6
	struct
	{
		uint32_t ip_dst;
		uint16_t port_dst;
	} __attribute__((__packed__, aligned(1)));

#elif KEY_SIZE == 8
	struct
	{
		uint32_t ip_src;
		uint32_t ip_dst;
	};
	uint64_t key;

#elif KEY_SIZE == 12
	struct
	{
		union {
			struct
			{
				uint32_t ip_src;
				uint32_t ip_dst;
			};
			uint64_t ips;
		};
		union {
			struct
			{
				uint16_t port_src;
				uint16_t port_dst;
			};
			uint32_t ports;
		};
	} __attribute__((__packed__, aligned(1)));
#endif
} __attribute__((__packed__)) ipv4_key_host;

extern volatile bool force_quit;

/* ethernet addresses of ports */
extern uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
extern struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
extern uint32_t enabled_port_mask;

/* Used only in exact match mode. */
extern int ipv6; /**< ipv6 is false by default. */
extern uint32_t hash_entry_number;

extern xmm_t val_eth[RTE_MAX_ETHPORTS];

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf *qconf, uint16_t n, uint16_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n))
	{
		do
		{
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(struct lcore_conf *qconf,
				   struct rte_mbuf *m, uint16_t port)
{
	uint16_t len;

	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST))
	{
		send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->tx_mbufs[port].len = len;
	return 0;
}

#ifdef DO_RFC_1812_CHECKS
static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct ipv4_hdr))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
		return -5;

	return 0;
}
#endif /* DO_RFC_1812_CHECKS */

void setup_hash(const int socketid);

int em_check_ptype(int portid);

uint16_t
em_cb_parse_ptype(uint16_t port, uint16_t queue, struct rte_mbuf *pkts[],
				  uint16_t nb_pkts, uint16_t max_pkts, void *user_param);
int em_main_loop(__attribute__((unused)) void *dummy);

/* Return ipv4/ipv6 fwd lookup struct  */
void *
em_get_ipv4_l3fwd_lookup_struct(const int socketid);

void *
em_get_ipv6_l3fwd_lookup_struct(const int socketid);

struct ipv4_5tuple
{
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t proto;
} __attribute__((__packed__));

union ipv4_5tuple_host {
	struct
	{
		uint8_t pad0;
		uint8_t proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

#endif /* __L3_FWD_H__ */
