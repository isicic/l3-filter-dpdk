/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   Copyright(c) 2017, Linaro Limited
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

#ifndef __L3FWD_EM_HLM_H__
#define __L3FWD_EM_HLM_H__

#if defined RTE_ARCH_X86
#include "l3fwd_sse.h"
#include "l3fwd_em_hlm_sse.h"
#include "l3fwd.h"
#endif

static __rte_always_inline void
em_get_dst_port_ipv4xN(struct lcore_conf *qconf, struct rte_mbuf *m[],
					   uint16_t dst_port[])
{
	int i;
	ipv4_key_host key[EM_HASH_LOOKUP_COUNT];
	const void *key_array[EM_HASH_LOOKUP_COUNT];

	for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++)
	{
		extract_ipv4_key(m[i], mask0.x, &key[i]);
		key_array[i] = &key[i];
	}
#if COUNT_CYCLES == 1
	int start = rte_get_timer_cycles();
#endif
	// uint16_t lookup_res[EM_HASH_LOOKUP_COUNT];
	// memset(lookup_res, 0, sizeof(lookup_res));

	// RTE_LOG(INFO, L3FWD, "CHNAME: %s\n", ime);
#if COUNT_BULK == 1
	int ret =
#endif
		lookup_bulk(qconf, &key_array[0], EM_HASH_LOOKUP_COUNT, (lookup_ret_t *)dst_port);

	// RTE_LOG(INFO, L3FWD, "KLJUC: %d! %d!\n", htonl(((int *)(*key_array))[0]),
	// 		htonl(((int *)(*key_array))[1]));
	// RTE_LOG(INFO, L3FWD, "BROJ UNOSA: %d: !\n", rte_hash_count(ipv4_l3fwd_lookup_struct[socketid]));
	// for (int i = EM_HASH_LOOKUP_COUNT; i--;)
	// {
	// 	// RTE_LOG(INFO, L3FWD, "REZ_BULK_VANI %d: %d\n", i, lookup_res[i]);
	// 	dst_port[i] = lookup_res[i];
	// }

#if COUNT_CYCLES == 1
	register const int end = rte_get_timer_cycles();
	if (qconf->count_index_bulk < NB_CYCLE_READINGS)
	{
		qconf->cycle_count_bulk[qconf->count_index_bulk] =
			(uint16_t)(end - start);
		qconf->count_index_bulk++;
	}
#endif

#if COUNT_BULK == 1
	qconf->bulk_match_count += ret;
	qconf->bulk_pkt_count += EM_HASH_LOOKUP_COUNT;
#endif
}

// static __rte_always_inline void
// em_get_dst_port_ipv6xN(struct lcore_conf *qconf, struct rte_mbuf *m[],
// 					   uint16_t dst_port[])
// {
// 	int i;
// 	int32_t ret[EM_HASH_LOOKUP_COUNT];
// 	union ipv6_5tuple_host key[EM_HASH_LOOKUP_COUNT];
// 	const void *key_array[EM_HASH_LOOKUP_COUNT];

// 	for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++)
// 	{
// 		get_ipv6_5tuple(m[i], mask1.x, mask2.x, &key[i]);
// 		key_array[i] = &key[i];
// 	}
// 	// ovdje dodati i lookup za ipv6
// 	// rte_hash_lookup_bulk(qconf->ipv6_lookup_struct, &key_array[0],
// 	// 		     EM_HASH_LOOKUP_COUNT, ret);

// 	for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++)
// 	{
// 		dst_port[i] = -1;
// 	}
// }

static __rte_always_inline uint16_t
em_get_dst_port(struct lcore_conf *qconf, struct rte_mbuf *pkt)
{
	uint16_t ret = -1;
	// struct ipv4_hdr *ipv4_hdr;
	//union ipv6_5tuple_host key;
	uint32_t tcp_or_udp;
	uint32_t l3_ptypes;

	ipv4_key_host key;

	tcp_or_udp = pkt->packet_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);
	l3_ptypes = pkt->packet_type & RTE_PTYPE_L3_MASK;

	if (tcp_or_udp && (l3_ptypes == RTE_PTYPE_L3_IPV4))
	{

		/* Handle IPv4 headers.*/
		extract_ipv4_key(pkt, mask0.x, &key);
#if COUNT_CYCLES == 1
		uint64_t start = rte_get_timer_cycles();
#endif
		ret = lookup_single((const lookup_struct_t *)qconf->ipv4_lookup_struct,
							(const void *)&key);
		// RTE_LOG(INFO, L3FWD, "single rez: %d\n", ret);
#if COUNT_CYCLES == 1
		uint64_t end = rte_get_timer_cycles();
		// FILE *fp = fopen("/tmp/l3fwd/results.txt", "a");
		// fprintf(fp, "%d \n", qconf->count_index);
		// fclose(fp);

		if (qconf->count_index_single < NB_CYCLE_READINGS)
		{
			qconf->cycle_count_single[qconf->count_index_single] = (uint16_t)(end - start);
			qconf->count_index_single++;
		}
#endif
	}
	return ret;
}

/*
 * Buffer optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
l3fwd_em_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
					  struct lcore_conf *qconf)
{
	int32_t i, j, pos;
	uint16_t dst_port[MAX_PKT_BURST];

	/*
	 * Send nb_rx - nb_rx % EM_HASH_LOOKUP_COUNT packets
	 * in groups of EM_HASH_LOOKUP_COUNT.
	 */
	int32_t n = RTE_ALIGN_FLOOR(nb_rx, EM_HASH_LOOKUP_COUNT);

	for (j = 0; j < EM_HASH_LOOKUP_COUNT && j < nb_rx; j++)
	{
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j],
									   struct ether_hdr *) +
					  1);
	}

	for (j = 0; j < n; j += EM_HASH_LOOKUP_COUNT)
	{

		uint32_t pkt_type = RTE_PTYPE_L3_MASK |
							RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP;
		uint32_t l3_type, tcp_or_udp;

		for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++)
			pkt_type &= pkts_burst[j + i]->packet_type;

		l3_type = pkt_type & RTE_PTYPE_L3_MASK;
		tcp_or_udp = pkt_type & (RTE_PTYPE_L4_TCP | RTE_PTYPE_L4_UDP);

		for (i = 0, pos = j + EM_HASH_LOOKUP_COUNT;
			 i < EM_HASH_LOOKUP_COUNT && pos < nb_rx; i++, pos++)
		{
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[pos],
										   struct ether_hdr *) +
						  1);
		}

		if (tcp_or_udp && (l3_type == RTE_PTYPE_L3_IPV4))
		{

			em_get_dst_port_ipv4xN(qconf, &pkts_burst[j],
								   &dst_port[j]);
		}
		else if (tcp_or_udp && (l3_type == RTE_PTYPE_L3_IPV6))
		{

			// em_get_dst_port_ipv6xN(qconf, &pkts_burst[j],
			// 					   &dst_port[j]);
		}
		else
		{
			for (i = 0; i < EM_HASH_LOOKUP_COUNT; i++)
				dst_port[j + i] = em_get_dst_port(qconf,
												  pkts_burst[j + i]);
		}
	}

	for (; j < nb_rx; j++)
		dst_port[j] = em_get_dst_port(qconf, pkts_burst[j]);

	send_packets_multi(qconf, pkts_burst, dst_port, nb_rx);
}
#endif /* __L3FWD_EM_HLM_H__ */
