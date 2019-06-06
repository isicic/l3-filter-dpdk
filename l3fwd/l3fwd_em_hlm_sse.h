/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
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

#ifndef __L3FWD_EM_HLM_SSE_H__
#define __L3FWD_EM_HLM_SSE_H__

#include "l3fwd_sse.h"
#include "l3fwd.h"
static __rte_always_inline void
get_ipv4_5tuple(struct rte_mbuf *m0, __m128i mask0,
				union ipv4_5tuple_host *key)
{
	__m128i tmpdata0 = _mm_loadu_si128(
		rte_pktmbuf_mtod_offset(m0, __m128i *,
								sizeof(struct ether_hdr) +
									offsetof(struct ipv4_hdr, time_to_live)));

	key->xmm = _mm_and_si128(tmpdata0, mask0);
}

static __rte_always_inline void
extract_ipv4_key(struct rte_mbuf *m0, __m128i mask,
				 ipv4_key_host *key)
{
	UNUSED(mask);
// provjeriti jesu li padovi nula
#if KEY_SIZE == 2
	key->port_dst = *rte_pktmbuf_mtod_offset(m0, uint16_t *,
											 sizeof(struct ether_hdr) +
												 offsetof(struct ipv4_hdr, dst_addr) + sizeof(uint32_t) + sizeof(uint16_t));
	// RTE_LOG(INFO, L3FWD, "port_dst: %hu\n", rte_be_to_cpu_16(key->port_dst));
#endif

#if KEY_SIZE == 4
	key->ip_dst = *rte_pktmbuf_mtod_offset(m0, uint32_t *,
										   sizeof(struct ether_hdr) +
											   offsetof(struct ipv4_hdr, dst_addr));

	// RTE_LOG(INFO, L3FWD, "ip_dst: %d\n", rte_be_to_cpu_32(key->ip_dst));
#endif

#if KEY_SIZE == 6
	// key->key = *rte_pktmbuf_mtod_offset(m0, uint64_t *,
	// 			sizeof(struct ether_hdr) +
	// 			offsetof(struct ipv4_hdr, time_to_live)
	// 			+ 6);

	key->ip_dst = *rte_pktmbuf_mtod_offset(m0, uint32_t *,
										   sizeof(struct ether_hdr) +
											   offsetof(struct ipv4_hdr, dst_addr));

	key->port_dst = *rte_pktmbuf_mtod_offset(m0, uint16_t *,
											 sizeof(struct ether_hdr) +
												 offsetof(struct ipv4_hdr, dst_addr) + sizeof(uint32_t) + sizeof(uint16_t));
	// RTE_LOG(INFO, L3FWD, "ip_dst: %d\n", rte_be_to_cpu_32(key->ip_dst));
	// RTE_LOG(INFO, L3FWD, "port_dst: %hu\n", rte_be_to_cpu_16(key->port_dst));
#endif

#if KEY_SIZE == 8
	key->key = *rte_pktmbuf_mtod_offset(m0, uint64_t *,
										sizeof(struct ether_hdr) +
											offsetof(struct ipv4_hdr, src_addr));
	// RTE_LOG(INFO, L3FWD, "ip_dst: %u\n", rte_be_to_cpu_32(key->ip_dst));
	// RTE_LOG(INFO, L3FWD, "ip_src: %u\n", rte_be_to_cpu_32(key->ip_src));
#endif

#if KEY_SIZE == 12
	// __m128i tmpdata0 = _mm_loadu_si128(
	// 		rte_pktmbuf_mtod_offset(m0, __m128i *,
	// 			sizeof(struct ether_hdr) +
	// 			offsetof(struct ipv4_hdr, time_to_live)));

	// key->ports = _mm_cvtsi128_si32(tmpdata0); // maska = {NOBITS, NOBITS, NOBITS, ALL}

	// key->ips =_mm_cvtsi128_si64(_mm_srli_si128(tmpdata0, 4));

	key->ips = *rte_pktmbuf_mtod_offset(m0, uint64_t *,
										sizeof(struct ether_hdr) +
											offsetof(struct ipv4_hdr, src_addr));

	key->ports = *rte_pktmbuf_mtod_offset(m0, uint32_t *,
										  sizeof(struct ether_hdr) +
											  offsetof(struct ipv4_hdr, dst_addr) + sizeof(uint32_t));

	// RTE_LOG(INFO, L3FWD, "ip_dst: %d\n", rte_be_to_cpu_32(key->ip_dst));
	// RTE_LOG(INFO, L3FWD, "ip_src: %d\n", rte_be_to_cpu_32(key->ip_src));
	// RTE_LOG(INFO, L3FWD, "port_dst: %hu\n", rte_be_to_cpu_16(key->port_dst));
	// RTE_LOG(INFO, L3FWD, "port_src: %hu\n", rte_be_to_cpu_16(key->port_src));
#endif
}

static inline void
get_ipv6_5tuple(struct rte_mbuf *m0, __m128i mask0,
				__m128i mask1, union ipv6_5tuple_host *key)
{
	__m128i tmpdata0 = _mm_loadu_si128(
		rte_pktmbuf_mtod_offset(m0, __m128i *,
								sizeof(struct ether_hdr) +
									offsetof(struct ipv6_hdr, payload_len)));

	__m128i tmpdata1 = _mm_loadu_si128(
		rte_pktmbuf_mtod_offset(m0, __m128i *,
								sizeof(struct ether_hdr) +
									offsetof(struct ipv6_hdr, payload_len) +
									sizeof(__m128i)));

	__m128i tmpdata2 = _mm_loadu_si128(
		rte_pktmbuf_mtod_offset(m0, __m128i *,
								sizeof(struct ether_hdr) +
									offsetof(struct ipv6_hdr, payload_len) +
									sizeof(__m128i) + sizeof(__m128i)));

	key->xmm[0] = _mm_and_si128(tmpdata0, mask0);
	key->xmm[1] = tmpdata1;
	key->xmm[2] = _mm_and_si128(tmpdata2, mask1);
}
#endif /* __L3FWD_EM_SSE_HLM_H__ */
