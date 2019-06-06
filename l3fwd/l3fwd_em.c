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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <rte_ethdev.h>

#include "l3fwd.h"
#include <time.h>
#include <math.h>
#include <unistd.h>
#define XXH_PRIVATE_API

#if defined(RTE_ARCH_X86) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define EM_HASH_CRC 0
#endif

#define IPV6_ADDR_LEN 16

#ifndef EXPECTED_KEYS
#define EXPECTED_KEYS 4000000
#endif

#if LOOKUP_METHOD == 1
#include <rte_hash.h>
#include "cuckoo_hash.h"
#elif LOOKUP_METHOD == 2
#include <rte_member.h>
#include "bloom_filter.h"
#endif

#define XMM_NUM_IN_IPV6_5TUPLE 3

struct ipv6_5tuple
{
	uint8_t ip_dst[IPV6_ADDR_LEN];
	uint8_t ip_src[IPV6_ADDR_LEN];
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t proto;
} __attribute__((__packed__));

union ipv6_5tuple_host {
	struct
	{
		uint16_t pad0;
		uint8_t proto;
		uint8_t pad1;
		uint8_t ip_src[IPV6_ADDR_LEN];
		uint8_t ip_dst[IPV6_ADDR_LEN];
		uint16_t port_src;
		uint16_t port_dst;
		uint64_t reserve;
	};
	xmm_t xmm[XMM_NUM_IN_IPV6_5TUPLE];
};

struct ipv4_l3fwd_em_route
{
	struct ipv4_5tuple key;
	uint8_t if_out;
};

struct ipv6_l3fwd_em_route
{
	struct ipv6_5tuple key;
	uint8_t if_out;
};

// static struct ipv4_l3fwd_em_route ipv4_l3fwd_em_route_array[] = {
// 	{{IPv4(101, 0, 0, 0), IPv4(100, 10, 0, 1), 101, 11, IPPROTO_UDP}, 1},
// 	{{IPv4(201, 0, 0, 0), IPv4(200, 20, 0, 1), 102, 12, IPPROTO_TCP}, 1},
// 	{{IPv4(111, 0, 0, 0), IPv4(100, 30, 0, 1), 101, 11, IPPROTO_TCP}, 1},
// 	{{IPv4(211, 0, 0, 0), IPv4(200, 40, 0, 1), 102, 12, IPPROTO_TCP}, 1},
// };

lookup_struct_t *ipv4_l3fwd_lookup_struct[NB_SOCKETS];
lookup_struct_t *ipv6_l3fwd_lookup_struct[NB_SOCKETS];

// static inline uint32_t
// ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
// 			  uint32_t init_val)
// {
// 	const union ipv4_key_host *k;
// 	uint32_t t;
// 	const uint32_t *p;

// 	k = data;
// 	t = k->proto;
// 	p = (const uint32_t *)&k->port_src;

// #ifdef EM_HASH_CRC
// 	init_val = rte_hash_crc_4byte(t, init_val);
// 	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
// 	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
// 	init_val = rte_hash_crc_4byte(*p, init_val);
// #else
// 	init_val = rte_jhash_1word(t, init_val);
// 	init_val = rte_jhash_1word(k->ip_src, init_val);
// 	init_val = rte_jhash_1word(k->ip_dst, init_val);
// 	init_val = rte_jhash_1word(*p, init_val);
// #endif

// 	return init_val;
// }

// static inline uint32_t
// ipv4_hash_xxh(const void *data, __rte_unused uint32_t data_len,
// 		uint32_t init_val)
// {
// 	// const union ipv4_5tuple_host *k;
// 	// uint32_t t;
// 	// const uint32_t *p;

// 	// k = data;
// 	// t = k->proto;
// 	// p = (const uint32_t *)&k->port_src;

// 	return  XXH64(data, sizeof(union ipv4_5tuple_host), init_val);
// }

static inline uint32_t
ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len,
			  uint32_t init_val)
{
	const union ipv6_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;
#ifdef EM_HASH_CRC
	const uint32_t *ip_src0, *ip_src1, *ip_src2, *ip_src3;
	const uint32_t *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef EM_HASH_CRC
	ip_src0 = (const uint32_t *)k->ip_src;
	ip_src1 = (const uint32_t *)(k->ip_src + 4);
	ip_src2 = (const uint32_t *)(k->ip_src + 8);
	ip_src3 = (const uint32_t *)(k->ip_src + 12);
	ip_dst0 = (const uint32_t *)k->ip_dst;
	ip_dst1 = (const uint32_t *)(k->ip_dst + 4);
	ip_dst2 = (const uint32_t *)(k->ip_dst + 8);
	ip_dst3 = (const uint32_t *)(k->ip_dst + 12);
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(*ip_src0, init_val);
	init_val = rte_hash_crc_4byte(*ip_src1, init_val);
	init_val = rte_hash_crc_4byte(*ip_src2, init_val);
	init_val = rte_hash_crc_4byte(*ip_src3, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash(k->ip_src,
						 sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
	init_val = rte_jhash(k->ip_dst,
						 sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif
	return init_val;
}

#define IPV4_L3FWD_EM_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_em_route_array) / sizeof(ipv4_l3fwd_em_route_array[0]))

#define IPV6_L3FWD_EM_NUM_ROUTES \
	(sizeof(ipv6_l3fwd_em_route_array) / sizeof(ipv6_l3fwd_em_route_array[0]))

//static uint8_t ipv4_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;
//static uint8_t ipv6_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;

static rte_xmm_t mask0;
// static rte_xmm_t mask1;
// static rte_xmm_t mask2;

#if defined(RTE_MACHINE_CPUFLAG_SSE2)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	__m128i data = _mm_loadu_si128((__m128i *)(key));

	return _mm_and_si128(data, mask);
}
#else
#error No vector engine (SSE) available, check your toolchain
#endif

// static inline uint16_t
// em_get_ipv4_dst_port(struct rte_mbuf *pkt, void *lookup_struct)
// {
// 	ipv4_key_host key;
// 	member_set_t set_id;

// 	/*
// 	 * Get 5 tuple: dst port, src port, dst IP address,
// 	 * src IP address and protocol.
// 	 */
// 	//key.xmm = em_mask_key(ipv4_hdr, mask0.x);
// 	// testAdresaS[ntohl(key.ip_src)]++;

// 	/* Find destination port */
// 	return rte_member_lookup((const struct rte_member_setsum *)lookup_struct,
// 							 (const void *)&key, &set_id) <= 0
// 			   ? BAD_PORT
// 			   : 1;
// }

// static inline uint16_t
// em_get_ipv6_dst_port(void *ipv6_hdr, void *lookup_struct)
// {
// 	union ipv6_5tuple_host key;
// 	struct rte_hash *ipv6_l3fwd_lookup_struct =
// 		(struct rte_hash *)lookup_struct;

// 	ipv6_hdr = (uint8_t *)ipv6_hdr + offsetof(struct ipv6_hdr, payload_len);
// 	void *data0 = ipv6_hdr;
// 	void *data1 = ((uint8_t *)ipv6_hdr) + sizeof(xmm_t);
// 	void *data2 = ((uint8_t *)ipv6_hdr) + sizeof(xmm_t) + sizeof(xmm_t);

// 	/* Get part of 5 tuple: src IP address lower 96 bits and protocol */
// 	key.xmm[0] = em_mask_key(data0, mask1.x);

// 	/*
// 	 * Get part of 5 tuple: dst IP address lower 96 bits
// 	 * and src IP address higher 32 bits.
// 	 */
// 	key.xmm[1] = *(xmm_t *)data1;

// 	/*
// 	 * Get part of 5 tuple: dst port and src port
// 	 * and dst IP address higher 32 bits.
// 	 */
// 	key.xmm[2] = em_mask_key(data2, mask2.x);

// 	return -1;
// 	return rte_hash_lookup(ipv6_l3fwd_lookup_struct, (const void *)&key) < 0 ? BAD_PORT : 1;
// }

#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON
#include "l3fwd_em_hlm.h"
#else
#include "l3fwd_em.h"
#endif

// static void
// convert_ipv4_5tuple(struct ipv4_5tuple *key1,
// 					union ipv4_5tuple_host *key2)
// {
// 	key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
// 	key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
// 	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
// 	key2->port_src = rte_cpu_to_be_16(key1->port_src);
// 	key2->proto = key1->proto;
// 	key2->pad0 = 0;
// 	key2->pad1 = 0;
// }

static void extract_key_from_tuple(struct ipv4_5tuple *tuple, ipv4_key_host *key)
{
#if KEY_SIZE == 2
	key->port_dst = rte_cpu_to_be_16(tuple->port_dst);
#endif

#if KEY_SIZE == 4
	key->ip_dst = rte_cpu_to_be_32(tuple->ip_dst);
#endif

#if KEY_SIZE == 6
	key->port_dst = rte_cpu_to_be_16(tuple->port_dst);
	key->ip_dst = rte_cpu_to_be_32(tuple->ip_dst);
#endif

#if KEY_SIZE == 8
	key->ip_dst = rte_cpu_to_be_32(tuple->ip_dst);
	key->ip_src = rte_cpu_to_be_32(tuple->ip_src);
#endif

#if KEY_SIZE == 12
	key->ip_dst = rte_cpu_to_be_32(tuple->ip_dst);
	key->ip_src = rte_cpu_to_be_32(tuple->ip_src);
	key->port_dst = rte_cpu_to_be_16(tuple->port_dst);
	key->port_src = rte_cpu_to_be_16(tuple->port_src);
#endif
}

// static void
// convert_ipv6_5tuple(struct ipv6_5tuple *key1,
// 					union ipv6_5tuple_host *key2)
// {
// 	uint32_t i;

// 	for (i = 0; i < 16; i++)
// 	{
// 		key2->ip_dst[i] = key1->ip_dst[i];
// 		key2->ip_src[i] = key1->ip_src[i];
// 	}
// 	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
// 	key2->port_src = rte_cpu_to_be_16(key1->port_src);
// 	key2->proto = key1->proto;
// 	key2->pad0 = 0;
// 	key2->pad1 = 0;
// 	key2->reserve = 0;
// }

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
#define BIT_16_TO_23 0x00ff0000

#define NUMBER_PORT_USED 4

static inline void
populate_ipv4_many_flow_into_table(lookup_struct_t *h,
								   unsigned int nr_flow)
{
	mask0 = (rte_xmm_t){.u32 = {BIT_8_TO_15, ALL_32_BITS,
								ALL_32_BITS, ALL_32_BITS}};
	RTE_LOG(INFO, L3FWD, "Key size: %lu\n", sizeof(ipv4_key_host));
	// RTE_LOG(INFO, L3FWD, "BFNAME: %s\n", h->name);
	static const char filename[] = "./keys.txt";
	FILE *file = fopen(filename, "r");
	if (file == NULL)
	{
		rte_exit(EXIT_FAILURE, "Unable to open input keys file.\n");
	}
	char line[128];
	char delim[] = " ";
	unsigned i;
	for (i = 0; i < nr_flow; i++)
	{
		struct ipv4_l3fwd_em_route entry;
		ipv4_key_host newkey;

		// /* Create the ipv4 exact match flow */
		memset(&entry, 0, sizeof(entry));
		entry.if_out = 1;
		if (fgets(line, sizeof line, file) != NULL)
		{
			entry.key.ip_src = (uint32_t)strtoul(strtok(line, delim), NULL, 10);
			entry.key.port_src = 0; //(uint16_t)strtoul(strtok(NULL, delim), NULL, 10);
			entry.key.ip_dst = (uint32_t)strtoul(strtok(NULL, delim), NULL, 10);
			entry.key.port_dst = 0; // (uint16_t)strtoul(strtok(NULL, delim), NULL, 10);
		}
		// if (i < 1000000)
		// {
		// 	entry.key.ip_dst = i * 100;
		// 	entry.key.ip_src = i * 100;
		// 	entry.key.port_dst = (uint16_t)0;
		// 	entry.key.port_src = (uint16_t)0;
		// }
		// else
		// {
		// 	entry.key.ip_dst = i + 99000001;
		// 	entry.key.ip_src = i + 99000001;
		// 	entry.key.port_dst = (uint16_t)0;
		// 	entry.key.port_src = (uint16_t)0;
		// }
		// RTE_LOG(INFO, L3FWD, "ENTRY: %u %hu %u %hu, %hhu, %hhu \n",
		// 		entry.key.ip_src,
		// 		entry.key.port_src,
		// 		entry.key.ip_dst,
		// 		entry.key.port_dst,
		// 		entry.key.proto,
		// 		entry.if_out);
		// RTE_LOG(INFO, L3FWD, "TOCKA1\n");
		// convert_ipv4_5tuple(&entry.key, &newkey);
		extract_key_from_tuple(&entry.key, &newkey);
		// RTE_LOG(INFO, L3FWD, "KEY: %u, %u, %lu \n\n",
		// 		rte_be_to_cpu_32(newkey.ip_src),
		// 		rte_be_to_cpu_32(newkey.ip_dst),
		// 		newkey.key);
		// RTE_LOG(INFO, L3FWD, "TOCKA2\n");
		int32_t ret = lookup_add_entry(h, (void *)&newkey);
		// RTE_LOG(INFO, L3FWD, "TOCKA3\n");

		if (ret < 0)
		{
			fclose(file);
			rte_exit(EXIT_FAILURE, "Unable to add entry %u. ERRCODE: %d\n", i, ret);
		}
		// ipv4_l3fwd_out_if[ret] = (uint8_t) entry.if_out;
	}
	fclose(file);
#if LOOKUP_METHOD == 1
	printf("Hash bucket size: %ld\n", get_bucket_size(h));
	printf("Hash number of buckets: %ld\n", get_num_bucket(h));
	printf("Hash number of entries: %ld\n", get_num_entries(h));
	printf("Hash key entry size: %ld\n", get_key_entry_size(h));
#endif
	printf("Hash: Adding 0x%x keys\n", nr_flow);
}

// static inline void
// populate_ipv6_many_flow_into_table(const struct rte_hash *h,
// 								   unsigned int nr_flow)
// {
// 	unsigned i;

// 	mask1 = (rte_xmm_t){.u32 = {BIT_16_TO_23, ALL_32_BITS,
// 								ALL_32_BITS, ALL_32_BITS}};
// 	mask2 = (rte_xmm_t){.u32 = {ALL_32_BITS, ALL_32_BITS, 0, 0}};

// 	for (i = 0; i < nr_flow; i++)
// 	{
// 		struct ipv6_l3fwd_em_route entry;
// 		union ipv6_5tuple_host newkey;

// 		uint8_t a = (uint8_t)((i / NUMBER_PORT_USED) % BYTE_VALUE_MAX);
// 		uint8_t b = (uint8_t)(((i / NUMBER_PORT_USED) / BYTE_VALUE_MAX) % BYTE_VALUE_MAX);
// 		uint8_t c = (uint8_t)((i / NUMBER_PORT_USED) / (BYTE_VALUE_MAX * BYTE_VALUE_MAX));

// 		/* Create the ipv6 exact match flow */
// 		memset(&entry, 0, sizeof(entry));
// 		switch (i & (NUMBER_PORT_USED - 1))
// 		{
// 		case 0:
// 			entry = ipv6_l3fwd_em_route_array[0];
// 			break;
// 		case 1:
// 			entry = ipv6_l3fwd_em_route_array[1];
// 			break;
// 		case 2:
// 			entry = ipv6_l3fwd_em_route_array[2];
// 			break;
// 		case 3:
// 			entry = ipv6_l3fwd_em_route_array[3];
// 			break;
// 		};
// 		entry.key.ip_dst[13] = c;
// 		entry.key.ip_dst[14] = b;
// 		entry.key.ip_dst[15] = a;
// 		convert_ipv6_5tuple(&entry.key, &newkey);
// 		int32_t ret = rte_hash_add_key(h, (void *)&newkey);

// 		if (ret < 0)
// 			rte_exit(EXIT_FAILURE, "Unable to add entry %u\n", i);

// 		ipv6_l3fwd_out_if[ret] = (uint8_t)entry.if_out;
// 	}
// 	printf("Hash: Adding 0x%x keys\n", nr_flow);
// }

/* Requirements:
 * 1. IP packets without extension;
 * 2. L4 payload should be either TCP or UDP.
 */
int em_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4_ext = 0;
	int ptype_l3_ipv6_ext = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i)
	{
		switch (ptypes[i])
		{
		case RTE_PTYPE_L3_IPV4_EXT:
			ptype_l3_ipv4_ext = 1;
			break;
		case RTE_PTYPE_L3_IPV6_EXT:
			ptype_l3_ipv6_ext = 1;
			break;
		case RTE_PTYPE_L4_TCP:
			ptype_l4_tcp = 1;
			break;
		case RTE_PTYPE_L4_UDP:
			ptype_l4_udp = 1;
			break;
		}
	}

	if (ptype_l3_ipv4_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4_EXT\n", portid);
	if (ptype_l3_ipv6_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6_EXT\n", portid);
	if (!ptype_l3_ipv4_ext || !ptype_l3_ipv6_ext)
		return 0;

	if (ptype_l4_tcp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_TCP\n", portid);
	if (ptype_l4_udp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_UDP\n", portid);
	if (ptype_l4_tcp && ptype_l4_udp)
		return 1;

	return 0;
}

static inline void
em_parse_ptype(struct rte_mbuf *m)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;
	void *l3;
	int hdr_len;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = eth_hdr->ether_type;
	l3 = (uint8_t *)eth_hdr + sizeof(struct ether_hdr);
	if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))
	{
		ipv4_hdr = (struct ipv4_hdr *)l3;
		hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				  IPV4_IHL_MULTIPLIER;
		if (hdr_len == sizeof(struct ipv4_hdr))
		{
			packet_type |= RTE_PTYPE_L3_IPV4;
			if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
				packet_type |= RTE_PTYPE_L4_TCP;
			else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				packet_type |= RTE_PTYPE_L4_UDP;
		}
		else
			packet_type |= RTE_PTYPE_L3_IPV4_EXT;
	}
	else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))
	{
		ipv6_hdr = (struct ipv6_hdr *)l3;
		if (ipv6_hdr->proto == IPPROTO_TCP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		else if (ipv6_hdr->proto == IPPROTO_UDP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		else
			packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	}

	m->packet_type = packet_type;
}

uint16_t
em_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
				  struct rte_mbuf *pkts[], uint16_t nb_pkts,
				  uint16_t max_pkts __rte_unused,
				  void *user_param __rte_unused)
{
	unsigned i;

	for (i = 0; i < nb_pkts; ++i)
		em_parse_ptype(pkts[i]);

	return nb_pkts;
}

/*
 * TX burst queue drain loop
 */
// static inline void
// tx_burst_queue_drain_loop(struct lcore_conf *qconf)
// {
// 	uint16_t portid;
// 	uint64_t prev_tsc = 0, diff_tsc, cur_tsc;
// 	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
// 			US_PER_S * BURST_TX_DRAIN_US;
// 	int i;
// 	int packets_sent = 0;
// 	while (!force_quit) {
// 		cur_tsc = rte_rdtsc();
// 		diff_tsc = cur_tsc - prev_tsc;
// 		if (unlikely(diff_tsc > drain_tsc)) {

// 			for (i = 0; i < qconf->n_tx_port; ++i) {
// 				portid = qconf->tx_port_id[i];
// 				if (qconf->tx_mbufs[portid].len == 0)
// 					continue;
// 				send_burst(qconf,
// 					qconf->tx_mbufs[portid].len,
// 					portid);
// 				packets_sent += qconf->tx_mbufs[portid].len;
// 				qconf->tx_mbufs[portid].len = 0;
// 			}

// 			prev_tsc = cur_tsc;
// 		}
// 	}
// 	printf("Sent %d packets", packets_sent);
// }

static int send_confirmations(void)
{
	FILE *fp = fopen("/tmp/l3fwd/confirm.txt", "a");
	fprintf(fp, "Started\n");
	fclose(fp);
	return 0;
}

static int print_packet_stats(uint64_t received, uint64_t dropped)
{
	FILE *fp = fopen("/tmp/l3fwd/results.txt", "a");
	fprintf(fp, "%" PRId64 " %" PRId64 "\n", received, dropped);
	fclose(fp);
	return 0;
}

#if COUNT_CYCLES == 1
static double avg_array(uint16_t *cycle_count, int n)
{

	int stride = 2;

	double res[NB_CYCLE_READINGS];

	for (int i = 0; i < n; i++)
	{
		res[i] = (double)cycle_count[i];
	}

	for (int k = 0; k < log(n) / log(2); k++)
	{

		for (int i = 0; i < n; i += stride)
		{
			res[i] = (res[i] + res[i + (int)pow(2, k)]) / 2.0;
		}
		stride *= 2;
	}
	return res[0];
}

static uint16_t max_array(uint16_t *cycle_count, int n)
{
	uint16_t max = 0;
	for (int i = 0; i < n; i++)
	{
		if (max < cycle_count[i])
		{
			max = cycle_count[i];
		}
	}
	return max;
}

static int print_cycles_single(uint16_t *cycle_count, int n)
{
	FILE *fp = fopen("/tmp/l3fwd/single_cycles.txt", "a");

	fprintf(fp, "%d\n ", n);

	fprintf(fp, "%f\n", avg_array(cycle_count, n));
	fprintf(fp, "%hu\n", max_array(cycle_count, n));
	fclose(fp);
	return 0;
}

static int print_cycles_bulk2(uint16_t *cycle_count, int n)
{
	FILE *fp = fopen("/tmp/l3fwd/bulk_cycles.txt", "a");
	fprintf(fp, "%d\n", n);
	fprintf(fp, "%f\n", avg_array(cycle_count, n));
	fprintf(fp, "%hu\n", max_array(cycle_count, n));
	fclose(fp);
	return 0;
}
#endif

#if LOOKUP_METHOD == 2
static int print_bf_num_hashes(uint32_t num_hashes)
{
	FILE *fp = fopen("/tmp/l3fwd/bf_info.txt", "a");
	fprintf(fp, "%d\n ", num_hashes);
	fclose(fp);
	return 0;
}

static int print_bf_table_size(uint32_t bits)
{
	FILE *fp = fopen("/tmp/l3fwd/bf_info.txt", "a");
	fprintf(fp, "%d\n ", bits);
	fclose(fp);
	return 0;
}
#endif

/*
 * Read packets from RX queues
 */
static inline void
rx_burst_queue_read_loop(struct lcore_conf *qconf)
{
	struct rte_ring *ring;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	int nb_rx;
	uint8_t queueid;
	uint16_t portid;

	ring = qconf->ring;
	RTE_LOG(INFO, L3FWD, "rx: ring size: %d\n", rte_ring_get_size(ring));
	send_confirmations();
	while (!force_quit)
	{
		portid = qconf->rx_queue_list[0].port_id;
		queueid = qconf->rx_queue_list[0].queue_id;
		nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
								 MAX_PKT_BURST);
		if (nb_rx == 0)
			continue;

		rte_ring_sp_enqueue_burst(ring, (void *const *)pkts_burst, nb_rx, NULL);
	}

	struct rte_eth_stats stats;
	rte_eth_stats_get(qconf->rx_queue_list[0].port_id, &stats);
	printf("Received %" PRId64 " packets\n", stats.ipackets);
	printf("Dropped %" PRId64 " packets\n", stats.imissed);
	print_packet_stats(stats.ipackets, stats.imissed);
}

/* Filter loop */
static inline void
filter_loop(struct lcore_conf *qconf)
{
	struct rte_ring *ring;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	int nb_rx;
	ring = qconf->ring;
	RTE_LOG(INFO, L3FWD, "filter: ring size: %d\n", rte_ring_get_size(ring));

	while (!force_quit)
	{
		nb_rx = rte_ring_sc_dequeue_burst(ring, (void **)pkts_burst, MAX_PKT_BURST, NULL);
		l3fwd_em_send_packets(nb_rx, pkts_burst, qconf);
	}
#if COUNT_CYCLES == 1
	print_cycles_single(qconf->cycle_count_single, qconf->count_index_single);
	print_cycles_bulk2(qconf->cycle_count_bulk, qconf->count_index_bulk);
#endif
#if COUNT_BULK == 1
	RTE_LOG(INFO, L3FWD, "bulk pkt count: %d\n", qconf->bulk_pkt_count);
	RTE_LOG(INFO, L3FWD, "bulk match count %u \n", qconf->bulk_match_count);
#endif
#if LOOKUP_METHOD == 2
	print_bf_num_hashes(((struct rte_member_setsum *)qconf->ipv4_lookup_struct)->num_hashes);
	print_bf_table_size(((struct rte_member_setsum *)qconf->ipv4_lookup_struct)->bits);
#endif
}

// static inline void
// single_core_main_loop(struct lcore_conf *qconf)
// {
// 	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
// 	int nb_rx, packets_received = 0;
// 	uint8_t queueid;
// 	uint16_t portid;
// 	send_confirmations();
// 	while (!force_quit)
// 	{
// 		portid = qconf->rx_queue_list[0].port_id;
// 		queueid = qconf->rx_queue_list[0].queue_id;
// 		nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
// 								 MAX_PKT_BURST);
// 		if (nb_rx == 0)
// 			continue;
// 		packets_received += nb_rx;
// 		l3fwd_em_send_packets(nb_rx, pkts_burst, qconf);
// 	}
// 	printf("Received %d packets\n", packets_received);
// }

/* main processing loop */
int em_main_loop(__attribute__((unused)) void *dummy)
{
	unsigned lcore_id;
	struct lcore_conf *qconf;
	uint8_t queueid;
	uint16_t portid;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
#if COUNT_CYCLES == 1
	qconf->count_index_single = 0;
	qconf->count_index_bulk = 0;
#endif
#if COUNT_BULK
	qconf->bulk_pkt_count = 0;
	qconf->bulk_match_count = 0;
#endif
	RTE_LOG(INFO, L3FWD, "LOOKUP JE: %d\n", LOOKUP_METHOD);
	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (int i = 0; i < qconf->n_rx_queue; i++)
	{
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
				" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
				lcore_id, portid, queueid);
	}

	if (lcore_id == 2)
		rx_burst_queue_read_loop(qconf);
	else
		filter_loop(qconf);

	return 0;
}

/*
 * Initialize exact match (hash) parameters.
 */
void setup_hash(const int socketid)
{
	/* create ipv4 lookup */
	// GENERALNA FUNKCIJA
	create_lookup_struct(&ipv4_l3fwd_lookup_struct[socketid],
						 sizeof(ipv4_key_host), EXPECTED_KEYS);

	// BLOOM FILTER FUNKCIJA
	// const struct rte_member_parameters setparams = {
	// 	.name = "BFd",
	// 	.type = 1,
	// 	.key_len = sizeof(ipv4_key_host),
	// 	.num_set = 1,
	// 	.num_keys = EXPECTED_KEYS,
	// 	.false_positive_rate = 0.01,
	// 	.prim_hash_seed = 23123124,
	// 	.sec_hash_seed = 11234};

	// ipv4_l3fwd_lookup_struct[socketid] = rte_member_create(&setparams);
	// if (ipv4_l3fwd_lookup_struct[socketid] == NULL)
	// 	rte_exit(EXIT_FAILURE,
	// 			 "Unable to create the l3fwd hash\n");

	// RTE_LOG(INFO, L3FWD, "add-setsumname: %s\n", ((struct rte_member_setsum *)ipv4_l3fwd_lookup_struct[socketid])->name);
	/* populate the ipv4 lookup */

	// CUCKOO HASH FUNKCIJA

	// struct rte_hash_parameters ipv4_l3fwd_hash_params = {
	// 	.name = "cuckoo_hash",
	// 	.entries = EXPECTED_KEYS,
	// 	.key_len = sizeof(ipv4_key_host),
	// 	.hash_func = ipv4_hash_crc,
	// 	.hash_func_init_val = 0,
	// 	.socket_id = 0};

	// ipv4_l3fwd_lookup_struct[socketid] = rte_hash_create(&ipv4_l3fwd_hash_params);
	// // RTE_LOG(INFO, L3FWD, "%s\n", ((struct rte_hash *)(*lookup_struct))->name);
	// if (ipv4_l3fwd_lookup_struct[socketid] == NULL)
	// 	rte_exit(EXIT_FAILURE,
	// 			 "Unable to create the l3fwd hash\n");

	populate_ipv4_many_flow_into_table(
		ipv4_l3fwd_lookup_struct[socketid],
		hash_entry_number);
	// ipv4_key_host *key;
	// rte_hash_get_key_with_position(ipv4_l3fwd_lookup_struct[socketid], 0, (void **)&key);
	// RTE_LOG(INFO, L3FWD, "KEY: %d! %d\n", htonl(key->ip_dst), htonl(key->ip_src));
	// rte_hash_get_key_with_position(ipv4_l3fwd_lookup_struct[socketid], 1, (void **)&key);
	// RTE_LOG(INFO, L3FWD, "KEY: %d! %d\n", htonl(key->ip_dst), htonl(key->ip_src));
	// RTE_LOG(INFO, L3FWD, "KEYYYYY: %lu!\n", key->key);
	// RTE_LOG(INFO, L3FWD, "sizeof(ipv4_key_host): %lu\n", sizeof(ipv4_key_host));
}

/* Return ipv4/ipv6 em fwd lookup struct. */
void *
em_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_lookup_struct[socketid];
}

void *
em_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
	return ipv6_l3fwd_lookup_struct[socketid];
}
