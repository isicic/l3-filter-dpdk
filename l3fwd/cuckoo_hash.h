#include <rte_hash.h>
#include <rte_hash_crc.h>
#include "l3fwd.h"
// #include <rte_cuckoo_hash.h>
typedef struct rte_hash lookup_struct_t;
typedef uint16_t lookup_ret_t;

int lookup_add_entry(const lookup_struct_t *lkp_struct, void *element);
int lookup_add_entry(const lookup_struct_t *lkp_struct, void *element)
{
    return rte_hash_add_key(lkp_struct, element);
}

static __rte_always_inline uint16_t lookup_single(
    const lookup_struct_t *lookup_struct,
    const void *key)
{
    return rte_hash_lookup((const lookup_struct_t *)lookup_struct,
                           key) < 0
               ? BAD_PORT
               : 1;
}

static __rte_always_inline int lookup_bulk(struct lcore_conf *qconf,
                                           const void **key_array,
                                           int lookup_count,
                                           lookup_ret_t *lookup_ret)
{
    int32_t positions[EM_HASH_LOOKUP_COUNT]; // hardkodirano, naci nacin da ne bude
    // char ime[32];
    // memcpy(ime, qconf->ipv4_lookup_struct, 32);
    int ret = rte_hash_lookup_bulk(qconf->ipv4_lookup_struct, key_array,
                                   lookup_count, positions);
    // RTE_LOG(INFO, L3FWD, "IME CH: %s!\n", ime);
    // RTE_LOG(INFO, L3FWD, "KLJUC_UNUTRA: %d! %d!\n", htonl(((int *)(*key_array))[0]), htonl(((int *)(*key_array))[1]));
    // RTE_LOG(INFO, L3FWD, "hash ret: %d\n", ret);
    for (int i = 0; i < lookup_count; i++)
    {
        // RTE_LOG(INFO, L3FWD, "REZ_BULK %d: %d\n", i, positions[i]);
        lookup_ret[i] = positions[i] < 0 ? BAD_PORT : 1;
    }
    return ret;
}

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
              uint32_t init_val)
{
    const ipv4_key_host *k;
    // uint32_t t;
    // const uint32_t *p;

    k = data;
    // t = k->proto;
    // p = (const uint32_t *)&k->port_src;

    // init_val = rte_hash_crc_4byte(t, init_val);
#if KEY_SIZE == 2
    init_val = rte_hash_crc_2byte(k->port_dst, init_val);
#elif KEY_SIZE == 4
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
#elif KEY_SIZE == 6
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_2byte(k->port_dst, init_val);
#elif KEY_SIZE == 8
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
#elif KEY_SIZE == 12
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_2byte(k->port_src, init_val);
    init_val = rte_hash_crc_2byte(k->port_dst, init_val);
#endif
    return init_val;
}
void create_lookup_struct(lookup_struct_t **lookup_struct,
                          int key_len, int num_entries);
void create_lookup_struct(lookup_struct_t **lookup_struct,
                          int key_len, int num_entries)
{
    struct rte_hash_parameters ipv4_l3fwd_hash_params = {
        .name = "cuckoo_hash",
        .entries = num_entries,
        .key_len = key_len,
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = 0};

    *lookup_struct = rte_hash_create(&ipv4_l3fwd_hash_params);
    // RTE_LOG(INFO, L3FWD, "%s\n", ((struct rte_hash *)(*lookup_struct))->name);
    if (*lookup_struct == NULL)
        rte_exit(EXIT_FAILURE,
                 "Unable to create the l3fwd hash\n");
}