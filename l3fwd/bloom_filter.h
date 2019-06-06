#include <rte_member.h>

typedef struct rte_member_setsum lookup_struct_t;
typedef member_set_t lookup_ret_t;

void create_lookup_struct(lookup_struct_t **lookup_struct,
                          int key_len, int num_entries);

void create_lookup_struct(lookup_struct_t **lookup_struct,
                          int key_len, int num_entries)
{
    const struct rte_member_parameters setparams = {
        .name = "BFd",
        .type = 1,
        .key_len = key_len,
        .num_set = 1,
        .num_keys = num_entries,
        .false_positive_rate = 0.01,
        .prim_hash_seed = 23123124,
        .sec_hash_seed = 11234};

    *lookup_struct = rte_member_create(&setparams);
    if (*lookup_struct == NULL)
        rte_exit(EXIT_FAILURE,
                 "Unable to create the l3fwd hash\n");
    RTE_LOG(INFO, L3FWD, "add-setsumname: %s\n", (*(struct rte_member_setsum **)lookup_struct)->name);
    RTE_LOG(INFO, L3FWD, "BF hash fun num: %d\n", (*(struct rte_member_setsum **)lookup_struct)->num_hashes);
    RTE_LOG(INFO, L3FWD, "BF bits/entry: %d\n", (*(struct rte_member_setsum **)lookup_struct)->bits);
}

int lookup_add_entry(const lookup_struct_t *lkp_struct, void *element);
int lookup_add_entry(const lookup_struct_t *lkp_struct, void *element)
{
    return rte_member_add(lkp_struct, element, 1);
}

static __rte_always_inline uint16_t lookup_single(
    const lookup_struct_t *lookup_struct,
    const void *key)
{
    member_set_t set_id;
    return rte_member_lookup((const struct rte_member_setsum *)lookup_struct,
                             key, &set_id) <= 0
               ? BAD_PORT
               : 1;
}

static __rte_always_inline int lookup_bulk(struct lcore_conf *qconf,
                                           const void **key_array,
                                           uint32_t lookup_count,
                                           lookup_ret_t *lookup_ret)
{
    member_set_t set_ids[8]; // hardkodirano, smisliti nacin da ne bude
    // RTE_LOG(INFO, L3FWD, "setsum: %d, keys: %d, set_ids: %d\n",
    //         qconf->ipv4_lookup_struct != NULL, key_array != NULL, set_ids != NULL);
    // RTE_LOG(INFO, L3FWD, "setsum_name: %s\n", ((struct rte_member_setsum *)qconf->ipv4_lookup_struct)->name);
    int ret = rte_member_lookup_bulk((const lookup_struct_t *)qconf->ipv4_lookup_struct, key_array,
                                     lookup_count, set_ids);

    for (uint16_t i = 0; i < lookup_count; i++)
    {
        // RTE_LOG(INFO, L3FWD, "REZ_BULK %d: %d\n", i, lookup_ret[i]);
        lookup_ret[i] = (set_ids[i] == 0) ? BAD_PORT : 1;
    }
    // RTE_LOG(INFO, L3FWD, "ERR: %d\n", ret);
    return ret;
}
