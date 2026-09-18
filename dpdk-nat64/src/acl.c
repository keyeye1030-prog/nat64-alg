#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <rte_acl.h>
#include <rte_byteorder.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_pause.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "acl.h"

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define NAT64_ACL_CATEGORY_MASK 1U
#define NAT64_ACL_CATEGORIES 1U
#define NAT64_ACL_RECLAIM_WAIT_LOOPS 1000000U

enum {
    NAT64_ACL_V4_PROTO = 0,
    NAT64_ACL_V4_SRC,
    NAT64_ACL_V4_DST,
    NAT64_ACL_V4_SPORT,
    NAT64_ACL_V4_DPORT,
    NAT64_ACL_V4_FIELD_COUNT,
};

enum {
    NAT64_ACL_V6_PROTO = 0,
    NAT64_ACL_V6_SRC0,
    NAT64_ACL_V6_SRC1,
    NAT64_ACL_V6_SRC2,
    NAT64_ACL_V6_SRC3,
    NAT64_ACL_V6_DST0,
    NAT64_ACL_V6_DST1,
    NAT64_ACL_V6_DST2,
    NAT64_ACL_V6_DST3,
    NAT64_ACL_V6_SPORT,
    NAT64_ACL_V6_DPORT,
    NAT64_ACL_V6_FIELD_COUNT,
};

struct nat64_acl_v4_key {
    uint8_t proto;
    uint8_t pad[3];
    rte_be32_t src;
    rte_be32_t dst;
    rte_be16_t sport;
    rte_be16_t dport;
} __attribute__((packed));

struct nat64_acl_v6_key {
    uint8_t proto;
    uint8_t pad[3];
    rte_be32_t src[4];
    rte_be32_t dst[4];
    rte_be16_t sport;
    rte_be16_t dport;
} __attribute__((packed));

RTE_ACL_RULE_DEF(nat64_acl_rule_v4, NAT64_ACL_V4_FIELD_COUNT);
RTE_ACL_RULE_DEF(nat64_acl_rule_v6, NAT64_ACL_V6_FIELD_COUNT);

static const struct rte_acl_field_def acl_v4_defs[NAT64_ACL_V4_FIELD_COUNT] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = NAT64_ACL_V4_PROTO,
        .input_index = 0,
        .offset = offsetof(struct nat64_acl_v4_key, proto),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V4_SRC,
        .input_index = 1,
        .offset = offsetof(struct nat64_acl_v4_key, src),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V4_DST,
        .input_index = 2,
        .offset = offsetof(struct nat64_acl_v4_key, dst),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(rte_be16_t),
        .field_index = NAT64_ACL_V4_SPORT,
        .input_index = 3,
        .offset = offsetof(struct nat64_acl_v4_key, sport),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(rte_be16_t),
        .field_index = NAT64_ACL_V4_DPORT,
        .input_index = 3,
        .offset = offsetof(struct nat64_acl_v4_key, dport),
    },
};

static const struct rte_acl_field_def acl_v6_defs[NAT64_ACL_V6_FIELD_COUNT] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = NAT64_ACL_V6_PROTO,
        .input_index = 0,
        .offset = offsetof(struct nat64_acl_v6_key, proto),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_SRC0,
        .input_index = 1,
        .offset = offsetof(struct nat64_acl_v6_key, src[0]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_SRC1,
        .input_index = 2,
        .offset = offsetof(struct nat64_acl_v6_key, src[1]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_SRC2,
        .input_index = 3,
        .offset = offsetof(struct nat64_acl_v6_key, src[2]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_SRC3,
        .input_index = 4,
        .offset = offsetof(struct nat64_acl_v6_key, src[3]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_DST0,
        .input_index = 5,
        .offset = offsetof(struct nat64_acl_v6_key, dst[0]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_DST1,
        .input_index = 6,
        .offset = offsetof(struct nat64_acl_v6_key, dst[1]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_DST2,
        .input_index = 7,
        .offset = offsetof(struct nat64_acl_v6_key, dst[2]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(rte_be32_t),
        .field_index = NAT64_ACL_V6_DST3,
        .input_index = 8,
        .offset = offsetof(struct nat64_acl_v6_key, dst[3]),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(rte_be16_t),
        .field_index = NAT64_ACL_V6_SPORT,
        .input_index = 9,
        .offset = offsetof(struct nat64_acl_v6_key, sport),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(rte_be16_t),
        .field_index = NAT64_ACL_V6_DPORT,
        .input_index = 9,
        .offset = offsetof(struct nat64_acl_v6_key, dport),
    },
};

static void free_runtime_set(struct nat64_acl_runtime_set *set);
static void cleanup_runtime_set_contents(struct nat64_acl_runtime_set *set);

static bool direction_matches(enum nat64_acl_direction direction, enum nat64_acl_direction packet_direction)
{
    return direction == NAT64_ACL_DIR_BOTH || direction == packet_direction;
}

const char *nat64_acl_direction_name(enum nat64_acl_direction direction)
{
    switch (direction) {
    case NAT64_ACL_DIR_V6_TO_V4:
        return "v6_to_v4";
    case NAT64_ACL_DIR_V4_TO_V6:
        return "v4_to_v6";
    case NAT64_ACL_DIR_BOTH:
        return "both";
    default:
        return "unknown";
    }
}

const char *nat64_acl_action_name(enum nat64_acl_action action)
{
    return action == NAT64_ACL_ACTION_DENY ? "deny" : "permit";
}

static uint32_t acl_direction_index(enum nat64_acl_direction direction)
{
    return direction == NAT64_ACL_DIR_V4_TO_V6 ? 1U : 0U;
}

static void extract_l4_ports(uint8_t proto, const void *l4, uint16_t *sport, uint16_t *dport)
{
    *sport = 0;
    *dport = 0;

    if (proto == IPPROTO_TCP) {
        const struct rte_tcp_hdr *tcp = l4;

        *sport = rte_be_to_cpu_16(tcp->src_port);
        *dport = rte_be_to_cpu_16(tcp->dst_port);
    } else if (proto == IPPROTO_UDP) {
        const struct rte_udp_hdr *udp = l4;

        *sport = rte_be_to_cpu_16(udp->src_port);
        *dport = rte_be_to_cpu_16(udp->dst_port);
    } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        const struct rte_icmp_hdr *icmp = l4;

        *sport = icmp->icmp_type;
        *dport = icmp->icmp_code;
    }
}

static uint32_t acl_prefix6_word_value(const struct nat64_prefix6 *prefix, uint32_t word)
{
    rte_be32_t be_word;

    memcpy(&be_word, &prefix->addr.s6_addr[word * sizeof(be_word)], sizeof(be_word));
    return rte_be_to_cpu_32(be_word);
}

static uint32_t acl_prefix6_word_mask(const struct nat64_prefix6 *prefix, uint32_t word)
{
    uint32_t used = word * 32U;

    if (prefix->mask <= used) {
        return 0;
    }
    if (prefix->mask - used >= 32U) {
        return 32;
    }
    return prefix->mask - used;
}

static bool service_index_for_config(struct nat64_ctx *ctx, const struct nat64_service_config *service,
                                     uint32_t *index)
{
    const struct nat64_config *cfg = ctx->mutable_cfg != NULL ? ctx->mutable_cfg : ctx->cfg;

    if (cfg == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < cfg->service_count && i < NAT64_MAX_SERVICES; i++) {
        if (&cfg->services[i] == service) {
            if (index != NULL) {
                *index = i;
            }
            return true;
        }
    }
    return false;
}

static uint32_t acl_reader_slot(uint16_t queue_id)
{
    return queue_id < NAT64_MAX_WORKERS ? queue_id : NAT64_ACL_CONTROL_READER;
}

static struct nat64_acl_runtime_set *acl_runtime_enter(struct nat64_ctx *ctx, uint16_t queue_id)
{
    struct nat64_acl_runtime_set *set;
    uint32_t slot;
    uint64_t generation;

    if (ctx == NULL) {
        return NULL;
    }
    slot = acl_reader_slot(queue_id);
    for (;;) {
        set = __atomic_load_n(&ctx->acl_active, __ATOMIC_ACQUIRE);
        generation = set == NULL ? 0 : set->generation;
        __atomic_store_n(&ctx->acl_reader_generations[slot], generation, __ATOMIC_RELEASE);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (__atomic_load_n(&ctx->acl_active, __ATOMIC_ACQUIRE) == set) {
            return set;
        }
        __atomic_store_n(&ctx->acl_reader_generations[slot], 0, __ATOMIC_RELEASE);
        rte_pause();
    }
}

static void acl_runtime_exit(struct nat64_ctx *ctx, uint16_t queue_id)
{
    if (ctx == NULL) {
        return;
    }
    __atomic_store_n(&ctx->acl_reader_generations[acl_reader_slot(queue_id)], 0, __ATOMIC_RELEASE);
}

static bool acl_readers_past_generation(struct nat64_ctx *ctx, uint64_t generation)
{
    for (uint32_t i = 0; i < NAT64_ACL_READER_SLOTS; i++) {
        uint64_t reader_generation = __atomic_load_n(&ctx->acl_reader_generations[i], __ATOMIC_ACQUIRE);

        if (reader_generation != 0 && reader_generation <= generation) {
            return false;
        }
    }
    return true;
}

static bool acl_wait_readers_past_generation(struct nat64_ctx *ctx, uint64_t generation)
{
    for (uint32_t i = 0; i < NAT64_ACL_RECLAIM_WAIT_LOOPS; i++) {
        if (acl_readers_past_generation(ctx, generation)) {
            return true;
        }
        rte_pause();
    }
    return acl_readers_past_generation(ctx, generation);
}

static bool acl_try_reclaim_deferred_locked(struct nat64_ctx *ctx)
{
    struct nat64_acl_runtime_set *deferred;

    if (ctx == NULL || ctx->acl_deferred_free == NULL) {
        return true;
    }
    if (!acl_wait_readers_past_generation(ctx, ctx->acl_deferred_generation)) {
        return false;
    }

    deferred = ctx->acl_deferred_free;
    ctx->acl_deferred_free = NULL;
    ctx->acl_deferred_generation = 0;
    free_runtime_set(deferred);
    ctx->acl_reclaim_success++;
    return true;
}

static void acl_retire_runtime_locked(struct nat64_ctx *ctx, struct nat64_acl_runtime_set *old_set)
{
    if (ctx == NULL || old_set == NULL) {
        return;
    }
    if (acl_wait_readers_past_generation(ctx, old_set->generation)) {
        free_runtime_set(old_set);
        ctx->acl_reclaim_success++;
        return;
    }

    ctx->acl_deferred_free = old_set;
    ctx->acl_deferred_generation = old_set->generation;
    ctx->acl_reclaim_deferred++;
}

static struct nat64_acl_classifier *classifier_for_service_runtime(struct nat64_acl_runtime_set *set,
                                                                   uint32_t index,
                                                                   enum nat64_acl_direction direction)
{
    if (set == NULL || index >= set->service_runtime_count) {
        return NULL;
    }
    if (direction == NAT64_ACL_DIR_V6_TO_V4) {
        return &set->service_runtime[index].acl_v6_to_v4;
    }
    return &set->service_runtime[index].acl_v4_to_v6;
}

static struct nat64_worker_hot_stats *worker_stats(struct nat64_ctx *ctx, uint16_t queue_id)
{
    return queue_id < NAT64_MAX_WORKERS ? &ctx->worker_stats[queue_id] : NULL;
}

static void acl_note_v6_to_v4(struct nat64_ctx *ctx, uint16_t queue_id, bool allow)
{
    struct nat64_worker_hot_stats *stats = worker_stats(ctx, queue_id);

    if (stats == NULL) {
        return;
    }
    if (allow) {
        stats->acl_permit_v6_to_v4++;
    } else {
        stats->acl_deny_v6_to_v4++;
    }
}

static void acl_note_v4_to_v6(struct nat64_ctx *ctx, uint16_t queue_id, bool allow)
{
    struct nat64_worker_hot_stats *stats = worker_stats(ctx, queue_id);

    if (stats == NULL) {
        return;
    }
    if (allow) {
        stats->acl_permit_v4_to_v6++;
    } else {
        stats->acl_deny_v4_to_v6++;
    }
}

static int build_v4_classifier(struct nat64_acl_classifier *classifier,
                               const struct nat64_service_config *service,
                               uint32_t service_index, uint64_t generation)
{
    struct nat64_acl_rule_v4 rules[NAT64_MAX_ACL_RULES];
    struct rte_acl_param param;
    struct rte_acl_config config;
    char name[64];
    uint32_t count = 0;

    memset(classifier, 0, sizeof(*classifier));
    classifier->default_permit = service->acl_default_permit;

    memset(rules, 0, sizeof(rules));
    for (uint32_t i = 0; i < service->acl_rule_count; i++) {
        const struct nat64_acl_rule_config *rule = &service->acl_rules[i];
        struct nat64_acl_rule_v4 *acl_rule;

        if (!direction_matches(rule->direction, NAT64_ACL_DIR_V4_TO_V6)) {
            continue;
        }
        acl_rule = &rules[count];
        acl_rule->data.category_mask = NAT64_ACL_CATEGORY_MASK;
        acl_rule->data.priority = (int32_t) (NAT64_MAX_ACL_RULES - i);
        acl_rule->data.userdata = count + 1;
        acl_rule->field[NAT64_ACL_V4_PROTO].value.u8 = rule->proto_any ? 0 : rule->proto;
        acl_rule->field[NAT64_ACL_V4_PROTO].mask_range.u8 = rule->proto_any ? 0 : 0xff;
        acl_rule->field[NAT64_ACL_V4_SRC].value.u32 =
            rule->has_src4 ? rte_be_to_cpu_32(rule->src4.addr.s_addr) : 0;
        acl_rule->field[NAT64_ACL_V4_SRC].mask_range.u32 = rule->has_src4 ? rule->src4.mask : 0;
        acl_rule->field[NAT64_ACL_V4_DST].value.u32 =
            rule->has_dst4 ? rte_be_to_cpu_32(rule->dst4.addr.s_addr) : 0;
        acl_rule->field[NAT64_ACL_V4_DST].mask_range.u32 = rule->has_dst4 ? rule->dst4.mask : 0;
        acl_rule->field[NAT64_ACL_V4_SPORT].value.u16 = rule->sport_from;
        acl_rule->field[NAT64_ACL_V4_SPORT].mask_range.u16 = rule->sport_to;
        acl_rule->field[NAT64_ACL_V4_DPORT].value.u16 = rule->dport_from;
        acl_rule->field[NAT64_ACL_V4_DPORT].mask_range.u16 = rule->dport_to;
        classifier->actions[count] = rule->action == NAT64_ACL_ACTION_PERMIT;
        classifier->rule_indices[count] = i;
        count++;
    }

    classifier->rule_count = count;
    classifier->has_rules = count > 0;
    if (count == 0) {
        return 0;
    }

    snprintf(name, sizeof(name), "nat64_acl_v4_s%u_g%llu",
             service_index, (unsigned long long) generation);
    memset(&param, 0, sizeof(param));
    param.name = name;
    param.socket_id = SOCKET_ID_ANY;
    param.rule_size = RTE_ACL_RULE_SZ(NAT64_ACL_V4_FIELD_COUNT);
    param.max_rule_num = count;
    classifier->ctx = rte_acl_create(&param);
    if (classifier->ctx == NULL) {
        return -ENOMEM;
    }
    if (rte_acl_add_rules(classifier->ctx, (const struct rte_acl_rule *) rules, count) < 0) {
        return -EINVAL;
    }

    memset(&config, 0, sizeof(config));
    config.num_categories = NAT64_ACL_CATEGORIES;
    config.num_fields = NAT64_ACL_V4_FIELD_COUNT;
    memcpy(config.defs, acl_v4_defs, sizeof(acl_v4_defs));
    if (rte_acl_build(classifier->ctx, &config) < 0) {
        return -EINVAL;
    }
    return 0;
}

static int build_v6_classifier(struct nat64_acl_classifier *classifier,
                               const struct nat64_service_config *service,
                               uint32_t service_index, uint64_t generation)
{
    struct nat64_acl_rule_v6 rules[NAT64_MAX_ACL_RULES];
    struct rte_acl_param param;
    struct rte_acl_config config;
    char name[64];
    uint32_t count = 0;

    memset(classifier, 0, sizeof(*classifier));
    classifier->default_permit = service->acl_default_permit;

    memset(rules, 0, sizeof(rules));
    for (uint32_t i = 0; i < service->acl_rule_count; i++) {
        const struct nat64_acl_rule_config *rule = &service->acl_rules[i];
        struct nat64_acl_rule_v6 *acl_rule;

        if (!direction_matches(rule->direction, NAT64_ACL_DIR_V6_TO_V4)) {
            continue;
        }
        acl_rule = &rules[count];
        acl_rule->data.category_mask = NAT64_ACL_CATEGORY_MASK;
        acl_rule->data.priority = (int32_t) (NAT64_MAX_ACL_RULES - i);
        acl_rule->data.userdata = count + 1;
        acl_rule->field[NAT64_ACL_V6_PROTO].value.u8 = rule->proto_any ? 0 : rule->proto;
        acl_rule->field[NAT64_ACL_V6_PROTO].mask_range.u8 = rule->proto_any ? 0 : 0xff;

        for (uint32_t word = 0; word < 4; word++) {
            uint32_t src_idx = NAT64_ACL_V6_SRC0 + word;
            uint32_t dst_idx = NAT64_ACL_V6_DST0 + word;

            acl_rule->field[src_idx].value.u32 = rule->has_src6 ? acl_prefix6_word_value(&rule->src6, word) : 0;
            acl_rule->field[src_idx].mask_range.u32 = rule->has_src6 ? acl_prefix6_word_mask(&rule->src6, word) : 0;
            acl_rule->field[dst_idx].value.u32 = rule->has_dst6 ? acl_prefix6_word_value(&rule->dst6, word) : 0;
            acl_rule->field[dst_idx].mask_range.u32 = rule->has_dst6 ? acl_prefix6_word_mask(&rule->dst6, word) : 0;
        }

        acl_rule->field[NAT64_ACL_V6_SPORT].value.u16 = rule->sport_from;
        acl_rule->field[NAT64_ACL_V6_SPORT].mask_range.u16 = rule->sport_to;
        acl_rule->field[NAT64_ACL_V6_DPORT].value.u16 = rule->dport_from;
        acl_rule->field[NAT64_ACL_V6_DPORT].mask_range.u16 = rule->dport_to;
        classifier->actions[count] = rule->action == NAT64_ACL_ACTION_PERMIT;
        classifier->rule_indices[count] = i;
        count++;
    }

    classifier->rule_count = count;
    classifier->has_rules = count > 0;
    if (count == 0) {
        return 0;
    }

    snprintf(name, sizeof(name), "nat64_acl_v6_s%u_g%llu",
             service_index, (unsigned long long) generation);
    memset(&param, 0, sizeof(param));
    param.name = name;
    param.socket_id = SOCKET_ID_ANY;
    param.rule_size = RTE_ACL_RULE_SZ(NAT64_ACL_V6_FIELD_COUNT);
    param.max_rule_num = count;
    classifier->ctx = rte_acl_create(&param);
    if (classifier->ctx == NULL) {
        return -ENOMEM;
    }
    if (rte_acl_add_rules(classifier->ctx, (const struct rte_acl_rule *) rules, count) < 0) {
        return -EINVAL;
    }

    memset(&config, 0, sizeof(config));
    config.num_categories = NAT64_ACL_CATEGORIES;
    config.num_fields = NAT64_ACL_V6_FIELD_COUNT;
    memcpy(config.defs, acl_v6_defs, sizeof(acl_v6_defs));
    if (rte_acl_build(classifier->ctx, &config) < 0) {
        return -EINVAL;
    }
    return 0;
}

static void free_classifier(struct nat64_acl_classifier *classifier)
{
    if (classifier == NULL) {
        return;
    }
    if (classifier->ctx != NULL) {
        rte_acl_free(classifier->ctx);
        classifier->ctx = NULL;
    }
    memset(classifier, 0, sizeof(*classifier));
}

static void free_runtime_set(struct nat64_acl_runtime_set *set)
{
    if (set == NULL) {
        return;
    }
    for (uint32_t i = 0; i < set->service_runtime_count && i < NAT64_MAX_SERVICES; i++) {
        free_classifier(&set->service_runtime[i].acl_v6_to_v4);
        free_classifier(&set->service_runtime[i].acl_v4_to_v6);
    }
    rte_free(set);
}

static void cleanup_runtime_set_contents(struct nat64_acl_runtime_set *set)
{
    if (set == NULL) {
        return;
    }
    for (uint32_t i = 0; i < set->service_runtime_count && i < NAT64_MAX_SERVICES; i++) {
        free_classifier(&set->service_runtime[i].acl_v6_to_v4);
        free_classifier(&set->service_runtime[i].acl_v4_to_v6);
    }
    memset(set, 0, sizeof(*set));
}

static int build_runtime_set(struct nat64_acl_runtime_set **set_out, const struct nat64_config *cfg,
                             uint64_t generation)
{
    struct nat64_acl_runtime_set *set;

    if (set_out == NULL || cfg == NULL) {
        return -EINVAL;
    }
    *set_out = NULL;

    set = rte_zmalloc("nat64_acl_runtime_set", sizeof(*set), 0);
    if (set == NULL) {
        return -ENOMEM;
    }
    set->generation = generation;
    set->service_runtime_count = cfg->service_count;
    if (set->service_runtime_count > NAT64_MAX_SERVICES) {
        set->service_runtime_count = NAT64_MAX_SERVICES;
    }

    for (uint32_t i = 0; i < set->service_runtime_count; i++) {
        const struct nat64_service_config *service = &cfg->services[i];
        int rc;

        set->service_runtime[i].cfg = service;
        rc = build_v6_classifier(&set->service_runtime[i].acl_v6_to_v4, service, i, generation);
        if (rc < 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                    "NAT64 init failed: failed to build IPv6 ACL for service %u: %d\n", i, rc);
            cleanup_runtime_set_contents(set);
            rte_free(set);
            return rc;
        }
        rc = build_v4_classifier(&set->service_runtime[i].acl_v4_to_v6, service, i, generation);
        if (rc < 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                    "NAT64 init failed: failed to build IPv4 ACL for service %u: %d\n", i, rc);
            cleanup_runtime_set_contents(set);
            rte_free(set);
            return rc;
        }
        rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
                "ACL service %u: rte_acl v6_to_v4_rules=%u v4_to_v6_rules=%u default=%s\n",
                i, set->service_runtime[i].acl_v6_to_v4.rule_count,
                set->service_runtime[i].acl_v4_to_v6.rule_count,
                service->acl_default_permit ? "permit" : "deny");
    }
    *set_out = set;
    return 0;
}

int nat64_acl_init(struct nat64_ctx *ctx)
{
    struct nat64_acl_runtime_set *set = NULL;
    int rc;

    if (ctx == NULL || ctx->cfg == NULL) {
        return -EINVAL;
    }

    nat64_acl_cleanup(ctx);
    ctx->mutable_cfg = (struct nat64_config *) ctx->cfg;
    ctx->acl_generation = 1;
    rc = build_runtime_set(&set, ctx->cfg, ctx->acl_generation);
    if (rc < 0) {
        return rc;
    }
    ctx->service_runtime_count = set->service_runtime_count;
    __atomic_store_n(&ctx->acl_active, set, __ATOMIC_RELEASE);
    memset(ctx->acl_rule_hits, 0, sizeof(ctx->acl_rule_hits));
    return 0;
}

void nat64_acl_cleanup(struct nat64_ctx *ctx)
{
    struct nat64_acl_runtime_set *active;
    struct nat64_acl_runtime_set *deferred;

    if (ctx == NULL) {
        return;
    }

    active = __atomic_exchange_n(&ctx->acl_active, NULL, __ATOMIC_ACQ_REL);
    free_runtime_set(active);
    deferred = ctx->acl_deferred_free;
    ctx->acl_deferred_free = NULL;
    ctx->acl_deferred_generation = 0;
    free_runtime_set(deferred);
    ctx->service_runtime_count = 0;
    memset(ctx->service_runtime, 0, sizeof(ctx->service_runtime));
    memset(ctx->acl_reader_generations, 0, sizeof(ctx->acl_reader_generations));
}

static bool classify_v4_key(struct nat64_acl_classifier *classifier, const struct nat64_acl_v4_key *key,
                            uint32_t *rule_index)
{
    const uint8_t *data[1];
    uint32_t results[NAT64_ACL_CATEGORIES] = {0};

    if (rule_index != NULL) {
        *rule_index = NAT64_ACL_DEFAULT_HIT_INDEX;
    }
    if (classifier == NULL || !classifier->has_rules || classifier->ctx == NULL) {
        return classifier == NULL ? false : classifier->default_permit;
    }

    data[0] = (const uint8_t *) key;

    if (rte_acl_classify(classifier->ctx, data, results, 1, NAT64_ACL_CATEGORIES) < 0 ||
        results[0] == 0) {
        return classifier->default_permit;
    }
    if (results[0] > classifier->rule_count) {
        return classifier->default_permit;
    }
    if (rule_index != NULL) {
        *rule_index = classifier->rule_indices[results[0] - 1];
    }
    return classifier->actions[results[0] - 1] != 0;
}

static bool classify_v4(struct nat64_acl_classifier *classifier, const struct rte_ipv4_hdr *ip4,
                        uint32_t *rule_index)
{
    struct nat64_acl_v4_key key;
    uint16_t sport;
    uint16_t dport;

    memset(&key, 0, sizeof(key));
    key.proto = ip4->next_proto_id;
    key.src = ip4->src_addr;
    key.dst = ip4->dst_addr;
    extract_l4_ports(ip4->next_proto_id, ip4 + 1, &sport, &dport);
    key.sport = rte_cpu_to_be_16(sport);
    key.dport = rte_cpu_to_be_16(dport);
    return classify_v4_key(classifier, &key, rule_index);
}

static bool classify_v6_key(struct nat64_acl_classifier *classifier, const struct nat64_acl_v6_key *key,
                            uint32_t *rule_index)
{
    const uint8_t *data[1];
    uint32_t results[NAT64_ACL_CATEGORIES] = {0};

    if (rule_index != NULL) {
        *rule_index = NAT64_ACL_DEFAULT_HIT_INDEX;
    }
    if (classifier == NULL || !classifier->has_rules || classifier->ctx == NULL) {
        return classifier == NULL ? false : classifier->default_permit;
    }

    data[0] = (const uint8_t *) key;

    if (rte_acl_classify(classifier->ctx, data, results, 1, NAT64_ACL_CATEGORIES) < 0 ||
        results[0] == 0) {
        return classifier->default_permit;
    }
    if (results[0] > classifier->rule_count) {
        return classifier->default_permit;
    }
    if (rule_index != NULL) {
        *rule_index = classifier->rule_indices[results[0] - 1];
    }
    return classifier->actions[results[0] - 1] != 0;
}

static bool classify_v6(struct nat64_acl_classifier *classifier, const struct rte_ipv6_hdr *ip6,
                        uint32_t *rule_index)
{
    struct nat64_acl_v6_key key;
    uint16_t sport;
    uint16_t dport;

    memset(&key, 0, sizeof(key));
    key.proto = ip6->proto;
    memcpy(key.src, ip6->src_addr, sizeof(key.src));
    memcpy(key.dst, ip6->dst_addr, sizeof(key.dst));
    extract_l4_ports(ip6->proto, ip6 + 1, &sport, &dport);
    key.sport = rte_cpu_to_be_16(sport);
    key.dport = rte_cpu_to_be_16(dport);
    return classify_v6_key(classifier, &key, rule_index);
}

static void acl_note_rule_hit(struct nat64_ctx *ctx, uint16_t queue_id, uint32_t service_index,
                              enum nat64_acl_direction direction, uint32_t rule_index)
{
    uint32_t dir_idx;

    if (ctx == NULL || queue_id >= NAT64_MAX_WORKERS || service_index >= NAT64_MAX_SERVICES) {
        return;
    }
    if (rule_index > NAT64_ACL_DEFAULT_HIT_INDEX) {
        rule_index = NAT64_ACL_DEFAULT_HIT_INDEX;
    }
    dir_idx = acl_direction_index(direction);
    ctx->acl_rule_hits[queue_id][service_index][dir_idx][rule_index]++;
}

static void acl_set_error(char *errbuf, size_t errbuf_len, const char *fmt, ...)
{
    va_list ap;

    if (errbuf == NULL || errbuf_len == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(errbuf, errbuf_len, fmt, ap);
    va_end(ap);
}

static bool same_prefix6_array(const struct nat64_prefix6 *a, uint32_t a_count,
                               const struct nat64_prefix6 *b, uint32_t b_count)
{
    if (a_count != b_count) {
        return false;
    }
    for (uint32_t i = 0; i < a_count; i++) {
        if (a[i].mask != b[i].mask ||
            memcmp(&a[i].addr, &b[i].addr, sizeof(a[i].addr)) != 0) {
            return false;
        }
    }
    return true;
}

static bool acl_reload_scope_matches(const struct nat64_config *old_cfg, const struct nat64_config *new_cfg,
                                     char *errbuf, size_t errbuf_len)
{
    if (old_cfg->service_count != new_cfg->service_count) {
        acl_set_error(errbuf, errbuf_len, "service_count mismatch: current=%u new=%u",
                      old_cfg->service_count, new_cfg->service_count);
        return false;
    }
    for (uint32_t i = 0; i < old_cfg->service_count && i < NAT64_MAX_SERVICES; i++) {
        const struct nat64_service_config *old_svc = &old_cfg->services[i];
        const struct nat64_service_config *new_svc = &new_cfg->services[i];

        if (strcmp(old_svc->vs.name, new_svc->vs.name) != 0) {
            acl_set_error(errbuf, errbuf_len, "service %u name mismatch", i);
            return false;
        }
        if (!same_prefix6_array(old_svc->vs.vaddr, old_svc->vs.vaddr_count,
                                new_svc->vs.vaddr, new_svc->vs.vaddr_count) ||
            !same_prefix6_array(old_svc->vs.saddr, old_svc->vs.saddr_count,
                                new_svc->vs.saddr, new_svc->vs.saddr_count)) {
            acl_set_error(errbuf, errbuf_len, "service %u ACL scope prefix mismatch", i);
            return false;
        }
    }
    return true;
}

static void copy_acl_config(struct nat64_config *dst, const struct nat64_config *src)
{
    for (uint32_t i = 0; i < dst->service_count && i < src->service_count && i < NAT64_MAX_SERVICES; i++) {
        dst->services[i].acl_default_permit = src->services[i].acl_default_permit;
        dst->services[i].acl_rule_count = src->services[i].acl_rule_count;
        memcpy(dst->services[i].acl_rules, src->services[i].acl_rules,
               sizeof(dst->services[i].acl_rules));
    }
}

int nat64_acl_reload_from_config(struct nat64_ctx *ctx, const char *path, char *errbuf, size_t errbuf_len)
{
    struct nat64_config new_cfg;
    struct nat64_acl_runtime_set *new_set = NULL;
    struct nat64_acl_runtime_set *old_set;
    uint64_t new_generation;
    int rc;

    if (ctx == NULL || ctx->mutable_cfg == NULL || path == NULL || path[0] == '\0') {
        acl_set_error(errbuf, errbuf_len, "missing runtime context or config path");
        return -EINVAL;
    }

    rte_spinlock_lock(&ctx->acl_update_lock);
    if (!acl_try_reclaim_deferred_locked(ctx)) {
        ctx->acl_reload_failure++;
        rte_spinlock_unlock(&ctx->acl_update_lock);
        acl_set_error(errbuf, errbuf_len, "previous ACL runtime is still in use; retry reload later");
        return -EAGAIN;
    }
    new_generation = ctx->acl_generation + 1;

    rc = nat64_config_load(path, &new_cfg);
    if (rc < 0) {
        ctx->acl_reload_failure++;
        rte_spinlock_unlock(&ctx->acl_update_lock);
        acl_set_error(errbuf, errbuf_len, "failed to load config: %d", rc);
        return rc;
    }
    if (!acl_reload_scope_matches(ctx->mutable_cfg, &new_cfg, errbuf, errbuf_len)) {
        ctx->acl_reload_failure++;
        rte_spinlock_unlock(&ctx->acl_update_lock);
        return -EINVAL;
    }

    rc = build_runtime_set(&new_set, &new_cfg, new_generation);
    if (rc < 0) {
        ctx->acl_reload_failure++;
        rte_spinlock_unlock(&ctx->acl_update_lock);
        acl_set_error(errbuf, errbuf_len, "failed to build ACL runtime: %d", rc);
        return rc;
    }

    copy_acl_config(ctx->mutable_cfg, &new_cfg);
    for (uint32_t i = 0; i < new_set->service_runtime_count && i < NAT64_MAX_SERVICES; i++) {
        new_set->service_runtime[i].cfg = &ctx->mutable_cfg->services[i];
    }
    old_set = __atomic_exchange_n(&ctx->acl_active, new_set, __ATOMIC_ACQ_REL);
    if (old_set != NULL) {
        acl_retire_runtime_locked(ctx, old_set);
    }
    ctx->acl_generation = new_generation;
    ctx->service_runtime_count = new_set->service_runtime_count;
    memset(ctx->acl_rule_hits, 0, sizeof(ctx->acl_rule_hits));
    ctx->acl_reload_success++;
    rte_spinlock_unlock(&ctx->acl_update_lock);
    acl_set_error(errbuf, errbuf_len, "ok");
    return 0;
}

uint64_t nat64_acl_get_rule_hits(struct nat64_ctx *ctx, uint32_t service_index,
                                 enum nat64_acl_direction direction, uint32_t rule_index)
{
    uint64_t total = 0;
    uint32_t dir_idx = acl_direction_index(direction);
    uint32_t worker_count;

    if (ctx == NULL || service_index >= NAT64_MAX_SERVICES || dir_idx >= 2 ||
        rule_index > NAT64_ACL_DEFAULT_HIT_INDEX) {
        return 0;
    }
    worker_count = ctx->queue_count > 0 && ctx->queue_count < NAT64_MAX_WORKERS ?
                   ctx->queue_count : NAT64_MAX_WORKERS;
    for (uint32_t q = 0; q < worker_count; q++) {
        total += __atomic_load_n(&ctx->acl_rule_hits[q][service_index][dir_idx][rule_index],
                                 __ATOMIC_RELAXED);
    }
    return total;
}

int nat64_acl_dry_run(struct nat64_ctx *ctx, const struct nat64_acl_dry_run_request *req,
                      struct nat64_acl_dry_run_result *out)
{
    struct nat64_acl_runtime_set *set;
    struct nat64_acl_classifier *classifier;
    uint32_t rule_index = NAT64_ACL_DEFAULT_HIT_INDEX;

    if (ctx == NULL || req == NULL || out == NULL ||
        req->service_index >= NAT64_MAX_SERVICES ||
        (req->direction != NAT64_ACL_DIR_V6_TO_V4 && req->direction != NAT64_ACL_DIR_V4_TO_V6)) {
        return -EINVAL;
    }

    rte_spinlock_lock(&ctx->acl_update_lock);
    set = __atomic_load_n(&ctx->acl_active, __ATOMIC_ACQUIRE);
    if (set == NULL || req->service_index >= set->service_runtime_count) {
        rte_spinlock_unlock(&ctx->acl_update_lock);
        return -ENOENT;
    }
    memset(out, 0, sizeof(*out));
    out->generation = set->generation;

    if (req->direction == NAT64_ACL_DIR_V6_TO_V4) {
        struct nat64_acl_v6_key key;

        memset(&key, 0, sizeof(key));
        key.proto = req->proto;
        memcpy(key.src, &req->src6, sizeof(key.src));
        memcpy(key.dst, &req->dst6, sizeof(key.dst));
        key.sport = rte_cpu_to_be_16(req->sport);
        key.dport = rte_cpu_to_be_16(req->dport);
        classifier = &set->service_runtime[req->service_index].acl_v6_to_v4;
        out->allow = classify_v6_key(classifier, &key, &rule_index);
    } else {
        struct nat64_acl_v4_key key;

        memset(&key, 0, sizeof(key));
        key.proto = req->proto;
        key.src = req->src4.s_addr;
        key.dst = req->dst4.s_addr;
        key.sport = rte_cpu_to_be_16(req->sport);
        key.dport = rte_cpu_to_be_16(req->dport);
        classifier = &set->service_runtime[req->service_index].acl_v4_to_v6;
        out->allow = classify_v4_key(classifier, &key, &rule_index);
    }

    out->rule_index = rule_index;
    out->matched_rule = rule_index != NAT64_ACL_DEFAULT_HIT_INDEX;
    if (out->matched_rule && ctx->mutable_cfg != NULL &&
        req->service_index < ctx->mutable_cfg->service_count &&
        rule_index < ctx->mutable_cfg->services[req->service_index].acl_rule_count) {
        snprintf(out->rule_name, sizeof(out->rule_name), "%s",
                 ctx->mutable_cfg->services[req->service_index].acl_rules[rule_index].name);
    }
    rte_spinlock_unlock(&ctx->acl_update_lock);
    return 0;
}

bool nat64_acl_allow_v6_to_v4(struct nat64_ctx *ctx, uint16_t queue_id,
                              const struct nat64_service_config *service,
                              const struct rte_ipv6_hdr *ip6)
{
    uint32_t service_index = 0;
    uint32_t rule_index = NAT64_ACL_DEFAULT_HIT_INDEX;
    struct nat64_acl_runtime_set *set;
    struct nat64_acl_classifier *classifier = NULL;
    bool allow;

    set = acl_runtime_enter(ctx, queue_id);
    if (service_index_for_config(ctx, service, &service_index)) {
        classifier = classifier_for_service_runtime(set, service_index, NAT64_ACL_DIR_V6_TO_V4);
    }
    allow = classify_v6(classifier, ip6, &rule_index);
    acl_runtime_exit(ctx, queue_id);

    acl_note_v6_to_v4(ctx, queue_id, allow);
    acl_note_rule_hit(ctx, queue_id, service_index, NAT64_ACL_DIR_V6_TO_V4, rule_index);
    return allow;
}

bool nat64_acl_allow_v4_to_v6(struct nat64_ctx *ctx, uint16_t queue_id,
                              const struct nat64_service_config *service,
                              const struct rte_ipv4_hdr *ip4)
{
    uint32_t service_index = 0;
    uint32_t rule_index = NAT64_ACL_DEFAULT_HIT_INDEX;
    struct nat64_acl_runtime_set *set;
    struct nat64_acl_classifier *classifier = NULL;
    bool allow;

    set = acl_runtime_enter(ctx, queue_id);
    if (service_index_for_config(ctx, service, &service_index)) {
        classifier = classifier_for_service_runtime(set, service_index, NAT64_ACL_DIR_V4_TO_V6);
    }
    allow = classify_v4(classifier, ip4, &rule_index);
    acl_runtime_exit(ctx, queue_id);

    acl_note_v4_to_v6(ctx, queue_id, allow);
    acl_note_rule_hit(ctx, queue_id, service_index, NAT64_ACL_DIR_V4_TO_V6, rule_index);
    return allow;
}
