#ifndef NAT64_ACL_H
#define NAT64_ACL_H

#include <stdbool.h>
#include <sys/types.h>

#include <rte_ip.h>

#include "nat64.h"

struct nat64_acl_dry_run_request {
    uint32_t service_index;
    enum nat64_acl_direction direction;
    uint8_t proto;
    struct in_addr src4;
    struct in_addr dst4;
    struct in6_addr src6;
    struct in6_addr dst6;
    uint16_t sport;
    uint16_t dport;
};

struct nat64_acl_dry_run_result {
    bool allow;
    bool matched_rule;
    uint32_t rule_index;
    char rule_name[32];
    uint64_t generation;
};

int nat64_acl_init(struct nat64_ctx *ctx);
void nat64_acl_cleanup(struct nat64_ctx *ctx);
int nat64_acl_reload_from_config(struct nat64_ctx *ctx, const char *path, char *errbuf, size_t errbuf_len);
int nat64_acl_dry_run(struct nat64_ctx *ctx, const struct nat64_acl_dry_run_request *req,
                      struct nat64_acl_dry_run_result *out);
uint64_t nat64_acl_get_rule_hits(struct nat64_ctx *ctx, uint32_t service_index,
                                 enum nat64_acl_direction direction, uint32_t rule_index);
const char *nat64_acl_direction_name(enum nat64_acl_direction direction);
const char *nat64_acl_action_name(enum nat64_acl_action action);
bool nat64_acl_allow_v6_to_v4(struct nat64_ctx *ctx, uint16_t queue_id,
                              const struct nat64_service_config *service,
                              const struct rte_ipv6_hdr *ip6);
bool nat64_acl_allow_v4_to_v6(struct nat64_ctx *ctx, uint16_t queue_id,
                              const struct nat64_service_config *service,
                              const struct rte_ipv4_hdr *ip4);

#endif
