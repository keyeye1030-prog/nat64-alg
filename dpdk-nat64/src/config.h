#ifndef NAT64_CONFIG_H
#define NAT64_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#define NAT64_MAX_CPUS 32
#define NAT64_MAX_PCIDEVS 16
#define NAT64_MAX_NETS 8
#define NAT64_MAX_IPS_PER_NET 16
#define NAT64_MAX_SERVICES 8
#define NAT64_MAX_VADDRS 8
#define NAT64_MAX_SADDRS 8
#define NAT64_MAX_RS 64
#define NAT64_MAX_LADDRS 64
#define NAT64_MAX_ACL_RULES 128
#define NAT64_MAX_STATIC_BIBS 128
#define NAT64_MAX_SUBSCRIBER_RULES 64

enum nat64_net_side {
    NAT64_NET_SIDE_UNSPEC = 0,
    NAT64_NET_SIDE_V6 = 1,
    NAT64_NET_SIDE_V4 = 2,
};

struct nat64_prefix4 {
    struct in_addr addr;
    uint8_t mask;
};

struct nat64_prefix6 {
    struct in6_addr addr;
    uint8_t mask;
};

struct nat64_sys_config {
    bool checksum_offload;
    uint32_t cpus[NAT64_MAX_CPUS];
    uint32_t cpu_count;
    uint32_t mem_mb;
    uint32_t loglevel;
    uint16_t rx_desc;
    uint16_t tx_desc;
    uint32_t frag_entries;
    char pcibus[NAT64_MAX_PCIDEVS][32];
    uint32_t pcibus_count;
};

struct nat64_netif_config {
    char name[32];
    char ip_raw[NAT64_MAX_IPS_PER_NET][64];
    uint32_t ip_count;
    bool has_port_id;
    uint16_t port_id;
    enum nat64_net_side side;
};

struct nat64_vs_config {
    char name[32];
    char proto[8];
    char mode[8];
    char sched[8];
    struct nat64_prefix6 vaddr[NAT64_MAX_VADDRS];
    uint32_t vaddr_count;
    struct nat64_prefix6 saddr[NAT64_MAX_SADDRS];
    uint32_t saddr_count;
};

struct nat64_rs_config {
    struct nat64_prefix4 prefix;
};

struct nat64_laddr_config {
    struct nat64_prefix4 prefix;
    char dev[32];
};

enum nat64_destination_mode {
    NAT64_DST_RS_POOL = 0,
    NAT64_DST_EMBED_V4 = 1,
};

enum nat64_acl_direction {
    NAT64_ACL_DIR_V6_TO_V4 = 0,
    NAT64_ACL_DIR_V4_TO_V6 = 1,
    NAT64_ACL_DIR_BOTH = 2,
};

enum nat64_acl_action {
    NAT64_ACL_ACTION_PERMIT = 0,
    NAT64_ACL_ACTION_DENY = 1,
};

struct nat64_acl_rule_config {
    char name[32];
    enum nat64_acl_direction direction;
    enum nat64_acl_action action;
    uint8_t proto;
    bool proto_any;
    bool has_src4;
    bool has_dst4;
    bool has_src6;
    bool has_dst6;
    struct nat64_prefix4 src4;
    struct nat64_prefix4 dst4;
    struct nat64_prefix6 src6;
    struct nat64_prefix6 dst6;
    uint16_t sport_from;
    uint16_t sport_to;
    uint16_t dport_from;
    uint16_t dport_to;
};

struct nat64_static_bib_config {
    char name[32];
    uint8_t proto;
    struct in_addr local_v4;
    struct in6_addr client_v6;
    uint16_t map_port_from;
    uint16_t map_port_to;
};

struct nat64_service_config {
    struct nat64_vs_config vs;
    enum nat64_destination_mode dst_mode;
    struct nat64_rs_config rs[NAT64_MAX_RS];
    uint32_t rs_count;
    struct nat64_laddr_config laddr[NAT64_MAX_LADDRS];
    uint32_t laddr_count;
    bool acl_default_permit;
    struct nat64_acl_rule_config acl_rules[NAT64_MAX_ACL_RULES];
    uint32_t acl_rule_count;
    struct nat64_static_bib_config static_bibs[NAT64_MAX_STATIC_BIBS];
    uint32_t static_bib_count;
};

struct nat64_audit_config {
    bool enabled;
    char file[260];
    uint64_t rotate_bytes;
};

struct nat64_subscriber_limit_rule_config {
    char name[32];
    struct nat64_prefix6 prefix;
    uint32_t max_sessions;
    uint32_t new_conn_per_sec;
    uint32_t burst;
};

struct nat64_subscriber_limits_config {
    bool enabled;
    uint8_t prefix_len;
    uint32_t max_entries;
    struct nat64_subscriber_limit_rule_config default_limit;
    struct nat64_subscriber_limit_rule_config rules[NAT64_MAX_SUBSCRIBER_RULES];
    uint32_t rule_count;
};

struct nat64_config {
    struct nat64_sys_config sys;
    struct nat64_netif_config nets[NAT64_MAX_NETS];
    uint32_t net_count;
    char route_file[260];
    struct nat64_audit_config audit;
    struct nat64_subscriber_limits_config subscriber_limits;
    struct nat64_service_config services[NAT64_MAX_SERVICES];
    uint32_t service_count;
};

int nat64_config_load(const char *path, struct nat64_config *cfg);
int nat64_build_eal_args(const struct nat64_config *cfg, char ***argv_out, int *argc_out);
void nat64_free_eal_args(char **argv, int argc);

#endif
