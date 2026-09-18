#ifndef NAT64_CORE_H
#define NAT64_CORE_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>

#include "config.h"
#include "capture.h"
#include "route.h"

#define NAT64_MAX_SESSIONS (5U * 1024U * 1024U)
#define NAT64_SESSION_SHARDS 4096
#define NAT64_SESSIONS_PER_SHARD (NAT64_MAX_SESSIONS / NAT64_SESSION_SHARDS)
#if (NAT64_SESSION_SHARDS & (NAT64_SESSION_SHARDS - 1)) != 0
#error "NAT64_SESSION_SHARDS must be a power of two"
#endif
#if (NAT64_MAX_SESSIONS % NAT64_SESSION_SHARDS) != 0
#error "NAT64_MAX_SESSIONS must be divisible by NAT64_SESSION_SHARDS"
#endif
#define NAT64_SESSION_CACHE_SIZE 64
#define NAT64_BURST_SIZE 64
#define NAT64_MAX_NEIGHBORS 1024
#define NAT64_NEIGHBOR_SHARDS 64
#define NAT64_DEFAULT_FRAG_ENTRIES 4096
#define NAT64_MAX_FRAG_ENTRIES 100000
#define NAT64_FRAG_MAX_PAYLOAD 65535
#define NAT64_FRAG_MAX_RANGES 64
#define NAT64_FRAG_MAX_OUTPUTS 64
#define NAT64_FRAG_TIMEOUT_SEC 15
#define NAT64_SESSION_TIMEOUT_SEC 300
#define NAT64_NEIGHBOR_TIMEOUT_SEC 1200
#define NAT64_ARP_REFRESH_SEC 30
#define NAT64_ARP_DEFEND_SEC 5
#define NAT64_LINK_POLL_MS 1000
#define NAT64_NEXTHOP_L2_PROBE_SEC 3
#define NAT64_NEXTHOP_L3_PROBE_SEC 5
#define NAT64_NEXTHOP_L2_STALE_SEC 10
#define NAT64_NEXTHOP_L3_STALE_SEC 15
#define NAT64_PING6_MAX_COUNT 64
#define NAT64_PING6_SEND_INTERVAL_SEC 1
#define NAT64_PING6_REPLY_WAIT_SEC 3
#define NAT64_PROBE4_MAX_COUNT 64
#define NAT64_PROBE4_SEND_INTERVAL_SEC 1
#define NAT64_PROBE4_REPLY_WAIT_SEC 3
#define NAT64_PROBE4_HTTP_WAIT_SEC 5
#define NAT64_STATS_PORT_COUNT 2
#define NAT64_STATS_DIR_COUNT 2
#define NAT64_STATS_FAMILY_COUNT 3
#define NAT64_MAX_WORKERS 128
#define NAT64_ACL_DEFAULT_HIT_INDEX NAT64_MAX_ACL_RULES
#define NAT64_ACL_HIT_SLOTS (NAT64_MAX_ACL_RULES + 1)
#define NAT64_SUBSCRIBER_SHARDS 256
#define NAT64_DEFAULT_SUBSCRIBER_ENTRIES 65536
#define NAT64_SUBSCRIBER_IDLE_SEC 600
#define NAT64_ACL_READER_SLOTS (NAT64_MAX_WORKERS + 1)
#define NAT64_ACL_CONTROL_READER NAT64_MAX_WORKERS
#define NAT64_ROUTE_READER_SLOTS (NAT64_MAX_WORKERS + 1)
#define NAT64_ROUTE_CONTROL_READER NAT64_MAX_WORKERS

enum nat64_stats_dir {
    NAT64_STATS_DIR_RX = 0,
    NAT64_STATS_DIR_TX = 1,
};

enum nat64_stats_family {
    NAT64_STATS_FAMILY_TOTAL = 0,
    NAT64_STATS_FAMILY_IPV4 = 1,
    NAT64_STATS_FAMILY_IPV6 = 2,
};

struct nat64_traffic_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t pps;
    uint64_t bps;
};

struct nat64_port_stats_snapshot {
    struct nat64_traffic_stats traffic[NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
};

struct nat64_worker_stats_snapshot {
    uint32_t lcore_id;
    uint64_t busy_cycles;
    uint64_t total_cycles;
    uint64_t busy_pct;
};

struct nat64_runtime_opts {
    struct rte_ether_addr v4_next_hop;
    bool has_v4_next_hop;
    struct rte_ether_addr v6_next_hop;
    bool has_v6_next_hop;
};

struct nat64_neighbor4_cache {
    bool valid;
    struct in_addr ip;
    struct rte_ether_addr mac;
    uint64_t last_seen_tsc;
};

struct nat64_neighbor6_cache {
    bool valid;
    struct in6_addr ip;
    struct rte_ether_addr mac;
    uint64_t last_seen_tsc;
};

struct nat64_worker_hot_stats {
    uint64_t v6_to_v4_packets;
    uint64_t v6_to_v4_bytes;
    uint64_t v4_to_v6_packets;
    uint64_t v4_to_v6_bytes;
    uint64_t acl_permit_v6_to_v4;
    uint64_t acl_deny_v6_to_v4;
    uint64_t acl_permit_v4_to_v6;
    uint64_t acl_deny_v4_to_v6;
    uint64_t port_packets[NAT64_STATS_PORT_COUNT][NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
    uint64_t port_bytes[NAT64_STATS_PORT_COUNT][NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
    uint64_t busy_cycles;
    uint64_t total_cycles;
};

struct nat64_session_cache_entry {
    bool valid;
    uint32_t index;
    uint32_t generation;
};

struct nat64_session {
    bool in_use;
    bool subscriber_counted;
    uint8_t proto;
    uint32_t generation;
    uint16_t service_index;
    struct in6_addr client_v6;
    struct in6_addr service_v6;
    uint16_t client_port;
    uint16_t service_port;
    struct in_addr local_v4;
    struct in_addr rs_v4;
    uint16_t local_port;
    uint16_t rs_port;
    bool route4_cached;
    bool route6_cached;
    bool route4_found;
    bool route6_found;
    int32_t tcp_delta_v6_to_v4;
    int32_t tcp_delta_v4_to_v6;
    struct in_addr route4_neigh_ip;
    struct in6_addr route6_neigh_ip;
    uint64_t route4_generation;
    uint64_t route6_generation;
    struct rte_ether_addr v6_reply_dmac;
    uint64_t created_unix;
    uint64_t last_seen_tsc;
};

struct nat64_session_filter {
    bool has_proto;
    uint8_t proto;
    bool has_service_index;
    uint16_t service_index;
    bool has_client_v6;
    bool has_service_v6;
    bool has_local_v4;
    bool has_rs_v4;
    struct in6_addr client_v6;
    struct in6_addr service_v6;
    struct in_addr local_v4;
    struct in_addr rs_v4;
    bool has_client_port;
    bool has_service_port;
    bool has_local_port;
    bool has_rs_port;
    uint16_t client_port;
    uint16_t service_port;
    uint16_t local_port;
    uint16_t rs_port;
};

struct nat64_neighbor4 {
    bool in_use;
    struct in_addr ip;
    struct rte_ether_addr mac;
    uint64_t last_seen_tsc;
};

struct nat64_neighbor6 {
    bool in_use;
    struct in6_addr ip;
    struct rte_ether_addr mac;
    uint64_t last_seen_tsc;
};

struct nat64_laddr_state {
    struct in_addr ip;
    uint64_t last_announce_tsc;
    uint64_t last_conflict_tsc;
    bool conflict_detected;
    struct rte_ether_addr conflict_mac;
};

struct nat64_link_state {
    bool up;
    uint32_t speed;
    bool full_duplex;
};

struct nat64_frag_range {
    uint16_t start;
    uint16_t end;
};

struct nat64_frag_entry {
    bool in_use;
    uint8_t family;
    uint8_t proto;
    uint16_t total_len;
    bool have_last;
    uint32_t id;
    struct in_addr src4;
    struct in_addr dst4;
    struct in6_addr src6;
    struct in6_addr dst6;
    uint64_t last_seen_tsc;
    uint32_t range_count;
    struct nat64_frag_range ranges[NAT64_FRAG_MAX_RANGES];
    uint8_t data[NAT64_FRAG_MAX_PAYLOAD];
};

struct nat64_nexthop4_state {
    bool configured;
    bool l2_up;
    bool l3_up;
    bool awaiting_reply;
    bool force_probe;
    struct in_addr target;
    uint16_t echo_id;
    uint16_t next_seq;
    uint16_t last_seq_sent;
    uint64_t last_l2_probe_tsc;
    uint64_t last_l3_probe_tsc;
    uint64_t last_l2_success_tsc;
    uint64_t last_l3_success_tsc;
    uint64_t last_l2_success_unix;
    uint64_t last_l3_success_unix;
    uint64_t l2_probes_sent;
    uint64_t l3_probes_sent;
    uint64_t l3_replies_rcvd;
};

struct nat64_nexthop6_state {
    bool configured;
    bool l2_up;
    bool l3_up;
    bool awaiting_reply;
    bool force_probe;
    struct in6_addr target;
    uint16_t echo_id;
    uint16_t next_seq;
    uint16_t last_seq_sent;
    uint64_t last_l2_probe_tsc;
    uint64_t last_l3_probe_tsc;
    uint64_t last_l2_success_tsc;
    uint64_t last_l3_success_tsc;
    uint64_t last_l2_success_unix;
    uint64_t last_l3_success_unix;
    uint64_t l2_probes_sent;
    uint64_t l3_probes_sent;
    uint64_t l3_replies_rcvd;
};

struct nat64_nexthop_stats_snapshot {
    bool configured;
    bool l2_up;
    bool l3_up;
    uint64_t last_l2_success_unix;
    uint64_t last_l3_success_unix;
    uint64_t l2_probes_sent;
    uint64_t l3_probes_sent;
    uint64_t l3_replies_rcvd;
};

struct nat64_ping6_state {
    bool active;
    bool done;
    bool route_found;
    bool direct;
    bool l2_up;
    char error[64];
    struct in6_addr target;
    struct in6_addr neigh_ip;
    uint16_t echo_id;
    uint16_t count;
    uint16_t sent;
    uint16_t received;
    uint16_t next_seq;
    uint64_t received_bitmap;
    uint64_t started_unix;
    uint64_t finished_unix;
    uint64_t last_l2_probe_tsc;
    uint64_t last_send_tsc;
    uint64_t last_reply_tsc;
    uint64_t last_reply_unix;
    uint64_t l2_probes_sent;
};

enum nat64_probe4_mode {
    NAT64_PROBE4_NONE = 0,
    NAT64_PROBE4_PING = 1,
    NAT64_PROBE4_TCP = 2,
    NAT64_PROBE4_HTTP = 3,
};

struct nat64_probe4_state {
    bool active;
    bool done;
    bool route_found;
    bool direct;
    bool l2_up;
    bool tcp_connected;
    bool http_request_sent;
    enum nat64_probe4_mode mode;
    char error[64];
    char http_host[128];
    char http_path[256];
    struct in_addr source;
    struct in_addr target;
    struct in_addr neigh_ip;
    uint16_t target_port;
    uint16_t source_port;
    uint16_t echo_id;
    uint16_t count;
    uint16_t sent;
    uint16_t received;
    uint16_t next_seq_icmp;
    uint32_t tcp_seq;
    uint32_t tcp_next_seq;
    uint32_t tcp_peer_next_seq;
    uint16_t http_status;
    uint32_t http_bytes;
    uint64_t started_unix;
    uint64_t finished_unix;
    uint64_t last_l2_probe_tsc;
    uint64_t last_send_tsc;
    uint64_t last_reply_tsc;
    uint64_t last_reply_unix;
    uint64_t l2_probes_sent;
};

struct nat64_stats_snapshot {
    uint64_t v6_to_v4_packets;
    uint64_t v6_to_v4_bytes;
    uint64_t v4_to_v6_packets;
    uint64_t v4_to_v6_bytes;
    uint64_t v6_to_v4_pps;
    uint64_t v6_to_v4_bps;
    uint64_t v4_to_v6_pps;
    uint64_t v4_to_v6_bps;
    uint64_t sessions_created;
    uint64_t sessions_expired;
    uint64_t frag_received;
    uint64_t frag_reassembled;
    uint64_t frag_emitted;
    uint64_t frag_dropped;
    uint64_t frag_expired;
    uint32_t frag_active;
    uint64_t icmp_error_v4_to_v6;
    uint64_t icmp_error_v6_to_v4;
    uint64_t icmp_error_v6_outer_src_pref64;
    uint64_t icmp_error_v6_outer_src_translator;
    uint64_t h323_packets_v6_to_v4;
    uint64_t h323_packets_v4_to_v6;
    uint64_t h323_rewrites_v6_to_v4;
    uint64_t h323_rewrites_v4_to_v6;
    uint64_t h323_failures;
    uint64_t acl_permit_v6_to_v4;
    uint64_t acl_deny_v6_to_v4;
    uint64_t acl_permit_v4_to_v6;
    uint64_t acl_deny_v4_to_v6;
    uint64_t subscriber_allowed_total;
    uint64_t subscriber_drop_max_sessions;
    uint64_t subscriber_drop_rate_limit;
    uint64_t subscriber_drop_no_entry;
    uint64_t subscriber_active_count;
    uint32_t sessions_active;
    uint32_t neighbors4_active;
    uint32_t neighbors6_active;
    uint16_t queue_count;
    struct nat64_link_state links[2];
    struct nat64_nexthop_stats_snapshot nexthops[2];
    struct nat64_port_stats_snapshot ports[NAT64_STATS_PORT_COUNT];
    struct nat64_worker_stats_snapshot workers[NAT64_MAX_WORKERS];
};

struct nat64_subscriber_entry {
    bool in_use;
    struct in6_addr prefix;
    uint8_t prefix_len;
    uint32_t rule_index;
    uint32_t active_sessions;
    uint64_t tokens_q32;
    uint64_t last_refill_tsc;
    uint64_t last_seen_tsc;
    uint64_t allowed_total;
    uint64_t drop_max_sessions;
    uint64_t drop_rate_limit;
};

struct nat64_subscriber_snapshot {
    bool in_use;
    struct in6_addr prefix;
    uint8_t prefix_len;
    uint32_t rule_index;
    char rule_name[32];
    uint32_t active_sessions;
    uint32_t max_sessions;
    uint32_t new_conn_per_sec;
    uint32_t burst;
    uint64_t allowed_total;
    uint64_t drop_max_sessions;
    uint64_t drop_rate_limit;
    uint64_t age_sec;
};

struct rte_acl_ctx;

struct nat64_acl_classifier {
    struct rte_acl_ctx *ctx;
    bool has_rules;
    bool default_permit;
    uint8_t actions[NAT64_MAX_ACL_RULES];
    uint32_t rule_indices[NAT64_MAX_ACL_RULES];
    uint32_t rule_count;
};

struct nat64_service_runtime {
    const struct nat64_service_config *cfg;
    struct nat64_acl_classifier acl_v6_to_v4;
    struct nat64_acl_classifier acl_v4_to_v6;
};

struct nat64_acl_runtime_set {
    struct nat64_service_runtime service_runtime[NAT64_MAX_SERVICES];
    uint32_t service_runtime_count;
    uint64_t generation;
};

struct nat64_ctx {
    const struct nat64_config *cfg;
    struct nat64_config *mutable_cfg;
    char config_path[260];
    const struct nat64_service_config *service;
    struct nat64_service_runtime service_runtime[NAT64_MAX_SERVICES];
    uint32_t service_runtime_count;
    struct nat64_acl_runtime_set *acl_active;
    struct nat64_acl_runtime_set *acl_deferred_free;
    uint64_t acl_deferred_generation;
    uint64_t acl_reader_generations[NAT64_ACL_READER_SLOTS];
    uint64_t acl_generation;
    uint64_t acl_reload_success;
    uint64_t acl_reload_failure;
    uint64_t acl_reclaim_success;
    uint64_t acl_reclaim_deferred;
    rte_spinlock_t acl_update_lock;
    uint64_t acl_rule_hits[NAT64_MAX_WORKERS][NAT64_MAX_SERVICES][2][NAT64_ACL_HIT_SLOTS];
    struct nat64_runtime_opts opts;
    struct rte_mempool *mbuf_pool;
    uint16_t port_v6;
    uint16_t port_v4;
    struct rte_ether_addr port_v6_mac;
    struct rte_ether_addr port_v4_mac;
    uint64_t port_v6_tx_offloads;
    uint64_t port_v4_tx_offloads;
    uint16_t port_v6_mtu;
    uint16_t port_v4_mtu;
    struct in6_addr port_v6_addr;
    uint8_t port_v6_prefix_len;
    struct in_addr port_v4_addr;
    uint8_t port_v4_prefix_len;
    struct nat64_session sessions[NAT64_MAX_SESSIONS];
    struct nat64_neighbor4 neighbors4[NAT64_MAX_NEIGHBORS];
    struct nat64_neighbor6 neighbors6[NAT64_MAX_NEIGHBORS];
    struct nat64_frag_entry *frag_entries;
    uint32_t frag_entry_count;
    struct nat64_laddr_state laddr_state[NAT64_MAX_LADDRS];
    uint32_t laddr_state_count;
    struct nat64_link_state links[2];
    struct nat64_nexthop4_state probe4;
    struct nat64_nexthop6_state probe6;
    struct nat64_ping6_state ping6;
    struct nat64_probe4_state active_probe4;
    struct nat64_subscriber_entry *subscriber_entries;
    uint32_t subscriber_entry_count;
    rte_spinlock_t session_locks[NAT64_SESSION_SHARDS];
    rte_spinlock_t neigh4_locks[NAT64_NEIGHBOR_SHARDS];
    rte_spinlock_t neigh6_locks[NAT64_NEIGHBOR_SHARDS];
    rte_spinlock_t frag_lock;
    rte_spinlock_t ping6_lock;
    rte_spinlock_t probe4_lock;
    rte_spinlock_t laddr_lock;
    rte_spinlock_t route_lock;
    rte_spinlock_t audit_lock;
    rte_spinlock_t subscriber_locks[NAT64_SUBSCRIBER_SHARDS];
    bool audit_enabled;
    int audit_fd;
    char audit_path[260];
    uint64_t audit_rotate_bytes;
    uint64_t audit_written_bytes;
    uint32_t rr_rs;
    uint32_t rr_laddr;
    uint32_t session_generation;
    uint64_t tsc_hz;
    uint64_t session_timeout_tsc;
    uint64_t neighbor_timeout_tsc;
    uint64_t arp_refresh_tsc;
    uint64_t arp_defend_tsc;
    uint64_t link_poll_tsc;
    uint64_t last_link_poll_tsc;
    uint64_t stats_sessions_created;
    uint64_t stats_sessions_expired;
    uint64_t stats_subscriber_allowed;
    uint64_t stats_subscriber_drop_max_sessions;
    uint64_t stats_subscriber_drop_rate_limit;
    uint64_t stats_subscriber_drop_no_entry;
    uint64_t stats_frag_received;
    uint64_t stats_frag_reassembled;
    uint64_t stats_frag_emitted;
    uint64_t stats_frag_dropped;
    uint64_t stats_frag_expired;
    uint64_t stats_icmp_error_v4_to_v6;
    uint64_t stats_icmp_error_v6_to_v4;
    uint64_t stats_icmp_error_v6_outer_src_pref64;
    uint64_t stats_icmp_error_v6_outer_src_translator;
    uint64_t stats_h323_packets_v6_to_v4;
    uint64_t stats_h323_packets_v4_to_v6;
    uint64_t stats_h323_rewrites_v6_to_v4;
    uint64_t stats_h323_rewrites_v4_to_v6;
    uint64_t stats_h323_failures;
    uint32_t frag_next_ipv4_id;
    uint32_t frag_next_ipv6_id;
    uint64_t stats_prev_v6_to_v4_packets;
    uint64_t stats_prev_v6_to_v4_bytes;
    uint64_t stats_prev_v4_to_v6_packets;
    uint64_t stats_prev_v4_to_v6_bytes;
    uint64_t stats_last_rate_tsc;
    uint64_t stats_v6_to_v4_pps;
    uint64_t stats_v6_to_v4_bps;
    uint64_t stats_v4_to_v6_pps;
    uint64_t stats_v4_to_v6_bps;
    uint64_t stats_port_prev_packets[NAT64_STATS_PORT_COUNT][NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
    uint64_t stats_port_prev_bytes[NAT64_STATS_PORT_COUNT][NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
    uint64_t stats_port_pps[NAT64_STATS_PORT_COUNT][NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
    uint64_t stats_port_bps[NAT64_STATS_PORT_COUNT][NAT64_STATS_DIR_COUNT][NAT64_STATS_FAMILY_COUNT];
    uint64_t worker_prev_busy_cycles[NAT64_MAX_WORKERS];
    uint64_t worker_prev_total_cycles[NAT64_MAX_WORKERS];
    uint64_t worker_busy_pct[NAT64_MAX_WORKERS];
    uint32_t worker_lcore_id[NAT64_MAX_WORKERS];
    struct nat64_worker_hot_stats worker_stats[NAT64_MAX_WORKERS];
    struct nat64_neighbor4_cache neigh4_cache[NAT64_MAX_WORKERS];
    struct nat64_neighbor6_cache neigh6_cache[NAT64_MAX_WORKERS];
    struct nat64_session_cache_entry session_v6_cache[NAT64_MAX_WORKERS][NAT64_SESSION_CACHE_SIZE];
    struct nat64_session_cache_entry session_v4_cache[NAT64_MAX_WORKERS][NAT64_SESSION_CACHE_SIZE];
    uint16_t queue_count;
    struct nat64_capture_state capture;
    struct nat64_route_table route_tables[2];
    const struct nat64_route_table *active_routes;
    uint32_t active_route_table;
    uint64_t route_reader_generations[NAT64_ROUTE_READER_SLOTS];
    int64_t route_last_seen_mtime_sec;
    int64_t route_last_seen_mtime_nsec;
};

int nat64_ctx_init(struct nat64_ctx *ctx, const struct nat64_config *cfg, struct rte_mempool *pool,
                   uint16_t port_v6, uint16_t port_v4, uint32_t net_v6_idx, uint32_t net_v4_idx,
                   uint64_t port_v6_tx_offloads, uint64_t port_v4_tx_offloads,
                   const struct nat64_runtime_opts *opts);
void nat64_process_burst(struct nat64_ctx *ctx, uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts,
                         uint16_t nb_pkts);
void nat64_age_entries(struct nat64_ctx *ctx, uint64_t now_tsc);
void nat64_periodic(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc);
void nat64_get_stats_snapshot(struct nat64_ctx *ctx, struct nat64_stats_snapshot *out);
uint32_t nat64_dump_sessions(struct nat64_ctx *ctx, struct nat64_session *sessions, uint32_t max_sessions);
uint32_t nat64_dump_sessions_filtered(struct nat64_ctx *ctx,
                                      const struct nat64_session_filter *filter,
                                      uint32_t offset, struct nat64_session *sessions,
                                      uint32_t max_sessions, uint32_t *matched_total);
void nat64_dump_neighbors(struct nat64_ctx *ctx,
                          struct nat64_neighbor4 *neighbors4, uint32_t *count4, uint32_t max4,
                          struct nat64_neighbor6 *neighbors6, uint32_t *count6, uint32_t max6);
uint32_t nat64_dump_subscribers(struct nat64_ctx *ctx, struct nat64_subscriber_snapshot *subscribers,
                                uint32_t offset, uint32_t max_subscribers, uint32_t *matched_total);
void nat64_note_worker_cycles(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t busy_cycles, uint64_t total_cycles);
void nat64_trigger_nexthop_probe(struct nat64_ctx *ctx);
int nat64_start_ping6(struct nat64_ctx *ctx, const struct in6_addr *target, uint16_t count);
void nat64_get_ping6_state(struct nat64_ctx *ctx, struct nat64_ping6_state *out);
int nat64_start_probe4(struct nat64_ctx *ctx, enum nat64_probe4_mode mode, const struct in_addr *source,
                       const struct in_addr *target, uint16_t target_port, uint16_t count,
                       const char *http_host, const char *http_path);
void nat64_get_probe4_state(struct nat64_ctx *ctx, struct nat64_probe4_state *out);
void nat64_audit_cleanup(struct nat64_ctx *ctx);
void nat64_subscriber_cleanup(struct nat64_ctx *ctx);

#endif
