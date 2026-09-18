#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_hash_crc.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_net.h>
#include <rte_arp.h>
#include <rte_pause.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "acl.h"
#include "nat64.h"

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif

#define ND_NEIGHBOR_SOLICIT 135
#define ND_NEIGHBOR_ADVERT 136
#define ICMPV6_OPT_TARGET_LINKADDR 2
#define ICMPV6_OPT_SOURCE_LINKADDR 1
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PACKET_TOO_BIG 2
#define ICMPV6_TIME_EXCEEDED 3
#define ICMPV6_PARAM_PROB 4
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_CODE_NOROUTE 0
#define ICMPV6_CODE_ADMIN_PROHIBITED 1
#define ICMPV6_CODE_ADDR_UNREACH 3
#define ICMPV6_CODE_PORT_UNREACH 4
#define ICMPV6_TIME_EXCEED_TRANSIT 0
#define ICMPV6_TIME_EXCEED_REASSEMBLY 1
#define ICMPV6_PARAMPROB_HEADER 0

#define ICMPV4_DEST_UNREACH 3
#define ICMPV4_SOURCE_QUENCH 4
#define ICMPV4_REDIRECT 5
#define ICMPV4_ECHO_REQUEST 8
#define ICMPV4_TIME_EXCEEDED 11
#define ICMPV4_PARAM_PROB 12
#define ICMPV4_ECHO_REPLY 0
#define ICMPV4_CODE_NET_UNREACH 0
#define ICMPV4_CODE_HOST_UNREACH 1
#define ICMPV4_CODE_PROTOCOL_UNREACH 2
#define ICMPV4_CODE_PORT_UNREACH 3
#define ICMPV4_CODE_FRAG_NEEDED 4
#define ICMPV4_CODE_ADMIN_PROHIBITED 13

#define SIP_PORT 5060
#define SIP_TLS_PORT 5061
#define NAT64_SIP_MAX_PAYLOAD 8192
#define H323_RAS_PORT 1719
#define H323_H225_PORT 1720
#define NAT64_H323_MAX_PAYLOAD 8192
#define NAT64_ROUTE_RECLAIM_WAIT_LOOPS 1000000U
#define NAT64_PROBE4_TCP_SOURCE_PORT_BASE 61000U
#define NAT64_TCP_FIN_FLAG 0x01
#define NAT64_TCP_SYN_FLAG 0x02
#define NAT64_TCP_RST_FLAG 0x04
#define NAT64_TCP_PSH_FLAG 0x08
#define NAT64_TCP_ACK_FLAG 0x10
#define NAT64_PROBE4_CONSUMED ((struct rte_mbuf *) (uintptr_t) 1)

#ifndef RTE_IPV4_HDR_MF_FLAG
#define RTE_IPV4_HDR_MF_FLAG 0x2000
#endif
#ifndef RTE_IPV4_HDR_OFFSET_MASK
#define RTE_IPV4_HDR_OFFSET_MASK 0x1fff
#endif
#ifndef RTE_ETHER_MTU
#define RTE_ETHER_MTU 1500
#endif

struct icmp_error_hdr {
    uint8_t type;
    uint8_t code;
    rte_be16_t checksum;
    rte_be32_t data;
} __attribute__((packed));

struct nd_msg {
    uint8_t type;
    uint8_t code;
    rte_be16_t checksum;
    rte_be32_t flags;
    uint8_t target[16];
};

struct nd_opt_lladdr {
    uint8_t type;
    uint8_t len;
    struct rte_ether_addr addr;
} __attribute__((packed));

struct ipv6_frag_hdr {
    uint8_t next_header;
    uint8_t reserved;
    rte_be16_t frag_data;
    rte_be32_t id;
} __attribute__((packed));

static void emit_single(struct nat64_ctx *ctx, struct rte_mbuf *m, uint16_t tx_port, uint16_t queue_id);
static int laddr_index(const struct nat64_ctx *ctx, struct in_addr ip);
static void format_mac(const struct rte_ether_addr *mac, char *buf, size_t len);
static bool route_lookup4_ctx(struct nat64_ctx *ctx, uint16_t queue_id, struct in_addr dst,
                              struct nat64_route4_entry *out);
static bool route_lookup6_ctx(struct nat64_ctx *ctx, uint16_t queue_id, const struct in6_addr *dst,
                              struct nat64_route6_entry *out);
static struct in_addr probe_source_v4(const struct nat64_ctx *ctx);
static uint64_t now_unix_sec(void);
static bool is_local_v4(const struct nat64_ctx *ctx, rte_be32_t ip_be);
static void refresh_nexthop_targets(struct nat64_ctx *ctx);
static void nexthop_probe_tick(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc);
static void ping6_tick(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc);
static void active_probe4_tick(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc);
static bool handle_icmpv4_probe_reply(struct nat64_ctx *ctx, struct rte_mbuf *m);
static bool handle_icmpv6_probe_reply(struct nat64_ctx *ctx, struct rte_mbuf *m);
static bool handle_ping6_reply(struct nat64_ctx *ctx, struct rte_mbuf *m);
static struct rte_mbuf *handle_active_probe4_reply(struct nat64_ctx *ctx, struct rte_mbuf *m);
static struct rte_mbuf *build_arp_request(struct nat64_ctx *ctx, struct in_addr sender, struct in_addr target);
static struct rte_mbuf *translate_icmpv4_error_to_v6(struct nat64_ctx *ctx, struct rte_ipv4_hdr *ip4,
                                                     const struct rte_ether_addr *src_mac, uint16_t ip4_payload);
static struct rte_mbuf *translate_icmpv6_error_to_v4(struct nat64_ctx *ctx, uint16_t queue_id,
                                                     struct rte_ipv6_hdr *ip6,
                                                     const struct rte_ether_addr *src_mac, uint16_t ip6_payload);

static const struct rte_ether_addr ether_broadcast_addr = {
    .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

static const struct rte_ether_addr ether_zero_addr = {
    .addr_bytes = {0, 0, 0, 0, 0, 0}
};

static int stats_port_index(struct nat64_ctx *ctx, uint16_t port_id)
{
    if (port_id == ctx->port_v6) {
        return 0;
    }
    if (port_id == ctx->port_v4) {
        return 1;
    }
    return -1;
}

static uint8_t stats_family_from_ether_type(uint16_t ether_type)
{
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        return NAT64_STATS_FAMILY_IPV4;
    }
    if (ether_type == RTE_ETHER_TYPE_IPV6) {
        return NAT64_STATS_FAMILY_IPV6;
    }
    return NAT64_STATS_FAMILY_COUNT;
}

static struct nat64_worker_hot_stats *worker_hot_stats(struct nat64_ctx *ctx, uint16_t queue_id)
{
    return queue_id < NAT64_MAX_WORKERS ? &ctx->worker_stats[queue_id] : NULL;
}

static void stats_note_port_traffic(struct nat64_ctx *ctx, uint16_t queue_id, uint16_t port_id, uint8_t dir,
                                    uint16_t ether_type, uint32_t packets, uint32_t bytes)
{
    struct nat64_worker_hot_stats *stats = worker_hot_stats(ctx, queue_id);
    int port_idx = stats_port_index(ctx, port_id);
    uint8_t family = stats_family_from_ether_type(ether_type);

    if (stats == NULL || port_idx < 0 || dir >= NAT64_STATS_DIR_COUNT) {
        return;
    }

    stats->port_packets[port_idx][dir][NAT64_STATS_FAMILY_TOTAL] += packets;
    stats->port_bytes[port_idx][dir][NAT64_STATS_FAMILY_TOTAL] += bytes;

    if (family < NAT64_STATS_FAMILY_COUNT) {
        stats->port_packets[port_idx][dir][family] += packets;
        stats->port_bytes[port_idx][dir][family] += bytes;
    }
}

void nat64_note_worker_cycles(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t busy_cycles,
                              uint64_t total_cycles)
{
    if (queue_id >= NAT64_MAX_WORKERS) {
        return;
    }
    ctx->worker_stats[queue_id].busy_cycles += busy_cycles;
    ctx->worker_stats[queue_id].total_cycles += total_cycles;
}

static uint32_t route_reader_slot(uint16_t queue_id)
{
    return queue_id < NAT64_MAX_WORKERS ? queue_id : NAT64_ROUTE_CONTROL_READER;
}

static const struct nat64_route_table *route_runtime_enter(struct nat64_ctx *ctx, uint16_t queue_id)
{
    const struct nat64_route_table *routes;
    uint32_t slot;
    uint64_t generation;

    if (ctx == NULL) {
        return NULL;
    }
    slot = route_reader_slot(queue_id);
    if (slot == NAT64_ROUTE_CONTROL_READER) {
        rte_spinlock_lock(&ctx->route_lock);
    }
    for (;;) {
        routes = __atomic_load_n(&ctx->active_routes, __ATOMIC_ACQUIRE);
        generation = routes == NULL ? 0 : routes->generation;
        __atomic_store_n(&ctx->route_reader_generations[slot], generation, __ATOMIC_RELEASE);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (__atomic_load_n(&ctx->active_routes, __ATOMIC_ACQUIRE) == routes) {
            return routes;
        }
        __atomic_store_n(&ctx->route_reader_generations[slot], 0, __ATOMIC_RELEASE);
        rte_pause();
    }
}

static void route_runtime_exit(struct nat64_ctx *ctx, uint16_t queue_id)
{
    if (ctx == NULL) {
        return;
    }
    uint32_t slot = route_reader_slot(queue_id);

    __atomic_store_n(&ctx->route_reader_generations[slot], 0, __ATOMIC_RELEASE);
    if (slot == NAT64_ROUTE_CONTROL_READER) {
        rte_spinlock_unlock(&ctx->route_lock);
    }
}

static bool route_readers_past_generation(struct nat64_ctx *ctx, uint64_t generation)
{
    for (uint32_t i = 0; i < NAT64_ROUTE_READER_SLOTS; i++) {
        uint64_t reader_generation = __atomic_load_n(&ctx->route_reader_generations[i], __ATOMIC_ACQUIRE);

        if (reader_generation != 0 && reader_generation <= generation) {
            return false;
        }
    }
    return true;
}

static bool route_wait_readers_past_generation(struct nat64_ctx *ctx, uint64_t generation)
{
    if (generation == 0) {
        return true;
    }
    for (uint32_t i = 0; i < NAT64_ROUTE_RECLAIM_WAIT_LOOPS; i++) {
        if (route_readers_past_generation(ctx, generation)) {
            return true;
        }
        rte_pause();
    }
    return route_readers_past_generation(ctx, generation);
}

static bool route_lookup4_ctx(struct nat64_ctx *ctx, uint16_t queue_id, struct in_addr dst,
                              struct nat64_route4_entry *out)
{
    const struct nat64_route_table *routes = route_runtime_enter(ctx, queue_id);
    struct nat64_route4_entry tmp;
    bool found = routes != NULL && routes->enabled && nat64_route_lookup4(routes, dst, out != NULL ? out : &tmp);

    route_runtime_exit(ctx, queue_id);
    return found;
}

static bool route_lookup6_ctx(struct nat64_ctx *ctx, uint16_t queue_id, const struct in6_addr *dst,
                              struct nat64_route6_entry *out)
{
    const struct nat64_route_table *routes = route_runtime_enter(ctx, queue_id);
    struct nat64_route6_entry tmp;
    bool found = routes != NULL && routes->enabled && nat64_route_lookup6(routes, dst, out != NULL ? out : &tmp);

    route_runtime_exit(ctx, queue_id);
    return found;
}

static struct in_addr session_v4_neigh_ip(struct nat64_ctx *ctx, uint16_t queue_id, struct nat64_session *sess)
{
    const struct nat64_route_table *routes = route_runtime_enter(ctx, queue_id);
    uint64_t generation = routes == NULL ? 0 : routes->generation;
    uint64_t cached_generation = __atomic_load_n(&sess->route4_generation, __ATOMIC_ACQUIRE);

    if (sess->route4_cached && cached_generation == generation) {
        route_runtime_exit(ctx, queue_id);
        return sess->route4_neigh_ip;
    }

    struct nat64_route4_entry route4;
    struct in_addr neigh_ip = sess->rs_v4;
    bool found = routes != NULL && routes->enabled && nat64_route_lookup4(routes, sess->rs_v4, &route4);

    if (found && !route4.direct) {
        neigh_ip = route4.via;
    }
    sess->route4_neigh_ip = neigh_ip;
    sess->route4_found = found;
    sess->route4_cached = true;
    __atomic_store_n(&sess->route4_generation, generation, __ATOMIC_RELEASE);
    route_runtime_exit(ctx, queue_id);
    return neigh_ip;
}

static struct in6_addr session_v6_neigh_ip(struct nat64_ctx *ctx, uint16_t queue_id, struct nat64_session *sess)
{
    const struct nat64_route_table *routes = route_runtime_enter(ctx, queue_id);
    uint64_t generation = routes == NULL ? 0 : routes->generation;
    uint64_t cached_generation = __atomic_load_n(&sess->route6_generation, __ATOMIC_ACQUIRE);

    if (sess->route6_cached && cached_generation == generation) {
        route_runtime_exit(ctx, queue_id);
        return sess->route6_neigh_ip;
    }

    struct nat64_route6_entry route6;
    struct in6_addr neigh_ip = sess->client_v6;
    bool found = routes != NULL && routes->enabled && nat64_route_lookup6(routes, &sess->client_v6, &route6);

    if (found && !route6.direct) {
        neigh_ip = route6.via;
    }
    sess->route6_neigh_ip = neigh_ip;
    sess->route6_found = found;
    sess->route6_cached = true;
    __atomic_store_n(&sess->route6_generation, generation, __ATOMIC_RELEASE);
    route_runtime_exit(ctx, queue_id);
    return neigh_ip;
}

static struct in_addr probe_source_v4(const struct nat64_ctx *ctx)
{
    if (ctx->port_v4_addr.s_addr != 0) {
        return ctx->port_v4_addr;
    }
    if (ctx->service != NULL && ctx->service->laddr_count > 0) {
        return ctx->service->laddr[0].prefix.addr;
    }
    return (struct in_addr) {0};
}

static uint64_t now_unix_sec(void)
{
    time_t now = time(NULL);

    return now < 0 ? 0 : (uint64_t) now;
}

static void nexthop4_mark_l2_success(struct nat64_ctx *ctx, uint64_t now_tsc)
{
    ctx->probe4.l2_up = true;
    ctx->probe4.last_l2_success_tsc = now_tsc;
    ctx->probe4.last_l2_success_unix = now_unix_sec();
}

static void nexthop6_mark_l2_success(struct nat64_ctx *ctx, uint64_t now_tsc)
{
    ctx->probe6.l2_up = true;
    ctx->probe6.last_l2_success_tsc = now_tsc;
    ctx->probe6.last_l2_success_unix = now_unix_sec();
}

static void nexthop4_mark_l3_success(struct nat64_ctx *ctx, uint64_t now_tsc)
{
    nexthop4_mark_l2_success(ctx, now_tsc);
    ctx->probe4.l3_up = true;
    ctx->probe4.awaiting_reply = false;
    ctx->probe4.last_l3_success_tsc = now_tsc;
    ctx->probe4.last_l3_success_unix = now_unix_sec();
    ctx->probe4.l3_replies_rcvd++;
}

static void nexthop6_mark_l3_success(struct nat64_ctx *ctx, uint64_t now_tsc)
{
    nexthop6_mark_l2_success(ctx, now_tsc);
    ctx->probe6.l3_up = true;
    ctx->probe6.awaiting_reply = false;
    ctx->probe6.last_l3_success_tsc = now_tsc;
    ctx->probe6.last_l3_success_unix = now_unix_sec();
    ctx->probe6.l3_replies_rcvd++;
}

int nat64_start_ping6(struct nat64_ctx *ctx, const struct in6_addr *target, uint16_t count)
{
    struct nat64_route6_entry route6;
    struct nat64_ping6_state next;
    bool found;

    if (ctx == NULL || target == NULL || count == 0 || count > NAT64_PING6_MAX_COUNT) {
        return -EINVAL;
    }
    if (IN6_IS_ADDR_UNSPECIFIED(target) || IN6_IS_ADDR_MULTICAST(target)) {
        return -EINVAL;
    }

    memset(&next, 0, sizeof(next));
    next.active = true;
    next.target = *target;
    next.count = count;
    next.echo_id = 0x7066;
    next.next_seq = 1;
    next.started_unix = now_unix_sec();

    found = route_lookup6_ctx(ctx, NAT64_ROUTE_CONTROL_READER, target, &route6);
    next.route_found = found;
    if (!found) {
        next.done = true;
        next.finished_unix = next.started_unix;
        snprintf(next.error, sizeof(next.error), "no IPv6 route");
    } else if (route6.direct) {
        next.direct = true;
        next.neigh_ip = *target;
    } else {
        next.direct = false;
        next.neigh_ip = route6.via;
    }

    rte_spinlock_lock(&ctx->ping6_lock);
    ctx->ping6 = next;
    rte_spinlock_unlock(&ctx->ping6_lock);
    return 0;
}

void nat64_get_ping6_state(struct nat64_ctx *ctx, struct nat64_ping6_state *out)
{
    if (ctx == NULL || out == NULL) {
        return;
    }

    rte_spinlock_lock(&ctx->ping6_lock);
    *out = ctx->ping6;
    rte_spinlock_unlock(&ctx->ping6_lock);
}

static uint16_t probe4_source_port(const struct in_addr *source, const struct in_addr *target, uint16_t target_port)
{
    uint32_t hash = 0x64040000U;

    hash ^= rte_be_to_cpu_32(source->s_addr);
    hash = rte_hash_crc_4byte(rte_be_to_cpu_32(target->s_addr), hash);
    hash ^= target_port;
    return (uint16_t) (NAT64_PROBE4_TCP_SOURCE_PORT_BASE + (hash % 1000U));
}

int nat64_start_probe4(struct nat64_ctx *ctx, enum nat64_probe4_mode mode, const struct in_addr *source,
                       const struct in_addr *target, uint16_t target_port, uint16_t count,
                       const char *http_host, const char *http_path)
{
    struct nat64_route4_entry route4;
    struct nat64_probe4_state next;
    bool found;

    if (ctx == NULL || target == NULL || count == 0 || count > NAT64_PROBE4_MAX_COUNT) {
        return -EINVAL;
    }
    if (mode != NAT64_PROBE4_PING && mode != NAT64_PROBE4_TCP && mode != NAT64_PROBE4_HTTP) {
        return -EINVAL;
    }
    if ((mode == NAT64_PROBE4_TCP || mode == NAT64_PROBE4_HTTP) && target_port == 0) {
        return -EINVAL;
    }
    if (target->s_addr == 0 || IN_MULTICAST(rte_be_to_cpu_32(target->s_addr))) {
        return -EINVAL;
    }

    memset(&next, 0, sizeof(next));
    next.active = true;
    next.mode = mode;
    next.source = source != NULL && source->s_addr != 0 ? *source : probe_source_v4(ctx);
    next.target = *target;
    next.target_port = target_port;
    next.count = count;
    next.echo_id = 0x7044;
    next.next_seq_icmp = 1;
    next.tcp_seq = 0x64040000U ^ (uint32_t) rte_get_tsc_cycles();
    next.tcp_next_seq = next.tcp_seq;
    next.started_unix = now_unix_sec();

    if (next.source.s_addr == 0 || !is_local_v4(ctx, next.source.s_addr)) {
        next.done = true;
        next.finished_unix = next.started_unix;
        snprintf(next.error, sizeof(next.error), "source is not a local IPv4 address");
    } else {
        found = route_lookup4_ctx(ctx, NAT64_ROUTE_CONTROL_READER, *target, &route4);
        next.route_found = found;
        if (!found) {
            next.done = true;
            next.finished_unix = next.started_unix;
            snprintf(next.error, sizeof(next.error), "no IPv4 route");
        } else if (route4.direct) {
            next.direct = true;
            next.neigh_ip = *target;
        } else {
            next.direct = false;
            next.neigh_ip = route4.via;
        }
    }

    if (mode == NAT64_PROBE4_TCP || mode == NAT64_PROBE4_HTTP) {
        next.source_port = probe4_source_port(&next.source, target, target_port);
    }
    if (mode == NAT64_PROBE4_HTTP) {
        if (http_host == NULL || http_host[0] == '\0' || http_path == NULL || http_path[0] == '\0') {
            return -EINVAL;
        }
        rte_strscpy(next.http_host, http_host, sizeof(next.http_host));
        rte_strscpy(next.http_path, http_path, sizeof(next.http_path));
    }

    rte_spinlock_lock(&ctx->probe4_lock);
    ctx->active_probe4 = next;
    rte_spinlock_unlock(&ctx->probe4_lock);
    return 0;
}

void nat64_get_probe4_state(struct nat64_ctx *ctx, struct nat64_probe4_state *out)
{
    if (ctx == NULL || out == NULL) {
        return;
    }

    rte_spinlock_lock(&ctx->probe4_lock);
    *out = ctx->active_probe4;
    rte_spinlock_unlock(&ctx->probe4_lock);
}

static void update_nexthop4_target(struct nat64_ctx *ctx, bool configured, struct in_addr target)
{
    if (!configured) {
        memset(&ctx->probe4, 0, sizeof(ctx->probe4));
        ctx->probe4.echo_id = 0x6404;
        return;
    }
    if (!ctx->probe4.configured || ctx->probe4.target.s_addr != target.s_addr) {
        struct nat64_nexthop4_state next = {0};

        next.configured = true;
        next.target = target;
        next.echo_id = 0x6404;
        ctx->probe4 = next;
    }
}

static void update_nexthop6_target(struct nat64_ctx *ctx, bool configured, const struct in6_addr *target)
{
    if (!configured) {
        memset(&ctx->probe6, 0, sizeof(ctx->probe6));
        ctx->probe6.echo_id = 0x6406;
        return;
    }
    if (!ctx->probe6.configured || memcmp(&ctx->probe6.target, target, sizeof(*target)) != 0) {
        struct nat64_nexthop6_state next = {0};

        next.configured = true;
        next.target = *target;
        next.echo_id = 0x6406;
        ctx->probe6 = next;
    }
}

static void refresh_nexthop_targets(struct nat64_ctx *ctx)
{
    struct in_addr via4 = {0};
    struct in6_addr via6 = IN6ADDR_ANY_INIT;
    bool has4 = false;
    bool has6 = false;

    const struct nat64_route_table *routes = route_runtime_enter(ctx, NAT64_ROUTE_CONTROL_READER);

    if (routes != NULL && routes->enabled) {
        for (uint32_t i = 0; i < routes->ipv4_count; i++) {
            const struct nat64_route4_entry *entry = &routes->ipv4[i];

            if (entry->prefix.mask == 0 && !entry->direct) {
                via4 = entry->via;
                has4 = true;
                break;
            }
        }
        for (uint32_t i = 0; i < routes->ipv6_count; i++) {
            const struct nat64_route6_entry *entry = &routes->ipv6[i];

            if (entry->prefix.mask == 0 && !entry->direct) {
                via6 = entry->via;
                has6 = true;
                break;
            }
        }
    }

    route_runtime_exit(ctx, NAT64_ROUTE_CONTROL_READER);
    update_nexthop4_target(ctx, has4, via4);
    update_nexthop6_target(ctx, has6, &via6);
}

static void stats_add_forward(struct nat64_ctx *ctx, uint16_t queue_id, uint16_t tx_port, uint32_t packets,
                              uint32_t bytes)
{
    struct nat64_worker_hot_stats *stats = worker_hot_stats(ctx, queue_id);

    if (stats == NULL) {
        return;
    }
    if (tx_port == ctx->port_v4) {
        stats->v6_to_v4_packets += packets;
        stats->v6_to_v4_bytes += bytes;
    } else if (tx_port == ctx->port_v6) {
        stats->v4_to_v6_packets += packets;
        stats->v4_to_v6_bytes += bytes;
    }
}

static void stats_note_session_created(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_sessions_created, 1, __ATOMIC_RELAXED);
}

static void stats_note_session_expired(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_sessions_expired, 1, __ATOMIC_RELAXED);
}

static void stats_note_frag_received(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_frag_received, 1, __ATOMIC_RELAXED);
}

static void stats_note_frag_reassembled(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_frag_reassembled, 1, __ATOMIC_RELAXED);
}

static void stats_note_frag_emitted(struct nat64_ctx *ctx, uint64_t count)
{
    __atomic_fetch_add(&ctx->stats_frag_emitted, count, __ATOMIC_RELAXED);
}

static void stats_note_frag_dropped(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_frag_dropped, 1, __ATOMIC_RELAXED);
}

static void stats_note_frag_expired(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_frag_expired, 1, __ATOMIC_RELAXED);
}

static void stats_note_icmp_error_v4_to_v6(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_icmp_error_v4_to_v6, 1, __ATOMIC_RELAXED);
}

static void stats_note_icmp_error_v6_to_v4(struct nat64_ctx *ctx, bool outer_src_pref64)
{
    __atomic_fetch_add(&ctx->stats_icmp_error_v6_to_v4, 1, __ATOMIC_RELAXED);
    if (outer_src_pref64) {
        __atomic_fetch_add(&ctx->stats_icmp_error_v6_outer_src_pref64, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&ctx->stats_icmp_error_v6_outer_src_translator, 1, __ATOMIC_RELAXED);
    }
}

static void stats_note_h323_packet(struct nat64_ctx *ctx, bool v6_to_v4)
{
    __atomic_fetch_add(v6_to_v4 ? &ctx->stats_h323_packets_v6_to_v4 : &ctx->stats_h323_packets_v4_to_v6,
                       1, __ATOMIC_RELAXED);
}

static void stats_note_h323_rewrite(struct nat64_ctx *ctx, bool v6_to_v4)
{
    __atomic_fetch_add(v6_to_v4 ? &ctx->stats_h323_rewrites_v6_to_v4 : &ctx->stats_h323_rewrites_v4_to_v6,
                       1, __ATOMIC_RELAXED);
}

static void stats_note_h323_failure(struct nat64_ctx *ctx)
{
    __atomic_fetch_add(&ctx->stats_h323_failures, 1, __ATOMIC_RELAXED);
}

static const char *nat64_proto_name(uint8_t proto)
{
    switch (proto) {
    case IPPROTO_TCP:
        return "tcp";
    case IPPROTO_UDP:
        return "udp";
    case IPPROTO_ICMP:
        return "icmp";
    case IPPROTO_ICMPV6:
        return "icmpv6";
    default:
        return "other";
    }
}

static int audit_open_file(struct nat64_ctx *ctx)
{
    struct stat st;

    ctx->audit_fd = open(ctx->audit_path, O_CREAT | O_APPEND | O_WRONLY, 0640);
    if (ctx->audit_fd < 0) {
        return -errno;
    }
    if (fstat(ctx->audit_fd, &st) == 0 && st.st_size > 0) {
        ctx->audit_written_bytes = (uint64_t) st.st_size;
    } else {
        ctx->audit_written_bytes = 0;
    }
    return 0;
}

static void audit_rotate_if_needed(struct nat64_ctx *ctx, size_t next_len)
{
    time_t now;
    struct tm tm_now;
    char rotated[320];
    size_t path_len;

    if (!ctx->audit_enabled || ctx->audit_rotate_bytes == 0 ||
        ctx->audit_written_bytes + next_len <= ctx->audit_rotate_bytes) {
        return;
    }

    close(ctx->audit_fd);
    ctx->audit_fd = -1;
    now = time(NULL);
    localtime_r(&now, &tm_now);
    path_len = strlen(ctx->audit_path);
    if (strftime(rotated, sizeof(rotated), ".%Y%m%d-%H%M%S", &tm_now) != 0 &&
        path_len + strlen(rotated) < sizeof(rotated)) {
        memmove(rotated + path_len, rotated, strlen(rotated) + 1);
        memcpy(rotated, ctx->audit_path, path_len);
        rename(ctx->audit_path, rotated);
    }
    if (audit_open_file(ctx) < 0) {
        ctx->audit_enabled = false;
    }
}

static void audit_log_session(struct nat64_ctx *ctx, const char *event, const struct nat64_session *s,
                              uint64_t now_tsc)
{
    char client_v6[INET6_ADDRSTRLEN];
    char service_v6[INET6_ADDRSTRLEN];
    char local_v4[INET_ADDRSTRLEN];
    char rs_v4[INET_ADDRSTRLEN];
    char line[768];
    time_t now = time(NULL);
    uint64_t age_sec = 0;
    int len;

    if (!ctx->audit_enabled || ctx->audit_fd < 0) {
        return;
    }
    if (inet_ntop(AF_INET6, &s->client_v6, client_v6, sizeof(client_v6)) == NULL ||
        inet_ntop(AF_INET6, &s->service_v6, service_v6, sizeof(service_v6)) == NULL ||
        inet_ntop(AF_INET, &s->local_v4, local_v4, sizeof(local_v4)) == NULL ||
        inet_ntop(AF_INET, &s->rs_v4, rs_v4, sizeof(rs_v4)) == NULL) {
        return;
    }
    if (now_tsc > s->last_seen_tsc && ctx->tsc_hz != 0) {
        age_sec = (now_tsc - s->last_seen_tsc) / ctx->tsc_hz;
    }

    len = snprintf(line, sizeof(line),
                   "{\"ts\":%llu,\"event\":\"%s\",\"proto\":\"%s\",\"service_index\":%u,"
                   "\"client_v6\":\"%s\",\"client_port\":%u,"
                   "\"service_v6\":\"%s\",\"service_port\":%u,"
                   "\"local_v4\":\"%s\",\"local_port\":%u,"
                   "\"rs_v4\":\"%s\",\"rs_port\":%u,"
                   "\"created_ts\":%llu,\"idle_sec\":%llu}\n",
                   (unsigned long long) now, event, nat64_proto_name(s->proto), s->service_index,
                   client_v6, s->client_port,
                   service_v6, s->service_port,
                   local_v4, s->local_port,
                   rs_v4, s->rs_port,
                   (unsigned long long) s->created_unix,
                   (unsigned long long) age_sec);
    if (len <= 0 || (size_t) len >= sizeof(line)) {
        return;
    }

    rte_spinlock_lock(&ctx->audit_lock);
    audit_rotate_if_needed(ctx, (size_t) len);
    if (ctx->audit_enabled && ctx->audit_fd >= 0) {
        ssize_t written = write(ctx->audit_fd, line, (size_t) len);

        if (written > 0) {
            ctx->audit_written_bytes += (uint64_t) written;
        }
    }
    rte_spinlock_unlock(&ctx->audit_lock);
}

static int audit_init(struct nat64_ctx *ctx)
{
    int rc;

    ctx->audit_fd = -1;
    if (!ctx->cfg->audit.enabled) {
        return 0;
    }
    if (ctx->cfg->audit.file[0] == '\0') {
        return -EINVAL;
    }

    snprintf(ctx->audit_path, sizeof(ctx->audit_path), "%s", ctx->cfg->audit.file);
    ctx->audit_rotate_bytes = ctx->cfg->audit.rotate_bytes;
    rc = audit_open_file(ctx);
    if (rc < 0) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: failed to open audit log %s: %d\n", ctx->audit_path, rc);
        return rc;
    }
    ctx->audit_enabled = true;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
            "NAT audit log enabled: file=%s rotate_bytes=%llu\n",
            ctx->audit_path, (unsigned long long) ctx->audit_rotate_bytes);
    return 0;
}

static void stats_sum_workers(struct nat64_ctx *ctx, struct nat64_worker_hot_stats *out)
{
    memset(out, 0, sizeof(*out));
    for (uint32_t i = 0; i < ctx->queue_count && i < NAT64_MAX_WORKERS; i++) {
        const struct nat64_worker_hot_stats *stats = &ctx->worker_stats[i];

        out->v6_to_v4_packets += __atomic_load_n(&stats->v6_to_v4_packets, __ATOMIC_RELAXED);
        out->v6_to_v4_bytes += __atomic_load_n(&stats->v6_to_v4_bytes, __ATOMIC_RELAXED);
        out->v4_to_v6_packets += __atomic_load_n(&stats->v4_to_v6_packets, __ATOMIC_RELAXED);
        out->v4_to_v6_bytes += __atomic_load_n(&stats->v4_to_v6_bytes, __ATOMIC_RELAXED);
        out->acl_permit_v6_to_v4 += __atomic_load_n(&stats->acl_permit_v6_to_v4, __ATOMIC_RELAXED);
        out->acl_deny_v6_to_v4 += __atomic_load_n(&stats->acl_deny_v6_to_v4, __ATOMIC_RELAXED);
        out->acl_permit_v4_to_v6 += __atomic_load_n(&stats->acl_permit_v4_to_v6, __ATOMIC_RELAXED);
        out->acl_deny_v4_to_v6 += __atomic_load_n(&stats->acl_deny_v4_to_v6, __ATOMIC_RELAXED);
        out->busy_cycles += __atomic_load_n(&stats->busy_cycles, __ATOMIC_RELAXED);
        out->total_cycles += __atomic_load_n(&stats->total_cycles, __ATOMIC_RELAXED);

        for (uint32_t port = 0; port < NAT64_STATS_PORT_COUNT; port++) {
            for (uint32_t dir = 0; dir < NAT64_STATS_DIR_COUNT; dir++) {
                for (uint32_t family = 0; family < NAT64_STATS_FAMILY_COUNT; family++) {
                    out->port_packets[port][dir][family] +=
                        __atomic_load_n(&stats->port_packets[port][dir][family], __ATOMIC_RELAXED);
                    out->port_bytes[port][dir][family] +=
                        __atomic_load_n(&stats->port_bytes[port][dir][family], __ATOMIC_RELAXED);
                }
            }
        }
    }
}

static bool prefix96_match(const struct in6_addr *addr, const struct nat64_prefix6 *prefix)
{
    return prefix->mask == 96 && memcmp(addr->s6_addr, prefix->addr.s6_addr, 12) == 0;
}

static void prefix96_embed_v4(const struct nat64_prefix6 *prefix, struct in_addr v4, struct in6_addr *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->s6_addr, prefix->addr.s6_addr, 12);
    memcpy(out->s6_addr + 12, &v4.s_addr, sizeof(v4.s_addr));
}

static bool prefix96_extract_v4(const struct nat64_prefix6 *prefix, const struct in6_addr *addr, struct in_addr *out)
{
    if (!prefix96_match(addr, prefix)) {
        return false;
    }
    memcpy(&out->s_addr, addr->s6_addr + 12, sizeof(out->s_addr));
    return true;
}

static const struct nat64_service_config *service_by_index(const struct nat64_ctx *ctx, uint16_t index)
{
    if (ctx == NULL || ctx->cfg == NULL || index >= ctx->cfg->service_count ||
        index >= NAT64_MAX_SERVICES) {
        return ctx != NULL ? ctx->service : NULL;
    }
    return &ctx->cfg->services[index];
}

static const struct nat64_service_config *find_service_for_v6(const struct nat64_ctx *ctx,
                                                              const struct in6_addr *dst,
                                                              uint16_t *service_index)
{
    if (ctx == NULL || ctx->cfg == NULL || dst == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < ctx->cfg->service_count && i < NAT64_MAX_SERVICES; i++) {
        const struct nat64_service_config *service = &ctx->cfg->services[i];

        for (uint32_t j = 0; j < service->vs.vaddr_count; j++) {
            if (prefix96_match(dst, &service->vs.vaddr[j])) {
                if (service_index != NULL) {
                    *service_index = (uint16_t) i;
                }
                return service;
            }
        }
    }
    return NULL;
}

static bool icmpv4_is_error(uint8_t type)
{
    return type == ICMPV4_DEST_UNREACH || type == ICMPV4_TIME_EXCEEDED || type == ICMPV4_PARAM_PROB;
}

static bool icmpv6_is_error(uint8_t type)
{
    return type == ICMPV6_DEST_UNREACH || type == ICMPV6_PACKET_TOO_BIG ||
           type == ICMPV6_TIME_EXCEEDED || type == ICMPV6_PARAM_PROB;
}

static bool parse_cidr4(const char *raw, struct in_addr *addr, uint8_t *prefix_len)
{
    char buf[64];
    char *slash;
    unsigned long prefix;

    if (strlen(raw) >= sizeof(buf)) {
        return false;
    }
    strcpy(buf, raw);
    slash = strchr(buf, '/');
    if (slash == NULL) {
        return false;
    }
    *slash++ = '\0';
    if (inet_pton(AF_INET, buf, addr) != 1) {
        return false;
    }
    prefix = strtoul(slash, NULL, 10);
    if (prefix > 32) {
        return false;
    }
    *prefix_len = (uint8_t) prefix;
    return true;
}

static bool parse_cidr6(const char *raw, struct in6_addr *addr, uint8_t *prefix_len)
{
    char buf[96];
    char *slash;
    unsigned long prefix;

    if (strlen(raw) >= sizeof(buf)) {
        return false;
    }
    strcpy(buf, raw);
    slash = strchr(buf, '/');
    if (slash == NULL) {
        return false;
    }
    *slash++ = '\0';
    if (inet_pton(AF_INET6, buf, addr) != 1) {
        return false;
    }
    prefix = strtoul(slash, NULL, 10);
    if (prefix > 128) {
        return false;
    }
    *prefix_len = (uint8_t) prefix;
    return true;
}

static uint32_t checksum_add_bytes(uint32_t sum, const uint8_t *data, size_t len)
{
    while (len > 1) {
        sum += (uint32_t) (((uint16_t) data[0] << 8) | data[1]);
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint32_t) (((uint16_t) data[0]) << 8);
    }
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return rte_cpu_to_be_16((uint16_t) ~sum);
}

static uint32_t checksum_add_word(uint32_t sum, uint16_t word)
{
    sum += word;
    return (sum & 0xffffU) + (sum >> 16);
}

static uint32_t checksum_sub_word(uint32_t sum, uint16_t word)
{
    return checksum_add_word(sum, (uint16_t) ~word);
}

static uint32_t checksum_sub_bytes(uint32_t sum, const uint8_t *data, size_t len)
{
    while (len > 1) {
        sum = checksum_sub_word(sum, (uint16_t) (((uint16_t) data[0] << 8) | data[1]));
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum = checksum_sub_word(sum, (uint16_t) (((uint16_t) data[0]) << 8));
    }
    return sum;
}

static uint32_t checksum_unfold(uint16_t cksum)
{
    return (uint32_t) ((uint16_t) ~rte_be_to_cpu_16(cksum));
}

static uint16_t ipv4_checksum(const void *data, size_t len)
{
    return checksum_finish(checksum_add_bytes(0, data, len));
}

static uint16_t l4_checksum_ipv4(const struct rte_ipv4_hdr *ip4, const void *l4, size_t len, uint8_t proto)
{
    uint32_t sum = 0;
    uint8_t pseudo[12];

    memcpy(&pseudo[0], &ip4->src_addr, sizeof(ip4->src_addr));
    memcpy(&pseudo[4], &ip4->dst_addr, sizeof(ip4->dst_addr));
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10] = (uint8_t) ((len >> 8) & 0xff);
    pseudo[11] = (uint8_t) (len & 0xff);

    sum = checksum_add_bytes(sum, pseudo, sizeof(pseudo));
    sum = checksum_add_bytes(sum, l4, len);
    return checksum_finish(sum);
}

static uint16_t l4_checksum_ipv6(const struct rte_ipv6_hdr *ip6, const void *l4, size_t len, uint8_t proto)
{
    uint32_t sum = 0;
    uint8_t pseudo[40];

    memcpy(&pseudo[0], ip6->src_addr, sizeof(ip6->src_addr));
    memcpy(&pseudo[16], ip6->dst_addr, sizeof(ip6->dst_addr));
    pseudo[32] = (uint8_t) ((len >> 24) & 0xff);
    pseudo[33] = (uint8_t) ((len >> 16) & 0xff);
    pseudo[34] = (uint8_t) ((len >> 8) & 0xff);
    pseudo[35] = (uint8_t) (len & 0xff);
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = proto;

    sum = checksum_add_bytes(sum, pseudo, sizeof(pseudo));
    sum = checksum_add_bytes(sum, l4, len);
    return checksum_finish(sum);
}

static uint32_t ipv6_pseudo_sum(const struct rte_ipv6_hdr *ip6, size_t len, uint8_t proto)
{
    uint8_t pseudo[40];

    memcpy(&pseudo[0], ip6->src_addr, sizeof(ip6->src_addr));
    memcpy(&pseudo[16], ip6->dst_addr, sizeof(ip6->dst_addr));
    pseudo[32] = (uint8_t) ((len >> 24) & 0xff);
    pseudo[33] = (uint8_t) ((len >> 16) & 0xff);
    pseudo[34] = (uint8_t) ((len >> 8) & 0xff);
    pseudo[35] = (uint8_t) (len & 0xff);
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = proto;
    return checksum_add_bytes(0, pseudo, sizeof(pseudo));
}

static uint32_t ipv6_pseudo_sub(uint32_t sum, const struct rte_ipv6_hdr *ip6, size_t len, uint8_t proto)
{
    uint8_t pseudo[40];

    memcpy(&pseudo[0], ip6->src_addr, sizeof(ip6->src_addr));
    memcpy(&pseudo[16], ip6->dst_addr, sizeof(ip6->dst_addr));
    pseudo[32] = (uint8_t) ((len >> 24) & 0xff);
    pseudo[33] = (uint8_t) ((len >> 16) & 0xff);
    pseudo[34] = (uint8_t) ((len >> 8) & 0xff);
    pseudo[35] = (uint8_t) (len & 0xff);
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = proto;
    return checksum_sub_bytes(sum, pseudo, sizeof(pseudo));
}

static uint16_t icmpv6_echo_cksum_to_icmpv4(const struct rte_ipv6_hdr *old_ip6, const struct rte_icmp_hdr *old_icmp,
                                            uint16_t l4_len, uint8_t new_type, uint16_t new_ident)
{
    uint32_t sum = checksum_unfold(old_icmp->icmp_cksum);
    uint16_t old_type_code = (uint16_t) (((uint16_t) old_icmp->icmp_type << 8) | old_icmp->icmp_code);
    uint16_t new_type_code = (uint16_t) (((uint16_t) new_type << 8) | 0);

    sum = ipv6_pseudo_sub(sum, old_ip6, l4_len, IPPROTO_ICMPV6);
    sum = checksum_sub_word(sum, old_type_code);
    sum = checksum_sub_word(sum, rte_be_to_cpu_16(old_icmp->icmp_ident));
    sum = checksum_add_word(sum, new_type_code);
    sum = checksum_add_word(sum, new_ident);
    return checksum_finish(sum);
}

static uint16_t icmpv4_echo_cksum_to_icmpv6(const struct rte_ipv6_hdr *new_ip6, const struct rte_icmp_hdr *old_icmp,
                                            uint16_t l4_len, uint8_t new_type, uint16_t new_ident)
{
    uint32_t sum = checksum_unfold(old_icmp->icmp_cksum);
    uint16_t old_type_code = (uint16_t) (((uint16_t) old_icmp->icmp_type << 8) | old_icmp->icmp_code);
    uint16_t new_type_code = (uint16_t) (((uint16_t) new_type << 8) | 0);

    sum = checksum_sub_word(sum, old_type_code);
    sum = checksum_sub_word(sum, rte_be_to_cpu_16(old_icmp->icmp_ident));
    sum = checksum_add_word(sum, new_type_code);
    sum = checksum_add_word(sum, new_ident);
    sum += ipv6_pseudo_sum(new_ip6, l4_len, IPPROTO_ICMPV6);
    return checksum_finish(sum);
}

static uint8_t tcp_hdr_len(const struct rte_tcp_hdr *tcp)
{
    uint8_t len = (uint8_t) ((tcp->data_off >> 4) * 4);

    return len >= sizeof(*tcp) ? len : (uint8_t) sizeof(*tcp);
}

static bool tx_l4_cksum_offload(uint64_t offloads, uint8_t proto)
{
    if (proto == IPPROTO_TCP) {
        return (offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) != 0;
    }
    if (proto == IPPROTO_UDP) {
        return (offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) != 0;
    }
    return false;
}

static void prepare_ipv4_tx_checksums(struct nat64_ctx *ctx, struct rte_mbuf *m, struct rte_ipv4_hdr *ip4,
                                      void *l4, uint16_t l4_len)
{
    uint64_t offloads = ctx->port_v4_tx_offloads;

    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(*ip4);
    if ((offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0) {
        m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
        ip4->hdr_checksum = 0;
    } else {
        ip4->hdr_checksum = 0;
        ip4->hdr_checksum = ipv4_checksum(ip4, sizeof(*ip4));
    }

    if (ip4->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = l4;

        tcp->cksum = 0;
        if (tx_l4_cksum_offload(offloads, ip4->next_proto_id)) {
            m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_CKSUM;
            m->l4_len = tcp_hdr_len(tcp);
            tcp->cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
        } else {
            tcp->cksum = l4_checksum_ipv4(ip4, tcp, l4_len, ip4->next_proto_id);
        }
    } else if (ip4->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = l4;

        udp->dgram_cksum = 0;
        if (tx_l4_cksum_offload(offloads, ip4->next_proto_id)) {
            m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
            m->l4_len = sizeof(*udp);
            udp->dgram_cksum = rte_ipv4_phdr_cksum(ip4, m->ol_flags);
        } else {
            udp->dgram_cksum = l4_checksum_ipv4(ip4, udp, l4_len, ip4->next_proto_id);
        }
    }
}

static void prepare_ipv6_tx_checksums(struct nat64_ctx *ctx, struct rte_mbuf *m, struct rte_ipv6_hdr *ip6,
                                      void *l4, uint16_t l4_len)
{
    uint64_t offloads = ctx->port_v6_tx_offloads;

    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(*ip6);
    if (ip6->proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = l4;

        tcp->cksum = 0;
        if (tx_l4_cksum_offload(offloads, ip6->proto)) {
            m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_TCP_CKSUM;
            m->l4_len = tcp_hdr_len(tcp);
            tcp->cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
        } else {
            tcp->cksum = l4_checksum_ipv6(ip6, tcp, l4_len, ip6->proto);
        }
    } else if (ip6->proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = l4;

        udp->dgram_cksum = 0;
        if (tx_l4_cksum_offload(offloads, ip6->proto)) {
            m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_UDP_CKSUM;
            m->l4_len = sizeof(*udp);
            udp->dgram_cksum = rte_ipv6_phdr_cksum(ip6, m->ol_flags);
        } else {
            udp->dgram_cksum = l4_checksum_ipv6(ip6, udp, l4_len, ip6->proto);
        }
    }
}

static uint32_t hash_ip4(struct in_addr addr)
{
    return rte_hash_crc_4byte(addr.s_addr, 0);
}

static uint32_t hash_ip6(const struct in6_addr *addr)
{
    return rte_hash_crc(addr->s6_addr, sizeof(addr->s6_addr), 0);
}

static uint32_t neighbor_shard(uint32_t hash)
{
    return hash & (NAT64_NEIGHBOR_SHARDS - 1);
}

static uint32_t neighbor_shard_base(uint32_t shard)
{
    return shard * (NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS);
}

static uint32_t neighbor_slot(uint32_t shard, uint32_t hash, uint32_t i)
{
    return neighbor_shard_base(shard) +
           ((hash + i) % (NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS));
}

static bool ipv4_prefix_match(struct in_addr ip, struct in_addr network, uint8_t prefix_len)
{
    uint32_t mask;
    uint32_t ip_host;
    uint32_t network_host;

    if (prefix_len == 0) {
        return true;
    }
    if (prefix_len > 32) {
        return false;
    }

    ip_host = rte_be_to_cpu_32(ip.s_addr);
    network_host = rte_be_to_cpu_32(network.s_addr);
    mask = prefix_len == 32 ? 0xffffffffU : (~0U << (32 - prefix_len));
    return (ip_host & mask) == (network_host & mask);
}

static bool ipv6_prefix_match(const struct in6_addr *ip, const struct in6_addr *network, uint8_t prefix_len)
{
    uint32_t full_bytes;
    uint32_t rem_bits;
    uint8_t mask;

    if (prefix_len == 0) {
        return true;
    }
    if (prefix_len > 128) {
        return false;
    }

    full_bytes = prefix_len / 8;
    rem_bits = prefix_len % 8;

    if (full_bytes > 0 && memcmp(ip->s6_addr, network->s6_addr, full_bytes) != 0) {
        return false;
    }
    if (rem_bits == 0) {
        return true;
    }

    mask = (uint8_t) (0xffU << (8 - rem_bits));
    return (ip->s6_addr[full_bytes] & mask) == (network->s6_addr[full_bytes] & mask);
}

static void ipv6_prefix_normalize(const struct in6_addr *ip, uint8_t prefix_len, struct in6_addr *out)
{
    uint32_t full_bytes;
    uint32_t rem_bits;

    memset(out, 0, sizeof(*out));
    if (prefix_len > 128) {
        prefix_len = 128;
    }
    full_bytes = prefix_len / 8;
    rem_bits = prefix_len % 8;
    if (full_bytes > 0) {
        memcpy(out->s6_addr, ip->s6_addr, full_bytes);
    }
    if (rem_bits != 0) {
        uint8_t mask = (uint8_t) (0xffU << (8 - rem_bits));

        out->s6_addr[full_bytes] = ip->s6_addr[full_bytes] & mask;
    }
}

static uint32_t hash_ipv6_prefix(const struct in6_addr *prefix, uint8_t prefix_len)
{
    uint32_t h = 2166136261U ^ prefix_len;

    for (uint32_t i = 0; i < sizeof(prefix->s6_addr); i++) {
        h ^= prefix->s6_addr[i];
        h *= 16777619U;
    }
    return h;
}

static const struct nat64_subscriber_limit_rule_config *subscriber_limit_for_client(struct nat64_ctx *ctx,
                                                                                   const struct in6_addr *client,
                                                                                   uint32_t *rule_index)
{
    const struct nat64_subscriber_limits_config *limits = &ctx->cfg->subscriber_limits;
    const struct nat64_subscriber_limit_rule_config *best = &limits->default_limit;
    uint8_t best_mask = 0;

    if (rule_index != NULL) {
        *rule_index = UINT32_MAX;
    }
    for (uint32_t i = 0; i < limits->rule_count && i < NAT64_MAX_SUBSCRIBER_RULES; i++) {
        const struct nat64_subscriber_limit_rule_config *rule = &limits->rules[i];

        if (rule->prefix.mask >= best_mask &&
            ipv6_prefix_match(client, &rule->prefix.addr, rule->prefix.mask)) {
            best = rule;
            best_mask = rule->prefix.mask;
            if (rule_index != NULL) {
                *rule_index = i;
            }
        }
    }
    return best;
}

static bool subscriber_limit_allow_new_session(struct nat64_ctx *ctx, const struct in6_addr *client,
                                               uint64_t now_tsc)
{
    const struct nat64_subscriber_limits_config *limits = &ctx->cfg->subscriber_limits;
    const struct nat64_subscriber_limit_rule_config *limit;
    struct in6_addr prefix;
    uint32_t rule_index;
    uint32_t hash;
    uint32_t shard;
    struct nat64_subscriber_entry *free_entry = NULL;
    struct nat64_subscriber_entry *entry = NULL;

    if (!limits->enabled || ctx->subscriber_entries == NULL || ctx->subscriber_entry_count == 0) {
        return true;
    }

    limit = subscriber_limit_for_client(ctx, client, &rule_index);
    ipv6_prefix_normalize(client, limits->prefix_len, &prefix);
    hash = hash_ipv6_prefix(&prefix, limits->prefix_len);
    shard = hash & (NAT64_SUBSCRIBER_SHARDS - 1);

    rte_spinlock_lock(&ctx->subscriber_locks[shard]);
    for (uint32_t i = shard; i < ctx->subscriber_entry_count; i += NAT64_SUBSCRIBER_SHARDS) {
        struct nat64_subscriber_entry *candidate = &ctx->subscriber_entries[i];

        if (candidate->in_use &&
            candidate->prefix_len == limits->prefix_len &&
            memcmp(&candidate->prefix, &prefix, sizeof(prefix)) == 0) {
            entry = candidate;
            break;
        }
        if (!candidate->in_use && free_entry == NULL) {
            free_entry = candidate;
        }
    }

        if (entry == NULL) {
        if (free_entry == NULL) {
            rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
            __atomic_fetch_add(&ctx->stats_subscriber_drop_no_entry, 1, __ATOMIC_RELAXED);
            return false;
        }
        entry = free_entry;
        memset(entry, 0, sizeof(*entry));
        entry->in_use = true;
        entry->prefix = prefix;
        entry->prefix_len = limits->prefix_len;
        entry->rule_index = rule_index;
        entry->tokens_q32 = (uint64_t) limit->burst << 32;
        entry->last_refill_tsc = now_tsc;
    }

    entry->last_seen_tsc = now_tsc;
    entry->rule_index = rule_index;
    if (limit->max_sessions > 0 && entry->active_sessions >= limit->max_sessions) {
        entry->drop_max_sessions++;
        rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
        __atomic_fetch_add(&ctx->stats_subscriber_drop_max_sessions, 1, __ATOMIC_RELAXED);
        return false;
    }

    if (limit->new_conn_per_sec > 0 && limit->burst > 0) {
        uint64_t cap = (uint64_t) limit->burst << 32;

        if (entry->last_refill_tsc == 0) {
            entry->last_refill_tsc = now_tsc;
        }
        if (now_tsc > entry->last_refill_tsc && ctx->tsc_hz > 0) {
            uint64_t elapsed = now_tsc - entry->last_refill_tsc;
            __uint128_t add = (__uint128_t) elapsed * limit->new_conn_per_sec;

            add = (add << 32) / ctx->tsc_hz;
            if (add > UINT64_MAX) {
                entry->tokens_q32 = cap;
            } else if (entry->tokens_q32 + (uint64_t) add >= cap) {
                entry->tokens_q32 = cap;
            } else {
                entry->tokens_q32 += (uint64_t) add;
            }
            entry->last_refill_tsc = now_tsc;
        }
        if (entry->tokens_q32 < (1ULL << 32)) {
            entry->drop_rate_limit++;
            rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
            __atomic_fetch_add(&ctx->stats_subscriber_drop_rate_limit, 1, __ATOMIC_RELAXED);
            return false;
        }
        entry->tokens_q32 -= 1ULL << 32;
    }

    entry->active_sessions++;
    entry->allowed_total++;
    rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
    __atomic_fetch_add(&ctx->stats_subscriber_allowed, 1, __ATOMIC_RELAXED);
    return true;
}

static void subscriber_limit_release_session(struct nat64_ctx *ctx, const struct in6_addr *client,
                                             uint64_t now_tsc)
{
    const struct nat64_subscriber_limits_config *limits = &ctx->cfg->subscriber_limits;
    struct in6_addr prefix;
    uint32_t hash;
    uint32_t shard;

    if (!limits->enabled || ctx->subscriber_entries == NULL || ctx->subscriber_entry_count == 0) {
        return;
    }
    ipv6_prefix_normalize(client, limits->prefix_len, &prefix);
    hash = hash_ipv6_prefix(&prefix, limits->prefix_len);
    shard = hash & (NAT64_SUBSCRIBER_SHARDS - 1);

    rte_spinlock_lock(&ctx->subscriber_locks[shard]);
    for (uint32_t i = shard; i < ctx->subscriber_entry_count; i += NAT64_SUBSCRIBER_SHARDS) {
        struct nat64_subscriber_entry *entry = &ctx->subscriber_entries[i];

        if (entry->in_use &&
            entry->prefix_len == limits->prefix_len &&
            memcmp(&entry->prefix, &prefix, sizeof(prefix)) == 0) {
            if (entry->active_sessions > 0) {
                entry->active_sessions--;
            }
            entry->last_seen_tsc = now_tsc;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
}

static bool is_own_laddr4(const struct nat64_ctx *ctx, struct in_addr ip)
{
    if (ctx == NULL || ctx->cfg == NULL) {
        return false;
    }

    for (uint32_t service_idx = 0; service_idx < ctx->cfg->service_count && service_idx < NAT64_MAX_SERVICES;
         service_idx++) {
        const struct nat64_service_config *service = &ctx->cfg->services[service_idx];

        for (uint32_t i = 0; i < service->laddr_count; i++) {
            if (service->laddr[i].prefix.addr.s_addr == ip.s_addr) {
                return true;
            }
        }
    }
    return false;
}

static bool should_track_neighbor4(const struct nat64_ctx *ctx, struct in_addr ip)
{
    if (ip.s_addr == 0) {
        return false;
    }
    if (is_own_laddr4(ctx, ip) || ip.s_addr == ctx->port_v4_addr.s_addr) {
        return false;
    }

    if (ctx->cfg != NULL) {
        for (uint32_t service_idx = 0; service_idx < ctx->cfg->service_count && service_idx < NAT64_MAX_SERVICES;
             service_idx++) {
            const struct nat64_service_config *service = &ctx->cfg->services[service_idx];

            for (uint32_t i = 0; i < service->laddr_count; i++) {
                if (ipv4_prefix_match(ip, service->laddr[i].prefix.addr, service->laddr[i].prefix.mask)) {
                    return true;
                }
            }
        }
    }
    if (ctx->port_v4_prefix_len > 0) {
        return ipv4_prefix_match(ip, ctx->port_v4_addr, ctx->port_v4_prefix_len);
    }
    return false;
}

static bool service_has_laddr(const struct nat64_service_config *service, struct in_addr ip)
{
    for (uint32_t i = 0; i < service->laddr_count; i++) {
        if (service->laddr[i].prefix.addr.s_addr == ip.s_addr) {
            return true;
        }
    }
    return false;
}

static bool should_track_neighbor6(const struct nat64_ctx *ctx, const struct in6_addr *ip)
{
    static const struct in6_addr zero6 = IN6ADDR_ANY_INIT;

    if (IN6_IS_ADDR_UNSPECIFIED(ip) || IN6_IS_ADDR_MULTICAST(ip) || IN6_IS_ADDR_LOOPBACK(ip)) {
        return false;
    }
    if (memcmp(ip, &ctx->port_v6_addr, sizeof(*ip)) == 0 || memcmp(ip, &zero6, sizeof(*ip)) == 0) {
        return false;
    }

    if (ctx->port_v6_prefix_len > 0) {
        return ipv6_prefix_match(ip, &ctx->port_v6_addr, ctx->port_v6_prefix_len);
    }
    return false;
}

static void neighbor4_update(struct nat64_ctx *ctx, struct in_addr ip, const struct rte_ether_addr *mac, uint64_t now)
{
    uint32_t hash = hash_ip4(ip);
    uint32_t shard = neighbor_shard(hash);

    if (!should_track_neighbor4(ctx, ip)) {
        return;
    }

    rte_spinlock_lock(&ctx->neigh4_locks[shard]);
    for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
        struct nat64_neighbor4 *n = &ctx->neighbors4[neighbor_slot(shard, hash, i)];
        if (!n->in_use || n->ip.s_addr == ip.s_addr) {
            n->in_use = true;
            n->ip = ip;
            rte_ether_addr_copy(mac, &n->mac);
            n->last_seen_tsc = now;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->neigh4_locks[shard]);
}

static void neighbor4_cache_store(struct nat64_ctx *ctx, uint16_t queue_id, struct in_addr ip,
                                  const struct rte_ether_addr *mac, uint64_t now)
{
    if (queue_id >= NAT64_MAX_WORKERS) {
        return;
    }
    ctx->neigh4_cache[queue_id].valid = true;
    ctx->neigh4_cache[queue_id].ip = ip;
    rte_ether_addr_copy(mac, &ctx->neigh4_cache[queue_id].mac);
    ctx->neigh4_cache[queue_id].last_seen_tsc = now;
}

static void neighbor6_cache_store(struct nat64_ctx *ctx, uint16_t queue_id, const struct in6_addr *ip,
                                  const struct rte_ether_addr *mac, uint64_t now)
{
    if (queue_id >= NAT64_MAX_WORKERS) {
        return;
    }
    ctx->neigh6_cache[queue_id].valid = true;
    ctx->neigh6_cache[queue_id].ip = *ip;
    rte_ether_addr_copy(mac, &ctx->neigh6_cache[queue_id].mac);
    ctx->neigh6_cache[queue_id].last_seen_tsc = now;
}

static bool neighbor4_cache_lookup(struct nat64_ctx *ctx, uint16_t queue_id, struct in_addr ip,
                                   struct rte_ether_addr *mac, uint64_t now)
{
    struct nat64_neighbor4_cache *cache;

    if (queue_id >= NAT64_MAX_WORKERS) {
        return false;
    }
    cache = &ctx->neigh4_cache[queue_id];
    if (!cache->valid || cache->ip.s_addr != ip.s_addr) {
        return false;
    }
    if (ctx->neighbor_timeout_tsc != 0 && now - cache->last_seen_tsc > ctx->neighbor_timeout_tsc) {
        cache->valid = false;
        return false;
    }
    rte_ether_addr_copy(&cache->mac, mac);
    cache->last_seen_tsc = now;
    return true;
}

static bool neighbor6_cache_lookup(struct nat64_ctx *ctx, uint16_t queue_id, const struct in6_addr *ip,
                                   struct rte_ether_addr *mac, uint64_t now)
{
    struct nat64_neighbor6_cache *cache;

    if (queue_id >= NAT64_MAX_WORKERS) {
        return false;
    }
    cache = &ctx->neigh6_cache[queue_id];
    if (!cache->valid || memcmp(&cache->ip, ip, sizeof(*ip)) != 0) {
        return false;
    }
    if (ctx->neighbor_timeout_tsc != 0 && now - cache->last_seen_tsc > ctx->neighbor_timeout_tsc) {
        cache->valid = false;
        return false;
    }
    rte_ether_addr_copy(&cache->mac, mac);
    cache->last_seen_tsc = now;
    return true;
}

static bool neighbor4_lookup(struct nat64_ctx *ctx, uint16_t queue_id, struct in_addr ip, struct rte_ether_addr *mac,
                             uint64_t now)
{
    uint32_t hash = hash_ip4(ip);
    uint32_t shard = neighbor_shard(hash);
    bool found = false;

    if (neighbor4_cache_lookup(ctx, queue_id, ip, mac, now)) {
        return true;
    }

    rte_spinlock_lock(&ctx->neigh4_locks[shard]);
    for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
        struct nat64_neighbor4 *n = &ctx->neighbors4[neighbor_slot(shard, hash, i)];
        if (n->in_use && n->ip.s_addr == ip.s_addr) {
            rte_ether_addr_copy(&n->mac, mac);
            n->last_seen_tsc = now;
            found = true;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->neigh4_locks[shard]);
    if (found) {
        neighbor4_cache_store(ctx, queue_id, ip, mac, now);
    }
    return found;
}

static void neighbor6_update(struct nat64_ctx *ctx, const struct in6_addr *ip, const struct rte_ether_addr *mac,
                             uint64_t now)
{
    uint32_t hash = hash_ip6(ip);
    uint32_t shard = neighbor_shard(hash);

    if (!should_track_neighbor6(ctx, ip)) {
        return;
    }

    rte_spinlock_lock(&ctx->neigh6_locks[shard]);
    for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
        struct nat64_neighbor6 *n = &ctx->neighbors6[neighbor_slot(shard, hash, i)];
        if (!n->in_use || memcmp(&n->ip, ip, sizeof(*ip)) == 0) {
            n->in_use = true;
            n->ip = *ip;
            rte_ether_addr_copy(mac, &n->mac);
            n->last_seen_tsc = now;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->neigh6_locks[shard]);
}

static bool neighbor6_lookup(struct nat64_ctx *ctx, uint16_t queue_id, const struct in6_addr *ip,
                             struct rte_ether_addr *mac, uint64_t now)
{
    uint32_t hash = hash_ip6(ip);
    uint32_t shard = neighbor_shard(hash);
    bool found = false;

    if (neighbor6_cache_lookup(ctx, queue_id, ip, mac, now)) {
        return true;
    }

    rte_spinlock_lock(&ctx->neigh6_locks[shard]);
    for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
        struct nat64_neighbor6 *n = &ctx->neighbors6[neighbor_slot(shard, hash, i)];
        if (n->in_use && memcmp(&n->ip, ip, sizeof(*ip)) == 0) {
            rte_ether_addr_copy(&n->mac, mac);
            n->last_seen_tsc = now;
            found = true;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->neigh6_locks[shard]);
    if (found) {
        neighbor6_cache_store(ctx, queue_id, ip, mac, now);
    }
    return found;
}

static uint32_t hash_session_v6(const struct in6_addr *client, const struct in6_addr *service, uint16_t cport,
                                uint16_t sport, uint8_t proto)
{
    const uint32_t *u32 = (const uint32_t *) client->s6_addr;
    const uint32_t *v32 = (const uint32_t *) service->s6_addr;
    uint32_t h = proto;

    for (int i = 0; i < 4; i++) {
        h ^= u32[i] + 0x9e3779b9U + (h << 6) + (h >> 2);
        h ^= v32[i] + 0x9e3779b9U + (h << 6) + (h >> 2);
    }
    h ^= ((uint32_t) cport << 16) | sport;
    return h;
}

static uint32_t hash_session_v4(struct in_addr rs, struct in_addr local, uint16_t rs_port, uint16_t local_port,
                                uint8_t proto)
{
    uint32_t h = proto;
    h ^= rs.s_addr + 0x9e3779b9U + (h << 6) + (h >> 2);
    h ^= local.s_addr + 0x9e3779b9U + (h << 6) + (h >> 2);
    h ^= ((uint32_t) rs_port << 16) | local_port;
    return h;
}

static uint32_t session_shard(uint8_t proto, uint16_t local_port)
{
    uint32_t h = proto;

    h ^= (uint32_t) local_port + 0x9e3779b9U + (h << 6) + (h >> 2);
    return h & (NAT64_SESSION_SHARDS - 1);
}

static uint32_t session_shard_base(uint32_t shard)
{
    return shard * NAT64_SESSIONS_PER_SHARD;
}

static uint32_t session_slot(uint32_t shard, uint32_t hash, uint32_t i)
{
    return session_shard_base(shard) + ((hash + i) % NAT64_SESSIONS_PER_SHARD);
}

static uint32_t session_index(struct nat64_ctx *ctx, const struct nat64_session *s)
{
    return (uint32_t) (s - ctx->sessions);
}

static void session_cache_store(struct nat64_session_cache_entry cache[NAT64_SESSION_CACHE_SIZE],
                                uint32_t hash, uint32_t index, uint32_t generation)
{
    struct nat64_session_cache_entry *entry = &cache[hash % NAT64_SESSION_CACHE_SIZE];

    entry->valid = true;
    entry->index = index;
    entry->generation = generation;
}

static struct nat64_session *session_v6_cache_lookup(struct nat64_ctx *ctx, uint16_t queue_id, uint32_t hash,
                                                     const struct in6_addr *client,
                                                     const struct in6_addr *service, uint16_t service_index,
                                                     uint16_t cport,
                                                     uint16_t sport, uint8_t proto)
{
    struct nat64_session_cache_entry *entry;
    struct nat64_session *s;

    if (queue_id >= NAT64_MAX_WORKERS) {
        return NULL;
    }
    entry = &ctx->session_v6_cache[queue_id][hash % NAT64_SESSION_CACHE_SIZE];
    if (!entry->valid || entry->index >= NAT64_MAX_SESSIONS) {
        return NULL;
    }
    s = &ctx->sessions[entry->index];
    if (!s->in_use || s->generation != entry->generation ||
        s->proto != proto || s->service_index != service_index ||
        s->client_port != cport || s->service_port != sport ||
        memcmp(&s->client_v6, client, sizeof(*client)) != 0 ||
        memcmp(&s->service_v6, service, sizeof(*service)) != 0) {
        entry->valid = false;
        return NULL;
    }
    s->last_seen_tsc = rte_rdtsc();
    return s;
}

static struct nat64_session *session_v4_cache_lookup(struct nat64_ctx *ctx, uint16_t queue_id, uint32_t hash,
                                                     struct in_addr rs, struct in_addr local,
                                                     uint16_t rs_port, uint16_t local_port, uint8_t proto)
{
    struct nat64_session_cache_entry *entry;
    struct nat64_session *s;

    if (queue_id >= NAT64_MAX_WORKERS) {
        return NULL;
    }
    entry = &ctx->session_v4_cache[queue_id][hash % NAT64_SESSION_CACHE_SIZE];
    if (!entry->valid || entry->index >= NAT64_MAX_SESSIONS) {
        return NULL;
    }
    s = &ctx->sessions[entry->index];
    if (!s->in_use || s->generation != entry->generation ||
        s->proto != proto || s->rs_port != rs_port || s->local_port != local_port ||
        s->rs_v4.s_addr != rs.s_addr || s->local_v4.s_addr != local.s_addr) {
        entry->valid = false;
        return NULL;
    }
    s->last_seen_tsc = rte_rdtsc();
    return s;
}

static struct nat64_session *find_session_v6(struct nat64_ctx *ctx, const struct in6_addr *client,
                                             const struct in6_addr *service, uint16_t service_index,
                                             uint16_t cport, uint16_t sport,
                                             uint8_t proto, uint16_t queue_id)
{
    uint32_t shard = session_shard(proto, cport);
    uint32_t hash = hash_session_v6(client, service, cport, sport, proto);
    struct nat64_session *result = NULL;

    result = session_v6_cache_lookup(ctx, queue_id, hash, client, service, service_index, cport, sport, proto);
    if (result != NULL) {
        return result;
    }

    rte_spinlock_lock(&ctx->session_locks[shard]);
    for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
        struct nat64_session *s = &ctx->sessions[session_slot(shard, hash, i)];
        if (s->in_use &&
            s->proto == proto &&
            s->service_index == service_index &&
            s->client_port == cport &&
            s->service_port == sport &&
            memcmp(&s->client_v6, client, sizeof(*client)) == 0 &&
            memcmp(&s->service_v6, service, sizeof(*service)) == 0) {
            result = s;
            if (queue_id < NAT64_MAX_WORKERS) {
                session_cache_store(ctx->session_v6_cache[queue_id], hash, session_index(ctx, s), s->generation);
            }
            break;
        }
    }
    rte_spinlock_unlock(&ctx->session_locks[shard]);
    return result;
}

static bool select_rs_v4_for_v6(struct nat64_ctx *ctx, const struct nat64_service_config *nat64_service,
                                const struct in6_addr *service, struct in_addr *rs_out)
{
    if (nat64_service->dst_mode == NAT64_DST_EMBED_V4) {
        for (uint32_t i = 0; i < nat64_service->vs.vaddr_count; i++) {
            if (prefix96_extract_v4(&nat64_service->vs.vaddr[i], service, rs_out)) {
                return true;
            }
        }
        return false;
    }

    if (nat64_service->rs_count == 0) {
        return false;
    }

    *rs_out = nat64_service->rs[
        __atomic_fetch_add(&ctx->rr_rs, 1, __ATOMIC_RELAXED) % nat64_service->rs_count
    ].prefix.addr;
    return true;
}

static const struct nat64_static_bib_config *static_bib_for_v6(const struct nat64_service_config *service,
                                                               const struct in6_addr *client,
                                                               uint16_t client_port, uint8_t proto)
{
    for (uint32_t i = 0; i < service->static_bib_count; i++) {
        const struct nat64_static_bib_config *bib = &service->static_bibs[i];

        if (bib->proto == proto &&
            client_port >= bib->map_port_from &&
            client_port <= bib->map_port_to &&
            memcmp(&bib->client_v6, client, sizeof(*client)) == 0) {
            return bib;
        }
    }
    return NULL;
}

static const struct nat64_static_bib_config *static_bib_for_v4(struct nat64_ctx *ctx, struct in_addr local,
                                                               uint16_t local_port, uint8_t proto,
                                                               uint16_t *service_index)
{
    for (uint32_t service_idx = 0; service_idx < ctx->cfg->service_count && service_idx < NAT64_MAX_SERVICES;
         service_idx++) {
        const struct nat64_service_config *service = &ctx->cfg->services[service_idx];

        for (uint32_t i = 0; i < service->static_bib_count; i++) {
            const struct nat64_static_bib_config *bib = &service->static_bibs[i];

            if (bib->proto == proto &&
                local_port >= bib->map_port_from &&
                local_port <= bib->map_port_to &&
                bib->local_v4.s_addr == local.s_addr) {
                if (service_index != NULL) {
                    *service_index = (uint16_t) service_idx;
                }
                return bib;
            }
        }
    }
    return NULL;
}

static bool static_bib_tuple_reserved(struct nat64_ctx *ctx, struct in_addr local, uint16_t local_port,
                                      uint8_t proto)
{
    return static_bib_for_v4(ctx, local, local_port, proto, NULL) != NULL;
}

static bool static_bib_tuple_duplicated(const struct nat64_config *cfg, uint32_t service_idx, uint32_t bib_idx)
{
    const struct nat64_static_bib_config *bib = &cfg->services[service_idx].static_bibs[bib_idx];

    for (uint32_t other_service_idx = 0; other_service_idx < cfg->service_count && other_service_idx < NAT64_MAX_SERVICES;
         other_service_idx++) {
        const struct nat64_service_config *service = &cfg->services[other_service_idx];

        for (uint32_t other_bib_idx = 0; other_bib_idx < service->static_bib_count; other_bib_idx++) {
            const struct nat64_static_bib_config *other = &service->static_bibs[other_bib_idx];

            if (other_service_idx == service_idx && other_bib_idx == bib_idx) {
                continue;
            }
            if (bib->proto == other->proto &&
                bib->map_port_from <= other->map_port_to &&
                other->map_port_from <= bib->map_port_to &&
                (bib->local_v4.s_addr == other->local_v4.s_addr ||
                 memcmp(&bib->client_v6, &other->client_v6, sizeof(bib->client_v6)) == 0)) {
                return true;
            }
        }
    }
    return false;
}

static bool select_local_v4_for_v6(struct nat64_ctx *ctx, const struct nat64_service_config *service,
                                   const struct nat64_static_bib_config *bib, uint8_t proto,
                                   uint16_t client_port, struct in_addr *local_out)
{
    uint32_t start;

    if (bib != NULL) {
        *local_out = bib->local_v4;
        return true;
    }

    if (service->laddr_count == 0) {
        return false;
    }

    start = __atomic_fetch_add(&ctx->rr_laddr, 1, __ATOMIC_RELAXED);
    for (uint32_t i = 0; i < service->laddr_count; i++) {
        struct in_addr candidate = service->laddr[(start + i) % service->laddr_count].prefix.addr;

        if (!static_bib_tuple_reserved(ctx, candidate, client_port, proto)) {
            *local_out = candidate;
            return true;
        }
    }
    return false;
}

static bool static_service_v6_for_v4(const struct nat64_service_config *service, struct in_addr rs,
                                     struct in6_addr *service_v6)
{
    if (service->vs.vaddr_count == 0) {
        return false;
    }
    prefix96_embed_v4(&service->vs.vaddr[0], rs, service_v6);
    return true;
}

static struct nat64_session *find_or_create_session_v6(struct nat64_ctx *ctx, const struct in6_addr *client,
                                                       const struct nat64_service_config *nat64_service,
                                                       uint16_t service_index,
                                                       const struct in6_addr *service, uint16_t cport,
                                                       uint16_t sport, uint8_t proto,
                                                       const struct rte_ether_addr *reply_mac,
                                                       uint16_t queue_id)
{
    struct nat64_session *existing = find_session_v6(ctx, client, service, service_index, cport, sport, proto,
                                                     queue_id);
    uint32_t shard;
    uint32_t hash;
    struct in_addr rs_v4;
    struct in_addr local_v4;
    const struct nat64_static_bib_config *bib;

    if (existing != NULL) {
        shard = session_shard(proto, cport);
        rte_spinlock_lock(&ctx->session_locks[shard]);
        existing->last_seen_tsc = rte_rdtsc();
        rte_ether_addr_copy(reply_mac, &existing->v6_reply_dmac);
        rte_spinlock_unlock(&ctx->session_locks[shard]);
        return existing;
    }

    if (!select_rs_v4_for_v6(ctx, nat64_service, service, &rs_v4)) {
        return NULL;
    }
    bib = static_bib_for_v6(nat64_service, client, cport, proto);
    if (!select_local_v4_for_v6(ctx, nat64_service, bib, proto, cport, &local_v4)) {
        return NULL;
    }
    if (!subscriber_limit_allow_new_session(ctx, client, rte_rdtsc())) {
        return NULL;
    }

    shard = session_shard(proto, cport);
    hash = hash_session_v6(client, service, cport, sport, proto);
    rte_spinlock_lock(&ctx->session_locks[shard]);
    for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
        struct nat64_session *s = &ctx->sessions[session_slot(shard, hash, i)];
        if (s->in_use) {
            continue;
        }

        memset(s, 0, sizeof(*s));
        s->in_use = true;
        s->subscriber_counted = true;
        s->proto = proto;
        s->generation = __atomic_add_fetch(&ctx->session_generation, 1, __ATOMIC_RELAXED);
        if (s->generation == 0) {
            s->generation = __atomic_add_fetch(&ctx->session_generation, 1, __ATOMIC_RELAXED);
        }
        s->client_v6 = *client;
        s->service_v6 = *service;
        s->service_index = service_index;
        s->client_port = cport;
        s->service_port = sport;
        s->rs_v4 = rs_v4;
        s->local_v4 = local_v4;
        s->local_port = cport;
        s->rs_port = sport;
        rte_ether_addr_copy(reply_mac, &s->v6_reply_dmac);
        s->created_unix = (uint64_t) time(NULL);
        s->last_seen_tsc = rte_rdtsc();
        if (queue_id < NAT64_MAX_WORKERS) {
            uint32_t idx = session_index(ctx, s);

            session_cache_store(ctx->session_v6_cache[queue_id], hash, idx, s->generation);
            session_cache_store(ctx->session_v4_cache[queue_id],
                                hash_session_v4(s->rs_v4, s->local_v4, s->rs_port, s->local_port, s->proto),
                                idx, s->generation);
        }
        rte_spinlock_unlock(&ctx->session_locks[shard]);
        stats_note_session_created(ctx);
        audit_log_session(ctx, "create", s, s->last_seen_tsc);
        return s;
    }
    rte_spinlock_unlock(&ctx->session_locks[shard]);
    subscriber_limit_release_session(ctx, client, rte_rdtsc());
    return NULL;
}

static struct nat64_session *find_session_v4(struct nat64_ctx *ctx, struct in_addr rs, struct in_addr local,
                                             uint16_t rs_port, uint16_t local_port, uint8_t proto,
                                             uint16_t queue_id)
{
    uint32_t shard = session_shard(proto, local_port);
    uint32_t hash = hash_session_v4(rs, local, rs_port, local_port, proto);
    struct nat64_session *result = NULL;

    result = session_v4_cache_lookup(ctx, queue_id, hash, rs, local, rs_port, local_port, proto);
    if (result != NULL) {
        return result;
    }

    rte_spinlock_lock(&ctx->session_locks[shard]);
    for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
        struct nat64_session *s = &ctx->sessions[session_slot(shard, hash, i)];
        if (s->in_use &&
            s->proto == proto &&
            s->rs_port == rs_port &&
            s->local_port == local_port &&
            s->rs_v4.s_addr == rs.s_addr &&
            s->local_v4.s_addr == local.s_addr) {
            s->last_seen_tsc = rte_rdtsc();
            result = s;
            if (queue_id < NAT64_MAX_WORKERS) {
                session_cache_store(ctx->session_v4_cache[queue_id], hash, session_index(ctx, s), s->generation);
            }
            break;
        }
    }
    rte_spinlock_unlock(&ctx->session_locks[shard]);
    return result;
}

static struct nat64_session *find_or_create_static_session_v4(struct nat64_ctx *ctx, struct in_addr rs,
                                                              struct in_addr local, uint16_t rs_port,
                                                              uint16_t local_port, uint8_t proto,
                                                              uint16_t queue_id)
{
    uint16_t service_index = 0;
    const struct nat64_static_bib_config *bib = static_bib_for_v4(ctx, local, local_port, proto, &service_index);
    const struct nat64_service_config *service;
    struct in6_addr service_v6;
    uint32_t shard;
    uint32_t hash;

    if (bib == NULL) {
        return NULL;
    }
    service = service_by_index(ctx, service_index);
    if (service == NULL || !static_service_v6_for_v4(service, rs, &service_v6)) {
        return NULL;
    }
    if (!subscriber_limit_allow_new_session(ctx, &bib->client_v6, rte_rdtsc())) {
        return NULL;
    }

    shard = session_shard(proto, local_port);
    hash = hash_session_v4(rs, local, rs_port, local_port, proto);
    rte_spinlock_lock(&ctx->session_locks[shard]);
    for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
        struct nat64_session *s = &ctx->sessions[session_slot(shard, hash, i)];

        if (s->in_use) {
            continue;
        }

        memset(s, 0, sizeof(*s));
        s->in_use = true;
        s->subscriber_counted = true;
        s->proto = proto;
        s->generation = __atomic_add_fetch(&ctx->session_generation, 1, __ATOMIC_RELAXED);
        if (s->generation == 0) {
            s->generation = __atomic_add_fetch(&ctx->session_generation, 1, __ATOMIC_RELAXED);
        }
        s->client_v6 = bib->client_v6;
        s->service_v6 = service_v6;
        s->service_index = service_index;
        s->client_port = local_port;
        s->service_port = rs_port;
        s->local_v4 = local;
        s->rs_v4 = rs;
        s->local_port = local_port;
        s->rs_port = rs_port;
        s->created_unix = (uint64_t) time(NULL);
        s->last_seen_tsc = rte_rdtsc();
        if (queue_id < NAT64_MAX_WORKERS) {
            uint32_t idx = session_index(ctx, s);

            session_cache_store(ctx->session_v4_cache[queue_id], hash, idx, s->generation);
            session_cache_store(ctx->session_v6_cache[queue_id],
                                hash_session_v6(&s->client_v6, &s->service_v6, s->client_port,
                                                s->service_port, s->proto),
                                idx, s->generation);
        }
        rte_spinlock_unlock(&ctx->session_locks[shard]);
        stats_note_session_created(ctx);
        audit_log_session(ctx, "create", s, s->last_seen_tsc);
        return s;
    }
    rte_spinlock_unlock(&ctx->session_locks[shard]);
    subscriber_limit_release_session(ctx, &bib->client_v6, rte_rdtsc());
    return NULL;
}

static struct nat64_session *find_session_v4_outbound(struct nat64_ctx *ctx, struct in_addr local, struct in_addr rs,
                                                      uint16_t local_port, uint16_t rs_port, uint8_t proto)
{
    uint32_t shard = session_shard(proto, local_port);
    struct nat64_session *result = NULL;

    rte_spinlock_lock(&ctx->session_locks[shard]);
    for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
        struct nat64_session *s = &ctx->sessions[session_shard_base(shard) + i];

        if (s->in_use &&
            s->proto == proto &&
            s->local_port == local_port &&
            s->rs_port == rs_port &&
            s->local_v4.s_addr == local.s_addr &&
            s->rs_v4.s_addr == rs.s_addr) {
            s->last_seen_tsc = rte_rdtsc();
            result = s;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->session_locks[shard]);
    return result;
}

static struct nat64_session *find_session_v6_translated(struct nat64_ctx *ctx, const struct in6_addr *service,
                                                        const struct in6_addr *client, uint16_t service_port,
                                                        uint16_t client_port, uint8_t proto)
{
    uint32_t shard = session_shard(proto, client_port);
    struct nat64_session *result = NULL;

    rte_spinlock_lock(&ctx->session_locks[shard]);
    for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
        struct nat64_session *s = &ctx->sessions[session_shard_base(shard) + i];

        if (s->in_use &&
            s->proto == proto &&
            s->service_port == service_port &&
            s->client_port == client_port &&
            memcmp(&s->service_v6, service, sizeof(*service)) == 0 &&
            memcmp(&s->client_v6, client, sizeof(*client)) == 0) {
            s->last_seen_tsc = rte_rdtsc();
            result = s;
            break;
        }
    }
    rte_spinlock_unlock(&ctx->session_locks[shard]);
    return result;
}

static uint16_t extract_ports(uint8_t proto, void *l4, uint16_t l4_len, uint16_t *src, uint16_t *dst,
                              uint8_t *session_proto)
{
    *session_proto = proto;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = l4;
        *src = rte_be_to_cpu_16(tcp->src_port);
        *dst = rte_be_to_cpu_16(tcp->dst_port);
        return (uint16_t) sizeof(*tcp);
    }
    if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = l4;
        *src = rte_be_to_cpu_16(udp->src_port);
        *dst = rte_be_to_cpu_16(udp->dst_port);
        return (uint16_t) sizeof(*udp);
    }
    if (proto == IPPROTO_ICMP && l4_len >= sizeof(struct rte_icmp_hdr)) {
        struct rte_icmp_hdr *icmp = l4;

        if ((icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST ||
             icmp->icmp_type == RTE_IP_ICMP_ECHO_REPLY) &&
            l4_len >= sizeof(*icmp)) {
            *src = rte_be_to_cpu_16(icmp->icmp_ident);
            *dst = 0;
            *session_proto = IPPROTO_ICMP;
            return (uint16_t) sizeof(*icmp);
        }
    }
    if (proto == IPPROTO_ICMPV6 && l4_len >= sizeof(struct rte_icmp_hdr)) {
        struct rte_icmp_hdr *icmp = l4;

        if ((icmp->icmp_type == ICMPV6_ECHO_REQUEST ||
             icmp->icmp_type == ICMPV6_ECHO_REPLY) &&
            l4_len >= sizeof(*icmp)) {
            *src = rte_be_to_cpu_16(icmp->icmp_ident);
            *dst = 0;
            *session_proto = IPPROTO_ICMP;
            return (uint16_t) sizeof(*icmp);
        }
    }
    return 0;
}

static void set_ports(uint8_t proto, void *l4, uint16_t src, uint16_t dst)
{
    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = l4;
        tcp->src_port = rte_cpu_to_be_16(src);
        tcp->dst_port = rte_cpu_to_be_16(dst);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = l4;
        udp->src_port = rte_cpu_to_be_16(src);
        udp->dst_port = rte_cpu_to_be_16(dst);
    }
}

static bool is_sip_port(uint16_t port)
{
    return port == SIP_PORT || port == SIP_TLS_PORT;
}

static bool is_sip_udp_packet(const void *l4, uint16_t l4_len)
{
    const struct rte_udp_hdr *udp = l4;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t udp_len;

    if (l4_len < sizeof(*udp)) {
        return false;
    }
    src_port = rte_be_to_cpu_16(udp->src_port);
    dst_port = rte_be_to_cpu_16(udp->dst_port);
    udp_len = rte_be_to_cpu_16(udp->dgram_len);
    return udp_len >= sizeof(*udp) && udp_len <= l4_len && (is_sip_port(src_port) || is_sip_port(dst_port));
}

static bool sip_payload_looks_textual(const uint8_t *payload, size_t len)
{
    size_t check_len = len < 128 ? len : 128;

    if (len == 0 || check_len == 0) {
        return false;
    }
    for (size_t i = 0; i < check_len; i++) {
        uint8_t c = payload[i];

        if (c == '\r' || c == '\n' || c == '\t') {
            continue;
        }
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

static bool append_bytes(uint8_t *out, size_t cap, size_t *len, const void *src, size_t src_len)
{
    if (*len > cap || src_len > cap - *len) {
        return false;
    }
    memcpy(out + *len, src, src_len);
    *len += src_len;
    return true;
}

static bool append_cstr(uint8_t *out, size_t cap, size_t *len, const char *src)
{
    return append_bytes(out, cap, len, src, strlen(src));
}

static bool replace_all_bytes(const uint8_t *in, size_t in_len, const char *from, const char *to,
                              uint8_t *out, size_t cap, size_t *out_len, bool *changed)
{
    size_t from_len = strlen(from);
    size_t to_len = strlen(to);
    size_t pos = 0;

    *out_len = 0;
    if (from_len == 0) {
        return append_bytes(out, cap, out_len, in, in_len);
    }

    while (pos < in_len) {
        if (pos + from_len <= in_len && memcmp(in + pos, from, from_len) == 0) {
            if (!append_bytes(out, cap, out_len, to, to_len)) {
                return false;
            }
            pos += from_len;
            *changed = true;
        } else {
            if (!append_bytes(out, cap, out_len, in + pos, 1)) {
                return false;
            }
            pos++;
        }
    }
    return true;
}

static bool replace_two_patterns(const uint8_t *in, size_t in_len,
                                 const char *from1, const char *to1,
                                 const char *from2, const char *to2,
                                 uint8_t *out, size_t cap, size_t *out_len, bool *changed)
{
    uint8_t tmp[NAT64_SIP_MAX_PAYLOAD];
    size_t tmp_len = 0;

    if (!replace_all_bytes(in, in_len, from1, to1, tmp, sizeof(tmp), &tmp_len, changed)) {
        return false;
    }
    return replace_all_bytes(tmp, tmp_len, from2, to2, out, cap, out_len, changed);
}

static const uint8_t *find_header_body_sep(const uint8_t *payload, size_t len, size_t *sep_len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (payload[i] == '\r' && payload[i + 1] == '\n' &&
            payload[i + 2] == '\r' && payload[i + 3] == '\n') {
            *sep_len = 4;
            return payload + i;
        }
    }
    for (size_t i = 0; i + 1 < len; i++) {
        if (payload[i] == '\n' && payload[i + 1] == '\n') {
            *sep_len = 2;
            return payload + i;
        }
    }
    *sep_len = 0;
    return NULL;
}

static bool starts_with_ci(const uint8_t *s, size_t len, const char *prefix)
{
    size_t prefix_len = strlen(prefix);

    if (len < prefix_len) {
        return false;
    }
    for (size_t i = 0; i < prefix_len; i++) {
        uint8_t a = s[i];
        uint8_t b = (uint8_t) prefix[i];

        if (a >= 'A' && a <= 'Z') {
            a = (uint8_t) (a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (uint8_t) (b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

static bool update_content_length(const uint8_t *header, size_t header_len, size_t body_len,
                                  uint8_t *out, size_t cap, size_t *out_len, bool *changed)
{
    size_t pos = 0;
    char len_buf[24];
    int len_buf_len = snprintf(len_buf, sizeof(len_buf), "%zu", body_len);

    *out_len = 0;
    if (len_buf_len <= 0 || (size_t) len_buf_len >= sizeof(len_buf)) {
        return false;
    }

    while (pos < header_len) {
        size_t line_start = pos;
        size_t line_end = pos;
        size_t eol_len = 0;

        while (line_end < header_len && header[line_end] != '\r' && header[line_end] != '\n') {
            line_end++;
        }
        if (line_end < header_len) {
            if (header[line_end] == '\r' && line_end + 1 < header_len && header[line_end + 1] == '\n') {
                eol_len = 2;
            } else {
                eol_len = 1;
            }
        }

        if (starts_with_ci(header + line_start, line_end - line_start, "Content-Length:")) {
            const uint8_t *colon = memchr(header + line_start, ':', line_end - line_start);
            size_t prefix_len;

            if (colon == NULL) {
                return false;
            }
            prefix_len = (size_t) (colon - (header + line_start)) + 1;
            if (!append_bytes(out, cap, out_len, header + line_start, prefix_len) ||
                !append_cstr(out, cap, out_len, " ") ||
                !append_bytes(out, cap, out_len, len_buf, (size_t) len_buf_len)) {
                return false;
            }
            *changed = true;
        } else {
            if (!append_bytes(out, cap, out_len, header + line_start, line_end - line_start)) {
                return false;
            }
        }
        if (eol_len > 0 && !append_bytes(out, cap, out_len, header + line_end, eol_len)) {
            return false;
        }
        pos = line_end + eol_len;
        if (eol_len == 0) {
            break;
        }
    }
    return true;
}

static bool sip_rewrite_payload(const uint8_t *payload, size_t payload_len,
                                const char *from_h1, const char *to_h1,
                                const char *from_h2, const char *to_h2,
                                const char *from_b1, const char *to_b1,
                                const char *from_b2, const char *to_b2,
                                uint8_t *out, size_t cap, size_t *out_len, bool *changed)
{
    const uint8_t *sep;
    size_t sep_len = 0;
    size_t header_len;
    size_t body_len;
    uint8_t header_tmp[NAT64_SIP_MAX_PAYLOAD];
    uint8_t header_final[NAT64_SIP_MAX_PAYLOAD];
    uint8_t body_tmp[NAT64_SIP_MAX_PAYLOAD];
    size_t header_tmp_len = 0;
    size_t header_final_len = 0;
    size_t body_tmp_len = 0;

    *out_len = 0;
    *changed = false;
    if (payload_len > NAT64_SIP_MAX_PAYLOAD || !sip_payload_looks_textual(payload, payload_len)) {
        return false;
    }

    sep = find_header_body_sep(payload, payload_len, &sep_len);
    if (sep == NULL) {
        return replace_two_patterns(payload, payload_len, from_h1, to_h1, from_h2, to_h2,
                                    out, cap, out_len, changed);
    }
    header_len = (size_t) (sep - payload);
    body_len = payload_len - header_len - sep_len;

    if (!replace_two_patterns(payload, header_len, from_h1, to_h1, from_h2, to_h2,
                              header_tmp, sizeof(header_tmp), &header_tmp_len, changed)) {
        return false;
    }
    if (!replace_two_patterns(sep + sep_len, body_len, from_b1, to_b1, from_b2, to_b2,
                              body_tmp, sizeof(body_tmp), &body_tmp_len, changed)) {
        return false;
    }
    if (*changed) {
        if (!update_content_length(header_tmp, header_tmp_len, body_tmp_len,
                                   header_final, sizeof(header_final), &header_final_len, changed)) {
            return false;
        }
    } else {
        memcpy(header_final, header_tmp, header_tmp_len);
        header_final_len = header_tmp_len;
    }

    return append_bytes(out, cap, out_len, header_final, header_final_len) &&
           append_bytes(out, cap, out_len, sep, sep_len) &&
           append_bytes(out, cap, out_len, body_tmp, body_tmp_len);
}

static void normalize_v4_reverse_session_ports(uint8_t proto, uint16_t *rs_port, uint16_t *local_port)
{
    if (proto == IPPROTO_ICMP) {
        *local_port = *rs_port;
        *rs_port = 0;
    }
}

static struct rte_mbuf *rebuild_ipv4_udp_payload(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                                 const uint8_t *payload, size_t payload_len)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *) (ip4 + 1);
    uint16_t total_len;
    struct rte_mbuf *out;
    char *buf;
    struct rte_ether_hdr *oeth;
    struct rte_ipv4_hdr *oip4;
    struct rte_udp_hdr *oudp;

    if (payload_len > UINT16_MAX - sizeof(*ip4) - sizeof(*udp)) {
        stats_note_frag_dropped(ctx);
        rte_pktmbuf_free(m);
        return NULL;
    }
    total_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip4) + sizeof(*oudp) + payload_len);
    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        rte_pktmbuf_free(m);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip4 = (struct rte_ipv4_hdr *) (oeth + 1);
    oudp = (struct rte_udp_hdr *) (oip4 + 1);
    *oeth = *eth;
    *oip4 = *ip4;
    *oudp = *udp;
    memcpy(oudp + 1, payload, payload_len);
    oip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*oip4) + sizeof(*oudp) + payload_len));
    oudp->dgram_len = rte_cpu_to_be_16((uint16_t) (sizeof(*oudp) + payload_len));
    out->port = m->port;
    rte_pktmbuf_free(m);
    return out;
}

static struct rte_mbuf *rebuild_ipv6_udp_payload(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                                 const uint8_t *payload, size_t payload_len)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *) (ip6 + 1);
    uint16_t total_len;
    struct rte_mbuf *out;
    char *buf;
    struct rte_ether_hdr *oeth;
    struct rte_ipv6_hdr *oip6;
    struct rte_udp_hdr *oudp;

    if (payload_len > UINT16_MAX - sizeof(*udp)) {
        stats_note_frag_dropped(ctx);
        rte_pktmbuf_free(m);
        return NULL;
    }
    total_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip6) + sizeof(*oudp) + payload_len);
    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        rte_pktmbuf_free(m);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip6 = (struct rte_ipv6_hdr *) (oeth + 1);
    oudp = (struct rte_udp_hdr *) (oip6 + 1);
    *oeth = *eth;
    *oip6 = *ip6;
    *oudp = *udp;
    memcpy(oudp + 1, payload, payload_len);
    oip6->payload_len = rte_cpu_to_be_16((uint16_t) (sizeof(*oudp) + payload_len));
    oudp->dgram_len = rte_cpu_to_be_16((uint16_t) (sizeof(*oudp) + payload_len));
    out->port = m->port;
    rte_pktmbuf_free(m);
    return out;
}

static struct rte_mbuf *apply_sip_alg_v6_to_v4(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                               const struct nat64_session *sess)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *) (ip4 + 1);
    uint16_t udp_len = rte_be_to_cpu_16(udp->dgram_len);
    uint16_t payload_len;
    uint8_t rewritten[NAT64_SIP_MAX_PAYLOAD];
    size_t rewritten_len = 0;
    bool changed = false;
    char client6[INET6_ADDRSTRLEN];
    char service6[INET6_ADDRSTRLEN];
    char local4[INET_ADDRSTRLEN];
    char rs4[INET_ADDRSTRLEN];
    char client6_bracket[INET6_ADDRSTRLEN + 2];
    char service6_bracket[INET6_ADDRSTRLEN + 2];
    char body_from_client[INET6_ADDRSTRLEN + 4];
    char body_from_service[INET6_ADDRSTRLEN + 4];
    char body_to_local[INET_ADDRSTRLEN + 4];
    char body_to_rs[INET_ADDRSTRLEN + 4];

    if (udp_len < sizeof(*udp) || !is_sip_udp_packet(udp, udp_len)) {
        return m;
    }
    payload_len = (uint16_t) (udp_len - sizeof(*udp));
    if (payload_len == 0 || payload_len > NAT64_SIP_MAX_PAYLOAD) {
        return m;
    }
    if (inet_ntop(AF_INET6, &sess->client_v6, client6, sizeof(client6)) == NULL ||
        inet_ntop(AF_INET6, &sess->service_v6, service6, sizeof(service6)) == NULL ||
        inet_ntop(AF_INET, &sess->local_v4, local4, sizeof(local4)) == NULL ||
        inet_ntop(AF_INET, &sess->rs_v4, rs4, sizeof(rs4)) == NULL) {
        return m;
    }
    snprintf(client6_bracket, sizeof(client6_bracket), "[%s]", client6);
    snprintf(service6_bracket, sizeof(service6_bracket), "[%s]", service6);
    snprintf(body_from_client, sizeof(body_from_client), "IP6 %s", client6);
    snprintf(body_from_service, sizeof(body_from_service), "IP6 %s", service6);
    snprintf(body_to_local, sizeof(body_to_local), "IP4 %s", local4);
    snprintf(body_to_rs, sizeof(body_to_rs), "IP4 %s", rs4);

    if (!sip_rewrite_payload((const uint8_t *) (udp + 1), payload_len,
                             client6_bracket, local4,
                             service6_bracket, rs4,
                             body_from_client, body_to_local,
                             body_from_service, body_to_rs,
                             rewritten, sizeof(rewritten), &rewritten_len, &changed) ||
        !changed) {
        return m;
    }
    return rebuild_ipv4_udp_payload(ctx, m, rewritten, rewritten_len);
}

static struct rte_mbuf *apply_sip_alg_v4_to_v6(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                               const struct nat64_session *sess)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *) (ip6 + 1);
    uint16_t udp_len = rte_be_to_cpu_16(udp->dgram_len);
    uint16_t payload_len;
    uint8_t rewritten[NAT64_SIP_MAX_PAYLOAD];
    size_t rewritten_len = 0;
    bool changed = false;
    char client6[INET6_ADDRSTRLEN];
    char service6[INET6_ADDRSTRLEN];
    char local4[INET_ADDRSTRLEN];
    char rs4[INET_ADDRSTRLEN];
    char client6_bracket[INET6_ADDRSTRLEN + 2];
    char service6_bracket[INET6_ADDRSTRLEN + 2];
    char body_from_local[INET_ADDRSTRLEN + 4];
    char body_from_rs[INET_ADDRSTRLEN + 4];
    char body_to_client[INET6_ADDRSTRLEN + 4];
    char body_to_service[INET6_ADDRSTRLEN + 4];

    if (udp_len < sizeof(*udp) || !is_sip_udp_packet(udp, udp_len)) {
        return m;
    }
    payload_len = (uint16_t) (udp_len - sizeof(*udp));
    if (payload_len == 0 || payload_len > NAT64_SIP_MAX_PAYLOAD) {
        return m;
    }
    if (inet_ntop(AF_INET6, &sess->client_v6, client6, sizeof(client6)) == NULL ||
        inet_ntop(AF_INET6, &sess->service_v6, service6, sizeof(service6)) == NULL ||
        inet_ntop(AF_INET, &sess->local_v4, local4, sizeof(local4)) == NULL ||
        inet_ntop(AF_INET, &sess->rs_v4, rs4, sizeof(rs4)) == NULL) {
        return m;
    }
    snprintf(client6_bracket, sizeof(client6_bracket), "[%s]", client6);
    snprintf(service6_bracket, sizeof(service6_bracket), "[%s]", service6);
    snprintf(body_from_local, sizeof(body_from_local), "IP4 %s", local4);
    snprintf(body_from_rs, sizeof(body_from_rs), "IP4 %s", rs4);
    snprintf(body_to_client, sizeof(body_to_client), "IP6 %s", client6);
    snprintf(body_to_service, sizeof(body_to_service), "IP6 %s", service6);

    if (!sip_rewrite_payload((const uint8_t *) (udp + 1), payload_len,
                             local4, client6_bracket,
                             rs4, service6_bracket,
                             body_from_local, body_to_client,
                             body_from_rs, body_to_service,
                             rewritten, sizeof(rewritten), &rewritten_len, &changed) ||
        !changed) {
        return m;
    }
    return rebuild_ipv6_udp_payload(ctx, m, rewritten, rewritten_len);
}

static bool is_h323_port(uint16_t port)
{
    return port == H323_RAS_PORT || port == H323_H225_PORT;
}

static bool h323_port_pair(uint16_t src_port, uint16_t dst_port)
{
    return is_h323_port(src_port) || is_h323_port(dst_port);
}

static const struct in6_addr *h323_v6_for_v4(const struct nat64_session *sess, const uint8_t *v4)
{
    if (memcmp(v4, &sess->local_v4.s_addr, sizeof(sess->local_v4.s_addr)) == 0) {
        return &sess->client_v6;
    }
    if (memcmp(v4, &sess->rs_v4.s_addr, sizeof(sess->rs_v4.s_addr)) == 0) {
        return &sess->service_v6;
    }
    return NULL;
}

static const struct in_addr *h323_v4_for_v6(const struct nat64_session *sess, const uint8_t *v6)
{
    if (memcmp(v6, &sess->client_v6, sizeof(sess->client_v6)) == 0) {
        return &sess->local_v4;
    }
    if (memcmp(v6, &sess->service_v6, sizeof(sess->service_v6)) == 0) {
        return &sess->rs_v4;
    }
    return NULL;
}

static bool h323_append_v4_to_v6_addr(const uint8_t *in, size_t in_len, size_t *pos,
                                      const struct nat64_session *sess,
                                      uint8_t *out, size_t cap, size_t *out_len,
                                      uint32_t *rewrites)
{
    const struct in6_addr *v6;

    if (*pos + 10 <= in_len && memcmp(in + *pos, "\x80\x00\x07\x00", 4) == 0 &&
        (v6 = h323_v6_for_v4(sess, in + *pos + 4)) != NULL) {
        if (!append_bytes(out, cap, out_len, "\x80\x13\x30", 3) ||
            !append_bytes(out, cap, out_len, v6, sizeof(*v6)) ||
            !append_bytes(out, cap, out_len, in + *pos + 8, 2)) {
            return false;
        }
        *pos += 10;
        (*rewrites)++;
        return true;
    }

    if (*pos + 7 <= in_len && in[*pos] == 0 &&
        (v6 = h323_v6_for_v4(sess, in + *pos + 1)) != NULL) {
        bool use_aligned_prefix = *pos > 0 && in[*pos - 1] == 0x30;

        if (!append_bytes(out, cap, out_len, use_aligned_prefix ? "\x03\x00" : "\x30",
                          use_aligned_prefix ? 2 : 1) ||
            !append_bytes(out, cap, out_len, v6, sizeof(*v6)) ||
            !append_bytes(out, cap, out_len, in + *pos + 5, 2)) {
            return false;
        }
        *pos += 7;
        (*rewrites)++;
        return true;
    }

    return false;
}

static bool h323_append_v6_to_v4_addr(const uint8_t *in, size_t in_len, size_t *pos,
                                      const struct nat64_session *sess,
                                      uint8_t *out, size_t cap, size_t *out_len,
                                      uint32_t *rewrites)
{
    const struct in_addr *v4;

    if (*pos + 21 <= in_len && memcmp(in + *pos, "\x80\x13\x30", 3) == 0 &&
        (v4 = h323_v4_for_v6(sess, in + *pos + 3)) != NULL) {
        if (!append_bytes(out, cap, out_len, "\x80\x00\x07\x00", 4) ||
            !append_bytes(out, cap, out_len, &v4->s_addr, sizeof(v4->s_addr)) ||
            !append_bytes(out, cap, out_len, in + *pos + 19, 2)) {
            return false;
        }
        *pos += 21;
        (*rewrites)++;
        return true;
    }

    if (*pos + 20 <= in_len && memcmp(in + *pos, "\x03\x00", 2) == 0 &&
        (v4 = h323_v4_for_v6(sess, in + *pos + 2)) != NULL) {
        if (!append_bytes(out, cap, out_len, "\x00", 1) ||
            !append_bytes(out, cap, out_len, &v4->s_addr, sizeof(v4->s_addr)) ||
            !append_bytes(out, cap, out_len, in + *pos + 18, 2)) {
            return false;
        }
        *pos += 20;
        (*rewrites)++;
        return true;
    }

    if (*pos + 19 <= in_len && in[*pos] == 0x30 &&
        (v4 = h323_v4_for_v6(sess, in + *pos + 1)) != NULL) {
        if (!append_bytes(out, cap, out_len, "\x00", 1) ||
            !append_bytes(out, cap, out_len, &v4->s_addr, sizeof(v4->s_addr)) ||
            !append_bytes(out, cap, out_len, in + *pos + 17, 2)) {
            return false;
        }
        *pos += 19;
        (*rewrites)++;
        return true;
    }

    return false;
}

static bool h323_rewrite_bytes(const uint8_t *in, size_t in_len, const struct nat64_session *sess,
                               bool v6_to_v4, uint8_t *out, size_t cap, size_t *out_len,
                               uint32_t *rewrites)
{
    size_t pos = 0;

    *out_len = 0;
    *rewrites = 0;
    while (pos < in_len) {
        size_t before = pos;
        bool matched = v6_to_v4 ?
            h323_append_v6_to_v4_addr(in, in_len, &pos, sess, out, cap, out_len, rewrites) :
            h323_append_v4_to_v6_addr(in, in_len, &pos, sess, out, cap, out_len, rewrites);

        if (matched) {
            continue;
        }
        if (pos != before || !append_bytes(out, cap, out_len, in + pos, 1)) {
            return false;
        }
        pos++;
    }
    return true;
}

static uint16_t h323_read_be16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static bool h323_rewrite_tpkt_frame(const uint8_t *frame, size_t frame_len,
                                    const struct nat64_session *sess, bool v6_to_v4,
                                    uint8_t *out, size_t cap, size_t *out_len,
                                    uint32_t *rewrites)
{
    size_t ie_pos = SIZE_MAX;
    uint16_t ie_len = 0;
    uint8_t rewritten[NAT64_H323_MAX_PAYLOAD];
    size_t rewritten_len = 0;
    uint32_t frame_rewrites = 0;

    *out_len = 0;
    *rewrites = 0;
    if (frame_len < 4 || frame[0] != 3 || frame[1] != 0) {
        return h323_rewrite_bytes(frame, frame_len, sess, v6_to_v4, out, cap, out_len, rewrites);
    }

    for (size_t pos = 4; pos + 3 <= frame_len; pos++) {
        if (frame[pos] != 0x7e) {
            continue;
        }
        ie_len = h323_read_be16(frame + pos + 1);
        if (pos + 3 + ie_len <= frame_len) {
            ie_pos = pos;
            break;
        }
    }
    if (ie_pos == SIZE_MAX) {
        return append_bytes(out, cap, out_len, frame, frame_len);
    }

    if (!h323_rewrite_bytes(frame + ie_pos + 3, ie_len, sess, v6_to_v4,
                            rewritten, sizeof(rewritten), &rewritten_len, &frame_rewrites)) {
        return false;
    }
    if (frame_rewrites == 0) {
        return append_bytes(out, cap, out_len, frame, frame_len);
    }

    size_t new_frame_len = frame_len - ie_len + rewritten_len;
    size_t new_ie_len = rewritten_len;
    uint8_t hdr[4];
    uint8_t ie_hdr[3];

    if (new_frame_len > UINT16_MAX || new_ie_len > UINT16_MAX) {
        return false;
    }
    memcpy(hdr, frame, sizeof(hdr));
    hdr[2] = (uint8_t) (new_frame_len >> 8);
    hdr[3] = (uint8_t) new_frame_len;
    ie_hdr[0] = 0x7e;
    ie_hdr[1] = (uint8_t) (new_ie_len >> 8);
    ie_hdr[2] = (uint8_t) new_ie_len;

    if (!append_bytes(out, cap, out_len, hdr, sizeof(hdr)) ||
        !append_bytes(out, cap, out_len, frame + 4, ie_pos - 4) ||
        !append_bytes(out, cap, out_len, ie_hdr, sizeof(ie_hdr)) ||
        !append_bytes(out, cap, out_len, rewritten, rewritten_len) ||
        !append_bytes(out, cap, out_len, frame + ie_pos + 3 + ie_len,
                      frame_len - ie_pos - 3 - ie_len)) {
        return false;
    }

    *rewrites = frame_rewrites;
    return true;
}

static bool h323_rewrite_payload(const uint8_t *payload, size_t payload_len,
                                 const struct nat64_session *sess, bool v6_to_v4,
                                 uint8_t *out, size_t cap, size_t *out_len,
                                 uint32_t *rewrites)
{
    size_t pos = 0;

    *out_len = 0;
    *rewrites = 0;
    while (pos + 4 <= payload_len && payload[pos] == 3 && payload[pos + 1] == 0) {
        uint16_t frame_len = h323_read_be16(payload + pos + 2);
        uint8_t frame_out[NAT64_H323_MAX_PAYLOAD];
        size_t frame_out_len = 0;
        uint32_t frame_rewrites = 0;

        if (frame_len < 4 || pos + frame_len > payload_len) {
            break;
        }
        if (!h323_rewrite_tpkt_frame(payload + pos, frame_len, sess, v6_to_v4,
                                     frame_out, sizeof(frame_out), &frame_out_len, &frame_rewrites) ||
            !append_bytes(out, cap, out_len, frame_out, frame_out_len)) {
            return false;
        }
        *rewrites += frame_rewrites;
        pos += frame_len;
    }

    if (pos < payload_len) {
        uint8_t tail_out[NAT64_H323_MAX_PAYLOAD];
        size_t tail_out_len = 0;
        uint32_t tail_rewrites = 0;

        if (!h323_rewrite_bytes(payload + pos, payload_len - pos, sess, v6_to_v4,
                                tail_out, sizeof(tail_out), &tail_out_len, &tail_rewrites) ||
            !append_bytes(out, cap, out_len, tail_out, tail_out_len)) {
            return false;
        }
        *rewrites += tail_rewrites;
    }
    return true;
}

static uint16_t l4_header_len(uint8_t proto, const void *l4, uint16_t l4_len)
{
    if (proto == IPPROTO_UDP) {
        return l4_len >= sizeof(struct rte_udp_hdr) ? sizeof(struct rte_udp_hdr) : 0;
    }
    if (proto == IPPROTO_TCP && l4_len >= sizeof(struct rte_tcp_hdr)) {
        const struct rte_tcp_hdr *tcp = l4;
        uint16_t hdr_len = (uint16_t) ((tcp->data_off >> 4) * 4);

        return hdr_len >= sizeof(*tcp) && hdr_len <= l4_len ? hdr_len : 0;
    }
    return 0;
}

static void adjust_tcp_seq_ack(struct rte_tcp_hdr *tcp, int32_t seq_delta, int32_t ack_delta)
{
    uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq);
    uint32_t ack = rte_be_to_cpu_32(tcp->recv_ack);

    tcp->sent_seq = rte_cpu_to_be_32(seq + (uint32_t) seq_delta);
    if (tcp->tcp_flags & 0x10) {
        tcp->recv_ack = rte_cpu_to_be_32(ack + (uint32_t) ack_delta);
    }
}

static struct rte_mbuf *rebuild_ipv4_l4_payload(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                                uint8_t proto, const uint8_t *payload, size_t payload_len)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    void *l4 = ip4 + 1;
    uint16_t old_l4_len = (uint16_t) (rte_be_to_cpu_16(ip4->total_length) - sizeof(*ip4));
    uint16_t hdr_len = l4_header_len(proto, l4, old_l4_len);
    struct rte_mbuf *out;
    char *buf;
    struct rte_ether_hdr *oeth;
    struct rte_ipv4_hdr *oip4;
    void *ol4;
    uint16_t total_len;

    if (hdr_len == 0 || payload_len > UINT16_MAX - sizeof(*ip4) - hdr_len) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    total_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip4) + hdr_len + payload_len);
    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        rte_pktmbuf_free(m);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip4 = (struct rte_ipv4_hdr *) (oeth + 1);
    ol4 = oip4 + 1;
    *oeth = *eth;
    *oip4 = *ip4;
    memcpy(ol4, l4, hdr_len);
    memcpy((uint8_t *) ol4 + hdr_len, payload, payload_len);
    oip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*oip4) + hdr_len + payload_len));
    if (proto == IPPROTO_UDP) {
        ((struct rte_udp_hdr *) ol4)->dgram_len = rte_cpu_to_be_16((uint16_t) (hdr_len + payload_len));
    }
    out->port = m->port;
    rte_pktmbuf_free(m);
    return out;
}

static struct rte_mbuf *rebuild_ipv6_l4_payload(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                                uint8_t proto, const uint8_t *payload, size_t payload_len)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    void *l4 = ip6 + 1;
    uint16_t old_l4_len = rte_be_to_cpu_16(ip6->payload_len);
    uint16_t hdr_len = l4_header_len(proto, l4, old_l4_len);
    struct rte_mbuf *out;
    char *buf;
    struct rte_ether_hdr *oeth;
    struct rte_ipv6_hdr *oip6;
    void *ol4;
    uint16_t total_len;

    if (hdr_len == 0 || payload_len > (size_t) (UINT16_MAX - hdr_len)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    total_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip6) + hdr_len + payload_len);
    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        rte_pktmbuf_free(m);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip6 = (struct rte_ipv6_hdr *) (oeth + 1);
    ol4 = oip6 + 1;
    *oeth = *eth;
    *oip6 = *ip6;
    memcpy(ol4, l4, hdr_len);
    memcpy((uint8_t *) ol4 + hdr_len, payload, payload_len);
    oip6->payload_len = rte_cpu_to_be_16((uint16_t) (hdr_len + payload_len));
    if (proto == IPPROTO_UDP) {
        ((struct rte_udp_hdr *) ol4)->dgram_len = rte_cpu_to_be_16((uint16_t) (hdr_len + payload_len));
    }
    out->port = m->port;
    rte_pktmbuf_free(m);
    return out;
}

static struct rte_mbuf *apply_h323_alg_v6_to_v4(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                                struct nat64_session *sess, int32_t *delta_out)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    void *l4 = ip4 + 1;
    uint16_t l4_len = (uint16_t) (rte_be_to_cpu_16(ip4->total_length) - sizeof(*ip4));
    uint16_t hdr_len = l4_header_len(ip4->next_proto_id, l4, l4_len);
    uint8_t rewritten[NAT64_H323_MAX_PAYLOAD];
    size_t rewritten_len = 0;
    uint32_t rewrites = 0;
    int32_t seq_delta = __atomic_load_n(&sess->tcp_delta_v6_to_v4, __ATOMIC_RELAXED);
    int32_t ack_delta = -__atomic_load_n(&sess->tcp_delta_v4_to_v6, __ATOMIC_RELAXED);

    *delta_out = 0;
    stats_note_h323_packet(ctx, true);
    if (hdr_len == 0 || l4_len < hdr_len || l4_len - hdr_len > NAT64_H323_MAX_PAYLOAD) {
        stats_note_h323_failure(ctx);
        return m;
    }
    if (ip4->next_proto_id == IPPROTO_TCP) {
        adjust_tcp_seq_ack((struct rte_tcp_hdr *) l4, seq_delta, ack_delta);
    }
    if (!h323_rewrite_payload((const uint8_t *) l4 + hdr_len, l4_len - hdr_len, sess, true,
                              rewritten, sizeof(rewritten), &rewritten_len, &rewrites)) {
        stats_note_h323_failure(ctx);
        return m;
    }
    if (rewrites == 0) {
        return m;
    }

    *delta_out = (int32_t) rewritten_len - (int32_t) (l4_len - hdr_len);
    stats_note_h323_rewrite(ctx, true);
    return rebuild_ipv4_l4_payload(ctx, m, ip4->next_proto_id, rewritten, rewritten_len);
}

static struct rte_mbuf *apply_h323_alg_v4_to_v6(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                                struct nat64_session *sess, int32_t *delta_out)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    void *l4 = ip6 + 1;
    uint16_t l4_len = rte_be_to_cpu_16(ip6->payload_len);
    uint16_t hdr_len = l4_header_len(ip6->proto, l4, l4_len);
    uint8_t rewritten[NAT64_H323_MAX_PAYLOAD];
    size_t rewritten_len = 0;
    uint32_t rewrites = 0;
    int32_t seq_delta = __atomic_load_n(&sess->tcp_delta_v4_to_v6, __ATOMIC_RELAXED);
    int32_t ack_delta = -__atomic_load_n(&sess->tcp_delta_v6_to_v4, __ATOMIC_RELAXED);

    *delta_out = 0;
    stats_note_h323_packet(ctx, false);
    if (hdr_len == 0 || l4_len < hdr_len || l4_len - hdr_len > NAT64_H323_MAX_PAYLOAD) {
        stats_note_h323_failure(ctx);
        return m;
    }
    if (ip6->proto == IPPROTO_TCP) {
        adjust_tcp_seq_ack((struct rte_tcp_hdr *) l4, seq_delta, ack_delta);
    }
    if (!h323_rewrite_payload((const uint8_t *) l4 + hdr_len, l4_len - hdr_len, sess, false,
                              rewritten, sizeof(rewritten), &rewritten_len, &rewrites)) {
        stats_note_h323_failure(ctx);
        return m;
    }
    if (rewrites == 0) {
        return m;
    }

    *delta_out = (int32_t) rewritten_len - (int32_t) (l4_len - hdr_len);
    stats_note_h323_rewrite(ctx, false);
    return rebuild_ipv6_l4_payload(ctx, m, ip6->proto, rewritten, rewritten_len);
}

static uint8_t map_icmpv4_error_code_to_v6(uint8_t type, uint8_t code)
{
    if (type == ICMPV4_DEST_UNREACH) {
        switch (code) {
        case ICMPV4_CODE_PORT_UNREACH:
            return ICMPV6_CODE_PORT_UNREACH;
        case ICMPV4_CODE_ADMIN_PROHIBITED:
            return ICMPV6_CODE_ADMIN_PROHIBITED;
        case ICMPV4_CODE_HOST_UNREACH:
            return ICMPV6_CODE_ADDR_UNREACH;
        case ICMPV4_CODE_NET_UNREACH:
        default:
            return ICMPV6_CODE_NOROUTE;
        }
    }
    if (type == ICMPV4_TIME_EXCEEDED) {
        return code == 1 ? ICMPV6_TIME_EXCEED_REASSEMBLY : ICMPV6_TIME_EXCEED_TRANSIT;
    }
    return ICMPV6_PARAMPROB_HEADER;
}

static uint8_t map_icmpv6_error_code_to_v4(uint8_t type, uint8_t code)
{
    if (type == ICMPV6_DEST_UNREACH) {
        switch (code) {
        case ICMPV6_CODE_PORT_UNREACH:
            return ICMPV4_CODE_PORT_UNREACH;
        case ICMPV6_CODE_ADMIN_PROHIBITED:
            return ICMPV4_CODE_ADMIN_PROHIBITED;
        case ICMPV6_CODE_ADDR_UNREACH:
            return ICMPV4_CODE_HOST_UNREACH;
        case ICMPV6_CODE_NOROUTE:
        default:
            return ICMPV4_CODE_NET_UNREACH;
        }
    }
    if (type == ICMPV6_PACKET_TOO_BIG) {
        return ICMPV4_CODE_FRAG_NEEDED;
    }
    return 0;
}

static void rewrite_embedded_l4_v4_to_v6(uint8_t proto, void *l4, uint16_t l4_len, const struct nat64_session *sess)
{
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        if (l4_len >= 4) {
            set_ports(proto, l4, sess->client_port, sess->service_port);
        }
        return;
    }

    if (proto == IPPROTO_ICMP && l4_len >= sizeof(struct rte_icmp_hdr)) {
        struct rte_icmp_hdr *icmp = l4;

        if (icmp->icmp_type == ICMPV4_ECHO_REQUEST) {
            icmp->icmp_type = ICMPV6_ECHO_REQUEST;
        } else if (icmp->icmp_type == ICMPV4_ECHO_REPLY) {
            icmp->icmp_type = ICMPV6_ECHO_REPLY;
        }
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(sess->client_port);
    }
}

static void rewrite_embedded_l4_v6_to_v4(uint8_t proto, void *l4, uint16_t l4_len, const struct nat64_session *sess)
{
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        if (l4_len >= 4) {
            set_ports(proto, l4, sess->rs_port, sess->local_port);
        }
        return;
    }

    if (proto == IPPROTO_ICMPV6 && l4_len >= sizeof(struct rte_icmp_hdr)) {
        struct rte_icmp_hdr *icmp = l4;

        if (icmp->icmp_type == ICMPV6_ECHO_REQUEST) {
            icmp->icmp_type = ICMPV4_ECHO_REQUEST;
        } else if (icmp->icmp_type == ICMPV6_ECHO_REPLY) {
            icmp->icmp_type = ICMPV4_ECHO_REPLY;
        }
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(sess->local_port);
    }
}

static struct rte_mbuf *translate_icmpv4_error_to_v6(struct nat64_ctx *ctx, struct rte_ipv4_hdr *ip4,
                                                     const struct rte_ether_addr *src_mac, uint16_t ip4_payload)
{
    struct icmp_error_hdr *icmp4 = (struct icmp_error_hdr *) (ip4 + 1);
    uint16_t outer_len = (uint16_t) sizeof(*icmp4);
    struct rte_ipv4_hdr *inner4;
    uint16_t inner4_hlen;
    uint16_t quoted_l4_len;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t ignored_hdr_len;
    uint8_t session_proto;
    struct nat64_session *sess;
    struct rte_mbuf *out;
    struct rte_ether_hdr *oeth;
    struct rte_ipv6_hdr *oip6;
    struct icmp_error_hdr *oicmp6;
    struct rte_ipv6_hdr *qip6;
    void *ql4_src;
    void *ql4_dst;
    uint16_t qpayload_len;
    uint16_t qcopy_l4_len;
    uint16_t total_len;
    struct in6_addr src6;

    if (ip4_payload < outer_len + sizeof(struct rte_ipv4_hdr) || !icmpv4_is_error(icmp4->type)) {
        return NULL;
    }

    inner4 = (struct rte_ipv4_hdr *) (icmp4 + 1);
    inner4_hlen = (uint16_t) ((inner4->version_ihl & 0x0fU) * 4U);
    if (inner4_hlen < sizeof(*inner4) || ip4_payload < outer_len + inner4_hlen) {
        return NULL;
    }

    quoted_l4_len = (uint16_t) (ip4_payload - outer_len - inner4_hlen);
    ignored_hdr_len = extract_ports(inner4->next_proto_id, inner4 + 1, quoted_l4_len, &src_port, &dst_port, &session_proto);
    if (ignored_hdr_len == 0) {
        return NULL;
    }

    neighbor4_update(ctx, *(struct in_addr *) &ip4->src_addr, src_mac, rte_rdtsc());

    sess = find_session_v4_outbound(ctx, *(struct in_addr *) &inner4->src_addr, *(struct in_addr *) &inner4->dst_addr,
                                    src_port, dst_port, session_proto);
    if (sess == NULL) {
        return NULL;
    }

    {
        const struct nat64_service_config *nat64_service = service_by_index(ctx, sess->service_index);

        prefix96_embed_v4(&nat64_service->vs.vaddr[0], *(struct in_addr *) &ip4->src_addr, &src6);
    }

    qpayload_len = (uint16_t) (rte_be_to_cpu_16(inner4->total_length) - inner4_hlen);
    qcopy_l4_len = quoted_l4_len;
    total_len = (uint16_t) (sizeof(struct rte_ether_hdr) + sizeof(*oip6) + sizeof(*oicmp6) +
                            sizeof(*qip6) + qcopy_l4_len);

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }
    char *buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip6 = (struct rte_ipv6_hdr *) (oeth + 1);
    oicmp6 = (struct icmp_error_hdr *) (oip6 + 1);
    qip6 = (struct rte_ipv6_hdr *) (oicmp6 + 1);
    ql4_src = inner4 + 1;
    ql4_dst = qip6 + 1;

    rte_ether_addr_copy(&sess->v6_reply_dmac, &oeth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &oeth->src_addr);
    oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    memset(oip6, 0, sizeof(*oip6));
    oip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    oip6->payload_len = rte_cpu_to_be_16((uint16_t) (sizeof(*oicmp6) + sizeof(*qip6) + qcopy_l4_len));
    oip6->proto = IPPROTO_ICMPV6;
    oip6->hop_limits = ip4->time_to_live;
    memcpy(oip6->src_addr, &src6, sizeof(src6));
    memcpy(oip6->dst_addr, &sess->client_v6, sizeof(sess->client_v6));

    memset(oicmp6, 0, sizeof(*oicmp6));
    if (icmp4->type == ICMPV4_DEST_UNREACH && icmp4->code == ICMPV4_CODE_FRAG_NEEDED) {
        uint32_t mtu = (uint32_t) rte_be_to_cpu_32(icmp4->data) & 0xffffU;
        oicmp6->type = ICMPV6_PACKET_TOO_BIG;
        oicmp6->code = 0;
        if (mtu > 0) {
            mtu += (uint32_t) (sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr));
            if (mtu < 1280U) {
                mtu = 1280U;
            }
        }
        oicmp6->data = rte_cpu_to_be_32(mtu);
    } else if (icmp4->type == ICMPV4_DEST_UNREACH) {
        oicmp6->type = ICMPV6_DEST_UNREACH;
        oicmp6->code = map_icmpv4_error_code_to_v6(icmp4->type, icmp4->code);
    } else if (icmp4->type == ICMPV4_TIME_EXCEEDED) {
        oicmp6->type = ICMPV6_TIME_EXCEEDED;
        oicmp6->code = map_icmpv4_error_code_to_v6(icmp4->type, icmp4->code);
    } else {
        oicmp6->type = ICMPV6_PARAM_PROB;
        oicmp6->code = ICMPV6_PARAMPROB_HEADER;
    }

    memset(qip6, 0, sizeof(*qip6));
    qip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    qip6->payload_len = rte_cpu_to_be_16(qpayload_len);
    qip6->proto = inner4->next_proto_id == IPPROTO_ICMP ? IPPROTO_ICMPV6 : inner4->next_proto_id;
    qip6->hop_limits = inner4->time_to_live;
    memcpy(qip6->src_addr, &sess->client_v6, sizeof(sess->client_v6));
    memcpy(qip6->dst_addr, &sess->service_v6, sizeof(sess->service_v6));

    memcpy(ql4_dst, ql4_src, qcopy_l4_len);
    rewrite_embedded_l4_v4_to_v6(inner4->next_proto_id, ql4_dst, qcopy_l4_len, sess);

    oicmp6->checksum = 0;
    oicmp6->checksum = l4_checksum_ipv6(oip6, oicmp6, sizeof(*oicmp6) + sizeof(*qip6) + qcopy_l4_len,
                                        IPPROTO_ICMPV6);
    stats_note_icmp_error_v4_to_v6(ctx);
    out->port = ctx->port_v6;
    return out;
}

static bool select_icmpv6_error_outer_src4(const struct nat64_service_config *nat64_service,
                                           const struct nat64_session *sess,
                                           const struct in6_addr *outer_src6,
                                           struct in_addr *outer_src4)
{
    for (uint32_t i = 0; i < nat64_service->vs.vaddr_count; i++) {
        if (prefix96_extract_v4(&nat64_service->vs.vaddr[i], outer_src6, outer_src4)) {
            return true;
        }
    }

    *outer_src4 = sess->local_v4;
    return false;
}

static struct rte_mbuf *translate_icmpv6_error_to_v4(struct nat64_ctx *ctx, uint16_t queue_id,
                                                     struct rte_ipv6_hdr *ip6,
                                                     const struct rte_ether_addr *src_mac, uint16_t ip6_payload)
{
    struct icmp_error_hdr *icmp6 = (struct icmp_error_hdr *) (ip6 + 1);
    uint16_t outer_len = (uint16_t) sizeof(*icmp6);
    struct rte_ipv6_hdr *inner6;
    uint16_t quoted_l4_len;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t ignored_hdr_len;
    uint8_t session_proto;
    struct nat64_session *sess;
    struct rte_mbuf *out;
    struct rte_ether_hdr *oeth;
    struct rte_ipv4_hdr *oip4;
    struct icmp_error_hdr *oicmp4;
    struct rte_ipv4_hdr *qip4;
    void *ql4_src;
    void *ql4_dst;
    uint16_t qpayload_len;
    uint16_t qcopy_l4_len;
    uint16_t total_len;
    struct in_addr src4;
    bool src4_from_pref64;

    if (ip6_payload < outer_len + sizeof(struct rte_ipv6_hdr) || !icmpv6_is_error(icmp6->type)) {
        return NULL;
    }

    inner6 = (struct rte_ipv6_hdr *) (icmp6 + 1);
    quoted_l4_len = (uint16_t) (ip6_payload - outer_len - sizeof(*inner6));
    ignored_hdr_len = extract_ports(inner6->proto, inner6 + 1, quoted_l4_len, &src_port, &dst_port, &session_proto);
    if (ignored_hdr_len == 0) {
        return NULL;
    }

    neighbor6_update(ctx, (const struct in6_addr *) ip6->src_addr, src_mac, rte_rdtsc());

    sess = find_session_v6_translated(ctx, (const struct in6_addr *) inner6->src_addr,
                                      (const struct in6_addr *) inner6->dst_addr,
                                      src_port, dst_port, session_proto);
    if (sess == NULL) {
        return NULL;
    }

    {
        const struct nat64_service_config *nat64_service = service_by_index(ctx, sess->service_index);

        src4_from_pref64 = select_icmpv6_error_outer_src4(nat64_service, sess,
                                                          (const struct in6_addr *) ip6->src_addr, &src4);
    }

    qpayload_len = rte_be_to_cpu_16(inner6->payload_len);
    qcopy_l4_len = quoted_l4_len;
    total_len = (uint16_t) (sizeof(struct rte_ether_hdr) + sizeof(*oip4) + sizeof(*oicmp4) +
                            sizeof(*qip4) + qcopy_l4_len);

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }
    char *buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip4 = (struct rte_ipv4_hdr *) (oeth + 1);
    oicmp4 = (struct icmp_error_hdr *) (oip4 + 1);
    qip4 = (struct rte_ipv4_hdr *) (oicmp4 + 1);
    ql4_src = inner6 + 1;
    ql4_dst = qip4 + 1;

    {
        struct rte_ether_addr dst_mac;
        struct nat64_route4_entry route4;
        struct in_addr neigh_ip = sess->rs_v4;

        if (route_lookup4_ctx(ctx, queue_id, sess->rs_v4, &route4)) {
            if (!route4.direct) {
                neigh_ip = route4.via;
            }
        } else if (ctx->opts.has_v4_next_hop) {
            dst_mac = ctx->opts.v4_next_hop;
            goto icmpv6_v4_nh_resolved;
        }

        if (!neighbor4_lookup(ctx, queue_id, neigh_ip, &dst_mac, rte_rdtsc())) {
            rte_pktmbuf_free(out);
            return build_arp_request(ctx, sess->local_v4, neigh_ip);
        }
icmpv6_v4_nh_resolved:
        rte_ether_addr_copy(&dst_mac, &oeth->dst_addr);
    }

    rte_ether_addr_copy(&ctx->port_v4_mac, &oeth->src_addr);
    oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(oip4, 0, sizeof(*oip4));
    oip4->version_ihl = RTE_IPV4_VHL_DEF;
    oip4->time_to_live = ip6->hop_limits;
    oip4->next_proto_id = IPPROTO_ICMP;
    oip4->src_addr = src4.s_addr;
    oip4->dst_addr = sess->rs_v4.s_addr;
    oip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*oip4) + sizeof(*oicmp4) + sizeof(*qip4) + qcopy_l4_len));

    memset(oicmp4, 0, sizeof(*oicmp4));
    if (icmp6->type == ICMPV6_PACKET_TOO_BIG) {
        uint32_t mtu = rte_be_to_cpu_32(icmp6->data);
        oicmp4->type = ICMPV4_DEST_UNREACH;
        oicmp4->code = ICMPV4_CODE_FRAG_NEEDED;
        if (mtu > (uint32_t) (sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr))) {
            mtu -= (uint32_t) (sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr));
        }
        oicmp4->data = rte_cpu_to_be_32(mtu & 0xffffU);
    } else if (icmp6->type == ICMPV6_DEST_UNREACH) {
        oicmp4->type = ICMPV4_DEST_UNREACH;
        oicmp4->code = map_icmpv6_error_code_to_v4(icmp6->type, icmp6->code);
    } else if (icmp6->type == ICMPV6_TIME_EXCEEDED) {
        oicmp4->type = ICMPV4_TIME_EXCEEDED;
        oicmp4->code = icmp6->code == ICMPV6_TIME_EXCEED_REASSEMBLY ? 1 : 0;
    } else {
        oicmp4->type = ICMPV4_PARAM_PROB;
        oicmp4->code = 0;
    }

    memset(qip4, 0, sizeof(*qip4));
    qip4->version_ihl = RTE_IPV4_VHL_DEF;
    qip4->time_to_live = inner6->hop_limits;
    qip4->next_proto_id = inner6->proto == IPPROTO_ICMPV6 ? IPPROTO_ICMP : inner6->proto;
    qip4->src_addr = sess->rs_v4.s_addr;
    qip4->dst_addr = sess->local_v4.s_addr;
    qip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*qip4) + qpayload_len));
    qip4->hdr_checksum = 0;
    qip4->hdr_checksum = ipv4_checksum(qip4, sizeof(*qip4));

    memcpy(ql4_dst, ql4_src, qcopy_l4_len);
    rewrite_embedded_l4_v6_to_v4(inner6->proto, ql4_dst, qcopy_l4_len, sess);

    oicmp4->checksum = 0;
    oicmp4->checksum = ipv4_checksum(oicmp4, sizeof(*oicmp4) + sizeof(*qip4) + qcopy_l4_len);
    oip4->hdr_checksum = 0;
    oip4->hdr_checksum = ipv4_checksum(oip4, sizeof(*oip4));
    stats_note_icmp_error_v6_to_v4(ctx, src4_from_pref64);
    out->port = ctx->port_v4;
    return out;
}

static struct rte_mbuf *build_arp_request(struct nat64_ctx *ctx, struct in_addr sender, struct in_addr target)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_arp_hdr *arp;
    char *buf;

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, sizeof(*eth) + sizeof(*arp));
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    arp = (struct rte_arp_hdr *) (eth + 1);

    rte_ether_addr_copy(&ether_broadcast_addr, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(*arp));
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(rte_be32_t);
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&ctx->port_v4_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = sender.s_addr;
    rte_ether_addr_copy(&ether_zero_addr, &arp->arp_data.arp_tha);
    arp->arp_data.arp_tip = target.s_addr;
    m->port = ctx->port_v4;
    return m;
}

static struct rte_mbuf *build_gratuitous_arp(struct nat64_ctx *ctx, struct in_addr owner_ip, bool is_reply)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_arp_hdr *arp;
    char *buf;

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, sizeof(*eth) + sizeof(*arp));
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    arp = (struct rte_arp_hdr *) (eth + 1);

    rte_ether_addr_copy(&ether_broadcast_addr, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(*arp));
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(rte_be32_t);
    arp->arp_opcode = rte_cpu_to_be_16(is_reply ? RTE_ARP_OP_REPLY : RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&ctx->port_v4_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = owner_ip.s_addr;
    if (is_reply) {
        rte_ether_addr_copy(&ether_broadcast_addr, &arp->arp_data.arp_tha);
    } else {
        rte_ether_addr_copy(&ether_zero_addr, &arp->arp_data.arp_tha);
    }
    arp->arp_data.arp_tip = owner_ip.s_addr;
    m->port = ctx->port_v4;
    return m;
}

static void mark_laddr_announce(struct nat64_ctx *ctx, struct in_addr ip, uint64_t now_tsc)
{
    int idx = laddr_index(ctx, ip);

    if (idx < 0) {
        return;
    }

    rte_spinlock_lock(&ctx->laddr_lock);
    ctx->laddr_state[idx].last_announce_tsc = now_tsc;
    rte_spinlock_unlock(&ctx->laddr_lock);
}

static void mark_laddr_conflict(struct nat64_ctx *ctx, struct in_addr ip, const struct rte_ether_addr *mac,
                                uint64_t now_tsc)
{
    int idx = laddr_index(ctx, ip);
    char ipbuf[INET_ADDRSTRLEN];
    char macbuf[32];

    if (idx < 0) {
        return;
    }

    rte_spinlock_lock(&ctx->laddr_lock);
    ctx->laddr_state[idx].conflict_detected = true;
    ctx->laddr_state[idx].last_conflict_tsc = now_tsc;
    rte_ether_addr_copy(mac, &ctx->laddr_state[idx].conflict_mac);
    rte_spinlock_unlock(&ctx->laddr_lock);

    inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
    format_mac(mac, macbuf, sizeof(macbuf));
    rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1, "ARP conflict on %s from MAC %s\n", ipbuf, macbuf);
}

static void clear_laddr_conflict(struct nat64_ctx *ctx, struct in_addr ip)
{
    int idx = laddr_index(ctx, ip);

    if (idx < 0) {
        return;
    }

    rte_spinlock_lock(&ctx->laddr_lock);
    ctx->laddr_state[idx].conflict_detected = false;
    rte_spinlock_unlock(&ctx->laddr_lock);
}

static bool solicited_node_multicast(const struct in6_addr *target, struct in6_addr *mcast)
{
    static const uint8_t prefix[13] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff};
    memset(mcast, 0, sizeof(*mcast));
    memcpy(mcast->s6_addr, prefix, sizeof(prefix));
    mcast->s6_addr[13] = target->s6_addr[13];
    mcast->s6_addr[14] = target->s6_addr[14];
    mcast->s6_addr[15] = target->s6_addr[15];
    return true;
}

static void solicited_node_mac(const struct in6_addr *target, struct rte_ether_addr *mac)
{
    mac->addr_bytes[0] = 0x33;
    mac->addr_bytes[1] = 0x33;
    mac->addr_bytes[2] = 0xff;
    mac->addr_bytes[3] = target->s6_addr[13];
    mac->addr_bytes[4] = target->s6_addr[14];
    mac->addr_bytes[5] = target->s6_addr[15];
}

static struct rte_mbuf *build_nd_solicit(struct nat64_ctx *ctx, const struct in6_addr *target)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_ipv6_hdr *ip6;
    struct nd_msg *nd;
    struct nd_opt_lladdr *opt;
    struct in6_addr mcast;
    char *buf;
    uint16_t payload_len = (uint16_t) (sizeof(*nd) + sizeof(*opt));

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, sizeof(*eth) + sizeof(*ip6) + payload_len);
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    nd = (struct nd_msg *) (ip6 + 1);
    opt = (struct nd_opt_lladdr *) (nd + 1);

    solicited_node_multicast(target, &mcast);
    solicited_node_mac(target, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    ip6->payload_len = rte_cpu_to_be_16(payload_len);
    ip6->proto = IPPROTO_ICMPV6;
    ip6->hop_limits = 255;
    memcpy(ip6->src_addr, &ctx->port_v6_addr, sizeof(ctx->port_v6_addr));
    memcpy(ip6->dst_addr, &mcast, sizeof(mcast));

    memset(nd, 0, sizeof(*nd));
    nd->type = ND_NEIGHBOR_SOLICIT;
    memcpy(nd->target, target, sizeof(*target));

    opt->type = ICMPV6_OPT_SOURCE_LINKADDR;
    opt->len = 1;
    rte_ether_addr_copy(&ctx->port_v6_mac, &opt->addr);

    nd->checksum = l4_checksum_ipv6(ip6, nd, payload_len, IPPROTO_ICMPV6);
    m->port = ctx->port_v6;
    return m;
}

static struct rte_mbuf *build_nd_advert(struct nat64_ctx *ctx, const struct in6_addr *target,
                                        const struct in6_addr *dst_ip, const struct rte_ether_addr *dst_mac)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_ipv6_hdr *ip6;
    struct nd_msg *nd;
    struct nd_opt_lladdr *opt;
    char *buf;
    uint16_t payload_len = (uint16_t) (sizeof(*nd) + sizeof(*opt));

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, sizeof(*eth) + sizeof(*ip6) + payload_len);
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    nd = (struct nd_msg *) (ip6 + 1);
    opt = (struct nd_opt_lladdr *) (nd + 1);

    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    ip6->payload_len = rte_cpu_to_be_16(payload_len);
    ip6->proto = IPPROTO_ICMPV6;
    ip6->hop_limits = 255;
    memcpy(ip6->src_addr, target, sizeof(*target));
    memcpy(ip6->dst_addr, dst_ip, sizeof(*dst_ip));

    memset(nd, 0, sizeof(*nd));
    nd->type = ND_NEIGHBOR_ADVERT;
    nd->flags = rte_cpu_to_be_32(0x60000000U);
    memcpy(nd->target, target, sizeof(*target));

    opt->type = ICMPV6_OPT_TARGET_LINKADDR;
    opt->len = 1;
    rte_ether_addr_copy(&ctx->port_v6_mac, &opt->addr);

    nd->checksum = l4_checksum_ipv6(ip6, nd, payload_len, IPPROTO_ICMPV6);
    m->port = ctx->port_v6;
    return m;
}

static struct rte_mbuf *build_icmpv4_echo_request(struct nat64_ctx *ctx, struct in_addr src, struct in_addr dst,
                                                  const struct rte_ether_addr *dst_mac, uint16_t ident,
                                                  uint16_t seq)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip4;
    struct rte_icmp_hdr *icmp;
    uint32_t *payload;
    char *buf;
    uint16_t payload_len = sizeof(*icmp) + 8;
    uint16_t total_len = (uint16_t) (sizeof(*eth) + sizeof(*ip4) + payload_len);

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    icmp = (struct rte_icmp_hdr *) (ip4 + 1);
    payload = (uint32_t *) (icmp + 1);

    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(ip4, 0, sizeof(*ip4));
    ip4->version_ihl = RTE_IPV4_VHL_DEF;
    ip4->time_to_live = 64;
    ip4->next_proto_id = IPPROTO_ICMP;
    ip4->src_addr = src.s_addr;
    ip4->dst_addr = dst.s_addr;
    ip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*ip4) + payload_len));

    memset(icmp, 0, payload_len);
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
    icmp->icmp_ident = rte_cpu_to_be_16(ident);
    icmp->icmp_seq_nb = rte_cpu_to_be_16(seq);
    payload[0] = rte_cpu_to_be_32(0x4e363456U);
    payload[1] = rte_cpu_to_be_32(seq);
    icmp->icmp_cksum = ipv4_checksum(icmp, payload_len);
    ip4->hdr_checksum = ipv4_checksum(ip4, sizeof(*ip4));
    m->port = ctx->port_v4;
    return m;
}

static struct rte_mbuf *build_tcpv4_packet(struct nat64_ctx *ctx, struct in_addr src, struct in_addr dst,
                                           const struct rte_ether_addr *dst_mac, uint16_t sport, uint16_t dport,
                                           uint32_t seq, uint32_t ack, uint8_t flags,
                                           const char *payload, uint16_t payload_len)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip4;
    struct rte_tcp_hdr *tcp;
    char *buf;
    uint16_t l4_len = (uint16_t) (sizeof(*tcp) + payload_len);
    uint16_t total_len = (uint16_t) (sizeof(*eth) + sizeof(*ip4) + l4_len);

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    tcp = (struct rte_tcp_hdr *) (ip4 + 1);

    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(ip4, 0, sizeof(*ip4));
    ip4->version_ihl = RTE_IPV4_VHL_DEF;
    ip4->time_to_live = 64;
    ip4->next_proto_id = IPPROTO_TCP;
    ip4->src_addr = src.s_addr;
    ip4->dst_addr = dst.s_addr;
    ip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*ip4) + l4_len));

    memset(tcp, 0, sizeof(*tcp));
    tcp->src_port = rte_cpu_to_be_16(sport);
    tcp->dst_port = rte_cpu_to_be_16(dport);
    tcp->sent_seq = rte_cpu_to_be_32(seq);
    tcp->recv_ack = rte_cpu_to_be_32(ack);
    tcp->data_off = (uint8_t) ((sizeof(*tcp) / 4U) << 4);
    tcp->tcp_flags = flags;
    tcp->rx_win = rte_cpu_to_be_16(4096);
    if (payload_len > 0 && payload != NULL) {
        rte_memcpy(tcp + 1, payload, payload_len);
    }
    prepare_ipv4_tx_checksums(ctx, m, ip4, tcp, l4_len);
    m->port = ctx->port_v4;
    return m;
}

static struct rte_mbuf *build_icmpv6_echo_request(struct nat64_ctx *ctx, const struct in6_addr *src,
                                                  const struct in6_addr *dst, const struct rte_ether_addr *dst_mac,
                                                  uint16_t ident, uint16_t seq)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(ctx->mbuf_pool);
    struct rte_ether_hdr *eth;
    struct rte_ipv6_hdr *ip6;
    struct rte_icmp_hdr *icmp;
    uint32_t *payload;
    char *buf;
    uint16_t payload_len = sizeof(*icmp) + 8;

    if (m == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(m, sizeof(*eth) + sizeof(*ip6) + payload_len);
    if (buf == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }

    eth = (struct rte_ether_hdr *) buf;
    ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    icmp = (struct rte_icmp_hdr *) (ip6 + 1);
    payload = (uint32_t *) (icmp + 1);

    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    ip6->payload_len = rte_cpu_to_be_16(payload_len);
    ip6->proto = IPPROTO_ICMPV6;
    ip6->hop_limits = 64;
    memcpy(ip6->src_addr, src, sizeof(*src));
    memcpy(ip6->dst_addr, dst, sizeof(*dst));

    memset(icmp, 0, payload_len);
    icmp->icmp_type = ICMPV6_ECHO_REQUEST;
    icmp->icmp_ident = rte_cpu_to_be_16(ident);
    icmp->icmp_seq_nb = rte_cpu_to_be_16(seq);
    payload[0] = rte_cpu_to_be_32(0x4e363456U);
    payload[1] = rte_cpu_to_be_32(seq);
    icmp->icmp_cksum = l4_checksum_ipv6(ip6, icmp, payload_len, IPPROTO_ICMPV6);
    m->port = ctx->port_v6;
    return m;
}

static bool is_local_v4(const struct nat64_ctx *ctx, rte_be32_t ip_be)
{
    if (ctx->port_v4_addr.s_addr == ip_be) {
        return true;
    }
    if (ctx->cfg == NULL) {
        return false;
    }
    for (uint32_t service_idx = 0; service_idx < ctx->cfg->service_count && service_idx < NAT64_MAX_SERVICES;
         service_idx++) {
        const struct nat64_service_config *service = &ctx->cfg->services[service_idx];

        for (uint32_t i = 0; i < service->laddr_count; i++) {
            if (service->laddr[i].prefix.addr.s_addr == ip_be) {
                return true;
            }
        }
    }
    return false;
}

static bool is_service_v6(const struct nat64_ctx *ctx, const struct in6_addr *target)
{
    return find_service_for_v6(ctx, target, NULL) != NULL;
}

static bool is_local_v6(const struct nat64_ctx *ctx, const struct in6_addr *target)
{
    return memcmp(target, &ctx->port_v6_addr, sizeof(*target)) == 0;
}

static int laddr_index(const struct nat64_ctx *ctx, struct in_addr ip)
{
    for (uint32_t i = 0; i < ctx->laddr_state_count; i++) {
        if (ctx->laddr_state[i].ip.s_addr == ip.s_addr) {
            return (int) i;
        }
    }
    return -1;
}

static void format_mac(const struct rte_ether_addr *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
             mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

static const char *duplex_str(uint16_t duplex)
{
    return duplex == RTE_ETH_LINK_FULL_DUPLEX ? "full" : "half";
}

static void announce_laddr(struct nat64_ctx *ctx, struct in_addr ip, uint16_t queue_id, uint64_t now_tsc)
{
    emit_single(ctx, build_gratuitous_arp(ctx, ip, false), ctx->port_v4, queue_id);
    emit_single(ctx, build_gratuitous_arp(ctx, ip, true), ctx->port_v4, queue_id);
    mark_laddr_announce(ctx, ip, now_tsc);
}

static void announce_all_laddrs(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc)
{
    for (uint32_t i = 0; i < ctx->laddr_state_count; i++) {
        announce_laddr(ctx, ctx->laddr_state[i].ip, queue_id, now_tsc);
    }
}

static void log_link_change(uint16_t port_id, const struct rte_eth_link *link)
{
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
            "port %u link %s speed %u Mbps duplex %s\n",
            port_id,
            link->link_status ? "up" : "down",
            link->link_speed,
            duplex_str(link->link_duplex));
}

static void update_link_state(struct nat64_ctx *ctx, uint16_t port_id, struct nat64_link_state *cache,
                              const struct rte_eth_link *link, uint16_t queue_id, uint64_t now_tsc)
{
    bool changed = cache->up != (link->link_status != 0) ||
                   cache->speed != link->link_speed ||
                   cache->full_duplex != (link->link_duplex == RTE_ETH_LINK_FULL_DUPLEX);
    bool became_up = !cache->up && link->link_status != 0;

    if (!changed) {
        return;
    }

    cache->up = link->link_status != 0;
    cache->speed = link->link_speed;
    cache->full_duplex = link->link_duplex == RTE_ETH_LINK_FULL_DUPLEX;
    log_link_change(port_id, link);

    if (port_id == ctx->port_v4 && became_up) {
        announce_all_laddrs(ctx, queue_id, now_tsc);
    }
}

static struct rte_mbuf *handle_arp(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *) (eth + 1);
    uint64_t now = rte_rdtsc();
    struct in_addr sip = *(struct in_addr *) &arp->arp_data.arp_sip;
    struct in_addr tip = *(struct in_addr *) &arp->arp_data.arp_tip;

    neighbor4_update(ctx, sip, &arp->arp_data.arp_sha, now);
    if (ctx->probe4.configured && ctx->probe4.target.s_addr == sip.s_addr) {
        nexthop4_mark_l2_success(ctx, now);
    }
    if (is_local_v4(ctx, arp->arp_data.arp_sip) &&
        !rte_is_same_ether_addr(&arp->arp_data.arp_sha, &ctx->port_v4_mac)) {
        mark_laddr_conflict(ctx, sip, &arp->arp_data.arp_sha, now);
    }

    if (rte_be_to_cpu_16(arp->arp_opcode) == RTE_ARP_OP_REQUEST && is_local_v4(ctx, arp->arp_data.arp_tip)) {
        struct rte_mbuf *out = rte_pktmbuf_alloc(ctx->mbuf_pool);
        struct rte_ether_hdr *oeth;
        struct rte_arp_hdr *oarp;
        char *buf;

        if (out == NULL) {
            return NULL;
        }
        buf = rte_pktmbuf_append(out, sizeof(*oeth) + sizeof(*oarp));
        if (buf == NULL) {
            rte_pktmbuf_free(out);
            return NULL;
        }

        oeth = (struct rte_ether_hdr *) buf;
        oarp = (struct rte_arp_hdr *) (oeth + 1);
        rte_ether_addr_copy(&arp->arp_data.arp_sha, &oeth->dst_addr);
        rte_ether_addr_copy(&ctx->port_v4_mac, &oeth->src_addr);
        oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

        memset(oarp, 0, sizeof(*oarp));
        oarp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
        oarp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        oarp->arp_hlen = RTE_ETHER_ADDR_LEN;
        oarp->arp_plen = sizeof(rte_be32_t);
        oarp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
        rte_ether_addr_copy(&ctx->port_v4_mac, &oarp->arp_data.arp_sha);
        oarp->arp_data.arp_sip = tip.s_addr;
        rte_ether_addr_copy(&arp->arp_data.arp_sha, &oarp->arp_data.arp_tha);
        oarp->arp_data.arp_tip = sip.s_addr;
        out->port = ctx->port_v4;
        return out;
    }

    return NULL;
}

static struct rte_mbuf *handle_nd(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct nd_msg *nd = (struct nd_msg *) (ip6 + 1);
    struct nd_opt_lladdr *opt = (struct nd_opt_lladdr *) (nd + 1);
    struct in6_addr src;
    struct in6_addr target;
    uint64_t now = rte_rdtsc();

    memcpy(&src, ip6->src_addr, sizeof(src));
    memcpy(&target, nd->target, sizeof(target));
    neighbor6_update(ctx, &src, &eth->src_addr, now);
    if (ctx->probe6.configured && memcmp(&ctx->probe6.target, &src, sizeof(src)) == 0) {
        nexthop6_mark_l2_success(ctx, now);
    }
    if (opt->len >= 1 &&
        (opt->type == ICMPV6_OPT_SOURCE_LINKADDR || opt->type == ICMPV6_OPT_TARGET_LINKADDR)) {
        neighbor6_update(ctx, &src, &opt->addr, now);
    }

    if (nd->type == ND_NEIGHBOR_SOLICIT && (is_service_v6(ctx, &target) || is_local_v6(ctx, &target))) {
        return build_nd_advert(ctx, &target, &src, &eth->src_addr);
    }

    return NULL;
}

static struct rte_mbuf *handle_icmpv4_local(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *) (ip4 + 1);
    uint16_t ip_len = rte_be_to_cpu_16(ip4->total_length);
    uint16_t l4_len = (uint16_t) (ip_len - sizeof(*ip4));
    struct rte_mbuf *out;
    char *buf;
    struct rte_ether_hdr *oeth;
    struct rte_ipv4_hdr *oip4;
    struct rte_icmp_hdr *oicmp;

    if (ip4->next_proto_id != IPPROTO_ICMP || icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
        return NULL;
    }
    if (!is_local_v4(ctx, ip4->dst_addr)) {
        return NULL;
    }

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(out, sizeof(*oeth) + ip_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip4 = (struct rte_ipv4_hdr *) (oeth + 1);
    oicmp = (struct rte_icmp_hdr *) (oip4 + 1);

    rte_ether_addr_copy(&eth->src_addr, &oeth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &oeth->src_addr);
    oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    rte_memcpy(oip4, ip4, ip_len);
    oip4->src_addr = ip4->dst_addr;
    oip4->dst_addr = ip4->src_addr;
    oip4->time_to_live = 64;
    oip4->hdr_checksum = 0;

    oicmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    oicmp->icmp_cksum = 0;
    oicmp->icmp_cksum = ipv4_checksum(oicmp, l4_len);
    oip4->hdr_checksum = ipv4_checksum(oip4, sizeof(*oip4));
    out->port = ctx->port_v4;
    return out;
}

static bool handle_icmpv4_probe_reply(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *) (ip4 + 1);
    uint64_t now = rte_rdtsc();

    if (!ctx->probe4.configured || ip4->next_proto_id != IPPROTO_ICMP ||
        icmp->icmp_type != RTE_IP_ICMP_ECHO_REPLY) {
        return false;
    }
    if (ip4->src_addr != ctx->probe4.target.s_addr || !is_local_v4(ctx, ip4->dst_addr)) {
        return false;
    }
    if (rte_be_to_cpu_16(icmp->icmp_ident) != ctx->probe4.echo_id) {
        return false;
    }

    neighbor4_update(ctx, *(struct in_addr *) &ip4->src_addr, &eth->src_addr, now);
    nexthop4_mark_l3_success(ctx, now);
    return true;
}

static uint16_t ipv4_header_len(const struct rte_ipv4_hdr *ip4)
{
    uint16_t ihl = (uint16_t) ((ip4->version_ihl & 0x0fU) * 4U);

    return ihl >= sizeof(*ip4) ? ihl : (uint16_t) sizeof(*ip4);
}

static bool parse_http_status_code(const char *payload, uint16_t payload_len, uint16_t *status)
{
    if (payload_len < 12 || memcmp(payload, "HTTP/1.", 7) != 0 ||
        payload[8] != ' ' ||
        payload[9] < '0' || payload[9] > '9' ||
        payload[10] < '0' || payload[10] > '9' ||
        payload[11] < '0' || payload[11] > '9') {
        return false;
    }
    *status = (uint16_t) ((payload[9] - '0') * 100 + (payload[10] - '0') * 10 + (payload[11] - '0'));
    return true;
}

static struct rte_mbuf *handle_active_probe4_reply(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    uint16_t ip_len = rte_be_to_cpu_16(ip4->total_length);
    uint16_t ihl = ipv4_header_len(ip4);
    uint64_t now = rte_rdtsc();
    struct nat64_probe4_state state;
    struct rte_ether_addr dmac;
    bool send_rst = false;
    bool send_http = false;
    uint32_t tx_seq = 0;
    uint32_t tx_ack = 0;
    char http_req[512];
    uint16_t http_req_len = 0;

    rte_spinlock_lock(&ctx->probe4_lock);
    state = ctx->active_probe4;
    rte_spinlock_unlock(&ctx->probe4_lock);
    if (!state.active || state.done || ip_len < ihl) {
        return NULL;
    }
    if (ip4->src_addr != state.target.s_addr || ip4->dst_addr != state.source.s_addr) {
        return NULL;
    }

    neighbor4_update(ctx, *(struct in_addr *) &ip4->src_addr, &eth->src_addr, now);
    rte_ether_addr_copy(&eth->src_addr, &dmac);

    if (state.mode == NAT64_PROBE4_PING) {
        struct rte_icmp_hdr *icmp;

        if (ip4->next_proto_id != IPPROTO_ICMP || ip_len < ihl + sizeof(*icmp)) {
            return NULL;
        }
        icmp = (struct rte_icmp_hdr *) ((char *) ip4 + ihl);
        if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REPLY ||
            rte_be_to_cpu_16(icmp->icmp_ident) != state.echo_id) {
            return NULL;
        }
        rte_spinlock_lock(&ctx->probe4_lock);
        if (ctx->active_probe4.active && !ctx->active_probe4.done &&
            ctx->active_probe4.mode == NAT64_PROBE4_PING &&
            ctx->active_probe4.target.s_addr == ip4->src_addr &&
            ctx->active_probe4.source.s_addr == ip4->dst_addr) {
            ctx->active_probe4.l2_up = true;
            ctx->active_probe4.received++;
            ctx->active_probe4.last_reply_tsc = now;
            ctx->active_probe4.last_reply_unix = now_unix_sec();
            if (ctx->active_probe4.received >= ctx->active_probe4.count) {
                ctx->active_probe4.done = true;
                ctx->active_probe4.finished_unix = ctx->active_probe4.last_reply_unix;
            }
        }
        rte_spinlock_unlock(&ctx->probe4_lock);
        return NAT64_PROBE4_CONSUMED;
    }

    if (state.mode == NAT64_PROBE4_TCP || state.mode == NAT64_PROBE4_HTTP) {
        struct rte_tcp_hdr *tcp;
        uint16_t l4_len;
        uint16_t tcp_len;
        uint16_t payload_len;
        const char *payload;
        uint8_t flags;
        uint32_t seq;
        uint32_t ack;

        if (ip4->next_proto_id != IPPROTO_TCP || ip_len < ihl + sizeof(*tcp)) {
            return NULL;
        }
        tcp = (struct rte_tcp_hdr *) ((char *) ip4 + ihl);
        if (rte_be_to_cpu_16(tcp->src_port) != state.target_port ||
            rte_be_to_cpu_16(tcp->dst_port) != state.source_port) {
            return NULL;
        }
        l4_len = (uint16_t) (ip_len - ihl);
        tcp_len = tcp_hdr_len(tcp);
        if (tcp_len > l4_len) {
            return NULL;
        }
        payload_len = (uint16_t) (l4_len - tcp_len);
        payload = (const char *) tcp + tcp_len;
        flags = tcp->tcp_flags;
        seq = rte_be_to_cpu_32(tcp->sent_seq);
        ack = rte_be_to_cpu_32(tcp->recv_ack);

        rte_spinlock_lock(&ctx->probe4_lock);
        if (ctx->active_probe4.active && !ctx->active_probe4.done &&
            ctx->active_probe4.target.s_addr == ip4->src_addr &&
            ctx->active_probe4.source.s_addr == ip4->dst_addr &&
            ctx->active_probe4.source_port == rte_be_to_cpu_16(tcp->dst_port) &&
            ctx->active_probe4.target_port == rte_be_to_cpu_16(tcp->src_port)) {
            ctx->active_probe4.l2_up = true;
            ctx->active_probe4.last_reply_tsc = now;
            ctx->active_probe4.last_reply_unix = now_unix_sec();
            if ((flags & NAT64_TCP_RST_FLAG) != 0) {
                ctx->active_probe4.done = true;
                ctx->active_probe4.finished_unix = ctx->active_probe4.last_reply_unix;
                snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "tcp reset");
            } else if (!ctx->active_probe4.tcp_connected &&
                       (flags & (NAT64_TCP_SYN_FLAG | NAT64_TCP_ACK_FLAG)) ==
                       (NAT64_TCP_SYN_FLAG | NAT64_TCP_ACK_FLAG) &&
                       ack == ctx->active_probe4.tcp_seq + 1U) {
                ctx->active_probe4.tcp_connected = true;
                ctx->active_probe4.tcp_next_seq = ack;
                ctx->active_probe4.tcp_peer_next_seq = seq + 1U;
                if (ctx->active_probe4.mode == NAT64_PROBE4_TCP) {
                    ctx->active_probe4.received++;
                    ctx->active_probe4.done = true;
                    ctx->active_probe4.finished_unix = ctx->active_probe4.last_reply_unix;
                    send_rst = true;
                    tx_seq = ctx->active_probe4.tcp_next_seq;
                    tx_ack = ctx->active_probe4.tcp_peer_next_seq;
                } else {
                    int n = snprintf(http_req, sizeof(http_req),
                                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: dpdk-nat64-probe\r\n"
                                     "Connection: close\r\n\r\n",
                                     ctx->active_probe4.http_path, ctx->active_probe4.http_host);
                    if (n > 0 && (size_t) n < sizeof(http_req)) {
                        http_req_len = (uint16_t) n;
                        send_http = true;
                        tx_seq = ctx->active_probe4.tcp_next_seq;
                        tx_ack = ctx->active_probe4.tcp_peer_next_seq;
                        ctx->active_probe4.http_request_sent = true;
                        ctx->active_probe4.tcp_next_seq += http_req_len;
                    } else {
                        ctx->active_probe4.done = true;
                        ctx->active_probe4.finished_unix = ctx->active_probe4.last_reply_unix;
                        snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "http request too large");
                    }
                }
            } else if (ctx->active_probe4.mode == NAT64_PROBE4_HTTP &&
                       ctx->active_probe4.tcp_connected && payload_len > 0) {
                uint16_t status = 0;

                ctx->active_probe4.http_bytes += payload_len;
                ctx->active_probe4.tcp_peer_next_seq = seq + payload_len;
                if (ctx->active_probe4.http_status == 0 &&
                    parse_http_status_code(payload, payload_len, &status)) {
                    ctx->active_probe4.http_status = status;
                }
                ctx->active_probe4.received++;
                ctx->active_probe4.done = true;
                ctx->active_probe4.finished_unix = ctx->active_probe4.last_reply_unix;
                send_rst = true;
                tx_seq = ctx->active_probe4.tcp_next_seq;
                tx_ack = ctx->active_probe4.tcp_peer_next_seq;
            }
        }
        rte_spinlock_unlock(&ctx->probe4_lock);

        if (send_http) {
            return build_tcpv4_packet(ctx, state.source, state.target, &dmac, state.source_port, state.target_port,
                                      tx_seq, tx_ack, NAT64_TCP_PSH_FLAG | NAT64_TCP_ACK_FLAG,
                                      http_req, http_req_len);
        }
        if (send_rst) {
            return build_tcpv4_packet(ctx, state.source, state.target, &dmac, state.source_port, state.target_port,
                                      tx_seq, tx_ack, NAT64_TCP_RST_FLAG | NAT64_TCP_ACK_FLAG, NULL, 0);
        }
        return NAT64_PROBE4_CONSUMED;
    }

    return NULL;
}

static struct rte_mbuf *handle_icmpv6_local(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *) (ip6 + 1);
    uint16_t payload_len = rte_be_to_cpu_16(ip6->payload_len);
    struct rte_mbuf *out;
    char *buf;
    struct rte_ether_hdr *oeth;
    struct rte_ipv6_hdr *oip6;
    struct rte_icmp_hdr *oicmp;

    if (ip6->proto != IPPROTO_ICMPV6 || icmp->icmp_type != ICMPV6_ECHO_REQUEST) {
        return NULL;
    }
    if (!is_local_v6(ctx, (const struct in6_addr *) ip6->dst_addr)) {
        return NULL;
    }

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(out, sizeof(*oeth) + sizeof(*oip6) + payload_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip6 = (struct rte_ipv6_hdr *) (oeth + 1);
    oicmp = (struct rte_icmp_hdr *) (oip6 + 1);

    rte_ether_addr_copy(&eth->src_addr, &oeth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &oeth->src_addr);
    oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    rte_memcpy(oip6, ip6, sizeof(*oip6) + payload_len);
    rte_memcpy(oip6->src_addr, ip6->dst_addr, sizeof(oip6->src_addr));
    rte_memcpy(oip6->dst_addr, ip6->src_addr, sizeof(oip6->dst_addr));
    oip6->hop_limits = 64;

    oicmp->icmp_type = ICMPV6_ECHO_REPLY;
    oicmp->icmp_cksum = 0;
    oicmp->icmp_cksum = l4_checksum_ipv6(oip6, oicmp, payload_len, IPPROTO_ICMPV6);
    out->port = ctx->port_v6;
    return out;
}

static bool handle_icmpv6_probe_reply(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *) (ip6 + 1);
    uint64_t now = rte_rdtsc();

    if (!ctx->probe6.configured || ip6->proto != IPPROTO_ICMPV6 ||
        icmp->icmp_type != ICMPV6_ECHO_REPLY) {
        return false;
    }
    if (memcmp(ip6->src_addr, &ctx->probe6.target, sizeof(ctx->probe6.target)) != 0 ||
        !is_local_v6(ctx, (const struct in6_addr *) ip6->dst_addr)) {
        return false;
    }
    if (rte_be_to_cpu_16(icmp->icmp_ident) != ctx->probe6.echo_id) {
        return false;
    }

    neighbor6_update(ctx, (const struct in6_addr *) ip6->src_addr, &eth->src_addr, now);
    nexthop6_mark_l3_success(ctx, now);
    return true;
}

static bool handle_ping6_reply(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *) (ip6 + 1);
    uint16_t ident;
    uint16_t seq;
    bool matched = false;
    uint64_t now = rte_rdtsc();

    if (ip6->proto != IPPROTO_ICMPV6 || icmp->icmp_type != ICMPV6_ECHO_REPLY ||
        !is_local_v6(ctx, (const struct in6_addr *) ip6->dst_addr)) {
        return false;
    }

    ident = rte_be_to_cpu_16(icmp->icmp_ident);
    seq = rte_be_to_cpu_16(icmp->icmp_seq_nb);

    rte_spinlock_lock(&ctx->ping6_lock);
    if (ctx->ping6.active && ident == ctx->ping6.echo_id &&
        memcmp(ip6->src_addr, &ctx->ping6.target, sizeof(ctx->ping6.target)) == 0 &&
        seq > 0 && seq <= ctx->ping6.count) {
        uint64_t bit = 1ULL << (seq - 1);

        matched = true;
        if ((ctx->ping6.received_bitmap & bit) == 0) {
            ctx->ping6.received_bitmap |= bit;
            ctx->ping6.received++;
        }
        ctx->ping6.l2_up = true;
        ctx->ping6.last_reply_tsc = now;
        ctx->ping6.last_reply_unix = now_unix_sec();
        if (ctx->ping6.received >= ctx->ping6.count) {
            ctx->ping6.done = true;
            ctx->ping6.finished_unix = ctx->ping6.last_reply_unix;
        }
    }
    rte_spinlock_unlock(&ctx->ping6_lock);

    if (matched) {
        neighbor6_update(ctx, (const struct in6_addr *) ip6->src_addr, &eth->src_addr, now);
    }
    return matched;
}

static void ping6_tick(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc)
{
    struct rte_ether_addr mac;
    struct in6_addr target;
    struct in6_addr neigh_ip;
    bool active;
    bool done;
    bool resolved = false;
    bool send_ns = false;
    bool send_echo = false;
    uint16_t ident = 0x7066;
    uint16_t seq = 0;

    rte_spinlock_lock(&ctx->ping6_lock);
    active = ctx->ping6.active;
    done = ctx->ping6.done;
    target = ctx->ping6.target;
    neigh_ip = ctx->ping6.neigh_ip;
    ident = ctx->ping6.echo_id;
    if (active && !done && !ctx->ping6.route_found) {
        ctx->ping6.done = true;
        ctx->ping6.finished_unix = now_unix_sec();
        snprintf(ctx->ping6.error, sizeof(ctx->ping6.error), "no IPv6 route");
        done = true;
    }
    if (active && !done && !ctx->links[0].up) {
        ctx->ping6.done = true;
        ctx->ping6.finished_unix = now_unix_sec();
        snprintf(ctx->ping6.error, sizeof(ctx->ping6.error), "IPv6 port link down");
        done = true;
    }
    rte_spinlock_unlock(&ctx->ping6_lock);

    if (!active || done) {
        return;
    }

    resolved = neighbor6_lookup(ctx, queue_id, &neigh_ip, &mac, now_tsc);

    rte_spinlock_lock(&ctx->ping6_lock);
    if (!ctx->ping6.active || ctx->ping6.done ||
        memcmp(&ctx->ping6.target, &target, sizeof(target)) != 0) {
        rte_spinlock_unlock(&ctx->ping6_lock);
        return;
    }

    if (resolved) {
        ctx->ping6.l2_up = true;
    }

    if (!resolved &&
        (ctx->ping6.last_l2_probe_tsc == 0 ||
         now_tsc - ctx->ping6.last_l2_probe_tsc >= ctx->tsc_hz * NAT64_NEXTHOP_L2_PROBE_SEC)) {
        send_ns = true;
        ctx->ping6.last_l2_probe_tsc = now_tsc;
        ctx->ping6.l2_probes_sent++;
    }

    if (resolved && ctx->ping6.sent < ctx->ping6.count &&
        (ctx->ping6.last_send_tsc == 0 ||
         now_tsc - ctx->ping6.last_send_tsc >= ctx->tsc_hz * NAT64_PING6_SEND_INTERVAL_SEC)) {
        seq = ctx->ping6.next_seq++;
        ctx->ping6.sent++;
        ctx->ping6.last_send_tsc = now_tsc;
        send_echo = true;
    }

    if (ctx->ping6.sent >= ctx->ping6.count && !send_echo &&
        ctx->ping6.last_send_tsc != 0 &&
        now_tsc - ctx->ping6.last_send_tsc >= ctx->tsc_hz * NAT64_PING6_REPLY_WAIT_SEC) {
        ctx->ping6.done = true;
        ctx->ping6.finished_unix = now_unix_sec();
        if (ctx->ping6.received == 0) {
            snprintf(ctx->ping6.error, sizeof(ctx->ping6.error), "timeout");
        } else if (ctx->ping6.received < ctx->ping6.sent) {
            snprintf(ctx->ping6.error, sizeof(ctx->ping6.error), "partial timeout");
        }
    }
    rte_spinlock_unlock(&ctx->ping6_lock);

    if (send_ns) {
        emit_single(ctx, build_nd_solicit(ctx, &neigh_ip), ctx->port_v6, queue_id);
    }
    if (send_echo) {
        emit_single(ctx, build_icmpv6_echo_request(ctx, &ctx->port_v6_addr, &target, &mac, ident, seq),
                    ctx->port_v6, queue_id);
    }
}

static void emit_single(struct nat64_ctx *ctx, struct rte_mbuf *m, uint16_t tx_port, uint16_t queue_id)
{
    if (m == NULL) {
        return;
    }
    {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
        uint32_t bytes = rte_pktmbuf_pkt_len(m);

        nat64_capture_note(&ctx->capture, tx_port, NAT64_CAPTURE_DIR_TX, m);
        uint16_t sent = rte_eth_tx_burst(tx_port, queue_id, &m, 1);

        if (sent == 0) {
            rte_pktmbuf_free(m);
            return;
        }
        stats_note_port_traffic(ctx, queue_id, tx_port, NAT64_STATS_DIR_TX, ether_type, 1, bytes);
    }
}

static void flush_tx_packets(struct nat64_ctx *ctx, uint16_t tx_port, uint16_t queue_id,
                             struct rte_mbuf **tx, uint16_t *tx_count)
{
    uint16_t sent;

    if (*tx_count == 0) {
        return;
    }

    for (uint16_t i = 0; i < *tx_count; i++) {
        nat64_capture_note(&ctx->capture, tx_port, NAT64_CAPTURE_DIR_TX, tx[i]);
    }
    sent = rte_eth_tx_burst(tx_port, queue_id, tx, *tx_count);
    if (sent > 0) {
        uint32_t total_bytes = 0;

        for (uint16_t i = 0; i < sent; i++) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(tx[i], struct rte_ether_hdr *);
            uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
            uint32_t pkt_len = rte_pktmbuf_pkt_len(tx[i]);

            total_bytes += pkt_len;
            stats_note_port_traffic(ctx, queue_id, tx_port, NAT64_STATS_DIR_TX, ether_type, 1, pkt_len);
        }
        stats_add_forward(ctx, queue_id, tx_port, sent, total_bytes);
    }
    for (uint16_t i = sent; i < *tx_count; i++) {
        rte_pktmbuf_free(tx[i]);
    }
    *tx_count = 0;
}

static bool mbuf_is_linear(struct rte_mbuf *m)
{
    return rte_pktmbuf_pkt_len(m) == rte_pktmbuf_data_len(m);
}

static bool ipv4_is_fragmented(const struct rte_ipv4_hdr *ip4)
{
    uint16_t frag = rte_be_to_cpu_16(ip4->fragment_offset);

    return (frag & (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) != 0;
}

static bool ipv6_has_fragment_header(const struct rte_ipv6_hdr *ip6)
{
    return ip6->proto == IPPROTO_FRAGMENT;
}

static bool frag_key_matches4(const struct nat64_frag_entry *entry, const struct rte_ipv4_hdr *ip4)
{
    return entry->in_use &&
           entry->family == 4 &&
           entry->proto == ip4->next_proto_id &&
           entry->id == rte_be_to_cpu_16(ip4->packet_id) &&
           entry->src4.s_addr == ip4->src_addr &&
           entry->dst4.s_addr == ip4->dst_addr;
}

static bool frag_key_matches6(const struct nat64_frag_entry *entry, const struct rte_ipv6_hdr *ip6,
                              const struct ipv6_frag_hdr *frag)
{
    return entry->in_use &&
           entry->family == 6 &&
           entry->proto == frag->next_header &&
           entry->id == rte_be_to_cpu_32(frag->id) &&
           memcmp(&entry->src6, ip6->src_addr, sizeof(entry->src6)) == 0 &&
           memcmp(&entry->dst6, ip6->dst_addr, sizeof(entry->dst6)) == 0;
}

static void frag_ranges_add(struct nat64_frag_entry *entry, uint16_t start, uint16_t end)
{
    struct nat64_frag_range next[NAT64_FRAG_MAX_RANGES];
    uint32_t out = 0;
    bool inserted = false;

    if (start >= end) {
        return;
    }

    for (uint32_t i = 0; i < entry->range_count && out < NAT64_FRAG_MAX_RANGES; i++) {
        struct nat64_frag_range cur = entry->ranges[i];

        if (!inserted && end < cur.start) {
            next[out++] = (struct nat64_frag_range) {start, end};
            inserted = true;
        }

        if (!inserted && start <= cur.end && end >= cur.start) {
            if (cur.start < start) {
                start = cur.start;
            }
            if (cur.end > end) {
                end = cur.end;
            }
            continue;
        }

        if (inserted || cur.end < start || cur.start > end) {
            next[out++] = cur;
        }
    }

    if (!inserted && out < NAT64_FRAG_MAX_RANGES) {
        next[out++] = (struct nat64_frag_range) {start, end};
    }

    for (uint32_t i = 0; i < out; i++) {
        if (i > 0 && next[i].start <= next[i - 1].end) {
            if (next[i].end > next[i - 1].end) {
                next[i - 1].end = next[i].end;
            }
            memmove(&next[i], &next[i + 1], (out - i - 1) * sizeof(next[0]));
            out--;
            i--;
        }
    }

    memcpy(entry->ranges, next, out * sizeof(next[0]));
    entry->range_count = out;
}

static bool frag_entry_complete(const struct nat64_frag_entry *entry)
{
    return entry->have_last &&
           entry->range_count == 1 &&
           entry->ranges[0].start == 0 &&
           entry->ranges[0].end >= entry->total_len;
}

static struct nat64_frag_entry *frag_find_or_alloc4(struct nat64_ctx *ctx, const struct rte_ipv4_hdr *ip4,
                                                    uint64_t now)
{
    struct nat64_frag_entry *free_entry = NULL;
    struct nat64_frag_entry *oldest = NULL;

    for (uint32_t i = 0; i < ctx->frag_entry_count; i++) {
        struct nat64_frag_entry *entry = &ctx->frag_entries[i];

        if (frag_key_matches4(entry, ip4)) {
            return entry;
        }
        if (!entry->in_use && free_entry == NULL) {
            free_entry = entry;
        }
        if (entry->in_use && (oldest == NULL || entry->last_seen_tsc < oldest->last_seen_tsc)) {
            oldest = entry;
        }
    }

    if (free_entry == NULL) {
        free_entry = oldest;
    }
    if (free_entry == NULL) {
        return NULL;
    }

    memset(free_entry, 0, sizeof(*free_entry));
    free_entry->in_use = true;
    free_entry->family = 4;
    free_entry->proto = ip4->next_proto_id;
    free_entry->id = rte_be_to_cpu_16(ip4->packet_id);
    free_entry->src4.s_addr = ip4->src_addr;
    free_entry->dst4.s_addr = ip4->dst_addr;
    free_entry->last_seen_tsc = now;
    return free_entry;
}

static struct nat64_frag_entry *frag_find_or_alloc6(struct nat64_ctx *ctx, const struct rte_ipv6_hdr *ip6,
                                                    const struct ipv6_frag_hdr *frag, uint64_t now)
{
    struct nat64_frag_entry *free_entry = NULL;
    struct nat64_frag_entry *oldest = NULL;

    for (uint32_t i = 0; i < ctx->frag_entry_count; i++) {
        struct nat64_frag_entry *entry = &ctx->frag_entries[i];

        if (frag_key_matches6(entry, ip6, frag)) {
            return entry;
        }
        if (!entry->in_use && free_entry == NULL) {
            free_entry = entry;
        }
        if (entry->in_use && (oldest == NULL || entry->last_seen_tsc < oldest->last_seen_tsc)) {
            oldest = entry;
        }
    }

    if (free_entry == NULL) {
        free_entry = oldest;
    }
    if (free_entry == NULL) {
        return NULL;
    }

    memset(free_entry, 0, sizeof(*free_entry));
    free_entry->in_use = true;
    free_entry->family = 6;
    free_entry->proto = frag->next_header;
    free_entry->id = rte_be_to_cpu_32(frag->id);
    memcpy(&free_entry->src6, ip6->src_addr, sizeof(free_entry->src6));
    memcpy(&free_entry->dst6, ip6->dst_addr, sizeof(free_entry->dst6));
    free_entry->last_seen_tsc = now;
    return free_entry;
}

static struct rte_mbuf *frag_build_ipv4(struct nat64_ctx *ctx, const struct rte_ether_hdr *eth,
                                        const struct rte_ipv4_hdr *ip4, struct nat64_frag_entry *entry)
{
    struct rte_mbuf *out;
    struct rte_ether_hdr *oeth;
    struct rte_ipv4_hdr *oip4;
    char *buf;
    uint16_t total_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip4) + entry->total_len);

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip4 = (struct rte_ipv4_hdr *) (oeth + 1);
    *oeth = *eth;
    *oip4 = *ip4;
    oip4->version_ihl = RTE_IPV4_VHL_DEF;
    oip4->fragment_offset = 0;
    oip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*oip4) + entry->total_len));
    oip4->hdr_checksum = 0;
    oip4->hdr_checksum = ipv4_checksum(oip4, sizeof(*oip4));
    memcpy(oip4 + 1, entry->data, entry->total_len);
    out->port = ctx->port_v4;
    return out;
}

static struct rte_mbuf *frag_build_ipv6(struct nat64_ctx *ctx, const struct rte_ether_hdr *eth,
                                        const struct rte_ipv6_hdr *ip6, struct nat64_frag_entry *entry)
{
    struct rte_mbuf *out;
    struct rte_ether_hdr *oeth;
    struct rte_ipv6_hdr *oip6;
    char *buf;
    uint16_t total_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip6) + entry->total_len);

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }
    buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    oip6 = (struct rte_ipv6_hdr *) (oeth + 1);
    *oeth = *eth;
    *oip6 = *ip6;
    oip6->proto = entry->proto;
    oip6->payload_len = rte_cpu_to_be_16(entry->total_len);
    memcpy(oip6 + 1, entry->data, entry->total_len);
    out->port = ctx->port_v6;
    return out;
}

static struct rte_mbuf *reassemble_ipv4_fragment(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    uint16_t ihl = (uint16_t) ((ip4->version_ihl & 0x0f) * 4);
    uint16_t total_len = rte_be_to_cpu_16(ip4->total_length);
    uint16_t frag = rte_be_to_cpu_16(ip4->fragment_offset);
    uint16_t offset = (uint16_t) ((frag & RTE_IPV4_HDR_OFFSET_MASK) * 8);
    bool more = (frag & RTE_IPV4_HDR_MF_FLAG) != 0;
    uint16_t payload_len;
    struct rte_mbuf *out = NULL;
    struct nat64_frag_entry *entry;
    uint64_t now = rte_rdtsc();

    stats_note_frag_received(ctx);
    if (ihl != sizeof(*ip4) || total_len < ihl || rte_pktmbuf_pkt_len(m) < sizeof(*eth) + total_len) {
        stats_note_frag_dropped(ctx);
        return NULL;
    }
    payload_len = (uint16_t) (total_len - ihl);
    if ((uint32_t) offset + payload_len > NAT64_FRAG_MAX_PAYLOAD) {
        stats_note_frag_dropped(ctx);
        return NULL;
    }

    rte_spinlock_lock(&ctx->frag_lock);
    entry = frag_find_or_alloc4(ctx, ip4, now);
    if (entry != NULL) {
        memcpy(entry->data + offset, (const uint8_t *) ip4 + ihl, payload_len);
        frag_ranges_add(entry, offset, (uint16_t) (offset + payload_len));
        entry->last_seen_tsc = now;
        if (!more) {
            entry->have_last = true;
            entry->total_len = (uint16_t) (offset + payload_len);
        }
        if (frag_entry_complete(entry)) {
            out = frag_build_ipv4(ctx, eth, ip4, entry);
            memset(entry, 0, sizeof(*entry));
            if (out != NULL) {
                stats_note_frag_reassembled(ctx);
            } else {
                stats_note_frag_dropped(ctx);
            }
        }
    } else {
        stats_note_frag_dropped(ctx);
    }
    rte_spinlock_unlock(&ctx->frag_lock);
    return out;
}

static struct rte_mbuf *reassemble_ipv6_fragment(struct nat64_ctx *ctx, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    struct ipv6_frag_hdr *frag_hdr = (struct ipv6_frag_hdr *) (ip6 + 1);
    uint16_t payload_len = rte_be_to_cpu_16(ip6->payload_len);
    uint16_t frag_data = rte_be_to_cpu_16(frag_hdr->frag_data);
    uint16_t offset = (uint16_t) (((frag_data & 0xfff8U) >> 3) * 8);
    bool more = (frag_data & 0x1U) != 0;
    uint16_t frag_payload_len;
    struct rte_mbuf *out = NULL;
    struct nat64_frag_entry *entry;
    uint64_t now = rte_rdtsc();

    stats_note_frag_received(ctx);
    if (payload_len < sizeof(*frag_hdr) ||
        rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip6) + payload_len) {
        stats_note_frag_dropped(ctx);
        return NULL;
    }
    frag_payload_len = (uint16_t) (payload_len - sizeof(*frag_hdr));
    if ((uint32_t) offset + frag_payload_len > NAT64_FRAG_MAX_PAYLOAD) {
        stats_note_frag_dropped(ctx);
        return NULL;
    }

    rte_spinlock_lock(&ctx->frag_lock);
    entry = frag_find_or_alloc6(ctx, ip6, frag_hdr, now);
    if (entry != NULL) {
        memcpy(entry->data + offset, frag_hdr + 1, frag_payload_len);
        frag_ranges_add(entry, offset, (uint16_t) (offset + frag_payload_len));
        entry->last_seen_tsc = now;
        if (!more) {
            entry->have_last = true;
            entry->total_len = (uint16_t) (offset + frag_payload_len);
        }
        if (frag_entry_complete(entry)) {
            out = frag_build_ipv6(ctx, eth, ip6, entry);
            memset(entry, 0, sizeof(*entry));
            if (out != NULL) {
                stats_note_frag_reassembled(ctx);
            } else {
                stats_note_frag_dropped(ctx);
            }
        }
    } else {
        stats_note_frag_dropped(ctx);
    }
    rte_spinlock_unlock(&ctx->frag_lock);
    return out;
}

static void free_fragments(struct rte_mbuf **frags, uint16_t count)
{
    for (uint16_t i = 0; i < count; i++) {
        rte_pktmbuf_free(frags[i]);
    }
}

static uint16_t tx_port_mtu(const struct nat64_ctx *ctx, uint16_t tx_port)
{
    if (tx_port == ctx->port_v6 && ctx->port_v6_mtu != 0) {
        return ctx->port_v6_mtu;
    }
    if (tx_port == ctx->port_v4 && ctx->port_v4_mtu != 0) {
        return ctx->port_v4_mtu;
    }
    return RTE_ETHER_MTU;
}

static bool packet_exceeds_tx_mtu(struct nat64_ctx *ctx, struct rte_mbuf *m, uint16_t tx_port)
{
    uint16_t mtu = tx_port_mtu(ctx, tx_port);

    return rte_pktmbuf_pkt_len(m) > sizeof(struct rte_ether_hdr) + mtu;
}

static void finalize_ipv4_l4_checksum(struct rte_ipv4_hdr *ip4)
{
    uint16_t ihl = (uint16_t) ((ip4->version_ihl & 0x0f) * 4);
    uint16_t total_len = rte_be_to_cpu_16(ip4->total_length);
    uint16_t l4_len;
    void *l4;

    if (ihl < sizeof(*ip4) || total_len < ihl) {
        return;
    }
    l4_len = (uint16_t) (total_len - ihl);
    l4 = (uint8_t *) ip4 + ihl;

    if (ip4->next_proto_id == IPPROTO_TCP && l4_len >= sizeof(struct rte_tcp_hdr)) {
        struct rte_tcp_hdr *tcp = l4;

        tcp->cksum = 0;
        tcp->cksum = l4_checksum_ipv4(ip4, tcp, l4_len, ip4->next_proto_id);
    } else if (ip4->next_proto_id == IPPROTO_UDP && l4_len >= sizeof(struct rte_udp_hdr)) {
        struct rte_udp_hdr *udp = l4;

        udp->dgram_cksum = 0;
        udp->dgram_cksum = l4_checksum_ipv4(ip4, udp, l4_len, ip4->next_proto_id);
    }
}

static void finalize_ipv6_l4_checksum(struct rte_ipv6_hdr *ip6)
{
    uint16_t l4_len = rte_be_to_cpu_16(ip6->payload_len);
    void *l4 = ip6 + 1;

    if (ip6->proto == IPPROTO_TCP && l4_len >= sizeof(struct rte_tcp_hdr)) {
        struct rte_tcp_hdr *tcp = l4;

        tcp->cksum = 0;
        tcp->cksum = l4_checksum_ipv6(ip6, tcp, l4_len, ip6->proto);
    } else if (ip6->proto == IPPROTO_UDP && l4_len >= sizeof(struct rte_udp_hdr)) {
        struct rte_udp_hdr *udp = l4;

        udp->dgram_cksum = 0;
        udp->dgram_cksum = l4_checksum_ipv6(ip6, udp, l4_len, ip6->proto);
    }
}

static int fragment_ipv4_packet(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                struct rte_mbuf **frags, uint16_t *frag_count)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip4;
    uint16_t mtu = tx_port_mtu(ctx, ctx->port_v4);
    uint16_t ihl;
    uint16_t total_len;
    uint16_t payload_len;
    uint16_t max_payload;
    uint16_t packet_id;
    const uint8_t *payload;
    uint16_t count = 0;

    *frag_count = 0;
    if (!mbuf_is_linear(m) || rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip4)) {
        return -EINVAL;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    ihl = (uint16_t) ((ip4->version_ihl & 0x0f) * 4);
    total_len = rte_be_to_cpu_16(ip4->total_length);
    if (ihl < sizeof(*ip4) || total_len < ihl ||
        rte_pktmbuf_pkt_len(m) < sizeof(*eth) + total_len ||
        total_len <= mtu) {
        return -EINVAL;
    }
    if (mtu <= ihl + 8) {
        return -EMSGSIZE;
    }

    payload_len = (uint16_t) (total_len - ihl);
    max_payload = (uint16_t) ((mtu - ihl) & ~7U);
    if (max_payload == 0) {
        return -EMSGSIZE;
    }

    finalize_ipv4_l4_checksum(ip4);
    payload = (const uint8_t *) ip4 + ihl;
    packet_id = rte_be_to_cpu_16(ip4->packet_id);
    if (packet_id == 0) {
        packet_id = (uint16_t) (__atomic_add_fetch(&ctx->frag_next_ipv4_id, 1, __ATOMIC_RELAXED) & 0xffffU);
    }

    for (uint16_t offset = 0; offset < payload_len; ) {
        uint16_t remaining = (uint16_t) (payload_len - offset);
        uint16_t chunk = remaining > max_payload ? max_payload : remaining;
        bool more = offset + chunk < payload_len;
        struct rte_mbuf *frag;
        struct rte_ether_hdr *oeth;
        struct rte_ipv4_hdr *oip4;
        uint8_t *buf;
        uint16_t frame_len = (uint16_t) (sizeof(*oeth) + ihl + chunk);

        if (count >= NAT64_FRAG_MAX_OUTPUTS) {
            free_fragments(frags, count);
            return -ENOSPC;
        }
        frag = rte_pktmbuf_alloc(ctx->mbuf_pool);
        if (frag == NULL) {
            free_fragments(frags, count);
            return -ENOMEM;
        }
        buf = (uint8_t *) rte_pktmbuf_append(frag, frame_len);
        if (buf == NULL) {
            rte_pktmbuf_free(frag);
            free_fragments(frags, count);
            return -ENOMEM;
        }

        oeth = (struct rte_ether_hdr *) buf;
        oip4 = (struct rte_ipv4_hdr *) (oeth + 1);
        *oeth = *eth;
        rte_memcpy(oip4, ip4, ihl);
        rte_memcpy((uint8_t *) oip4 + ihl, payload + offset, chunk);
        oip4->packet_id = rte_cpu_to_be_16(packet_id);
        oip4->total_length = rte_cpu_to_be_16((uint16_t) (ihl + chunk));
        oip4->fragment_offset = rte_cpu_to_be_16((uint16_t) ((offset / 8) |
                                                            (more ? RTE_IPV4_HDR_MF_FLAG : 0)));
        oip4->hdr_checksum = 0;
        oip4->hdr_checksum = ipv4_checksum(oip4, ihl);
        frag->ol_flags = 0;
        frag->l2_len = sizeof(*oeth);
        frag->l3_len = ihl;
        frag->port = ctx->port_v4;
        frags[count++] = frag;
        offset = (uint16_t) (offset + chunk);
    }

    *frag_count = count;
    return 0;
}

static int fragment_ipv6_packet(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                struct rte_mbuf **frags, uint16_t *frag_count)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv6_hdr *ip6;
    uint16_t mtu = tx_port_mtu(ctx, ctx->port_v6);
    uint16_t payload_len;
    uint16_t max_payload;
    uint32_t frag_id;
    const uint8_t *payload;
    uint16_t count = 0;
    uint8_t next_header;

    *frag_count = 0;
    if (!mbuf_is_linear(m) || rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip6)) {
        return -EINVAL;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    payload_len = rte_be_to_cpu_16(ip6->payload_len);
    if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip6) + payload_len ||
        sizeof(*ip6) + payload_len <= mtu) {
        return -EINVAL;
    }
    if (mtu <= sizeof(*ip6) + sizeof(struct ipv6_frag_hdr) + 8) {
        return -EMSGSIZE;
    }

    max_payload = (uint16_t) ((mtu - sizeof(*ip6) - sizeof(struct ipv6_frag_hdr)) & ~7U);
    if (max_payload == 0) {
        return -EMSGSIZE;
    }

    finalize_ipv6_l4_checksum(ip6);
    payload = (const uint8_t *) (ip6 + 1);
    next_header = ip6->proto;
    frag_id = __atomic_add_fetch(&ctx->frag_next_ipv6_id, 1, __ATOMIC_RELAXED);

    for (uint16_t offset = 0; offset < payload_len; ) {
        uint16_t remaining = (uint16_t) (payload_len - offset);
        uint16_t chunk = remaining > max_payload ? max_payload : remaining;
        bool more = offset + chunk < payload_len;
        struct rte_mbuf *frag;
        struct rte_ether_hdr *oeth;
        struct rte_ipv6_hdr *oip6;
        struct ipv6_frag_hdr *ofrag;
        uint8_t *buf;
        uint16_t frame_len = (uint16_t) (sizeof(*oeth) + sizeof(*oip6) + sizeof(*ofrag) + chunk);
        uint16_t frag_data = (uint16_t) (((offset / 8) << 3) | (more ? 1U : 0U));

        if (count >= NAT64_FRAG_MAX_OUTPUTS) {
            free_fragments(frags, count);
            return -ENOSPC;
        }
        frag = rte_pktmbuf_alloc(ctx->mbuf_pool);
        if (frag == NULL) {
            free_fragments(frags, count);
            return -ENOMEM;
        }
        buf = (uint8_t *) rte_pktmbuf_append(frag, frame_len);
        if (buf == NULL) {
            rte_pktmbuf_free(frag);
            free_fragments(frags, count);
            return -ENOMEM;
        }

        oeth = (struct rte_ether_hdr *) buf;
        oip6 = (struct rte_ipv6_hdr *) (oeth + 1);
        ofrag = (struct ipv6_frag_hdr *) (oip6 + 1);
        *oeth = *eth;
        *oip6 = *ip6;
        oip6->proto = IPPROTO_FRAGMENT;
        oip6->payload_len = rte_cpu_to_be_16((uint16_t) (sizeof(*ofrag) + chunk));
        ofrag->next_header = next_header;
        ofrag->reserved = 0;
        ofrag->frag_data = rte_cpu_to_be_16(frag_data);
        ofrag->id = rte_cpu_to_be_32(frag_id);
        rte_memcpy(ofrag + 1, payload + offset, chunk);
        frag->ol_flags = 0;
        frag->l2_len = sizeof(*oeth);
        frag->l3_len = sizeof(*oip6);
        frag->port = ctx->port_v6;
        frags[count++] = frag;
        offset = (uint16_t) (offset + chunk);
    }

    *frag_count = count;
    return 0;
}

static void enqueue_tx_packet(struct nat64_ctx *ctx, uint16_t tx_port, uint16_t queue_id,
                              struct rte_mbuf *m, struct rte_mbuf **tx, uint16_t *tx_count)
{
    struct rte_ether_hdr *eth;
    uint16_t ether_type;

    if (m == NULL) {
        return;
    }
    if (!packet_exceeds_tx_mtu(ctx, m, tx_port)) {
        if (*tx_count == NAT64_BURST_SIZE) {
            flush_tx_packets(ctx, tx_port, queue_id, tx, tx_count);
        }
        tx[(*tx_count)++] = m;
        return;
    }
    if (!mbuf_is_linear(m) || rte_pktmbuf_pkt_len(m) < sizeof(*eth)) {
        stats_note_frag_dropped(ctx);
        rte_pktmbuf_free(m);
        return;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth->ether_type);
    if (ether_type == RTE_ETHER_TYPE_IPV4) {
        struct rte_mbuf *frags[NAT64_FRAG_MAX_OUTPUTS];
        uint16_t frag_count = 0;

        if (fragment_ipv4_packet(ctx, m, frags, &frag_count) == 0) {
            stats_note_frag_emitted(ctx, frag_count);
            for (uint16_t i = 0; i < frag_count; i++) {
                if (*tx_count == NAT64_BURST_SIZE) {
                    flush_tx_packets(ctx, tx_port, queue_id, tx, tx_count);
                }
                tx[(*tx_count)++] = frags[i];
            }
        } else {
            stats_note_frag_dropped(ctx);
        }
        rte_pktmbuf_free(m);
        return;
    }
    if (ether_type == RTE_ETHER_TYPE_IPV6) {
        struct rte_mbuf *frags[NAT64_FRAG_MAX_OUTPUTS];
        uint16_t frag_count = 0;

        if (fragment_ipv6_packet(ctx, m, frags, &frag_count) == 0) {
            stats_note_frag_emitted(ctx, frag_count);
            for (uint16_t i = 0; i < frag_count; i++) {
                if (*tx_count == NAT64_BURST_SIZE) {
                    flush_tx_packets(ctx, tx_port, queue_id, tx, tx_count);
                }
                tx[(*tx_count)++] = frags[i];
            }
        } else {
            stats_note_frag_dropped(ctx);
        }
        rte_pktmbuf_free(m);
        return;
    }

    stats_note_frag_dropped(ctx);
    rte_pktmbuf_free(m);
}

static bool translate_v6_to_v4_inplace(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                       const struct nat64_session *sess,
                                       const struct rte_ether_addr *dst_mac)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv6_hdr *ip6;
    struct rte_ipv4_hdr *ip4;
    void *old_l4;
    void *new_l4;
    uint8_t proto;
    uint8_t hop_limit;
    uint16_t ip6_payload;
    uint8_t translated_icmp_type = 0;
    uint16_t translated_icmp_cksum = 0;

    if (!mbuf_is_linear(m) || rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip6)) {
        return false;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    proto = ip6->proto;
    hop_limit = ip6->hop_limits;
    ip6_payload = rte_be_to_cpu_16(ip6->payload_len);
    if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip6) + ip6_payload) {
        return false;
    }

    old_l4 = ip6 + 1;
    if (proto == IPPROTO_ICMPV6) {
        struct rte_icmp_hdr *old_icmp = old_l4;

        if (old_icmp->icmp_type == ICMPV6_ECHO_REQUEST) {
            translated_icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
        } else if (old_icmp->icmp_type == ICMPV6_ECHO_REPLY) {
            translated_icmp_type = RTE_IP_ICMP_ECHO_REPLY;
        } else {
            return false;
        }
        translated_icmp_cksum = icmpv6_echo_cksum_to_icmpv4(ip6, old_icmp, ip6_payload,
                                                            translated_icmp_type, sess->local_port);
    }
    ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    new_l4 = ip4 + 1;
    memmove(new_l4, old_l4, ip6_payload);
    if (rte_pktmbuf_trim(m, sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr)) != 0) {
        return false;
    }

    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(ip4, 0, sizeof(*ip4));
    ip4->version_ihl = RTE_IPV4_VHL_DEF;
    ip4->time_to_live = hop_limit;
    ip4->next_proto_id = proto == IPPROTO_ICMPV6 ? IPPROTO_ICMP : proto;
    ip4->src_addr = sess->local_v4.s_addr;
    ip4->dst_addr = sess->rs_v4.s_addr;
    ip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*ip4) + ip6_payload));

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        set_ports(proto, new_l4, sess->local_port, sess->rs_port);
    } else if (proto == IPPROTO_ICMPV6) {
        struct rte_icmp_hdr *icmp = new_l4;

        icmp->icmp_type = translated_icmp_type;
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(sess->local_port);
        icmp->icmp_cksum = translated_icmp_cksum;
    }

    m->ol_flags = 0;
    prepare_ipv4_tx_checksums(ctx, m, ip4, new_l4, ip6_payload);
    m->port = ctx->port_v4;
    return true;
}

static bool translate_v4_to_v6_inplace(struct nat64_ctx *ctx, struct rte_mbuf *m,
                                       const struct nat64_session *sess,
                                       const struct rte_ether_addr *dst_mac)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip4;
    struct rte_ipv6_hdr *ip6;
    void *old_l4;
    void *new_l4;
    uint8_t proto;
    uint16_t ip4_payload;
    uint8_t ttl;

    if (!mbuf_is_linear(m) || rte_pktmbuf_tailroom(m) < sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr) ||
        rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip4)) {
        return false;
    }

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    proto = ip4->next_proto_id;
    ttl = ip4->time_to_live;
    ip4_payload = (uint16_t) (rte_be_to_cpu_16(ip4->total_length) - sizeof(*ip4));
    if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(*ip4) + ip4_payload) {
        return false;
    }

    if (rte_pktmbuf_append(m, sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr)) == NULL) {
        return false;
    }

    old_l4 = ip4 + 1;
    ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    new_l4 = ip6 + 1;
    memmove(new_l4, old_l4, ip4_payload);

    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    ip6->payload_len = rte_cpu_to_be_16(ip4_payload);
    ip6->proto = proto == IPPROTO_ICMP ? IPPROTO_ICMPV6 : proto;
    ip6->hop_limits = ttl;
    rte_memcpy(ip6->src_addr, &sess->service_v6, sizeof(sess->service_v6));
    rte_memcpy(ip6->dst_addr, &sess->client_v6, sizeof(sess->client_v6));

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        set_ports(proto, new_l4, sess->service_port, sess->client_port);
    } else if (proto == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp = new_l4;
        uint8_t new_type;

        if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            new_type = ICMPV6_ECHO_REQUEST;
        } else if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
            new_type = ICMPV6_ECHO_REPLY;
        } else {
            return false;
        }
        icmp->icmp_cksum = icmpv4_echo_cksum_to_icmpv6(ip6, icmp, ip4_payload, new_type, sess->client_port);
        icmp->icmp_type = new_type;
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(sess->client_port);
    }

    m->ol_flags = 0;
    prepare_ipv6_tx_checksums(ctx, m, ip6, new_l4, ip4_payload);
    m->port = ctx->port_v6;
    return true;
}

static struct rte_mbuf *translate_v6_to_v4(struct nat64_ctx *ctx, uint16_t queue_id, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
    uint8_t proto = ip6->proto;
    uint16_t ip6_payload = rte_be_to_cpu_16(ip6->payload_len);
    void *l4 = ip6 + 1;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t l4_hdr_len;
    uint8_t session_proto;
    struct nat64_session *sess;
    struct rte_mbuf *out;
    struct rte_ether_hdr *oeth;
    struct rte_ipv4_hdr *ip4;
    void *ol4;
    uint16_t total_len;
    struct rte_ether_addr dst_mac;
    uint64_t now = rte_rdtsc();
    const struct nat64_service_config *nat64_service;
    uint16_t service_index = 0;

    nat64_service = find_service_for_v6(ctx, (const struct in6_addr *) ip6->dst_addr, &service_index);
    if (nat64_service == NULL) {
        return NULL;
    }
    if (ipv6_has_fragment_header(ip6)) {
        stats_note_frag_dropped(ctx);
        return NULL;
    }

    neighbor6_update(ctx, (const struct in6_addr *) ip6->src_addr, &eth->src_addr, now);

    if (proto == IPPROTO_ICMPV6 && ip6_payload >= sizeof(struct icmp_error_hdr)) {
        struct icmp_error_hdr *icmp6 = l4;

        if (icmpv6_is_error(icmp6->type)) {
            return translate_icmpv6_error_to_v4(ctx, queue_id, ip6, &eth->src_addr, ip6_payload);
        }
    }

    l4_hdr_len = extract_ports(proto, l4, ip6_payload, &src_port, &dst_port, &session_proto);
    if (l4_hdr_len == 0) {
        return NULL;
    }

    if (!nat64_acl_allow_v6_to_v4(ctx, queue_id, nat64_service, ip6)) {
        return NULL;
    }

    sess = find_or_create_session_v6(ctx, (const struct in6_addr *) ip6->src_addr,
                                     nat64_service, service_index,
                                     (const struct in6_addr *) ip6->dst_addr, src_port, dst_port,
                                     session_proto, &eth->src_addr, queue_id);
    if (sess == NULL) {
        return NULL;
    }

    {
        struct in_addr neigh_ip = session_v4_neigh_ip(ctx, queue_id, sess);

        if (neigh_ip.s_addr == sess->rs_v4.s_addr && ctx->opts.has_v4_next_hop && !sess->route4_found) {
            dst_mac = ctx->opts.v4_next_hop;
            goto resolved_v4_next_hop;
        }

        if (!neighbor4_lookup(ctx, queue_id, neigh_ip, &dst_mac, now)) {
            return build_arp_request(ctx, sess->local_v4, neigh_ip);
        }
    }
resolved_v4_next_hop:

    if (!((proto == IPPROTO_UDP && (is_sip_port(src_port) || is_sip_port(dst_port))) ||
          ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && h323_port_pair(src_port, dst_port))) &&
        translate_v6_to_v4_inplace(ctx, m, sess, &dst_mac)) {
        return m;
    }

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }

    total_len = (uint16_t) (sizeof(*oeth) + sizeof(*ip4) + ip6_payload);
    char *buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    ip4 = (struct rte_ipv4_hdr *) (oeth + 1);
    ol4 = ip4 + 1;

    rte_ether_addr_copy(&dst_mac, &oeth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v4_mac, &oeth->src_addr);
    oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    memset(ip4, 0, sizeof(*ip4));
    ip4->version_ihl = RTE_IPV4_VHL_DEF;
    ip4->time_to_live = ip6->hop_limits;
    ip4->next_proto_id = proto == IPPROTO_ICMPV6 ? IPPROTO_ICMP : proto;
    ip4->src_addr = sess->local_v4.s_addr;
    ip4->dst_addr = sess->rs_v4.s_addr;
    ip4->total_length = rte_cpu_to_be_16((uint16_t) (sizeof(*ip4) + ip6_payload));

    rte_memcpy(ol4, l4, ip6_payload);
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        set_ports(proto, ol4, sess->local_port, sess->rs_port);
    } else if (proto == IPPROTO_ICMPV6) {
        struct rte_icmp_hdr *icmp = ol4;
        uint8_t new_type;

        if (icmp->icmp_type == ICMPV6_ECHO_REQUEST) {
            new_type = RTE_IP_ICMP_ECHO_REQUEST;
        } else if (icmp->icmp_type == ICMPV6_ECHO_REPLY) {
            new_type = RTE_IP_ICMP_ECHO_REPLY;
        } else {
            rte_pktmbuf_free(out);
            return NULL;
        }
        icmp->icmp_cksum = icmpv6_echo_cksum_to_icmpv4(ip6, icmp, ip6_payload, new_type, sess->local_port);
        icmp->icmp_type = new_type;
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(sess->local_port);
    }

    if (proto == IPPROTO_UDP && (is_sip_port(src_port) || is_sip_port(dst_port))) {
        out = apply_sip_alg_v6_to_v4(ctx, out, sess);
        if (out == NULL) {
            return NULL;
        }
        oeth = rte_pktmbuf_mtod(out, struct rte_ether_hdr *);
        ip4 = (struct rte_ipv4_hdr *) (oeth + 1);
        ol4 = ip4 + 1;
        ip6_payload = (uint16_t) (rte_be_to_cpu_16(ip4->total_length) - sizeof(*ip4));
    }
    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && h323_port_pair(src_port, dst_port)) {
        int32_t delta = 0;

        out = apply_h323_alg_v6_to_v4(ctx, out, sess, &delta);
        if (out == NULL) {
            return NULL;
        }
        if (delta != 0 && proto == IPPROTO_TCP) {
            __atomic_fetch_add(&sess->tcp_delta_v6_to_v4, delta, __ATOMIC_RELAXED);
        }
        oeth = rte_pktmbuf_mtod(out, struct rte_ether_hdr *);
        ip4 = (struct rte_ipv4_hdr *) (oeth + 1);
        ol4 = ip4 + 1;
        ip6_payload = (uint16_t) (rte_be_to_cpu_16(ip4->total_length) - sizeof(*ip4));
    }

    prepare_ipv4_tx_checksums(ctx, out, ip4, ol4, ip6_payload);

    out->port = ctx->port_v4;
    return out;
}

static struct rte_mbuf *translate_v4_to_v6(struct nat64_ctx *ctx, uint16_t queue_id, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);
    uint8_t proto = ip4->next_proto_id;
    uint16_t ip4_payload = (uint16_t) (rte_be_to_cpu_16(ip4->total_length) - sizeof(*ip4));
    void *l4 = ip4 + 1;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t l4_hdr_len;
    uint8_t session_proto;
    struct nat64_session *sess;
    struct rte_mbuf *out;
    struct rte_ether_hdr *oeth;
    struct rte_ipv6_hdr *ip6;
    void *ol4;
    uint16_t total_len;
    struct rte_ether_addr dst_mac;
    uint64_t now = rte_rdtsc();

    if (ipv4_is_fragmented(ip4)) {
        stats_note_frag_dropped(ctx);
        return NULL;
    }

    if (proto == IPPROTO_ICMP && ip4_payload >= sizeof(struct icmp_error_hdr)) {
        struct icmp_error_hdr *icmp4 = l4;

        if (icmpv4_is_error(icmp4->type)) {
            return translate_icmpv4_error_to_v6(ctx, ip4, &eth->src_addr, ip4_payload);
        }
    }

    l4_hdr_len = extract_ports(proto, l4, ip4_payload, &src_port, &dst_port, &session_proto);
    if (l4_hdr_len == 0) {
        return NULL;
    }

    neighbor4_update(ctx, *(struct in_addr *) &ip4->src_addr, &eth->src_addr, now);
    normalize_v4_reverse_session_ports(session_proto, &src_port, &dst_port);

    sess = find_session_v4(ctx, *(struct in_addr *) &ip4->src_addr, *(struct in_addr *) &ip4->dst_addr,
                           src_port, dst_port, session_proto, queue_id);
    if (sess == NULL) {
        sess = find_or_create_static_session_v4(ctx, *(struct in_addr *) &ip4->src_addr,
                                                *(struct in_addr *) &ip4->dst_addr,
                                                src_port, dst_port, session_proto, queue_id);
        if (sess == NULL) {
            return NULL;
        }
    }

    if (!nat64_acl_allow_v4_to_v6(ctx, queue_id, service_by_index(ctx, sess->service_index), ip4)) {
        return NULL;
    }

    {
        struct in6_addr neigh_ip = session_v6_neigh_ip(ctx, queue_id, sess);

        if (memcmp(&neigh_ip, &sess->client_v6, sizeof(neigh_ip)) == 0 && ctx->opts.has_v6_next_hop &&
            !sess->route6_found) {
            dst_mac = ctx->opts.v6_next_hop;
            goto resolved_v6_next_hop;
        }

        if (!neighbor6_lookup(ctx, queue_id, &neigh_ip, &dst_mac, now)) {
            return build_nd_solicit(ctx, &neigh_ip);
        }
    }
resolved_v6_next_hop:

    if (!((proto == IPPROTO_UDP && (is_sip_port(src_port) || is_sip_port(dst_port))) ||
          ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && h323_port_pair(src_port, dst_port))) &&
        translate_v4_to_v6_inplace(ctx, m, sess, &dst_mac)) {
        return m;
    }

    out = rte_pktmbuf_alloc(ctx->mbuf_pool);
    if (out == NULL) {
        return NULL;
    }

    total_len = (uint16_t) (sizeof(*oeth) + sizeof(*ip6) + ip4_payload);
    char *buf = rte_pktmbuf_append(out, total_len);
    if (buf == NULL) {
        rte_pktmbuf_free(out);
        return NULL;
    }

    oeth = (struct rte_ether_hdr *) buf;
    ip6 = (struct rte_ipv6_hdr *) (oeth + 1);
    ol4 = ip6 + 1;

    rte_ether_addr_copy(&dst_mac, &oeth->dst_addr);
    rte_ether_addr_copy(&ctx->port_v6_mac, &oeth->src_addr);
    oeth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    memset(ip6, 0, sizeof(*ip6));
    ip6->vtc_flow = rte_cpu_to_be_32(6U << 28);
    ip6->payload_len = rte_cpu_to_be_16(ip4_payload);
    ip6->proto = proto == IPPROTO_ICMP ? IPPROTO_ICMPV6 : proto;
    ip6->hop_limits = ip4->time_to_live;
    rte_memcpy(ip6->src_addr, &sess->service_v6, sizeof(sess->service_v6));
    rte_memcpy(ip6->dst_addr, &sess->client_v6, sizeof(sess->client_v6));

    rte_memcpy(ol4, l4, ip4_payload);
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        set_ports(proto, ol4, sess->service_port, sess->client_port);
    } else if (proto == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp = ol4;
        uint8_t new_type;

        if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            new_type = ICMPV6_ECHO_REQUEST;
        } else if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
            new_type = ICMPV6_ECHO_REPLY;
        } else {
            rte_pktmbuf_free(out);
            return NULL;
        }
        icmp->icmp_cksum = icmpv4_echo_cksum_to_icmpv6(ip6, icmp, ip4_payload, new_type, sess->client_port);
        icmp->icmp_type = new_type;
        icmp->icmp_code = 0;
        icmp->icmp_ident = rte_cpu_to_be_16(sess->client_port);
    }

    if (proto == IPPROTO_UDP && (is_sip_port(src_port) || is_sip_port(dst_port))) {
        out = apply_sip_alg_v4_to_v6(ctx, out, sess);
        if (out == NULL) {
            return NULL;
        }
        oeth = rte_pktmbuf_mtod(out, struct rte_ether_hdr *);
        ip6 = (struct rte_ipv6_hdr *) (oeth + 1);
        ol4 = ip6 + 1;
        ip4_payload = rte_be_to_cpu_16(ip6->payload_len);
    }
    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && h323_port_pair(src_port, dst_port)) {
        int32_t delta = 0;

        out = apply_h323_alg_v4_to_v6(ctx, out, sess, &delta);
        if (out == NULL) {
            return NULL;
        }
        if (delta != 0 && proto == IPPROTO_TCP) {
            __atomic_fetch_add(&sess->tcp_delta_v4_to_v6, delta, __ATOMIC_RELAXED);
        }
        oeth = rte_pktmbuf_mtod(out, struct rte_ether_hdr *);
        ip6 = (struct rte_ipv6_hdr *) (oeth + 1);
        ol4 = ip6 + 1;
        ip4_payload = rte_be_to_cpu_16(ip6->payload_len);
    }

    prepare_ipv6_tx_checksums(ctx, out, ip6, ol4, ip4_payload);

    out->port = ctx->port_v6;
    return out;
}

int nat64_ctx_init(struct nat64_ctx *ctx, const struct nat64_config *cfg, struct rte_mempool *pool,
                   uint16_t port_v6, uint16_t port_v4, uint32_t net_v6_idx, uint32_t net_v4_idx,
                   uint64_t port_v6_tx_offloads, uint64_t port_v4_tx_offloads,
                   const struct nat64_runtime_opts *opts)
{
    if (cfg->service_count == 0) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "NAT64 init failed: no ipvs service configured\n");
        return -1;
    }
    if (cfg->service_count > NAT64_MAX_SERVICES) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: service count %u exceeds limit %u\n",
                cfg->service_count, NAT64_MAX_SERVICES);
        return -1;
    }
    for (uint32_t service_idx = 0; service_idx < cfg->service_count; service_idx++) {
        const struct nat64_service_config *service = &cfg->services[service_idx];

        if (service->vs.vaddr_count == 0 || service->laddr_count == 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                    "NAT64 init failed: service %u requires at least one vaddr and one laddr\n",
                    service_idx);
            return -1;
        }
        if (service->dst_mode == NAT64_DST_RS_POOL && service->rs_count == 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                    "NAT64 init failed: service %u rs pool mode requires at least one rs entry\n",
                    service_idx);
            return -1;
        }
        for (uint32_t i = 0; i < service->vs.vaddr_count; i++) {
            if (service->vs.vaddr[i].mask != 96) {
                rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                        "NAT64 init failed: service %u vaddr %u is /%u; only /96 NAT64 prefixes are supported\n",
                        service_idx, i, service->vs.vaddr[i].mask);
                return -1;
            }
        }
        for (uint32_t i = 0; i < service->static_bib_count; i++) {
            const struct nat64_static_bib_config *bib = &service->static_bibs[i];

            if (bib->map_port_from > bib->map_port_to || !service_has_laddr(service, bib->local_v4)) {
                rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                        "NAT64 init failed: invalid static_bib %u on service %u\n", i, service_idx);
                return -1;
            }
            if (static_bib_tuple_duplicated(cfg, service_idx, i)) {
                rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                        "NAT64 init failed: overlapping static_bib tuple on service %u\n", service_idx);
                return -1;
            }
        }
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = cfg;
    ctx->mutable_cfg = (struct nat64_config *) cfg;
    ctx->service = &cfg->services[0];
    ctx->mbuf_pool = pool;
    ctx->port_v6 = port_v6;
    ctx->port_v4 = port_v4;
    ctx->port_v6_tx_offloads = port_v6_tx_offloads;
    ctx->port_v4_tx_offloads = port_v4_tx_offloads;
    ctx->opts = *opts;
    for (uint32_t i = 0; i < NAT64_SESSION_SHARDS; i++) {
        rte_spinlock_init(&ctx->session_locks[i]);
    }
    for (uint32_t i = 0; i < NAT64_NEIGHBOR_SHARDS; i++) {
        rte_spinlock_init(&ctx->neigh4_locks[i]);
        rte_spinlock_init(&ctx->neigh6_locks[i]);
    }
    for (uint32_t i = 0; i < NAT64_SUBSCRIBER_SHARDS; i++) {
        rte_spinlock_init(&ctx->subscriber_locks[i]);
    }
    rte_spinlock_init(&ctx->laddr_lock);
    rte_spinlock_init(&ctx->route_lock);
    rte_spinlock_init(&ctx->ping6_lock);
    rte_spinlock_init(&ctx->probe4_lock);
    rte_spinlock_init(&ctx->frag_lock);
    rte_spinlock_init(&ctx->audit_lock);
    rte_spinlock_init(&ctx->acl_update_lock);
    if (nat64_acl_init(ctx) < 0) {
        return -1;
    }
    if (cfg->subscriber_limits.enabled) {
        ctx->subscriber_entry_count = cfg->subscriber_limits.max_entries != 0 ?
                                      cfg->subscriber_limits.max_entries :
                                      NAT64_DEFAULT_SUBSCRIBER_ENTRIES;
        if (ctx->subscriber_entry_count < NAT64_SUBSCRIBER_SHARDS) {
            ctx->subscriber_entry_count = NAT64_SUBSCRIBER_SHARDS;
        }
        ctx->subscriber_entries = rte_zmalloc("nat64_subscriber_entries",
                                              sizeof(*ctx->subscriber_entries) * ctx->subscriber_entry_count, 0);
        if (ctx->subscriber_entries == NULL) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                    "NAT64 init failed: subscriber limit table allocation failed\n");
            nat64_acl_cleanup(ctx);
            return -1;
        }
        rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
                "subscriber limits enabled: prefix_len=%u entries=%u default_max_sessions=%u rate=%u burst=%u\n",
                cfg->subscriber_limits.prefix_len,
                ctx->subscriber_entry_count,
                cfg->subscriber_limits.default_limit.max_sessions,
                cfg->subscriber_limits.default_limit.new_conn_per_sec,
                cfg->subscriber_limits.default_limit.burst);
    }
    ctx->frag_entry_count = cfg->sys.frag_entries != 0 ? cfg->sys.frag_entries : NAT64_DEFAULT_FRAG_ENTRIES;
    if (ctx->frag_entry_count > NAT64_MAX_FRAG_ENTRIES) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: sys.frag_entries %u exceeds max %u\n",
                ctx->frag_entry_count, NAT64_MAX_FRAG_ENTRIES);
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    ctx->frag_entries = rte_zmalloc("nat64_frag_entries",
                                    sizeof(*ctx->frag_entries) * ctx->frag_entry_count, 0);
    if (ctx->frag_entries == NULL) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "NAT64 init failed: fragment table allocation failed\n");
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
            "fragment table: entries=%u bytes=%llu\n",
            ctx->frag_entry_count,
            (unsigned long long) ((uint64_t) sizeof(*ctx->frag_entries) * ctx->frag_entry_count));
    rte_eth_macaddr_get(port_v6, &ctx->port_v6_mac);
    rte_eth_macaddr_get(port_v4, &ctx->port_v4_mac);
    ctx->port_v6_mtu = RTE_ETHER_MTU;
    ctx->port_v4_mtu = RTE_ETHER_MTU;
    if (rte_eth_dev_get_mtu(port_v6, &ctx->port_v6_mtu) < 0) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
                "failed to read IPv6 port MTU, using default %u\n", ctx->port_v6_mtu);
    }
    if (rte_eth_dev_get_mtu(port_v4, &ctx->port_v4_mtu) < 0) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
                "failed to read IPv4 port MTU, using default %u\n", ctx->port_v4_mtu);
    }
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
            "port MTU: v6 port %u mtu=%u, v4 port %u mtu=%u\n",
            port_v6, ctx->port_v6_mtu, port_v4, ctx->port_v4_mtu);
    ctx->tsc_hz = rte_get_tsc_hz();
    ctx->session_timeout_tsc = ctx->tsc_hz * NAT64_SESSION_TIMEOUT_SEC;
    ctx->neighbor_timeout_tsc = ctx->tsc_hz * NAT64_NEIGHBOR_TIMEOUT_SEC;
    ctx->arp_refresh_tsc = ctx->tsc_hz * NAT64_ARP_REFRESH_SEC;
    ctx->arp_defend_tsc = ctx->tsc_hz * NAT64_ARP_DEFEND_SEC;
    ctx->link_poll_tsc = (ctx->tsc_hz * NAT64_LINK_POLL_MS) / 1000;

    if (net_v6_idx >= cfg->net_count || cfg->nets[net_v6_idx].ip_count == 0) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: IPv6 net index %u is missing or has no addresses\n", net_v6_idx);
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    if (net_v4_idx >= cfg->net_count || cfg->nets[net_v4_idx].ip_count == 0) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: IPv4 net index %u is missing or has no addresses\n", net_v4_idx);
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    if (!parse_cidr6(cfg->nets[net_v6_idx].ip_raw[0], &ctx->port_v6_addr, &ctx->port_v6_prefix_len)) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: invalid IPv6 address on net[%u]: %s\n",
                net_v6_idx, cfg->nets[net_v6_idx].ip_raw[0]);
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    if (!parse_cidr4(cfg->nets[net_v4_idx].ip_raw[0], &ctx->port_v4_addr, &ctx->port_v4_prefix_len)) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                "NAT64 init failed: invalid IPv4 address on net[%u]: %s\n",
                net_v4_idx, cfg->nets[net_v4_idx].ip_raw[0]);
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    for (uint32_t service_idx = 0; service_idx < cfg->service_count; service_idx++) {
        const struct nat64_service_config *service = &cfg->services[service_idx];

        for (uint32_t i = 0; i < service->laddr_count && ctx->laddr_state_count < NAT64_MAX_LADDRS; i++) {
            if (laddr_index(ctx, service->laddr[i].prefix.addr) >= 0) {
                continue;
            }
            ctx->laddr_state[ctx->laddr_state_count++].ip = service->laddr[i].prefix.addr;
        }
    }
    if (ctx->laddr_state_count == NAT64_MAX_LADDRS) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
                "local IPv4 ARP state capped at %u unique addresses\n", NAT64_MAX_LADDRS);
    }
    if (nat64_capture_init(&ctx->capture, "nat64_capture", ctx->tsc_hz) < 0) {
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "NAT64 init failed: packet capture init failed\n");
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    if (cfg->route_file[0] != '\0') {
        int rc = nat64_route_table_load_file(cfg->route_file, &ctx->route_tables[0]);

        if (rc < 0) {
            rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                    "NAT64 init failed: failed to load route file %s: %d\n", cfg->route_file, rc);
            nat64_capture_cleanup(&ctx->capture);
            nat64_subscriber_cleanup(ctx);
            nat64_acl_cleanup(ctx);
            return -1;
        }
        ctx->route_tables[0].generation = 1;
        ctx->active_route_table = 0;
        __atomic_store_n(&ctx->active_routes, &ctx->route_tables[0], __ATOMIC_RELEASE);
        ctx->route_last_seen_mtime_sec = ctx->route_tables[0].loaded_mtime_sec;
        ctx->route_last_seen_mtime_nsec = ctx->route_tables[0].loaded_mtime_nsec;
        rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
                "loaded route file %s (generation=1, ipv4=%u, ipv6=%u)\n",
                ctx->route_tables[0].path, ctx->route_tables[0].ipv4_count, ctx->route_tables[0].ipv6_count);
    }
    if (audit_init(ctx) < 0) {
        nat64_capture_cleanup(&ctx->capture);
        nat64_subscriber_cleanup(ctx);
        nat64_acl_cleanup(ctx);
        return -1;
    }
    ctx->probe4.echo_id = 0x6404;
    ctx->probe6.echo_id = 0x6406;
    refresh_nexthop_targets(ctx);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
            "session table: shards=%u sessions_per_shard=%u per_worker_cache=%u neighbor_shards=%u\n",
            NAT64_SESSION_SHARDS, NAT64_SESSIONS_PER_SHARD, NAT64_SESSION_CACHE_SIZE, NAT64_NEIGHBOR_SHARDS);
    return 0;
}

void nat64_process_burst(struct nat64_ctx *ctx, uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts,
                         uint16_t nb_pkts)
{
    struct rte_mbuf *tx[NAT64_BURST_SIZE];
    uint16_t tx_count = 0;

    for (uint16_t i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *out = NULL;
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
        uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
        uint32_t pkt_len = rte_pktmbuf_pkt_len(pkts[i]);

        nat64_capture_note(&ctx->capture, port_id, NAT64_CAPTURE_DIR_RX, pkts[i]);
        stats_note_port_traffic(ctx, queue_id, port_id, NAT64_STATS_DIR_RX, ether_type, 1, pkt_len);

        if (port_id == ctx->port_v4 && ether_type == RTE_ETHER_TYPE_ARP) {
            emit_single(ctx, handle_arp(ctx, pkts[i]), ctx->port_v4, queue_id);
            rte_pktmbuf_free(pkts[i]);
            continue;
        }

        if (port_id == ctx->port_v4 && ether_type == RTE_ETHER_TYPE_IPV4) {
            struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *) (eth + 1);

            if (ipv4_is_fragmented(ip4)) {
                struct rte_mbuf *full = reassemble_ipv4_fragment(ctx, pkts[i]);

                rte_pktmbuf_free(pkts[i]);
                if (full == NULL) {
                    continue;
                }
                pkts[i] = full;
                eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
                ip4 = (struct rte_ipv4_hdr *) (eth + 1);
            }
            struct rte_mbuf *probe_ctrl = handle_active_probe4_reply(ctx, pkts[i]);
            if (probe_ctrl != NULL) {
                if (probe_ctrl != NAT64_PROBE4_CONSUMED) {
                    emit_single(ctx, probe_ctrl, ctx->port_v4, queue_id);
                }
                rte_pktmbuf_free(pkts[i]);
                continue;
            }
            if (handle_icmpv4_probe_reply(ctx, pkts[i])) {
                rte_pktmbuf_free(pkts[i]);
                continue;
            }
            struct rte_mbuf *ctrl = handle_icmpv4_local(ctx, pkts[i]);
            emit_single(ctx, ctrl, ctx->port_v4, queue_id);
            if (ctrl != NULL) {
                rte_pktmbuf_free(pkts[i]);
                continue;
            }
        }

        if (port_id == ctx->port_v6 && ether_type == RTE_ETHER_TYPE_IPV6) {
            struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *) (eth + 1);
            if (ipv6_has_fragment_header(ip6)) {
                struct rte_mbuf *full = reassemble_ipv6_fragment(ctx, pkts[i]);

                rte_pktmbuf_free(pkts[i]);
                if (full == NULL) {
                    continue;
                }
                pkts[i] = full;
                eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
                ip6 = (struct rte_ipv6_hdr *) (eth + 1);
            }
            if (ip6->proto == IPPROTO_ICMPV6) {
                if (handle_ping6_reply(ctx, pkts[i])) {
                    rte_pktmbuf_free(pkts[i]);
                    continue;
                }
                if (handle_icmpv6_probe_reply(ctx, pkts[i])) {
                    rte_pktmbuf_free(pkts[i]);
                    continue;
                }
                struct rte_mbuf *ctrl = handle_icmpv6_local(ctx, pkts[i]);
                if (ctrl == NULL) {
                    ctrl = handle_nd(ctx, pkts[i]);
                }
                emit_single(ctx, ctrl, ctx->port_v6, queue_id);
                if (ctrl != NULL) {
                    rte_pktmbuf_free(pkts[i]);
                    continue;
                }
            }
        }

        if (port_id == ctx->port_v6) {
            out = translate_v6_to_v4(ctx, queue_id, pkts[i]);
        } else if (port_id == ctx->port_v4) {
            out = translate_v4_to_v6(ctx, queue_id, pkts[i]);
        }

        if (out != pkts[i]) {
            rte_pktmbuf_free(pkts[i]);
        }

        if (out != NULL) {
            uint16_t tx_port = port_id == ctx->port_v6 ? ctx->port_v4 : ctx->port_v6;

            enqueue_tx_packet(ctx, tx_port, queue_id, out, tx, &tx_count);
        }
    }

    flush_tx_packets(ctx, port_id == ctx->port_v6 ? ctx->port_v4 : ctx->port_v6, queue_id, tx, &tx_count);
}

void nat64_age_entries(struct nat64_ctx *ctx, uint64_t now_tsc)
{
    for (uint32_t shard = 0; shard < NAT64_SESSION_SHARDS; shard++) {
        uint32_t base = session_shard_base(shard);

        rte_spinlock_lock(&ctx->session_locks[shard]);
        for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
            struct nat64_session *s = &ctx->sessions[base + i];

            if (s->in_use && now_tsc - s->last_seen_tsc > ctx->session_timeout_tsc) {
                audit_log_session(ctx, "expire", s, now_tsc);
                if (s->subscriber_counted) {
                    subscriber_limit_release_session(ctx, &s->client_v6, now_tsc);
                }
                s->in_use = false;
                stats_note_session_expired(ctx);
            }
        }
        rte_spinlock_unlock(&ctx->session_locks[shard]);
    }

    for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS; shard++) {
        uint32_t base = neighbor_shard_base(shard);

        rte_spinlock_lock(&ctx->neigh4_locks[shard]);
        for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
            struct nat64_neighbor4 *n = &ctx->neighbors4[base + i];

            if (n->in_use && now_tsc - n->last_seen_tsc > ctx->neighbor_timeout_tsc) {
                n->in_use = false;
            }
        }
        rte_spinlock_unlock(&ctx->neigh4_locks[shard]);
    }

    for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS; shard++) {
        uint32_t base = neighbor_shard_base(shard);

        rte_spinlock_lock(&ctx->neigh6_locks[shard]);
        for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
            struct nat64_neighbor6 *n = &ctx->neighbors6[base + i];

            if (n->in_use && now_tsc - n->last_seen_tsc > ctx->neighbor_timeout_tsc) {
                n->in_use = false;
            }
        }
        rte_spinlock_unlock(&ctx->neigh6_locks[shard]);
    }

    if (ctx->frag_entries != NULL) {
        uint64_t timeout_tsc = ctx->tsc_hz * NAT64_FRAG_TIMEOUT_SEC;

        rte_spinlock_lock(&ctx->frag_lock);
        for (uint32_t i = 0; i < ctx->frag_entry_count; i++) {
            struct nat64_frag_entry *entry = &ctx->frag_entries[i];

            if (entry->in_use && now_tsc - entry->last_seen_tsc > timeout_tsc) {
                memset(entry, 0, sizeof(*entry));
                stats_note_frag_expired(ctx);
            }
        }
        rte_spinlock_unlock(&ctx->frag_lock);
    }
}

void nat64_periodic(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc)
{
    struct rte_eth_link link;
    uint64_t elapsed_tsc;
    struct nat64_worker_hot_stats totals;

    if (queue_id != 0) {
        return;
    }

    if (ctx->last_link_poll_tsc != 0 &&
        now_tsc - ctx->last_link_poll_tsc < ctx->link_poll_tsc) {
        return;
    }
    ctx->last_link_poll_tsc = now_tsc;

    nat64_age_entries(ctx, now_tsc);
    refresh_nexthop_targets(ctx);

    {
        const struct nat64_route_table *routes = route_runtime_enter(ctx, NAT64_ROUTE_CONTROL_READER);
        char route_path[sizeof(ctx->route_tables[0].path)] = {0};
        uint64_t current_generation = 0;
        int64_t sec = 0;
        int64_t nsec = 0;
        bool should_reload = false;

        if (routes != NULL && routes->enabled && routes->path[0] != '\0' &&
            nat64_route_file_mtime(routes->path, &sec, &nsec) == 0 &&
            (sec != ctx->route_last_seen_mtime_sec || nsec != ctx->route_last_seen_mtime_nsec)) {
            rte_strscpy(route_path, routes->path, sizeof(route_path));
            current_generation = routes->generation;
            should_reload = true;
        }
        route_runtime_exit(ctx, NAT64_ROUTE_CONTROL_READER);

        if (should_reload) {
            uint32_t next_idx = ctx->active_route_table ^ 1U;
            uint64_t reusable_generation = ctx->route_tables[next_idx].generation;
            int rc;

            if (reusable_generation != 0 &&
                !route_wait_readers_past_generation(ctx, reusable_generation)) {
                rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
                        "deferred route reload for %s: old route generation %llu is still in use\n",
                        route_path, (unsigned long long) reusable_generation);
            } else {
                rc = nat64_route_table_load_file(route_path, &ctx->route_tables[next_idx]);
                ctx->route_last_seen_mtime_sec = sec;
                ctx->route_last_seen_mtime_nsec = nsec;
                if (rc < 0) {
                    rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1,
                            "failed to reload route file %s: %d\n", route_path, rc);
                } else {
                    uint64_t generation;

                    rte_spinlock_lock(&ctx->route_lock);
                    generation = current_generation + 1;
                    ctx->route_tables[next_idx].generation = generation;
                    ctx->active_route_table = next_idx;
                    __atomic_store_n(&ctx->active_routes, &ctx->route_tables[next_idx], __ATOMIC_RELEASE);
                    rte_spinlock_unlock(&ctx->route_lock);
                    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
                            "reloaded route file %s (generation=%llu, ipv4=%u, ipv6=%u)\n",
                            ctx->route_tables[next_idx].path,
                            (unsigned long long) generation,
                            ctx->route_tables[next_idx].ipv4_count,
                            ctx->route_tables[next_idx].ipv6_count);
                    refresh_nexthop_targets(ctx);
                }
            }
        }
    }

    if (ctx->stats_last_rate_tsc != 0) {
        elapsed_tsc = now_tsc - ctx->stats_last_rate_tsc;
        if (elapsed_tsc > 0) {
            stats_sum_workers(ctx, &totals);

            ctx->stats_v6_to_v4_pps =
                ((totals.v6_to_v4_packets - ctx->stats_prev_v6_to_v4_packets) * ctx->tsc_hz) / elapsed_tsc;
            ctx->stats_v6_to_v4_bps =
                ((totals.v6_to_v4_bytes - ctx->stats_prev_v6_to_v4_bytes) * 8 * ctx->tsc_hz) / elapsed_tsc;
            ctx->stats_prev_v6_to_v4_packets = totals.v6_to_v4_packets;
            ctx->stats_prev_v6_to_v4_bytes = totals.v6_to_v4_bytes;

            ctx->stats_v4_to_v6_pps =
                ((totals.v4_to_v6_packets - ctx->stats_prev_v4_to_v6_packets) * ctx->tsc_hz) / elapsed_tsc;
            ctx->stats_v4_to_v6_bps =
                ((totals.v4_to_v6_bytes - ctx->stats_prev_v4_to_v6_bytes) * 8 * ctx->tsc_hz) / elapsed_tsc;
            ctx->stats_prev_v4_to_v6_packets = totals.v4_to_v6_packets;
            ctx->stats_prev_v4_to_v6_bytes = totals.v4_to_v6_bytes;

            for (uint32_t port = 0; port < NAT64_STATS_PORT_COUNT; port++) {
                for (uint32_t dir = 0; dir < NAT64_STATS_DIR_COUNT; dir++) {
                    for (uint32_t family = 0; family < NAT64_STATS_FAMILY_COUNT; family++) {
                        ctx->stats_port_pps[port][dir][family] =
                            ((totals.port_packets[port][dir][family] -
                              ctx->stats_port_prev_packets[port][dir][family]) * ctx->tsc_hz) / elapsed_tsc;
                        ctx->stats_port_bps[port][dir][family] =
                            ((totals.port_bytes[port][dir][family] -
                              ctx->stats_port_prev_bytes[port][dir][family]) * 8 * ctx->tsc_hz) / elapsed_tsc;
                        ctx->stats_port_prev_packets[port][dir][family] = totals.port_packets[port][dir][family];
                        ctx->stats_port_prev_bytes[port][dir][family] = totals.port_bytes[port][dir][family];
                    }
                }
            }

            for (uint32_t i = 0; i < ctx->queue_count && i < NAT64_MAX_WORKERS; i++) {
                uint64_t curr_busy = __atomic_load_n(&ctx->worker_stats[i].busy_cycles, __ATOMIC_RELAXED);
                uint64_t curr_total = __atomic_load_n(&ctx->worker_stats[i].total_cycles, __ATOMIC_RELAXED);

                if (curr_total > ctx->worker_prev_total_cycles[i]) {
                    uint64_t diff_busy = curr_busy - ctx->worker_prev_busy_cycles[i];
                    uint64_t diff_total = curr_total - ctx->worker_prev_total_cycles[i];

                    ctx->worker_busy_pct[i] = diff_total == 0 ? 0 : (diff_busy * 100U) / diff_total;
                }
                ctx->worker_prev_busy_cycles[i] = curr_busy;
                ctx->worker_prev_total_cycles[i] = curr_total;
            }
        }
    } else {
        stats_sum_workers(ctx, &totals);
        ctx->stats_prev_v6_to_v4_packets = totals.v6_to_v4_packets;
        ctx->stats_prev_v6_to_v4_bytes = totals.v6_to_v4_bytes;
        ctx->stats_prev_v4_to_v6_packets = totals.v4_to_v6_packets;
        ctx->stats_prev_v4_to_v6_bytes = totals.v4_to_v6_bytes;
        for (uint32_t port = 0; port < NAT64_STATS_PORT_COUNT; port++) {
            for (uint32_t dir = 0; dir < NAT64_STATS_DIR_COUNT; dir++) {
                for (uint32_t family = 0; family < NAT64_STATS_FAMILY_COUNT; family++) {
                    ctx->stats_port_prev_packets[port][dir][family] = totals.port_packets[port][dir][family];
                    ctx->stats_port_prev_bytes[port][dir][family] = totals.port_bytes[port][dir][family];
                }
            }
        }
        for (uint32_t i = 0; i < ctx->queue_count && i < NAT64_MAX_WORKERS; i++) {
            ctx->worker_prev_busy_cycles[i] =
                __atomic_load_n(&ctx->worker_stats[i].busy_cycles, __ATOMIC_RELAXED);
            ctx->worker_prev_total_cycles[i] =
                __atomic_load_n(&ctx->worker_stats[i].total_cycles, __ATOMIC_RELAXED);
        }
    }
    ctx->stats_last_rate_tsc = now_tsc;

    memset(&link, 0, sizeof(link));
    rte_eth_link_get_nowait(ctx->port_v6, &link);
    update_link_state(ctx, ctx->port_v6, &ctx->links[0], &link, queue_id, now_tsc);

    memset(&link, 0, sizeof(link));
    rte_eth_link_get_nowait(ctx->port_v4, &link);
    update_link_state(ctx, ctx->port_v4, &ctx->links[1], &link, queue_id, now_tsc);

    if (ctx->links[1].up) {
        rte_spinlock_lock(&ctx->laddr_lock);
        for (uint32_t i = 0; i < ctx->laddr_state_count; i++) {
            struct nat64_laddr_state *state = &ctx->laddr_state[i];
            bool need_refresh = state->last_announce_tsc == 0 ||
                                now_tsc - state->last_announce_tsc >= ctx->arp_refresh_tsc;
            bool need_defend = state->conflict_detected &&
                               now_tsc - state->last_conflict_tsc >= ctx->arp_defend_tsc;
            struct in_addr ip = state->ip;

            rte_spinlock_unlock(&ctx->laddr_lock);

            if (need_refresh || need_defend) {
                if (need_defend) {
                    char ipbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
                    rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
                            "defending ARP ownership for %s via gratuitous ARP\n", ipbuf);
                }
                announce_laddr(ctx, ip, queue_id, now_tsc);
                if (need_defend) {
                    clear_laddr_conflict(ctx, ip);
                }
            }

            rte_spinlock_lock(&ctx->laddr_lock);
        }
        rte_spinlock_unlock(&ctx->laddr_lock);
    }

    nexthop_probe_tick(ctx, queue_id, now_tsc);
    ping6_tick(ctx, queue_id, now_tsc);
    active_probe4_tick(ctx, queue_id, now_tsc);
}

void nat64_get_stats_snapshot(struct nat64_ctx *ctx, struct nat64_stats_snapshot *out)
{
    struct nat64_worker_hot_stats totals;

    memset(out, 0, sizeof(*out));
    stats_sum_workers(ctx, &totals);
    out->v6_to_v4_packets = totals.v6_to_v4_packets;
    out->v6_to_v4_bytes = totals.v6_to_v4_bytes;
    out->v4_to_v6_packets = totals.v4_to_v6_packets;
    out->v4_to_v6_bytes = totals.v4_to_v6_bytes;
    out->v6_to_v4_pps = __atomic_load_n(&ctx->stats_v6_to_v4_pps, __ATOMIC_RELAXED);
    out->v6_to_v4_bps = __atomic_load_n(&ctx->stats_v6_to_v4_bps, __ATOMIC_RELAXED);
    out->v4_to_v6_pps = __atomic_load_n(&ctx->stats_v4_to_v6_pps, __ATOMIC_RELAXED);
    out->v4_to_v6_bps = __atomic_load_n(&ctx->stats_v4_to_v6_bps, __ATOMIC_RELAXED);
    out->sessions_created = __atomic_load_n(&ctx->stats_sessions_created, __ATOMIC_RELAXED);
    out->sessions_expired = __atomic_load_n(&ctx->stats_sessions_expired, __ATOMIC_RELAXED);
    out->frag_received = __atomic_load_n(&ctx->stats_frag_received, __ATOMIC_RELAXED);
    out->frag_reassembled = __atomic_load_n(&ctx->stats_frag_reassembled, __ATOMIC_RELAXED);
    out->frag_emitted = __atomic_load_n(&ctx->stats_frag_emitted, __ATOMIC_RELAXED);
    out->frag_dropped = __atomic_load_n(&ctx->stats_frag_dropped, __ATOMIC_RELAXED);
    out->frag_expired = __atomic_load_n(&ctx->stats_frag_expired, __ATOMIC_RELAXED);
    out->icmp_error_v4_to_v6 = __atomic_load_n(&ctx->stats_icmp_error_v4_to_v6, __ATOMIC_RELAXED);
    out->icmp_error_v6_to_v4 = __atomic_load_n(&ctx->stats_icmp_error_v6_to_v4, __ATOMIC_RELAXED);
    out->icmp_error_v6_outer_src_pref64 =
        __atomic_load_n(&ctx->stats_icmp_error_v6_outer_src_pref64, __ATOMIC_RELAXED);
    out->icmp_error_v6_outer_src_translator =
        __atomic_load_n(&ctx->stats_icmp_error_v6_outer_src_translator, __ATOMIC_RELAXED);
    out->h323_packets_v6_to_v4 = __atomic_load_n(&ctx->stats_h323_packets_v6_to_v4, __ATOMIC_RELAXED);
    out->h323_packets_v4_to_v6 = __atomic_load_n(&ctx->stats_h323_packets_v4_to_v6, __ATOMIC_RELAXED);
    out->h323_rewrites_v6_to_v4 = __atomic_load_n(&ctx->stats_h323_rewrites_v6_to_v4, __ATOMIC_RELAXED);
    out->h323_rewrites_v4_to_v6 = __atomic_load_n(&ctx->stats_h323_rewrites_v4_to_v6, __ATOMIC_RELAXED);
    out->h323_failures = __atomic_load_n(&ctx->stats_h323_failures, __ATOMIC_RELAXED);
    out->acl_permit_v6_to_v4 = totals.acl_permit_v6_to_v4;
    out->acl_deny_v6_to_v4 = totals.acl_deny_v6_to_v4;
    out->acl_permit_v4_to_v6 = totals.acl_permit_v4_to_v6;
    out->acl_deny_v4_to_v6 = totals.acl_deny_v4_to_v6;
    out->subscriber_allowed_total = __atomic_load_n(&ctx->stats_subscriber_allowed, __ATOMIC_RELAXED);
    out->subscriber_drop_max_sessions =
        __atomic_load_n(&ctx->stats_subscriber_drop_max_sessions, __ATOMIC_RELAXED);
    out->subscriber_drop_rate_limit =
        __atomic_load_n(&ctx->stats_subscriber_drop_rate_limit, __ATOMIC_RELAXED);
    out->subscriber_drop_no_entry =
        __atomic_load_n(&ctx->stats_subscriber_drop_no_entry, __ATOMIC_RELAXED);
    out->queue_count = ctx->queue_count;
    out->links[0] = ctx->links[0];
    out->links[1] = ctx->links[1];
    out->nexthops[0].configured = ctx->probe6.configured;
    out->nexthops[0].l2_up = ctx->probe6.l2_up;
    out->nexthops[0].l3_up = ctx->probe6.l3_up;
    out->nexthops[0].last_l2_success_unix = ctx->probe6.last_l2_success_unix;
    out->nexthops[0].last_l3_success_unix = ctx->probe6.last_l3_success_unix;
    out->nexthops[0].l2_probes_sent = ctx->probe6.l2_probes_sent;
    out->nexthops[0].l3_probes_sent = ctx->probe6.l3_probes_sent;
    out->nexthops[0].l3_replies_rcvd = ctx->probe6.l3_replies_rcvd;
    out->nexthops[1].configured = ctx->probe4.configured;
    out->nexthops[1].l2_up = ctx->probe4.l2_up;
    out->nexthops[1].l3_up = ctx->probe4.l3_up;
    out->nexthops[1].last_l2_success_unix = ctx->probe4.last_l2_success_unix;
    out->nexthops[1].last_l3_success_unix = ctx->probe4.last_l3_success_unix;
    out->nexthops[1].l2_probes_sent = ctx->probe4.l2_probes_sent;
    out->nexthops[1].l3_probes_sent = ctx->probe4.l3_probes_sent;
    out->nexthops[1].l3_replies_rcvd = ctx->probe4.l3_replies_rcvd;

    for (uint32_t port = 0; port < NAT64_STATS_PORT_COUNT; port++) {
        for (uint32_t dir = 0; dir < NAT64_STATS_DIR_COUNT; dir++) {
            for (uint32_t family = 0; family < NAT64_STATS_FAMILY_COUNT; family++) {
                out->ports[port].traffic[dir][family].packets =
                    totals.port_packets[port][dir][family];
                out->ports[port].traffic[dir][family].bytes =
                    totals.port_bytes[port][dir][family];
                out->ports[port].traffic[dir][family].pps =
                    __atomic_load_n(&ctx->stats_port_pps[port][dir][family], __ATOMIC_RELAXED);
                out->ports[port].traffic[dir][family].bps =
                    __atomic_load_n(&ctx->stats_port_bps[port][dir][family], __ATOMIC_RELAXED);
            }
        }
    }

    for (uint32_t i = 0; i < out->queue_count && i < NAT64_MAX_WORKERS; i++) {
        out->workers[i].lcore_id = __atomic_load_n(&ctx->worker_lcore_id[i], __ATOMIC_RELAXED);
        out->workers[i].busy_cycles = __atomic_load_n(&ctx->worker_stats[i].busy_cycles, __ATOMIC_RELAXED);
        out->workers[i].total_cycles = __atomic_load_n(&ctx->worker_stats[i].total_cycles, __ATOMIC_RELAXED);
        out->workers[i].busy_pct = __atomic_load_n(&ctx->worker_busy_pct[i], __ATOMIC_RELAXED);
    }

    for (uint32_t shard = 0; shard < NAT64_SESSION_SHARDS; shard++) {
        uint32_t base = session_shard_base(shard);

        rte_spinlock_lock(&ctx->session_locks[shard]);
        for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
            if (ctx->sessions[base + i].in_use) {
                out->sessions_active++;
            }
        }
        rte_spinlock_unlock(&ctx->session_locks[shard]);
    }

    for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS; shard++) {
        uint32_t base = neighbor_shard_base(shard);

        rte_spinlock_lock(&ctx->neigh4_locks[shard]);
        for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
            if (ctx->neighbors4[base + i].in_use) {
                out->neighbors4_active++;
            }
        }
        rte_spinlock_unlock(&ctx->neigh4_locks[shard]);
    }

    for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS; shard++) {
        uint32_t base = neighbor_shard_base(shard);

        rte_spinlock_lock(&ctx->neigh6_locks[shard]);
        for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
            if (ctx->neighbors6[base + i].in_use) {
                out->neighbors6_active++;
            }
        }
        rte_spinlock_unlock(&ctx->neigh6_locks[shard]);
    }

    if (ctx->frag_entries != NULL) {
        rte_spinlock_lock(&ctx->frag_lock);
        for (uint32_t i = 0; i < ctx->frag_entry_count; i++) {
            if (ctx->frag_entries[i].in_use) {
                out->frag_active++;
            }
        }
        rte_spinlock_unlock(&ctx->frag_lock);
    }

    if (ctx->subscriber_entries != NULL) {
        for (uint32_t shard = 0; shard < NAT64_SUBSCRIBER_SHARDS; shard++) {
            rte_spinlock_lock(&ctx->subscriber_locks[shard]);
            for (uint32_t i = shard; i < ctx->subscriber_entry_count; i += NAT64_SUBSCRIBER_SHARDS) {
                if (ctx->subscriber_entries[i].in_use) {
                    out->subscriber_active_count++;
                }
            }
            rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
        }
    }
}

uint32_t nat64_dump_subscribers(struct nat64_ctx *ctx, struct nat64_subscriber_snapshot *subscribers,
                                uint32_t offset, uint32_t max_subscribers, uint32_t *matched_total)
{
    const struct nat64_subscriber_limits_config *limits = &ctx->cfg->subscriber_limits;
    uint32_t matched = 0;
    uint32_t returned = 0;
    uint64_t now_tsc = rte_rdtsc();

    if (matched_total != NULL) {
        *matched_total = 0;
    }
    if (!limits->enabled || ctx->subscriber_entries == NULL) {
        return 0;
    }

    for (uint32_t shard = 0; shard < NAT64_SUBSCRIBER_SHARDS; shard++) {
        rte_spinlock_lock(&ctx->subscriber_locks[shard]);
        for (uint32_t i = shard; i < ctx->subscriber_entry_count; i += NAT64_SUBSCRIBER_SHARDS) {
            const struct nat64_subscriber_entry *entry = &ctx->subscriber_entries[i];

            if (!entry->in_use) {
                continue;
            }
            if (matched >= offset && subscribers != NULL && returned < max_subscribers) {
                struct nat64_subscriber_snapshot *out = &subscribers[returned];
                const struct nat64_subscriber_limit_rule_config *limit = &limits->default_limit;

                memset(out, 0, sizeof(*out));
                out->in_use = true;
                out->prefix = entry->prefix;
                out->prefix_len = entry->prefix_len;
                out->rule_index = entry->rule_index;
                if (entry->rule_index != UINT32_MAX && entry->rule_index < limits->rule_count) {
                    limit = &limits->rules[entry->rule_index];
                }
                snprintf(out->rule_name, sizeof(out->rule_name), "%s", limit->name);
                out->active_sessions = entry->active_sessions;
                out->max_sessions = limit->max_sessions;
                out->new_conn_per_sec = limit->new_conn_per_sec;
                out->burst = limit->burst;
                out->allowed_total = entry->allowed_total;
                out->drop_max_sessions = entry->drop_max_sessions;
                out->drop_rate_limit = entry->drop_rate_limit;
                if (now_tsc > entry->last_seen_tsc && ctx->tsc_hz != 0) {
                    out->age_sec = (now_tsc - entry->last_seen_tsc) / ctx->tsc_hz;
                }
                returned++;
            }
            matched++;
        }
        rte_spinlock_unlock(&ctx->subscriber_locks[shard]);
    }
    if (matched_total != NULL) {
        *matched_total = matched;
    }
    return returned;
}

uint32_t nat64_dump_sessions(struct nat64_ctx *ctx, struct nat64_session *sessions, uint32_t max_sessions)
{
    return nat64_dump_sessions_filtered(ctx, NULL, 0, sessions, max_sessions, NULL);
}

static bool session_matches_filter(const struct nat64_session *s, const struct nat64_session_filter *filter)
{
    if (filter == NULL) {
        return true;
    }
    if (filter->has_proto && s->proto != filter->proto) {
        return false;
    }
    if (filter->has_service_index && s->service_index != filter->service_index) {
        return false;
    }
    if (filter->has_client_v6 && memcmp(&s->client_v6, &filter->client_v6, sizeof(s->client_v6)) != 0) {
        return false;
    }
    if (filter->has_service_v6 && memcmp(&s->service_v6, &filter->service_v6, sizeof(s->service_v6)) != 0) {
        return false;
    }
    if (filter->has_local_v4 && s->local_v4.s_addr != filter->local_v4.s_addr) {
        return false;
    }
    if (filter->has_rs_v4 && s->rs_v4.s_addr != filter->rs_v4.s_addr) {
        return false;
    }
    if (filter->has_client_port && s->client_port != filter->client_port) {
        return false;
    }
    if (filter->has_service_port && s->service_port != filter->service_port) {
        return false;
    }
    if (filter->has_local_port && s->local_port != filter->local_port) {
        return false;
    }
    if (filter->has_rs_port && s->rs_port != filter->rs_port) {
        return false;
    }
    return true;
}

uint32_t nat64_dump_sessions_filtered(struct nat64_ctx *ctx,
                                      const struct nat64_session_filter *filter,
                                      uint32_t offset, struct nat64_session *sessions,
                                      uint32_t max_sessions, uint32_t *matched_total)
{
    uint32_t returned = 0;
    uint32_t matched = 0;

    for (uint32_t shard = 0; shard < NAT64_SESSION_SHARDS; shard++) {
        uint32_t base = session_shard_base(shard);

        rte_spinlock_lock(&ctx->session_locks[shard]);
        for (uint32_t i = 0; i < NAT64_SESSIONS_PER_SHARD; i++) {
            if (!ctx->sessions[base + i].in_use) {
                continue;
            }
            if (!session_matches_filter(&ctx->sessions[base + i], filter)) {
                continue;
            }
            if (matched >= offset && sessions != NULL && returned < max_sessions) {
                sessions[returned++] = ctx->sessions[base + i];
            }
            matched++;
        }
        rte_spinlock_unlock(&ctx->session_locks[shard]);
    }
    if (matched_total != NULL) {
        *matched_total = matched;
    }
    return returned;
}

void nat64_audit_cleanup(struct nat64_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    rte_spinlock_lock(&ctx->audit_lock);
    if (ctx->audit_fd >= 0) {
        close(ctx->audit_fd);
        ctx->audit_fd = -1;
    }
    ctx->audit_enabled = false;
    rte_spinlock_unlock(&ctx->audit_lock);
}

void nat64_subscriber_cleanup(struct nat64_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->subscriber_entries != NULL) {
        rte_free(ctx->subscriber_entries);
        ctx->subscriber_entries = NULL;
    }
    ctx->subscriber_entry_count = 0;
}

void nat64_dump_neighbors(struct nat64_ctx *ctx,
                          struct nat64_neighbor4 *neighbors4, uint32_t *count4, uint32_t max4,
                          struct nat64_neighbor6 *neighbors6, uint32_t *count6, uint32_t max6)
{
    uint32_t out4 = 0;
    uint32_t out6 = 0;

    if (count4 != NULL) {
        *count4 = 0;
    }
    if (count6 != NULL) {
        *count6 = 0;
    }

    if (neighbors4 != NULL && max4 > 0) {
        for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS && out4 < max4; shard++) {
            uint32_t base = neighbor_shard_base(shard);

            rte_spinlock_lock(&ctx->neigh4_locks[shard]);
            for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS && out4 < max4; i++) {
                if (!ctx->neighbors4[base + i].in_use) {
                    continue;
                }
                neighbors4[out4++] = ctx->neighbors4[base + i];
            }
            rte_spinlock_unlock(&ctx->neigh4_locks[shard]);
        }
    } else {
        for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS; shard++) {
            uint32_t base = neighbor_shard_base(shard);

            rte_spinlock_lock(&ctx->neigh4_locks[shard]);
            for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
                if (ctx->neighbors4[base + i].in_use) {
                    out4++;
                }
            }
            rte_spinlock_unlock(&ctx->neigh4_locks[shard]);
        }
    }

    if (neighbors6 != NULL && max6 > 0) {
        for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS && out6 < max6; shard++) {
            uint32_t base = neighbor_shard_base(shard);

            rte_spinlock_lock(&ctx->neigh6_locks[shard]);
            for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS && out6 < max6; i++) {
                if (!ctx->neighbors6[base + i].in_use) {
                    continue;
                }
                neighbors6[out6++] = ctx->neighbors6[base + i];
            }
            rte_spinlock_unlock(&ctx->neigh6_locks[shard]);
        }
    } else {
        for (uint32_t shard = 0; shard < NAT64_NEIGHBOR_SHARDS; shard++) {
            uint32_t base = neighbor_shard_base(shard);

            rte_spinlock_lock(&ctx->neigh6_locks[shard]);
            for (uint32_t i = 0; i < NAT64_MAX_NEIGHBORS / NAT64_NEIGHBOR_SHARDS; i++) {
                if (ctx->neighbors6[base + i].in_use) {
                    out6++;
                }
            }
            rte_spinlock_unlock(&ctx->neigh6_locks[shard]);
        }
    }

    if (count4 != NULL) {
        *count4 = out4;
    }
    if (count6 != NULL) {
        *count6 = out6;
    }
}

static void nexthop_probe_tick(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc)
{
    struct rte_ether_addr mac;
    struct in_addr src4;
    bool resolved4 = false;
    bool resolved6 = false;

    if (ctx->probe4.configured) {
        src4 = probe_source_v4(ctx);
        if (!ctx->links[1].up) {
            ctx->probe4.l2_up = false;
            ctx->probe4.l3_up = false;
            ctx->probe4.awaiting_reply = false;
        } else {
            resolved4 = neighbor4_lookup(ctx, queue_id, ctx->probe4.target, &mac, now_tsc);
            if (resolved4) {
                nexthop4_mark_l2_success(ctx, now_tsc);
            } else if (ctx->probe4.last_l2_success_tsc != 0 &&
                       now_tsc - ctx->probe4.last_l2_success_tsc > ctx->tsc_hz * NAT64_NEXTHOP_L2_STALE_SEC) {
                ctx->probe4.l2_up = false;
                ctx->probe4.l3_up = false;
            }

            if (!resolved4 || ctx->probe4.force_probe ||
                ctx->probe4.last_l2_probe_tsc == 0 ||
                now_tsc - ctx->probe4.last_l2_probe_tsc >= ctx->tsc_hz * NAT64_NEXTHOP_L2_PROBE_SEC) {
                emit_single(ctx, build_arp_request(ctx, src4, ctx->probe4.target), ctx->port_v4, queue_id);
                ctx->probe4.last_l2_probe_tsc = now_tsc;
                ctx->probe4.l2_probes_sent++;
            }

            if (resolved4 &&
                (ctx->probe4.force_probe || ctx->probe4.last_l3_probe_tsc == 0 ||
                 now_tsc - ctx->probe4.last_l3_probe_tsc >= ctx->tsc_hz * NAT64_NEXTHOP_L3_PROBE_SEC)) {
                ctx->probe4.last_seq_sent = ctx->probe4.next_seq++;
                emit_single(ctx, build_icmpv4_echo_request(ctx, src4, ctx->probe4.target, &mac,
                                                           ctx->probe4.echo_id, ctx->probe4.last_seq_sent),
                            ctx->port_v4, queue_id);
                ctx->probe4.last_l3_probe_tsc = now_tsc;
                ctx->probe4.awaiting_reply = true;
                ctx->probe4.l3_probes_sent++;
            }

            if (ctx->probe4.last_l3_success_tsc != 0 &&
                now_tsc - ctx->probe4.last_l3_success_tsc > ctx->tsc_hz * NAT64_NEXTHOP_L3_STALE_SEC) {
                ctx->probe4.l3_up = false;
            }
        }
        ctx->probe4.force_probe = false;
    }

    if (ctx->probe6.configured) {
        if (!ctx->links[0].up) {
            ctx->probe6.l2_up = false;
            ctx->probe6.l3_up = false;
            ctx->probe6.awaiting_reply = false;
        } else {
            resolved6 = neighbor6_lookup(ctx, queue_id, &ctx->probe6.target, &mac, now_tsc);
            if (resolved6) {
                nexthop6_mark_l2_success(ctx, now_tsc);
            } else if (ctx->probe6.last_l2_success_tsc != 0 &&
                       now_tsc - ctx->probe6.last_l2_success_tsc > ctx->tsc_hz * NAT64_NEXTHOP_L2_STALE_SEC) {
                ctx->probe6.l2_up = false;
                ctx->probe6.l3_up = false;
            }

            if (!resolved6 || ctx->probe6.force_probe ||
                ctx->probe6.last_l2_probe_tsc == 0 ||
                now_tsc - ctx->probe6.last_l2_probe_tsc >= ctx->tsc_hz * NAT64_NEXTHOP_L2_PROBE_SEC) {
                emit_single(ctx, build_nd_solicit(ctx, &ctx->probe6.target), ctx->port_v6, queue_id);
                ctx->probe6.last_l2_probe_tsc = now_tsc;
                ctx->probe6.l2_probes_sent++;
            }

            if (resolved6 &&
                (ctx->probe6.force_probe || ctx->probe6.last_l3_probe_tsc == 0 ||
                 now_tsc - ctx->probe6.last_l3_probe_tsc >= ctx->tsc_hz * NAT64_NEXTHOP_L3_PROBE_SEC)) {
                ctx->probe6.last_seq_sent = ctx->probe6.next_seq++;
                emit_single(ctx, build_icmpv6_echo_request(ctx, &ctx->port_v6_addr, &ctx->probe6.target, &mac,
                                                           ctx->probe6.echo_id, ctx->probe6.last_seq_sent),
                            ctx->port_v6, queue_id);
                ctx->probe6.last_l3_probe_tsc = now_tsc;
                ctx->probe6.awaiting_reply = true;
                ctx->probe6.l3_probes_sent++;
            }

            if (ctx->probe6.last_l3_success_tsc != 0 &&
                now_tsc - ctx->probe6.last_l3_success_tsc > ctx->tsc_hz * NAT64_NEXTHOP_L3_STALE_SEC) {
                ctx->probe6.l3_up = false;
            }
        }
        ctx->probe6.force_probe = false;
    }
}

static void active_probe4_tick(struct nat64_ctx *ctx, uint16_t queue_id, uint64_t now_tsc)
{
    struct nat64_probe4_state state;
    struct rte_ether_addr mac;
    bool resolved = false;
    bool send_arp = false;
    bool send_ping = false;
    bool send_syn = false;
    uint16_t icmp_seq = 0;

    rte_spinlock_lock(&ctx->probe4_lock);
    state = ctx->active_probe4;
    if (!state.active || state.done) {
        rte_spinlock_unlock(&ctx->probe4_lock);
        return;
    }
    if (!state.route_found) {
        ctx->active_probe4.done = true;
        ctx->active_probe4.finished_unix = now_unix_sec();
        snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "no IPv4 route");
        rte_spinlock_unlock(&ctx->probe4_lock);
        return;
    }
    if (!ctx->links[1].up) {
        ctx->active_probe4.done = true;
        ctx->active_probe4.finished_unix = now_unix_sec();
        snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "IPv4 port link down");
        rte_spinlock_unlock(&ctx->probe4_lock);
        return;
    }
    rte_spinlock_unlock(&ctx->probe4_lock);

    resolved = neighbor4_lookup(ctx, queue_id, state.neigh_ip, &mac, now_tsc);

    rte_spinlock_lock(&ctx->probe4_lock);
    if (!ctx->active_probe4.active || ctx->active_probe4.done ||
        ctx->active_probe4.target.s_addr != state.target.s_addr ||
        ctx->active_probe4.source.s_addr != state.source.s_addr) {
        rte_spinlock_unlock(&ctx->probe4_lock);
        return;
    }

    if (resolved) {
        ctx->active_probe4.l2_up = true;
    } else if (ctx->active_probe4.last_l2_probe_tsc == 0 ||
               now_tsc - ctx->active_probe4.last_l2_probe_tsc >= ctx->tsc_hz * NAT64_NEXTHOP_L2_PROBE_SEC) {
        ctx->active_probe4.last_l2_probe_tsc = now_tsc;
        ctx->active_probe4.l2_probes_sent++;
        send_arp = true;
    }

    if (resolved && ctx->active_probe4.mode == NAT64_PROBE4_PING &&
        ctx->active_probe4.sent < ctx->active_probe4.count &&
        (ctx->active_probe4.last_send_tsc == 0 ||
         now_tsc - ctx->active_probe4.last_send_tsc >= ctx->tsc_hz * NAT64_PROBE4_SEND_INTERVAL_SEC)) {
        icmp_seq = ctx->active_probe4.next_seq_icmp++;
        ctx->active_probe4.sent++;
        ctx->active_probe4.last_send_tsc = now_tsc;
        send_ping = true;
    } else if (resolved &&
               (ctx->active_probe4.mode == NAT64_PROBE4_TCP ||
                ctx->active_probe4.mode == NAT64_PROBE4_HTTP) &&
               !ctx->active_probe4.tcp_connected &&
               ctx->active_probe4.sent < ctx->active_probe4.count &&
               (ctx->active_probe4.last_send_tsc == 0 ||
                now_tsc - ctx->active_probe4.last_send_tsc >= ctx->tsc_hz * NAT64_PROBE4_SEND_INTERVAL_SEC)) {
        ctx->active_probe4.sent++;
        ctx->active_probe4.last_send_tsc = now_tsc;
        send_syn = true;
    }

    if (ctx->active_probe4.mode == NAT64_PROBE4_PING &&
        ctx->active_probe4.sent >= ctx->active_probe4.count &&
        ctx->active_probe4.last_send_tsc != 0 &&
        now_tsc - ctx->active_probe4.last_send_tsc >= ctx->tsc_hz * NAT64_PROBE4_REPLY_WAIT_SEC) {
        ctx->active_probe4.done = true;
        ctx->active_probe4.finished_unix = now_unix_sec();
        if (ctx->active_probe4.received == 0) {
            snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "timeout");
        } else if (ctx->active_probe4.received < ctx->active_probe4.sent) {
            snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "partial timeout");
        }
    } else if ((ctx->active_probe4.mode == NAT64_PROBE4_TCP ||
                ctx->active_probe4.mode == NAT64_PROBE4_HTTP) &&
               ctx->active_probe4.sent >= ctx->active_probe4.count &&
               !ctx->active_probe4.tcp_connected &&
               ctx->active_probe4.last_send_tsc != 0 &&
               now_tsc - ctx->active_probe4.last_send_tsc >= ctx->tsc_hz * NAT64_PROBE4_REPLY_WAIT_SEC) {
        ctx->active_probe4.done = true;
        ctx->active_probe4.finished_unix = now_unix_sec();
        snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "tcp timeout");
    } else if (ctx->active_probe4.mode == NAT64_PROBE4_HTTP &&
               ctx->active_probe4.http_request_sent &&
               ctx->active_probe4.last_reply_tsc != 0 &&
               now_tsc - ctx->active_probe4.last_reply_tsc >= ctx->tsc_hz * NAT64_PROBE4_HTTP_WAIT_SEC) {
        ctx->active_probe4.done = true;
        ctx->active_probe4.finished_unix = now_unix_sec();
        if (ctx->active_probe4.http_bytes == 0) {
            snprintf(ctx->active_probe4.error, sizeof(ctx->active_probe4.error), "http timeout");
        }
    }
    state = ctx->active_probe4;
    rte_spinlock_unlock(&ctx->probe4_lock);

    if (send_arp) {
        emit_single(ctx, build_arp_request(ctx, state.source, state.neigh_ip), ctx->port_v4, queue_id);
    }
    if (send_ping) {
        emit_single(ctx, build_icmpv4_echo_request(ctx, state.source, state.target, &mac,
                                                   state.echo_id, icmp_seq),
                    ctx->port_v4, queue_id);
    }
    if (send_syn) {
        emit_single(ctx, build_tcpv4_packet(ctx, state.source, state.target, &mac,
                                            state.source_port, state.target_port,
                                            state.tcp_seq, 0, NAT64_TCP_SYN_FLAG, NULL, 0),
                    ctx->port_v4, queue_id);
    }
}

void nat64_trigger_nexthop_probe(struct nat64_ctx *ctx)
{
    ctx->probe4.force_probe = true;
    ctx->probe6.force_probe = true;
}
