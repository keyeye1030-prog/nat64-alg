#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>

#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_string_fns.h>

#include "acl.h"
#include "monitor.h"

#define NAT64_CAPTURE_DIR_NAME "captures"
#define NAT64_CONN_DEFAULT_LIMIT 100U
#define NAT64_CONN_TEXT_DEFAULT_LIMIT 10000U
#define NAT64_CONN_MAX_LIMIT 10000U
#define NAT64_SUBSCRIBER_DEFAULT_LIMIT 100U
#define NAT64_SUBSCRIBER_MAX_LIMIT 10000U

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

static const char *proto_name(uint8_t proto)
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

static bool acl_rule_applies_to_direction(enum nat64_acl_direction rule_direction,
                                          enum nat64_acl_direction packet_direction)
{
    return rule_direction == NAT64_ACL_DIR_BOTH || rule_direction == packet_direction;
}

static void format_mac_text(const struct rte_ether_addr *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
             mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

static void format_unix_time_text(uint64_t unix_sec, char *buf, size_t len)
{
    time_t ts = (time_t) unix_sec;
    struct tm tmv;

    if (buf == NULL || len == 0) {
        return;
    }
    if (unix_sec == 0 || localtime_r(&ts, &tmv) == NULL) {
        snprintf(buf, len, "-");
        return;
    }
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tmv);
}

static bool socket_write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t written;
#ifdef MSG_NOSIGNAL
        int flags = MSG_NOSIGNAL;
#else
        int flags = 0;
#endif

        written = send(fd, buf, len, flags);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            poll(NULL, 0, 1);
            continue;
        }
        if (written <= 0) {
            return false;
        }
        buf += written;
        len -= (size_t) written;
    }
    return true;
}

static bool send_http_header(int fd, int status, const char *status_text, const char *content_type)
{
    char header[256];
    int len = snprintf(header, sizeof(header),
                       "HTTP/1.1 %d %s\r\n"
                       "Connection: close\r\n"
                       "Content-Type: %s\r\n"
                       "\r\n",
                       status, status_text, content_type);

    if (len < 0 || (size_t) len >= sizeof(header)) {
        return false;
    }
    return socket_write_all(fd, header, (size_t) len);
}

static bool append_format(char *buf, size_t cap, size_t *len, const char *fmt, ...)
{
    va_list ap;
    int written;

    if (*len >= cap) {
        return false;
    }

    va_start(ap, fmt);
    written = vsnprintf(buf + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t) written >= cap - *len) {
        return false;
    }

    *len += (size_t) written;
    return true;
}

static const char *port_side_name(uint32_t port_idx)
{
    return port_idx == 0 ? "v6" : "v4";
}

static const char *stats_dir_name(uint32_t dir)
{
    return dir == NAT64_STATS_DIR_RX ? "rx" : "tx";
}

static const char *stats_family_name(uint32_t family)
{
    switch (family) {
    case NAT64_STATS_FAMILY_TOTAL:
        return "total";
    case NAT64_STATS_FAMILY_IPV4:
        return "ipv4";
    case NAT64_STATS_FAMILY_IPV6:
        return "ipv6";
    default:
        return "unknown";
    }
}

static void split_query_string(char *path, char **query)
{
    char *sep = strchr(path, '?');

    if (sep == NULL) {
        *query = NULL;
        return;
    }
    *sep = '\0';
    *query = sep + 1;
}

static bool query_get_value(const char *query, const char *key, char *dst, size_t dst_len)
{
    size_t key_len;
    const char *cur;

    if (query == NULL || key == NULL || dst_len == 0) {
        return false;
    }

    key_len = strlen(key);
    cur = query;
    while (*cur != '\0') {
        const char *amp = strchr(cur, '&');
        const char *eq = strchr(cur, '=');
        size_t value_len;

        if (amp == NULL) {
            amp = cur + strlen(cur);
        }
        if (eq != NULL && eq < amp && (size_t) (eq - cur) == key_len && strncmp(cur, key, key_len) == 0) {
            value_len = (size_t) (amp - eq - 1);
            if (value_len + 1 > dst_len) {
                return false;
            }
            memcpy(dst, eq + 1, value_len);
            dst[value_len] = '\0';
            return true;
        }
        if (*amp == '\0') {
            break;
        }
        cur = amp + 1;
    }

    return false;
}

static bool capture_side_to_mask(struct nat64_monitor *monitor, const char *side, uint64_t *port_mask)
{
    if (strcmp(side, "v6") == 0) {
        *port_mask = 1ULL << monitor->ctx->port_v6;
        return true;
    }
    if (strcmp(side, "v4") == 0) {
        *port_mask = 1ULL << monitor->ctx->port_v4;
        return true;
    }
    if (strcmp(side, "all") == 0) {
        *port_mask = (1ULL << monitor->ctx->port_v6) | (1ULL << monitor->ctx->port_v4);
        return true;
    }
    return false;
}

static const char *capture_mask_to_side(struct nat64_monitor *monitor, uint64_t port_mask)
{
    uint64_t v6_mask = 1ULL << monitor->ctx->port_v6;
    uint64_t v4_mask = 1ULL << monitor->ctx->port_v4;

    if (port_mask == v6_mask) {
        return "v6";
    }
    if (port_mask == v4_mask) {
        return "v4";
    }
    if (port_mask == (v6_mask | v4_mask)) {
        return "all";
    }
    return "unknown";
}

static uint8_t capture_direction_mask(const char *direction)
{
    if (strcmp(direction, "rx") == 0) {
        return NAT64_CAPTURE_DIR_RX;
    }
    if (strcmp(direction, "tx") == 0) {
        return NAT64_CAPTURE_DIR_TX;
    }
    if (strcmp(direction, "both") == 0) {
        return NAT64_CAPTURE_DIR_RX | NAT64_CAPTURE_DIR_TX;
    }
    return 0;
}

static const char *capture_direction_name(uint8_t dir_mask)
{
    if (dir_mask == NAT64_CAPTURE_DIR_RX) {
        return "rx";
    }
    if (dir_mask == NAT64_CAPTURE_DIR_TX) {
        return "tx";
    }
    if (dir_mask == (NAT64_CAPTURE_DIR_RX | NAT64_CAPTURE_DIR_TX)) {
        return "both";
    }
    return "unknown";
}

static bool parse_duration_sec(const char *text, uint32_t *out)
{
    unsigned long value;
    char *end = NULL;

    if (text == NULL || *text == '\0' || out == NULL) {
        return false;
    }

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return false;
    }

    *out = (uint32_t) value;
    return true;
}

static bool parse_u32_text(const char *text, uint32_t *out)
{
    unsigned long value;
    char *end = NULL;

    if (text == NULL || *text == '\0' || out == NULL) {
        return false;
    }

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t) value;
    return true;
}

static bool parse_u16_text(const char *text, uint16_t *out)
{
    uint32_t value;

    if (!parse_u32_text(text, &value) || value > UINT16_MAX) {
        return false;
    }
    *out = (uint16_t) value;
    return true;
}

static bool parse_proto_text(const char *text, uint8_t *proto)
{
    if (strcmp(text, "tcp") == 0 || strcmp(text, "6") == 0) {
        *proto = IPPROTO_TCP;
        return true;
    }
    if (strcmp(text, "udp") == 0 || strcmp(text, "17") == 0) {
        *proto = IPPROTO_UDP;
        return true;
    }
    if (strcmp(text, "icmp") == 0 || strcmp(text, "1") == 0) {
        *proto = IPPROTO_ICMP;
        return true;
    }
    if (strcmp(text, "icmpv6") == 0 || strcmp(text, "58") == 0) {
        *proto = IPPROTO_ICMPV6;
        return true;
    }
    return false;
}

static bool parse_acl_direction_text(const char *text, enum nat64_acl_direction *direction)
{
    if (strcmp(text, "v6_to_v4") == 0 || strcmp(text, "6to4") == 0) {
        *direction = NAT64_ACL_DIR_V6_TO_V4;
        return true;
    }
    if (strcmp(text, "v4_to_v6") == 0 || strcmp(text, "4to6") == 0) {
        *direction = NAT64_ACL_DIR_V4_TO_V6;
        return true;
    }
    if (strcmp(text, "both") == 0) {
        *direction = NAT64_ACL_DIR_BOTH;
        return true;
    }
    return false;
}

static bool json_escape_append(char *dst, size_t cap, size_t *len, const char *text)
{
    if (!append_format(dst, cap, len, "\"")) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *) text; *p != '\0'; p++) {
        if (*p == '"' || *p == '\\') {
            if (!append_format(dst, cap, len, "\\%c", *p)) {
                return false;
            }
        } else if (*p >= 0x20 && *p < 0x7f) {
            if (!append_format(dst, cap, len, "%c", *p)) {
                return false;
            }
        } else {
            if (!append_format(dst, cap, len, "\\u%04x", *p)) {
                return false;
            }
        }
    }
    return append_format(dst, cap, len, "\"");
}

static bool parse_connection_query(const char *query, struct nat64_session_filter *filter,
                                   uint32_t *offset, uint32_t *limit, uint32_t default_limit)
{
    char value[128];

    memset(filter, 0, sizeof(*filter));
    *offset = 0;
    *limit = default_limit;

    if (query_get_value(query, "offset", value, sizeof(value)) && !parse_u32_text(value, offset)) {
        return false;
    }
    if (query_get_value(query, "limit", value, sizeof(value))) {
        if (!parse_u32_text(value, limit) || *limit == 0 || *limit > NAT64_CONN_MAX_LIMIT) {
            return false;
        }
    }
    if (query_get_value(query, "proto", value, sizeof(value))) {
        if (!parse_proto_text(value, &filter->proto)) {
            return false;
        }
        filter->has_proto = true;
    }
    if (query_get_value(query, "service_index", value, sizeof(value))) {
        if (!parse_u16_text(value, &filter->service_index)) {
            return false;
        }
        filter->has_service_index = true;
    }
    if (query_get_value(query, "client_v6", value, sizeof(value))) {
        if (inet_pton(AF_INET6, value, &filter->client_v6) != 1) {
            return false;
        }
        filter->has_client_v6 = true;
    }
    if (query_get_value(query, "service_v6", value, sizeof(value))) {
        if (inet_pton(AF_INET6, value, &filter->service_v6) != 1) {
            return false;
        }
        filter->has_service_v6 = true;
    }
    if (query_get_value(query, "local_v4", value, sizeof(value))) {
        if (inet_pton(AF_INET, value, &filter->local_v4) != 1) {
            return false;
        }
        filter->has_local_v4 = true;
    }
    if (query_get_value(query, "rs_v4", value, sizeof(value))) {
        if (inet_pton(AF_INET, value, &filter->rs_v4) != 1) {
            return false;
        }
        filter->has_rs_v4 = true;
    }
    if (query_get_value(query, "client_port", value, sizeof(value))) {
        if (!parse_u16_text(value, &filter->client_port)) {
            return false;
        }
        filter->has_client_port = true;
    }
    if (query_get_value(query, "service_port", value, sizeof(value))) {
        if (!parse_u16_text(value, &filter->service_port)) {
            return false;
        }
        filter->has_service_port = true;
    }
    if (query_get_value(query, "local_port", value, sizeof(value))) {
        if (!parse_u16_text(value, &filter->local_port)) {
            return false;
        }
        filter->has_local_port = true;
    }
    if (query_get_value(query, "rs_port", value, sizeof(value))) {
        if (!parse_u16_text(value, &filter->rs_port)) {
            return false;
        }
        filter->has_rs_port = true;
    }
    return true;
}

static bool capture_parse_filter(const char *value, struct nat64_capture_filter *filter)
{
    memset(filter, 0, sizeof(*filter));
    if (value == NULL || value[0] == '\0') {
        return true;
    }
    if (inet_pton(AF_INET, value, &filter->addr4) == 1) {
        filter->enabled = true;
        filter->is_ipv6 = false;
        snprintf(filter->text, sizeof(filter->text), "%s", value);
        return true;
    }
    if (inet_pton(AF_INET6, value, &filter->addr6) == 1) {
        filter->enabled = true;
        filter->is_ipv6 = true;
        snprintf(filter->text, sizeof(filter->text), "%s", value);
        return true;
    }
    return false;
}

static void build_capture_file_path(struct nat64_monitor *monitor, uint64_t port_mask, const char *side,
                                    const char *direction, char *file_path, size_t file_path_len)
{
    time_t now = time(NULL);
    struct tm tm_now;
    char timestamp[32];
    const char *port_label = "multi";
    char port_num_buf[16];

#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif

    if (strcmp(side, "v6") == 0) {
        snprintf(port_num_buf, sizeof(port_num_buf), "%u", (unsigned) monitor->ctx->port_v6);
        port_label = port_num_buf;
    } else if (strcmp(side, "v4") == 0) {
        snprintf(port_num_buf, sizeof(port_num_buf), "%u", (unsigned) monitor->ctx->port_v4);
        port_label = port_num_buf;
    } else if (strcmp(side, "all") == 0 || port_mask != 0) {
        port_label = "all";
    }

    if (mkdir(NAT64_CAPTURE_DIR_NAME, 0755) != 0 && errno != EEXIST) {
        snprintf(file_path, file_path_len, "%s/nat64-port%s-%s-%s.pcap",
                 NAT64_CAPTURE_DIR_NAME, port_label, side, direction);
        return;
    }

    strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &tm_now);
    snprintf(file_path, file_path_len, "%s/nat64-%s-port%s-%s-%s.pcap",
             NAT64_CAPTURE_DIR_NAME, timestamp, port_label, side, direction);
}

static void send_text_response(int fd, int status, const char *status_text, const char *body)
{
    if (!send_http_header(fd, status, status_text, "text/plain; charset=utf-8")) {
        return;
    }
    socket_write_all(fd, body, strlen(body));
}

static void serve_metrics(struct nat64_monitor *monitor, int client_fd)
{
    struct nat64_stats_snapshot stats;
    char body[65536];
    size_t len = 0;

    nat64_get_stats_snapshot(monitor->ctx, &stats);
    if (!append_format(
            body, sizeof(body), &len,
            "# HELP nat64_forward_packets_total Successfully forwarded packets.\n"
            "# TYPE nat64_forward_packets_total counter\n"
            "nat64_forward_packets_total{direction=\"v6_to_v4\"} %llu\n"
            "nat64_forward_packets_total{direction=\"v4_to_v6\"} %llu\n"
            "# HELP nat64_forward_bytes_total Successfully forwarded bytes.\n"
            "# TYPE nat64_forward_bytes_total counter\n"
            "nat64_forward_bytes_total{direction=\"v6_to_v4\"} %llu\n"
            "nat64_forward_bytes_total{direction=\"v4_to_v6\"} %llu\n"
            "# HELP nat64_forward_pps Instant forwarding packets per second.\n"
            "# TYPE nat64_forward_pps gauge\n"
            "nat64_forward_pps{direction=\"v6_to_v4\"} %llu\n"
            "nat64_forward_pps{direction=\"v4_to_v6\"} %llu\n"
            "# HELP nat64_forward_bps Instant forwarding bits per second.\n"
            "# TYPE nat64_forward_bps gauge\n"
            "nat64_forward_bps{direction=\"v6_to_v4\"} %llu\n"
            "nat64_forward_bps{direction=\"v4_to_v6\"} %llu\n"
            "# HELP nat64_sessions_active Current active NAT sessions.\n"
            "# TYPE nat64_sessions_active gauge\n"
            "nat64_sessions_active %u\n"
            "# HELP nat64_sessions_created_total Total NAT sessions created.\n"
            "# TYPE nat64_sessions_created_total counter\n"
            "nat64_sessions_created_total %llu\n"
            "# HELP nat64_sessions_expired_total Total NAT sessions expired by aging.\n"
            "# TYPE nat64_sessions_expired_total counter\n"
            "nat64_sessions_expired_total %llu\n"
            "# HELP nat64_fragments_received_total Total fragmented IPv4/IPv6 packets received for reassembly.\n"
            "# TYPE nat64_fragments_received_total counter\n"
            "nat64_fragments_received_total %llu\n"
            "# HELP nat64_fragments_reassembled_total Total fragmented flows successfully reassembled.\n"
            "# TYPE nat64_fragments_reassembled_total counter\n"
            "nat64_fragments_reassembled_total %llu\n"
            "# HELP nat64_fragments_emitted_total Total outgoing IPv4/IPv6 fragments emitted after translation.\n"
            "# TYPE nat64_fragments_emitted_total counter\n"
            "nat64_fragments_emitted_total %llu\n"
            "# HELP nat64_fragments_dropped_total Total fragments or oversized packets dropped by fragmentation handling.\n"
            "# TYPE nat64_fragments_dropped_total counter\n"
            "nat64_fragments_dropped_total %llu\n"
            "# HELP nat64_fragments_expired_total Total incomplete fragmented flows expired.\n"
            "# TYPE nat64_fragments_expired_total counter\n"
            "nat64_fragments_expired_total %llu\n"
            "# HELP nat64_fragments_active Current active fragmented flows in the reassembly table.\n"
            "# TYPE nat64_fragments_active gauge\n"
            "nat64_fragments_active %u\n"
            "# HELP nat64_icmp_error_translations_total ICMP error packets translated by direction.\n"
            "# TYPE nat64_icmp_error_translations_total counter\n"
            "nat64_icmp_error_translations_total{direction=\"v4_to_v6\"} %llu\n"
            "nat64_icmp_error_translations_total{direction=\"v6_to_v4\"} %llu\n"
            "# HELP nat64_icmpv6_error_outer_source_total IPv4 source selection for translated ICMPv6 errors.\n"
            "# TYPE nat64_icmpv6_error_outer_source_total counter\n"
            "nat64_icmpv6_error_outer_source_total{mode=\"pref64\"} %llu\n"
            "nat64_icmpv6_error_outer_source_total{mode=\"translator_laddr\"} %llu\n"
            "# HELP nat64_h323_packets_total H.323 ALG candidate packets by direction.\n"
            "# TYPE nat64_h323_packets_total counter\n"
            "nat64_h323_packets_total{direction=\"v6_to_v4\"} %llu\n"
            "nat64_h323_packets_total{direction=\"v4_to_v6\"} %llu\n"
            "# HELP nat64_h323_rewrites_total H.323 ALG packets whose payload was rewritten by direction.\n"
            "# TYPE nat64_h323_rewrites_total counter\n"
            "nat64_h323_rewrites_total{direction=\"v6_to_v4\"} %llu\n"
            "nat64_h323_rewrites_total{direction=\"v4_to_v6\"} %llu\n"
            "# HELP nat64_h323_failures_total H.323 ALG rewrite failures.\n"
            "# TYPE nat64_h323_failures_total counter\n"
            "nat64_h323_failures_total %llu\n"
            "# HELP nat64_acl_decisions_total ACL decisions by direction and action.\n"
            "# TYPE nat64_acl_decisions_total counter\n"
            "nat64_acl_decisions_total{direction=\"v6_to_v4\",action=\"permit\"} %llu\n"
            "nat64_acl_decisions_total{direction=\"v6_to_v4\",action=\"deny\"} %llu\n"
            "nat64_acl_decisions_total{direction=\"v4_to_v6\",action=\"permit\"} %llu\n"
            "nat64_acl_decisions_total{direction=\"v4_to_v6\",action=\"deny\"} %llu\n"
            "# HELP nat64_acl_reloads_total ACL reload attempts by result.\n"
            "# TYPE nat64_acl_reloads_total counter\n"
            "nat64_acl_reloads_total{result=\"success\"} %llu\n"
            "nat64_acl_reloads_total{result=\"failure\"} %llu\n"
            "# HELP nat64_acl_generation Current ACL runtime generation.\n"
            "# TYPE nat64_acl_generation gauge\n"
            "nat64_acl_generation %llu\n"
            "# HELP nat64_subscriber_new_sessions_allowed_total Subscriber-limited new NAT sessions allowed.\n"
            "# TYPE nat64_subscriber_new_sessions_allowed_total counter\n"
            "nat64_subscriber_new_sessions_allowed_total %llu\n"
            "# HELP nat64_subscriber_new_sessions_dropped_total Subscriber-limited new NAT sessions dropped by reason.\n"
            "# TYPE nat64_subscriber_new_sessions_dropped_total counter\n"
            "nat64_subscriber_new_sessions_dropped_total{reason=\"max_sessions\"} %llu\n"
            "nat64_subscriber_new_sessions_dropped_total{reason=\"rate_limit\"} %llu\n"
            "nat64_subscriber_new_sessions_dropped_total{reason=\"no_entry\"} %llu\n"
            "# HELP nat64_subscribers_active Current active subscriber prefix entries.\n"
            "# TYPE nat64_subscribers_active gauge\n"
            "nat64_subscribers_active %llu\n"
            "# HELP nat64_neighbors_active Current neighbor entries.\n"
            "# TYPE nat64_neighbors_active gauge\n"
            "nat64_neighbors_active{family=\"ipv4\"} %u\n"
            "nat64_neighbors_active{family=\"ipv6\"} %u\n"
            "# HELP nat64_link_up Link status by port side.\n"
            "# TYPE nat64_link_up gauge\n"
            "nat64_link_up{side=\"v6\"} %u\n"
            "nat64_link_up{side=\"v4\"} %u\n"
            "# HELP nat64_link_speed_mbps Link speed in Mbps by port side.\n"
            "# TYPE nat64_link_speed_mbps gauge\n"
            "nat64_link_speed_mbps{side=\"v6\"} %u\n"
            "nat64_link_speed_mbps{side=\"v4\"} %u\n"
            "# HELP nat64_link_full_duplex Link duplex mode by port side.\n"
            "# TYPE nat64_link_full_duplex gauge\n"
            "nat64_link_full_duplex{side=\"v6\"} %u\n"
            "nat64_link_full_duplex{side=\"v4\"} %u\n",
            (unsigned long long) stats.v6_to_v4_packets,
            (unsigned long long) stats.v4_to_v6_packets,
            (unsigned long long) stats.v6_to_v4_bytes,
            (unsigned long long) stats.v4_to_v6_bytes,
            (unsigned long long) stats.v6_to_v4_pps,
            (unsigned long long) stats.v4_to_v6_pps,
            (unsigned long long) stats.v6_to_v4_bps,
            (unsigned long long) stats.v4_to_v6_bps,
            stats.sessions_active,
            (unsigned long long) stats.sessions_created,
            (unsigned long long) stats.sessions_expired,
            (unsigned long long) stats.frag_received,
            (unsigned long long) stats.frag_reassembled,
            (unsigned long long) stats.frag_emitted,
            (unsigned long long) stats.frag_dropped,
            (unsigned long long) stats.frag_expired,
            stats.frag_active,
            (unsigned long long) stats.icmp_error_v4_to_v6,
            (unsigned long long) stats.icmp_error_v6_to_v4,
            (unsigned long long) stats.icmp_error_v6_outer_src_pref64,
            (unsigned long long) stats.icmp_error_v6_outer_src_translator,
            (unsigned long long) stats.h323_packets_v6_to_v4,
            (unsigned long long) stats.h323_packets_v4_to_v6,
            (unsigned long long) stats.h323_rewrites_v6_to_v4,
            (unsigned long long) stats.h323_rewrites_v4_to_v6,
            (unsigned long long) stats.h323_failures,
            (unsigned long long) stats.acl_permit_v6_to_v4,
            (unsigned long long) stats.acl_deny_v6_to_v4,
            (unsigned long long) stats.acl_permit_v4_to_v6,
            (unsigned long long) stats.acl_deny_v4_to_v6,
            (unsigned long long) monitor->ctx->acl_reload_success,
            (unsigned long long) monitor->ctx->acl_reload_failure,
            (unsigned long long) monitor->ctx->acl_generation,
            (unsigned long long) stats.subscriber_allowed_total,
            (unsigned long long) stats.subscriber_drop_max_sessions,
            (unsigned long long) stats.subscriber_drop_rate_limit,
            (unsigned long long) stats.subscriber_drop_no_entry,
            (unsigned long long) stats.subscriber_active_count,
            stats.neighbors4_active,
            stats.neighbors6_active,
            stats.links[0].up ? 1U : 0U,
            stats.links[1].up ? 1U : 0U,
            stats.links[0].speed,
            stats.links[1].speed,
            stats.links[0].full_duplex ? 1U : 0U,
            stats.links[1].full_duplex ? 1U : 0U)) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "metrics buffer overflow\n", 24);
        return;
    }

    if (!append_format(body, sizeof(body), &len,
                       "# HELP nat64_nexthop_configured Whether a default next-hop probe target is configured.\n"
                       "# TYPE nat64_nexthop_configured gauge\n"
                       "# HELP nat64_nexthop_l2_up Whether next-hop L2 resolution is currently healthy.\n"
                       "# TYPE nat64_nexthop_l2_up gauge\n"
                       "# HELP nat64_nexthop_l3_up Whether next-hop L3 echo probing is currently healthy.\n"
                       "# TYPE nat64_nexthop_l3_up gauge\n"
                       "# HELP nat64_nexthop_last_l2_success_seconds Unix time of the last successful L2 resolution.\n"
                       "# TYPE nat64_nexthop_last_l2_success_seconds gauge\n"
                       "# HELP nat64_nexthop_last_l3_success_seconds Unix time of the last successful L3 echo reply.\n"
                       "# TYPE nat64_nexthop_last_l3_success_seconds gauge\n"
                       "# HELP nat64_nexthop_l2_probes_sent_total Total active L2 probes sent to the next hop.\n"
                       "# TYPE nat64_nexthop_l2_probes_sent_total counter\n"
                       "# HELP nat64_nexthop_l3_probes_sent_total Total active L3 probes sent to the next hop.\n"
                       "# TYPE nat64_nexthop_l3_probes_sent_total counter\n"
                       "# HELP nat64_nexthop_l3_replies_total Total successful L3 echo replies from the next hop.\n"
                       "# TYPE nat64_nexthop_l3_replies_total counter\n"
                       "nat64_nexthop_configured{side=\"v6\"} %u\n"
                       "nat64_nexthop_configured{side=\"v4\"} %u\n"
                       "nat64_nexthop_l2_up{side=\"v6\"} %u\n"
                       "nat64_nexthop_l2_up{side=\"v4\"} %u\n"
                       "nat64_nexthop_l3_up{side=\"v6\"} %u\n"
                       "nat64_nexthop_l3_up{side=\"v4\"} %u\n"
                       "nat64_nexthop_last_l2_success_seconds{side=\"v6\"} %llu\n"
                       "nat64_nexthop_last_l2_success_seconds{side=\"v4\"} %llu\n"
                       "nat64_nexthop_last_l3_success_seconds{side=\"v6\"} %llu\n"
                       "nat64_nexthop_last_l3_success_seconds{side=\"v4\"} %llu\n"
                       "nat64_nexthop_l2_probes_sent_total{side=\"v6\"} %llu\n"
                       "nat64_nexthop_l2_probes_sent_total{side=\"v4\"} %llu\n"
                       "nat64_nexthop_l3_probes_sent_total{side=\"v6\"} %llu\n"
                       "nat64_nexthop_l3_probes_sent_total{side=\"v4\"} %llu\n"
                       "nat64_nexthop_l3_replies_total{side=\"v6\"} %llu\n"
                       "nat64_nexthop_l3_replies_total{side=\"v4\"} %llu\n",
                       stats.nexthops[0].configured ? 1U : 0U,
                       stats.nexthops[1].configured ? 1U : 0U,
                       stats.nexthops[0].l2_up ? 1U : 0U,
                       stats.nexthops[1].l2_up ? 1U : 0U,
                       stats.nexthops[0].l3_up ? 1U : 0U,
                       stats.nexthops[1].l3_up ? 1U : 0U,
                       (unsigned long long) stats.nexthops[0].last_l2_success_unix,
                       (unsigned long long) stats.nexthops[1].last_l2_success_unix,
                       (unsigned long long) stats.nexthops[0].last_l3_success_unix,
                       (unsigned long long) stats.nexthops[1].last_l3_success_unix,
                       (unsigned long long) stats.nexthops[0].l2_probes_sent,
                       (unsigned long long) stats.nexthops[1].l2_probes_sent,
                       (unsigned long long) stats.nexthops[0].l3_probes_sent,
                       (unsigned long long) stats.nexthops[1].l3_probes_sent,
                       (unsigned long long) stats.nexthops[0].l3_replies_rcvd,
                       (unsigned long long) stats.nexthops[1].l3_replies_rcvd)) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "metrics buffer overflow\n", 24);
        return;
    }

    if (!append_format(body, sizeof(body), &len,
                       "# HELP nat64_worker_busy_pct Worker busy-loop utilization percent by queue.\n"
                       "# TYPE nat64_worker_busy_pct gauge\n")) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "metrics buffer overflow\n", 24);
        return;
    }
    for (uint32_t i = 0; i < stats.queue_count && i < NAT64_MAX_WORKERS; i++) {
        if (!append_format(body, sizeof(body), &len,
                           "nat64_worker_busy_pct{queue=\"%u\",lcore=\"%u\"} %llu\n",
                           i,
                           stats.workers[i].lcore_id,
                           (unsigned long long) stats.workers[i].busy_pct)) {
            send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
            socket_write_all(client_fd, "metrics buffer overflow\n", 24);
            return;
        }
    }

    if (!append_format(body, sizeof(body), &len,
                       "# HELP nat64_port_packets_total Per-port traffic packets by direction and family.\n"
                       "# TYPE nat64_port_packets_total counter\n"
                       "# HELP nat64_port_bytes_total Per-port traffic bytes by direction and family.\n"
                       "# TYPE nat64_port_bytes_total counter\n"
                       "# HELP nat64_port_pps Per-port traffic packets per second by direction and family.\n"
                       "# TYPE nat64_port_pps gauge\n"
                       "# HELP nat64_port_bps Per-port traffic bits per second by direction and family.\n"
                       "# TYPE nat64_port_bps gauge\n")) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "metrics buffer overflow\n", 24);
        return;
    }
    for (uint32_t port = 0; port < NAT64_STATS_PORT_COUNT; port++) {
        const char *side = port_side_name(port);

        for (uint32_t dir = 0; dir < NAT64_STATS_DIR_COUNT; dir++) {
            const char *direction = stats_dir_name(dir);

            for (uint32_t family = 0; family < NAT64_STATS_FAMILY_COUNT; family++) {
                const char *family_name = stats_family_name(family);
                const struct nat64_traffic_stats *traffic = &stats.ports[port].traffic[dir][family];

                if (!append_format(body, sizeof(body), &len,
                                   "nat64_port_packets_total{side=\"%s\",direction=\"%s\",family=\"%s\"} %llu\n"
                                   "nat64_port_bytes_total{side=\"%s\",direction=\"%s\",family=\"%s\"} %llu\n"
                                   "nat64_port_pps{side=\"%s\",direction=\"%s\",family=\"%s\"} %llu\n"
                                   "nat64_port_bps{side=\"%s\",direction=\"%s\",family=\"%s\"} %llu\n",
                                   side, direction, family_name, (unsigned long long) traffic->packets,
                                   side, direction, family_name, (unsigned long long) traffic->bytes,
                                   side, direction, family_name, (unsigned long long) traffic->pps,
                                   side, direction, family_name, (unsigned long long) traffic->bps)) {
                    send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
                    socket_write_all(client_fd, "metrics buffer overflow\n", 24);
                    return;
                }
            }
        }
    }

    if (!send_http_header(client_fd, 200, "OK", "text/plain; version=0.0.4; charset=utf-8")) {
        return;
    }
    socket_write_all(client_fd, body, len);
}

static void serve_connections(struct nat64_monitor *monitor, int client_fd, const char *query)
{
    struct nat64_session *sessions;
    struct nat64_session_filter filter;
    uint32_t offset;
    uint32_t limit;
    uint32_t count;
    uint32_t matched_total = 0;
    uint64_t now_tsc;
    char line[512];

    if (!parse_connection_query(query, &filter, &offset, &limit, NAT64_CONN_TEXT_DEFAULT_LIMIT)) {
        send_text_response(client_fd, 400, "Bad Request",
                           "invalid query, use limit=1..10000, offset>=0, proto=tcp|udp|icmp\n");
        return;
    }

    sessions = calloc(limit, sizeof(*sessions));
    if (sessions == NULL && limit > 0) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "allocation failure\n", 19);
        return;
    }

    count = nat64_dump_sessions_filtered(monitor->ctx, &filter, offset, sessions, limit, &matched_total);
    now_tsc = rte_rdtsc();

    if (!send_http_header(client_fd, 200, "OK", "text/plain; charset=utf-8")) {
        free(sessions);
        return;
    }

    {
        static const char header[] =
            "# proto client_v6 client_port service_v6 service_port local_v4 local_port rs_v4 rs_port age_sec created_ts\n";
        socket_write_all(client_fd, header, sizeof(header) - 1);
    }
    {
        int len = snprintf(line, sizeof(line),
                           "# matched_total=%u offset=%u limit=%u returned=%u has_more=%u\n",
                           matched_total, offset, limit, count,
                           matched_total > offset + count ? 1U : 0U);
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    for (uint32_t i = 0; i < count; i++) {
        char client_v6[INET6_ADDRSTRLEN];
        char service_v6[INET6_ADDRSTRLEN];
        char local_v4[INET_ADDRSTRLEN];
        char rs_v4[INET_ADDRSTRLEN];
        unsigned long long age_sec = 0;
        int len;

        inet_ntop(AF_INET6, &sessions[i].client_v6, client_v6, sizeof(client_v6));
        inet_ntop(AF_INET6, &sessions[i].service_v6, service_v6, sizeof(service_v6));
        inet_ntop(AF_INET, &sessions[i].local_v4, local_v4, sizeof(local_v4));
        inet_ntop(AF_INET, &sessions[i].rs_v4, rs_v4, sizeof(rs_v4));
        if (now_tsc > sessions[i].last_seen_tsc && monitor->ctx->tsc_hz != 0) {
            age_sec = (now_tsc - sessions[i].last_seen_tsc) / monitor->ctx->tsc_hz;
        }

        len = snprintf(line, sizeof(line),
                       "%s %s %u %s %u %s %u %s %u %llu %llu\n",
                       proto_name(sessions[i].proto),
                       client_v6,
                       sessions[i].client_port,
                       service_v6,
                       sessions[i].service_port,
                       local_v4,
                       sessions[i].local_port,
                       rs_v4,
                       sessions[i].rs_port,
                       age_sec,
                       (unsigned long long) sessions[i].created_unix);
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    free(sessions);
}

static void serve_connections_json(struct nat64_monitor *monitor, int client_fd, const char *query)
{
    struct nat64_session_filter filter;
    struct nat64_session *sessions;
    uint32_t offset;
    uint32_t limit;
    uint32_t count;
    uint32_t matched_total = 0;
    uint64_t now_tsc;
    char line[1024];
    int len;

    if (!parse_connection_query(query, &filter, &offset, &limit, NAT64_CONN_DEFAULT_LIMIT)) {
        send_text_response(client_fd, 400, "Bad Request",
                           "invalid query, use limit=1..10000, offset>=0, proto=tcp|udp|icmp\n");
        return;
    }

    sessions = calloc(limit, sizeof(*sessions));
    if (sessions == NULL && limit > 0) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "allocation failure\n", 19);
        return;
    }

    count = nat64_dump_sessions_filtered(monitor->ctx, &filter, offset, sessions, limit, &matched_total);
    now_tsc = rte_rdtsc();

    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        free(sessions);
        return;
    }

    len = snprintf(line, sizeof(line),
                   "{\n"
                   "  \"matched_total\": %u,\n"
                   "  \"offset\": %u,\n"
                   "  \"limit\": %u,\n"
                   "  \"returned\": %u,\n"
                   "  \"has_more\": %s,\n"
                   "  \"next_offset\": %u,\n"
                   "  \"connections\": [\n",
                   matched_total, offset, limit, count,
                   matched_total > offset + count ? "true" : "false",
                   offset + count);
    if (len > 0 && (size_t) len < sizeof(line)) {
        socket_write_all(client_fd, line, (size_t) len);
    }

    for (uint32_t i = 0; i < count; i++) {
        char client_v6[INET6_ADDRSTRLEN];
        char service_v6[INET6_ADDRSTRLEN];
        char local_v4[INET_ADDRSTRLEN];
        char rs_v4[INET_ADDRSTRLEN];
        unsigned long long age_sec = 0;

        inet_ntop(AF_INET6, &sessions[i].client_v6, client_v6, sizeof(client_v6));
        inet_ntop(AF_INET6, &sessions[i].service_v6, service_v6, sizeof(service_v6));
        inet_ntop(AF_INET, &sessions[i].local_v4, local_v4, sizeof(local_v4));
        inet_ntop(AF_INET, &sessions[i].rs_v4, rs_v4, sizeof(rs_v4));
        if (now_tsc > sessions[i].last_seen_tsc && monitor->ctx->tsc_hz != 0) {
            age_sec = (now_tsc - sessions[i].last_seen_tsc) / monitor->ctx->tsc_hz;
        }

        len = snprintf(line, sizeof(line),
                       "    {\"proto\":\"%s\",\"service_index\":%u,"
                       "\"client_v6\":\"%s\",\"client_port\":%u,"
                       "\"service_v6\":\"%s\",\"service_port\":%u,"
                       "\"local_v4\":\"%s\",\"local_port\":%u,"
                       "\"rs_v4\":\"%s\",\"rs_port\":%u,"
                       "\"age_sec\":%llu,\"created_ts\":%llu}%s\n",
                       proto_name(sessions[i].proto),
                       sessions[i].service_index,
                       client_v6, sessions[i].client_port,
                       service_v6, sessions[i].service_port,
                       local_v4, sessions[i].local_port,
                       rs_v4, sessions[i].rs_port,
                       age_sec,
                       (unsigned long long) sessions[i].created_unix,
                       i + 1 < count ? "," : "");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    socket_write_all(client_fd, "  ]\n}\n", 6);
    free(sessions);
}

static bool parse_paged_query(const char *query, uint32_t *offset, uint32_t *limit,
                              uint32_t default_limit, uint32_t max_limit)
{
    char value[128];

    *offset = 0;
    *limit = default_limit;
    if (query_get_value(query, "offset", value, sizeof(value)) && !parse_u32_text(value, offset)) {
        return false;
    }
    if (query_get_value(query, "limit", value, sizeof(value))) {
        if (!parse_u32_text(value, limit) || *limit == 0 || *limit > max_limit) {
            return false;
        }
    }
    return true;
}

static void serve_subscribers_json(struct nat64_monitor *monitor, int client_fd, const char *query)
{
    struct nat64_subscriber_snapshot *subscribers;
    uint32_t offset;
    uint32_t limit;
    uint32_t count;
    uint32_t matched_total = 0;
    char line[1024];
    int len;

    if (!parse_paged_query(query, &offset, &limit, NAT64_SUBSCRIBER_DEFAULT_LIMIT, NAT64_SUBSCRIBER_MAX_LIMIT)) {
        send_text_response(client_fd, 400, "Bad Request",
                           "invalid query, use limit=1..10000 and offset>=0\n");
        return;
    }

    subscribers = calloc(limit, sizeof(*subscribers));
    if (subscribers == NULL && limit > 0) {
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "allocation failure\n", 19);
        return;
    }

    count = nat64_dump_subscribers(monitor->ctx, subscribers, offset, limit, &matched_total);
    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        free(subscribers);
        return;
    }

    len = snprintf(line, sizeof(line),
                   "{\n"
                   "  \"enabled\": %s,\n"
                   "  \"prefix_len\": %u,\n"
                   "  \"matched_total\": %u,\n"
                   "  \"offset\": %u,\n"
                   "  \"limit\": %u,\n"
                   "  \"returned\": %u,\n"
                   "  \"has_more\": %s,\n"
                   "  \"subscribers\": [\n",
                   monitor->ctx->cfg->subscriber_limits.enabled ? "true" : "false",
                   monitor->ctx->cfg->subscriber_limits.prefix_len,
                   matched_total, offset, limit, count,
                   matched_total > offset + count ? "true" : "false");
    if (len > 0 && (size_t) len < sizeof(line)) {
        socket_write_all(client_fd, line, (size_t) len);
    }

    for (uint32_t i = 0; i < count; i++) {
        char prefix[INET6_ADDRSTRLEN];
        char rule_index_json[32];

        inet_ntop(AF_INET6, &subscribers[i].prefix, prefix, sizeof(prefix));
        if (subscribers[i].rule_index == UINT32_MAX) {
            snprintf(rule_index_json, sizeof(rule_index_json), "null");
        } else {
            snprintf(rule_index_json, sizeof(rule_index_json), "%u", subscribers[i].rule_index);
        }
        len = snprintf(line, sizeof(line),
                       "    {\"prefix\":\"%s/%u\",\"rule_index\":%s,\"rule_name\":\"%s\","
                       "\"active_sessions\":%u,\"max_sessions\":%u,"
                       "\"new_conn_per_sec\":%u,\"burst\":%u,"
                       "\"allowed_total\":%llu,\"drop_max_sessions\":%llu,"
                       "\"drop_rate_limit\":%llu,\"age_sec\":%llu}%s\n",
                       prefix, subscribers[i].prefix_len,
                       rule_index_json,
                       subscribers[i].rule_name,
                       subscribers[i].active_sessions,
                       subscribers[i].max_sessions,
                       subscribers[i].new_conn_per_sec,
                       subscribers[i].burst,
                       (unsigned long long) subscribers[i].allowed_total,
                       (unsigned long long) subscribers[i].drop_max_sessions,
                       (unsigned long long) subscribers[i].drop_rate_limit,
                       (unsigned long long) subscribers[i].age_sec,
                       i + 1 < count ? "," : "");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }
    socket_write_all(client_fd, "  ]\n}\n", 6);
    free(subscribers);
}

static void serve_neighbors(struct nat64_monitor *monitor, int client_fd)
{
    struct nat64_neighbor4 *neighbors4;
    struct nat64_neighbor6 *neighbors6;
    uint32_t count4 = 0;
    uint32_t count6 = 0;
    uint64_t now_tsc;
    char line[512];

    neighbors4 = calloc(NAT64_MAX_NEIGHBORS, sizeof(*neighbors4));
    neighbors6 = calloc(NAT64_MAX_NEIGHBORS, sizeof(*neighbors6));
    if (neighbors4 == NULL || neighbors6 == NULL) {
        free(neighbors4);
        free(neighbors6);
        send_http_header(client_fd, 500, "Internal Server Error", "text/plain; charset=utf-8");
        socket_write_all(client_fd, "allocation failure\n", 19);
        return;
    }

    nat64_dump_neighbors(monitor->ctx, neighbors4, &count4, NAT64_MAX_NEIGHBORS,
                         neighbors6, &count6, NAT64_MAX_NEIGHBORS);
    now_tsc = rte_rdtsc();

    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        free(neighbors4);
        free(neighbors6);
        return;
    }

    {
        int len = snprintf(line, sizeof(line),
                           "{\n"
                           "  \"ipv4\": [\n");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    for (uint32_t i = 0; i < count4; i++) {
        char ipbuf[INET_ADDRSTRLEN];
        char macbuf[32];
        unsigned long long age_sec = 0;
        int len;

        inet_ntop(AF_INET, &neighbors4[i].ip, ipbuf, sizeof(ipbuf));
        format_mac_text(&neighbors4[i].mac, macbuf, sizeof(macbuf));
        if (now_tsc > neighbors4[i].last_seen_tsc && monitor->ctx->tsc_hz != 0) {
            age_sec = (now_tsc - neighbors4[i].last_seen_tsc) / monitor->ctx->tsc_hz;
        }

        len = snprintf(line, sizeof(line),
                       "    {\"ip\":\"%s\",\"mac\":\"%s\",\"age_sec\":%llu}%s\n",
                       ipbuf,
                       macbuf,
                       age_sec,
                       i + 1 < count4 ? "," : "");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    {
        int len = snprintf(line, sizeof(line),
                           "  ],\n"
                           "  \"ipv6\": [\n");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    for (uint32_t i = 0; i < count6; i++) {
        char ipbuf[INET6_ADDRSTRLEN];
        char macbuf[32];
        unsigned long long age_sec = 0;
        int len;

        inet_ntop(AF_INET6, &neighbors6[i].ip, ipbuf, sizeof(ipbuf));
        format_mac_text(&neighbors6[i].mac, macbuf, sizeof(macbuf));
        if (now_tsc > neighbors6[i].last_seen_tsc && monitor->ctx->tsc_hz != 0) {
            age_sec = (now_tsc - neighbors6[i].last_seen_tsc) / monitor->ctx->tsc_hz;
        }

        len = snprintf(line, sizeof(line),
                       "    {\"ip\":\"%s\",\"mac\":\"%s\",\"age_sec\":%llu}%s\n",
                       ipbuf,
                       macbuf,
                       age_sec,
                       i + 1 < count6 ? "," : "");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    {
        int len = snprintf(line, sizeof(line),
                           "  ]\n"
                           "}\n");
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    free(neighbors4);
    free(neighbors6);
}

static void serve_capture_status(struct nat64_monitor *monitor, int client_fd)
{
    struct nat64_capture_status status;
    char body[768];
    uint64_t now_unix_sec = (uint64_t) time(NULL);
    uint64_t remaining_sec = 0;
    int len;

    nat64_capture_get_status(&monitor->ctx->capture, &status);
    if (status.active && status.stop_at_unix_sec > now_unix_sec) {
        remaining_sec = status.stop_at_unix_sec - now_unix_sec;
    }
    len = snprintf(body, sizeof(body),
                   "active: %s\n"
                   "side: %s\n"
                   "direction: %s\n"
                   "filter: %s\n"
                   "file: %s\n"
                   "duration_sec: %u\n"
                   "stop_at_unix_sec: %llu\n"
                   "remaining_sec: %llu\n"
                   "captured_packets: %llu\n"
                   "dropped_packets: %llu\n",
                   status.active ? "true" : "false",
                   status.active ? capture_mask_to_side(monitor, status.port_mask) : "-",
                   status.active ? capture_direction_name(status.dir_mask) : "-",
                   status.active && status.filter.enabled ? status.filter.text : "-",
                   status.file_path[0] != '\0' ? status.file_path : "-",
                   status.duration_sec,
                   (unsigned long long) status.stop_at_unix_sec,
                   (unsigned long long) remaining_sec,
                   (unsigned long long) status.captured_packets,
                   (unsigned long long) status.dropped_packets);
    if (len < 0 || (size_t) len >= sizeof(body)) {
        send_text_response(client_fd, 500, "Internal Server Error", "capture status overflow\n");
        return;
    }
    send_text_response(client_fd, 200, "OK", body);
}

static void serve_capture_stop(struct nat64_monitor *monitor, int client_fd)
{
    nat64_capture_stop(&monitor->ctx->capture);
    send_text_response(client_fd, 200, "OK", "capture stopped\n");
}

static void serve_capture_start(struct nat64_monitor *monitor, int client_fd, const char *query)
{
    char side[16];
    char direction[16] = "both";
    char filter_value[NAT64_CAPTURE_FILTER_LEN];
    char duration_value[32];
    char file_path[NAT64_CAPTURE_FILE_LEN];
    uint64_t port_mask;
    uint8_t dir_mask;
    uint32_t duration_sec = 0;
    struct nat64_capture_filter filter;
    int rc;
    char body[768];
    int len;

    if (!query_get_value(query, "side", side, sizeof(side))) {
        send_text_response(client_fd, 400, "Bad Request", "missing side query parameter\n");
        return;
    }
    if (!capture_side_to_mask(monitor, side, &port_mask)) {
        send_text_response(client_fd, 400, "Bad Request", "invalid side, use v4, v6, or all\n");
        return;
    }
    if (query_get_value(query, "direction", direction, sizeof(direction))) {
        dir_mask = capture_direction_mask(direction);
        if (dir_mask == 0) {
            send_text_response(client_fd, 400, "Bad Request", "invalid direction, use rx, tx, or both\n");
            return;
        }
    } else {
        dir_mask = NAT64_CAPTURE_DIR_RX | NAT64_CAPTURE_DIR_TX;
    }
    if (query_get_value(query, "addr", filter_value, sizeof(filter_value))) {
        if (!capture_parse_filter(filter_value, &filter)) {
            send_text_response(client_fd, 400, "Bad Request", "invalid addr filter, use one IPv4 or IPv6 address\n");
            return;
        }
    } else {
        memset(&filter, 0, sizeof(filter));
    }
    if (query_get_value(query, "duration_sec", duration_value, sizeof(duration_value))) {
        if (!parse_duration_sec(duration_value, &duration_sec) || duration_sec == 0) {
            send_text_response(client_fd, 400, "Bad Request", "invalid duration_sec, use a positive integer number of seconds\n");
            return;
        }
    }

    if (!query_get_value(query, "file", file_path, sizeof(file_path))) {
        build_capture_file_path(monitor, port_mask, side, direction, file_path, sizeof(file_path));
    }

    rc = nat64_capture_start(&monitor->ctx->capture, port_mask, dir_mask, &filter, file_path, duration_sec);
    if (rc == -EBUSY) {
        send_text_response(client_fd, 409, "Conflict", "capture already active\n");
        return;
    }
    if (rc < 0) {
        len = snprintf(body, sizeof(body), "failed to start capture: %d\n", rc);
        if (len < 0 || (size_t) len >= sizeof(body)) {
            send_text_response(client_fd, 500, "Internal Server Error", "failed to start capture\n");
            return;
        }
        send_text_response(client_fd, 500, "Internal Server Error", body);
        return;
    }

    len = snprintf(body, sizeof(body),
                   "capture started\n"
                   "side: %s\n"
                   "direction: %s\n"
                   "filter: %s\n"
                   "duration_sec: %u\n"
                   "file: %s\n",
                   side, direction, filter.enabled ? filter.text : "-", duration_sec, file_path);
    if (len < 0 || (size_t) len >= sizeof(body)) {
        send_text_response(client_fd, 500, "Internal Server Error", "capture started\n");
        return;
    }
    send_text_response(client_fd, 200, "OK", body);
}

static void serve_nexthops(struct nat64_monitor *monitor, int client_fd)
{
    char body[1536];
    char v4buf[INET_ADDRSTRLEN] = "-";
    char v6buf[INET6_ADDRSTRLEN] = "-";
    char v6_l2_time[32];
    char v6_l3_time[32];
    char v4_l2_time[32];
    char v4_l3_time[32];
    int len;

    if (monitor->ctx->probe4.configured) {
        inet_ntop(AF_INET, &monitor->ctx->probe4.target, v4buf, sizeof(v4buf));
    }
    if (monitor->ctx->probe6.configured) {
        inet_ntop(AF_INET6, &monitor->ctx->probe6.target, v6buf, sizeof(v6buf));
    }
    format_unix_time_text(monitor->ctx->probe6.last_l2_success_unix, v6_l2_time, sizeof(v6_l2_time));
    format_unix_time_text(monitor->ctx->probe6.last_l3_success_unix, v6_l3_time, sizeof(v6_l3_time));
    format_unix_time_text(monitor->ctx->probe4.last_l2_success_unix, v4_l2_time, sizeof(v4_l2_time));
    format_unix_time_text(monitor->ctx->probe4.last_l3_success_unix, v4_l3_time, sizeof(v4_l3_time));

    len = snprintf(body, sizeof(body),
                   "v6_target: %s\n"
                   "v6_configured: %s\n"
                   "v6_l2_up: %s\n"
                   "v6_l3_up: %s\n"
                   "v6_l2_probes_sent: %llu\n"
                   "v6_l3_probes_sent: %llu\n"
                   "v6_l3_replies: %llu\n"
                   "v6_last_l2_success_unix: %llu\n"
                   "v6_last_l2_success_time: %s\n"
                   "v6_last_l3_success_unix: %llu\n"
                   "v6_last_l3_success_time: %s\n"
                   "v4_target: %s\n"
                   "v4_configured: %s\n"
                   "v4_l2_up: %s\n"
                   "v4_l3_up: %s\n"
                   "v4_l2_probes_sent: %llu\n"
                   "v4_l3_probes_sent: %llu\n"
                   "v4_l3_replies: %llu\n"
                   "v4_last_l2_success_unix: %llu\n"
                   "v4_last_l2_success_time: %s\n"
                   "v4_last_l3_success_unix: %llu\n"
                   "v4_last_l3_success_time: %s\n",
                   v6buf,
                   monitor->ctx->probe6.configured ? "true" : "false",
                   monitor->ctx->probe6.l2_up ? "true" : "false",
                   monitor->ctx->probe6.l3_up ? "true" : "false",
                   (unsigned long long) monitor->ctx->probe6.l2_probes_sent,
                   (unsigned long long) monitor->ctx->probe6.l3_probes_sent,
                   (unsigned long long) monitor->ctx->probe6.l3_replies_rcvd,
                   (unsigned long long) monitor->ctx->probe6.last_l2_success_unix,
                   v6_l2_time,
                   (unsigned long long) monitor->ctx->probe6.last_l3_success_unix,
                   v6_l3_time,
                   v4buf,
                   monitor->ctx->probe4.configured ? "true" : "false",
                   monitor->ctx->probe4.l2_up ? "true" : "false",
                   monitor->ctx->probe4.l3_up ? "true" : "false",
                   (unsigned long long) monitor->ctx->probe4.l2_probes_sent,
                   (unsigned long long) monitor->ctx->probe4.l3_probes_sent,
                   (unsigned long long) monitor->ctx->probe4.l3_replies_rcvd,
                   (unsigned long long) monitor->ctx->probe4.last_l2_success_unix,
                   v4_l2_time,
                   (unsigned long long) monitor->ctx->probe4.last_l3_success_unix,
                   v4_l3_time);
    if (len < 0 || (size_t) len >= sizeof(body)) {
        send_text_response(client_fd, 500, "Internal Server Error", "nexthop status overflow\n");
        return;
    }
    send_text_response(client_fd, 200, "OK", body);
}

static void serve_probe_trigger(struct nat64_monitor *monitor, int client_fd)
{
    nat64_trigger_nexthop_probe(monitor->ctx);
    send_text_response(client_fd, 200, "OK",
                       "next-hop probe trigger armed\n"
                       "GET /nexthops to inspect probe state\n");
}

static void serve_ping6_status(struct nat64_monitor *monitor, int client_fd)
{
    struct nat64_ping6_state state;
    char target[INET6_ADDRSTRLEN] = "-";
    char neigh[INET6_ADDRSTRLEN] = "-";
    char started_time[32];
    char finished_time[32];
    char last_reply_time[32];
    char body[1536];
    int len;

    nat64_get_ping6_state(monitor->ctx, &state);
    if (state.active) {
        inet_ntop(AF_INET6, &state.target, target, sizeof(target));
        inet_ntop(AF_INET6, &state.neigh_ip, neigh, sizeof(neigh));
    }
    format_unix_time_text(state.started_unix, started_time, sizeof(started_time));
    format_unix_time_text(state.finished_unix, finished_time, sizeof(finished_time));
    format_unix_time_text(state.last_reply_unix, last_reply_time, sizeof(last_reply_time));

    len = snprintf(body, sizeof(body),
                   "{\n"
                   "  \"active\": %s,\n"
                   "  \"done\": %s,\n"
                   "  \"target\": \"%s\",\n"
                   "  \"neighbor\": \"%s\",\n"
                   "  \"route_found\": %s,\n"
                   "  \"direct\": %s,\n"
                   "  \"l2_up\": %s,\n"
                   "  \"count\": %u,\n"
                   "  \"sent\": %u,\n"
                   "  \"received\": %u,\n"
                   "  \"loss\": %u,\n"
                   "  \"l2_probes_sent\": %llu,\n"
                   "  \"started_unix\": %llu,\n"
                   "  \"started_time\": \"%s\",\n"
                   "  \"finished_unix\": %llu,\n"
                   "  \"finished_time\": \"%s\",\n"
                   "  \"last_reply_unix\": %llu,\n"
                   "  \"last_reply_time\": \"%s\",\n"
                   "  \"error\": \"%s\"\n"
                   "}\n",
                   state.active ? "true" : "false",
                   state.done ? "true" : "false",
                   target,
                   neigh,
                   state.route_found ? "true" : "false",
                   state.direct ? "true" : "false",
                   state.l2_up ? "true" : "false",
                   (unsigned) state.count,
                   (unsigned) state.sent,
                   (unsigned) state.received,
                   (unsigned) (state.sent >= state.received ? state.sent - state.received : 0),
                   (unsigned long long) state.l2_probes_sent,
                   (unsigned long long) state.started_unix,
                   started_time,
                   (unsigned long long) state.finished_unix,
                   finished_time,
                   (unsigned long long) state.last_reply_unix,
                   last_reply_time,
                   state.error);
    if (len < 0 || (size_t) len >= sizeof(body)) {
        send_text_response(client_fd, 500, "Internal Server Error", "ping6 status overflow\n");
        return;
    }

    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        return;
    }
    socket_write_all(client_fd, body, (size_t) len);
}

static void serve_ping6_start(struct nat64_monitor *monitor, int client_fd, const char *query)
{
    char addr_text[INET6_ADDRSTRLEN];
    char count_text[16];
    struct in6_addr target;
    uint32_t count = 4;
    int rc;

    if (!query_get_value(query, "addr", addr_text, sizeof(addr_text))) {
        send_text_response(client_fd, 400, "Bad Request", "missing addr query parameter\n");
        return;
    }
    if (inet_pton(AF_INET6, addr_text, &target) != 1) {
        send_text_response(client_fd, 400, "Bad Request", "invalid IPv6 addr query parameter\n");
        return;
    }
    if (query_get_value(query, "count", count_text, sizeof(count_text))) {
        if (!parse_duration_sec(count_text, &count) || count == 0 || count > NAT64_PING6_MAX_COUNT) {
            send_text_response(client_fd, 400, "Bad Request", "invalid count, use 1..64\n");
            return;
        }
    }

    rc = nat64_start_ping6(monitor->ctx, &target, (uint16_t) count);
    if (rc < 0) {
        char body[128];
        int len = snprintf(body, sizeof(body), "failed to start ping6: %d\n", rc);

        if (len < 0 || (size_t) len >= sizeof(body)) {
            send_text_response(client_fd, 500, "Internal Server Error", "failed to start ping6\n");
            return;
        }
        send_text_response(client_fd, rc == -EINVAL ? 400 : 500,
                           rc == -EINVAL ? "Bad Request" : "Internal Server Error", body);
        return;
    }

    serve_ping6_status(monitor, client_fd);
}

static const char *probe4_mode_text(enum nat64_probe4_mode mode)
{
    switch (mode) {
    case NAT64_PROBE4_PING:
        return "ping4";
    case NAT64_PROBE4_TCP:
        return "tcp";
    case NAT64_PROBE4_HTTP:
        return "http";
    default:
        return "none";
    }
}

static void serve_probe4_status(struct nat64_monitor *monitor, int client_fd)
{
    struct nat64_probe4_state state;
    char source[INET_ADDRSTRLEN] = "-";
    char target[INET_ADDRSTRLEN] = "-";
    char neigh[INET_ADDRSTRLEN] = "-";
    char started_time[32];
    char finished_time[32];
    char last_reply_time[32];
    char body[2048];
    int len;

    nat64_get_probe4_state(monitor->ctx, &state);
    if (state.active) {
        inet_ntop(AF_INET, &state.source, source, sizeof(source));
        inet_ntop(AF_INET, &state.target, target, sizeof(target));
        inet_ntop(AF_INET, &state.neigh_ip, neigh, sizeof(neigh));
    }
    format_unix_time_text(state.started_unix, started_time, sizeof(started_time));
    format_unix_time_text(state.finished_unix, finished_time, sizeof(finished_time));
    format_unix_time_text(state.last_reply_unix, last_reply_time, sizeof(last_reply_time));

    len = snprintf(body, sizeof(body),
                   "{\n"
                   "  \"active\": %s,\n"
                   "  \"done\": %s,\n"
                   "  \"mode\": \"%s\",\n"
                   "  \"source\": \"%s\",\n"
                   "  \"target\": \"%s\",\n"
                   "  \"neighbor\": \"%s\",\n"
                   "  \"route_found\": %s,\n"
                   "  \"direct\": %s,\n"
                   "  \"l2_up\": %s,\n"
                   "  \"target_port\": %u,\n"
                   "  \"source_port\": %u,\n"
                   "  \"tcp_connected\": %s,\n"
                   "  \"http_request_sent\": %s,\n"
                   "  \"http_status\": %u,\n"
                   "  \"http_bytes\": %u,\n"
                   "  \"count\": %u,\n"
                   "  \"sent\": %u,\n"
                   "  \"received\": %u,\n"
                   "  \"loss\": %u,\n"
                   "  \"l2_probes_sent\": %llu,\n"
                   "  \"started_unix\": %llu,\n"
                   "  \"started_time\": \"%s\",\n"
                   "  \"finished_unix\": %llu,\n"
                   "  \"finished_time\": \"%s\",\n"
                   "  \"last_reply_unix\": %llu,\n"
                   "  \"last_reply_time\": \"%s\",\n"
                   "  \"error\": \"%s\"\n"
                   "}\n",
                   state.active ? "true" : "false",
                   state.done ? "true" : "false",
                   probe4_mode_text(state.mode),
                   source,
                   target,
                   neigh,
                   state.route_found ? "true" : "false",
                   state.direct ? "true" : "false",
                   state.l2_up ? "true" : "false",
                   (unsigned) state.target_port,
                   (unsigned) state.source_port,
                   state.tcp_connected ? "true" : "false",
                   state.http_request_sent ? "true" : "false",
                   (unsigned) state.http_status,
                   (unsigned) state.http_bytes,
                   (unsigned) state.count,
                   (unsigned) state.sent,
                   (unsigned) state.received,
                   (unsigned) (state.sent >= state.received ? state.sent - state.received : 0),
                   (unsigned long long) state.l2_probes_sent,
                   (unsigned long long) state.started_unix,
                   started_time,
                   (unsigned long long) state.finished_unix,
                   finished_time,
                   (unsigned long long) state.last_reply_unix,
                   last_reply_time,
                   state.error);
    if (len < 0 || (size_t) len >= sizeof(body)) {
        send_text_response(client_fd, 500, "Internal Server Error", "probe status overflow\n");
        return;
    }
    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        return;
    }
    socket_write_all(client_fd, body, (size_t) len);
}

static bool parse_probe4_common(const char *query, struct in_addr *source, struct in_addr *target,
                                uint16_t *port, uint16_t *count, uint16_t default_port,
                                uint16_t default_count, char *err, size_t err_len)
{
    char value[256];

    memset(source, 0, sizeof(*source));
    *port = default_port;
    *count = default_count;
    if (!query_get_value(query, "target", value, sizeof(value)) &&
        !query_get_value(query, "addr", value, sizeof(value))) {
        snprintf(err, err_len, "missing target query parameter");
        return false;
    }
    if (inet_pton(AF_INET, value, target) != 1) {
        snprintf(err, err_len, "invalid IPv4 target query parameter");
        return false;
    }
    if (query_get_value(query, "source", value, sizeof(value)) &&
        inet_pton(AF_INET, value, source) != 1) {
        snprintf(err, err_len, "invalid IPv4 source query parameter");
        return false;
    }
    if (query_get_value(query, "port", value, sizeof(value)) &&
        (!parse_u16_text(value, port) || *port == 0)) {
        snprintf(err, err_len, "invalid port query parameter");
        return false;
    }
    if (query_get_value(query, "count", value, sizeof(value))) {
        uint32_t parsed = 0;

        if (!parse_duration_sec(value, &parsed) || parsed == 0 || parsed > NAT64_PROBE4_MAX_COUNT) {
            snprintf(err, err_len, "invalid count, use 1..64");
            return false;
        }
        *count = (uint16_t) parsed;
    }
    return true;
}

static bool parse_http_url(const char *url, struct in_addr *target, uint16_t *port,
                           char *host, size_t host_len, char *path, size_t path_len)
{
    const char *cur;
    const char *slash;
    char *colon;
    char hostport[160];
    size_t hostport_len;

    if (strncmp(url, "http://", 7) != 0) {
        return false;
    }
    cur = url + 7;
    slash = strchr(cur, '/');
    if (slash == NULL) {
        slash = cur + strlen(cur);
    }
    hostport_len = (size_t) (slash - cur);
    if (hostport_len == 0 || hostport_len >= sizeof(hostport)) {
        return false;
    }
    memcpy(hostport, cur, hostport_len);
    hostport[hostport_len] = '\0';

    colon = strrchr(hostport, ':');
    *port = 80;
    if (colon != NULL) {
        uint16_t parsed_port;

        *colon = '\0';
        if (!parse_u16_text(colon + 1, &parsed_port) || parsed_port == 0) {
            return false;
        }
        *port = parsed_port;
    }
    if (inet_pton(AF_INET, hostport, target) != 1) {
        return false;
    }
    if (hostport_len + 1 > host_len) {
        return false;
    }
    rte_strscpy(host, hostport, host_len);
    if (*slash == '\0') {
        rte_strscpy(path, "/", path_len);
    } else {
        if (strlen(slash) + 1 > path_len) {
            return false;
        }
        rte_strscpy(path, slash, path_len);
    }
    return true;
}

static void serve_probe4_start(struct nat64_monitor *monitor, int client_fd, const char *query,
                               enum nat64_probe4_mode mode)
{
    struct in_addr source;
    struct in_addr target;
    uint16_t port;
    uint16_t count;
    char err[128] = {0};
    char value[512];
    char host[128] = {0};
    char path[256] = "/";
    int rc;

    if (mode == NAT64_PROBE4_HTTP && query_get_value(query, "url", value, sizeof(value))) {
        memset(&source, 0, sizeof(source));
        count = 1;
        if (!parse_http_url(value, &target, &port, host, sizeof(host), path, sizeof(path))) {
            send_text_response(client_fd, 400, "Bad Request", "invalid url, use http://<ipv4>[:port]/path\n");
            return;
        }
        if (query_get_value(query, "source", value, sizeof(value)) &&
            inet_pton(AF_INET, value, &source) != 1) {
            send_text_response(client_fd, 400, "Bad Request", "invalid IPv4 source query parameter\n");
            return;
        }
    } else {
        uint16_t default_port = mode == NAT64_PROBE4_HTTP ? 80 : 0;
        uint16_t default_count = mode == NAT64_PROBE4_PING ? 4 : 1;

        if (!parse_probe4_common(query, &source, &target, &port, &count, default_port, default_count,
                                 err, sizeof(err))) {
            send_text_response(client_fd, 400, "Bad Request", err[0] != '\0' ? err : "invalid probe query\n");
            return;
        }
        if (mode == NAT64_PROBE4_HTTP) {
            if (!query_get_value(query, "host", host, sizeof(host))) {
                inet_ntop(AF_INET, &target, host, sizeof(host));
            }
            if (query_get_value(query, "path", value, sizeof(value))) {
                if (value[0] != '/' || strlen(value) >= sizeof(path)) {
                    send_text_response(client_fd, 400, "Bad Request", "invalid path, use /path\n");
                    return;
                }
                rte_strscpy(path, value, sizeof(path));
            }
        }
    }

    rc = nat64_start_probe4(monitor->ctx, mode, source.s_addr != 0 ? &source : NULL, &target, port, count,
                            mode == NAT64_PROBE4_HTTP ? host : NULL,
                            mode == NAT64_PROBE4_HTTP ? path : NULL);
    if (rc < 0) {
        char body[128];
        int len = snprintf(body, sizeof(body), "failed to start %s probe: %d\n", probe4_mode_text(mode), rc);

        if (len < 0 || (size_t) len >= sizeof(body)) {
            send_text_response(client_fd, 500, "Internal Server Error", "failed to start probe\n");
            return;
        }
        send_text_response(client_fd, rc == -EINVAL ? 400 : 500,
                           rc == -EINVAL ? "Bad Request" : "Internal Server Error", body);
        return;
    }

    serve_probe4_status(monitor, client_fd);
}

static void serve_acl_reload(struct nat64_monitor *monitor, int client_fd)
{
    char errbuf[256] = {0};
    char body[512];
    const char *path = monitor->ctx->config_path[0] != '\0' ? monitor->ctx->config_path : "<unset>";
    int rc = nat64_acl_reload_from_config(monitor->ctx, monitor->ctx->config_path, errbuf, sizeof(errbuf));
    int len;

    if (rc < 0) {
        len = snprintf(body, sizeof(body),
                       "{\"ok\":false,\"config_path\":\"%s\",\"error\":\"%s\",\"rc\":%d}\n",
                       path, errbuf[0] != '\0' ? errbuf : "acl reload failed", rc);
        if (!send_http_header(client_fd, 400, "Bad Request", "application/json; charset=utf-8")) {
            return;
        }
        if (len > 0 && (size_t) len < sizeof(body)) {
            socket_write_all(client_fd, body, (size_t) len);
        }
        return;
    }

    len = snprintf(body, sizeof(body),
                   "{\"ok\":true,\"config_path\":\"%s\",\"generation\":%llu,"
                   "\"reload_success\":%llu,\"reload_failure\":%llu}\n",
                   path,
                   (unsigned long long) monitor->ctx->acl_generation,
                   (unsigned long long) monitor->ctx->acl_reload_success,
                   (unsigned long long) monitor->ctx->acl_reload_failure);
    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        return;
    }
    if (len > 0 && (size_t) len < sizeof(body)) {
        socket_write_all(client_fd, body, (size_t) len);
    }
}

static void serve_acl_rules(struct nat64_monitor *monitor, int client_fd)
{
    struct nat64_ctx *ctx = monitor->ctx;
    const struct nat64_config *cfg = ctx->mutable_cfg != NULL ? ctx->mutable_cfg : ctx->cfg;
    char line[1024];
    bool first = true;

    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        return;
    }
    {
        int len = snprintf(line, sizeof(line),
                           "{\n  \"generation\": %llu,\n"
                           "  \"reload_success\": %llu,\n"
                           "  \"reload_failure\": %llu,\n"
                           "  \"rules\": [\n",
                           (unsigned long long) ctx->acl_generation,
                           (unsigned long long) ctx->acl_reload_success,
                           (unsigned long long) ctx->acl_reload_failure);
        if (len > 0 && (size_t) len < sizeof(line)) {
            socket_write_all(client_fd, line, (size_t) len);
        }
    }

    for (uint32_t svc = 0; svc < cfg->service_count && svc < NAT64_MAX_SERVICES; svc++) {
        const struct nat64_service_config *service = &cfg->services[svc];
        const enum nat64_acl_direction dirs[2] = {NAT64_ACL_DIR_V6_TO_V4, NAT64_ACL_DIR_V4_TO_V6};

        for (uint32_t d = 0; d < 2; d++) {
            uint64_t hits = nat64_acl_get_rule_hits(ctx, svc, dirs[d], NAT64_ACL_DEFAULT_HIT_INDEX);
            size_t len = 0;

            if (!append_format(line, sizeof(line), &len,
                               "%s    {\"service_index\":%u,\"service_name\":",
                               first ? "" : ",\n", svc) ||
                !json_escape_append(line, sizeof(line), &len, service->vs.name) ||
                !append_format(line, sizeof(line), &len,
                               ",\"direction\":\"%s\",\"rule_index\":%u,\"name\":\"__default__\","
                               "\"action\":\"%s\",\"default\":true,\"hits\":%llu}",
                               nat64_acl_direction_name(dirs[d]), NAT64_ACL_DEFAULT_HIT_INDEX,
                               service->acl_default_permit ? "permit" : "deny",
                               (unsigned long long) hits)) {
                continue;
            }
            socket_write_all(client_fd, line, len);
            first = false;
        }

        for (uint32_t i = 0; i < service->acl_rule_count && i < NAT64_MAX_ACL_RULES; i++) {
            const struct nat64_acl_rule_config *rule = &service->acl_rules[i];

            for (uint32_t d = 0; d < 2; d++) {
                uint64_t hits = nat64_acl_get_rule_hits(ctx, svc, dirs[d], i);
                size_t len = 0;

                if (!append_format(line, sizeof(line), &len,
                                   "%s    {\"service_index\":%u,\"service_name\":",
                                   first ? "" : ",\n", svc) ||
                    !json_escape_append(line, sizeof(line), &len, service->vs.name) ||
                    !append_format(line, sizeof(line), &len,
                                   ",\"direction\":\"%s\",\"rule_index\":%u,\"name\":",
                                   nat64_acl_direction_name(dirs[d]), i) ||
                    !json_escape_append(line, sizeof(line), &len, rule->name) ||
                    !append_format(line, sizeof(line), &len,
                                   ",\"configured_direction\":\"%s\",\"action\":\"%s\","
                                   "\"applicable\":%s,\"hits\":%llu}",
                                   nat64_acl_direction_name(rule->direction),
                                   nat64_acl_action_name(rule->action),
                                   acl_rule_applies_to_direction(rule->direction, dirs[d]) ? "true" : "false",
                                   (unsigned long long) hits)) {
                    continue;
                }
                socket_write_all(client_fd, line, len);
                first = false;
            }
        }
    }
    {
        static const char footer[] = "\n  ]\n}\n";
        socket_write_all(client_fd, footer, sizeof(footer) - 1);
    }
}

static bool parse_acl_dry_run_query(const char *query, struct nat64_acl_dry_run_request *req)
{
    char value[128];
    uint16_t service_index16;

    memset(req, 0, sizeof(*req));
    if (query_get_value(query, "service_index", value, sizeof(value))) {
        if (!parse_u16_text(value, &service_index16)) {
            return false;
        }
        req->service_index = service_index16;
    }
    if (!query_get_value(query, "direction", value, sizeof(value)) ||
        !parse_acl_direction_text(value, &req->direction) ||
        req->direction == NAT64_ACL_DIR_BOTH) {
        return false;
    }
    if (!query_get_value(query, "proto", value, sizeof(value)) ||
        !parse_proto_text(value, &req->proto)) {
        return false;
    }
    if (!query_get_value(query, "src", value, sizeof(value))) {
        return false;
    }
    if (req->direction == NAT64_ACL_DIR_V6_TO_V4) {
        if (inet_pton(AF_INET6, value, &req->src6) != 1) {
            return false;
        }
    } else if (inet_pton(AF_INET, value, &req->src4) != 1) {
        return false;
    }
    if (!query_get_value(query, "dst", value, sizeof(value))) {
        return false;
    }
    if (req->direction == NAT64_ACL_DIR_V6_TO_V4) {
        if (inet_pton(AF_INET6, value, &req->dst6) != 1) {
            return false;
        }
    } else if (inet_pton(AF_INET, value, &req->dst4) != 1) {
        return false;
    }
    if (query_get_value(query, "sport", value, sizeof(value)) && !parse_u16_text(value, &req->sport)) {
        return false;
    }
    if (query_get_value(query, "dport", value, sizeof(value)) && !parse_u16_text(value, &req->dport)) {
        return false;
    }
    return true;
}

static void serve_acl_dry_run(struct nat64_monitor *monitor, int client_fd, const char *query)
{
    struct nat64_acl_dry_run_request req;
    struct nat64_acl_dry_run_result result;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    char body[1024];
    int rc;
    int len;

    if (!parse_acl_dry_run_query(query, &req)) {
        send_text_response(client_fd, 400, "Bad Request",
                           "invalid query, use service_index=<n>&direction=v6_to_v4|v4_to_v6&proto=tcp|udp|icmp&src=<ip>&dst=<ip>&sport=<n>&dport=<n>\n");
        return;
    }

    rc = nat64_acl_dry_run(monitor->ctx, &req, &result);
    if (rc < 0) {
        len = snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"acl dry-run failed\",\"rc\":%d}\n", rc);
        if (!send_http_header(client_fd, 400, "Bad Request", "application/json; charset=utf-8")) {
            return;
        }
        if (len > 0 && (size_t) len < sizeof(body)) {
            socket_write_all(client_fd, body, (size_t) len);
        }
        return;
    }

    if (req.direction == NAT64_ACL_DIR_V6_TO_V4) {
        inet_ntop(AF_INET6, &req.src6, src, sizeof(src));
        inet_ntop(AF_INET6, &req.dst6, dst, sizeof(dst));
    } else {
        inet_ntop(AF_INET, &req.src4, src, sizeof(src));
        inet_ntop(AF_INET, &req.dst4, dst, sizeof(dst));
    }
    len = snprintf(body, sizeof(body),
                   "{\"ok\":true,\"generation\":%llu,\"service_index\":%u,"
                   "\"direction\":\"%s\",\"proto\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\","
                   "\"sport\":%u,\"dport\":%u,\"action\":\"%s\","
                   "\"matched_rule\":%s,\"rule_index\":%u,\"rule_name\":\"%s\"}\n",
                   (unsigned long long) result.generation,
                   req.service_index,
                   nat64_acl_direction_name(req.direction),
                   proto_name(req.proto),
                   src, dst,
                   req.sport, req.dport,
                   result.allow ? "permit" : "deny",
                   result.matched_rule ? "true" : "false",
                   result.rule_index,
                   result.matched_rule ? result.rule_name : "__default__");
    if (!send_http_header(client_fd, 200, "OK", "application/json; charset=utf-8")) {
        return;
    }
    if (len > 0 && (size_t) len < sizeof(body)) {
        socket_write_all(client_fd, body, (size_t) len);
    }
}

static void serve_index(int client_fd)
{
    static const char body[] =
        "dpdk-nat64 monitor\n"
        "GET /metrics for Prometheus metrics\n"
        "GET /connections?limit=<1..10000>&offset=<n> for NAT connection table text snapshot\n"
        "GET /connections.json?limit=<1..10000>&offset=<n>&proto=tcp|udp|icmp for paged NAT connection table JSON\n"
        "GET /subscribers.json?limit=<1..10000>&offset=<n> for subscriber prefix limit state\n"
        "GET /neighbors for IPv4 ARP and IPv6 ND neighbor table in JSON\n"
        "GET /nexthops for next-hop L2/L3 probe state\n"
        "GET /probe/trigger to force the next active gateway probe\n"
        "GET /probe/ping6?addr=<ipv6>&count=<1..64> to start an active ICMPv6 Echo probe\n"
        "GET /probe/ping6/status to inspect the active ICMPv6 Echo probe\n"
        "GET /probe/ping4?target=<ipv4>&source=<pool_ipv4>&count=<1..64> to start an active IPv4 ICMP probe\n"
        "GET /probe/tcp?target=<ipv4>&source=<pool_ipv4>&port=<1..65535>&count=<1..64> to test TCP SYN reachability\n"
        "GET /probe/http?url=http://<ipv4>[:port]/path&source=<pool_ipv4> to run a lightweight HTTP GET probe\n"
        "GET /probe/status to inspect the active IPv4 probe\n"
        "GET /acl/rules for ACL rule hit details in JSON\n"
        "GET /acl/dry-run?service_index=<n>&direction=v6_to_v4|v4_to_v6&proto=tcp|udp|icmp&src=<ip>&dst=<ip>&sport=<n>&dport=<n> to test ACL without changing counters\n"
        "GET /acl/reload to reload ACL rules from the current config file\n"
        "GET /capture/status for capture state\n"
        "GET /capture/start?side=v4|v6|all&direction=rx|tx|both&addr=<ip>&duration_sec=<sec>&file=<path>.pcap to start capture\n"
        "GET /capture/stop to stop capture\n";

    if (!send_http_header(client_fd, 200, "OK", "text/plain; charset=utf-8")) {
        return;
    }
    socket_write_all(client_fd, body, sizeof(body) - 1);
}

static void serve_not_found(int client_fd)
{
    static const char body[] = "not found\n";

    if (!send_http_header(client_fd, 404, "Not Found", "text/plain; charset=utf-8")) {
        return;
    }
    socket_write_all(client_fd, body, sizeof(body) - 1);
}

static void handle_client(struct nat64_monitor *monitor, int client_fd)
{
    char req[1024];
    char method[16];
    char path[256];
    char *query = NULL;
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);

    if (n <= 0) {
        return;
    }
    req[n] = '\0';

    if (sscanf(req, "%15s %255s", method, path) != 2) {
        serve_not_found(client_fd);
        return;
    }
    if (strcmp(method, "GET") != 0) {
        serve_not_found(client_fd);
        return;
    }

    split_query_string(path, &query);

    if (strcmp(path, "/metrics") == 0) {
        serve_metrics(monitor, client_fd);
    } else if (strcmp(path, "/connections") == 0) {
        serve_connections(monitor, client_fd, query);
    } else if (strcmp(path, "/connections.json") == 0) {
        serve_connections_json(monitor, client_fd, query);
    } else if (strcmp(path, "/subscribers.json") == 0) {
        serve_subscribers_json(monitor, client_fd, query);
    } else if (strcmp(path, "/neighbors") == 0) {
        serve_neighbors(monitor, client_fd);
    } else if (strcmp(path, "/nexthops") == 0) {
        serve_nexthops(monitor, client_fd);
    } else if (strcmp(path, "/probe/trigger") == 0) {
        serve_probe_trigger(monitor, client_fd);
    } else if (strcmp(path, "/probe/ping6") == 0) {
        serve_ping6_start(monitor, client_fd, query);
    } else if (strcmp(path, "/probe/ping6/status") == 0) {
        serve_ping6_status(monitor, client_fd);
    } else if (strcmp(path, "/probe/ping4") == 0) {
        serve_probe4_start(monitor, client_fd, query, NAT64_PROBE4_PING);
    } else if (strcmp(path, "/probe/tcp") == 0) {
        serve_probe4_start(monitor, client_fd, query, NAT64_PROBE4_TCP);
    } else if (strcmp(path, "/probe/http") == 0) {
        serve_probe4_start(monitor, client_fd, query, NAT64_PROBE4_HTTP);
    } else if (strcmp(path, "/probe/status") == 0) {
        serve_probe4_status(monitor, client_fd);
    } else if (strcmp(path, "/acl/rules") == 0) {
        serve_acl_rules(monitor, client_fd);
    } else if (strcmp(path, "/acl/dry-run") == 0) {
        serve_acl_dry_run(monitor, client_fd, query);
    } else if (strcmp(path, "/acl/reload") == 0) {
        serve_acl_reload(monitor, client_fd);
    } else if (strcmp(path, "/capture/status") == 0) {
        serve_capture_status(monitor, client_fd);
    } else if (strcmp(path, "/capture/start") == 0) {
        serve_capture_start(monitor, client_fd, query);
    } else if (strcmp(path, "/capture/stop") == 0) {
        serve_capture_stop(monitor, client_fd);
    } else if (strcmp(path, "/") == 0) {
        serve_index(client_fd);
    } else {
        serve_not_found(client_fd);
    }
}

static void *monitor_thread_main(void *arg)
{
    struct nat64_monitor *monitor = arg;

    while (!monitor->stop_requested) {
        struct pollfd pfd;
        int rc;

        nat64_capture_check_timeout(&monitor->ctx->capture, (uint64_t) time(NULL));

        pfd.fd = monitor->listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        rc = poll(&pfd, 1, 1000);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rc == 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        for (;;) {
            int client_fd = accept(monitor->listen_fd, NULL, NULL);

            if (client_fd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }

            handle_client(monitor, client_fd);
            close(client_fd);
            break;
        }
    }

    return NULL;
}

int nat64_monitor_start(struct nat64_monitor *monitor, struct nat64_ctx *ctx, const char *bind_addr, uint16_t port)
{
    struct sockaddr_in addr;
    int one = 1;

    memset(monitor, 0, sizeof(*monitor));
    monitor->ctx = ctx;
    monitor->port = port;
    monitor->listen_fd = -1;
    snprintf(monitor->bind_addr, sizeof(monitor->bind_addr), "%s", bind_addr);

    monitor->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (monitor->listen_fd < 0) {
        return -errno;
    }
    if (setsockopt(monitor->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        close(monitor->listen_fd);
        monitor->listen_fd = -1;
        return -errno;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        close(monitor->listen_fd);
        monitor->listen_fd = -1;
        return -EINVAL;
    }

    if (bind(monitor->listen_fd, (const struct sockaddr *) &addr, sizeof(addr)) != 0) {
        int rc = -errno;

        close(monitor->listen_fd);
        monitor->listen_fd = -1;
        return rc;
    }
    if (listen(monitor->listen_fd, 16) != 0) {
        int rc = -errno;

        close(monitor->listen_fd);
        monitor->listen_fd = -1;
        return rc;
    }
    {
        int thread_rc = pthread_create(&monitor->thread, NULL, monitor_thread_main, monitor);

        if (thread_rc != 0) {
            close(monitor->listen_fd);
            monitor->listen_fd = -1;
            return -thread_rc;
        }
    }

    monitor->running = true;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
            "monitor exporter listening on http://%s:%u\n", monitor->bind_addr, monitor->port);
    return 0;
}

void nat64_monitor_stop(struct nat64_monitor *monitor)
{
    if (!monitor->running) {
        return;
    }

    monitor->stop_requested = true;
    shutdown(monitor->listen_fd, SHUT_RDWR);
    close(monitor->listen_fd);
    pthread_join(monitor->thread, NULL);
    monitor->listen_fd = -1;
    monitor->running = false;
}
