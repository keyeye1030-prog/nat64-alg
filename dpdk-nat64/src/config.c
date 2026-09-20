#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "jsmn.h"

#define TOKEN_CAP 2048

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

static int read_file(const char *path, char **buf_out, size_t *len_out)
{
    FILE *fp = fopen(path, "rb");
    char *buf;
    long size;

    if (fp == NULL) {
        return -errno;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -EIO;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -EIO;
    }
    rewind(fp);

    buf = calloc((size_t) size + 1, 1);
    if (buf == NULL) {
        fclose(fp);
        return -ENOMEM;
    }

    if (fread(buf, 1, (size_t) size, fp) != (size_t) size) {
        free(buf);
        fclose(fp);
        return -EIO;
    }

    fclose(fp);
    *buf_out = buf;
    *len_out = (size_t) size;
    return 0;
}

static int skip_token(const jsmntok_t *tokens, int idx)
{
    int end = idx + 1;

    if (tokens[idx].type == JSMN_ARRAY || tokens[idx].type == JSMN_OBJECT) {
        for (int i = 0; i < tokens[idx].size; i++) {
            end = skip_token(tokens, end);
        }
    }
    return end;
}

static bool token_equals(const char *json, const jsmntok_t *tok, const char *s)
{
    size_t len = strlen(s);
    return (tok->type == JSMN_STRING || tok->type == JSMN_PRIMITIVE) &&
           (size_t) (tok->end - tok->start) == len &&
           strncmp(json + tok->start, s, len) == 0;
}

static int object_get(const char *json, const jsmntok_t *tokens, int obj_idx, const char *key)
{
    int idx = obj_idx + 1;

    if (tokens[obj_idx].type != JSMN_OBJECT) {
        return -1;
    }

    for (int i = 0; i < tokens[obj_idx].size; i += 2) {
        int key_idx = idx;
        int val_idx = idx + 1;

        if (token_equals(json, &tokens[key_idx], key)) {
            return val_idx;
        }

        idx = skip_token(tokens, val_idx);
    }

    return -1;
}

static int array_get(const jsmntok_t *tokens, int arr_idx, int elem_index)
{
    int idx = arr_idx + 1;

    if (tokens[arr_idx].type != JSMN_ARRAY || elem_index >= tokens[arr_idx].size) {
        return -1;
    }

    for (int i = 0; i < elem_index; i++) {
        idx = skip_token(tokens, idx);
    }

    return idx;
}

static int token_to_cstr(const char *json, const jsmntok_t *tok, char *dst, size_t dst_len)
{
    size_t len = (size_t) (tok->end - tok->start);

    if (len + 1 > dst_len) {
        return -ENOSPC;
    }

    memcpy(dst, json + tok->start, len);
    dst[len] = '\0';
    return 0;
}

static int token_to_u32(const char *json, const jsmntok_t *tok, uint32_t *out)
{
    char tmp[32];
    char *endptr = NULL;
    unsigned long v;

    if (token_to_cstr(json, tok, tmp, sizeof(tmp)) < 0) {
        return -EINVAL;
    }

    v = strtoul(tmp, &endptr, 10);
    if (endptr == tmp || *endptr != '\0') {
        return -EINVAL;
    }

    *out = (uint32_t) v;
    return 0;
}

static int token_to_u64(const char *json, const jsmntok_t *tok, uint64_t *out)
{
    char tmp[32];
    char *endptr = NULL;
    unsigned long long v;

    if (token_to_cstr(json, tok, tmp, sizeof(tmp)) < 0) {
        return -EINVAL;
    }

    v = strtoull(tmp, &endptr, 10);
    if (endptr == tmp || *endptr != '\0') {
        return -EINVAL;
    }

    *out = (uint64_t) v;
    return 0;
}

static int parse_port_range_token(const char *json, const jsmntok_t *tok, uint16_t *from, uint16_t *to)
{
    char tmp[32];
    char *dash;
    char *endptr = NULL;
    unsigned long first;
    unsigned long last;

    if (token_to_cstr(json, tok, tmp, sizeof(tmp)) < 0) {
        return -EINVAL;
    }

    dash = strchr(tmp, '-');
    if (dash == NULL) {
        first = strtoul(tmp, &endptr, 10);
        if (endptr == tmp || *endptr != '\0' || first > UINT16_MAX) {
            return -EINVAL;
        }
        *from = (uint16_t) first;
        *to = (uint16_t) first;
        return 0;
    }

    *dash = '\0';
    first = strtoul(tmp, &endptr, 10);
    if (endptr == tmp || *endptr != '\0' || first > UINT16_MAX) {
        return -EINVAL;
    }

    endptr = NULL;
    last = strtoul(dash + 1, &endptr, 10);
    if (endptr == dash + 1 || *endptr != '\0' || last > UINT16_MAX || first > last) {
        return -EINVAL;
    }

    *from = (uint16_t) first;
    *to = (uint16_t) last;
    return 0;
}

static int token_to_bool(const char *json, const jsmntok_t *tok, bool *out)
{
    if (token_equals(json, tok, "true") || token_equals(json, tok, "1")) {
        *out = true;
        return 0;
    }
    if (token_equals(json, tok, "false") || token_equals(json, tok, "0")) {
        *out = false;
        return 0;
    }

    char tmp[16];
    if (token_to_cstr(json, tok, tmp, sizeof(tmp)) < 0) {
        return -EINVAL;
    }
    if (strcmp(tmp, "1") == 0) {
        *out = true;
        return 0;
    }
    if (strcmp(tmp, "0") == 0) {
        *out = false;
        return 0;
    }
    return -EINVAL;
}

static int parse_prefix6(const char *json, const jsmntok_t *tokens, int idx, struct nat64_prefix6 *out)
{
    int addr_idx = object_get(json, tokens, idx, "addr");
    int mask_idx = object_get(json, tokens, idx, "mask");
    char addr[64];
    uint32_t mask;

    if (addr_idx < 0 || mask_idx < 0) {
        return -EINVAL;
    }
    if (token_to_cstr(json, &tokens[addr_idx], addr, sizeof(addr)) < 0) {
        return -EINVAL;
    }
    if (inet_pton(AF_INET6, addr, &out->addr) != 1) {
        return -EINVAL;
    }
    if (token_to_u32(json, &tokens[mask_idx], &mask) < 0 || mask > 128) {
        return -EINVAL;
    }
    out->mask = (uint8_t) mask;
    return 0;
}

static int parse_prefix6_cidr_text(const char *text, struct nat64_prefix6 *out)
{
    char buf[96];
    char *slash;
    char *endptr = NULL;
    unsigned long mask;

    if (strlen(text) >= sizeof(buf)) {
        return -ENOSPC;
    }
    snprintf(buf, sizeof(buf), "%s", text);
    slash = strchr(buf, '/');
    if (slash == NULL) {
        return -EINVAL;
    }
    *slash = '\0';
    if (inet_pton(AF_INET6, buf, &out->addr) != 1) {
        return -EINVAL;
    }
    mask = strtoul(slash + 1, &endptr, 10);
    if (endptr == slash + 1 || *endptr != '\0' || mask > 128) {
        return -EINVAL;
    }
    out->mask = (uint8_t) mask;
    return 0;
}

static int parse_prefix6_flexible(const char *json, const jsmntok_t *tokens, int idx, struct nat64_prefix6 *out)
{
    char text[96];

    if (tokens[idx].type == JSMN_OBJECT) {
        return parse_prefix6(json, tokens, idx, out);
    }
    if (token_to_cstr(json, &tokens[idx], text, sizeof(text)) < 0) {
        return -EINVAL;
    }
    return parse_prefix6_cidr_text(text, out);
}

static int parse_prefix4(const char *json, const jsmntok_t *tokens, int idx, struct nat64_prefix4 *out)
{
    int addr_idx = object_get(json, tokens, idx, "addr");
    int mask_idx = object_get(json, tokens, idx, "mask");
    char addr[32];
    uint32_t mask;

    if (addr_idx < 0 || mask_idx < 0) {
        return -EINVAL;
    }
    if (token_to_cstr(json, &tokens[addr_idx], addr, sizeof(addr)) < 0) {
        return -EINVAL;
    }
    if (inet_pton(AF_INET, addr, &out->addr) != 1) {
        return -EINVAL;
    }
    if (token_to_u32(json, &tokens[mask_idx], &mask) < 0 || mask > 32) {
        return -EINVAL;
    }
    out->mask = (uint8_t) mask;
    return 0;
}

static int parse_acl_direction(const char *json, const jsmntok_t *tok, enum nat64_acl_direction *direction)
{
    char buf[16];

    if (token_to_cstr(json, tok, buf, sizeof(buf)) < 0) {
        return -EINVAL;
    }
    if (strcmp(buf, "v6_to_v4") == 0) {
        *direction = NAT64_ACL_DIR_V6_TO_V4;
        return 0;
    }
    if (strcmp(buf, "v4_to_v6") == 0) {
        *direction = NAT64_ACL_DIR_V4_TO_V6;
        return 0;
    }
    if (strcmp(buf, "both") == 0) {
        *direction = NAT64_ACL_DIR_BOTH;
        return 0;
    }
    return -EINVAL;
}

static int parse_acl_action(const char *json, const jsmntok_t *tok, enum nat64_acl_action *action)
{
    char buf[16];

    if (token_to_cstr(json, tok, buf, sizeof(buf)) < 0) {
        return -EINVAL;
    }
    if (strcmp(buf, "permit") == 0 || strcmp(buf, "allow") == 0) {
        *action = NAT64_ACL_ACTION_PERMIT;
        return 0;
    }
    if (strcmp(buf, "deny") == 0 || strcmp(buf, "drop") == 0) {
        *action = NAT64_ACL_ACTION_DENY;
        return 0;
    }
    return -EINVAL;
}

static int parse_acl_proto(const char *json, const jsmntok_t *tok, uint8_t *proto, bool *proto_any)
{
    char buf[16];

    if (token_to_cstr(json, tok, buf, sizeof(buf)) < 0) {
        return -EINVAL;
    }
    if (strcmp(buf, "any") == 0) {
        *proto_any = true;
        *proto = 0;
        return 0;
    }
    if (strcmp(buf, "tcp") == 0) {
        *proto_any = false;
        *proto = IPPROTO_TCP;
        return 0;
    }
    if (strcmp(buf, "udp") == 0) {
        *proto_any = false;
        *proto = IPPROTO_UDP;
        return 0;
    }
    if (strcmp(buf, "icmp") == 0) {
        *proto_any = false;
        *proto = IPPROTO_ICMP;
        return 0;
    }
    if (strcmp(buf, "icmpv6") == 0) {
        *proto_any = false;
        *proto = IPPROTO_ICMPV6;
        return 0;
    }
    return -EINVAL;
}

static int parse_net_side(const char *json, const jsmntok_t *tok, enum nat64_net_side *side)
{
    char buf[16];

    if (token_to_cstr(json, tok, buf, sizeof(buf)) < 0) {
        return -EINVAL;
    }
    if (strcmp(buf, "v6") == 0 || strcmp(buf, "ipv6") == 0) {
        *side = NAT64_NET_SIDE_V6;
        return 0;
    }
    if (strcmp(buf, "v4") == 0 || strcmp(buf, "ipv4") == 0) {
        *side = NAT64_NET_SIDE_V4;
        return 0;
    }
    return -EINVAL;
}

static int parse_acl_rule(const char *json, const jsmntok_t *tokens, int idx, struct nat64_acl_rule_config *rule)
{
    int tok_idx;

    memset(rule, 0, sizeof(*rule));
    rule->direction = NAT64_ACL_DIR_BOTH;
    rule->action = NAT64_ACL_ACTION_PERMIT;
    rule->proto_any = true;
    rule->sport_from = 0;
    rule->sport_to = UINT16_MAX;
    rule->dport_from = 0;
    rule->dport_to = UINT16_MAX;

    tok_idx = object_get(json, tokens, idx, "name");
    if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], rule->name, sizeof(rule->name)) < 0) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "direction");
    if (tok_idx >= 0 && parse_acl_direction(json, &tokens[tok_idx], &rule->direction) < 0) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "action");
    if (tok_idx >= 0 && parse_acl_action(json, &tokens[tok_idx], &rule->action) < 0) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "proto");
    if (tok_idx >= 0 && parse_acl_proto(json, &tokens[tok_idx], &rule->proto, &rule->proto_any) < 0) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "src4");
    if (tok_idx >= 0) {
        if (parse_prefix4(json, tokens, tok_idx, &rule->src4) < 0) {
            return -EINVAL;
        }
        rule->has_src4 = true;
    }

    tok_idx = object_get(json, tokens, idx, "dst4");
    if (tok_idx >= 0) {
        if (parse_prefix4(json, tokens, tok_idx, &rule->dst4) < 0) {
            return -EINVAL;
        }
        rule->has_dst4 = true;
    }

    tok_idx = object_get(json, tokens, idx, "src6");
    if (tok_idx >= 0) {
        if (parse_prefix6(json, tokens, tok_idx, &rule->src6) < 0) {
            return -EINVAL;
        }
        rule->has_src6 = true;
    }

    tok_idx = object_get(json, tokens, idx, "dst6");
    if (tok_idx >= 0) {
        if (parse_prefix6(json, tokens, tok_idx, &rule->dst6) < 0) {
            return -EINVAL;
        }
        rule->has_dst6 = true;
    }

    tok_idx = object_get(json, tokens, idx, "sport_from");
    if (tok_idx >= 0) {
        uint32_t port;

        if (token_to_u32(json, &tokens[tok_idx], &port) < 0 || port > UINT16_MAX) {
            return -EINVAL;
        }
        rule->sport_from = (uint16_t) port;
    }

    tok_idx = object_get(json, tokens, idx, "sport_to");
    if (tok_idx >= 0) {
        uint32_t port;

        if (token_to_u32(json, &tokens[tok_idx], &port) < 0 || port > UINT16_MAX) {
            return -EINVAL;
        }
        rule->sport_to = (uint16_t) port;
    }

    tok_idx = object_get(json, tokens, idx, "dport_from");
    if (tok_idx >= 0) {
        uint32_t port;

        if (token_to_u32(json, &tokens[tok_idx], &port) < 0 || port > UINT16_MAX) {
            return -EINVAL;
        }
        rule->dport_from = (uint16_t) port;
    }

    tok_idx = object_get(json, tokens, idx, "dport_to");
    if (tok_idx >= 0) {
        uint32_t port;

        if (token_to_u32(json, &tokens[tok_idx], &port) < 0 || port > UINT16_MAX) {
            return -EINVAL;
        }
        rule->dport_to = (uint16_t) port;
    }

    if (rule->sport_from > rule->sport_to || rule->dport_from > rule->dport_to) {
        return -EINVAL;
    }
    return 0;
}

static int parse_static_bib(const char *json, const jsmntok_t *tokens, int idx,
                            struct nat64_static_bib_config *bib)
{
    int tok_idx;
    char addr[INET6_ADDRSTRLEN];
    bool proto_any = false;

    memset(bib, 0, sizeof(*bib));

    tok_idx = object_get(json, tokens, idx, "name");
    if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], bib->name, sizeof(bib->name)) < 0) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "proto");
    if (tok_idx < 0 || parse_acl_proto(json, &tokens[tok_idx], &bib->proto, &proto_any) < 0 || proto_any ||
        bib->proto == IPPROTO_ICMPV6) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "local_v4");
    if (tok_idx < 0 || token_to_cstr(json, &tokens[tok_idx], addr, sizeof(addr)) < 0 ||
        inet_pton(AF_INET, addr, &bib->local_v4) != 1) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "client_v6");
    if (tok_idx < 0 || token_to_cstr(json, &tokens[tok_idx], addr, sizeof(addr)) < 0 ||
        inet_pton(AF_INET6, addr, &bib->client_v6) != 1) {
        return -EINVAL;
    }

    tok_idx = object_get(json, tokens, idx, "map_port");
    if (tok_idx >= 0) {
        return parse_port_range_token(json, &tokens[tok_idx], &bib->map_port_from, &bib->map_port_to);
    }

    /*
     * Compatibility path for early static_bib configs. New configs should use
     * map_port because static BIB always keeps IPv6 and IPv4 ports identical.
     */
    int local_port_idx = object_get(json, tokens, idx, "local_port");
    int client_port_idx = object_get(json, tokens, idx, "client_port");
    uint16_t local_port;
    uint16_t local_port_to;
    uint16_t client_port;
    uint16_t client_port_to;

    if (local_port_idx < 0 || client_port_idx < 0 ||
        parse_port_range_token(json, &tokens[local_port_idx], &local_port, &local_port_to) < 0 ||
        parse_port_range_token(json, &tokens[client_port_idx], &client_port, &client_port_to) < 0 ||
        local_port != local_port_to || client_port != client_port_to || local_port != client_port) {
        return -EINVAL;
    }
    bib->map_port_from = local_port;
    bib->map_port_to = local_port;
    return 0;
}

static int parse_subscriber_limit_values(const char *json, const jsmntok_t *tokens, int idx,
                                         struct nat64_subscriber_limit_rule_config *limit)
{
    int tok_idx;

    tok_idx = object_get(json, tokens, idx, "name");
    if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], limit->name, sizeof(limit->name)) < 0) {
        return -EINVAL;
    }
    tok_idx = object_get(json, tokens, idx, "prefix");
    if (tok_idx >= 0 && parse_prefix6_flexible(json, tokens, tok_idx, &limit->prefix) < 0) {
        return -EINVAL;
    }
    tok_idx = object_get(json, tokens, idx, "max_sessions");
    if (tok_idx >= 0 && token_to_u32(json, &tokens[tok_idx], &limit->max_sessions) < 0) {
        return -EINVAL;
    }
    tok_idx = object_get(json, tokens, idx, "new_conn_per_sec");
    if (tok_idx >= 0 && token_to_u32(json, &tokens[tok_idx], &limit->new_conn_per_sec) < 0) {
        return -EINVAL;
    }
    tok_idx = object_get(json, tokens, idx, "burst");
    if (tok_idx >= 0 && token_to_u32(json, &tokens[tok_idx], &limit->burst) < 0) {
        return -EINVAL;
    }
    if (limit->burst == 0 && limit->new_conn_per_sec > 0) {
        limit->burst = limit->new_conn_per_sec;
    }
    return 0;
}

static int parse_subscriber_limits(const char *json, const jsmntok_t *tokens, int idx,
                                   struct nat64_subscriber_limits_config *limits)
{
    int tok_idx;

    memset(limits, 0, sizeof(*limits));
    limits->prefix_len = 64;
    limits->max_entries = 65536;
    limits->default_limit.prefix.mask = 0;

    tok_idx = object_get(json, tokens, idx, "enabled");
    if (tok_idx >= 0 && token_to_bool(json, &tokens[tok_idx], &limits->enabled) < 0) {
        return -EINVAL;
    }
    tok_idx = object_get(json, tokens, idx, "prefix_len");
    if (tok_idx >= 0) {
        uint32_t prefix_len;

        if (token_to_u32(json, &tokens[tok_idx], &prefix_len) < 0 || prefix_len > 128) {
            return -EINVAL;
        }
        limits->prefix_len = (uint8_t) prefix_len;
    }
    tok_idx = object_get(json, tokens, idx, "max_entries");
    if (tok_idx >= 0 && (token_to_u32(json, &tokens[tok_idx], &limits->max_entries) < 0 ||
                         limits->max_entries == 0)) {
        return -EINVAL;
    }
    tok_idx = object_get(json, tokens, idx, "default");
    if (tok_idx >= 0 && parse_subscriber_limit_values(json, tokens, tok_idx, &limits->default_limit) < 0) {
        return -EINVAL;
    }
    limits->default_limit.prefix.mask = 0;
    if (limits->default_limit.name[0] == '\0') {
        snprintf(limits->default_limit.name, sizeof(limits->default_limit.name), "%s", "default");
    }

    tok_idx = object_get(json, tokens, idx, "rules");
    if (tok_idx >= 0) {
        if (tokens[tok_idx].type != JSMN_ARRAY) {
            return -EINVAL;
        }
        limits->rule_count = (uint32_t) tokens[tok_idx].size;
        if (limits->rule_count > NAT64_MAX_SUBSCRIBER_RULES) {
            return -EINVAL;
        }
        for (uint32_t i = 0; i < limits->rule_count; i++) {
            int item_idx = array_get(tokens, tok_idx, (int) i);

            if (item_idx < 0 || parse_subscriber_limit_values(json, tokens, item_idx, &limits->rules[i]) < 0 ||
                limits->rules[i].prefix.mask == 0) {
                return -EINVAL;
            }
            if (limits->rules[i].name[0] == '\0') {
                snprintf(limits->rules[i].name, sizeof(limits->rules[i].name), "rule%u", i);
            }
        }
    }
    return 0;
}

static int parse_sys(const char *json, const jsmntok_t *tokens, int idx, struct nat64_sys_config *sys)
{
    int checksum_idx = object_get(json, tokens, idx, "checksum_offload");
    int cpus_idx = object_get(json, tokens, idx, "cpus");
    int mem_idx = object_get(json, tokens, idx, "mem");
    int loglevel_idx = object_get(json, tokens, idx, "loglevel");
    int rx_desc_idx = object_get(json, tokens, idx, "rx_desc");
    int tx_desc_idx = object_get(json, tokens, idx, "tx_desc");
    int frag_entries_idx = object_get(json, tokens, idx, "frag_entries");
    int pcibus_idx = object_get(json, tokens, idx, "pcibus");

    if (checksum_idx >= 0 && token_to_bool(json, &tokens[checksum_idx], &sys->checksum_offload) < 0) {
        return -EINVAL;
    }
    if (mem_idx >= 0 && token_to_u32(json, &tokens[mem_idx], &sys->mem_mb) < 0) {
        return -EINVAL;
    }
    if (loglevel_idx >= 0 && token_to_u32(json, &tokens[loglevel_idx], &sys->loglevel) < 0) {
        return -EINVAL;
    }
    if (rx_desc_idx >= 0) {
        uint32_t desc;

        if (token_to_u32(json, &tokens[rx_desc_idx], &desc) < 0 || desc == 0 || desc > UINT16_MAX) {
            return -EINVAL;
        }
        sys->rx_desc = (uint16_t) desc;
    }
    if (tx_desc_idx >= 0) {
        uint32_t desc;

        if (token_to_u32(json, &tokens[tx_desc_idx], &desc) < 0 || desc == 0 || desc > UINT16_MAX) {
            return -EINVAL;
        }
        sys->tx_desc = (uint16_t) desc;
    }
    if (frag_entries_idx >= 0 &&
        (token_to_u32(json, &tokens[frag_entries_idx], &sys->frag_entries) < 0 || sys->frag_entries == 0)) {
        return -EINVAL;
    }

    if (cpus_idx >= 0) {
        sys->cpu_count = (uint32_t) tokens[cpus_idx].size;
        if (sys->cpu_count > NAT64_MAX_CPUS) {
            return -E2BIG;
        }
        for (uint32_t i = 0; i < sys->cpu_count; i++) {
            int tok_idx = array_get(tokens, cpus_idx, (int) i);
            if (token_to_u32(json, &tokens[tok_idx], &sys->cpus[i]) < 0) {
                return -EINVAL;
            }
        }
    }

    if (pcibus_idx >= 0) {
        sys->pcibus_count = (uint32_t) tokens[pcibus_idx].size;
        if (sys->pcibus_count > NAT64_MAX_PCIDEVS) {
            return -E2BIG;
        }
        for (uint32_t i = 0; i < sys->pcibus_count; i++) {
            int tok_idx = array_get(tokens, pcibus_idx, (int) i);
            if (token_to_cstr(json, &tokens[tok_idx], sys->pcibus[i], sizeof(sys->pcibus[i])) < 0) {
                return -EINVAL;
            }
        }
    }

    return 0;
}

static int parse_audit(const char *json, const jsmntok_t *tokens, int idx, struct nat64_audit_config *audit)
{
    int enabled_idx = object_get(json, tokens, idx, "enabled");
    int file_idx = object_get(json, tokens, idx, "file");
    int rotate_idx = object_get(json, tokens, idx, "rotate_bytes");

    if (enabled_idx >= 0 && token_to_bool(json, &tokens[enabled_idx], &audit->enabled) < 0) {
        return -EINVAL;
    }
    if (file_idx >= 0 && token_to_cstr(json, &tokens[file_idx], audit->file, sizeof(audit->file)) < 0) {
        return -EINVAL;
    }
    if (rotate_idx >= 0 && token_to_u64(json, &tokens[rotate_idx], &audit->rotate_bytes) < 0) {
        return -EINVAL;
    }
    if (audit->enabled && audit->file[0] == '\0') {
        return -EINVAL;
    }
    return 0;
}

static int parse_nets(const char *json, const jsmntok_t *tokens, int idx, struct nat64_config *cfg)
{
    cfg->net_count = (uint32_t) tokens[idx].size;
    if (cfg->net_count > NAT64_MAX_NETS) {
        return -E2BIG;
    }

    for (uint32_t i = 0; i < cfg->net_count; i++) {
        int net_idx = array_get(tokens, idx, (int) i);
        int name_idx = object_get(json, tokens, net_idx, "name");
        int ip_idx = object_get(json, tokens, net_idx, "ip");
        int port_idx = object_get(json, tokens, net_idx, "port");
        int side_idx = object_get(json, tokens, net_idx, "side");
        struct nat64_netif_config *net = &cfg->nets[i];

        if (name_idx < 0 || ip_idx < 0) {
            return -EINVAL;
        }
        if (port_idx < 0) {
            port_idx = object_get(json, tokens, net_idx, "port_id");
        }
        if (side_idx < 0) {
            side_idx = object_get(json, tokens, net_idx, "family");
        }
        if (token_to_cstr(json, &tokens[name_idx], net->name, sizeof(net->name)) < 0) {
            return -EINVAL;
        }
        if (port_idx >= 0) {
            uint32_t port_id;

            if (token_to_u32(json, &tokens[port_idx], &port_id) < 0 || port_id > UINT16_MAX) {
                return -EINVAL;
            }
            net->has_port_id = true;
            net->port_id = (uint16_t) port_id;
        }
        if (side_idx >= 0 && parse_net_side(json, &tokens[side_idx], &net->side) < 0) {
            return -EINVAL;
        }
        net->ip_count = (uint32_t) tokens[ip_idx].size;
        if (net->ip_count > NAT64_MAX_IPS_PER_NET) {
            return -E2BIG;
        }
        for (uint32_t j = 0; j < net->ip_count; j++) {
            int ip_tok = array_get(tokens, ip_idx, (int) j);
            if (token_to_cstr(json, &tokens[ip_tok], net->ip_raw[j], sizeof(net->ip_raw[j])) < 0) {
                return -EINVAL;
            }
        }
    }

    return 0;
}

static int parse_services(const char *json, const jsmntok_t *tokens, int idx, struct nat64_config *cfg)
{
    cfg->service_count = (uint32_t) tokens[idx].size;
    if (cfg->service_count > NAT64_MAX_SERVICES) {
        return -E2BIG;
    }

    for (uint32_t i = 0; i < cfg->service_count; i++) {
        int svc_idx = array_get(tokens, idx, (int) i);
        int vs_idx = object_get(json, tokens, svc_idx, "vs");
        int rs_idx = object_get(json, tokens, svc_idx, "rs");
        int laddr_idx = object_get(json, tokens, svc_idx, "laddr");
        int dst_mode_idx = object_get(json, tokens, svc_idx, "dst_mode");
        int acl_default_idx = object_get(json, tokens, svc_idx, "acl_default");
        int acl_idx = object_get(json, tokens, svc_idx, "acl");
        int static_bib_idx = object_get(json, tokens, svc_idx, "static_bib");
        struct nat64_service_config *svc = &cfg->services[i];
        int tok_idx;

        if (vs_idx < 0 || rs_idx < 0 || laddr_idx < 0) {
            return -EINVAL;
        }
        svc->acl_default_permit = true;
        svc->dst_mode = NAT64_DST_RS_POOL;
        if (static_bib_idx < 0) {
            static_bib_idx = object_get(json, tokens, svc_idx, "static_bibs");
        }
        if (dst_mode_idx >= 0) {
            char mode[32];

            if (token_to_cstr(json, &tokens[dst_mode_idx], mode, sizeof(mode)) < 0) {
                return -EINVAL;
            }
            if (strcmp(mode, "rs_pool") == 0 || strcmp(mode, "pool") == 0) {
                svc->dst_mode = NAT64_DST_RS_POOL;
            } else if (strcmp(mode, "embed_v4") == 0 || strcmp(mode, "prefix96_embed") == 0) {
                svc->dst_mode = NAT64_DST_EMBED_V4;
            } else {
                return -EINVAL;
            }
        }

        if (acl_default_idx >= 0) {
            char action[16];

            if (token_to_cstr(json, &tokens[acl_default_idx], action, sizeof(action)) < 0) {
                return -EINVAL;
            }
            if (strcmp(action, "permit") == 0 || strcmp(action, "allow") == 0) {
                svc->acl_default_permit = true;
            } else if (strcmp(action, "deny") == 0 || strcmp(action, "drop") == 0) {
                svc->acl_default_permit = false;
            } else {
                return -EINVAL;
            }
        }

        tok_idx = object_get(json, tokens, vs_idx, "name");
        if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], svc->vs.name, sizeof(svc->vs.name)) < 0) {
            return -EINVAL;
        }
        tok_idx = object_get(json, tokens, vs_idx, "proto");
        if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], svc->vs.proto, sizeof(svc->vs.proto)) < 0) {
            return -EINVAL;
        }
        tok_idx = object_get(json, tokens, vs_idx, "mode");
        if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], svc->vs.mode, sizeof(svc->vs.mode)) < 0) {
            return -EINVAL;
        }
        tok_idx = object_get(json, tokens, vs_idx, "sched");
        if (tok_idx >= 0 && token_to_cstr(json, &tokens[tok_idx], svc->vs.sched, sizeof(svc->vs.sched)) < 0) {
            return -EINVAL;
        }

        tok_idx = object_get(json, tokens, vs_idx, "vaddr");
        if (tok_idx >= 0) {
            svc->vs.vaddr_count = (uint32_t) tokens[tok_idx].size;
            if (svc->vs.vaddr_count > NAT64_MAX_VADDRS) {
                return -E2BIG;
            }
            for (uint32_t j = 0; j < svc->vs.vaddr_count; j++) {
                int item_idx = array_get(tokens, tok_idx, (int) j);
                if (parse_prefix6(json, tokens, item_idx, &svc->vs.vaddr[j]) < 0) {
                    return -EINVAL;
                }
            }
        }

        tok_idx = object_get(json, tokens, vs_idx, "saddr");
        if (tok_idx >= 0) {
            svc->vs.saddr_count = (uint32_t) tokens[tok_idx].size;
            if (svc->vs.saddr_count > NAT64_MAX_SADDRS) {
                return -E2BIG;
            }
            for (uint32_t j = 0; j < svc->vs.saddr_count; j++) {
                int item_idx = array_get(tokens, tok_idx, (int) j);
                if (parse_prefix6(json, tokens, item_idx, &svc->vs.saddr[j]) < 0) {
                    return -EINVAL;
                }
            }
        }

        svc->rs_count = (uint32_t) tokens[rs_idx].size;
        if (svc->rs_count > NAT64_MAX_RS) {
            return -E2BIG;
        }
        for (uint32_t j = 0; j < svc->rs_count; j++) {
            int item_idx = array_get(tokens, rs_idx, (int) j);
            if (parse_prefix4(json, tokens, item_idx, &svc->rs[j].prefix) < 0) {
                return -EINVAL;
            }
        }
        if (svc->dst_mode == NAT64_DST_RS_POOL && svc->rs_count == 0) {
            return -EINVAL;
        }

        svc->laddr_count = (uint32_t) tokens[laddr_idx].size;
        if (svc->laddr_count > NAT64_MAX_LADDRS) {
            return -E2BIG;
        }
        for (uint32_t j = 0; j < svc->laddr_count; j++) {
            int item_idx = array_get(tokens, laddr_idx, (int) j);
            int dev_idx;

            if (parse_prefix4(json, tokens, item_idx, &svc->laddr[j].prefix) < 0) {
                return -EINVAL;
            }
            dev_idx = object_get(json, tokens, item_idx, "dev");
            if (dev_idx >= 0 &&
                token_to_cstr(json, &tokens[dev_idx], svc->laddr[j].dev, sizeof(svc->laddr[j].dev)) < 0) {
                return -EINVAL;
            }
        }

        if (acl_idx >= 0) {
            svc->acl_rule_count = (uint32_t) tokens[acl_idx].size;
            if (svc->acl_rule_count > NAT64_MAX_ACL_RULES) {
                return -E2BIG;
            }
            for (uint32_t j = 0; j < svc->acl_rule_count; j++) {
                int item_idx = array_get(tokens, acl_idx, (int) j);

                if (parse_acl_rule(json, tokens, item_idx, &svc->acl_rules[j]) < 0) {
                    return -EINVAL;
                }
            }
        }

        if (static_bib_idx >= 0) {
            svc->static_bib_count = (uint32_t) tokens[static_bib_idx].size;
            if (svc->static_bib_count > NAT64_MAX_STATIC_BIBS) {
                return -E2BIG;
            }
            for (uint32_t j = 0; j < svc->static_bib_count; j++) {
                int item_idx = array_get(tokens, static_bib_idx, (int) j);

                if (parse_static_bib(json, tokens, item_idx, &svc->static_bibs[j]) < 0) {
                    return -EINVAL;
                }
            }
        }
    }

    return 0;
}

int nat64_config_load(const char *path, struct nat64_config *cfg)
{
    char *json = NULL;
    size_t len = 0;
    jsmn_parser parser;
    jsmntok_t tokens[TOKEN_CAP];
    int tok_count;
    int rc;
    int idx;

    memset(cfg, 0, sizeof(*cfg));

    rc = read_file(path, &json, &len);
    if (rc < 0) {
        return rc;
    }

    jsmn_init(&parser);
    tok_count = jsmn_parse(&parser, json, len, tokens, TOKEN_CAP);
    if (tok_count < 0) {
        free(json);
        return -EINVAL;
    }

    idx = object_get(json, tokens, 0, "sys");
    if (idx >= 0 && parse_sys(json, tokens, idx, &cfg->sys) < 0) {
        free(json);
        return -EINVAL;
    }
    idx = object_get(json, tokens, 0, "net");
    if (idx >= 0 && parse_nets(json, tokens, idx, cfg) < 0) {
        free(json);
        return -EINVAL;
    }
    idx = object_get(json, tokens, 0, "route_file");
    if (idx >= 0 && token_to_cstr(json, &tokens[idx], cfg->route_file, sizeof(cfg->route_file)) < 0) {
        free(json);
        return -EINVAL;
    }
    idx = object_get(json, tokens, 0, "audit");
    if (idx >= 0 && parse_audit(json, tokens, idx, &cfg->audit) < 0) {
        free(json);
        return -EINVAL;
    }
    idx = object_get(json, tokens, 0, "subscriber_limits");
    if (idx >= 0 && parse_subscriber_limits(json, tokens, idx, &cfg->subscriber_limits) < 0) {
        free(json);
        return -EINVAL;
    }
    idx = object_get(json, tokens, 0, "ipvs");
    if (idx >= 0 && parse_services(json, tokens, idx, cfg) < 0) {
        free(json);
        return -EINVAL;
    }

    free(json);
    return 0;
}

static char *xstrdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *p = malloc(len);

    if (p != NULL) {
        memcpy(p, s, len);
    }
    return p;
}

int nat64_build_eal_args(const struct nat64_config *cfg, char ***argv_out, int *argc_out)
{
    char **argv = calloc(32 + (size_t) cfg->sys.pcibus_count * 2, sizeof(char *));
    char buf[256];
    int argc = 0;

    if (argv == NULL) {
        return -ENOMEM;
    }

    argv[argc++] = xstrdup("dpdk-nat64");

    if (cfg->sys.cpu_count > 0) {
        size_t pos = 0;

        for (uint32_t i = 0; i < cfg->sys.cpu_count; i++) {
            int n = snprintf(buf + pos, sizeof(buf) - pos, "%s%u", i == 0 ? "" : ",", cfg->sys.cpus[i]);
            if (n < 0 || (size_t) n >= sizeof(buf) - pos) {
                nat64_free_eal_args(argv, argc);
                return -ENOSPC;
            }
            pos += (size_t) n;
        }
        argv[argc++] = xstrdup("-l");
        argv[argc++] = xstrdup(buf);
    }

    if (cfg->sys.mem_mb > 0) {
        uint32_t mem_mb = cfg->sys.mem_mb;
        FILE *hp_f = fopen("/sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages", "r");
        if (hp_f == NULL) {
            hp_f = fopen("/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages", "r");
        }
        if (hp_f != NULL) {
            unsigned int nr = 0;
            if (fscanf(hp_f, "%u", &nr) == 1 && nr > 0) {
                uint32_t max_hp_mb = (uint32_t) nr * 1024;
                if (mem_mb > max_hp_mb) {
                    fprintf(stderr,
                            "warning: configured mem %u MB exceeds available 1GB hugepages (%u MB), capping to %u MB\n",
                            mem_mb, max_hp_mb, max_hp_mb);
                    mem_mb = max_hp_mb;
                }
            }
            fclose(hp_f);
        }
        snprintf(buf, sizeof(buf), "%u", mem_mb);
        argv[argc++] = xstrdup("--socket-mem");
        argv[argc++] = xstrdup(buf);
    }

    snprintf(buf, sizeof(buf), "%u", cfg->sys.loglevel);
    argv[argc++] = xstrdup("--log-level");
    argv[argc++] = xstrdup(buf);

    for (uint32_t i = 0; i < cfg->sys.pcibus_count; i++) {
        argv[argc++] = xstrdup("-a");
        argv[argc++] = xstrdup(cfg->sys.pcibus[i]);
    }

    *argv_out = argv;
    *argc_out = argc;
    return 0;
}

void nat64_free_eal_args(char **argv, int argc)
{
    if (argv == NULL) {
        return;
    }

    for (int i = 0; i < argc; i++) {
        bool seen = false;

        for (int j = 0; j < i; j++) {
            if (argv[j] == argv[i]) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            free(argv[i]);
        }
    }
    free(argv);
}
