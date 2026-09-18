#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "jsmn.h"
#include "route.h"

#define NAT64_ROUTE_TOKEN_CAP 2048

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
    return -EINVAL;
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

static int parse_route4_entry(const char *json, const jsmntok_t *tokens, int idx, struct nat64_route4_entry *out)
{
    int prefix_idx = object_get(json, tokens, idx, "prefix");
    int via_idx = object_get(json, tokens, idx, "via");
    int next_hop_idx = object_get(json, tokens, idx, "next_hop");
    int direct_idx = object_get(json, tokens, idx, "direct");
    char via[32];

    memset(out, 0, sizeof(*out));
    if (prefix_idx < 0 || parse_prefix4(json, tokens, prefix_idx, &out->prefix) < 0) {
        return -EINVAL;
    }
    if (via_idx < 0) {
        via_idx = next_hop_idx;
    }

    out->direct = via_idx < 0;
    if (direct_idx >= 0 && token_to_bool(json, &tokens[direct_idx], &out->direct) < 0) {
        return -EINVAL;
    }
    if (via_idx >= 0) {
        if (token_to_cstr(json, &tokens[via_idx], via, sizeof(via)) < 0) {
            return -EINVAL;
        }
        if (inet_pton(AF_INET, via, &out->via) != 1) {
            return -EINVAL;
        }
    }
    if (!out->direct && via_idx < 0) {
        return -EINVAL;
    }
    return 0;
}

static int parse_route6_entry(const char *json, const jsmntok_t *tokens, int idx, struct nat64_route6_entry *out)
{
    int prefix_idx = object_get(json, tokens, idx, "prefix");
    int via_idx = object_get(json, tokens, idx, "via");
    int next_hop_idx = object_get(json, tokens, idx, "next_hop");
    int direct_idx = object_get(json, tokens, idx, "direct");
    char via[64];

    memset(out, 0, sizeof(*out));
    if (prefix_idx < 0 || parse_prefix6(json, tokens, prefix_idx, &out->prefix) < 0) {
        return -EINVAL;
    }
    if (via_idx < 0) {
        via_idx = next_hop_idx;
    }

    out->direct = via_idx < 0;
    if (direct_idx >= 0 && token_to_bool(json, &tokens[direct_idx], &out->direct) < 0) {
        return -EINVAL;
    }
    if (via_idx >= 0) {
        if (token_to_cstr(json, &tokens[via_idx], via, sizeof(via)) < 0) {
            return -EINVAL;
        }
        if (inet_pton(AF_INET6, via, &out->via) != 1) {
            return -EINVAL;
        }
    }
    if (!out->direct && via_idx < 0) {
        return -EINVAL;
    }
    return 0;
}

int nat64_route_file_mtime(const char *path, int64_t *sec_out, int64_t *nsec_out)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return -errno;
    }

#if defined(__APPLE__)
    *sec_out = (int64_t) st.st_mtimespec.tv_sec;
    *nsec_out = (int64_t) st.st_mtimespec.tv_nsec;
#else
    *sec_out = (int64_t) st.st_mtime;
    *nsec_out = 0;
#endif
    return 0;
}

int nat64_route_table_load_file(const char *path, struct nat64_route_table *out)
{
    char *json = NULL;
    size_t len = 0;
    jsmn_parser parser;
    jsmntok_t tokens[NAT64_ROUTE_TOKEN_CAP];
    int tok_count;
    int idx;
    int rc;

    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", path);

    rc = read_file(path, &json, &len);
    if (rc < 0) {
        return rc;
    }

    jsmn_init(&parser);
    tok_count = jsmn_parse(&parser, json, len, tokens, NAT64_ROUTE_TOKEN_CAP);
    if (tok_count < 0) {
        free(json);
        return -EINVAL;
    }

    idx = object_get(json, tokens, 0, "ipv4");
    if (idx >= 0) {
        out->ipv4_count = (uint32_t) tokens[idx].size;
        if (out->ipv4_count > NAT64_MAX_ROUTES) {
            free(json);
            return -E2BIG;
        }
        for (uint32_t i = 0; i < out->ipv4_count; i++) {
            int item_idx = array_get(tokens, idx, (int) i);

            if (parse_route4_entry(json, tokens, item_idx, &out->ipv4[i]) < 0) {
                free(json);
                return -EINVAL;
            }
        }
    }

    idx = object_get(json, tokens, 0, "ipv6");
    if (idx >= 0) {
        out->ipv6_count = (uint32_t) tokens[idx].size;
        if (out->ipv6_count > NAT64_MAX_ROUTES) {
            free(json);
            return -E2BIG;
        }
        for (uint32_t i = 0; i < out->ipv6_count; i++) {
            int item_idx = array_get(tokens, idx, (int) i);

            if (parse_route6_entry(json, tokens, item_idx, &out->ipv6[i]) < 0) {
                free(json);
                return -EINVAL;
            }
        }
    }

    free(json);
    rc = nat64_route_file_mtime(path, &out->loaded_mtime_sec, &out->loaded_mtime_nsec);
    if (rc < 0) {
        return rc;
    }

    out->enabled = true;
    return 0;
}

static bool prefix4_match(struct in_addr dst, const struct nat64_prefix4 *prefix)
{
    uint32_t dst_host = ntohl(dst.s_addr);
    uint32_t prefix_host = ntohl(prefix->addr.s_addr);
    uint32_t mask;

    if (prefix->mask == 0) {
        return true;
    }
    mask = UINT32_MAX << (32 - prefix->mask);
    return (dst_host & mask) == (prefix_host & mask);
}

static bool prefix6_match(const struct in6_addr *dst, const struct nat64_prefix6 *prefix)
{
    uint8_t full_bytes = prefix->mask / 8;
    uint8_t remain_bits = prefix->mask % 8;

    if (full_bytes > 0 && memcmp(dst->s6_addr, prefix->addr.s6_addr, full_bytes) != 0) {
        return false;
    }
    if (remain_bits > 0) {
        uint8_t mask = (uint8_t) (0xffU << (8 - remain_bits));

        if ((dst->s6_addr[full_bytes] & mask) != (prefix->addr.s6_addr[full_bytes] & mask)) {
            return false;
        }
    }
    return true;
}

bool nat64_route_lookup4(const struct nat64_route_table *table, struct in_addr dst,
                         struct nat64_route4_entry *out)
{
    bool found = false;
    uint8_t best_mask = 0;

    for (uint32_t i = 0; i < table->ipv4_count; i++) {
        if (!prefix4_match(dst, &table->ipv4[i].prefix)) {
            continue;
        }
        if (!found || table->ipv4[i].prefix.mask > best_mask) {
            *out = table->ipv4[i];
            best_mask = table->ipv4[i].prefix.mask;
            found = true;
        }
    }

    return found;
}

bool nat64_route_lookup6(const struct nat64_route_table *table, const struct in6_addr *dst,
                         struct nat64_route6_entry *out)
{
    bool found = false;
    uint8_t best_mask = 0;

    for (uint32_t i = 0; i < table->ipv6_count; i++) {
        if (!prefix6_match(dst, &table->ipv6[i].prefix)) {
            continue;
        }
        if (!found || table->ipv6[i].prefix.mask > best_mask) {
            *out = table->ipv6[i];
            best_mask = table->ipv6[i].prefix.mask;
            found = true;
        }
    }

    return found;
}
