#ifndef NAT64_ROUTE_H
#define NAT64_ROUTE_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "config.h"

#define NAT64_MAX_ROUTES 256
#define NAT64_ROUTE_PATH_LEN 260

struct nat64_route4_entry {
    struct nat64_prefix4 prefix;
    bool direct;
    struct in_addr via;
};

struct nat64_route6_entry {
    struct nat64_prefix6 prefix;
    bool direct;
    struct in6_addr via;
};

struct nat64_route_table {
    bool enabled;
    char path[NAT64_ROUTE_PATH_LEN];
    struct nat64_route4_entry ipv4[NAT64_MAX_ROUTES];
    uint32_t ipv4_count;
    struct nat64_route6_entry ipv6[NAT64_MAX_ROUTES];
    uint32_t ipv6_count;
    uint64_t generation;
    int64_t loaded_mtime_sec;
    int64_t loaded_mtime_nsec;
};

int nat64_route_file_mtime(const char *path, int64_t *sec_out, int64_t *nsec_out);
int nat64_route_table_load_file(const char *path, struct nat64_route_table *out);
bool nat64_route_lookup4(const struct nat64_route_table *table, struct in_addr dst,
                         struct nat64_route4_entry *out);
bool nat64_route_lookup6(const struct nat64_route_table *table, const struct in6_addr *dst,
                         struct nat64_route6_entry *out);

#endif
