#ifndef NAT64_CAPTURE_H
#define NAT64_CAPTURE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <pthread.h>

#include <rte_mbuf.h>
#include <rte_spinlock.h>

#define NAT64_CAPTURE_FILE_LEN 260
#define NAT64_CAPTURE_FILTER_LEN 64
#define NAT64_CAPTURE_DIR_RX 0x1
#define NAT64_CAPTURE_DIR_TX 0x2

struct nat64_capture_filter {
    bool enabled;
    bool is_ipv6;
    struct in_addr addr4;
    struct in6_addr addr6;
    char text[NAT64_CAPTURE_FILTER_LEN];
};

struct nat64_capture_status {
    bool active;
    uint64_t port_mask;
    uint8_t dir_mask;
    char file_path[NAT64_CAPTURE_FILE_LEN];
    struct nat64_capture_filter filter;
    uint32_t duration_sec;
    uint64_t stop_at_unix_sec;
    uint64_t captured_packets;
    uint64_t dropped_packets;
};

struct nat64_capture_slot;

struct nat64_capture_state {
    bool active;
    bool stop_requested;
    uint64_t port_mask;
    uint8_t dir_mask;
    char file_path[NAT64_CAPTURE_FILE_LEN];
    struct nat64_capture_filter filter;
    FILE *fp;
    pthread_t thread;
    void *free_ring;
    void *ready_ring;
    struct nat64_capture_slot *slots;
    uint32_t slot_count;
    uint32_t snaplen;
    uint64_t base_tsc;
    uint64_t base_unix_us;
    uint64_t tsc_hz;
    uint32_t duration_sec;
    uint64_t stop_at_unix_sec;
    uint64_t captured_packets;
    uint64_t dropped_packets;
    rte_spinlock_t lock;
};

int nat64_capture_init(struct nat64_capture_state *state, const char *name_prefix, uint64_t tsc_hz);
void nat64_capture_cleanup(struct nat64_capture_state *state);
int nat64_capture_start(struct nat64_capture_state *state, uint64_t port_mask, uint8_t dir_mask,
                        const struct nat64_capture_filter *filter, const char *file_path, uint32_t duration_sec);
void nat64_capture_stop(struct nat64_capture_state *state);
void nat64_capture_note(struct nat64_capture_state *state, uint16_t port_id, uint8_t dir, struct rte_mbuf *m);
void nat64_capture_get_status(struct nat64_capture_state *state, struct nat64_capture_status *out);
bool nat64_capture_check_timeout(struct nat64_capture_state *state, uint64_t now_unix_sec);

#endif
