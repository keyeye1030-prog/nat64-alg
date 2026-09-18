#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "capture.h"

#define NAT64_CAPTURE_SLOT_COUNT 1024
#define NAT64_CAPTURE_RING_COUNT 2048
#define NAT64_CAPTURE_SNAPLEN 2048

struct nat64_capture_slot {
    uint64_t tsc;
    uint32_t orig_len;
    uint32_t captured_len;
    uint8_t data[NAT64_CAPTURE_SNAPLEN];
};

struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

static struct rte_ring *capture_free_ring(const struct nat64_capture_state *state)
{
    return (struct rte_ring *) state->free_ring;
}

static struct rte_ring *capture_ready_ring(const struct nat64_capture_state *state)
{
    return (struct rte_ring *) state->ready_ring;
}

static bool capture_port_matches(uint64_t port_mask, uint16_t port_id)
{
    if (port_id >= 64) {
        return false;
    }
    return (port_mask & (1ULL << port_id)) != 0;
}

static bool capture_filter_matches(const struct nat64_capture_filter *filter, struct rte_mbuf *m)
{
    struct {
        struct rte_ether_hdr eth;
        union {
            struct rte_ipv4_hdr ip4;
            struct rte_ipv6_hdr ip6;
        } ip;
    } hdr_buf;
    const void *data;
    const struct rte_ether_hdr *eth;
    const struct rte_ipv4_hdr *ip4;
    const struct rte_ipv6_hdr *ip6;
    size_t needed_len;

    if (filter == NULL || !filter->enabled) {
        return true;
    }

    needed_len = sizeof(struct rte_ether_hdr) +
                 (filter->is_ipv6 ? sizeof(struct rte_ipv6_hdr) : sizeof(struct rte_ipv4_hdr));
    data = rte_pktmbuf_read(m, 0, needed_len, &hdr_buf);
    if (data == NULL) {
        return false;
    }
    eth = (const struct rte_ether_hdr *) data;

    if (!filter->is_ipv6 && rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4) {
        ip4 = (const struct rte_ipv4_hdr *) (eth + 1);
        return ip4->src_addr == filter->addr4.s_addr || ip4->dst_addr == filter->addr4.s_addr;
    }
    if (filter->is_ipv6 && rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV6) {
        ip6 = (const struct rte_ipv6_hdr *) (eth + 1);
        return memcmp(ip6->src_addr, filter->addr6.s6_addr, sizeof(filter->addr6.s6_addr)) == 0 ||
               memcmp(ip6->dst_addr, filter->addr6.s6_addr, sizeof(filter->addr6.s6_addr)) == 0;
    }

    return false;
}

static bool write_pcap_global(FILE *fp)
{
    struct pcap_global_header hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic_number = 0xa1b2c3d4U;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.snaplen = NAT64_CAPTURE_SNAPLEN;
    hdr.network = 1;
    return fwrite(&hdr, 1, sizeof(hdr), fp) == sizeof(hdr);
}

static bool write_pcap_packet(FILE *fp, const struct nat64_capture_state *state, const struct nat64_capture_slot *slot)
{
    struct pcap_packet_header hdr;
    uint64_t delta_us;
    uint64_t wall_us;

    delta_us = state->tsc_hz == 0 ? 0 : ((slot->tsc - state->base_tsc) * 1000000ULL) / state->tsc_hz;
    wall_us = state->base_unix_us + delta_us;
    hdr.ts_sec = (uint32_t) (wall_us / 1000000ULL);
    hdr.ts_usec = (uint32_t) (wall_us % 1000000ULL);
    hdr.incl_len = slot->captured_len;
    hdr.orig_len = slot->orig_len;

    return fwrite(&hdr, 1, sizeof(hdr), fp) == sizeof(hdr) &&
           fwrite(slot->data, 1, slot->captured_len, fp) == slot->captured_len;
}

static void *capture_writer_main(void *arg)
{
    struct nat64_capture_state *state = arg;
    struct rte_ring *ready = capture_ready_ring(state);
    struct rte_ring *free_ring = capture_free_ring(state);

    for (;;) {
        struct nat64_capture_slot *slot = NULL;

        if (rte_ring_dequeue(ready, (void **) &slot) == 0) {
            if (!write_pcap_packet(state->fp, state, slot)) {
                rte_spinlock_lock(&state->lock);
                state->stop_requested = true;
                state->active = false;
                rte_spinlock_unlock(&state->lock);
            }
            rte_ring_enqueue(free_ring, slot);
            continue;
        }

        rte_spinlock_lock(&state->lock);
        if (state->stop_requested) {
            rte_spinlock_unlock(&state->lock);
            break;
        }
        rte_spinlock_unlock(&state->lock);
        {
            struct timespec ts = {0, 10 * 1000 * 1000};

            nanosleep(&ts, NULL);
        }
    }

    fflush(state->fp);
    return NULL;
}

static void capture_reset_rings(struct nat64_capture_state *state)
{
    struct rte_ring *free_ring = capture_free_ring(state);
    struct rte_ring *ready = capture_ready_ring(state);

    rte_ring_reset(free_ring);
    rte_ring_reset(ready);
    for (uint32_t i = 0; i < state->slot_count; i++) {
        rte_ring_enqueue(free_ring, &state->slots[i]);
    }
}

int nat64_capture_init(struct nat64_capture_state *state, const char *name_prefix, uint64_t tsc_hz)
{
    char free_name[64];
    char ready_name[64];

    memset(state, 0, sizeof(*state));
    rte_spinlock_init(&state->lock);
    state->slot_count = NAT64_CAPTURE_SLOT_COUNT;
    state->snaplen = NAT64_CAPTURE_SNAPLEN;
    state->tsc_hz = tsc_hz;
    state->slots = rte_zmalloc("nat64_capture_slots",
                               sizeof(*state->slots) * state->slot_count,
                               RTE_CACHE_LINE_SIZE);
    if (state->slots == NULL) {
        return -ENOMEM;
    }

    snprintf(free_name, sizeof(free_name), "%s_free_%u", name_prefix, (unsigned) getpid());
    snprintf(ready_name, sizeof(ready_name), "%s_ready_%u", name_prefix, (unsigned) getpid());
    state->free_ring = rte_ring_create(free_name, NAT64_CAPTURE_RING_COUNT, rte_socket_id(), RING_F_SC_DEQ);
    state->ready_ring = rte_ring_create(ready_name, NAT64_CAPTURE_RING_COUNT, rte_socket_id(), RING_F_SC_DEQ);
    if (state->free_ring == NULL || state->ready_ring == NULL) {
        nat64_capture_cleanup(state);
        return -ENOMEM;
    }

    capture_reset_rings(state);
    return 0;
}

void nat64_capture_cleanup(struct nat64_capture_state *state)
{
    nat64_capture_stop(state);
    if (state->free_ring != NULL) {
        rte_ring_free(capture_free_ring(state));
        state->free_ring = NULL;
    }
    if (state->ready_ring != NULL) {
        rte_ring_free(capture_ready_ring(state));
        state->ready_ring = NULL;
    }
    if (state->slots != NULL) {
        rte_free(state->slots);
        state->slots = NULL;
    }
}

int nat64_capture_start(struct nat64_capture_state *state, uint64_t port_mask, uint8_t dir_mask,
                        const struct nat64_capture_filter *filter, const char *file_path, uint32_t duration_sec)
{
    struct timeval tv;

    if (dir_mask == 0 || port_mask == 0) {
        return -EINVAL;
    }

    rte_spinlock_lock(&state->lock);
    if (state->active) {
        rte_spinlock_unlock(&state->lock);
        return -EBUSY;
    }

    state->fp = fopen(file_path, "wb");
    if (state->fp == NULL) {
        int rc = -errno;

        rte_spinlock_unlock(&state->lock);
        return rc;
    }
    if (!write_pcap_global(state->fp)) {
        fclose(state->fp);
        state->fp = NULL;
        rte_spinlock_unlock(&state->lock);
        return -EIO;
    }

    capture_reset_rings(state);
    state->port_mask = port_mask;
    state->dir_mask = dir_mask;
    state->captured_packets = 0;
    state->dropped_packets = 0;
    state->stop_requested = false;
    state->active = true;
    memset(&state->filter, 0, sizeof(state->filter));
    if (filter != NULL) {
        state->filter = *filter;
    }
    snprintf(state->file_path, sizeof(state->file_path), "%s", file_path);
    gettimeofday(&tv, NULL);
    state->duration_sec = duration_sec;
    state->stop_at_unix_sec = duration_sec == 0 ? 0 : ((uint64_t) tv.tv_sec + (uint64_t) duration_sec);
    state->base_tsc = rte_rdtsc();
    state->base_unix_us = ((uint64_t) tv.tv_sec * 1000000ULL) + (uint64_t) tv.tv_usec;
    if (pthread_create(&state->thread, NULL, capture_writer_main, state) != 0) {
        fclose(state->fp);
        state->fp = NULL;
        state->active = false;
        rte_spinlock_unlock(&state->lock);
        return -EIO;
    }
    rte_spinlock_unlock(&state->lock);
    return 0;
}

void nat64_capture_stop(struct nat64_capture_state *state)
{
    bool need_join = false;
    pthread_t thread;

    rte_spinlock_lock(&state->lock);
    if (state->active || state->fp != NULL) {
        state->active = false;
        state->stop_requested = true;
        thread = state->thread;
        need_join = true;
    }
    rte_spinlock_unlock(&state->lock);

    if (need_join) {
        pthread_join(thread, NULL);
        rte_spinlock_lock(&state->lock);
        if (state->fp != NULL) {
            fclose(state->fp);
            state->fp = NULL;
        }
        memset(&state->filter, 0, sizeof(state->filter));
        state->duration_sec = 0;
        state->stop_at_unix_sec = 0;
        state->file_path[0] = '\0';
        rte_spinlock_unlock(&state->lock);
    }
}

void nat64_capture_note(struct nat64_capture_state *state, uint16_t port_id, uint8_t dir, struct rte_mbuf *m)
{
    struct nat64_capture_slot *slot;
    const void *data;
    uint32_t pkt_len;
    uint32_t captured_len;
    bool active;
    uint64_t port_mask;
    uint8_t dir_mask;
    struct nat64_capture_filter filter;

    active = __atomic_load_n(&state->active, __ATOMIC_RELAXED);
    port_mask = __atomic_load_n(&state->port_mask, __ATOMIC_RELAXED);
    dir_mask = __atomic_load_n(&state->dir_mask, __ATOMIC_RELAXED);

    if (!active || !capture_port_matches(port_mask, port_id)) {
        return;
    }
    if ((dir == NAT64_CAPTURE_DIR_RX && (dir_mask & NAT64_CAPTURE_DIR_RX) == 0) ||
        (dir == NAT64_CAPTURE_DIR_TX && (dir_mask & NAT64_CAPTURE_DIR_TX) == 0)) {
        return;
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    filter = state->filter;
    if (!capture_filter_matches(&filter, m)) {
        return;
    }

    if (rte_ring_dequeue(capture_free_ring(state), (void **) &slot) != 0) {
        __atomic_fetch_add(&state->dropped_packets, 1, __ATOMIC_RELAXED);
        return;
    }

    pkt_len = rte_pktmbuf_pkt_len(m);
    captured_len = pkt_len > state->snaplen ? state->snaplen : pkt_len;
    slot->tsc = rte_rdtsc();
    slot->orig_len = pkt_len;
    slot->captured_len = captured_len;

    data = rte_pktmbuf_read(m, 0, captured_len, slot->data);
    if (data == NULL) {
        rte_ring_enqueue(capture_free_ring(state), slot);
        __atomic_fetch_add(&state->dropped_packets, 1, __ATOMIC_RELAXED);
        return;
    }
    if (data != slot->data) {
        memcpy(slot->data, data, captured_len);
    }
    if (rte_ring_enqueue(capture_ready_ring(state), slot) != 0) {
        rte_ring_enqueue(capture_free_ring(state), slot);
        __atomic_fetch_add(&state->dropped_packets, 1, __ATOMIC_RELAXED);
        return;
    }

    __atomic_fetch_add(&state->captured_packets, 1, __ATOMIC_RELAXED);
}

void nat64_capture_get_status(struct nat64_capture_state *state, struct nat64_capture_status *out)
{
    memset(out, 0, sizeof(*out));

    rte_spinlock_lock(&state->lock);
    out->active = state->active;
    out->port_mask = state->port_mask;
    out->dir_mask = state->dir_mask;
    out->filter = state->filter;
    out->duration_sec = state->duration_sec;
    out->stop_at_unix_sec = state->stop_at_unix_sec;
    snprintf(out->file_path, sizeof(out->file_path), "%s", state->file_path);
    rte_spinlock_unlock(&state->lock);
    out->captured_packets = __atomic_load_n(&state->captured_packets, __ATOMIC_RELAXED);
    out->dropped_packets = __atomic_load_n(&state->dropped_packets, __ATOMIC_RELAXED);
}

bool nat64_capture_check_timeout(struct nat64_capture_state *state, uint64_t now_unix_sec)
{
    bool should_stop = false;

    rte_spinlock_lock(&state->lock);
    if (state->active && state->stop_at_unix_sec != 0 && now_unix_sec >= state->stop_at_unix_sec) {
        should_stop = true;
    }
    rte_spinlock_unlock(&state->lock);

    if (!should_stop) {
        return false;
    }

    nat64_capture_stop(state);
    return true;
}
