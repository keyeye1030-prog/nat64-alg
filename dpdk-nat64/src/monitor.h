#ifndef NAT64_MONITOR_H
#define NAT64_MONITOR_H

#include <stdbool.h>
#include <stdint.h>

#include <pthread.h>

#include "nat64.h"

struct nat64_monitor {
    struct nat64_ctx *ctx;
    char bind_addr[64];
    uint16_t port;
    int listen_fd;
    bool running;
    bool stop_requested;
    pthread_t thread;
};

int nat64_monitor_start(struct nat64_monitor *monitor, struct nat64_ctx *ctx, const char *bind_addr, uint16_t port);
void nat64_monitor_stop(struct nat64_monitor *monitor);

#endif
