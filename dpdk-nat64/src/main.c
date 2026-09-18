#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_version.h>
#include <rte_cycles.h>

#include "config.h"
#include "acl.h"
#include "monitor.h"
#include "nat64.h"

#define MIN_NUM_MBUFS 8191
#define MBUF_SPARE_PER_PORT 4096
#define MBUF_CACHE_SIZE 256
#define MBUF_DATA_ROOM_SIZE 9216
#define DEFAULT_RX_DESC 8192
#define DEFAULT_TX_DESC 8192

static uint8_t rss_key[] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    0x89, 0x35, 0x10, 0x2f, 0x4d, 0x7e, 0x9c, 0x11,
    0x63, 0x21, 0x7f, 0x5d
};

static volatile bool force_quit;
struct worker_args {
    struct nat64_ctx *ctx;
    uint16_t queue_id;
};

static void handle_signal(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        force_quit = true;
    }
}

struct app_args {
    const char *config_path;
    struct nat64_runtime_opts opts;
    char metrics_bind[64];
    uint16_t metrics_port;
    bool metrics_enabled;
};

static unsigned int calculate_mbuf_count(uint16_t port_count, uint16_t queue_count,
                                         uint16_t rx_desc, uint16_t tx_desc)
{
    uint64_t rx_ring_mbufs = (uint64_t) port_count * queue_count * rx_desc;
    uint64_t tx_ring_budget = (uint64_t) port_count * queue_count * tx_desc;
    uint64_t cache_budget = (uint64_t) (queue_count + 1) * MBUF_CACHE_SIZE;
    uint64_t spare_budget = (uint64_t) port_count * MBUF_SPARE_PER_PORT;
    uint64_t total = rx_ring_mbufs + tx_ring_budget + cache_budget + spare_budget;

    if (total < MIN_NUM_MBUFS) {
        total = MIN_NUM_MBUFS;
    }
    if (total > UINT32_MAX) {
        total = UINT32_MAX;
    }
    return (unsigned int) total;
}

static int net_port_id(const struct nat64_config *cfg, uint32_t net_idx, uint16_t *port_id)
{
    if (net_idx >= cfg->net_count) {
        return -EINVAL;
    }
    if (cfg->nets[net_idx].has_port_id) {
        *port_id = cfg->nets[net_idx].port_id;
        return 0;
    }
    if (net_idx > UINT16_MAX) {
        return -EINVAL;
    }
    *port_id = (uint16_t) net_idx;
    return 0;
}

static int select_port_roles(const struct nat64_config *cfg, uint16_t port_count,
                             uint16_t *port_v6, uint16_t *port_v4,
                             uint32_t *net_v6_idx, uint32_t *net_v4_idx)
{
    bool have_v6 = false;
    bool have_v4 = false;

    if (cfg->net_count < 2) {
        fprintf(stderr, "need at least 2 net entries, got %u\n", cfg->net_count);
        return -EINVAL;
    }

    for (uint32_t i = 0; i < cfg->net_count; i++) {
        if (cfg->nets[i].side == NAT64_NET_SIDE_V6) {
            if (have_v6) {
                fprintf(stderr, "duplicate IPv6 net side: net[%u]\n", i);
                return -EINVAL;
            }
            *net_v6_idx = i;
            have_v6 = true;
        } else if (cfg->nets[i].side == NAT64_NET_SIDE_V4) {
            if (have_v4) {
                fprintf(stderr, "duplicate IPv4 net side: net[%u]\n", i);
                return -EINVAL;
            }
            *net_v4_idx = i;
            have_v4 = true;
        }
    }

    if (!have_v6) {
        *net_v6_idx = 0;
    }
    if (!have_v4) {
        *net_v4_idx = 1;
    }

    if (net_port_id(cfg, *net_v6_idx, port_v6) < 0 || net_port_id(cfg, *net_v4_idx, port_v4) < 0) {
        fprintf(stderr, "failed to resolve DPDK port id from net entries\n");
        return -EINVAL;
    }
    if (*port_v6 == *port_v4) {
        fprintf(stderr, "IPv6 and IPv4 sides cannot use the same DPDK port id %u\n", *port_v6);
        return -EINVAL;
    }
    if (*port_v6 >= port_count || *port_v4 >= port_count) {
        fprintf(stderr, "configured port id out of range: v6=%u v4=%u available=%u\n",
                *port_v6, *port_v4, port_count);
        return -EINVAL;
    }

    fprintf(stderr,
            "selected port roles: v6 port=%u net[%u]=%s, v4 port=%u net[%u]=%s\n",
            *port_v6, *net_v6_idx, cfg->nets[*net_v6_idx].name,
            *port_v4, *net_v4_idx, cfg->nets[*net_v4_idx].name);
    return 0;
}

static int parse_mac(const char *text, struct rte_ether_addr *mac)
{
    return rte_ether_unformat_addr(text, mac);
}

static int parse_app_args(int argc, char **argv, struct app_args *args)
{
    static const struct option long_opts[] = {
        {"config", required_argument, 0, 'c'},
        {"v4-next-hop-mac", required_argument, 0, 1},
        {"v6-next-hop-mac", required_argument, 0, 2},
        {"metrics-bind", required_argument, 0, 3},
        {"metrics-port", required_argument, 0, 4},
        {"disable-metrics", no_argument, 0, 5},
        {0, 0, 0, 0}
    };
    int opt;

    memset(args, 0, sizeof(*args));
    snprintf(args->metrics_bind, sizeof(args->metrics_bind), "%s", "0.0.0.0");
    args->metrics_port = 9104;
    args->metrics_enabled = true;

    while ((opt = getopt_long(argc, argv, "c:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            args->config_path = optarg;
            break;
        case 1:
            if (parse_mac(optarg, &args->opts.v4_next_hop) != 0) {
                return -EINVAL;
            }
            args->opts.has_v4_next_hop = true;
            break;
        case 2:
            if (parse_mac(optarg, &args->opts.v6_next_hop) != 0) {
                return -EINVAL;
            }
            args->opts.has_v6_next_hop = true;
            break;
        case 3:
            if (strlen(optarg) >= sizeof(args->metrics_bind)) {
                return -EINVAL;
            }
            snprintf(args->metrics_bind, sizeof(args->metrics_bind), "%s", optarg);
            break;
        case 4: {
            char *end = NULL;
            unsigned long port = strtoul(optarg, &end, 10);

            if (end == NULL || *end != '\0' || port == 0 || port > 65535) {
                return -EINVAL;
            }
            args->metrics_port = (uint16_t) port;
            break;
        }
        case 5:
            args->metrics_enabled = false;
            break;
        default:
            return -EINVAL;
        }
    }

    return args->config_path == NULL ? -EINVAL : 0;
}

static int configure_port(uint16_t port_id, struct rte_mempool *pool, bool checksum_offload, uint16_t queue_count,
                          uint16_t rx_desc, uint16_t tx_desc, uint64_t *enabled_tx_offloads)
{
    struct rte_eth_conf port_conf = {0};
    struct rte_eth_dev_info dev_info;
    uint16_t adjusted_rx_desc = rx_desc;
    uint16_t adjusted_tx_desc = tx_desc;
    uint64_t requested_rss;
    uint64_t requested_rx_offloads = 0;
    uint64_t requested_tx_offloads = 0;
    int rc;

    rc = rte_eth_dev_info_get(port_id, &dev_info);
    if (rc < 0) {
        return rc;
    }

    if (queue_count > dev_info.max_rx_queues || queue_count > dev_info.max_tx_queues) {
        fprintf(stderr,
                "port %u queue_count=%u exceeds device capability rx=%u tx=%u\n",
                port_id, queue_count, dev_info.max_rx_queues, dev_info.max_tx_queues);
        return -EINVAL;
    }

    requested_rss = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_TCP |
                    RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_IPV6 |
                    RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP;
    requested_rss &= dev_info.flow_type_rss_offloads;

    if (queue_count > 1 && requested_rss != 0) {
        uint32_t key_len = dev_info.hash_key_size > 0 && dev_info.hash_key_size <= sizeof(rss_key) ?
                           dev_info.hash_key_size : sizeof(rss_key);

        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_hf = requested_rss;
        port_conf.rx_adv_conf.rss_conf.rss_key = rss_key;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = key_len;
    } else {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
    }

    if (checksum_offload) {
        requested_rx_offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
        requested_tx_offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                                RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
                                RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
        port_conf.rxmode.offloads = requested_rx_offloads & dev_info.rx_offload_capa;
        port_conf.txmode.offloads = requested_tx_offloads & dev_info.tx_offload_capa;
    }
    if (enabled_tx_offloads != NULL) {
        *enabled_tx_offloads = port_conf.txmode.offloads;
    }

    fprintf(stderr,
            "configuring port %u: queues=%u rss_hf=0x%lx rx_offloads=0x%lx tx_offloads=0x%lx\n",
            port_id, queue_count,
            (unsigned long) port_conf.rx_adv_conf.rss_conf.rss_hf,
            (unsigned long) port_conf.rxmode.offloads,
            (unsigned long) port_conf.txmode.offloads);

    rc = rte_eth_dev_configure(port_id, queue_count, queue_count, &port_conf);
    if (rc < 0) {
        return rc;
    }
    rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &adjusted_rx_desc, &adjusted_tx_desc);
    if (rc < 0) {
        return rc;
    }
    if (adjusted_rx_desc != rx_desc || adjusted_tx_desc != tx_desc) {
        fprintf(stderr,
                "port %u adjusted descriptors: rx_desc %u->%u tx_desc %u->%u\n",
                port_id, rx_desc, adjusted_rx_desc, tx_desc, adjusted_tx_desc);
    }

    for (uint16_t q = 0; q < queue_count; q++) {
        rc = rte_eth_rx_queue_setup(port_id, q, adjusted_rx_desc, rte_eth_dev_socket_id(port_id), NULL, pool);
        if (rc < 0) {
            return rc;
        }
        rc = rte_eth_tx_queue_setup(port_id, q, adjusted_tx_desc, rte_eth_dev_socket_id(port_id), NULL);
        if (rc < 0) {
            return rc;
        }
    }
    rc = rte_eth_dev_start(port_id);
    if (rc < 0) {
        return rc;
    }
    if (queue_count > 1 && port_conf.rx_adv_conf.rss_conf.rss_hf != 0 && dev_info.reta_size > 0) {
        uint16_t reta_size = dev_info.reta_size;
        uint16_t reta_conf_size = RTE_ETH_RSS_RETA_SIZE_64;
        uint16_t reta_groups = (uint16_t) ((reta_size + reta_conf_size - 1) / reta_conf_size);
        struct rte_eth_rss_reta_entry64 *reta_conf = calloc(reta_groups, sizeof(*reta_conf));

        if (reta_conf == NULL) {
            return -ENOMEM;
        }
        for (uint16_t i = 0; i < reta_size; i++) {
            reta_conf[i / reta_conf_size].mask |= 1ULL << (i % reta_conf_size);
            reta_conf[i / reta_conf_size].reta[i % reta_conf_size] = i % queue_count;
        }
        rc = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);
        if (rc < 0) {
            fprintf(stderr, "port %u failed to configure RSS RETA: %d; continuing with PMD default RETA\n",
                    port_id, rc);
            free(reta_conf);
            rte_eth_promiscuous_enable(port_id);
            return 0;
        }
        free(reta_conf);
        fprintf(stderr, "configured port %u RSS RETA size=%u queues=%u\n", port_id, reta_size, queue_count);
    }
    rte_eth_promiscuous_enable(port_id);
    return 0;
}

static int worker_main(void *arg)
{
    struct worker_args *wa = arg;
    struct nat64_ctx *ctx = wa->ctx;
    uint16_t queue_id = wa->queue_id;
    struct rte_mbuf *pkts[NAT64_BURST_SIZE];
    uint32_t lcore_id = rte_lcore_id();

    if (queue_id < NAT64_MAX_WORKERS) {
        __atomic_store_n(&ctx->worker_lcore_id[queue_id], lcore_id, __ATOMIC_RELAXED);
    }

    while (!force_quit) {
        uint64_t loop_start = rte_rdtsc();
        uint64_t busy_cycles = 0;
        uint16_t nb = rte_eth_rx_burst(ctx->port_v6, queue_id, pkts, NAT64_BURST_SIZE);
        if (nb > 0) {
            uint64_t busy_start = rte_rdtsc();

            nat64_process_burst(ctx, ctx->port_v6, queue_id, pkts, nb);
            busy_cycles += rte_rdtsc() - busy_start;
        }
        nb = rte_eth_rx_burst(ctx->port_v4, queue_id, pkts, NAT64_BURST_SIZE);
        if (nb > 0) {
            uint64_t busy_start = rte_rdtsc();

            nat64_process_burst(ctx, ctx->port_v4, queue_id, pkts, nb);
            busy_cycles += rte_rdtsc() - busy_start;
        }

        uint64_t now = rte_rdtsc();

        nat64_periodic(ctx, queue_id, now);
        busy_cycles += rte_rdtsc() - now;
        nat64_note_worker_cycles(ctx, queue_id, busy_cycles, rte_rdtsc() - loop_start);
    }

    return 0;
}

static struct nat64_config cfg;
static struct nat64_ctx ctx;
static struct nat64_monitor monitor;
static struct worker_args workers[RTE_MAX_LCORE];

int main(int argc, char **argv)
{
    struct app_args app;
    char **eal_argv = NULL;
    int eal_argc = 0;
    int rc;
    struct rte_mempool *pool;
    uint16_t port_count;
    uint16_t port_v6 = 0;
    uint16_t port_v4 = 1;
    uint32_t net_v6_idx = 0;
    uint32_t net_v4_idx = 1;
    unsigned int lcore_id;
    uint16_t queue_count = 0;
    uint16_t rx_desc;
    uint16_t tx_desc;
    uint64_t port_v6_tx_offloads = 0;
    uint64_t port_v4_tx_offloads = 0;

    rc = parse_app_args(argc, argv, &app);
    if (rc < 0) {
        fprintf(stderr,
                "usage: %s --config <path> [--v4-next-hop-mac <mac>] [--v6-next-hop-mac <mac>] "
                "[--metrics-bind <ip>] [--metrics-port <port>] [--disable-metrics]\n",
                argv[0]);
        return 1;
    }

    rc = nat64_config_load(app.config_path, &cfg);
    if (rc < 0) {
        fprintf(stderr, "failed to load config: %d\n", rc);
        return 1;
    }

    rc = nat64_build_eal_args(&cfg, &eal_argv, &eal_argc);
    if (rc < 0) {
        fprintf(stderr, "failed to build EAL args: %d\n", rc);
        return 1;
    }

    rc = rte_eal_init(eal_argc, eal_argv);
    nat64_free_eal_args(eal_argv, eal_argc);
    if (rc < 0) {
        fprintf(stderr, "failed to init EAL\n");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    port_count = rte_eth_dev_count_avail();
    if (port_count < 2) {
        fprintf(stderr, "need at least 2 DPDK ports, got %u\n", port_count);
        return 1;
    }
    rc = select_port_roles(&cfg, port_count, &port_v6, &port_v4, &net_v6_idx, &net_v4_idx);
    if (rc < 0) {
        return 1;
    }

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        queue_count++;
    }
    queue_count++;

    rx_desc = cfg.sys.rx_desc > 0 ? cfg.sys.rx_desc : DEFAULT_RX_DESC;
    tx_desc = cfg.sys.tx_desc > 0 ? cfg.sys.tx_desc : DEFAULT_TX_DESC;
    unsigned int mbuf_count = calculate_mbuf_count(port_count, queue_count, rx_desc, tx_desc);

    fprintf(stderr, "creating mbuf pool: mbufs=%u data_room=%u ports=%u queues=%u rx_desc=%u tx_desc=%u\n",
            mbuf_count, MBUF_DATA_ROOM_SIZE, port_count, queue_count, rx_desc, tx_desc);
    pool = rte_pktmbuf_pool_create("mbuf_pool", mbuf_count, MBUF_CACHE_SIZE, 0,
                                   MBUF_DATA_ROOM_SIZE, rte_socket_id());
    if (pool == NULL) {
        fprintf(stderr, "failed to create mbuf pool\n");
        return 1;
    }

    rc = configure_port(port_v6, pool, cfg.sys.checksum_offload, queue_count, rx_desc, tx_desc,
                        &port_v6_tx_offloads);
    if (rc < 0) {
        fprintf(stderr, "failed to configure v6 port: %d\n", rc);
        return 1;
    }
    rc = configure_port(port_v4, pool, cfg.sys.checksum_offload, queue_count, rx_desc, tx_desc,
                        &port_v4_tx_offloads);
    if (rc < 0) {
        fprintf(stderr, "failed to configure v4 port: %d\n", rc);
        return 1;
    }

    rc = nat64_ctx_init(&ctx, &cfg, pool, port_v6, port_v4, net_v6_idx, net_v4_idx,
                        port_v6_tx_offloads, port_v4_tx_offloads, &app.opts);
    if (rc < 0) {
        fprintf(stderr, "failed to initialize NAT64 context\n");
        return 1;
    }
    snprintf(ctx.config_path, sizeof(ctx.config_path), "%s", app.config_path);
    ctx.queue_count = queue_count > NAT64_MAX_WORKERS ? NAT64_MAX_WORKERS : queue_count;
    if (queue_count > NAT64_MAX_WORKERS) {
        rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1,
                "worker stats capped at %u queues (configured queues: %u)\n",
                NAT64_MAX_WORKERS, queue_count);
    }
    memset(&monitor, 0, sizeof(monitor));
    if (app.metrics_enabled) {
        rc = nat64_monitor_start(&monitor, &ctx, app.metrics_bind, app.metrics_port);
        if (rc < 0) {
            fprintf(stderr, "failed to start monitor exporter: %d\n", rc);
            nat64_capture_cleanup(&ctx.capture);
            nat64_audit_cleanup(&ctx);
            nat64_subscriber_cleanup(&ctx);
            nat64_acl_cleanup(&ctx);
            return 1;
        }
    }

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "NAT64 started with %u service(s)\n", cfg.service_count);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "Built for DPDK runtime %s (supported series: 23.11.x)\n",
            rte_version());
    if (queue_count == 1) {
        ctx.worker_lcore_id[0] = rte_lcore_id();
        workers[rte_lcore_id()].ctx = &ctx;
        workers[rte_lcore_id()].queue_id = 0;
        worker_main(&workers[rte_lcore_id()]);
    } else {
        uint16_t q = 1;
        struct worker_args main_worker = { .ctx = &ctx, .queue_id = 0 };

        ctx.worker_lcore_id[0] = rte_lcore_id();
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
            workers[lcore_id].ctx = &ctx;
            workers[lcore_id].queue_id = q++;
            if (workers[lcore_id].queue_id < NAT64_MAX_WORKERS) {
                ctx.worker_lcore_id[workers[lcore_id].queue_id] = lcore_id;
            }
            rte_eal_remote_launch(worker_main, &workers[lcore_id], lcore_id);
        }
        worker_main(&main_worker);
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
            rte_eal_wait_lcore(lcore_id);
        }
    }

    nat64_monitor_stop(&monitor);
    nat64_capture_cleanup(&ctx.capture);
    nat64_audit_cleanup(&ctx);
    nat64_subscriber_cleanup(&ctx);
    nat64_acl_cleanup(&ctx);
    rte_eth_dev_stop(port_v6);
    rte_eth_dev_stop(port_v4);
    rte_eth_dev_close(port_v6);
    rte_eth_dev_close(port_v4);
    rte_eal_cleanup();
    return 0;
}
