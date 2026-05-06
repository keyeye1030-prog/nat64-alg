#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/*
 * NAT64 XDP Kernel Program
 * 
 * 职责:
 * 1. 识别 IPv6 流量中匹配 NAT64 前缀 (64:ff9b::/96) 的包
 * 2. 识别回程的 IPv4 流量 (目的 IP 在 pool_ips map 中)
 * 3. 将这些包重定向到 AF_XDP 用户态套接字 (XDP_REDIRECT)
 * 4. 普通流量直接放行 (XDP_PASS)
 *
 * 更新:
 * - 添加 pool_ips BPF_MAP_TYPE_HASH 用于精确过滤 IPv4 回程流量
 *   用户态程序在启动时将所有 pool IPv4 地址和静态映射地址写入此 map
 * - 不再将所有 IPv4 包无差别重定向到用户态
 */

/* AF_XDP Socket Map: 将队列 ID 映射到 AF_XDP socket fd */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map SEC(".maps");

/*
 * Pool IPv4 Address Map: 存储所有 NAT64 出口地址 (动态池 + 静态映射)
 * Key = IPv4 地址 (网络字节序 __u32)
 * Value = 1 (仅标记存在)
 *
 * 用户态在启动时写入:
 *   - 所有 pool_ipv4s 地址
 *   - 所有 static_mappings 中的 IPv4 地址
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} pool_ips SEC(".maps");

/* 统计计数器 Map (可选, 用于调试) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

enum stat_key {
	STAT_IPV6_REDIRECTED = 0,
	STAT_IPV4_REDIRECTED = 1,
	STAT_IPV4_PASSED     = 2,
	STAT_OTHER_PASSED    = 3,
};

static __always_inline void inc_stat(__u32 key) {
	__u64 *val = bpf_map_lookup_elem(&stats, &key);
	if (val)
		(*val)++;
}

SEC("xdp_nat64")
int xdp_nat64_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__u16 h_proto = eth->h_proto;

	/* 处理 IPv6 -> IPv4 (寻找 NAT64 前缀 64:ff9b::/96) */
	if (h_proto == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (data + sizeof(struct ethhdr));
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;

		/*
		 * 检查目的地址前缀: 64:ff9b::/96
		 * IPv6 地址前 12 字节 (96 bits):
		 *   s6_addr32[0] = 0x0064ff9b (网络字节序: 0x9bff6400)
		 *   s6_addr32[1] = 0x00000000
		 *   s6_addr32[2] = 0x00000000
		 * 最后 4 字节 (s6_addr32[3]) = 嵌入的 IPv4 地址
		 */
		if (ip6->daddr.s6_addr32[0] == __constant_htonl(0x0064ff9b) &&
		    ip6->daddr.s6_addr32[1] == 0 &&
		    ip6->daddr.s6_addr32[2] == 0) {
			inc_stat(STAT_IPV6_REDIRECTED);
			return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
		}
	}

	/* 处理 IPv4 -> IPv6 (仅重定向目的 IP 在 pool 中的回程包) */
	if (h_proto == __constant_htons(ETH_P_IP)) {
		struct iphdr *ip4 = (data + sizeof(struct ethhdr));
		if ((void *)(ip4 + 1) > data_end)
			return XDP_PASS;

		/* 在 pool_ips map 中查找目的 IPv4 地址 */
		__u32 daddr = ip4->daddr;
		__u32 *found = bpf_map_lookup_elem(&pool_ips, &daddr);
		if (found) {
			/* 匹配: 这是发往我们 NAT64 池的回程包, 重定向到用户态 */
			inc_stat(STAT_IPV4_REDIRECTED);
			return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
		}
		/* 非 pool 地址: 放行给内核协议栈 */
		inc_stat(STAT_IPV4_PASSED);
	}

	inc_stat(STAT_OTHER_PASSED);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
