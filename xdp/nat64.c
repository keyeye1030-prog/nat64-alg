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
 * 2. 识别回程的 IPv4 流量
 * 3. 将这些包重定向到 AF_XDP 用户态套接字 (XDP_REDIRECT)
 * 4. 普通流量直接放行 (XDP_PASS)
 */

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map SEC(".maps");

SEC("xdp_nat64")
int xdp_nat64_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__u16 h_proto = eth->h_proto;

	// 处理 IPv6 -> IPv4 (寻找 NAT64 前缀)
	if (h_proto == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (data + sizeof(struct ethhdr));
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;

		// 检查前缀: 64:ff9b::/96 
		// (简单检查前 4 字节: 0064ff9b)
		if (ip6->daddr.s6_addr32[0] == __constant_htonl(0x0064ff9b)) {
			// 重定向到 AF_XDP 队列
			return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
		}
	}

	// 处理 IPv4 -> IPv6 (寻找目的 IP 是否在 NAT64 网关池中)
	if (h_proto == __constant_htons(ETH_P_IP)) {
		struct iphdr *ip4 = (data + sizeof(struct ethhdr));
		if ((void *)(ip4 + 1) > data_end)
			return XDP_PASS;

		// 这里可以用 map 动态下发 pool_ip, 
		// 暂时演示逻辑: 将所有进入本接口的 IPv4 尝试重定向到用户态 ALG/NAT
		return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
