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

	/*
	 * ARP 代理: 对 pool IP 的 ARP 请求就地回复
	 *
	 * 当 IPv4 侧路由器发送 ARP "Who has <pool_ip>?" 时,
	 * 我们在 XDP 层直接用本网卡的 MAC 地址构造 ARP Reply 并发回。
	 * 这样 pool IP 就能被 IPv4 侧正确路由到我们这里。
	 *
	 * ARP 帧布局 (以太网 + ARP, 共 42 字节):
	 *   Ethernet Header (14B):
	 *     [6B dst_mac] [6B src_mac] [2B type=0x0806]
	 *   ARP Header (28B):
	 *     [2B hw_type=1] [2B proto_type=0x0800] [1B hw_size=6] [1B proto_size=4]
	 *     [2B opcode: 1=request, 2=reply]
	 *     [6B sender_mac] [4B sender_ip]
	 *     [6B target_mac] [4B target_ip]
	 */
	if (h_proto == __constant_htons(ETH_P_ARP)) {
		/* ARP header starts right after Ethernet header */
		/* We need at least 28 bytes of ARP data */
		void *arp_start = data + sizeof(struct ethhdr);
		if (arp_start + 28 > data_end)
			return XDP_PASS;

		__u8 *arp = arp_start;

		/* Check: hw_type=Ethernet(1), proto=IPv4(0x0800), hw_size=6, proto_size=4 */
		__u16 hw_type   = (__u16)arp[0] << 8 | arp[1];
		__u16 proto_type = (__u16)arp[2] << 8 | arp[3];
		__u8  hw_size   = arp[4];
		__u8  proto_size = arp[5];
		__u16 opcode    = (__u16)arp[6] << 8 | arp[7];

		if (hw_type != 1 || proto_type != 0x0800 ||
		    hw_size != 6 || proto_size != 4 || opcode != 1)
			return XDP_PASS; /* Not an ARP REQUEST for IPv4, pass */

		/* ARP offsets: sender_mac=8, sender_ip=14, target_mac=18, target_ip=24 */
		__u32 target_ip;
		__builtin_memcpy(&target_ip, arp + 24, 4);

		/* Check if target IP is in our pool */
		__u32 *found = bpf_map_lookup_elem(&pool_ips, &target_ip);
		if (!found)
			return XDP_PASS; /* Not our IP, let kernel handle */

		/*
		 * Construct ARP Reply in-place:
		 * 1. Swap Ethernet src/dst MACs
		 * 2. Set opcode = 2 (REPLY)
		 * 3. Move sender → target (the original requester)
		 * 4. Set sender = our MAC + the requested IP
		 */

		/* Save original sender info */
		__u8 orig_sender_mac[6];
		__u32 orig_sender_ip;
		__builtin_memcpy(orig_sender_mac, arp + 8, 6);
		__builtin_memcpy(&orig_sender_ip, arp + 14, 4);

		/* Ethernet: dst = original src, src = our MAC (current dst in incoming frame) */
		__u8 our_mac[6];
		__builtin_memcpy(our_mac, eth->h_dest, 6);
		__builtin_memcpy(eth->h_dest, eth->h_source, 6);
		__builtin_memcpy(eth->h_source, our_mac, 6);

		/* ARP opcode = REPLY (2) */
		arp[6] = 0x00;
		arp[7] = 0x02;

		/* ARP sender = our MAC + target IP */
		__builtin_memcpy(arp + 8, our_mac, 6);
		__builtin_memcpy(arp + 14, &target_ip, 4);

		/* ARP target = original sender */
		__builtin_memcpy(arp + 18, orig_sender_mac, 6);
		__builtin_memcpy(arp + 24, &orig_sender_ip, 4);

		/* Send back out the same interface */
		return XDP_TX;
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
