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
 * NAT64 Dynamic Prefix Map: 动态设置自定义 IPv6 前缀 (第 1-3 个 32位块)
 * Key = 0 (__u32)
 * Value = __u32[4] (16 bytes, 网络字节序)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32[4]);
} prefix_map SEC(".maps");

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

/*
 * Local IPv6 Address Map: 存储本机 IPv6 地址 (用于 NDP 代理应答)
 * Key = 0 (__u32)
 * Value = __u32[4] (16 bytes, 与 s6_addr32 对齐)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32[4]);
} local_ip6 SEC(".maps");

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

	/* 处理 IPv6 流量 */
	if (h_proto == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (data + sizeof(struct ethhdr));
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;

		/*
		 * NDP 代理: 对本机 IPv6 地址的 Neighbor Solicitation 就地回复 NA
		 *
		 * 当 XDP Generic + AF_XDP 附着时, 内核的 NDP 响应可能被干扰,
		 * 导致路由器无法解析本机 MAC → 所有入站流量中断。
		 * 在 XDP 层直接回复 NA 彻底避免此问题。
		 */
		if (ip6->nexthdr == 58) { /* ICMPv6 */
			__u8 *icmp6 = (__u8 *)(ip6 + 1);
			/* NA 需要写 32 字节 ICMPv6, 确保空间足够 */
			if ((void *)(icmp6 + 32) > data_end)
				goto nat64_check;

			if (icmp6[0] == 135 && icmp6[1] == 0) { /* NS type=135 code=0 */
				/* NS target address 在 ICMPv6 偏移 8 处 */
				__u32 *ns_target = (__u32 *)(icmp6 + 8);

				__u32 lk = 0;
				__u32 *local = bpf_map_lookup_elem(&local_ip6, &lk);
				if (!local)
					goto nat64_check;

				if (ns_target[0] != local[0] || ns_target[1] != local[1] ||
				    ns_target[2] != local[2] || ns_target[3] != local[3])
					goto nat64_check; /* 不是请求我们的地址 */

				/* === 构造 Neighbor Advertisement === */
				__u8 our_mac[6];
				__builtin_memcpy(our_mac, eth->h_dest, 6);

				/* 以太网: 交换 src/dst MAC */
				__builtin_memcpy(eth->h_dest, eth->h_source, 6);
				__builtin_memcpy(eth->h_source, our_mac, 6);

				/* IPv6: src=我们的IP, dst=请求者的IP */
				struct in6_addr req_ip;
				__builtin_memcpy(&req_ip, &ip6->saddr, 16);
				__builtin_memcpy(&ip6->saddr, ns_target, 16);
				__builtin_memcpy(&ip6->daddr, &req_ip, 16);
				ip6->hop_limit = 255;
				ip6->payload_len = __constant_htons(32);

				/* ICMPv6 NA header */
				icmp6[0] = 136;  /* Type: NA */
				icmp6[1] = 0;
				icmp6[2] = 0; icmp6[3] = 0; /* checksum 清零 */
				icmp6[4] = 0x60; /* Flags: S=1, O=1 */
				icmp6[5] = 0; icmp6[6] = 0; icmp6[7] = 0;
				/* target addr 在 [8..23] 已经是正确的 (来自 NS) */

				/* Option: Target Link-Layer Address */
				icmp6[24] = 2;   /* type=2 */
				icmp6[25] = 1;   /* length=1 (8字节) */
				__builtin_memcpy(icmp6 + 26, our_mac, 6);

				/* 计算 ICMPv6 校验和 (伪首部 + 报文) */
				__u32 csum = 0;
				__u16 *p;
				/* 伪首部: src addr */
				p = (__u16 *)&ip6->saddr;
				csum += p[0]; csum += p[1]; csum += p[2]; csum += p[3];
				csum += p[4]; csum += p[5]; csum += p[6]; csum += p[7];
				/* 伪首部: dst addr */
				p = (__u16 *)&ip6->daddr;
				csum += p[0]; csum += p[1]; csum += p[2]; csum += p[3];
				csum += p[4]; csum += p[5]; csum += p[6]; csum += p[7];
				/* 伪首部: length + next header */
				csum += __constant_htons(32);
				csum += __constant_htons(58);
				/* ICMPv6 报文 (32字节 = 16个16位字) */
				p = (__u16 *)icmp6;
				csum += p[0]; csum += p[1]; csum += p[2]; csum += p[3];
				csum += p[4]; csum += p[5]; csum += p[6]; csum += p[7];
				csum += p[8]; csum += p[9]; csum += p[10]; csum += p[11];
				csum += p[12]; csum += p[13]; csum += p[14]; csum += p[15];
				/* 折叠进位 */
				csum = (csum & 0xFFFF) + (csum >> 16);
				csum = (csum & 0xFFFF) + (csum >> 16);
				icmp6[2] = (~csum) & 0xFF;
				icmp6[3] = (~csum >> 8) & 0xFF;

				return XDP_TX;
			}
		}

nat64_check:
		;
		/*
		 * NAT64 前缀匹配: 优先使用 dynamic prefix_map 中由用户态设置的自定义前缀
		 */
		__u32 map_key = 0;
		__u32 *prefix = bpf_map_lookup_elem(&prefix_map, &map_key);
		
		if (prefix && (prefix[0] != 0 || prefix[1] != 0)) {
			if (ip6->daddr.s6_addr32[0] == prefix[0] &&
			    ip6->daddr.s6_addr32[1] == prefix[1] &&
			    ip6->daddr.s6_addr32[2] == prefix[2]) {
				inc_stat(STAT_IPV6_REDIRECTED);
				return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
			}
		} else {
			if (ip6->daddr.s6_addr32[0] == __constant_htonl(0x0064ff9b) &&
			    ip6->daddr.s6_addr32[1] == 0 &&
			    ip6->daddr.s6_addr32[2] == 0) {
				inc_stat(STAT_IPV6_REDIRECTED);
				return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
			}
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
