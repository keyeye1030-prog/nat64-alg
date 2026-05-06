package nat64

import (
	"net"
	"sync"
	"time"
)

// ============================================================================
// 邻居表 (Neighbor Table)
//
// 管理二层 MAC 地址解析:
//   - 静态配置: 默认网关 MAC (推荐生产使用)
//   - 动态学习: 从入站帧的 srcMAC 学习 IP→MAC 映射
//
// 在 AF_XDP 模式下, 内核协议栈不参与包处理, 因此我们必须自己管理
// 邻居关系 (相当于用户态的 ARP/NDP 缓存表)。
// ============================================================================

// NeighborEntry 邻居表条目
type NeighborEntry struct {
	MAC      net.HardwareAddr
	LastSeen time.Time
	IsStatic bool
}

// NeighborTable 邻居缓存表
type NeighborTable struct {
	mu      sync.RWMutex
	entries map[string]*NeighborEntry // key = IP.String()
}

// NewNeighborTable 创建邻居表
func NewNeighborTable() *NeighborTable {
	return &NeighborTable{
		entries: make(map[string]*NeighborEntry),
	}
}

// SetStatic 设置静态邻居条目 (不会被动态学习覆盖)
func (nt *NeighborTable) SetStatic(ip net.IP, mac net.HardwareAddr) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.entries[ip.String()] = &NeighborEntry{
		MAC:      mac,
		IsStatic: true,
	}
}

// Learn 从帧中学习 IP→MAC 映射 (不覆盖静态条目)
func (nt *NeighborTable) Learn(ip net.IP, mac net.HardwareAddr) {
	key := ip.String()
	nt.mu.RLock()
	existing, exists := nt.entries[key]
	nt.mu.RUnlock()

	if exists && existing.IsStatic {
		return // 不覆盖静态条目
	}

	macCopy := make(net.HardwareAddr, len(mac))
	copy(macCopy, mac)

	nt.mu.Lock()
	nt.entries[key] = &NeighborEntry{
		MAC:      macCopy,
		LastSeen: time.Now(),
	}
	nt.mu.Unlock()
}

// Lookup 查找 IP 对应的 MAC 地址
func (nt *NeighborTable) Lookup(ip net.IP) (net.HardwareAddr, bool) {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	entry, ok := nt.entries[ip.String()]
	if !ok {
		return nil, false
	}
	return entry.MAC, true
}

// MACConfig 保存引擎所需的二层地址配置
type MACConfig struct {
	// 本机网卡 MAC (从 net.Interface 自动获取)
	LocalMAC6 net.HardwareAddr // eth2 (IPv6侧) 自身 MAC
	LocalMAC4 net.HardwareAddr // eth1 (IPv4侧) 自身 MAC

	// 默认网关 MAC (静态配置或从首包学习)
	GatewayMAC6 net.HardwareAddr // IPv6 侧网关 MAC (发 IPv6 帧时的目的 MAC)
	GatewayMAC4 net.HardwareAddr // IPv4 侧网关 MAC (发 IPv4 帧时的目的 MAC)

	// 邻居表 (动态学习 IPv6 终端的 MAC)
	Neighbors *NeighborTable
}

// NewMACConfig 创建默认 MAC 配置
func NewMACConfig() *MACConfig {
	return &MACConfig{
		Neighbors: NewNeighborTable(),
	}
}

// ResolveMAC6 解析 IPv6 地址对应的 MAC
// 优先查邻居表, 没有则返回 IPv6 侧默认网关 MAC
func (mc *MACConfig) ResolveMAC6(dstIPv6 net.IP) net.HardwareAddr {
	if mac, ok := mc.Neighbors.Lookup(dstIPv6); ok {
		return mac
	}
	return mc.GatewayMAC6
}

// ResolveMAC4 解析 IPv4 地址对应的 MAC
// 优先查邻居表, 没有则返回 IPv4 侧默认网关 MAC
func (mc *MACConfig) ResolveMAC4(dstIPv4 net.IP) net.HardwareAddr {
	if mac, ok := mc.Neighbors.Lookup(dstIPv4); ok {
		return mac
	}
	return mc.GatewayMAC4
}

// ParseMAC 解析 MAC 地址字符串, 如 "AA:BB:CC:DD:EE:FF"
func ParseMAC(s string) (net.HardwareAddr, error) {
	return net.ParseMAC(s)
}
