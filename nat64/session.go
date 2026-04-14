package nat64

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ============================================================================
// 有状态 NAT64 会话表 (Stateful NAT64 Session Table)
// 参照 RFC 6146 Section 3: Binding Information Bases (BIBs)
// ============================================================================

// Protocol 是传输层协议编号
type Protocol uint8

const (
	ProtoTCP  Protocol = 6
	ProtoUDP  Protocol = 17
	ProtoICMP Protocol = 1 // ICMPv4 (映射自 ICMPv6 = 58)
)

// SessionKey6 是 IPv6 侧的五元组 Key
type SessionKey6 struct {
	SrcIP   [16]byte // IPv6 源地址
	DstIP   [16]byte // IPv6 目的地址 (含 NAT64 前缀嵌入的 IPv4)
	SrcPort uint16
	DstPort uint16 // 对 ICMP 来说, 这是 Identifier
	Proto   Protocol
}

// SessionKey4 是 IPv4 侧的五元组 Key
type SessionKey4 struct {
	SrcIP   [4]byte // NAT64 网关的 IPv4 公网地址 (出口)
	DstIP   [4]byte // 真正的 IPv4 目的地址
	SrcPort uint16  // NAT 后映射的源端口
	DstPort uint16
	Proto   Protocol
}

// Session 保存一条活跃的 NAT64 转换会话
type Session struct {
	Key6      SessionKey6
	Key4      SessionKey4
	CreatedAt time.Time
	LastSeen  time.Time

	// ALG 相关
	TCPTracker *TCPDeltaTracker // TCP 序列号修正 (仅在需要 ALG 的 TCP 会话中延迟初始化)
}

// SessionTable 是核心的有状态映射表, 使用分片锁降低竞争
type SessionTable struct {
	shards     [256]sessionShard
	poolIPv4s  []net.IP // NAT64 网关的多个 IPv4 出口地址 (地址池)
	portStart  uint16   // 可分配端口范围起点
	portEnd    uint16   // 可分配端口范围终点
	nextPort   uint16   // 下一个分配端口 (简单轮询)
	portMu     sync.Mutex
	sessionTTL time.Duration

	staticMappings map[string]net.IP // Static 1:1 mappings
}

// SetStaticMappings injects a static IP map
func (st *SessionTable) SetStaticMappings(mappings map[string]net.IP) {
	st.staticMappings = mappings
}

type sessionShard struct {
	mu       sync.RWMutex
	byKey6   map[SessionKey6]*Session
	byKey4   map[SessionKey4]*Session
}

// NewSessionTable 初始化会话表
func NewSessionTable(poolAddrs []net.IP, portStart, portEnd uint16, ttl time.Duration) *SessionTable {
	pool4s := make([]net.IP, len(poolAddrs))
	for i, ip := range poolAddrs {
		pool4s[i] = ip.To4()
	}

	st := &SessionTable{
		poolIPv4s:  pool4s,
		portStart:  portStart,
		portEnd:    portEnd,
		nextPort:   portStart,
		sessionTTL: ttl,
	}
	for i := range st.shards {
		st.shards[i].byKey6 = make(map[SessionKey6]*Session)
		st.shards[i].byKey4 = make(map[SessionKey4]*Session)
	}
	return st
}

// shardIndex 通过端口低 8 位简单分片
func shardIndex(port uint16) uint8 {
	return uint8(port & 0xFF)
}

// hashBasedIPv4 从地址池中稳定地选取一个地址 (IP 亲和性)
func (st *SessionTable) hashBasedIPv4(ipv6Src [16]byte) net.IP {
	var hash uint32
	for _, b := range ipv6Src {
		hash = (hash * 31) + uint32(b)
	}
	idx := hash % uint32(len(st.poolIPv4s))
	return st.poolIPv4s[idx]
}

// Lookup6to4 根据 IPv6 侧的信息查找已有会话, 如果不存在则自动创建
func (st *SessionTable) Lookup6to4(key6 SessionKey6) (*Session, error) {
	idx := shardIndex(key6.SrcPort)
	shard := &st.shards[idx]

	// 快速读路径
	shard.mu.RLock()
	if sess, ok := shard.byKey6[key6]; ok {
		sess.LastSeen = time.Now()
		shard.mu.RUnlock()
		return sess, nil
	}
	shard.mu.RUnlock()

	// 慢路径: 创建新会话
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 双重检查: 可能有其他 goroutine 在我们等写锁的同时已经创建
	if sess, ok := shard.byKey6[key6]; ok {
		sess.LastSeen = time.Now()
		return sess, nil
	}

	// 1:1 Static mapping check vs N:M PAT Hash Mapping
	isStatic := false
	mappedIPv4 := st.hashBasedIPv4(key6.SrcIP)
	mappedPort := key6.SrcPort // default explicitly to original port

	if st.staticMappings != nil {
		if staticIP, ok := st.staticMappings[net.IP(key6.SrcIP[:]).String()]; ok {
			mappedIPv4 = staticIP.To4()
			isStatic = true
		}
	}

	if !isStatic {
		// 分配 IPv4 出口动态端口 (N:1 PAT)
		var err error
		mappedPort, err = st.allocatePort()
		if err != nil {
			return nil, err
		}
	}

	// 提取 IPv4 目的地址 (从 NAT64 合成地址)
	dstIPv6 := net.IP(key6.DstIP[:])
	dstIPv4 := IPv6ExtractIPv4(dstIPv6)
	if dstIPv4 == nil {
		return nil, fmt.Errorf("目标地址 %s 不在 NAT64 前缀范围内", dstIPv6)
	}

	now := time.Now()
	sess := &Session{
		Key6: key6,
		Key4: SessionKey4{
			SrcPort: mappedPort,
			DstPort: key6.DstPort,
			Proto:   key6.Proto,
		},
		CreatedAt: now,
		LastSeen:  now,
	}
	copy(sess.Key4.SrcIP[:], mappedIPv4)
	copy(sess.Key4.DstIP[:], dstIPv4.To4())

	// 存储 IPv6 正向索引 (在当前 shard 中)
	shard.byKey6[key6] = sess

	// 存储 IPv4 反向索引 (在 mappedPort 对应的 shard 中, 以便反向查找)
	revIdx := shardIndex(mappedPort)
	if revIdx == idx {
		// 同一个 shard, 已持有锁
		shard.byKey4[sess.Key4] = sess
	} else {
		revShard := &st.shards[revIdx]
		revShard.mu.Lock()
		revShard.byKey4[sess.Key4] = sess
		revShard.mu.Unlock()
	}

	return sess, nil
}

// Lookup4to6 根据 IPv4 侧信息查找反向会话 (IPv4 回包到 IPv6)
// key4 必须与创建时存储的 Key4 完全一致 (SrcIP=pool, DstIP=remote, SrcPort=mapped, DstPort=remoteDst)
func (st *SessionTable) Lookup4to6(key4 SessionKey4) (*Session, bool) {
	idx := shardIndex(key4.SrcPort)
	shard := &st.shards[idx]

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	sess, ok := shard.byKey4[key4]
	if ok {
		sess.LastSeen = time.Now()
	}
	return sess, ok
}

// LookupByMappedPort 通过 NAT 映射端口查找反向会话
// 当收到 IPv4 回包时, 回包的目的端口就是我们分配的 mappedPort, 目的IP是我们绑定的 mappedIP
func (st *SessionTable) LookupByMappedPort(mappedIP, remoteIP net.IP, remotePort, mappedPort uint16, proto Protocol) (*Session, bool) {
	var key4 SessionKey4
	copy(key4.SrcIP[:], mappedIP.To4())
	copy(key4.DstIP[:], remoteIP.To4())
	key4.SrcPort = mappedPort
	key4.DstPort = remotePort
	key4.Proto = proto

	idx := shardIndex(mappedPort)
	shard := &st.shards[idx]

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	sess, ok := shard.byKey4[key4]
	if ok {
		sess.LastSeen = time.Now()
	}
	return sess, ok
}

// allocatePort 简单轮询分配端口
func (st *SessionTable) allocatePort() (uint16, error) {
	st.portMu.Lock()
	defer st.portMu.Unlock()

	port := st.nextPort
	st.nextPort++
	if st.nextPort > st.portEnd {
		st.nextPort = st.portStart
	}
	return port, nil
}

// CleanExpired 清理过期会话 (应由后台 goroutine 定期调用)
func (st *SessionTable) CleanExpired() int {
	cleaned := 0
	cutoff := time.Now().Add(-st.sessionTTL)

	for i := range st.shards {
		shard := &st.shards[i]
		shard.mu.Lock()
		for k6, sess := range shard.byKey6 {
			if sess.LastSeen.Before(cutoff) {
				delete(shard.byKey6, k6)
				// 删除反向索引 (可能在不同 shard)
				revIdx := shardIndex(sess.Key4.SrcPort)
				if int(revIdx) == i {
					delete(shard.byKey4, sess.Key4)
				} else {
					revShard := &st.shards[revIdx]
					revShard.mu.Lock()
					delete(revShard.byKey4, sess.Key4)
					revShard.mu.Unlock()
				}
				cleaned++
			}
		}
		shard.mu.Unlock()
	}
	return cleaned
}

// IsPoolIP checks if the given IPv4 address belongs to the dynamic NAT pool or static mappings
func (st *SessionTable) IsPoolIP(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	// Check static maps first
	if st.staticMappings != nil {
		for _, mapped := range st.staticMappings {
			if mapped.To4().Equal(ipv4) {
				return true
			}
		}
	}
	// Check dynamic pool
	for _, poolIP := range st.poolIPv4s {
		if poolIP.Equal(ipv4) {
			return true
		}
	}
	return false
}

// Stats 返回当前活跃会话数
func (st *SessionTable) Stats() int {
	total := 0
	for i := range st.shards {
		st.shards[i].mu.RLock()
		total += len(st.shards[i].byKey6)
		st.shards[i].mu.RUnlock()
	}
	return total
}
