// +build linux

package engine

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"nat64-alg/nat64"
)

// XDPEngine 封装了 AF_XDP 相关的底层操作 (使用自定义 eBPF 过滤)
type XDPEngine struct {
	ifaceName  string
	link       link.Link
	coll       *ebpf.Collection
	xsk        *xdp.Socket
	translator *nat64.Translator
}

// NewXDPEngine 初始化并附着 XDP 程序到目标网卡 (支持 Generic 模式)
func NewXDPEngine(ifaceName string, poolIPv4 net.IP) (*XDPEngine, error) {
	eth, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("找不到网卡 %s: %w", ifaceName, err)
	}

	// 1. 加载并加载自定义 eBPF 程序 (nat64.o)
	spec, err := ebpf.LoadCollectionSpec("nat64.o")
	if err != nil {
		return nil, fmt.Errorf("加载 nat64.o 失败: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("创建 eBPF Collection 失败: %w", err)
	}

	prog := coll.Programs["xdp_nat64_func"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("找不到 xdp_nat64_func 程序")
	}

	// 2. 附着到网卡 (使用 Generic/SKB 模式以提高兼容性)
	// 注意: cilium/ebpf v0.4.0 使用 link 包
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: eth.Index,
		Flags:     link.XDPGenericMode, // 强制 Generic 模式
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("附着 XDP 程序失败 (Generic Mode): %w", err)
	}
	log.Printf("[XDPEngine] XDP 程序已以 Generic 模式附着到 %s", ifaceName)

	// 3. 创建 AF_XDP socket
	// 我们仍然使用 asavie/xdp 来简化 UMEM 和 Ring 管理
	xsk, err := xdp.NewSocket(eth.Index, 0, nil)
	if err != nil {
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("创建 AF_XDP socket 失败: %w", err)
	}

	// 4. 将 Socket 注册到 eBPF Map
	xsksMap := coll.Maps["xsks_map"]
	if xsksMap == nil {
		xsk.Close()
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("找不到 xsks_map")
	}
	fd := uint32(xsk.FD())
	key := uint32(0) // 队列 0
	if err := xsksMap.Update(&key, &fd, ebpf.UpdateAny); err != nil {
		xsk.Close()
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("更新 xsks_map 失败: %w", err)
	}

	// 5. 初始化 Pool IPv4 Map (用于回程流量过滤)
	poolMap := coll.Maps["pool_ips"]
	if poolMap != nil {
		v4 := poolIPv4.To4()
		var ipInt uint32
		ipInt = uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
		val := uint32(1)
		poolMap.Update(&ipInt, &val, ebpf.UpdateAny)
		log.Printf("[XDPEngine] 已同步 Pool IP %s 到 BPF Map", poolIPv4)
	}

	// 5b. 初始化 Dynamic Prefix Map (用于 XDP 层匹配自定义 IPv6 前缀)
	prefixMap := coll.Maps["prefix_map"]
	if prefixMap != nil {
		var prefixBytes [4]uint32
		prefixV6 := nat64.WellKnownPrefix.To16()
		if prefixV6 != nil {
			prefixBytes[0] = uint32(prefixV6[0]) | uint32(prefixV6[1])<<8 | uint32(prefixV6[2])<<16 | uint32(prefixV6[3])<<24
			prefixBytes[1] = uint32(prefixV6[4]) | uint32(prefixV6[5])<<8 | uint32(prefixV6[6])<<16 | uint32(prefixV6[7])<<24
			prefixBytes[2] = uint32(prefixV6[8]) | uint32(prefixV6[9])<<8 | uint32(prefixV6[10])<<16 | uint32(prefixV6[11])<<24
			prefixBytes[3] = uint32(prefixV6[12]) | uint32(prefixV6[13])<<8 | uint32(prefixV6[14])<<16 | uint32(prefixV6[15])<<24
			
			key := uint32(0)
			if err := prefixMap.Update(&key, &prefixBytes, ebpf.UpdateAny); err != nil {
				log.Printf("[XDPEngine] 警告: 更新 dynamic prefix_map BPF Map 失败: %v", err)
			} else {
				log.Printf("[XDPEngine] 已同步 NAT64 Prefix %s 到 BPF Map", nat64.WellKnownPrefix)
			}
		}
	}

	// 6. 初始化翻译器
	poolIPv4s := []net.IP{poolIPv4}
	sessionTable := nat64.NewSessionTable(poolIPv4s, 10000, 60000, 5*time.Minute)
	translator := nat64.NewTranslator(poolIPv4s[0], sessionTable)

	return &XDPEngine{
		ifaceName:  ifaceName,
		link:       l,
		coll:       coll,
		xsk:        xsk,
		translator: translator,
	}, nil
}

// Start 开启数据帧处理
func (e *XDPEngine) Start() {
	log.Println("[XDPEngine] 启动数据循环 (基于自定义 BPF 过滤)...")
	e.fillRxRing()

	for {
		_, _, err := e.xsk.Poll(-1)
		if err != nil {
			continue
		}

		numRx := e.xsk.NumReceived()
		if numRx > 0 {
			rxDescs := e.xsk.Receive(numRx)
			for i := range rxDescs {
				frame := e.xsk.GetFrame(rxDescs[i])
				frameLen := int(rxDescs[i].Len)
				
				// 只有命中 BPF 过滤规则的包才会进入此处
				e.processAndSend(frame[:frameLen])
			}
			e.fillRxRing()
		}

		numComp := e.xsk.NumCompleted()
		if numComp > 0 {
			e.xsk.Complete(numComp)
		}
	}
}

func (e *XDPEngine) processAndSend(frame []byte) {
	result := e.translator.ProcessFrame(frame)
	if result.Error != nil {
		return
	}
	// 翻译后的包发送出去
	if result.OutputFrame != nil {
		e.sendFrame(result.OutputFrame)
	}
}

func (e *XDPEngine) sendFrame(frame []byte) {
	if e.xsk.NumFreeTxSlots() < 1 {
		return
	}
	descs := e.xsk.GetDescs(1)
	if len(descs) < 1 {
		return
	}
	txFrame := e.xsk.GetFrame(descs[0])
	n := copy(txFrame, frame)
	descs[0].Len = uint32(n)
	e.xsk.Transmit(descs)
}

func (e *XDPEngine) fillRxRing() {
	n := e.xsk.NumFreeFillSlots()
	if n == 0 {
		return
	}
	descs := e.xsk.GetDescs(n)
	for i := range descs {
		descs[i].Len = 0
	}
	e.xsk.Fill(descs)
}

func (e *XDPEngine) Close() {
	if e.xsk != nil {
		e.xsk.Close()
	}
	if e.link != nil {
		e.link.Close()
	}
	if e.coll != nil {
		e.coll.Close()
	}
}

func (e *XDPEngine) GetTranslator() *nat64.Translator {
	return e.translator
}
