# NAT64-ALG

基于 Golang + AF_XDP 的高性能 NAT64 转换引擎，支持 SIP / H.323 应用层网关 (ALG) 协议适配。

## 特性

- **RFC 6052**: NAT64 Well-Known Prefix (`64:ff9b::/96`) 地址合成
- **RFC 6145**: IPv6 ↔ IPv4 双向包头转换
- **RFC 6146**: 有状态 NAT64 会话表 (256 分片锁, BIB)
- **L2 MAC & 邻居表**: 用户态 ARP/NDP 邻居动态学习、静态网关绑定与**后台自动老化清理（防泛洪）**
- **ICMP ↔ ICMPv6**: 完整的类型/代码映射、MTU 调整、嵌套包头递归翻译
- **SIP ALG**: SIP/SDP 信令中 IPv6 地址重写与媒体端口适配
- **H.323 ALG**: H.225/H.245 ASN.1 信令中传输地址翻译
- **AF_XDP 数据面**: 基于 eBPF/XDP 的零拷贝高性能包处理

## 构建

```bash
go build -o nat64-alg .
```

## 运行

```bash
sudo ./nat64-alg -interface eth0 -pool-ipv4 198.51.100.1
```

## 测试

```bash
go test -v ./nat64/
go test -v ./alg/...
```

## 项目结构

```
├── main.go              # 应用入口
├── engine/              # AF_XDP 数据面引擎
├── nat64/               # 核心 NAT64 转换逻辑与邻居表
├── alg/                 # 应用层网关协议适配
│   ├── sip/             # SIP/SDP ALG
│   └── h323/            # H.323 ALG
└── dpdk-nat64/          # DPDK 高性能数据面（支持 CentOS 7 / Glibc 2.17 静态兼容运行）
```

## 开发进度与更新日志 (Changelog)

- **2026-09-18**:
  - **老旧环境（CentOS 7 / Glibc 2.17）与架构兼容处理**：
    - 新增 `dpdk-nat64/src/compat.c` 兼容层，覆写 `rte_cpu_is_supported` 并实现 PRNG 伪随机数算法，消除 Intel Haswell / 早期 CPU 缺少 `rdseed` 指令引发的崩溃。
    - 针对 CentOS 7 (Kernel 3.10, Glibc 2.17) 注入 `memfd_create` 系统调用 shim（syscall 319），并通过 `.symver` 将 `fmemopen` 绑定至 `fmemopen@GLIBC_2.2.5`，彻底消除 `GLIBC_2.22` 等高版本符号依赖。
    - 提供针对性静态整包驱动链接方案（`build_static_compat.sh`），精简依赖，实现零外部依赖开箱即用。
    - 增加老旧 AVS 配置转换脚本（`avs_to_dpdk_cfg.py`）及全套运维管控脚本（`run.sh`, `stop.sh`, `status.sh`）。
- **2026-08-27**:
  - **二层邻居表自动老化清理 (Aging / GC)**：
    - `NeighborTable` 增加 `CleanExpired(ttl)`、`Stats()`、`Count()` 及 `StartCleaner()`。
    - 后台协程每 30 秒执行一次自动扫描，剔除超过 5 分钟未活跃（`time.Since(LastSeen) > 5m`）的动态学习条目。
    - 静态网关配置条目（`IsStatic`）受到永久保护不被清除，有效防止伪造源 IP 泛洪攻击导致内存泄漏。
    - 在双网卡数据面引擎（`DualNICEngine`）与单臂引擎（`XDPEngine`）中统一集成。
- **2026-08-20**:
  - 增强 NAT64 核心引擎与 SIP/H.323 协议适配；
  - 支持多 IPv4 池地址哈希映射与 Full-Cone 入站穿透；
  - 实现 AF_XDP 双臂双网卡数据面与物理网卡 Preflight 预检。

## License

MIT

