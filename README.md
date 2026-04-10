# NAT64-ALG

基于 Golang + AF_XDP 的高性能 NAT64 转换引擎，支持 SIP / H.323 应用层网关 (ALG) 协议适配。

## 特性

- **RFC 6052**: NAT64 Well-Known Prefix (`64:ff9b::/96`) 地址合成
- **RFC 6145**: IPv6 ↔ IPv4 双向包头转换
- **RFC 6146**: 有状态 NAT64 会话表 (256 分片锁, BIB)
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
├── nat64/               # 核心 NAT64 转换逻辑
└── alg/                 # 应用层网关协议适配
    ├── sip/             # SIP/SDP ALG
    └── h323/            # H.323 ALG
```

## License

MIT
