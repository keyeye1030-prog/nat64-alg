# NAT64-ALG 高性能应用层网关部署指南

本文档将指导您在 Linux 系统上从零编译并部署基于 `AF_XDP` 和 eBPF 的高性能 NAT64 双臂网关。

---

## 1. 部署架构说明

本项目推荐使用 **双臂双网卡部署模式 (Mode B)**，实现最高的隔离性和吞吐量：

*   **eth0（IPv6 侧）**：专用于接收和发送内网纯 IPv6 流量。绑定的 IP 需能与内网终端通信。
*   **eth1（IPv4 侧）**：专用于与外部 IPv4 互联网或媒体服务器通信。
*   **NAT64 出口地址 (Pool IPv4)**：网关代理内网终端发出的虚假 IPv4 源地址（例如 `198.51.100.1`，该地址最好在 `eth1` 上路由可达或响应 ARP）。

---

## 2. 环境准备 (环境要求)

1. **操作系统**: Linux (推荐 Ubuntu 20.04/22.04 LTS 或更高版本)
2. **内核版本**: Linux Kernel 5.4+ (必须支持 AF_XDP，推荐 5.15+ 以获得完整的 Zero-Copy XDP 支持)
3. **编译工具**:
   - `golang` (1.20+)
   - `clang`, `llvm`, `libbpf-dev`, `make`, `gcc` (用于编译 eBPF XDP 内核程序)

**安装依赖项** (Ubuntu):
```bash
sudo apt update
sudo apt install -y golang clang llvm libbpf-dev make gcc
```

---

## 3. 编译阶段

项目包含两部分代码：内核态的 eBPF 过滤代码 (`C`) 和 用户态的网关引擎 (`Go`)。

### 3.1 编译 XDP eBPF 内核代码
进入项目目录并使用 `clang` 将 `xdp/nat64.c` 编译为 BPF 字节码挂载文件 (.o)：

```bash
cd xdp/
clang -O2 -g -Wall -target bpf -c nat64.c -o nat64.o
cd ..
```
编译成功后，在 `xdp` 目录下会生成 `nat64.o`，这是后续加载到网卡上的过滤程序。

### 3.2 编译 Go 用户态程序
回到项目根目录，使用 `go build` 编译执行文件：

```bash
go build -o nat64-alg main.go
```

---

## 4. 编写配置文件

我们刚刚为系统加入了 JSON 配置文件支持。在项目目录下创建 `config.json` 文件：

```json
{
  "mode": "dual",
  "pool_ipv4": "198.51.100.1",
  "iface_ipv6": "eth0",
  "iface_ipv4": "eth1",
  "gw_ipv6": "2001:db8::1",
  "rtp_port_start": 20000,
  "rtp_port_end": 30000
}
```

**参数说明**：
*   `mode`: 填写 `"dual"` 表示启用双臂双网卡模式，`"single"`为单臂模式。
*   `pool_ipv4`: NAT64 转换后，内网 IPv6 终端在 IPv4 世界中显现的**源 IP**（转换池地址）。
*   `iface_ipv6`: 接入 IPv6 网络的网卡名。
*   `iface_ipv4`: 接入 IPv4 网络的网卡名。
*   `gw_ipv6`: 网关机器自身的 IPv6 接口地址，SIP ALG 在为 RTP 分配中继点时，将把 SDP 重写为该地址。
*   `rtp_port_start` / `rtp_port_end`: 用于 RTP 媒体中继动态分配的 UDP 端口范围。

---

## 5. 网卡及系统调优配置

在使用 `AF_XDP` 之前，必须对参与的网卡进行一些基础参数配置，以避免硬件层面的校验或组包干扰内核旁路。

请以 `root` 权限执行以下配置：

### 5.1 开启网卡混杂模式
AF_XDP 原始套接字通常需要网卡处于杂散（Promiscuous）模式，以接收非指配给本机 MAC 的二层帧：
```bash
ip link set dev eth0 promisc on
ip link set dev eth1 promisc on
```

### 5.2 关闭网卡硬件卸载 (Offloads)
为了保证 XDP 能接收到原始以太网帧进行解包以及进行软件维度的校验和重新计算，**必须关闭**（LRO, GRO, TSO, TX Checksum 等）：
```bash
# 关闭 eth0 的卸载
ethtool -K eth0 rx off tx off tso off gso off gro off lro off
# 关闭 eth1 的卸载
ethtool -K eth1 rx off tx off tso off gso off gro off lro off
```

*(如果 `ethtool` 报错个别项无法修改，忽略即可，这是硬件不支持对应的卸载)*

---

## 6. 运行与部署

### 6.1 手动运行测试

先在终端下手动加载启动，查看是否有错误输出：
```bash
sudo ./nat64-alg -config ./config.json
```
如果输出如下内容，说明挂载成功且双通引擎正在运行：
```text
======================================
  NAT64-ALG Engine
  Mode     : dual
  Pool IPv4: 198.51.100.1
======================================
[DualNIC] IPv6 侧网卡: eth0 (Index: 2, MTU: 1500)
[DualNIC] IPv4 侧网卡: eth1 (Index: 3, MTU: 1500)
...
```

### 6.2 配置 Systemd 后台服务部署

为了在生产环境中后台运行和开机自启，推荐封装为 `systemd`。

1. 创建文件 `/etc/systemd/system/nat64-alg.service`:

```ini
[Unit]
Description=High Performance NAT64 ALG Gateway (AF_XDP)
After=network.target

[Service]
Type=simple
User=root
# 修改为实际代码所在路径
WorkingDirectory=/opt/nat64-alg
# 提前关闭硬件 offload 
ExecStartPre=/sbin/ethtool -K eth0 rx off tx off tso off gso off gro off lro off
ExecStartPre=-/sbin/ethtool -K eth1 rx off tx off tso off gso off gro off lro off
ExecStart=/opt/nat64-alg/nat64-alg -config /opt/nat64-alg/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

2. 加载与启动：
```bash
sudo systemctl daemon-reload
sudo systemctl enable nat64-alg
sudo systemctl start nat64-alg
```

3. 查看运行日志：
```bash
sudo journalctl -u nat64-alg -f
```

---

## 7. 高可用与性能监控

*   **指标查看**: 日志中会定期输出 `[SessionCleaner]` 等信息，显示当前活跃会话和 RTP 中继数。
*   **路由注意**: 上游 IPv4 路由器需配置指向 `eth1` 的路由，使得前往 `198.51.100.1` (设定好的 Pool IP) 的回程报文能送达这台网关。
*   **eBPF 监控**: 若需排查 `nat64.o` 是否正确附着到了网卡，可使用 `ip link show` 或者 `bpftool net` 命令检查 XDP 状态。
