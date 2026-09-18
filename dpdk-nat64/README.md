# DPDK NAT64 数据面引擎 (含 CentOS 7 / Glibc 2.17 兼容支持)

本项目为高性能 DPDK NAT64 数据面服务，内置针对老旧企业级生产环境（CentOS 7、Linux Kernel 3.10、Glibc 2.17、Haswell 架构 CPU）的完整兼容层与静态部署工具链。

## 目录结构
```
dpdk-nat64/
├── build_static_compat.sh    # 针对 CentOS 7 / Glibc 2.17 / Haswell 的一键静态编译脚本
├── meson.build               # Meson 构建配置
├── src/                      # C 语言源码
│   ├── compat.c              # Haswell rdseed 指令覆写、Glibc 2.17 系统调用/符号降级实现
│   ├── compat_symver.h       # 符号版本降级头文件
│   ├── acl.c / acl.h         # ACL 访问控制列表
│   ├── capture.c / capture.h # 实时抓包模块 (PCAP)
│   ├── config.c / config.h   # JSON 配置解析
│   ├── jsmn.c / jsmn.h       # 轻量级 JSON 解析器
│   ├── main.c                # 主入口、EAL 初始化与网口配置
│   ├── monitor.c / monitor.h # Prometheus 监控指标与 HTTP 管理接口
│   ├── nat64.c / nat64.h     # NAT64 核心无状态/有状态报文转换流水线
│   └── route.c / route.h     # 路由表管理
├── configs/                  # 配置文件示例
│   ├── cfg.json              # 运行配置示例
│   └── remote-routes.json    # 下行与上行静态路由配置
├── scripts/                  # 运维与转换脚本
│   ├── run.sh                # 启动脚本
│   ├── stop.sh               # 停止脚本
│   ├── status.sh             # 状态查看与健康检查脚本
│   └── avs_to_dpdk_cfg.py    # 兼容老旧 AVS cfg.json 转为原生 DPDK 配置
└── docs/                     # 架构与技术文档
    └── centos7-glibc217-compatibility.md
```

## 快速开始

### 1. 静态编译 (适配 CentOS 7 / Glibc 2.17)
```bash
./build_static_compat.sh
```
生成的目标文件位于 `build/dpdk-nat64`。

### 2. 从老旧 AVS 提取配置
```bash
python scripts/avs_to_dpdk_cfg.py /root/avs/cfg.json configs/cfg.json configs/remote-routes.json
```

### 3. 运行与状态检查
```bash
./scripts/run.sh
./scripts/status.sh
```
HTTP 管理与指标端点默认监听于 `http://127.0.0.1:9104`。
