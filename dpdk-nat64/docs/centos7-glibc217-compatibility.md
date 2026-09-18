# 老旧环境（CentOS 7 / Glibc 2.17）与架构兼容处理技术方案

## 1. 背景与技术挑战
在将现代 DPDK-NAT64 引擎部署至旧生产环境（如 CentOS 7.4、Linux Kernel 3.10、Glibc 2.17、GCC 4.8.5 以及 Intel Haswell 架构 CPU）时，会面临一系列底层架构与系统调用级的不兼容问题：

1. **CPU 指令集缺失 (`rdseed`)**:
   - 目标机搭载 Intel Xeon E5-2650 v3 (Haswell 架构)，该架构不支持 Intel 较新的 `rdseed` 指令。
   - DPDK 23.11 EAL 初始化阶段默认会通过 `rte_cpu_is_supported()` 进行 CPU 特性强制检测，若检测失败会输出：
     ```
     ERROR: This system does not support "RDSEED"
     Please check that RTE_MACHINE is set correctly.
     EAL: FATAL: unsupported cpu type.
     ```
   - 即使绕过检测，在 `rte_rand_init` 中直接执行 `rdseed` 指令会直接引发核心转储崩溃（`SIGILL: Illegal instruction`）。

2. **GLIBC 2.17 符号与系统调用断代**:
   - 现代 DPDK 在内存管理中大量使用 Linux 3.17+ 引入的 `memfd_create` 系统调用。在 CentOS 7 (Kernel 3.10, Glibc 2.17) 中，glibc 未导出 `memfd_create` 符号。
   - DPDK `rte_ethdev` 模块调用的 `fmemopen` 在高版本 glibc 下会被默认解析绑定为 `fmemopen@@GLIBC_2.22`，导致在旧 glibc 机器上动态加载失败：
     ```
     /lib64/libc.so.6: version 'GLIBC_2.22' not found (required by dpdk-nat64)
     ```
   - 部分高版本编译工具链引入了 `fcntl64`。

3. **静态驱动剥离 (Whole-Archive 失效)**:
   - DPDK 网卡驱动（PMD，如 `ixgbe`, `e1000`）及总线驱动（`bus_pci`, `bus_vdev`）均基于构造函数（`RTE_INIT` / `__attribute__((constructor))`）进行自注册。
   - 若在静态链接时未正确指定 `-Wl,--whole-archive` 保护，GNU ld 会因主程序未显式引用驱动符号而将驱动全部剥离，导致运行时出现：
     ```
     EAL: failed to parse device "0000:03:00.0"
     EAL: Unable to parse device '0000:03:00.0'
     failed to init EAL
     ```
   - 反之，若盲目将所有 DPDK 驱动纳入 `--whole-archive`，会导致不必要的第三方依赖（如 `libbpf.so.0`、`libcrypto.so.1.1`），而这些第三方库自身又强依赖 `GLIBC_2.22`，形成死锁。

---

## 2. 兼容层架构与核心设计

```
+-------------------------------------------------------------+
|                      dpdk-nat64 (Main)                      |
+-------------------------------------------------------------+
                              |
      +-----------------------+-----------------------+
      |                                               |
      v                                               v
+-----------------------------+     +--------------------------------+
|      compat.c (Shim层)       |     | Targeted Static Linking (.a)   |
+-----------------------------+     +--------------------------------+
| - rte_cpu_is_supported -> 1 |     | - librte_bus_pci.a (whole)     |
| - PRNG (xorshift/LCG) 无    |     | - librte_net_ixgbe.a (whole)   |
|   rdseed 指令兼容算法        |     | - librte_mempool_ring.a (whole)|
| - syscall(__NR_memfd_create)|     | - librte_eal.a (core static)   |
| - fmemopen@GLIBC_2.2.5 降级  |     | - 排除 libbpf / libcrypto 污染 |
| - fcntl64 兼容封装           |     +--------------------------------+
+-----------------------------+                       |
               |                                      v
               +--------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------+
|           Target OS (CentOS 7, Glibc 2.17, Kernel 3.10)     |
|             仅依赖标准系统库: libc, libm, libpthread, libnuma     |
+-------------------------------------------------------------+
```

### 2.1 指令集与 CPU 特性垫片 (`compat.c`)
- **绕过 EAL CPU 检查**:
  ```c
  int rte_cpu_is_supported(void) {
      return 1;
  }
  ```
- **无硬件指令依赖的 PRNG 算法实现**:
  覆写 DPDK 的 `rte_srand`, `rte_rand`, `rte_rand_max`, `rte_drand`，采用高性能 64 位 xorshift/LCG 状态机生成伪随机数，彻底剥除对 `rdseed` 指令的依赖。

### 2.2 系统调用与符号降级 (`compat.c` & `compat_symver.h`)
- **系统调用代理**:
  ```c
  #ifndef __NR_memfd_create
  #define __NR_memfd_create 319
  #endif

  int memfd_create(const char *name, unsigned int flags) {
      return syscall(__NR_memfd_create, name, flags);
  }
  ```
- **符号版本强制对齐**:
  通过 `.symver` 将 `fmemopen` 显式重定向绑定到旧版 `fmemopen@GLIBC_2.2.5`：
  ```c
  __asm__(".symver glibc_fmemopen, fmemopen@GLIBC_2.2.5");
  extern FILE *glibc_fmemopen(void *buf, size_t size, const char *mode);

  FILE *fmemopen(void *buf, size_t size, const char *mode) {
      return glibc_fmemopen(buf, size, mode);
  }
  ```

### 2.3 针对性整包静态链接策略 (`build_static_compat.sh`)
- 仅针对当前硬件（Intel 82599ES 10G NIC / PCI 总线），精选如下驱动进入 `--whole-archive`：
  - `librte_bus_pci.a`
  - `librte_bus_vdev.a`
  - `librte_net_ixgbe.a`
  - `librte_net_e1000.a`
  - `librte_mempool_ring.a`
- 排除不适用的驱动包（如 `librte_net_af_xdp.a`、`librte_crypto_openssl.a`、Broadcom/Mellanox PMDs），使得最终二进制彻底脱离 `libbpf`、`libcrypto`、`libpcap`、`libelf` 等高版本共享库。
- 动态链接库完全收敛为系统基础库：
  `libc.so.6`, `libm.so.6`, `libdl.so.2`, `libnuma.so.1`, `libpthread.so.0`。
  最高依赖符号版本严格限制在 `GLIBC_2.17` 以内。

---

## 3. 自动化转换与部署工具
- **`build_static_compat.sh`**: 一键静态编译脚本，生成即用型纯静态可执行文件。
- **`scripts/avs_to_dpdk_cfg.py`**: 自动解析老旧 AVS `/root/avs/cfg.json` 配置，无缝生成原生 `cfg.json` 及 `remote-routes.json`。
- **`scripts/run.sh` / `stop.sh` / `status.sh`**: 标准化运维管控脚本，支持巨页自检、驱动绑定确认与进程守护。
