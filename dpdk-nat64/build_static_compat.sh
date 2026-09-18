#!/bin/bash
# ==============================================================================
# build_static_compat.sh
# Automated build script for DPDK NAT64 on/for legacy CentOS 7 / Glibc 2.17 / Haswell
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
SRC_DIR="${SCRIPT_DIR}/src"

echo "=== Building DPDK NAT64 for CentOS 7 / Glibc 2.17 / Haswell ==="

export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

if ! pkg-config --exists libdpdk; then
    echo "ERROR: libdpdk not found in PKG_CONFIG_PATH: $PKG_CONFIG_PATH" >&2
    exit 1
fi

mkdir -p "${BUILD_DIR}"

CFLAGS="$(pkg-config --cflags libdpdk) -I${SRC_DIR} -O3 -std=c11 -Wall -Wextra -Wno-unused-parameter"

# Embed targeted drivers in whole-archive so constructors are retained
DRIVERS="-Wl,--whole-archive \
/usr/local/lib64/librte_bus_pci.a \
/usr/local/lib64/librte_bus_vdev.a \
/usr/local/lib64/librte_net_ixgbe.a \
/usr/local/lib64/librte_net_e1000.a \
/usr/local/lib64/librte_mempool_ring.a \
-Wl,--no-whole-archive"

# Static core DPDK libraries (avoids dynamic linking and glibc version jumps)
CORE_STATIC="\
/usr/local/lib64/librte_acl.a \
/usr/local/lib64/librte_security.a \
/usr/local/lib64/librte_cryptodev.a \
/usr/local/lib64/librte_ethdev.a \
/usr/local/lib64/librte_net.a \
/usr/local/lib64/librte_mbuf.a \
/usr/local/lib64/librte_mempool.a \
/usr/local/lib64/librte_ring.a \
/usr/local/lib64/librte_eal.a \
/usr/local/lib64/librte_telemetry.a \
/usr/local/lib64/librte_kvargs.a \
/usr/local/lib64/librte_log.a \
/usr/local/lib64/librte_pci.a \
/usr/local/lib64/librte_cmdline.a \
/usr/local/lib64/librte_hash.a \
/usr/local/lib64/librte_rcu.a \
/usr/local/lib64/librte_timer.a \
/usr/local/lib64/librte_meter.a"

# Standard system libraries available natively on CentOS 7
LDFLAGS="-Wl,--allow-multiple-definition -Wl,--start-group ${DRIVERS} ${CORE_STATIC} -Wl,--end-group -pthread -lm -ldl -lnuma"

SRCS="\
${SRC_DIR}/compat.c \
${SRC_DIR}/acl.c \
${SRC_DIR}/capture.c \
${SRC_DIR}/config.c \
${SRC_DIR}/jsmn.c \
${SRC_DIR}/main.c \
${SRC_DIR}/monitor.c \
${SRC_DIR}/nat64.c \
${SRC_DIR}/route.c"

TARGET="${BUILD_DIR}/dpdk-nat64"

echo "Compiling..."
gcc $CFLAGS $SRCS $LDFLAGS -o "${TARGET}"

echo "Build complete: ${TARGET}"
ls -lh "${TARGET}"
echo "Dependencies (ldd):"
ldd "${TARGET}" || true
echo "GLIBC requirement check (max required):"
objdump -p "${TARGET}" | grep -E "GLIBC_" | sort -u | tail -n 5 || true
