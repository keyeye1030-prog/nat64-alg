#!/usr/bin/env bash
killall dpdk-nat64 2>/dev/null || true
rm -f /opt/dpdk-nat64/dpdk-nat64.pid
echo "dpdk-nat64 stopped"
