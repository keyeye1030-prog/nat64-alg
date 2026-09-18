#!/usr/bin/env bash
export LD_LIBRARY_PATH=/opt/dpdk-nat64/lib:$LD_LIBRARY_PATH
set -euo pipefail

cd /opt/dpdk-nat64

# Stop old processes
killall dpdk-nat64 2>/dev/null || true
killall avs 2>/dev/null || true
sleep 2

# Bind interfaces to igb_uio if not bound
python /root/avs/dpdk-devbind.py -b igb_uio 03:00.0 03:00.1 2>/dev/null || true

nohup /opt/dpdk-nat64/bin/dpdk-nat64 \
  --config /opt/dpdk-nat64/etc/cfg.json \
  --metrics-bind 127.0.0.1 \
  --metrics-port 9104 \
  > /opt/dpdk-nat64/logs/nat64.log 2>&1 &

echo $! > /opt/dpdk-nat64/dpdk-nat64.pid
echo "dpdk-nat64 started with PID $(cat /opt/dpdk-nat64/dpdk-nat64.pid)"
