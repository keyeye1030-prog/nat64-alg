#!/bin/bash
echo "=== dpdk-nat64 Process Status ==="
ps aux | grep dpdk-nat64 | grep -v grep || echo "dpdk-nat64 is not running"

echo ""
echo "=== Nexthop State ==="
curl -s http://127.0.0.1:9104/nexthops || true

echo ""
echo "=== Neighbor State ==="
curl -s http://127.0.0.1:9104/neighbors || true

echo ""
echo "=== Recent Logs ==="
tail -n 20 /opt/dpdk-nat64/logs/nat64.log || true
