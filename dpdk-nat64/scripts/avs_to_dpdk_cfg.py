#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
avs_to_dpdk_cfg.py
Parses legacy AVS cfg.json and generates native DPDK-NAT64 cfg.json & remote-routes.json
"""

import json
import sys
import os

def convert_cfg(avs_cfg_path, out_cfg_path, out_route_path):
    with open(avs_cfg_path, 'r') as f:
        avs = json.load(f)

    # 1. Parse ports
    net_list = avs.get('net', [])
    dpdk0 = next((n for n in net_list if n.get('dev') == 'dpdk0'), {})
    dpdk1 = next((n for n in net_list if n.get('dev') == 'dpdk1'), {})

    v6_ip = dpdk0.get('ip', '240b:8004:88e:f000::36/126')
    v6_gw = dpdk0.get('gw', '240b:8004:88e:f000::35')

    v4_ips = dpdk1.get('ip', ['10.111.211.160', '10.111.211.161', '10.111.211.162', '10.111.211.163'])
    if isinstance(v4_ips, (str, unicode)):
        v4_ips = [v4_ips]
    v4_mask = dpdk1.get('mask', '255.255.255.128')
    v4_gw = dpdk1.get('gw', '10.111.211.254')

    nat64_info = avs.get('nat64', {})
    pref64 = nat64_info.get('prefix', '240b:8104:088e:fffa::/96')

    # 2. Build native DPDK-NAT64 config
    dpdk_cfg = {
        "sys": {
            "ports": [
                {
                    "name": "dpdk0",
                    "side": "v6",
                    "pci": "0000:03:00.0",
                    "ip": v6_ip,
                    "gateway": v6_gw
                },
                {
                    "name": "dpdk1",
                    "side": "v4",
                    "pci": "0000:03:00.1",
                    "ip": v4_ips[0] if v4_ips else "10.111.211.160",
                    "mask": v4_mask,
                    "gateway": v4_gw
                }
            ],
            "route_file": out_route_path,
            "rx_desc": 4096,
            "tx_desc": 4096,
            "checksum_offload": True,
            "arp_refresh_seconds": 60,
            "arp_defend_seconds": 5
        },
        "services": [
            {
                "prefix": pref64,
                "pools": [
                    {
                        "ips": v4_ips,
                        "port_min": 1024,
                        "port_max": 65535
                    }
                ],
                "tcp_timeout_seconds": 3600,
                "udp_timeout_seconds": 300,
                "icmp_timeout_seconds": 60,
                "acl_action": "pass"
            }
        ]
    }

    # 3. Build remote routes
    routes = {
        "ipv4": [
            {
                "cidr": "0.0.0.0/0",
                "nexthop": v4_gw
            }
        ],
        "ipv6": [
            {
                "cidr": "::/0",
                "nexthop": v6_gw
            }
        ]
    }

    os.makedirs(os.path.dirname(os.path.abspath(out_cfg_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(out_route_path)), exist_ok=True)

    with open(out_cfg_path, 'w') as f:
        json.dump(dpdk_cfg, f, indent=2)

    with open(out_route_path, 'w') as f:
        json.dump(routes, f, indent=2)

    print("Generated {} and {}".format(out_cfg_path, out_route_path))

if __name__ == '__main__':
    avs_in = sys.argv[1] if len(sys.argv) > 1 else '/root/avs/cfg.json'
    cfg_out = sys.argv[2] if len(sys.argv) > 2 else '/opt/dpdk-nat64/etc/cfg.json'
    route_out = sys.argv[3] if len(sys.argv) > 3 else '/opt/dpdk-nat64/etc/remote-routes.json'
    convert_cfg(avs_in, cfg_out, route_out)
