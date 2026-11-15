#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
topology.py - DIEM VAO DUY NHAT. Chi doc tham so dong lenh, roi goi cac module khac.

    sudo mn -c                       # don dep lan chay truoc
    sudo python3 topology.py         # dung mang, vao dau nhac mininet>
    sudo python3 topology.py --test  # tu dong ping kiem tra roi vao mininet>
    python3 topology.py --check-plan quy_hoach_IP_VLAN_v2.xlsx   # doi chieu IP voi Excel (khong can Mininet)

Cau truc file (sua loi o dau thi mo file do):
    config.py     tham so (bang thong, IP gateway, VLAN...)
    ip_plan.py    sinh IP cam bien/camera, doi chieu Excel
    nodes.py      LinuxRouter (Gateway)
    builder.py    dung host, switch, lien ket
    configure.py  VLAN tren OVS, sub-interface gateway, IP phu, tuy chon SYN
    verify.py     ping kiem tra Test 1-4
"""
import argparse
import os
import sys

import config
from ip_plan import check_plan


def main():
    ap = argparse.ArgumentParser(description='Mang ao 4 tang cho de tai QoS + Edge AI chong DDoS')
    ap.add_argument('--test', action='store_true', help='tu dong ping kiem tra sau khi dung mang')
    ap.add_argument('--no-cli', action='store_true', help='khong vao dau nhac mininet>, thoat sau khi chay xong')
    ap.add_argument('--no-syncookies', action='store_true',
                    help='tat SYN cookies tren srv (de SYN Flood lam day hang doi ket noi)')
    ap.add_argument('--bw', type=int, default=config.LINK_BW, help='bang thong moi lien ket (Mbps)')
    ap.add_argument('--delay', default=config.LINK_DELAY, help='do tre moi lien ket, vi du 1ms')
    ap.add_argument('--check-plan', metavar='XLSX', help='doi chieu IP voi file Excel roi thoat')
    args = ap.parse_args()

    if args.check_plan:
        sys.exit(0 if check_plan(args.check_plan) else 1)
    try:
        from mininet.cli import CLI
        from mininet.log import setLogLevel, info
    except ImportError:
        sys.exit('Chua cai Mininet: sudo apt install mininet openvswitch-switch')
    if os.geteuid() != 0:
        sys.exit('Can chay bang root: sudo python3 topology.py')
    from builder import build_network
    from configure import configure_all
    from verify import run_tests

    setLogLevel('info')
    os.system('modprobe 8021q')            # module nhan VLAN cua Linux, can cho gw-eth0.10/.20/.30
    net, sensors, cams, aliases = build_network(args.bw, args.delay)
    net.start()
    try:
        configure_all(net, sensors, cams, aliases, args.no_syncookies)
        info('*** Mang san sang: %d cam bien (%d host), %d camera, gw, srv, atk, s1\n'
             % (config.N_FLOORS * config.SENSORS_PER_FLOOR, len(sensors), len(cams)))
        if args.test:
            run_tests(net, sensors, cams, aliases)
        if not args.no_cli:
            CLI(net)
    finally:
        net.stop()


if __name__ == '__main__':
    main()
