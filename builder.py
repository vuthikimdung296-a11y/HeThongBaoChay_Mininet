# -*- coding: utf-8 -*-
"""builder.py - DUNG SO DO: tao host, switch, lien ket (chua cau hinh VLAN/IP phu). Sua so do thi sua file nay."""
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink

from config import (N_FLOORS, CAMS_PER_FLOOR, SRV_IP, ATK_IP,
                    SENSOR_SUBNET, CAM_SUBNET)
from ip_plan import sensor_ips, camera_ip
from nodes import LinuxRouter


def build_network(bw, delay):
    # controller=None + OVSBridge: switch 'standalone' (hoc MAC nhu switch thuong), hieu tag VLAN, khong can SDN controller.
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink, autoSetMacs=True, build=False)
    lk = dict(bw=bw, delay=delay)          # TCLink: gioi han bang thong + do tre

    s1 = net.addSwitch('s1')
    gw = net.addHost('gw', cls=LinuxRouter, ip=None)   # IP cau hinh sau (sub-interface VLAN)
    srv = net.addHost('srv', ip=SRV_IP, defaultRoute='via 10.0.30.1')
    atk = net.addHost('atk', ip=ATK_IP, defaultRoute='via 192.168.100.1')

    # Thu tu addLink quyet dinh ten giao dien: gw-eth0 (trunk), gw-eth1 (mang ngoai)
    net.addLink(gw, s1, intfName1='gw-eth0', intfName2='s1-gw', **lk)
    net.addLink(gw, atk, intfName1='gw-eth1', intfName2='atk-eth0', **lk)
    net.addLink(srv, s1, intfName1='srv-eth0', intfName2='s1-srv', **lk)

    sensors, cams, aliases = [], [], {}
    for f in range(1, N_FLOORS + 1):
        name = 'hs%02d' % f
        ips = sensor_ips(f)
        h = net.addHost(name, ip=ips[0] + '/' + SENSOR_SUBNET.split('/')[1],
                        defaultRoute='via 10.0.10.1')
        net.addLink(h, s1, intfName1=name + '-eth0', intfName2='s1-' + name, **lk)
        sensors.append(name)
        aliases[name] = ips[1:]            # 29 IP con lai gan lam IP phu
    for n in range(1, N_FLOORS * CAMS_PER_FLOOR + 1):
        name = 'cam%02d' % n
        h = net.addHost(name, ip=camera_ip(n) + '/' + CAM_SUBNET.split('/')[1],
                        defaultRoute='via 10.0.20.1')
        net.addLink(h, s1, intfName1=name + '-eth0', intfName2='s1-' + name, **lk)
        cams.append(name)
    return net, sensors, cams, aliases
