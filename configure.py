# -*- coding: utf-8 -*-
"""configure.py - CAU HINH SAU KHI MANG CHAY: VLAN tren OVS, sub-interface tren Gateway, IP phu, tuy chon SYN.
Loi VLAN -> sua configure_ovs; loi dinh tuyen/gateway -> configure_gateway; loi IP cam bien -> configure_aliases."""
from mininet.log import info

from config import (VLAN_SENSOR, VLAN_CAM, VLAN_SRV, GW_VLAN_IP, GW_EXT_IP)


def configure_ovs(net, sensors, cams):
    """Gan tag VLAN tren cong truy cap, trunk 10,20,30 tren cong len gateway."""
    s1 = net.get('s1')

    def ovs(cmd):
        out = s1.cmd('ovs-vsctl ' + cmd)
        if out.strip():
            info('  ovs-vsctl %s -> %s\n' % (cmd, out.strip()))
    for h in sensors:
        ovs('set port s1-%s vlan_mode=access tag=%d' % (h, VLAN_SENSOR))
    for h in cams:
        ovs('set port s1-%s vlan_mode=access tag=%d' % (h, VLAN_CAM))
    ovs('set port s1-srv vlan_mode=access tag=%d' % VLAN_SRV)
    ovs('set port s1-gw vlan_mode=trunk trunks=%d,%d,%d' % (VLAN_SENSOR, VLAN_CAM, VLAN_SRV))


def configure_gateway(net):
    """Sub-interface VLAN tren gw-eth0, IP cong ngoai gw-eth1, tat rp_filter."""
    gw = net.get('gw')
    gw.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')       # cho phep goi gia mao IP di qua
    gw.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
    gw.cmd('sysctl -w net.ipv4.conf.gw-eth0.rp_filter=0')
    gw.cmd('sysctl -w net.ipv4.conf.gw-eth1.rp_filter=0')
    for vid, ip in GW_VLAN_IP.items():
        sub = 'gw-eth0.%d' % vid
        gw.cmd('ip link add link gw-eth0 name %s type vlan id %d' % (sub, vid))
        gw.cmd('ip addr add %s dev %s' % (ip, sub))
        gw.cmd('ip link set %s up' % sub)
    gw.cmd('ip addr add %s dev gw-eth1' % GW_EXT_IP)
    gw.cmd('ip link set gw-eth1 up')


def configure_aliases(net, aliases):
    """29 IP phu tren moi host cam bien (de moi client MQTT bind dung IP cam bien)."""
    for name, ips in aliases.items():
        net.get(name).cmd(' ; '.join('ip addr add %s/23 dev %s-eth0' % (ip, name) for ip in ips))


def configure_options(net, no_syncookies):
    """Tuy chon: tat SYN cookies tren srv; tat IPv6 de goi tin sach."""
    if no_syncookies:
        net.get('srv').cmd('sysctl -w net.ipv4.tcp_syncookies=0')
    for node in net.hosts:
        node.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')


def configure_all(net, sensors, cams, aliases, no_syncookies=False):
    configure_ovs(net, sensors, cams)
    configure_gateway(net)
    configure_aliases(net, aliases)
    configure_options(net, no_syncookies)
