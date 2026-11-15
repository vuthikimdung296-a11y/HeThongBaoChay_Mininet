# -*- coding: utf-8 -*-
"""config.py - TAT CA THAM SO CUA MANG. Muon doi so (bang thong, so tang, IP gateway...) chi sua o day."""

N_FLOORS = 10              # so tang
SENSORS_PER_FLOOR = 30     # cam bien moi tang  -> 300 cam bien
CAMS_PER_FLOOR = 2         # camera moi tang    -> 20 camera

LINK_BW = 100              # Mbps, moi lien ket (so do: [100])
LINK_DELAY = '1ms'         # tre moi lien ket   (so do: [1] ms)

VLAN_SENSOR, VLAN_CAM, VLAN_SRV = 10, 20, 30

# Dia chi Gateway tren tung VLAN (eth0.10 / eth0.20 / eth0.30) va cong ngoai eth1
GW_VLAN_IP = {VLAN_SENSOR: '10.0.10.1/23',
              VLAN_CAM:    '10.0.20.1/24',
              VLAN_SRV:    '10.0.30.1/24'}
GW_EXT_IP = '192.168.100.1/24'
SRV_IP = '10.0.30.10/24'
ATK_IP = '192.168.100.100/24'
