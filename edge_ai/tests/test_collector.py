# -*- coding: utf-8 -*-
"""Kiem thu bo thu thap: tao pcap co so lieu da biet truoc, chay collect_metadata, doi chieu tung cua so."""
import csv
import os
import subprocess
import sys
import tempfile

from scapy.all import Ether, Dot1Q, IP, TCP, UDP, ICMP, Raw, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECT = os.path.join(HERE, '..', 'collect_metadata.py')
T0 = 1_700_000_000.0


def mk(ts, pkt):
    pkt.time = ts
    return pkt


def build():
    pk = []
    # Cua so 0: 10 goi MQTT (TCP ACK|PSH) tu 5 IP cam bien, co tag VLAN 10, IP len = 20+20+40 = 80
    for i in range(10):
        pk.append(mk(T0 + 0.05 * i, Ether() / Dot1Q(vlan=10) / IP(src='10.0.10.%d' % (33 + i % 5), dst='10.0.30.10')
                     / TCP(dport=1883, flags='PA') / Raw(b'x' * 40)))
    # Cua so 1: de trong (khong goi)
    # Cua so 2: SYN flood gia mao 50 IP nguon + 5 goi UDP camera tu 1 IP (khong tag)
    for i in range(50):
        pk.append(mk(T0 + 2.0 + 0.01 * i, Ether() / IP(src='172.16.%d.%d' % (i // 200, i % 200 + 1), dst='10.0.30.10')
                     / TCP(dport=1883, flags='S')))
    for i in range(5):
        pk.append(mk(T0 + 2.6 + 0.01 * i, Ether() / IP(src='10.0.20.11', dst='10.0.30.10') / UDP(dport=5004) / Raw(b'v' * 100)))
    # Cua so 3: 1 goi SYN-ACK (khong tinh la SYN moi), 1 goi ICMP
    pk.append(mk(T0 + 3.1, Ether() / IP(src='10.0.30.10', dst='10.0.10.33') / TCP(sport=1883, flags='SA')))
    pk.append(mk(T0 + 3.2, Ether() / IP(src='192.168.100.100', dst='10.0.30.10') / ICMP()))
    return pk


def main():
    d = tempfile.mkdtemp()
    pcap, out = os.path.join(d, 't.pcap'), os.path.join(d, 'f.csv')
    wrpcap(pcap, build())
    subprocess.check_call([sys.executable, COLLECT, '--pcap', pcap, '--out', out], stdout=subprocess.DEVNULL)
    rows = list(csv.DictReader(open(out)))
    assert len(rows) == 4, 'phai co 4 cua so (ke ca cua so rong), co %d' % len(rows)
    r = [{k: float(v) for k, v in x.items()} for x in rows]
    base = int(T0)
    assert [int(x['window_start']) - base for x in r] == [0, 1, 2, 3]
    # cua so 0
    assert r[0]['packet_rate'] == 10 and r[0]['byte_rate'] == 10 * 80
    assert r[0]['syn_count'] == 0 and r[0]['ip_dispersion'] == 5 and r[0]['udp_ratio'] == 0
    # cua so 1 rong
    assert all(r[1][k] == 0 for k in ('packet_rate', 'byte_rate', 'syn_count', 'ip_dispersion'))
    # cua so 2
    assert r[2]['packet_rate'] == 55 and r[2]['syn_count'] == 50 and r[2]['ip_dispersion'] == 51
    assert abs(r[2]['udp_ratio'] - 5 / 55) < 1e-3
    assert r[2]['byte_rate'] == 50 * 40 + 5 * (20 + 8 + 100)
    # cua so 3: SYN-ACK khong tinh, 2 goi, 2 IP
    assert r[3]['syn_count'] == 0 and r[3]['packet_rate'] == 2 and r[3]['ip_dispersion'] == 2
    print('TEST COLLECTOR: DAT (4/4 cua so khop so lieu mong doi)')


if __name__ == '__main__':
    main()
