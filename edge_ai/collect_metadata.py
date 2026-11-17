# -*- coding: utf-8 -*-
"""collect_metadata.py - Thu thap header metadata theo cua so 1 giay tai Gateway.

Ba che do:
  1) Doc file pcap (offline):    python3 collect_metadata.py --pcap vao_eth0.pcap vao_eth1.pcap --out features.csv
  2) Bat truc tiep (AF_PACKET): sudo python3 collect_metadata.py --iface gw-eth0 gw-eth1 --duration 120 --out features.csv
  3) Bat truc tiep bang tshark:  sudo python3 collect_metadata.py --iface gw-eth0 gw-eth1 --backend tshark --duration 120 --out features.csv

Chi dem chieu VAO (ingress) cua Gateway de moi goi khong bi dem hai lan (xem README muc 7).
Moi dong CSV = 1 cua so 1 giay: window_start (epoch giay), 4 dac trung loi + 3 dac trung bo sung.
"""
import argparse
import csv
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import CSV_COLUMNS, WindowAggregator, parse_frame  # noqa: E402

PACKET_OUTGOING = 4   # pkttype cua Linux: goi do chinh may nay gui ra -> bo qua


def make_writer(path):
    f = open(path, 'w', newline='')
    w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
    w.writeheader()

    def write(row):
        w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in row.items()})
        f.flush()
    return write, f


def read_pcaps(paths, agg):
    """Doc nhieu file pcap, tron theo thoi gian roi dua vao bo gom cua so."""
    from scapy.utils import RawPcapReader
    packets = []
    for p in paths:
        for raw, meta in RawPcapReader(p):
            ts = meta.sec + (meta.usec / (1e9 if getattr(meta, 'tsresol', 1000000) == 1000000000 else 1e6))
            parsed = parse_frame(raw)
            if parsed:
                packets.append((ts,) + parsed)
    packets.sort(key=lambda x: x[0])
    for ts, src, length, proto, syn in packets:
        agg.add(ts, src, length, proto, syn)
    agg.close()
    return len(packets)


def sniff_raw(ifaces, duration, agg):
    """Bat truc tiep bang socket AF_PACKET (Linux, can root). Socket tra ve huong goi
    (PACKET_OUTGOING) nen loc duoc chieu ra, moi goi chi dem mot lan. Nhanh hon sniff() cua Scapy."""
    import select
    import socket
    socks = {}
    for i in ifaces:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))   # ETH_P_ALL
        s.bind((i, 0))
        s.setblocking(False)
        socks[s] = i
    end = time.time() + duration
    while True:
        now = time.time()
        if now >= end:
            break
        ready, _, _ = select.select(list(socks), [], [], 0.2)
        for s in ready:
            try:
                while True:
                    raw, addr = s.recvfrom(65535)
                    if addr[2] == PACKET_OUTGOING:
                        continue
                    parsed = parse_frame(raw)
                    if parsed:
                        agg.add(time.time(), *parsed)
            except BlockingIOError:
                pass
        agg.flush_until(time.time() - 0.5)
    agg.flush_until(end + 1)
    agg.close()


def sniff_tshark(ifaces, duration, agg):
    """tshark nhanh hon Scapy khi toc do goi cao. Dung bo loc 'inbound' de chi lay chieu vao."""
    cmd = ['tshark', '-l', '-n', '-f', 'inbound', '-a', 'duration:%d' % duration,
           '-T', 'fields', '-E', 'separator=,',
           '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.len', '-e', 'ip.proto', '-e', 'tcp.flags']
    for i in ifaces:
        cmd += ['-i', i]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        parts = line.strip().split(',')
        if len(parts) < 4 or not parts[1]:
            continue
        try:
            ts = float(parts[0])
            a, b, c, d = (int(x) for x in parts[1].split('.'))
            src = (a << 24) | (b << 16) | (c << 8) | d
            length, proto = int(parts[2]), int(parts[3])
            flags = int(parts[4], 16) if len(parts) > 4 and parts[4] else 0
        except ValueError:
            continue
        agg.add(ts, src, length, proto, 1 if (flags & 0x12) == 0x02 else 0)
    agg.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--pcap', nargs='+', help='file pcap de doc offline')
    src.add_argument('--iface', nargs='+', help='giao dien de bat truc tiep, vi du gw-eth0 gw-eth1')
    ap.add_argument('--backend', choices=['raw', 'tshark'], default='raw')
    ap.add_argument('--duration', type=int, default=60, help='so giay bat (che do truc tiep)')
    ap.add_argument('--out', required=True, help='file CSV dau ra')
    a = ap.parse_args()

    write, fh = make_writer(a.out)
    agg = WindowAggregator(write)
    if a.pcap:
        n = read_pcaps(a.pcap, agg)
        print('Da doc %d goi IPv4 tu %d file pcap' % (n, len(a.pcap)))
    elif a.backend == 'tshark':
        sniff_tshark(a.iface, a.duration, agg)
    else:
        sniff_raw(a.iface, a.duration, agg)
    fh.close()
    print('Da ghi', a.out)


if __name__ == '__main__':
    main()
