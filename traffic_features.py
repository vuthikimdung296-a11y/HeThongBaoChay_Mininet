#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trich xuat dac trung theo luong 1 giay tu PCAP da thu thap de huan luyen Edge AI."""
import argparse
import csv
import os
from collections import defaultdict
from datetime import datetime, timezone


FIELDS = [
    'window_start_utc', 'src_ip', 'dst_ip', 'protocol',
    'src_port', 'dst_port', 'packets', 'bytes', 'mean_packet_bytes', 'label',
]
PROTOCOLS = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


def extract_features(pcap_path, csv_path, label):
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise SystemExit('Thieu Scapy. Cai bang: pip3 install -r requirements.txt') from exc

    flows = defaultdict(lambda: [0, 0])
    reader = PcapReader(pcap_path)
    try:
        for packet in reader:
            if IP not in packet:
                continue
            timestamp = int(float(packet.time))
            protocol_number = int(packet[IP].proto)
            source_port = destination_port = ''
            if TCP in packet:
                source_port, destination_port = int(packet[TCP].sport), int(packet[TCP].dport)
            elif UDP in packet:
                source_port, destination_port = int(packet[UDP].sport), int(packet[UDP].dport)
            elif ICMP not in packet:
                continue

            key = (
                timestamp, packet[IP].src, packet[IP].dst,
                PROTOCOLS.get(protocol_number, str(protocol_number)),
                source_port, destination_port,
            )
            flows[key][0] += 1
            flows[key][1] += len(packet)
    finally:
        reader.close()

    file_exists = os.path.exists(csv_path) and os.path.getsize(csv_path) > 0
    if file_exists:
        with open(csv_path, 'r', newline='', encoding='utf-8') as existing:
            if next(csv.reader(existing), []) != FIELDS:
                raise ValueError('CSV da ton tai nhung header khong dung schema: %s' % csv_path)

    with open(csv_path, 'a', newline='', encoding='utf-8') as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        if not file_exists:
            writer.writeheader()
        for key in sorted(flows):
            window, src, dst, protocol, src_port, dst_port = key
            packets, byte_count = flows[key]
            writer.writerow({
                'window_start_utc': datetime.fromtimestamp(window, timezone.utc).isoformat(),
                'src_ip': src,
                'dst_ip': dst,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'packets': packets,
                'bytes': byte_count,
                'mean_packet_bytes': round(byte_count / packets, 2),
                'label': label,
            })
    return len(flows)


def main():
    parser = argparse.ArgumentParser(
        description='Trich xuat dac trung IPv4 theo luong 1 giay tu PCAP da thu thap'
    )
    parser.add_argument('--pcap', required=True, help='Duong dan PCAP da thu thap')
    parser.add_argument('--label', required=True, choices=['normal', 'attack', 'unknown'],
                        help='Nhan cua kich ban da duoc capture')
    parser.add_argument('--csv', default='ai_features.csv', help='CSV dau ra (mac dinh: ai_features.csv)')
    args = parser.parse_args()

    count = extract_features(args.pcap, args.csv, args.label)
    print('Da ghi %d flow-window tu %s vao %s (label=%s).' %
          (count, args.pcap, args.csv, args.label))


if __name__ == '__main__':
    main()
