# -*- coding: utf-8 -*-
"""features.py - Trich dac trung tu HEADER METADATA theo cua so 1 giay.

Chi dung truong header (IP nguon, do dai IP, giao thuc, co SYN), khong doc payload.
4 dac trung loi theo de cuong: packet_rate, byte_rate, syn_count, ip_dispersion.
3 dac trung bo sung (de so sanh): src_entropy, udp_ratio, avg_pkt_len.
"""
import math
import threading
import ipaddress
from collections import Counter

FEATURES_CORE = ['packet_rate', 'byte_rate', 'syn_count', 'ip_dispersion']
FEATURES_EXT = FEATURES_CORE + ['src_entropy', 'udp_ratio', 'avg_pkt_len']
EXTRA_ROW_KEYS = ['top_src_ip', 'top_src_ips', 'ext_packet_rate', 'ext_byte_rate', 'top_ext_share']
CSV_COLUMNS = ['window_start'] + FEATURES_EXT

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

# Các dải mạng nội bộ an toàn (dạng (network_int, mask_int) để lọc nhanh theo từng gói)
_INTERNAL_NETS = [
    (int(ipaddress.IPv4Address('10.0.10.0')), 0xFFFFFE00),       # 10.0.10.0/23 (VLAN 10 - Cảm biến)
    (int(ipaddress.IPv4Address('10.0.20.0')), 0xFFFFFF00),       # 10.0.20.0/24 (VLAN 20 - Camera)
    (int(ipaddress.IPv4Address('10.0.30.0')), 0xFFFFFF00),       # 10.0.30.0/24 (VLAN 30 - Máy chủ MQTT)
    (int(ipaddress.IPv4Address('192.168.100.1')), 0xFFFFFFFF),   # IP Gateway gw-eth1
    (int(ipaddress.IPv4Address('127.0.0.0')), 0xFF000000),       # Loopback nội bộ
]


def _is_internal_src(src_val):
    if not isinstance(src_val, int):
        try:
            src_val = int(ipaddress.IPv4Address(str(src_val)))
        except ValueError:
            return False
    return any((src_val & mask) == net for net, mask in _INTERNAL_NETS)


def _fmt_ip(src_val):
    if isinstance(src_val, int):
        return str(ipaddress.IPv4Address(src_val))
    return str(src_val)


def parse_frame(raw):
    """Phan tich khung Ethernet (co hoac khong co tag VLAN 802.1Q/802.1ad).
    Tra ve (src_ip_int, ip_total_len, proto, is_syn) hoac None neu khong phai IPv4.
    is_syn = 1 chi khi co SYN va khong co ACK (goi mo ket noi moi)."""
    n = len(raw)
    if n < 34:
        return None
    ethertype = (raw[12] << 8) | raw[13]
    off = 14
    while ethertype in (0x8100, 0x88A8) and n >= off + 4:
        ethertype = (raw[off + 2] << 8) | raw[off + 3]
        off += 4
    if ethertype != 0x0800 or n < off + 20:
        return None
    ihl = (raw[off] & 0x0F) * 4
    total_len = (raw[off + 2] << 8) | raw[off + 3]
    proto = raw[off + 9]
    src = int.from_bytes(raw[off + 12:off + 16], 'big')
    syn = 0
    if proto == PROTO_TCP and n >= off + ihl + 14:
        flags = raw[off + ihl + 13]
        syn = 1 if (flags & 0x12) == 0x02 else 0
    return src, total_len, proto, syn


class WindowAggregator:
    """Gom goi tin vao cac cua so 1 giay; khi cua so dong, goi on_window(row).
    Cua so rong (khong co goi) van duoc phat ra voi gia tri 0."""

    def __init__(self, on_window, win=1.0):
        self.on_window = on_window
        self.win = win
        self.cur = None
        self._reset()
        self._lock = threading.Lock()

    def _reset(self):
        self.pkts = 0
        self.bytes = 0
        self.syn = 0
        self.udp = 0
        self.srcs = Counter()
        self.ext_pkts = 0
        self.ext_bytes = 0
        self.ext_srcs = Counter()

    def _flush_current(self):
        n = self.pkts
        if n:
            total = float(n)
            entropy = max(0.0, -sum((c / total) * math.log2(c / total) for c in self.srcs.values()))
            ranked_ips = [_fmt_ip(ip) for ip, _ in self.srcs.most_common(5)]
            ext_ranked = [(_fmt_ip(ip), cnt) for ip, cnt in self.ext_srcs.most_common(5)]
            top_ext_ip = ext_ranked[0][0] if ext_ranked else None
            top_ext_share = (ext_ranked[0][1] / float(self.ext_pkts)) if (ext_ranked and self.ext_pkts > 0) else 0.0

            row = {'packet_rate': n / self.win, 'byte_rate': self.bytes / self.win,
                   'syn_count': self.syn, 'ip_dispersion': len(self.srcs),
                   'src_entropy': entropy, 'udp_ratio': self.udp / total,
                   'avg_pkt_len': self.bytes / total,
                   'top_src_ip': top_ext_ip if top_ext_ip else (ranked_ips[0] if ranked_ips else None),
                   'top_src_ips': [ip for ip, _ in ext_ranked] if ext_ranked else ranked_ips,
                   'ext_packet_rate': self.ext_pkts / self.win,
                   'ext_byte_rate': self.ext_bytes / self.win,
                   'top_ext_share': top_ext_share}
        else:
            row = {k: 0 for k in FEATURES_EXT}
            row['top_src_ip'] = None
            row['top_src_ips'] = []
            row['ext_packet_rate'] = 0.0
            row['ext_byte_rate'] = 0.0
            row['top_ext_share'] = 0.0
        row['window_start'] = self.cur * self.win
        self._reset()
        self.on_window(row)

    def _advance_to(self, w):
        if self.cur is None:
            self.cur = w
            return
        while w > self.cur:
            self._flush_current()
            self.cur += 1

    def add(self, ts, src, length, proto, syn):
        with self._lock:
            self._advance_to(int(ts // self.win))
            self.pkts += 1
            self.bytes += length
            self.syn += syn
            if proto == PROTO_UDP:
                self.udp += 1
            self.srcs[src] += 1
            if not _is_internal_src(src):
                self.ext_pkts += 1
                self.ext_bytes += length
                self.ext_srcs[src] += 1

    def flush_until(self, now):
        """Dong cac cua so da ket thuc truoc thoi diem `now` (dung khi chay truc tuyen
        de khong bi ket khi mang im lang)."""
        with self._lock:
            if self.cur is not None:
                self._advance_to(int(now // self.win))

    def close(self):
        with self._lock:
            if self.cur is not None:
                self._flush_current()
                self.cur = None
