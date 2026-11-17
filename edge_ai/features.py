# -*- coding: utf-8 -*-
"""features.py - Trich dac trung tu HEADER METADATA theo cua so 1 giay.

Chi dung truong header (IP nguon, do dai IP, giao thuc, co SYN), khong doc payload.
4 dac trung loi theo de cuong: packet_rate, byte_rate, syn_count, ip_dispersion.
3 dac trung bo sung (de so sanh): src_entropy, udp_ratio, avg_pkt_len.
"""
import math
import threading
from collections import Counter

FEATURES_CORE = ['packet_rate', 'byte_rate', 'syn_count', 'ip_dispersion']
FEATURES_EXT = FEATURES_CORE + ['src_entropy', 'udp_ratio', 'avg_pkt_len']
CSV_COLUMNS = ['window_start'] + FEATURES_EXT

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1


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

    def _flush_current(self):
        n = self.pkts
        if n:
            total = float(n)
            entropy = max(0.0, -sum((c / total) * math.log2(c / total) for c in self.srcs.values()))
            row = {'packet_rate': n / self.win, 'byte_rate': self.bytes / self.win,
                   'syn_count': self.syn, 'ip_dispersion': len(self.srcs),
                   'src_entropy': entropy, 'udp_ratio': self.udp / total,
                   'avg_pkt_len': self.bytes / total}
        else:
            row = {k: 0 for k in FEATURES_EXT}
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
