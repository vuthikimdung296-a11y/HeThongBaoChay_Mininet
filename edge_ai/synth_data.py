# -*- coding: utf-8 -*-
"""synth_data.py - SINH DU LIEU MO PHONG THONG KE (thay tam khi chua co luu luong that tu Mininet/Tổ 3).

KHONG phai du lieu do tu mang that. Moi cua so 1 giay duoc sinh tu mo hinh thong ke co tham so lay tu README:
  - 300 cam bien MQTT (10 host x 30 IP), moi cam bien gui ban tin ~ 5 giay/lan
  - 20 camera, ~4 Mbps/camera (UDP, goi ~1200 byte) -> ~10 MB/s di qua Gateway
  - ke tan cong 'atk' o mang ngoai (192.168.100.100), qua gw-eth1
Co chu y tao cac truong hop KHO de khong qua de dang:
  - luu luong binh thuong dot bien: bao chay (nhieu cam bien cung gui), ket noi lai hang loat (nhieu SYN),
    camera tat bot
  - tan cong cuong do thap (SYN flood / UDP flood vai tram goi/giay) tron vao luu luong nen
Dau ra: features CSV (kem cot episode) + nhat ky tan cong CSV -> dua vao build_dataset.py nhu du lieu that.
Khi co pcap that, thay buoc nay bang collect_metadata.py; phan con lai cua pipeline giu nguyen.
"""
import argparse
import csv
import math
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import CSV_COLUMNS  # noqa: E402

N_SENSORS, N_CAMS = 300, 20
CAM_PKT = 1200            # byte/goi camera
SENSOR_PKT = 90           # byte/goi MQTT (IP length)
CAPTURE_CAP_PPS = 60000   # nang luc bat goi toi da cua may ao (vuot qua thi mat goi)
EP_LEN = 120              # do dai moi luot chay (giay)
ATK_START, ATK_END = 30.4, 90.7   # tan cong chay tu giay 30.4 toi 90.7 (le 0.x de co cua so o bien)

ATTACKS = ['syn_flood', 'syn_flood_spoof', 'udp_flood', 'udp_flood_spoof']


def entropy_from(counts_n_src_normal, normal_pkts, atk_pkts, atk_srcs):
    """Entropy nguon xap xi: goi binh thuong chia deu cho cac IP, goi tan cong chia deu cho atk_srcs IP."""
    tot = normal_pkts + atk_pkts
    if tot <= 0:
        return 0.0
    h = 0.0
    if normal_pkts > 0 and counts_n_src_normal > 0:
        p = (normal_pkts / tot) / counts_n_src_normal
        h -= counts_n_src_normal * p * math.log2(p)
    if atk_pkts > 0 and atk_srcs > 0:
        p = (atk_pkts / tot) / atk_srcs
        h -= atk_srcs * p * math.log2(p)
    return h


def normal_window(rng, profile):
    """Dac trung cua mot cua so luu luong binh thuong (chua co tan cong)."""
    cams = N_CAMS
    if profile == 'cam_partial':
        cams = int(rng.integers(5, 16))
    cam_mbps = max(0.5, rng.normal(4.0, 0.25))                     # moi camera
    cam_bytes = cams * cam_mbps * 1e6 / 8 * rng.normal(1.0, 0.03)
    cam_pkts = cam_bytes / CAM_PKT
    active_sensors = rng.poisson(N_SENSORS / 5.0)                  # cam bien gui trong giay nay
    sensor_pkts = active_sensors * 2 + rng.poisson(40)             # ban tin + ACK + ping MQTT
    syn = rng.poisson(1.0)
    srcs = cams + 1 + active_sensors                               # camera + srv + cam bien
    if profile == 'fire_burst':                                    # bao chay: mot tang (30) toi ca toa nha cung gui
        k = int(rng.choice([30, 30, 60, 150, 300]))
        sensor_pkts += k * rng.integers(2, 6)
        srcs = cams + 1 + min(N_SENSORS, active_sensors + k)
    if profile == 'reconnect_storm':                               # broker khoi dong lai: nhieu cam bien dung ket noi TCP lai
        k = int(rng.integers(20, 160))
        syn += k
        sensor_pkts += k * 4
        srcs = cams + 1 + min(N_SENSORS, active_sensors + k)
    pkts = cam_pkts + sensor_pkts
    byts = cam_bytes + sensor_pkts * SENSOR_PKT
    return dict(pkts=pkts, bytes=byts, syn=syn, srcs=srcs, udp=cam_pkts, normal_srcs=srcs)


def attack_contribution(rng, kind, frac, ramp):
    """Dong gop cua tan cong trong cua so (gioi han phu hop voi MAX_RATE_PPS = 5000 cua traffic/attack.py)."""
    lo, hi = {'syn_flood': (500, 5000), 'syn_flood_spoof': (500, 5000),
              'udp_flood': (500, 5000), 'udp_flood_spoof': (500, 5000)}[kind]
    return lo, hi


def synth_episode(rng, ep_id, t0, attack_kind=None, rate=None, profile='normal'):
    rows = []
    for sec in range(EP_LEN):
        t = t0 + sec
        w = normal_window(rng, profile)
        pkts, byts, syn, srcs, udp = w['pkts'], w['bytes'], w['syn'], w['srcs'], w['udp']
        atk_pkts, atk_srcs = 0.0, 0
        if attack_kind:
            frac = max(0.0, min(t + 1, t0 + ATK_END) - max(t, t0 + ATK_START))
            if frac > 0:
                ramp = min(1.0, 0.4 + 0.3 * (t - (t0 + ATK_START)) / 1.0) if t - (t0 + ATK_START) < 2 else 1.0
                atk_pkts = rate * rng.normal(1.0, 0.08) * ramp * frac
                spoof = attack_kind.endswith('spoof')
                if attack_kind.startswith('syn'):
                    size, syn_add, udp_add = 40, atk_pkts, 0
                elif attack_kind.startswith('udp'):
                    size, syn_add, udp_add = 1200 if rng.random() < 0.7 else 60, 0, atk_pkts
                else:
                    size, syn_add, udp_add = 84, 0, 0
                atk_srcs = max(1, int(atk_pkts)) if spoof else 1
                if spoof:
                    atk_srcs = int(min(atk_pkts, atk_pkts * rng.uniform(0.85, 1.0)))
                    atk_srcs = max(atk_srcs, 1)
                pkts += atk_pkts
                byts += atk_pkts * size
                syn += syn_add
                udp += udp_add
                srcs += atk_srcs
        scale = 1.0
        if pkts > CAPTURE_CAP_PPS:                                  # mat goi khi bat qua nhanh
            scale = CAPTURE_CAP_PPS / pkts
        pkts_o, byts_o = pkts * scale, byts * scale
        syn_o = syn * (scale if atk_pkts > 0 else 1.0)
        srcs_o = int(min(srcs, pkts_o))
        h = entropy_from(w['normal_srcs'], w['pkts'], atk_pkts * scale, atk_srcs)
        rows.append({'window_start': float(t), 'packet_rate': round(pkts_o, 2), 'byte_rate': round(byts_o, 1),
                     'syn_count': int(round(syn_o)), 'ip_dispersion': srcs_o,
                     'src_entropy': round(h, 4), 'udp_ratio': round(min(1.0, udp * scale / max(pkts_o, 1)), 4),
                     'avg_pkt_len': round(byts_o / max(pkts_o, 1), 2), 'episode': ep_id})
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out-features', default='data/features_synth.csv')
    ap.add_argument('--out-log', default='data/attack_log_synth.csv')
    ap.add_argument('--normal-episodes', type=int, default=60)
    ap.add_argument('--attack-episodes', type=int, default=100)
    ap.add_argument('--seed', type=int, default=42)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    os.makedirs(os.path.dirname(a.out_features) or '.', exist_ok=True)

    rows, log = [], []
    t0 = 1_800_000_000.0
    profiles = ['normal', 'normal', 'cam_partial', 'fire_burst', 'reconnect_storm']
    for i in range(a.normal_episodes):
        ep = 'C%03d' % (i + 1)
        rows += synth_episode(rng, ep, t0, profile=profiles[i % len(profiles)])
        t0 += EP_LEN + 10
    for i in range(a.attack_episodes):
        ep = 'D%03d' % (i + 1)
        kind = ATTACKS[i % len(ATTACKS)]
        lo, hi = attack_contribution(rng, kind, 1, 1)
        rate = float(np.exp(rng.uniform(math.log(lo), math.log(hi))))    # cuong do phan bo log-deu
        profile = profiles[int(rng.integers(0, len(profiles)))]
        rows += synth_episode(rng, ep, t0, attack_kind=kind, rate=rate, profile=profile)
        log.append({'episode': ep, 'start': t0 + ATK_START, 'end': t0 + ATK_END, 'attack_type': kind,
                    'rate_pps': round(rate)})
        t0 += EP_LEN + 10

    with open(a.out_features, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS + ['episode'])
        w.writeheader()
        w.writerows(rows)
    with open(a.out_log, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['episode', 'start', 'end', 'attack_type', 'rate_pps'])
        w.writeheader()
        w.writerows(log)
    print('Da sinh %d cua so (%d luot C, %d luot D) -> %s, %s' %
          (len(rows), a.normal_episodes, a.attack_episodes, a.out_features, a.out_log))


if __name__ == '__main__':
    main()
