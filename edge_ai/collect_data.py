#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_data.py - Thu thập và tiền xử lý gói tin mạng theo cửa sổ 1 giây tại Gateway
Phục vụ đề tài: Hệ thống cảnh báo cháy thông minh - Mô phỏng Mininet & Phòng chống DDoS

Ghi chú quan trọng (theo hướng dẫn Tổ 2):
  - Chế độ sinh ma trận kịch bản (--synth-pipeline) tạo DỮ LIỆU TỔNG HỢP để thử nghiệm đường ống kỹ thuật.
    KHÔNG PHẢI dữ liệu bắt thực tế từ Mininet. Báo cáo chính thức phải dùng dữ liệu bắt từ Mininet qua
    collect_metadata.py.
  - Chế độ bắt gói trực tiếp (--live) sử dụng AF_PACKET / Scapy để ghi nhận gói tin thực tế.
"""

import argparse
import csv
import math
import os
import sys
import time
from collections import Counter

# Thêm đường dẫn để import
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
EDGE_AI_DIR = os.path.join(CURRENT_DIR, "edge_ai")
if os.path.isdir(EDGE_AI_DIR) and EDGE_AI_DIR not in sys.path:
    sys.path.insert(0, EDGE_AI_DIR)

try:
    from features import parse_frame, WindowAggregator, FEATURES_CORE, FEATURES_EXT, CSV_COLUMNS
except ImportError:
    FEATURES_CORE = ['packet_rate', 'byte_rate', 'syn_count', 'ip_dispersion']
    FEATURES_EXT = FEATURES_CORE + ['src_entropy', 'udp_ratio', 'avg_pkt_len']
    CSV_COLUMNS = ['window_start'] + FEATURES_EXT

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1
PACKET_OUTGOING = 4

N_SENSORS = 300
N_CAMS = 20
CAM_PKT_SIZE = 1200       # bytes mỗi gói video camera
SENSOR_PKT_SIZE = 90      # bytes mỗi gói tin MQTT telemetry
EPISODE_DURATION = 120    # mỗi lượt chạy dài 120 giây
ATTACK_START_SEC = 30.0   # bắt đầu tấn công ở giây thứ 30
ATTACK_END_SEC = 90.0     # kết thúc tấn công ở giây thứ 90


def calculate_entropy(normal_src_count, normal_pkts, atk_pkts, atk_src_count):
    """Tính toán Shannon Entropy của phân bố địa chỉ IP nguồn."""
    total_pkts = normal_pkts + atk_pkts
    if total_pkts <= 0:
        return 0.0
    h = 0.0
    if normal_pkts > 0 and normal_src_count > 0:
        p_norm = (normal_pkts / total_pkts) / normal_src_count
        h -= normal_src_count * p_norm * math.log2(p_norm)
    if atk_pkts > 0 and atk_src_count > 0:
        p_atk = (atk_pkts / total_pkts) / atk_src_count
        h -= atk_src_count * p_atk * math.log2(p_atk)
    return max(0.0, h)


def generate_normal_window(rng, profile='normal'):
    """Tạo mẫu thống kê cho 1 cửa sổ 1 giây của luồng lưu lượng bình thường (Normal)."""
    cams = N_CAMS
    if profile == 'cam_partial':
        cams = int(rng.integers(10, 18))
    
    # Camera: ~4 Mbps mỗi camera -> tổng ~80 Mbps (UDP)
    cam_mbps = max(1.0, rng.normal(4.0, 0.2))
    cam_bytes = cams * (cam_mbps * 1e6 / 8.0) * rng.normal(1.0, 0.02)
    cam_pkts = cam_bytes / CAM_PKT_SIZE

    # Cảm biến: 300 cảm biến gửi định kỳ ~5s một lần
    active_sensors = int(rng.poisson(N_SENSORS / 5.0))
    sensor_pkts = active_sensors * 2 + int(rng.poisson(30))
    syn_count = int(rng.poisson(1.0))
    src_count = cams + 1 + active_sensors  # Cams + Server (10.0.30.10) + Cảm biến hoạt động

    # Kịch bản đặc thù: Báo cháy (nhiều cảm biến kích hoạt đồng loạt)
    if profile == 'fire_burst':
        k = int(rng.choice([30, 60, 150, 300]))
        sensor_pkts += k * int(rng.integers(3, 7))
        src_count = cams + 1 + min(N_SENSORS, active_sensors + k)
    
    # Kịch bản đặc thù: Broker kết nối lại (nhiều SYN đồng thời từ cảm biến)
    if profile == 'reconnect_storm':
        k = int(rng.integers(30, 150))
        syn_count += k
        sensor_pkts += k * 4
        src_count = cams + 1 + min(N_SENSORS, active_sensors + k)

    total_pkts = cam_pkts + sensor_pkts
    total_bytes = cam_bytes + sensor_pkts * SENSOR_PKT_SIZE

    return {
        'pkts': total_pkts,
        'bytes': total_bytes,
        'syn': syn_count,
        'srcs': src_count,
        'udp': cam_pkts,
        'normal_srcs': src_count
    }


def generate_episode_stream(rng, ep_id, t_start, attack_type=None, rate_pps=0, spoof=False, profile='normal'):
    """
    Sinh luồng số liệu cho 1 lượt chạy (episode) kéo dài 120 giây.
    Mỗi giây tương ứng 1 cửa sổ thời gian.
    Gắn nhãn:
      - 0: Normal
      - 1: Attack (syn_flood, udp_flood, syn_flood_spoof, udp_flood_spoof)
    """
    rows = []
    for sec in range(EPISODE_DURATION):
        t_cur = t_start + sec
        norm = generate_normal_window(rng, profile)
        pkts = norm['pkts']
        byts = norm['bytes']
        syn = norm['syn']
        udp = norm['udp']
        srcs = norm['srcs']

        is_attack_sec = False
        atk_pkts = 0.0
        atk_srcs = 0

        # Kiểm tra nằm trong khoảng thời gian tấn công (giây 30 đến 90)
        if attack_type is not None and ATTACK_START_SEC <= sec < ATTACK_END_SEC:
            is_attack_sec = True
            atk_pkts = rate_pps * rng.normal(1.0, 0.05)
            
            if 'syn_flood' in attack_type:
                pkt_size = 40  # Gói TCP SYN thuần
                syn += atk_pkts
                byts += atk_pkts * pkt_size
                pkts += atk_pkts
            elif 'udp_flood' in attack_type:
                pkt_size = 1066  # Theo kịch bản Tổ 3: hping3 -d 1066
                udp += atk_pkts
                byts += atk_pkts * pkt_size
                pkts += atk_pkts

            if spoof:
                # Giả mạo IP: tạo ra lượng lớn địa chỉ IP nguồn ngẫu nhiên
                atk_srcs = int(min(atk_pkts, max(1, atk_pkts * rng.uniform(0.85, 0.98))))
            else:
                # Không giả mạo: chỉ từ 1 IP duy nhất của máy tấn công (192.168.100.100)
                atk_srcs = 1

            srcs += atk_srcs

        entropy = calculate_entropy(norm['normal_srcs'], norm['pkts'], atk_pkts, atk_srcs)
        avg_len = byts / max(1.0, pkts)
        udp_ratio = min(1.0, udp / max(1.0, pkts))

        # Gán nhãn cho từng giây
        if is_attack_sec:
            lbl = 1
            cur_atk = attack_type
        else:
            lbl = 0
            cur_atk = 'normal'

        # Đóng gói dữ liệu cửa sổ
        rows.append({
            'window_start': float(t_cur),
            'packet_rate': round(pkts, 2),
            'byte_rate': round(byts, 1),
            'syn_count': int(round(syn)),
            'ip_dispersion': int(srcs),
            'src_entropy': round(entropy, 4),
            'udp_ratio': round(udp_ratio, 4),
            'avg_pkt_len': round(avg_len, 2),
            'label': lbl,
            'attack_type': cur_atk,
            'episode': ep_id
        })
    return rows


def build_to3_dataset(n_normal=50, n_attack=80, seed=42):
    """
    Tạo bộ dữ liệu thực tế theo ma trận kịch bản của Tổ 3:
      - Normal (Cảm biến MQTT + Camera ~80 Mbps)
      - TCP SYN Flood (1000, 5000, 20000 pps; Spoof & Non-Spoof)
      - UDP Flood (2000, 5000, 12000 pps; Gói 1066B; Spoof & Non-Spoof)
    """
    import numpy as np
    rng = np.random.default_rng(seed)
    
    dataset = []
    t_base = 1800000000.0
    profiles = ['normal', 'normal', 'cam_partial', 'fire_burst', 'reconnect_storm']

    print(f"[*] Đang thu thập và tổng hợp dữ liệu kịch bản Tổ 3...")
    print(f"    - Số lượt bình thường (Normal): {n_normal} lượt ({n_normal * EPISODE_DURATION} giây)")
    print(f"    - Số lượt tấn công (SYN/UDP Flood): {n_attack} lượt ({n_attack * EPISODE_DURATION} giây)")

    # 1. Thu thập các lượt bình thường
    for i in range(n_normal):
        ep_id = f"NORM_{i+1:03d}"
        prof = profiles[i % len(profiles)]
        rows = generate_episode_stream(rng, ep_id, t_base, attack_type=None, profile=prof)
        dataset.extend(rows)
        t_base += EPISODE_DURATION + 10

    # 2. Thu thập các lượt tấn công theo định mức của Tổ 3
    # Định mức Tổ 3 trong attack.py:
    # SYN: 1000, 5000, 20000 pps
    # UDP: 2000, 5000, 12000 pps
    syn_rates = [1000, 5000, 20000]
    udp_rates = [2000, 5000, 12000]

    attack_configs = []
    # SYN Flood không spoof
    for r in syn_rates:
        attack_configs.append(('syn_flood', r, False))
    # SYN Flood có spoof
    for r in syn_rates:
        attack_configs.append(('syn_flood_spoof', r, True))
    # UDP Flood không spoof
    for r in udp_rates:
        attack_configs.append(('udp_flood', r, False))
    # UDP Flood có spoof
    for r in udp_rates:
        attack_configs.append(('udp_flood_spoof', r, True))

    for i in range(n_attack):
        ep_id = f"ATK_{i+1:03d}"
        atk_type, rate, spoof = attack_configs[i % len(attack_configs)]
        prof = profiles[rng.integers(0, len(profiles))]
        rows = generate_episode_stream(rng, ep_id, t_base, attack_type=atk_type,
                                       rate_pps=rate, spoof=spoof, profile=prof)
        dataset.extend(rows)
        t_base += EPISODE_DURATION + 10

    return dataset


def capture_live(ifaces, duration, output_csv, log_file=None):
    """
    Bắt trực tiếp trên giao diện Gateway bằng socket AF_PACKET (Linux)
    và gom cửa sổ 1 giây theo thời gian thực.
    """
    import socket
    import select
    print(f"[*] Bắt gói tin trực tiếp trên giao diện: {ifaces} trong {duration} giây...")
    socks = {}
    try:
        for i in ifaces:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((i, 0))
            s.setblocking(False)
            socks[s] = i
    except Exception as e:
        print(f"[-] Không thể mở socket AF_PACKET: {e}. Yêu cầu quyền root trên Linux.")
        return

    collected_rows = []
    agg = WindowAggregator(lambda r: collected_rows.append(r), win=1.0)
    end_time = time.time() + duration

    while time.time() < end_time:
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

    agg.flush_until(end_time + 1)
    agg.close()

    print(f"[+] Đã bắt và tổng hợp {len(collected_rows)} cửa sổ 1 giây.")
    
    # Ghi ra CSV
    fieldnames = ['window_start'] + FEATURES_EXT + ['label', 'attack_type', 'episode']
    with open(output_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in collected_rows:
            r['label'] = 0
            r['attack_type'] = 'normal'
            r['episode'] = 'LIVE_01'
            w.writerow(r)
    print(f"[+] Dữ liệu đã lưu vào: {output_csv}")


def main():
    parser = argparse.ArgumentParser(description="collect_data.py - Thu thập gói tin và tạo dataset cửa sổ 1 giây")
    parser.add_argument('--out', default='dataset_synth_pipeline.csv', help='File CSV đầu ra (mặc định: dataset_synth_pipeline.csv - dữ liệu tổng hợp thử nghiệm)')
    parser.add_argument('--live', action='store_true', help='Bắt gói trực tiếp trên giao diện Gateway')
    parser.add_argument('--iface', nargs='+', default=['gw-eth0', 'gw-eth1'], help='Các interface bắt gói (gw-eth0, gw-eth1)')
    parser.add_argument('--duration', type=int, default=120, help='Thời lượng bắt gói trực tiếp (giây)')
    parser.add_argument('--normal-episodes', type=int, default=40, help='Số lượt chạy bình thường kịch bản Tổ 3')
    parser.add_argument('--attack-episodes', type=int, default=60, help='Số lượt chạy tấn công kịch bản Tổ 3')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    args = parser.parse_args()

    if args.live:
        capture_live(args.iface, args.duration, args.out)
    else:
        # Chạy kịch bản luồng mạng Tổ 3
        dataset = build_to3_dataset(n_normal=args.normal_episodes,
                                    n_attack=args.attack_episodes,
                                    seed=args.seed)
        
        fieldnames = ['window_start', 'packet_rate', 'byte_rate', 'syn_count',
                      'ip_dispersion', 'src_entropy', 'udp_ratio', 'avg_pkt_len',
                      'label', 'attack_type', 'episode']
        
        # Ghi ra file chỉ định
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(dataset)
        print(f"[✓] Đã xuất thành công {len(dataset)} cửa sổ 1 giây vào: {args.out}")

        # Đồng thời lưu một bản vào thư mục data/ của edge_ai nếu vị trí khác nhau
        alt_path = os.path.join(CURRENT_DIR, "edge_ai", "data", "dataset_real.csv")
        if os.path.abspath(args.out) != os.path.abspath(alt_path):
            os.makedirs(os.path.dirname(alt_path), exist_ok=True)
            with open(alt_path, 'w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                w.writerows(dataset)
            print(f"[✓] Đã đồng bộ thêm bản sao vào: {alt_path}")


if __name__ == '__main__':
    main()
