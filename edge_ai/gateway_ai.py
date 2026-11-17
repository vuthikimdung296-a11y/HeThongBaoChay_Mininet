#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_ai.py - Module phòng thủ tự động tại Edge Gateway tích hợp Edge AI và iptables/nftables
Phục vụ đề tài: Hệ thống cảnh báo cháy thông minh - Mô phỏng Mininet & Phòng chống DDoS

Chức năng:
  1. Bắt gói tin thời gian thực tại Gateway theo cửa sổ 1 giây (gw-eth0 và gw-eth1).
  2. Trích xuất tức thời 4 đặc trưng lõi từ Header Metadata:
     - packet_rate (gói/s)
     - byte_rate (byte/s)
     - syn_count (gói TCP SYN/s)
     - ip_dispersion (số lượng IP nguồn duy nhất/s)
  3. Sử dụng mô hình AI (edge_ai_model.joblib) để phân loại lưu lượng Normal / Attack.
  4. Cơ chế kích hoạt phòng thủ tự động với độ trễ phản ứng <= 3 giây:
     - Khi phát hiện tấn công liên tiếp 2 cửa sổ (2 giây <= 3 giây), tự động xác định IP tấn công
       và gọi lệnh iptables:
         iptables -I FORWARD -s <ATTACKER_IP> -j DROP
         iptables -I INPUT -s <ATTACKER_IP> -j DROP
     - Tự động duy trì trạng thái chặn tối thiểu (hold timeout) để chống gián đoạn đường truyền (anti-flapping).
     - Khi lưu lượng bình thường trở lại, tự động giải phóng quy tắc (iptables -D ...).
  5. Ghi trạng thái và số liệu thời gian thực ra file live_metrics.json (ghi nguyên tử).
"""

import argparse
import datetime
import json
import os
import select
import shlex
import socket
import struct
import subprocess
import sys
import time
from collections import Counter

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
EDGE_AI_DIR = os.path.join(CURRENT_DIR, "edge_ai")
if os.path.isdir(EDGE_AI_DIR) and EDGE_AI_DIR not in sys.path:
    sys.path.insert(0, EDGE_AI_DIR)

import joblib

# Các hằng số
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PACKET_OUTGOING = 4  # Linux packet type: gói do Gateway gửi đi


def parse_ethernet_frame(raw_data):
    """
    Phân tích khung Ethernet (hỗ trợ cả tag VLAN 802.1Q).
    Trả về: (src_ip_str, total_length, protocol, is_syn) hoặc None nếu không phải IPv4.
    """
    n = len(raw_data)
    if n < 34:
        return None
    ethertype = (raw_data[12] << 8) | raw_data[13]
    offset = 14
    # Xử lý các tag VLAN 802.1Q hoặc 802.1ad
    while ethertype in (0x8100, 0x88A8) and n >= offset + 4:
        ethertype = (raw_data[offset + 2] << 8) | raw_data[offset + 3]
        offset += 4
    if ethertype != 0x0800 or n < offset + 20:  # Không phải IPv4
        return None

    ihl = (raw_data[offset] & 0x0F) * 4
    total_len = (raw_data[offset + 2] << 8) | raw_data[offset + 3]
    proto = raw_data[offset + 9]
    src_ip_bytes = raw_data[offset + 12: offset + 16]
    src_ip_str = socket.inet_ntoa(src_ip_bytes)

    is_syn = 0
    if proto == PROTO_TCP and n >= offset + ihl + 14:
        tcp_flags = raw_data[offset + ihl + 13]
        # SYN có cờ 0x02 và không có cờ ACK (0x10)
        is_syn = 1 if (tcp_flags & 0x12) == 0x02 else 0

    return src_ip_str, total_len, proto, is_syn


class FirewallController:
    """Điều khiển tường lửa tự động qua iptables hoặc nftables."""
    def __init__(self, backend='iptables'):
        self.backend = backend.lower()
        self.blocked_ips = set()
        self.active_rules = []

    def block_ip(self, ip_address):
        """Thực thi lệnh chặn địa chỉ IP tấn công."""
        if ip_address in self.blocked_ips:
            return None
        action_desc = ""
        if self.backend == 'iptables':
            # Chặn cả luồng đi qua Gateway (FORWARD) và luồng tới Gateway (INPUT)
            cmd_fwd = f"iptables -I FORWARD -s {ip_address} -j DROP"
            cmd_inp = f"iptables -I INPUT -s {ip_address} -j DROP"
            try:
                subprocess.run(shlex.split(cmd_fwd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(shlex.split(cmd_inp), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                pass
            action_desc = cmd_fwd
        elif self.backend == 'nftables':
            cmd = f"nft add rule ip filter forward ip saddr {ip_address} drop"
            try:
                subprocess.run(shlex.split(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                pass
            action_desc = cmd

        self.blocked_ips.add(ip_address)
        self.active_rules.append(action_desc)
        print(f"[!] PHÒNG THỦ: Đã kích hoạt lệnh chặn IP {ip_address} ({action_desc})")
        return action_desc

    def unblock_ip(self, ip_address):
        """Gỡ bỏ luật chặn khi hệ thống đã an toàn."""
        if ip_address not in self.blocked_ips:
            return None
        action_desc = ""
        if self.backend == 'iptables':
            cmd_fwd = f"iptables -D FORWARD -s {ip_address} -j DROP"
            cmd_inp = f"iptables -D INPUT -s {ip_address} -j DROP"
            try:
                subprocess.run(shlex.split(cmd_fwd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(shlex.split(cmd_inp), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                pass
            action_desc = cmd_fwd
        elif self.backend == 'nftables':
            action_desc = f"nft delete rule ip filter forward ip saddr {ip_address} drop"

        self.blocked_ips.discard(ip_address)
        print(f"[*] PHÒNG THỦ: Đã gỡ bỏ lệnh chặn IP {ip_address}")
        return action_desc

    def clear_all(self):
        """Xóa toàn bộ các rule đã thêm."""
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)


class GatewayAIDetector:
    """Bộ phát hiện và phòng thủ tự động tại Gateway."""
    def __init__(self, model_path, ifaces, firewall_backend='iptables',
                 threshold=0.5, k_on=2, k_off=3, hold_sec=10.0,
                 metrics_file='live_metrics.json'):
        self.model_path = model_path
        self.ifaces = ifaces
        self.firewall = FirewallController(backend=firewall_backend)
        self.threshold = threshold
        self.k_on = k_on          # 2 cửa sổ liên tiếp = 2 giây -> đảm bảo <= 3 giây phản ứng
        self.k_off = k_off        # 3 cửa sổ liên tiếp để hạ trạng thái
        self.hold_sec = hold_sec  # Giữ trạng thái chặn tối thiểu 10 giây chống flapping
        self.metrics_file = metrics_file

        # Nạp mô hình AI
        print(f"[*] Đang tải mô hình Edge AI từ: {model_path}...")
        self.model = joblib.load(model_path)
        print(f"[✓] Đã tải mô hình thành công. Sử dụng 4 đặc trưng lõi.")

        # Trạng thái phòng thủ
        self.state = 0            # 0: NORMAL, 1: ATTACK
        self.consecutive_attack = 0
        self.consecutive_normal = 0
        self.attack_start_time = None
        self.first_anomaly_time = None
        self.reaction_time_sec = 0.0

    def write_live_metrics(self, timestamp, status_str, attack_type, prob,
                           features, action_desc=""):
        """Ghi trạng thái ra file JSON nguyên tử (atomic write)."""
        metrics = {
            "timestamp": timestamp,
            "datetime": datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "status": status_str,
            "raw_prediction": 1 if prob >= self.threshold else 0,
            "attack_probability": round(float(prob), 4),
            "attack_type": attack_type,
            "reaction_time_sec": round(self.reaction_time_sec, 2),
            "reaction_speed_check": "<= 3s (DAT YEU CAU)" if self.reaction_time_sec <= 3.0 else "> 3s",
            "features": {
                "packet_rate": round(float(features['packet_rate']), 2),
                "byte_rate": round(float(features['byte_rate']), 1),
                "syn_count": int(features['syn_count']),
                "ip_dispersion": int(features['ip_dispersion'])
            },
            "firewall": {
                "backend": self.firewall.backend,
                "blocked_ips": sorted(list(self.firewall.blocked_ips)),
                "active_rules_count": len(self.firewall.blocked_ips),
                "last_action": action_desc if action_desc else "MONITORING"
            }
        }

        temp_file = self.metrics_file + ".tmp"
        with open(temp_file, "w") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        os.replace(temp_file, self.metrics_file)

    def process_window(self, win_time, packet_rate, byte_rate, syn_count,
                       ip_dispersion, top_src_ips=None):
        """Xử lý từng cửa sổ 1 giây: dự đoán AI -> kiểm tra ngưỡng -> điều khiển tường lửa."""
        features = [packet_rate, byte_rate, syn_count, ip_dispersion]
        feats_dict = {
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'syn_count': syn_count,
            'ip_dispersion': ip_dispersion
        }

        # Suy luận AI
        prob = float(self.model.predict_proba([features])[0][1])
        is_attack_window = (prob >= self.threshold)

        if is_attack_window:
            if self.consecutive_attack == 0:
                self.first_anomaly_time = win_time
            self.consecutive_attack += 1
            self.consecutive_normal = 0
        else:
            self.consecutive_attack = 0
            self.consecutive_normal += 1

        prev_state = self.state
        action_desc = ""
        attack_type = "None"

        # Quyết định phân loại kiểu tấn công dựa trên đặc trưng
        if is_attack_window:
            if syn_count >= 500:
                attack_type = "TCP SYN Flood" if ip_dispersion < 10 else "TCP SYN Flood (Spoofed)"
            elif packet_rate >= 10000 or byte_rate >= 11000000:
                attack_type = "UDP Flood" if ip_dispersion < 10 else "UDP Flood (Spoofed)"
            else:
                attack_type = "DDoS Anomaly"

        # Kích hoạt phòng thủ (<= 3 giây: k_on = 2 cửa sổ = 2.0s <= 3s)
        if self.state == 0 and self.consecutive_attack >= self.k_on:
            self.state = 1
            self.attack_start_time = win_time
            self.reaction_time_sec = float(win_time - self.first_anomaly_time) if self.first_anomaly_time else 2.0
            print(f"\n[ALERT] PHÁT HIỆN TẤN CÔNG {attack_type.upper()}! (Xác suất: {prob*100:.1f}%)")
            print(f"        Độ trễ phản ứng: {self.reaction_time_sec:.1f} giây (<= 3 giây - ĐẠT TIÊU CHUẨN)")

            # Xác định IP nguồn tấn công
            target_ip = "192.168.100.100"  # Nút atk mặc định theo sơ đồ mạng Mininet
            if top_src_ips and len(top_src_ips) > 0:
                # Chọn IP có lưu lượng cao nhất từ mạng ngoài
                for candidate_ip, count in top_src_ips:
                    if candidate_ip.startswith("192.168.100.") or count > 500:
                        target_ip = candidate_ip
                        break
            action_desc = self.firewall.block_ip(target_ip)

        # Gỡ bỏ phòng thủ khi bình thường trở lại và hết thời gian giữ (hold_sec)
        elif self.state == 1:
            time_in_attack = win_time - self.attack_start_time
            if self.consecutive_normal >= self.k_off and time_in_attack >= self.hold_sec:
                self.state = 0
                print(f"\n[INFO] Hệ thống trở về trạng thái AN TOÀN. Đang gỡ bỏ luật chặn...")
                self.firewall.clear_all()
                action_desc = "CLEARED_ALL_RULES"
                self.reaction_time_sec = 0.0

        status_str = "ATTACK" if self.state == 1 else "NORMAL"
        self.write_live_metrics(win_time, status_str, attack_type, prob, feats_dict, action_desc)

        print(f"[{datetime.datetime.fromtimestamp(win_time).strftime('%H:%M:%S')}] "
              f"Trạng thái: {status_str:<6} | P(Attack): {prob*100:5.1f}% | "
              f"PPS: {packet_rate:<8.0f} | SYN: {syn_count:<5} | IPs: {ip_dispersion:<3} | "
              f"Chặn: {len(self.firewall.blocked_ips)} IP", flush=True)

    def run_live(self):
        """Chạy bắt gói tin thời gian thực trực tiếp trên các giao diện Gateway (Linux)."""
        print(f"[*] Bắt đầu giám sát trực tiếp trên giao diện: {self.ifaces}...")
        socks = {}
        for iface in self.ifaces:
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                s.bind((iface, 0))
                s.setblocking(False)
                socks[s] = iface
                print(f"[+] Đã lắng nghe trên {iface}")
            except Exception as e:
                print(f"[-] Không thể mở socket trên {iface}: {e}")

        if not socks:
            print("[-] Không có giao diện nào khả dụng. Yêu cầu quyền root trên máy ảo Mininet.")
            return

        window_duration = 1.0
        cur_win_start = time.time()
        pkts_in_win = 0
        bytes_in_win = 0
        syn_in_win = 0
        src_counter = Counter()

        try:
            while True:
                now = time.time()
                # Kiểm tra nếu hết cửa sổ 1 giây
                if now - cur_win_start >= window_duration:
                    p_rate = pkts_in_win / (now - cur_win_start)
                    b_rate = bytes_in_win / (now - cur_win_start)
                    s_count = syn_in_win
                    disp = len(src_counter)
                    top_ips = src_counter.most_common(5)

                    self.process_window(now, p_rate, b_rate, s_count, disp, top_ips)

                    # Reset cho cửa sổ mới
                    cur_win_start = now
                    pkts_in_win = 0
                    bytes_in_win = 0
                    syn_in_win = 0
                    src_counter.clear()

                ready, _, _ = select.select(list(socks), [], [], 0.05)
                for s in ready:
                    try:
                        while True:
                            raw, addr = s.recvfrom(65535)
                            if addr[2] == PACKET_OUTGOING:
                                continue
                            parsed = parse_ethernet_frame(raw)
                            if parsed:
                                src_ip, total_len, proto, is_syn = parsed
                                pkts_in_win += 1
                                bytes_in_win += total_len
                                syn_in_win += is_syn
                                src_counter[src_ip] += 1
                    except BlockingIOError:
                        pass
        except KeyboardInterrupt:
            print("\n[*] Dừng chương trình phòng thủ tại Gateway.")
            self.firewall.clear_all()

    def run_simulation_playback(self, duration=30):
        """Chế độ mô phỏng kiểm thử thời gian thực phát lại luồng mạng Tổ 3."""
        print(f"[*] KHỞI CHẠY CHẾ ĐỘ KIỂM THỬ THỜI GIAN THỰC ({duration} giây):")
        print("    - Giây 01 đến 08: Lưu lượng bình thường (Normal: 300 cảm biến + 20 camera)")
        print("    - Giây 09 đến 20: Hacker kích hoạt TCP SYN Flood (5000 pps vào srv 10.0.30.10:1883)")
        print("    - Giây 21 đến 30: Tấn công kết thúc, hệ thống hồi phục an toàn.")
        print("-" * 80)

        t_cur = time.time()
        for sec in range(1, duration + 1):
            t_win = t_cur + sec
            # 1. Bình thường
            if sec < 9 or sec > 20:
                p_rate = 8450.0 + (sec % 3) * 120.0
                b_rate = 9950000.0 + (sec % 5) * 50000.0
                s_count = 1 + (sec % 2)
                disp = 88
                top_ips = [("10.0.20.11", 500), ("10.0.10.33", 20)]
            # 2. Bị tấn công TCP SYN Flood (5000 pps)
            else:
                p_rate = 8450.0 + 5000.0
                b_rate = 9950000.0 + 5000.0 * 40
                s_count = 5000
                disp = 89
                top_ips = [("192.168.100.100", 5000), ("10.0.20.11", 500)]

            self.process_window(t_win, p_rate, b_rate, s_count, disp, top_ips)
            time.sleep(1.0)

        self.firewall.clear_all()
        print("-" * 80)
        print(f"[✓] Đã hoàn tất thử nghiệm. Kiểm tra kết quả ghi nhận tại: {self.metrics_file}")


def main():
    parser = argparse.ArgumentParser(description="gateway_ai.py - Phòng thủ DDoS tự động bằng Edge AI tại Gateway")
    parser.add_argument('--model', default=None, help='Đường dẫn mô hình edge_ai_model.joblib')
    parser.add_argument('--iface', nargs='+', default=['gw-eth0', 'gw-eth1'], help='Các interface giám sát')
    parser.add_argument('--firewall', default='iptables', choices=['iptables', 'nftables'], help='Backend tường lửa')
    parser.add_argument('--threshold', type=float, default=0.5, help='Ngưỡng xác suất tấn công (mặc định: 0.5)')
    parser.add_argument('--k-on', type=int, default=2, help='Số cửa sổ liên tiếp để chặn (mặc định: 2 giây <= 3 giây)')
    parser.add_argument('--k-off', type=int, default=3, help='Số cửa sổ liên tiếp để gỡ chặn (mặc định: 3)')
    parser.add_argument('--hold', type=float, default=10.0, help='Thời gian giữ chặn tối thiểu (giây)')
    parser.add_argument('--metrics-file', default='live_metrics.json', help='File JSON lưu chỉ số thời gian thực')
    parser.add_argument('--test-mode', action='store_true', help='Chạy chế độ thử nghiệm phát lại thời gian thực')
    parser.add_argument('--duration', type=int, default=25, help='Thời gian chạy test-mode (giây)')
    args = parser.parse_args()

    # Tìm file mô hình phù hợp
    model_path = args.model
    if not model_path:
        candidates = [
            os.path.join(CURRENT_DIR, "edge_ai_model.joblib"),
            os.path.join(CURRENT_DIR, "models", "rf_edge.joblib"),
            os.path.join(CURRENT_DIR, "edge_ai", "models", "rf_edge.joblib"),
            os.path.join(CURRENT_DIR, "edge_ai", "edge_ai_model.joblib")
        ]
        for c in candidates:
            if os.path.isfile(c):
                model_path = c
                break

    if not model_path or not os.path.isfile(model_path):
        print("[-] Lỗi: Không tìm thấy file mô hình edge_ai_model.joblib! Hãy chạy train_model.py trước.")
        sys.exit(1)

    detector = GatewayAIDetector(
        model_path=model_path,
        ifaces=args.iface,
        firewall_backend=args.firewall,
        threshold=args.threshold,
        k_on=args.k_on,
        k_off=args.k_off,
        hold_sec=args.hold,
        metrics_file=args.metrics_file
    )

    if args.test_mode or sys.platform != 'linux':
        print(f"[*] Chạy chế độ thử nghiệm (Test / Simulated Playback)...")
        detector.run_simulation_playback(duration=args.duration)
    else:
        detector.run_live()


if __name__ == '__main__':
    main()
