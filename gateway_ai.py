#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway_ai.py - Module phòng thủ tự động tại Edge Gateway (Tích hợp Edge AI & nftables/iptables)
Phục vụ đề tài: Hệ thống cảnh báo cháy thông minh - Mô phỏng Mininet & Phòng chống DDoS

Cơ chế hoạt động chuẩn hóa theo yêu cầu Tổ 2:
  1. Trích xuất đặc trưng từ HEADER METADATA qua features.py (cửa sổ 1 giây).
  2. Phân loại bằng Random Forest (4 đặc trưng lõi: packet_rate, byte_rate, syn_count, ip_dispersion).
  3. Làm mượt trạng thái: k_on = 2 cửa sổ để báo ATTACK, k_off = 3 cửa sổ và hold >= 10s để về NORMAL.
  4. Tường lửa tách biệt (Bảng riêng inet ddos, không can thiệp bảng QoS inet qos):
     - Hook prerouting priority -300 (chạy trước QoS mangle priority -150).
     - Rate-limit cổng ngoài gw-eth1 khi bị tấn công (bảo vệ chống tấn công giả mạo IP nguồn).
     - Whitelist nghiêm ngặt: VLAN 10 (cảm biến), VLAN 20 (camera), VLAN 30 (server), Gateway IP.
     - Kiểm tra mã trả về của lệnh hệ thống, ghi nhận lỗi và nhật ký thời gian theo chuẩn UTC (ISO 8601).
"""
import argparse
import datetime
import ipaddress
import json
import os
import select
import shlex
import socket
import subprocess
import sys
import time

# Đảm bảo import được features.py từ cùng thư mục hoặc thư mục edge_ai/
_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CUR_DIR not in sys.path:
    sys.path.insert(0, _CUR_DIR)
_EDGE_AI_DIR = os.path.join(_CUR_DIR, 'edge_ai')
if os.path.exists(_EDGE_AI_DIR) and _EDGE_AI_DIR not in sys.path:
    sys.path.insert(0, _EDGE_AI_DIR)

try:
    from features import FEATURES_CORE, WindowAggregator, parse_frame
except ImportError:
    # Fallback nếu chạy ở thư mục ngoài
    sys.path.insert(0, os.path.abspath('edge_ai'))
    from features import FEATURES_CORE, WindowAggregator, parse_frame

try:
    import joblib
except ImportError:
    joblib = None

# WHITELIST CÁC DẢI MẠNG HỢP LỆ NỘI BỘ (TUYỆT ĐỐI KHÔNG CHẶN NHẦM)
WHITELIST_NETWORKS = [
    ipaddress.ip_network('10.0.10.0/23'),      # VLAN 10: 300 cảm biến báo cháy MQTT
    ipaddress.ip_network('10.0.20.0/24'),      # VLAN 20: 20 camera giám sát
    ipaddress.ip_network('10.0.30.0/24'),      # VLAN 30: Máy chủ MQTT srv (10.0.30.10)
    ipaddress.ip_network('192.168.100.1/32'),  # IP Gateway trên giao diện gw-eth1
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback nội bộ
]

PACKET_OUTGOING = 4  # Gói tin egress của Linux


def is_ip_whitelisted(ip_str):
    """Kiểm tra IP có thuộc danh sách an toàn không."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in WHITELIST_NETWORKS)
    except ValueError:
        return False


class FirewallManager:
    """Quản lý tường lửa tự động: hỗ trợ nftables (chuẩn đề cương) và iptables."""

    def __init__(self, backend='nftables', outside_iface='gw-eth1'):
        self.backend = backend.lower()
        self.outside_iface = outside_iface
        self.blocked_ips = set()
        self.rate_limit_active = False
        self.errors = []
        self.active_rules_count = 0
        self.last_action = "INITIALIZED"

        if self.backend == 'nftables':
            self._init_nftables()
        elif self.backend == 'iptables':
            self._init_iptables()

    def _run_cmd(self, cmd_str):
        """Thực thi lệnh hệ thống và kiểm tra mã trả về."""
        try:
            res = subprocess.run(
                shlex.split(cmd_str),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if res.returncode != 0:
                err_msg = f"Lỗi lệnh [{cmd_str}]: {res.stderr.strip()}"
                self.errors.append(err_msg)
                print(f"[FIREWALL ERROR] {err_msg}", file=sys.stderr)
                return False
            return True
        except Exception as e:
            err_msg = f"Ngoại lệ khi thực thi [{cmd_str}]: {str(e)}"
            self.errors.append(err_msg)
            print(f"[FIREWALL EXCEPTION] {err_msg}", file=sys.stderr)
            return False

    def _init_nftables(self):
        """Khởi tạo bảng riêng inet ddos (tách biệt khỏi bảng inet qos)."""
        # Tạo table inet ddos và set blocklist có timeout 60s
        self._run_cmd("nft add table inet ddos")
        self._run_cmd("nft 'add set inet ddos blocklist { type ipv4_addr; flags timeout; timeout 60s; }'")
        self._run_cmd("nft 'add chain inet ddos prerouting { type filter hook prerouting priority -300; policy accept; }'")
        # Luật chặn các IP trong blocklist
        if self._run_cmd("nft add rule inet ddos prerouting ip saddr @blocklist counter drop"):
            self.active_rules_count += 1
            print("[FIREWALL] Đã khởi tạo bảng nftables riêng 'inet ddos' (priority -300)")

    def _init_iptables(self):
        """Khởi tạo chain riêng DDOS_FILTER cho iptables."""
        self._run_cmd("iptables -N DDOS_FILTER")
        # Kiểm tra trước khi chèn vào FORWARD để tránh lặp rule
        res = subprocess.run(shlex.split("iptables -C FORWARD -j DDOS_FILTER"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            self._run_cmd("iptables -I FORWARD 1 -j DDOS_FILTER")
        self.active_rules_count += 1
        print("[FIREWALL] Đã khởi tạo chain iptables DDOS_FILTER")

    def activate_attack_mitigation(self, attacker_ip=None):
        """Kích hoạt biện pháp phòng thủ khi phát hiện tấn công."""
        self.last_action = "MITIGATION_ACTIVATED"
        success = True

        if self.backend == 'nftables':
            # Lớp 1: Rate limit trên cổng ngoài gw-eth1 (áp dụng ngay cả khi tấn công giả mạo IP)
            if not self.rate_limit_active:
                cmd_syn = f'nft add rule inet ddos prerouting iifname "{self.outside_iface}" tcp flags & (syn | ack) == syn limit rate over 200/second counter drop'
                cmd_udp = f'nft add rule inet ddos prerouting iifname "{self.outside_iface}" meta l4proto udp limit rate over 500/second counter drop'
                if self._run_cmd(cmd_syn) and self._run_cmd(cmd_udp):
                    self.rate_limit_active = True
                    self.active_rules_count += 2
                    print(f"[FIREWALL] Đã áp dụng rate-limit trên giao diện ngoài {self.outside_iface}")
                else:
                    success = False

            # Lớp 2: Chặn IP cụ thể nếu xác định được và không nằm trong Whitelist
            if attacker_ip and attacker_ip != "spoofed":
                if is_ip_whitelisted(attacker_ip):
                    print(f"[SECURITY ALERT] Bỏ qua yêu cầu chặn IP {attacker_ip} do thuộc WHITELIST nội bộ!")
                else:
                    if attacker_ip not in self.blocked_ips:
                        cmd_set = f"nft add element inet ddos blocklist '{{ {attacker_ip} }}'"
                        if self._run_cmd(cmd_set):
                            self.blocked_ips.add(attacker_ip)
                            print(f"[FIREWALL] Đã đưa IP {attacker_ip} vào blocklist (timeout 60s)")
                        else:
                            success = False

        elif self.backend == 'iptables':
            if attacker_ip and attacker_ip != "spoofed":
                if is_ip_whitelisted(attacker_ip):
                    print(f"[SECURITY ALERT] Bỏ qua yêu cầu chặn IP {attacker_ip} do thuộc WHITELIST nội bộ!")
                else:
                    if attacker_ip not in self.blocked_ips:
                        cmd = f"iptables -I DDOS_FILTER -s {attacker_ip} -j DROP"
                        if self._run_cmd(cmd):
                            self.blocked_ips.add(attacker_ip)
                            self.active_rules_count += 1
                            print(f"[FIREWALL] iptables đã DROP IP {attacker_ip}")
                        else:
                            success = False
            else:
                # Giới hạn cổng ngoài khi không rõ IP đơn lẻ
                cmd_rate = f"iptables -I DDOS_FILTER -i {self.outside_iface} -p tcp --syn -m limit --limit 200/s --limit-burst 300 -j ACCEPT"
                cmd_drop = f"iptables -A DDOS_FILTER -i {self.outside_iface} -p tcp --syn -j DROP"
                self._run_cmd(cmd_rate)
                self._run_cmd(cmd_drop)
                self.rate_limit_active = True

        return success

    def deactivate_attack_mitigation(self):
        """Hạ trạng thái phòng thủ khi lưu lượng trở lại bình thường."""
        self.last_action = "MITIGATION_DEACTIVATED"
        if self.backend == 'nftables':
            # Làm sạch prerouting chain của inet ddos và tái lập rule blocklist cơ bản
            self._run_cmd("nft flush chain inet ddos prerouting")
            self._run_cmd("nft add rule inet ddos prerouting ip saddr @blocklist counter drop")
            self.rate_limit_active = False
            self.active_rules_count = 1
            print(f"[FIREWALL] Đã gỡ bỏ rate-limit trên {self.outside_iface}, giữ lại set tự hết hạn.")
        elif self.backend == 'iptables':
            self._run_cmd("iptables -F DDOS_FILTER")
            self.blocked_ips.clear()
            self.rate_limit_active = False
            self.active_rules_count = 0
            print("[FIREWALL] iptables đã flush chain DDOS_FILTER.")

    def cleanup(self):
        """Dọn dẹp tài nguyên khi tắt chương trình (KHÔNG bao giờ flush toàn bộ ruleset)."""
        if self.backend == 'nftables':
            # Chỉ xóa bảng riêng inet ddos, bảo toàn nguyên vẹn bảng inet qos
            self._run_cmd("nft delete table inet ddos")
            print("[FIREWALL] Đã xóa bảng inet ddos an toàn.")
        elif self.backend == 'iptables':
            self._run_cmd("iptables -D FORWARD -j DDOS_FILTER")
            self._run_cmd("iptables -F DDOS_FILTER")
            self._run_cmd("iptables -X DDOS_FILTER")
            print("[FIREWALL] Đã xóa chain DDOS_FILTER an toàn.")


class EdgeAIDetector:
    """Bộ phát hiện và phòng thủ DDoS sử dụng Edge AI tại Gateway."""

    def __init__(self, model_path, threshold=0.5, k_on=2, k_off=3, hold_sec=10.0,
                 firewall_backend='nftables', metrics_file='live_metrics.json'):
        self.threshold = threshold
        self.k_on = k_on
        self.k_off = k_off
        self.hold_sec = hold_sec
        self.metrics_file = os.path.abspath(metrics_file)

        self.model = None
        self.features_list = FEATURES_CORE
        self._load_model(model_path)

        self.fw = FirewallManager(backend=firewall_backend)

        # Trạng thái máy học & bộ lọc chống flapping
        self.state = 0  # 0: NORMAL, 1: ATTACK
        self.consecutive_attack = 0
        self.consecutive_normal = 0
        self.first_anomaly_time = None
        self.attack_start_time = None
        self.reaction_time_sec = None

        self.latest_features = {}
        self.last_prob = 0.0

    def _load_model(self, model_path):
        if not model_path or not os.path.exists(model_path):
            print(f"[WARN] Không tìm thấy model tại '{model_path}'. Chạy ở chế độ heuristic cơ bản.")
            return

        try:
            self.model = joblib.load(model_path)
            meta_path = os.path.splitext(model_path)[0] + '.json'
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                    self.features_list = meta.get('features', FEATURES_CORE)
            print(f"[MODEL] Đã nạp thành công mô hình từ '{model_path}' (Đặc trưng: {self.features_list})")
        except Exception as e:
            print(f"[ERROR] Không thể nạp mô hình: {e}")

    def predict_window(self, row):
        """Dự đoán xác suất tấn công trên một cửa sổ 1 giây."""
        self.latest_features = {k: float(row.get(k, 0)) for k in self.features_list}
        if self.model is not None:
            try:
                x = [[self.latest_features[k] for k in self.features_list]]
                prob = float(self.model.predict_proba(x)[0][1])
                return prob
            except Exception as e:
                self.fw.errors.append(f"Inference error: {str(e)}")
        # Heuristic fallback nếu không có model
        rate = self.latest_features.get('packet_rate', 0)
        syn = self.latest_features.get('syn_count', 0)
        if rate > 2000 or syn > 500:
            return 1.0
        return 0.0

    def on_window(self, row, attacker_ip=None, now_epoch=None):
        """Xử lý sự kiện khi một cửa sổ 1 giây kết thúc."""
        now = now_epoch if now_epoch is not None else time.time()
        prob = self.predict_window(row)
        self.last_prob = prob
        raw_pred = 1 if prob >= self.threshold else 0

        # Cập nhật bộ đếm
        if raw_pred == 1:
            self.consecutive_attack += 1
            self.consecutive_normal = 0
            if self.first_anomaly_time is None:
                self.first_anomaly_time = now
        else:
            self.consecutive_normal += 1
            self.consecutive_attack = 0

        prev_state = self.state

        # Kích hoạt phòng thủ (k_on cửa sổ liên tiếp)
        if self.state == 0 and self.consecutive_attack >= self.k_on:
            self.state = 1
            self.attack_start_time = now
            if self.first_anomaly_time:
                self.reaction_time_sec = max(0.1, round(now - self.first_anomaly_time, 3))
            else:
                self.reaction_time_sec = float(self.k_on)

            print(f"\n[CẢNH BÁO TẤN CÔNG] Xác suất P={prob:.3f} >= {self.threshold} liên tiếp {self.k_on}s.")
            print(f"                 Thời gian phản ứng đo được: {self.reaction_time_sec}s")
            self.fw.activate_attack_mitigation(attacker_ip=attacker_ip)

        # Gỡ bỏ phòng thủ (k_off cửa sổ bình thường VÀ đã qua hold_sec)
        elif self.state == 1:
            time_in_attack = now - self.attack_start_time if self.attack_start_time else 0
            if self.consecutive_normal >= self.k_off and time_in_attack >= self.hold_sec:
                self.state = 0
                self.first_anomaly_time = None
                self.reaction_time_sec = None
                print(f"\n[BÌNH THƯỜNG TRỞ LẠI] Lưu lượng an toàn {self.k_off}s liên tiếp và hết thời gian giữ {self.hold_sec}s.")
                self.fw.deactivate_attack_mitigation()

        self._export_metrics(now)

    def _export_metrics(self, now):
        """Ghi file metrics nguyên tử theo chuẩn UTC ISO 8601."""
        now_utc_str = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).isoformat()
        metrics = {
            "timestamp_epoch": round(now, 4),
            "timestamp_utc": now_utc_str,
            "status": "ATTACK" if self.state == 1 else "NORMAL",
            "attack_probability": round(self.last_prob, 4),
            "reaction_time_sec": self.reaction_time_sec,
            "features": self.latest_features,
            "firewall": {
                "backend": self.fw.backend,
                "rate_limit_active": self.fw.rate_limit_active,
                "blocked_ips": list(self.fw.blocked_ips),
                "active_rules_count": self.fw.active_rules_count,
                "last_action": self.fw.last_action,
                "errors": self.fw.errors[-5:] if self.fw.errors else []
            }
        }
        tmp_file = self.metrics_file + ".tmp"
        try:
            with open(tmp_file, "w") as f:
                json.dump(metrics, f, indent=2)
            os.replace(tmp_file, self.metrics_file)
        except Exception as e:
            print(f"[ERROR] Không thể ghi file {self.metrics_file}: {e}")

    def cleanup(self):
        self.fw.cleanup()


def sniff_live_loop(detector, ifaces, duration=3600):
    """Vòng lặp bắt gói trực tiếp AF_PACKET trên Linux có bảo vệ chống treo (B5)."""
    socks = {}
    for i in ifaces:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((i, 0))
            s.setblocking(False)
            socks[s] = i
        except Exception as e:
            print(f"[ERROR] Không thể mở raw socket trên giao diện {i}: {e}")
            return

    agg = WindowAggregator(lambda r: detector.on_window(r))
    end_time = time.time() + duration
    print(f"[*] Bắt đầu giám sát trực tiếp trên {ifaces} trong {duration}s...")

    try:
        while time.time() < end_time:
            ready, _, _ = select.select(list(socks), [], [], 0.2)
            for s in ready:
                pkt_count = 0
                try:
                    # Giới hạn tối đa 5000 gói mỗi lượt đọc để không bị nghẽn CPU/vòng lặp
                    while pkt_count < 5000:
                        raw, addr = s.recvfrom(65535)
                        pkt_count += 1
                        if addr[2] == PACKET_OUTGOING:
                            continue
                        parsed = parse_frame(raw)
                        if parsed:
                            agg.add(time.time(), *parsed)
                except BlockingIOError:
                    pass
            agg.flush_until(time.time() - 0.5)
    except KeyboardInterrupt:
        print("\n[*] Nhận tín hiệu dừng từ người dùng.")
    finally:
        agg.flush_until(time.time() + 1)
        agg.close()
        for s in socks:
            s.close()


def run_simulation(detector, duration=25):
    """Chế độ giả lập thử nghiệm đường ống (In rõ nhãn cảnh báo theo yêu cầu B6)."""
    print("\n" + "=" * 70)
    print(" [CẢNH BÁO] CHẾ ĐỘ THỬ NGHIỆM ĐƯỜNG ỐNG (SIMULATION PIPELINE TEST)")
    print(" Dữ liệu sau đây là giả lập kỹ thuật để kiểm tra cơ chế kích hoạt.")
    print(" KHÔNG PHẢI KẾT QUẢ ĐO THỰC TẾ TRÊN MẠNG MININET.")
    print("=" * 70 + "\n")

    t_now = time.time()
    for sec in range(duration):
        cur_t = t_now + sec
        if 5 <= sec < 15:
            # Giả lập tấn công từ 192.168.100.100
            row = {'packet_rate': 12000.0, 'byte_rate': 9500000.0, 'syn_count': 4500, 'ip_dispersion': 90}
            detector.on_window(row, attacker_ip="192.168.100.100", now_epoch=cur_t)
        else:
            # Lưu lượng bình thường
            row = {'packet_rate': 8500.0, 'byte_rate': 10000000.0, 'syn_count': 1, 'ip_dispersion': 85}
            detector.on_window(row, attacker_ip=None, now_epoch=cur_t)

        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser(description="Edge AI DDoS Detection and Defense at Gateway")
    parser.add_argument('--iface', nargs='+', default=['gw-eth0', 'gw-eth1'], help='Các giao diện cần bắt gói')
    parser.add_argument('--model', default='edge_ai_model.joblib', help='Đường dẫn file mô hình AI')
    parser.add_argument('--firewall', choices=['nftables', 'iptables'], default='nftables', help='Backend tường lửa')
    parser.add_argument('--threshold', type=float, default=0.5, help='Ngưỡng xác suất tấn công')
    parser.add_argument('--k-on', type=int, default=2, help='Số cửa sổ liên tiếp để báo ATTACK')
    parser.add_argument('--k-off', type=int, default=3, help='Số cửa sổ liên tiếp để về NORMAL')
    parser.add_argument('--hold', type=float, default=10.0, help='Thời gian hold tối thiểu (giây)')
    parser.add_argument('--metrics-file', default='live_metrics.json', help='File xuất trạng thái JSON')
    parser.add_argument('--duration', type=int, default=3600, help='Thời gian chạy (giây)')
    parser.add_argument('--test-mode', action='store_true', help='Chạy chế độ thử nghiệm đường ống giả lập')

    args = parser.parse_args()

    detector = EdgeAIDetector(
        model_path=args.model,
        threshold=args.threshold,
        k_on=args.k_on,
        k_off=args.k_off,
        hold_sec=args.hold,
        firewall_backend=args.firewall,
        metrics_file=args.metrics_file
    )

    try:
        if args.test_mode or sys.platform != 'linux':
            if sys.platform != 'linux':
                print(f"[*] Phát hiện hệ điều hành {sys.platform} (không hỗ trợ AF_PACKET Linux). Tự động chạy chế độ thử nghiệm.")
            run_simulation(detector, duration=min(args.duration, 20))
        else:
            sniff_live_loop(detector, args.iface, duration=args.duration)
    finally:
        print("[*] Đang hoàn tất và dọn dẹp tường lửa...")
        detector.cleanup()
        print("[*] Hoàn tất.")


if __name__ == '__main__':
    main()
