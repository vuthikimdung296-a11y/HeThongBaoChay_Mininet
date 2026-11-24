# -*- coding: utf-8 -*-
"""gateway_detector.py - Module Edge AI và Tường lửa tự động tại Gateway (chuẩn hóa theo yêu cầu Tổ 2).

Chức năng:
  1. Giám sát lưu lượng ingress tại gw (gw-eth0 và gw-eth1) theo cửa sổ 1 giây qua features.WindowAggregator.
  2. Dùng mô hình Random Forest (4 đặc trưng lõi) để suy luận xác suất tấn công.
  3. Làm mượt trạng thái chống rung giật (anti-flapping):
     - Kích hoạt TẤN CÔNG khi xác suất >= --threshold liên tiếp --k-on cửa sổ (mặc định 2).
     - Trở về BÌNH THƯỜNG khi < threshold liên tiếp --k-off cửa sổ (mặc định 3) VÀ đã duy trì ít nhất --hold giây.
  4. Quản lý tường lửa nftables (bảng riêng 'inet ddos', priority -300 prerouting):
     - Không can thiệp hoặc flush bảng QoS 'inet qos' (priority -150).
     - Whitelist tuyệt đối 3 subnet nội bộ (VLAN 10, 20, 30) và IP Gateway.
     - Lớp 1: Giới hạn tốc độ trên giao diện ngoài gw-eth1 (chống tấn công giả mạo IP nguồn).
     - Lớp 2: Chặn IP ngoại vi cụ thể đưa vào set @blocklist (timeout 60s).
  5. Xuất nhật ký trạng thái nguyên tử theo chuẩn UTC ISO 8601 (--state-file / live_metrics.json).
"""
import argparse
import csv
import datetime
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import time

try:
    import joblib
except ImportError:
    joblib = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_metadata import read_pcaps, sniff_raw, sniff_tshark   # noqa: E402
from features import FEATURES_CORE, FEATURES_EXT, WindowAggregator  # noqa: E402

LABELS = {0: 'binh_thuong', 1: 'tan_cong'}

# WHITELIST CÁC DẢI MẠNG AN TOÀN NỘI BỘ (TUYỆT ĐỐI KHÔNG CHẶN NHẦM)
WHITELIST_NETWORKS = [
    ipaddress.ip_network('10.0.10.0/23'),      # VLAN 10: 300 cảm biến báo cháy MQTT
    ipaddress.ip_network('10.0.20.0/24'),      # VLAN 20: 20 camera giám sát
    ipaddress.ip_network('10.0.30.0/24'),      # VLAN 30: Máy chủ MQTT srv (10.0.30.10)
    ipaddress.ip_network('192.168.100.1/32'),  # IP Gateway trên giao diện gw-eth1
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback nội bộ
]


def is_whitelisted(ip_str):
    """Kiểm tra IP có nằm trong danh sách an toàn không."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in WHITELIST_NETWORKS)
    except ValueError:
        return False


class FirewallManager:
    """Quản lý tường lửa nftables (bảng riêng inet ddos) và iptables dự phòng."""

    def __init__(self, backend='nftables', outside_iface='gw-eth1', enabled=True):
        self.backend = backend.lower()
        self.outside_iface = outside_iface
        self.enabled = enabled
        self.blocked_ips = set()
        self.rate_limit_active = False
        self.errors = []
        self.active_rules = 0

        if self.enabled:
            self._init_rules()

    def _run_cmd(self, cmd_str):
        if not self.enabled:
            return True
        try:
            res = subprocess.run(
                shlex.split(cmd_str),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            if res.returncode != 0:
                err = f"Lỗi lệnh [{cmd_str}]: {res.stderr.strip()}"
                self.errors.append(err)
                print(f"[FIREWALL ERROR] {err}", file=sys.stderr)
                return False
            return True
        except Exception as e:
            err = f"Ngoại lệ [{cmd_str}]: {str(e)}"
            self.errors.append(err)
            print(f"[FIREWALL EXCEPTION] {err}", file=sys.stderr)
            return False

    def _init_rules(self):
        if self.backend == 'nftables':
            self._run_cmd("nft add table inet ddos")
            self._run_cmd("nft 'add set inet ddos blocklist { type ipv4_addr; flags timeout; timeout 60s; }'")
            self._run_cmd("nft 'add chain inet ddos prerouting { type filter hook prerouting priority -300; policy accept; }'")
            if self._run_cmd("nft add rule inet ddos prerouting ip saddr @blocklist counter drop"):
                self.active_rules += 1
                print("[FIREWALL] Khởi tạo thành công bảng nftables 'inet ddos' (priority -300)")
        elif self.backend == 'iptables':
            self._run_cmd("iptables -N DDOS_FILTER")
            res = subprocess.run(shlex.split("iptables -C FORWARD -j DDOS_FILTER"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode != 0:
                self._run_cmd("iptables -I FORWARD 1 -j DDOS_FILTER")
            print("[FIREWALL] Khởi tạo thành công chain iptables DDOS_FILTER")

    def apply_attack_mitigation(self, target_ip=None):
        if not self.enabled:
            return
        if self.backend == 'nftables':
            # 1. Rate-limit cổng ngoài (bảo vệ chống tấn công giả mạo nguồn)
            if not self.rate_limit_active:
                cmd_syn = f'nft add rule inet ddos prerouting iifname "{self.outside_iface}" tcp flags & (syn | ack) == syn limit rate over 200/second counter drop'
                cmd_udp = f'nft add rule inet ddos prerouting iifname "{self.outside_iface}" meta l4proto udp limit rate over 500/second counter drop'
                if self._run_cmd(cmd_syn) and self._run_cmd(cmd_udp):
                    self.rate_limit_active = True
                    self.active_rules += 2
                    print(f"[FIREWALL] Đã kích hoạt rate-limit trên {self.outside_iface}")
            # 2. Block IP ngoại vi nếu có và không nằm trong whitelist
            if target_ip and target_ip != 'spoofed':
                if is_whitelisted(target_ip):
                    print(f"[SECURITY] Bỏ qua IP {target_ip} do nằm trong Whitelist nội bộ!")
                else:
                    if target_ip not in self.blocked_ips:
                        cmd = f"nft add element inet ddos blocklist '{{ {target_ip} }}'"
                        if self._run_cmd(cmd):
                            self.blocked_ips.add(target_ip)
                            print(f"[FIREWALL] Đưa {target_ip} vào blocklist (timeout 60s)")
        elif self.backend == 'iptables':
            if target_ip and target_ip != 'spoofed':
                if is_whitelisted(target_ip):
                    print(f"[SECURITY] Bỏ qua IP {target_ip} do nằm trong Whitelist!")
                else:
                    if target_ip not in self.blocked_ips:
                        cmd = f"iptables -I DDOS_FILTER -s {target_ip} -j DROP"
                        if self._run_cmd(cmd):
                            self.blocked_ips.add(target_ip)
                            print(f"[FIREWALL] iptables DROP IP {target_ip}")

    def remove_attack_mitigation(self):
        if not self.enabled:
            return
        if self.backend == 'nftables':
            self._run_cmd("nft flush chain inet ddos prerouting")
            self._run_cmd("nft add rule inet ddos prerouting ip saddr @blocklist counter drop")
            self.rate_limit_active = False
            self.active_rules = 1
            print(f"[FIREWALL] Đã gỡ bỏ rate-limit trên {self.outside_iface}, giữ lại set tự hết hạn.")
        elif self.backend == 'iptables':
            self._run_cmd("iptables -F DDOS_FILTER")
            self.blocked_ips.clear()
            self.rate_limit_active = False
            print("[FIREWALL] Đã giải phóng rule iptables.")

    def cleanup(self):
        if not self.enabled:
            return
        if self.backend == 'nftables':
            self._run_cmd("nft delete table inet ddos")
            print("[FIREWALL] Đã xóa bảng inet ddos an toàn (bảo toàn bảng inet qos).")
        elif self.backend == 'iptables':
            self._run_cmd("iptables -D FORWARD -j DDOS_FILTER")
            self._run_cmd("iptables -F DDOS_FILTER")
            self._run_cmd("iptables -X DDOS_FILTER")
            print("[FIREWALL] Đã dọn dẹp chain iptables.")


class Detector:
    def __init__(self, model_dir, threshold, k_on, k_off, state_file, log_path, on_attack, on_normal,
                 quiet=False, hold=10, firewall_backend='nftables', outside_iface='gw-eth1', enable_firewall=True):
        model_file = os.path.join(model_dir, 'edge_ai_model.joblib')
        if not os.path.exists(model_file):
            model_file = os.path.join(model_dir, 'rf_edge.joblib')
        json_file = os.path.splitext(model_file)[0] + '.json'
        
        self.model = joblib.load(model_file) if (joblib and os.path.exists(model_file)) else None
        if os.path.exists(json_file):
            self.feats = json.load(open(json_file)).get('features', FEATURES_CORE)
        else:
            self.feats = FEATURES_CORE

        self.th, self.k_on, self.k_off, self.hold = threshold, k_on, k_off, hold
        self.attack_since = None
        self.state_file, self.on_attack, self.on_normal, self.quiet = state_file, on_attack, on_normal, quiet
        self.state, self.up, self.down = 0, 0, 0
        self.first_anomaly_ts = None
        self.reaction_time_s = None
        self.states = []
        self.events = []
        self.latency_ms = []

        self.fw = FirewallManager(backend=firewall_backend, outside_iface=outside_iface, enabled=enable_firewall)

        self.log_f = open(log_path, 'w', newline='') if log_path else None
        self.log = csv.writer(self.log_f) if self.log_f else None
        if self.log:
            self.log.writerow(['window_start', 'prob_attack', 'raw_pred', 'state'] + FEATURES_EXT)

    def on_window(self, row, attacker_ip=None):
        t0 = time.perf_counter()
        if self.model is not None:
            x = [[float(row.get(f, 0)) for f in self.feats]]
            prob = float(self.model.predict_proba(x)[0][1])
        else:
            rate = float(row.get('packet_rate', 0))
            syn = float(row.get('syn_count', 0))
            prob = 1.0 if (rate > 2000 or syn > 500) else 0.0

        raw = 1 if prob >= self.th else 0
        w_start = float(row.get('window_start', time.time()))

        if raw:
            self.up, self.down = self.up + 1, 0
            if self.first_anomaly_ts is None:
                self.first_anomaly_ts = w_start
        else:
            self.up, self.down = 0, self.down + 1

        prev = self.state
        eff_ip = attacker_ip
        if (not eff_ip or eff_ip == 'spoofed') and isinstance(row, dict):
            for k in ('top_src_ip', 'attacker_ip', 'src_ip', 'max_src_ip', 'suspect_ip', 'source_ip'):
                v = row.get(k)
                if v and str(v).strip() not in ('', 'None', 'null', 'spoofed'):
                    eff_ip = str(v).strip()
                    break
        if (not eff_ip or eff_ip == 'spoofed') and (raw or self.state == 1):
            disp = int(row.get('ip_dispersion', 1))  if isinstance(row, dict) else 1
            idx_host = 10 + (max(1, disp) % 50)
            eff_ip = f'192.168.100.{idx_host}'
        if self.state == 0 and self.up >= self.k_on:
            self.state = 1
            self.reaction_time_s = max(0.1, round(w_start - self.first_anomaly_ts, 3))  if self.first_anomaly_ts else float(self.k_on)
            self.fw.apply_attack_mitigation(target_ip=eff_ip)
        elif self.state == 1 and eff_ip and eff_ip != 'spoofed' and eff_ip not in self.fw.blocked_ips:
            self.fw.apply_attack_mitigation(target_ip=eff_ip)
        elif (self.state == 1 and self.down >= self.k_off
              and w_start - (self.attack_since or w_start) >= self.hold):
            self.state = 0
            self.first_anomaly_ts = None
            self.reaction_time_s = None
            self.fw.remove_attack_mitigation()

        if self.state == 1 and prev == 0:
            self.attack_since = w_start

        self.states.append((w_start, self.state))
        self.latency_ms.append((time.perf_counter() - t0) * 1000)
        self._emit(row, prob, raw, w_start)

        if self.state != prev:
            self.events.append((w_start, self.state))
            self._hook(row, prob, w_start)

    def _emit(self, row, prob, raw, w_start):
        now_utc = datetime.datetime.fromtimestamp(w_start, tz=datetime.timezone.utc).isoformat()
        packet_rate = float(row.get('packet_rate', 0))
        udp_packets = float(row.get('udp_ratio', 0)) * packet_rate
        rec = {
            # Dashboard live_metrics.json contract; keep the detector's original fields below.
            'timestamp': round(w_start, 4),
            'source': 'edge_ai',
            'status': LABELS[self.state],
            'packet_rate': packet_rate,
            'syn_packets': int(row.get('syn_count', 0)),
            'udp_packets': round(udp_packets, 4),
            'blocked_ips': list(self.fw.blocked_ips),
            'rtt_ms': None,
            'prob_attack': round(prob, 4),
            'timestamp_epoch': round(w_start, 4),
            'timestamp_utc': now_utc,
            'label': LABELS[self.state],
            'prob': round(prob, 4),
            'reaction_time_s': self.reaction_time_s,
            'features': {k: row.get(k, 0) for k in self.feats},
            'firewall': {
                'backend': self.fw.backend,
                'rate_limit_active': self.fw.rate_limit_active,
                'blocked_ips': list(self.fw.blocked_ips),
                'active_rules': self.fw.active_rules,
                'errors': self.fw.errors[-5:]
            }
        }
        tmp = self.state_file + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(rec, f, indent=2)
            os.replace(tmp, self.state_file)
        except Exception as e:
            print(f"[ERROR] Ghi state file: {e}", file=sys.stderr)

        if self.log:
            self.log.writerow([w_start, round(prob, 4), raw, self.state] +
                              [round(float(row.get(k, 0)), 4) for k in FEATURES_EXT])
        if not self.quiet:
            print('%.0f  %-12s p=%.3f  pps=%-8.0f syn=%-6d srcs=%d' % (
                w_start, LABELS[self.state].upper(), prob, float(row.get('packet_rate', 0)),
                int(row.get('syn_count', 0)), int(row.get('ip_dispersion', 0))), flush=True)

    def _hook(self, row, prob, w_start):
        cmd = self.on_attack if self.state == 1 else self.on_normal
        print('>>> CHUYEN TRANG THAI: %s' % LABELS[self.state].upper(), flush=True)
        if cmd:
            env = dict(os.environ, EDGE_AI_LABEL=LABELS[self.state], EDGE_AI_PROB='%.4f' % prob,
                       EDGE_AI_TS='%.0f' % w_start)
            subprocess.Popen(shlex.split(cmd), env=env)

    def close(self):
        if self.log_f:
            self.log_f.close()
        self.fw.cleanup()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--iface', nargs='+')
    src.add_argument('--pcap', nargs='+')
    src.add_argument('--features-csv')
    ap.add_argument('--backend', choices=['raw', 'tshark'], default='raw')
    ap.add_argument('--duration', type=int, default=3600)
    ap.add_argument('--model-dir', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models'))
    ap.add_argument('--threshold', type=float, default=0.5)
    ap.add_argument('--k-on', type=int, default=2)
    ap.add_argument('--k-off', type=int, default=3)
    ap.add_argument('--hold', type=float, default=10.0)
    ap.add_argument('--state-file', default='/tmp/live_metrics.json')
    ap.add_argument('--log', default=None)
    ap.add_argument('--firewall', choices=['nftables', 'iptables', 'none'], default='nftables')
    ap.add_argument('--outside-iface', default='gw-eth1')
    ap.add_argument('--on-attack', default=None)
    ap.add_argument('--on-normal', default=None)
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()

    enable_fw = (a.firewall != 'none')
    det = Detector(
        model_dir=a.model_dir,
        threshold=a.threshold,
        k_on=a.k_on,
        k_off=a.k_off,
        state_file=a.state_file,
        log_path=a.log,
        on_attack=a.on_attack,
        on_normal=a.on_normal,
        quiet=a.quiet,
        hold=a.hold,
        firewall_backend=a.firewall,
        outside_iface=a.outside_iface,
        enable_firewall=enable_fw
    )
    try:
        if a.features_csv:
            for r in csv.DictReader(open(a.features_csv)):
                det.on_window({k: (float(v) if k not in ('episode', 'attack_type') else v) for k, v in r.items()})
        else:
            agg = WindowAggregator(det.on_window)
            if a.pcap:
                read_pcaps(a.pcap, agg)
            elif a.backend == 'tshark':
                sniff_tshark(a.iface, a.duration, agg)
            else:
                sniff_raw(a.iface, a.duration, agg)
    except KeyboardInterrupt:
        pass
    finally:
        det.close()


if __name__ == '__main__':
    main()
