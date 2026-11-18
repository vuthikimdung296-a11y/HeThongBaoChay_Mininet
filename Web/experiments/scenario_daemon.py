# -*- coding: utf-8 -*-
"""scenario_daemon.py - Cầu nối giữa nút bấm trên Web và kịch bản của Tổ 3.

Streamlit chạy ở tiến trình riêng nên không có đối tượng `net` của Mininet. Daemon này chạy
TRONG tiến trình Mininet, đọc file lệnh do dashboard ghi (/tmp/scenario_cmd.json), gọi
traffic.run_scenario.run_scenario(net, ...) và ghi trạng thái ra /tmp/scenario_status.json.

Dùng tại dấu nhắc mininet> (khởi động mạng từ thư mục Network/):
  mininet> py import sys; sys.path.insert(0, '..')
  mininet> py from Web.experiments.scenario_daemon import serve
  mininet> py serve(net)                      # chiếm dòng lệnh, in log kịch bản; Ctrl+C để thoát

Tham số monitor_cmd (tùy chọn): lệnh chạy Edge AI ở chế độ chỉ ghi live_metrics.json, không chặn, dùng cho
kịch bản 1 và 2 khi DEMO để Web luôn có dữ liệu. Khi ĐO benchmark thì đừng dùng, vì kịch bản 2 phải tắt AI.

Kịch bản 3 ("có AI+QoS") = qos.sh start (do run_scenario làm) + chạy script Edge AI trên Gateway
(--ai-cmd). Mặc định tìm edge_ai/gateway_ai.py của Việt Anh; nếu chưa có thì kịch bản 3 chỉ có QoS
và trạng thái sẽ ghi rõ "AI chưa bật".
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "Web" / "dashboard"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import dashboard_logic as dl  # noqa: E402

DEFAULT_AI = f"python3 {ROOT / 'edge_ai' / 'gateway_ai.py'} --iface gw-eth0 gw-eth1"


def start_ai(net, ai_cmd, log_path):
    """Chạy Edge AI trong namespace của Gateway. Trả về Popen hoặc None nếu không có script."""
    script = shlex.split(ai_cmd)[1] if len(shlex.split(ai_cmd)) > 1 else ""
    if not Path(script).exists():
        return None
    log = open(log_path, "w", encoding="utf-8")
    proc = net.get("gw").popen(shlex.split(ai_cmd), stdout=log, stderr=subprocess.STDOUT)
    time.sleep(3)                                  # chờ nạp mô hình + bắt đầu bắt gói
    if proc.poll() is not None:
        raise RuntimeError(f"gateway_ai thoát ngay (rc={proc.returncode}); xem {log_path}")
    return proc


def stop_ai(net, proc, reset_cmd):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if reset_cmd:                                  # gỡ luật chặn của lượt vừa chạy, tránh nhiễm lượt sau
        net.get("gw").cmd(reset_cmd)


def run_command(net, cmd, ai_cmd=DEFAULT_AI, reset_cmd=None, monitor_cmd=None):
    from traffic.run_scenario import run_scenario
    scenario = cmd["scenario"]
    use_ai = scenario == "attack_qos"
    results = ROOT / "traffic" / "results"
    results.mkdir(parents=True, exist_ok=True)
    ai = None
    note = ""
    try:
        if reset_cmd:
            net.get("gw").cmd(reset_cmd)
        if use_ai:
            ai = start_ai(net, ai_cmd, results / "gateway_ai.log")
            note = "AI đã bật. " if ai else "AI CHƯA BẬT (không tìm thấy gateway_ai.py), chỉ có QoS. "
        elif monitor_cmd:      # chỉ để Web có dữ liệu khi demo; KHÔNG dùng khi đo benchmark
            ai = start_ai(net, monitor_cmd, results / "gateway_monitor.log")
            note = "(Edge AI chỉ giám sát, không chặn) " if ai else ""
        kw = dict(scenario=scenario, duration=int(cmd.get("duration", 60)))
        if scenario != "normal":
            kw.update(attack_type=cmd.get("attack_type", "syn_flood"),
                      attack_rate=int(cmd.get("attack_rate", 1000)),
                      attack_duration=int(cmd.get("attack_duration", 20)))
        row = run_scenario(net, **kw)
        qos_note = ("QoS đã bật và kiểm tra thành công. " if row.get("qos_enabled")
                    else "QoS không bật trong kịch bản này. ")
        return note + qos_note + (f"RTT TB {row.get('rtt_avg_ms')} ms, P95 {row.get('rtt_p95_ms')} ms, "
                       f"P99 {row.get('rtt_p99_ms')} ms, mất gói {row.get('ping_packet_loss_percent')}%")
    finally:
        stop_ai(net, ai, reset_cmd)


def serve(net, ai_cmd=DEFAULT_AI, reset_cmd=None, monitor_cmd=None, poll_s=1.0):
    """Vòng lặp chính: nhận lệnh từ dashboard. Một luồng riêng ghi heartbeat mỗi giây để Web biết
    daemon còn sống ngay cả khi kịch bản đang chạy (chặn vòng lặp chính hàng chục giây)."""
    import threading
    cur = {"state": "idle", "scenario": None, "message": "Sẵn sàng"}
    stop = threading.Event()

    def beat():
        while not stop.is_set():
            dl.write_status(**cur)
            stop.wait(1.0)

    threading.Thread(target=beat, daemon=True).start()
    last_id = (dl.read_command() or {}).get("id")      # bỏ qua lệnh cũ còn sót
    print("[daemon] sẵn sàng; mở dashboard và bấm nút kịch bản. Ctrl+C để thoát.", flush=True)
    try:
        while True:
            cmd = dl.read_command()
            if cmd and cmd.get("id") != last_id:
                last_id = cmd["id"]
                name = cmd["scenario"]
                print(f"[daemon] nhận lệnh {cmd['id']}: {name}", flush=True)
                cur.update(state="running", scenario=name, message="Đang chạy...", started=time.time())
                try:
                    msg = run_command(net, cmd, ai_cmd, reset_cmd, monitor_cmd)
                    cur.update(state="done", message=msg)
                    print(f"[daemon] xong {name}: {msg}", flush=True)
                except Exception as e:                  # noqa: BLE001 - báo lỗi lên Web, không sập daemon
                    traceback.print_exc()
                    cur.update(state="error", message=str(e))
            time.sleep(poll_s)
    except KeyboardInterrupt:
        cur.update(state="stopped", scenario=None, message="Daemon đã dừng")
        dl.write_status(**cur)
        print("[daemon] dừng.", flush=True)
    finally:
        stop.set()
