#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Orchestrate traffic from the live Mininet CLI.

Usage at `mininet>` prompt (network must already be running):
  py from traffic.run_scenario import run_scenario
  py run_scenario(net, scenario='normal', duration=60)
  py run_scenario(net, scenario='attack_no_qos', duration=60, attack_type='syn_flood', attack_rate=1000)
  py run_scenario(net, scenario='attack_qos', duration=60, attack_type='udp_flood', attack_rate=1000)
"""
from __future__ import annotations
import csv
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRAFFIC = ROOT / "traffic"
QOS_SCRIPT = ROOT / "qos" / "qos.sh"
RESULTS = TRAFFIC / "results"


def _wait_port(host, port: int, timeout: float = 8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check = host.cmd(f"ss -lnt '( sport = :{int(port)} )' | grep -q LISTEN; echo $?").strip()
        if check.endswith("0"):
            return
        time.sleep(0.25)
    raise RuntimeError(f"Service did not listen on TCP/{port} in Mininet host {host.name}")


def _start_service(host, command):
    proc = host.popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    if proc.poll() is not None:
        raise RuntimeError(f"Could not start service in {host.name}: {command}")
    return proc


def _ping_metrics(output: str):
    values = [float(x) for x in re.findall(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", output)]
    loss_match = re.search(r"([0-9.]+)% packet loss", output)
    values_sorted = sorted(values)
    def percentile(p):
        if not values_sorted:
            return None
        index = max(0, min(len(values_sorted) - 1, int((p / 100) * (len(values_sorted) - 1) + 0.999999)))
        return round(values_sorted[index], 4)
    return {
        "ping_samples": len(values),
        "rtt_avg_ms": round(sum(values) / len(values), 4) if values else None,
        "rtt_p95_ms": percentile(95),
        "rtt_p99_ms": percentile(99),
        "ping_packet_loss_percent": float(loss_match.group(1)) if loss_match else None,
    }


def _ping_samples(output: str):
    """Tra ve [(epoch_giay, rtt_ms)] tu ping -D (moi dong tra loi bat dau bang [epoch])."""
    return [(float(t), float(r)) for t, r in
            re.findall(r"\[(\d+(?:\.\d+)?)\].*?time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", output)]


def _window_metrics(samples, w0: float, w1: float, interval: float = 0.2):
    """RTT/mat goi CHI trong cua so [w0, w1] (giay epoch). Mat goi = 1 - so tra loi / so goi du kien."""
    vals = sorted(r for t, r in samples if w0 <= t <= w1)
    expected = max(1, round((w1 - w0) / interval))
    def pct(p):
        if not vals:
            return None
        i = max(0, min(len(vals) - 1, int((p / 100) * (len(vals) - 1) + 0.999999)))
        return round(vals[i], 4)
    return {
        "win_samples": len(vals),
        "win_rtt_avg_ms": round(sum(vals) / len(vals), 4) if vals else None,
        "win_rtt_p95_ms": pct(95),
        "win_rtt_p99_ms": pct(99),
        "win_loss_percent": round(max(0.0, 100.0 * (1 - len(vals) / expected)), 2),
    }


def _append_csv(path: Path, row: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def run_scenario(net, scenario="normal", duration=60, attack_type="syn_flood",
                 attack_rate=1000, attack_duration=20, spoof=False,
                 camera_bandwidth="4M", telemetry_interval=30,
                 probe_dscp=48, strict=False):
    """Run one repeatable experiment using Mininet host objects from the CLI.

    Scenarios: normal, attack_no_qos, attack_qos. QoS is applied only in
    attack_qos. The MQTT broker and iperf3 server run inside `srv` namespace.

    probe_dscp: DSCP cua goi ping do RTT (48 = giong ban tin canh bao -> lop 1:10; None = DSCP 0).
    strict: True = dung ngay khi bat ky tien trinh con nao thoat loi (hanh vi cu);
            False = ghi lai tien trinh loi vao CSV (cot failed_processes, alarm_ok) va chay tiep.
    Cac cot win_* la RTT/mat goi TRONG CUA SO TAN CONG (hoac cua so 10 s cung vi tri o kich ban normal).
    """
    if scenario not in {"normal", "attack_no_qos", "attack_qos"}:
        raise ValueError("scenario must be normal, attack_no_qos or attack_qos")
    if duration < 15 or duration > 600:
        raise ValueError("duration must be between 15 and 600 seconds")
    if scenario == "normal":
        attack_duration = 0
    elif attack_duration <= 0 or attack_duration >= duration:
        raise ValueError("attack_duration must be >0 and shorter than experiment duration")

    RESULTS.mkdir(parents=True, exist_ok=True)
    srv, gw = net.get("srv"), net.get("gw")
    qos_enabled = scenario == "attack_qos"
    if qos_enabled:
        out = gw.cmd(f"bash {QOS_SCRIPT} start")
        print(out)
        check = gw.cmd(f"bash {QOS_SCRIPT} check; echo QOS_RC:$?")
        print(check)
        if "QOS_RC:0" not in check:
            raise RuntimeError("QoS validation failed; aborting experiment")
    else:
        gw.cmd(f"bash {QOS_SCRIPT} stop")

    processes = []
    failed = []
    log_handles = []
    iperf_servers = []
    broker = None
    ping = None
    started_iso = datetime.now(timezone.utc).isoformat()
    try:
        # Use a dedicated iperf3 listener per camera so simultaneous clients do
        # not contend for a single server session.
        # Mosquitto 2.x mac dinh CHI nhan ket noi tu chinh may no (localhost) va tu choi nac danh,
        # nen cac host hs01..hs10 se bi tu choi. Phai chay kem file cau hinh nay.
        srv.cmd("pkill -x mosquitto 2>/dev/null; sleep 0.5")
        Path("/tmp/mosq_scenario.conf").write_text(
            "listener 1883 0.0.0.0\nallow_anonymous true\n", encoding="utf-8")
        broker = _start_service(srv, ["mosquitto", "-c", "/tmp/mosq_scenario.conf"])
        _wait_port(srv, 1883)
        for number in range(1, 21):
            port = 5200 + number
            server = _start_service(srv, ["iperf3", "-s", "-p", str(port)])
            iperf_servers.append(server)
            _wait_port(srv, port)

        # Ten hosts, each representing 30 logical sensors with unique IP aliases.
        for floor in range(1, 11):
            host = net.get(f"hs{floor:02d}")
            cmd = [sys.executable, str(TRAFFIC / "normal_mqtt.py"), "--floor", str(floor),
                   "--duration", str(duration), "--telemetry-interval", str(telemetry_interval)]
            if floor == 1:
                cmd += ["--alarm-after", "10", "--alarm-index", "1"]
            log_path = RESULTS / f"mqtt_hs{floor:02d}.log"
            log = log_path.open("w", encoding="utf-8")
            log_handles.append(log)
            processes.append((f"MQTT hs{floor:02d} ({log_path})",
                              host.popen(cmd, stdout=log, stderr=subprocess.STDOUT)))

        # Twenty independent camera hosts, each capped at the requested UDP rate.
        for number in range(1, 21):
            host = net.get(f"cam{number:02d}")
            camera_id = f"cam{number:02d}"
            port = 5200 + number
            cmd = [sys.executable, str(TRAFFIC / "camera_iperf.py"), "--camera-id", camera_id,
                   "--target", "10.0.30.10", "--port", str(port), "--bandwidth", camera_bandwidth,
                   "--duration", str(duration), "--output-dir", str(RESULTS)]
            log_path = RESULTS / f"{camera_id}.log"
            log = log_path.open("w", encoding="utf-8")
            log_handles.append(log)
            processes.append((f"camera {camera_id} ({log_path})",
                              host.popen(cmd, stdout=log, stderr=subprocess.STDOUT)))

        # RTT probe from a sensor VLAN host to the server, sampled every 200 ms.
        ping_cmd = ["ping", "-D", "-i", "0.2", "-w", str(duration)]
        if probe_dscp is not None:
            ping_cmd += ["-Q", hex((int(probe_dscp) & 0x3F) << 2)]   # DSCP 48 -> TOS 0xc0
        ping_cmd.append("10.0.30.10")
        probe_t0 = time.time()
        ping = net.get("hs01").popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        attack_start_delay = min(10, max(2, duration // 5))
        win_start, win_len = probe_t0 + attack_start_delay, float(attack_duration if scenario != "normal" else 10)

        if scenario != "normal":
            time.sleep(attack_start_delay)
            win_start = time.time()          # moc that su luc bat dau tan cong
            atk = net.get("atk")
            attack_cmd = [sys.executable, str(TRAFFIC / "attack.py"), "--type", attack_type,
                          "--rate", str(int(attack_rate)), "--duration", str(int(attack_duration)),
                          "--target", "10.0.30.10", "--port", "1883", "--episode", scenario]
            if spoof:
                # Explicit double opt-in is required by attack.py; spoof only inside lab namespaces.
                attack_cmd += ["--spoof", "--allow-spoof"]
            attack_log_path = RESULTS / f"attack_{scenario}.log"
            attack_log = attack_log_path.open("w", encoding="utf-8")
            log_handles.append(attack_log)
            attack = atk.popen(attack_cmd, stdout=attack_log, stderr=subprocess.STDOUT)
            processes.append((f"attack generator ({attack_log_path})", attack))

        # Wait for generators and probes; camera/attack scripts have their own bounded lifetime.
        for label, proc in processes:
            try:
                returncode = proc.wait(timeout=duration + 30)
            except subprocess.TimeoutExpired as exc:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                if strict:
                    raise RuntimeError(f"{label} timed out; inspect its traffic log") from exc
                failed.append(label.split(" (")[0] + " timeout")
                continue
            if returncode != 0:
                m = re.search(r"\((.*)\)$", label)
                if m and Path(m.group(1)).is_file():
                    lines = Path(m.group(1)).read_text(encoding="utf-8", errors="replace").splitlines()
                    print(f"--- 15 dong cuoi cua log {m.group(1)} ---")
                    print("\n".join(lines[-15:]))
                if strict:
                    raise RuntimeError(f"{label} exited with status {returncode}; inspect its traffic log")
                failed.append(label.split(" (")[0] + f" rc={returncode}")
        ping_out, _ = ping.communicate(timeout=duration + 10)
        ping_metrics = _ping_metrics(ping_out)
        win = _window_metrics(_ping_samples(ping_out), win_start, win_start + win_len)
        row = {"timestamp_utc": started_iso, "scenario": scenario, "duration_s": duration,
               "qos_enabled": qos_enabled, "attack_type": attack_type if scenario != "normal" else "none",
               "attack_rate_pps": attack_rate if scenario != "normal" else 0,
               "attack_duration_s": attack_duration if scenario != "normal" else 0,
               **ping_metrics, **win,
               "probe_dscp": probe_dscp if probe_dscp is not None else 0,
               "alarm_ok": not any(f.startswith("MQTT hs01") for f in failed),
               "failed_processes": ";".join(failed)}
        _append_csv(RESULTS / "scenario_metrics.csv", row)
        (RESULTS / f"ping_{scenario}.txt").write_text(ping_out, encoding="utf-8")
        print("Scenario complete:", row)
        print("Camera metrics:", RESULTS / "camera_metrics.csv")
        print("Attack event log:", RESULTS / "attack_events.csv")
        return row
    finally:
        for _, proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in [broker, *iperf_servers]:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for handle in log_handles:
            handle.close()
        if ping is not None and ping.poll() is None:
            ping.terminate()