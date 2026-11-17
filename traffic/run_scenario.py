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
                 camera_bandwidth="4M", telemetry_interval=30):
    """Run one repeatable experiment using Mininet host objects from the CLI.

    Scenarios: normal, attack_no_qos, attack_qos. QoS is applied only in
    attack_qos. The MQTT broker and iperf3 server run inside `srv` namespace.
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

    # Start the actual MQTT broker and iperf3 receiver in the server namespace.
    broker = _start_service(srv, ["mosquitto", "-p", "1883"])
    iperf_server = _start_service(srv, ["iperf3", "-s", "-p", "5201"])
    _wait_port(srv, 1883)
    _wait_port(srv, 5201)

    processes = []
    log_handles = []
    ping = None
    started_iso = datetime.now(timezone.utc).isoformat()
    try:
        # Ten hosts, each representing 30 logical sensors with unique IP aliases.
        for floor in range(1, 11):
            host = net.get(f"hs{floor:02d}")
            cmd = [sys.executable, str(TRAFFIC / "normal_mqtt.py"), "--floor", str(floor),
                   "--duration", str(duration), "--telemetry-interval", str(telemetry_interval)]
            if floor == 1:
                cmd += ["--alarm-after", "10", "--alarm-index", "1"]
            log = (RESULTS / f"mqtt_hs{floor:02d}.log").open("w", encoding="utf-8")
            log_handles.append(log)
            processes.append(host.popen(cmd, stdout=log, stderr=subprocess.STDOUT))

        # Twenty independent camera hosts, each capped at the requested UDP rate.
        for number in range(1, 21):
            host = net.get(f"cam{number:02d}")
            camera_id = f"cam{number:02d}"
            cmd = [sys.executable, str(TRAFFIC / "camera_iperf.py"), "--camera-id", camera_id,
                   "--target", "10.0.30.10", "--bandwidth", camera_bandwidth,
                   "--duration", str(duration), "--output-dir", str(RESULTS)]
            log = (RESULTS / f"{camera_id}.log").open("w", encoding="utf-8")
            log_handles.append(log)
            processes.append(host.popen(cmd, stdout=log, stderr=subprocess.STDOUT))

        # RTT probe from a sensor VLAN host to the server, sampled every 200 ms.
        ping = net.get("hs01").popen(["ping", "-D", "-i", "0.2", "-w", str(duration), "10.0.30.10"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        if scenario != "normal":
            attack_start_delay = min(10, max(2, duration // 5))
            time.sleep(attack_start_delay)
            atk = net.get("atk")
            attack_cmd = [sys.executable, str(TRAFFIC / "attack.py"), "--type", attack_type,
                          "--rate", str(int(attack_rate)), "--duration", str(int(attack_duration)),
                          "--target", "10.0.30.10", "--port", "1883", "--episode", scenario]
            if spoof:
                # Explicit double opt-in is required by attack.py; spoof only inside lab namespaces.
                attack_cmd += ["--spoof", "--allow-spoof"]
            attack = atk.popen(attack_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(attack)

        # Wait for generators and probes; camera/attack scripts have their own bounded lifetime.
        for proc in processes:
            try:
                proc.wait(timeout=duration + 30)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        ping_out, _ = ping.communicate(timeout=duration + 10)
        ping_metrics = _ping_metrics(ping_out)
        row = {"timestamp_utc": started_iso, "scenario": scenario, "duration_s": duration,
               "qos_enabled": qos_enabled, "attack_type": attack_type if scenario != "normal" else "none",
               "attack_rate_pps": attack_rate if scenario != "normal" else 0,
               "attack_duration_s": attack_duration if scenario != "normal" else 0,
               **ping_metrics}
        _append_csv(RESULTS / "scenario_metrics.csv", row)
        (RESULTS / f"ping_{scenario}.txt").write_text(ping_out, encoding="utf-8")
        print("Scenario complete:", row)
        print("Camera metrics:", RESULTS / "camera_metrics.csv")
        print("Attack event log:", RESULTS / "events.csv")
        return row
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in (iperf_server, broker):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for handle in log_handles:
            handle.close()
        if ping is not None and ping.poll() is None:
            ping.terminate()
