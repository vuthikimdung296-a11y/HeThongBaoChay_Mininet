#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Measure end-to-end MQTT PUBLISH->PUBACK latency for one QoS class.

Run INSIDE a Mininet sensor host, e.g. hs01 (must be on the sensor VLAN so
the DSCP value below actually reaches the Gateway's fire-alarm
classification rule in qos/marks.nft):

  python3 probe_rtt.py --floor 1 --index 2 --count 300 --interval 0.2 --label manual_test

This opens ONE MQTT connection (unlike traffic/normal_mqtt.py, which opens a
fresh connection per real alarm), sets DSCP on that socket once, then
repeatedly publishes a small QoS 1 "probe" message on a dedicated topic and
times how long each PUBLISH takes to be PUBACK-ed. A sample that is not
acknowledged within --timeout seconds counts as lost.

Place this file in experiments/ (sibling of network/, traffic/, qos/).
--index should differ from the sensor index used for real fire alarms in
traffic/normal_mqtt.py (that script defaults to --alarm-index 1), so the
probe's own connection does not share a source IP with the real alarm
sender during the same run.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import paho.mqtt.client as mqtt  # type: ignore[import-not-found]
except ImportError as exc:
    raise SystemExit(
        "Missing paho-mqtt. Install python3-paho-mqtt (or: pip3 install paho-mqtt --break-system-packages)."
    ) from exc

HERE = Path(__file__).resolve().parent
NETWORK_DIR = HERE.parent / "network"
if not NETWORK_DIR.is_dir():
    raise RuntimeError(f"network directory not found: {NETWORK_DIR}")
sys.path.insert(0, str(NETWORK_DIR))

try:
    from ip_plan import sensor_ips  # type: ignore[import-not-found]
except ImportError:
    import importlib.util

    ip_plan_path = NETWORK_DIR / "ip_plan.py"
    if not ip_plan_path.is_file():
        raise RuntimeError(f"ip_plan.py not found: {ip_plan_path}")
    spec = importlib.util.spec_from_file_location("ip_plan", ip_plan_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load ip_plan from {ip_plan_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sensor_ips = module.sensor_ips

DEFAULT_BROKER = os.environ.get("MQTT_BROKER", "10.0.30.10")
DEFAULT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MIN_COUNT, MAX_COUNT = 10, 5000
MIN_INTERVAL, MAX_INTERVAL = 0.01, 10.0
MIN_TIMEOUT, MAX_TIMEOUT = 0.1, 30.0


def make_client(client_id: str):
    try:
        return mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                            client_id=client_id, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=client_id, clean_session=True)


def set_dscp(sock: socket.socket, dscp: int) -> None:
    # IP_TOS stores DSCP in the upper six bits; the low two bits are ECN.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, (dscp & 0x3F) << 2)


def percentile(values_sorted, p: float):
    if not values_sorted:
        return None
    idx = max(0, min(len(values_sorted) - 1, int((p / 100) * (len(values_sorted) - 1) + 0.999999)))
    return round(values_sorted[idx], 4)


class Prober:
    """One MQTT connection, timing PUBLISH->PUBACK for QoS 1 messages."""

    def __init__(self, bind_ip: str, broker: str, port: int, dscp: int, client_id: str):
        self.bind_ip, self.broker, self.port, self.dscp = bind_ip, broker, port, dscp
        self.client = make_client(client_id)
        self.connected = threading.Event()
        self.connect_error = None
        self._wait_mid = None
        self._ack_event = threading.Event()
        self._ack_time = None
        self.client.on_connect = self._on_connect
        self.client.on_publish = self._on_publish
        self.client.on_socket_open = lambda client, userdata, sock: set_dscp(sock, self.dscp)

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        # Paho 1.x and 2.x both pass a success code as the fourth argument.
        try:
            ok = int(reason_code) == 0
        except (TypeError, ValueError):
            ok = str(reason_code).lower() in ("success", "0")
        if ok:
            self.connected.set()
        else:
            self.connect_error = str(reason_code)
            self.connected.set()

    def _on_publish(self, client, userdata, mid, *_extra):
        # paho 1.x calls this with (client, userdata, mid); 2.x adds
        # reason_code/properties. *_extra absorbs either signature.
        if mid == self._wait_mid:
            self._ack_time = time.monotonic()
            self._ack_event.set()

    def connect(self, timeout: float = 8.0) -> None:
        self.client.connect(self.broker, self.port, keepalive=30, bind_address=self.bind_ip)
        self.client.loop_start()
        if not self.connected.wait(timeout):
            raise TimeoutError(f"MQTT connect timeout ({self.bind_ip} -> {self.broker}:{self.port})")
        if self.connect_error:
            raise ConnectionError(f"MQTT connect failed: {self.connect_error}")

    def probe_once(self, topic: str, payload: str, timeout: float):
        """Publish one QoS1 message and time its PUBACK. Returns RTT in ms, or None if lost."""
        self._ack_event.clear()
        self._ack_time = None
        t0 = time.monotonic()
        info = self.client.publish(topic, payload, qos=1)
        self._wait_mid = info.mid
        if not self._ack_event.wait(timeout):
            return None
        return (self._ack_time - t0) * 1000.0

    def close(self) -> None:
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()


def write_live_json(path: Path, label: str, samples_done: int, rtts_ms, lost: int) -> None:
    sorted_rtts = sorted(rtts_ms)
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "samples_so_far": samples_done,
        "lost_so_far": lost,
        "rtt_avg_ms": round(sum(rtts_ms) / len(rtts_ms), 4) if rtts_ms else None,
        "rtt_p95_ms": percentile(sorted_rtts, 95),
        "rtt_p99_ms": percentile(sorted_rtts, 99),
        "loss_percent": round(100.0 * lost / samples_done, 4) if samples_done else 0.0,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def append_csv_row(path: Path, row: dict, fieldnames) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k) for k in fieldnames})


def run(args) -> None:
    addresses = sensor_ips(args.floor)
    if not 1 <= args.index <= len(addresses):
        raise SystemExit(f"index must be 1..{len(addresses)} for floor {args.floor}")
    bind_ip = addresses[args.index - 1]
    sensor_id = f"S{args.floor:02d}-{args.index:02d}"
    client_id = f"probe_{sensor_id}_{int(time.time())}"

    prober = Prober(bind_ip, args.broker, args.port, args.dscp, client_id)
    prober.connect()
    print(f"[PROBE] connected: {sensor_id} ({bind_ip}) -> {args.broker}:{args.port}, DSCP={args.dscp}", flush=True)

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = out_dir / f"rtt_probe_{args.label}.csv"
    summary_path = out_dir / "rtt_summary.csv"
    live_path = args.live_json

    rtts = []
    lost = 0
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    started_utc = datetime.now(timezone.utc).isoformat()
    t_start = time.monotonic()

    try:
        for i in range(1, args.count + 1):
            if stop.is_set():
                break
            sample_t0 = time.monotonic()
            send_ts = datetime.now(timezone.utc).isoformat()
            payload = json.dumps({
                "sensor_id": sensor_id, "floor": args.floor, "probe_seq": i,
                "label": args.label, "timestamp": send_ts,
            })
            rtt_ms = prober.probe_once(args.topic, payload, args.timeout)
            if rtt_ms is None:
                lost += 1
                append_csv_row(samples_path, {"sample": i, "send_ts_utc": send_ts, "rtt_ms": "", "lost": True},
                                ["sample", "send_ts_utc", "rtt_ms", "lost"])
            else:
                rtts.append(rtt_ms)
                append_csv_row(samples_path,
                                {"sample": i, "send_ts_utc": send_ts, "rtt_ms": round(rtt_ms, 4), "lost": False},
                                ["sample", "send_ts_utc", "rtt_ms", "lost"])
            if i % 10 == 0 or i == args.count:
                write_live_json(live_path, args.label, i, rtts, lost)
            # Pace samples at roughly --interval; probe_once already spent up
            # to --timeout waiting for the ack, so only sleep the remainder.
            remaining = args.interval - (time.monotonic() - sample_t0)
            if remaining > 0 and not stop.is_set():
                stop.wait(remaining)
    except KeyboardInterrupt:
        stop.set()
    finally:
        prober.close()

    duration_s = time.monotonic() - t_start
    sorted_rtts = sorted(rtts)
    total = len(rtts) + lost
    summary = {
        "timestamp_utc": started_utc, "label": args.label, "floor": args.floor, "index": args.index,
        "dscp": args.dscp, "topic": args.topic, "count": total, "lost": lost,
        "rtt_avg_ms": round(sum(rtts) / len(rtts), 4) if rtts else None,
        "rtt_p95_ms": percentile(sorted_rtts, 95), "rtt_p99_ms": percentile(sorted_rtts, 99),
        "loss_percent": round(100.0 * lost / total, 4) if total else 0.0,
        "duration_s": round(duration_s, 2),
    }
    append_csv_row(summary_path, summary, list(summary))
    write_live_json(live_path, args.label, total, rtts, lost)
    print(f"[PROBE] done: {summary}", flush=True)
    print(f"[PROBE] samples: {samples_path}", flush=True)
    print(f"[PROBE] summary: {summary_path}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="MQTT PUBLISH->PUBACK RTT probe for one QoS class")
    ap.add_argument("--floor", type=int, required=True, choices=range(1, 11))
    ap.add_argument("--index", type=int, default=1, help="sensor index 1..30 to bind from")
    ap.add_argument("--broker", default=DEFAULT_BROKER)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--interval", type=float, default=0.2, help="target seconds between sample starts")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for PUBACK before counting a loss")
    ap.add_argument("--dscp", type=int, default=48, help="48 (CS6) = fire-alarm class; 0 = telemetry class")
    ap.add_argument("--topic", default="iot/probe/rtt", help="dedicated topic; never mixed with real alarms")
    ap.add_argument("--label", required=True, help="tag identifying this run, e.g. attack_qos-syn_flood-5000pps-r1")
    ap.add_argument("--out-dir", type=Path, default=HERE / "results")
    ap.add_argument("--live-json", type=Path, default=None)
    args = ap.parse_args()

    if not MIN_COUNT <= args.count <= MAX_COUNT:
        ap.error(f"count must be {MIN_COUNT}..{MAX_COUNT}")
    if not MIN_INTERVAL <= args.interval <= MAX_INTERVAL:
        ap.error(f"interval must be {MIN_INTERVAL}..{MAX_INTERVAL}")
    if not MIN_TIMEOUT <= args.timeout <= MAX_TIMEOUT:
        ap.error(f"timeout must be {MIN_TIMEOUT}..{MAX_TIMEOUT}")
    if not 0 <= args.dscp <= 63:
        ap.error("dscp must be 0..63")
    if args.live_json is None:
        args.live_json = args.out_dir / "live_rtt.json"
    run(args)


if __name__ == "__main__":
    main()