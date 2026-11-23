#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate telemetry and real MQTT fire-alarm messages for one Mininet floor.

Run INSIDE a Mininet sensor host, e.g. hs01:
  python3 normal_mqtt.py --floor 1 --duration 60
Each floor host represents 30 logical sensors with 30 distinct source IPs.
Telemetry uses DSCP 0; alarm uses DSCP 48 (CS6) on a separate short-lived TCP
connection so nftables can distinguish it without inspecting MQTT payloads.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import paho.mqtt.client as mqtt  # type: ignore[import-not-found]
except ImportError as exc:
    raise SystemExit("Missing paho-mqtt. Install python3-paho-mqtt.") from exc

HERE = Path(__file__).resolve().parent
NETWORK_DIR = HERE.parent / "Network"
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

BROKER = os.environ.get("MQTT_BROKER", "10.0.30.10")
PORT = int(os.environ.get("MQTT_PORT", "1883"))
TELEMETRY_TOPIC = "iot/sensor/telemetry"
ALARM_TOPIC = "iot/sensor/alarm"


def make_client(client_id: str):
    try:
        return mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                           client_id=client_id, clean_session=True)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=client_id, clean_session=True)


def set_dscp(client, sock, dscp: int):
    # IP_TOS stores DSCP in the upper six bits; the low two bits are ECN.
    import socket
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, (dscp & 0x3F) << 2)


class VirtualSensor:
    def __init__(self, floor: int, index: int, ip: str):
        self.floor, self.index, self.ip = floor, index, ip
        self.sensor_id = f"S{floor:02d}-{index:02d}"
        self.client = make_client(f"tele_{self.sensor_id}")
        self.connected = threading.Event()
        self.error = None
        self.client.on_connect = self._on_connect
        self.client.on_socket_open = lambda client, userdata, sock: set_dscp(client, sock, 0)

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        # Paho 1.x and 2.x both pass a success code as the fourth argument.
        try:
            ok = int(reason_code) == 0
        except (TypeError, ValueError):
            ok = str(reason_code).lower() in ("success", "0")
        if ok:
            self.connected.set()
        else:
            self.error = str(reason_code)
            self.connected.set()

    def connect(self):
        self.client.connect(BROKER, PORT, keepalive=30, bind_address=self.ip)
        self.client.loop_start()
        if not self.connected.wait(8):
            raise TimeoutError(f"MQTT connect timeout: {self.sensor_id} ({self.ip})")
        if self.error:
            raise ConnectionError(f"MQTT connect failed: {self.sensor_id}: {self.error}")

    def send_telemetry(self):
        payload = {
            "sensor_id": self.sensor_id,
            "floor": self.floor,
            "status": "normal",
            "temperature_c": 25.5,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        info = self.client.publish(TELEMETRY_TOPIC, json.dumps(payload), qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"Telemetry publish failed for {self.sensor_id}: rc={info.rc}")

    def send_fire_alarm(self):
        # A separate connection is essential: DSCP is per IP packet/socket,
        # not per MQTT topic/message on a shared TCP connection.
        alarm = make_client(f"alarm_{self.sensor_id}_{int(time.time())}")
        connected = threading.Event()
        errors = []

        def on_connect(client, userdata, flags, reason_code, properties=None):
            try:
                ok = int(reason_code) == 0
            except (TypeError, ValueError):
                ok = str(reason_code).lower() in ("success", "0")
            if not ok:
                errors.append(str(reason_code))
            connected.set()

        alarm.on_connect = on_connect
        alarm.on_socket_open = lambda client, userdata, sock: set_dscp(client, sock, 48)
        alarm.connect(BROKER, PORT, keepalive=15, bind_address=self.ip)
        alarm.loop_start()
        try:
            if not connected.wait(8) or errors:
                raise ConnectionError(f"Alarm MQTT connection failed: {errors or 'timeout'}")
            payload = {
                "sensor_id": self.sensor_id,
                "floor": self.floor,
                "status": "FIRE_DETECTED",
                "temperature_c": 75.0,
                "severity": "critical",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            info = alarm.publish(ALARM_TOPIC, json.dumps(payload), qos=1, retain=False)
            info.wait_for_publish(timeout=8)
            if not info.is_published():
                raise TimeoutError("Alarm publish was not acknowledged before timeout")
        finally:
            alarm.disconnect()
            alarm.loop_stop()

    def close(self):
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()


def main():
    ap = argparse.ArgumentParser(description="MQTT telemetry/fire-alarm generator for one floor")
    ap.add_argument("--floor", type=int, required=True, choices=range(1, 11))
    ap.add_argument("--duration", type=float, default=120)
    ap.add_argument("--telemetry-interval", type=float, default=30)
    ap.add_argument("--alarm-after", type=float, default=None,
                    help="seconds after start to publish one real FIRE_DETECTED message")
    ap.add_argument("--alarm-index", type=int, default=1, help="sensor index 1..30 for alarm")
    args = ap.parse_args()
    if args.duration <= 0 or args.telemetry_interval <= 0:
        ap.error("duration and telemetry-interval must be positive")
    if not 1 <= args.alarm_index <= 30:
        ap.error("alarm-index must be between 1 and 30")

    addresses = sensor_ips(args.floor)
    if len(addresses) != 30 or len(set(addresses)) != 30:
        raise RuntimeError(f"IP plan error on floor {args.floor}: expected 30 unique IPs")
    sensors = [VirtualSensor(args.floor, i + 1, ip) for i, ip in enumerate(addresses)]
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    connected = []
    try:
        for sensor in sensors:
            sensor.connect()
            connected.append(sensor)
        print(f"[MQTT] floor={args.floor}: connected {len(connected)} sensors, IPs {addresses[0]}..{addresses[-1]}", flush=True)
        started = time.monotonic()
        next_telemetry = 0.0
        alarm_sent = False
        while not stop.is_set() and time.monotonic() - started < args.duration:
            elapsed = time.monotonic() - started
            if elapsed >= next_telemetry:
                for sensor in sensors:
                    sensor.send_telemetry()
                next_telemetry += args.telemetry_interval
            if args.alarm_after is not None and not alarm_sent and elapsed >= args.alarm_after:
                sensors[args.alarm_index - 1].send_fire_alarm()
                alarm_sent = True
                print(f"[MQTT] FIRE ALARM published by {sensors[args.alarm_index - 1].sensor_id} (DSCP 48)", flush=True)
            stop.wait(0.2)
    finally:
        for sensor in connected:
            sensor.close()
        print(f"[MQTT] floor={args.floor}: stopped", flush=True)


if __name__ == "__main__":
    main()
