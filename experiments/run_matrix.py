#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the full normal / attack_no_qos / attack_qos experiment matrix.

Must be called from the live Mininet CLI, with the network already running
(python3 topology.py from inside network/), e.g.:

  mininet> py import sys; sys.path.insert(0, '..')
  mininet> py from experiments.run_matrix import run_matrix
  mininet> py run_matrix(net)

Reuses the already-running network for every run (no mn -c / rebuild between
runs): it starts/stops only the per-run services (broker, iperf3 servers,
QoS, generators), the same way traffic/run_scenario.py already does for a
single run.

Matrix (13 combinations x repeats, default repeats=3 => 39 runs):
  - normal                                              x repeats
  - attack_no_qos, syn_flood, rate in {500,1000,5000} x repeats
  - attack_no_qos, udp_flood, rate in {2000,5000,12000} x repeats
  - attack_qos,    syn_flood, rate in {500,1000,5000} x repeats
  - attack_qos,    udp_flood, rate in {2000,5000,12000} x repeats

NOTE: traffic/attack.py currently refuses rate > MAX_RATE_PPS (5000 at the
time this script was written). Runs above that cap are recorded as
"skipped_rate_cap" in the manifest instead of raising, so one capped
combination does not abort the whole matrix. Raise MAX_RATE_PPS in
traffic/attack.py before running the full matrix for the final report.

Each run also launches experiments/probe_rtt.py on hs01 (sensor index 2, so
it never shares a source IP with the real fire-alarm sender, which uses
index 1) to measure fire-alarm-class RTT via MQTT PUBLISH->PUBACK, alongside
the ping-based RTT that traffic/run_scenario.py already records. Whether the
report's official RTT number should come from ping or from PUBACK is still
open (see the "can chot" list in the task-split doc) — this script collects
both so the team can compare before deciding.
"""
from __future__ import annotations

import csv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "experiments"
RESULTS = EXPERIMENTS / "results"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Imported this way (not a plain "from traffic.run_scenario import ...") so
# it keeps working even without __init__.py files, matching the pattern
# traffic/README.md already documents for the Mininet CLI.
run_scenario = __import__("traffic.run_scenario", fromlist=["run_scenario"]).run_scenario

MANIFEST_FIELDS = [
    "run_id", "scenario", "attack_type", "attack_rate_pps", "repeat",
    "status", "error", "started_utc", "ended_utc",
    "rtt_avg_ms", "rtt_p95_ms", "rtt_p99_ms", "ping_packet_loss_percent",
    "win_rtt_avg_ms", "win_rtt_p95_ms", "win_rtt_p99_ms", "win_loss_percent",
    "alarm_ok", "failed_processes",
]


def _build_combinations(include_edge_ai=True):
    combos = [("normal", None, 0)]
    for attack_type, rates in (("syn_flood", (500, 1000, 5000)), ("udp_flood", (2000, 5000, 12000))):
        for rate in rates:
            combos.append(("attack_no_qos", attack_type, rate))
            combos.append(("attack_qos", attack_type, rate))
            if include_edge_ai:
                combos.append(("attack_qos_edge_ai", attack_type, rate))
    return combos


def _run_id(scenario: str, attack_type, rate: int, repeat: int) -> str:
    kind = attack_type or "none"
    return f"{scenario}-{kind}-{rate}pps-r{repeat}"


def _load_done_run_ids(manifest_path: Path):
    done = set()
    if not manifest_path.exists():
        return done
    with manifest_path.open("r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("status") == "ok":
                done.add(row.get("run_id", ""))
    return done


def _append_manifest(manifest_path: Path, row: dict) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    new = not manifest_path.exists()
    with manifest_path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in MANIFEST_FIELDS})


def _start_probe(net, label: str, scenario_duration: int):
    """Launch experiments/probe_rtt.py on hs01 for the fire-alarm QoS class."""
    host = net.get("hs01")
    count = max(10, min(300, int((scenario_duration - 10) / 0.2)))
    cmd = [sys.executable, str(EXPERIMENTS / "probe_rtt.py"),
           "--floor", "1", "--index", "2", "--count", str(count), "--interval", "0.2",
           "--dscp", "48", "--label", label]
    log_path = RESULTS / f"probe_{label}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w", encoding="utf-8")
    proc = host.popen(cmd, stdout=log, stderr=log)
    return proc, log


def _stop_probe(proc, log, scenario_duration: int) -> None:
    try:
        proc.wait(timeout=max(10, scenario_duration))
    except Exception:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    finally:
        log.close()


def run_matrix(net, repeats: int = 3, duration: int = 90, attack_duration: int = 20,
                resume: bool = True, cooldown_s: float = 5.0, with_probe: bool = True,
                manifest_path=None):
    """Run every (scenario, attack_type, rate) x repeats combination once.

    resume=True (default): combinations already marked "ok" in the manifest
    from a previous call are skipped, so an interrupted matrix can be
    continued by calling this function again.
    """
    manifest_path = Path(manifest_path) if manifest_path else (RESULTS / "run_matrix_manifest.csv")
    done = _load_done_run_ids(manifest_path) if resume else set()
    combos = _build_combinations()

    total = len(combos) * repeats
    counters = {"ok": 0, "skipped_rate_cap": 0, "skipped_resume": 0, "error": 0}
    print(f"[MATRIX] {total} runs planned ({len(combos)} combinations x {repeats} repeats); "
          f"{len(done)} already marked ok and will be skipped.", flush=True)

    for scenario, attack_type, rate in combos:
        for repeat in range(1, repeats + 1):
            run_id = _run_id(scenario, attack_type, rate, repeat)
            if run_id in done:
                print(f"[MATRIX] {run_id}: already ok, skipping.", flush=True)
                counters["skipped_resume"] += 1
                continue

            started_utc = datetime.now(timezone.utc).isoformat()
            probe_proc = probe_log = None
            try:
                if with_probe:
                    probe_proc, probe_log = _start_probe(net, run_id, duration)

                result = run_scenario(net, scenario=scenario, duration=duration,
                                       attack_type=attack_type or "syn_flood",
                                       attack_rate=rate, attack_duration=attack_duration)
                row = {
                    "run_id": run_id, "scenario": scenario, "attack_type": attack_type or "none",
                    "attack_rate_pps": rate, "repeat": repeat, "status": "ok", "error": "",
                    "started_utc": started_utc, "ended_utc": datetime.now(timezone.utc).isoformat(),
                    "rtt_avg_ms": result.get("rtt_avg_ms"), "rtt_p95_ms": result.get("rtt_p95_ms"),
                    "rtt_p99_ms": result.get("rtt_p99_ms"),
                    "ping_packet_loss_percent": result.get("ping_packet_loss_percent"),
                    **{k: result.get(k) for k in ("win_rtt_avg_ms", "win_rtt_p95_ms", "win_rtt_p99_ms",
                                                  "win_loss_percent", "alarm_ok", "failed_processes")},
                }
                counters["ok"] += 1
            except ValueError as exc:
                # traffic/attack.py raises ValueError when rate exceeds its own
                # safety cap; record and move on instead of aborting the matrix.
                row = {
                    "run_id": run_id, "scenario": scenario, "attack_type": attack_type or "none",
                    "attack_rate_pps": rate, "repeat": repeat, "status": "skipped_rate_cap",
                    "error": str(exc), "started_utc": started_utc,
                    "ended_utc": datetime.now(timezone.utc).isoformat(),
                }
                counters["skipped_rate_cap"] += 1
                print(f"[MATRIX] {run_id}: skipped ({exc}).", flush=True)
            except Exception as exc:  # log and continue the matrix
                row = {
                    "run_id": run_id, "scenario": scenario, "attack_type": attack_type or "none",
                    "attack_rate_pps": rate, "repeat": repeat, "status": "error",
                    "error": str(exc), "started_utc": started_utc,
                    "ended_utc": datetime.now(timezone.utc).isoformat(),
                }
                counters["error"] += 1
                print(f"[MATRIX] {run_id}: ERROR: {exc}", flush=True)
            finally:
                if probe_proc is not None:
                    _stop_probe(probe_proc, probe_log, duration)

            _append_manifest(manifest_path, row)
            time.sleep(cooldown_s)

    print(f"[MATRIX] finished: {counters}", flush=True)
    print(f"[MATRIX] manifest: {manifest_path}", flush=True)
    return counters


if __name__ == "__main__":
    print(__doc__)