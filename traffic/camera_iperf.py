#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate one bounded UDP camera stream and record receiver-side metrics."""
from __future__ import annotations
import argparse, csv, json, subprocess
from datetime import datetime, timezone
from pathlib import Path


def _summary(result: dict) -> dict:
    """Prefer receiver statistics; sender statistics are a fallback only."""
    server = result.get("server_output_json") or {}
    end_server = server.get("end", {}) if isinstance(server, dict) else {}
    end_client = result.get("end", {})
    candidates = [end_server.get("sum"), end_server.get("sum_received"),
                  end_client.get("sum_received"), end_client.get("sum"),
                  end_client.get("sum_sent")]
    return next((x for x in candidates if isinstance(x, dict) and x), {})


def extract_metrics(result: dict) -> dict:
    s = _summary(result)
    sent = (result.get("end", {}).get("sum_sent") or {})
    received = (result.get("server_output_json", {}).get("end", {}).get("sum") or
                result.get("end", {}).get("sum_received") or {})
    jitter = s.get("jitter_ms", s.get(" jitter_ms", 0))
    lost = s.get("lost_packets", received.get("lost_packets", 0))
    total = s.get("packets", received.get("packets", 0))
    return {
        "throughput_mbps": round(float(s.get("bits_per_second", 0) or 0) / 1e6, 6),
        "jitter_ms": round(float(jitter or 0), 6),
        "packet_loss_percent": round(float(s.get("lost_percent", 0) or 0), 6),
        "packets_lost": int(lost or 0),
        "packets_total": int(total or 0),
        "bytes_sent": int(sent.get("bytes", 0) or 0),
        "bytes_received": int(received.get("bytes", 0) or 0),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="One camera UDP stream using iperf3")
    ap.add_argument("--camera-id", required=True)
    ap.add_argument("--target", default="10.0.30.10")
    ap.add_argument("--port", type=int, default=5201)
    ap.add_argument("--bandwidth", default="4M")
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--interval", type=int, default=1)
    ap.add_argument("--output-dir", default=str(Path(__file__).resolve().parent / "results"))
    args = ap.parse_args()
    if not (1 <= args.port <= 65535 and 1 <= args.duration <= 600 and 1 <= args.interval <= args.duration):
        ap.error("port/duration/interval out of allowed range")
    outdir = Path(args.output_dir); outdir.mkdir(parents=True, exist_ok=True)
    cmd = ["iperf3", "-c", args.target, "-p", str(args.port), "-u", "-b", args.bandwidth,
           "-t", str(args.duration), "-i", str(args.interval), "--get-server-output", "-J"]
    started = datetime.now(timezone.utc).isoformat()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.duration + 30, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"iperf3 timeout for {args.camera_id}") from exc
    raw = outdir / f"iperf_{args.camera_id}.json"
    raw.write_text(proc.stdout or proc.stderr or "", encoding="utf-8")
    if proc.returncode != 0:
        raise SystemExit(f"iperf3 failed for {args.camera_id} (rc={proc.returncode}): {proc.stderr[-1000:]}")
    try: result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc: raise SystemExit(f"Invalid JSON; inspect {raw}") from exc
    row = {"timestamp_utc": started, "camera_id": args.camera_id, "target": args.target,
           "port": args.port, "bandwidth_requested": args.bandwidth, "duration_s": args.duration,
           **extract_metrics(result)}
    path = outdir / "camera_metrics.csv"; exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row));
        if not exists: writer.writeheader()
        writer.writerow(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)

if __name__ == "__main__": main()
