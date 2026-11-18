"""Kiểm thử bộ phân tích benchmark bằng dữ liệu GIẢ có đáp án biết trước (không phải số liệu thực nghiệm)."""
import json, os, sys, tempfile, csv
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import benchmark as bm

T0 = 1_800_000_000.0

def ping_text(start, rtts, drop=(), interval=0.2):
    lines = ["PING 10.0.30.10 (10.0.30.10) 56(84) bytes of data."]
    for i, r in enumerate(rtts, 1):
        if i in drop: continue
        ts = start + (i - 1) * interval + r / 1000
        lines.append(f"[{ts:.6f}] 64 bytes from 10.0.30.10: icmp_seq={i} ttl=63 time={r} ms")
    return "\n".join(lines) + "\n"

def test_percentile():
    assert bm.percentile([1, 2, 3, 4, 5], 50) == 3
    assert abs(bm.percentile(list(range(1, 101)), 95) - 95.05) < 1e-9
    assert bm.percentile([], 99) is None

def test_parse_and_loss_whole():
    rtts = [10.0] * 50
    s = bm.parse_ping(ping_text(T0, rtts, drop={10, 11}))
    assert len(s) == 48
    st = bm.probe_stats(s)
    assert st["n_sent"] == 50 and st["n_recv"] == 48 and abs(st["loss_pct"] - 4.0) < 1e-9

def test_window_assigns_lost_packets():
    # 100 gói = 20 s; mất gói 60..70 nằm ở giây 11.8..13.8; cửa sổ tấn công = [T0+10, T0+15]
    rtts = [10.0] * 40 + [300.0] * 30 + [10.0] * 30
    s = bm.parse_ping(ping_text(T0, rtts, drop=set(range(60, 71))))
    atk = bm.probe_stats(s, T0 + 8, T0 + 14)       # seq 41..71 -> 31 gói gửi
    out = bm.probe_stats(s, T0 + 15, T0 + 20)
    assert atk["loss_pct"] > 30 and out["loss_pct"] == 0
    assert atk["p99"] == 300.0 and out["p99"] == 10.0

def make_run(root, key, label, ai, rtts, drop, cam_thr, cam_loss, rep=1, react=None):
    d = Path(root) / f"{key}_r{rep:02d}"; d.mkdir(parents=True)
    (d / "ping_alarm_dscp48.txt").write_text(ping_text(T0 - 5, rtts + [10.0] * 50, drop))
    (d / "ping_telemetry_dscp0.txt").write_text(ping_text(T0, [10.0] * len(rtts)))
    (d / "meta.json").write_text(json.dumps({"key": key, "label": label, "ai": ai, "repeat": rep,
                                             "attack_type": "syn_flood" if key != "normal" else "none"}))
    with (d / "camera_metrics.csv").open("w", newline="") as f:
        w = csv.writer(f); w.writerow(["throughput_mbps", "packets_lost", "packets_total", "jitter_ms"])
        for _ in range(20): w.writerow([cam_thr, int(cam_loss * 10), 1000, 0.5])
    if key != "normal":
        (d / "attack_events.csv").write_text(
            "start_utc,end_utc\n2027-01-15T08:00:10+00:00,2027-01-15T08:00:20+00:00\n")
    if react is not None:
        with (d / "live_samples.jsonl").open("w") as f:
            a0 = bm._iso_epoch("2027-01-15T08:00:10+00:00")
            for t in (a0 - 1, a0 + react - 0.5, a0 + react):
                f.write(json.dumps({"t": t, "status_key": "mitigated" if t >= a0 + react else "attack",
                                    "blocked": ["1.1.1.1"] if t >= a0 + react else []}) + "\n")

def test_end_to_end():
    global T0
    T0 = bm._iso_epoch("2027-01-15T08:00:00+00:00")
    root = tempfile.mkdtemp()
    make_run(root, "normal", "Bình thường", False, [20.0] * 300, set(), 80.0, 0.0)
    make_run(root, "attack_no_qos", "Tấn công, chưa bật AI+QoS", False, [20.0] * 50 + [400.0] * 50 + [20.0] * 200, set(range(60, 80)), 40.0, 30.0)
    make_run(root, "attack_ai_qos", "Tấn công, có AI+QoS", True, [20.0] * 300, set(), 79.0, 0.2, react=1.8)
    make_run(root, "attack_ai_qos", "Tấn công, có AI+QoS", True, [20.0] * 300, set(), 79.0, 0.2, rep=2, react=2.2)
    agg = {r["scenario"]: r for r in bm.analyze(root)}
    assert agg["normal"]["alarm_loss_pct"] == 0 and abs(agg["normal"]["alarm_p99"] - 20) < 1e-6
    assert agg["attack_no_qos"]["alarm_atk_p99"] >= 400 - 1e-6 and agg["attack_no_qos"]["alarm_atk_loss_pct"] > 0
    assert abs(agg["attack_ai_qos"]["react_s"] - 2.0) < 1e-6 and agg["attack_ai_qos"]["n_runs"] == 2
    assert abs(agg["normal"]["cam_throughput_total_mbps"] - 1600) < 1e-6
    v = bm.verdict(agg["attack_ai_qos"]); assert v["rtt_ok"] and v["loss_ok"] and v["react_ok"]
    assert not bm.verdict(agg["attack_no_qos"])["rtt_ok"]
    for f in ("bang_2_4_2.md", "hinh_rtt.png", "hinh_throughput.png", "benchmark_summary.csv"):
        assert (Path(root) / f).exists(), f
    print(root)

if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith("test_"): v(); print("ok", k)
