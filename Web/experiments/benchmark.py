# -*- coding: utf-8 -*-
"""benchmark.py - Chạy 3 kịch bản của Tổ 3 nhiều lượt và tính RTT (TB/P95/P99), Throughput, Packet Loss.

Hai chế độ:
  1) CHẠY (tại mininet>, mạng đã dựng):
        mininet> py import sys; sys.path.insert(0, '..')
        mininet> py from Web.experiments.benchmark import run_all
        mininet> py run_all(net, repeats=3, duration=60, attack_type='syn_flood', attack_rate=1000, attack_duration=20)
     Mỗi lượt lưu vào experiments/results/benchmark_<thời gian>_<kiểu tấn công>/<kịch bản>_rNN/ rồi tự phân tích.
  2) PHÂN TÍCH (máy nào cũng chạy được, chỉ cần thư mục kết quả):
        python3 Web/experiments/benchmark.py analyze experiments/results/benchmark_xxx

Các phép đo (mỗi lượt):
  - RTT báo cháy   : ping -Q 192 (DSCP 48 = lớp báo cháy, mark 0x10) từ hs02 -> srv, 5 gói/giây. Đây là mẫu
                     đại diện cho bản tin báo cháy; ping KHÔNG phải RTT MQTT đầy đủ (ghi rõ trong báo cáo).
  - RTT telemetry  : ping của run_scenario (DSCP 0, lớp 0x11) để đối chiếu.
  - Throughput     : tổng Mbps 20 luồng camera (iperf3 UDP, đo ở phía nhận).
  - Packet loss    : % mất gói của probe báo cháy; % mất gói UDP camera (iperf3).
  - Thời gian phản ứng AI (chỉ kịch bản 3): từ lúc tấn công bắt đầu đến lúc live_metrics.json báo
                     BLOCKED hoặc có IP bị chặn (KPI <= 3 s).
Phân vị dùng nội suy tuyến tính (giống numpy.percentile mặc định).
"""
from __future__ import annotations

import csv
import json
import math
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT, ROOT / "Web" / "dashboard", ROOT / "Web" / "experiments"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

T3_RESULTS = ROOT / "traffic" / "results"
RESULTS = ROOT / "experiments" / "results"
PROBE_INTERVAL_S = 0.2
KPI_RTT_NORMAL, KPI_RTT_ATTACK, KPI_REACT_S = 50.0, 200.0, 3.0

SCENARIOS = [
    {"key": "normal", "label": "Bình thường", "run": "normal", "ai": False},
    {"key": "attack_no_qos", "label": "Tấn công, chưa bật AI+QoS", "run": "attack_no_qos", "ai": False},
    {"key": "attack_ai_qos", "label": "Tấn công, có AI+QoS", "run": "attack_qos", "ai": True},
]
QOS_ONLY = {"key": "attack_qos_only", "label": "Tấn công, chỉ QoS (đối chứng)", "run": "attack_qos", "ai": False}


# ====================================================================== thống kê / phân tích
def percentile(values, p):
    v = sorted(values)
    if not v:
        return None
    if len(v) == 1:
        return v[0]
    k = (len(v) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def mean(values):
    return sum(values) / len(values) if values else None


def stdev(values):
    if len(values) < 2:
        return 0.0 if values else None
    m = mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / (len(values) - 1))


_RE_REPLY = re.compile(r"^\[(?P<ts>[0-9.]+)\].*?icmp_seq=(?P<seq>\d+).*?time[=<](?P<rtt>[0-9.]+)\s*ms")


def parse_ping(text: str):
    """Đọc đầu ra `ping -D`. Trả về danh sách (ts_nhận, seq, rtt_ms) theo thứ tự."""
    out = []
    for line in text.splitlines():
        m = _RE_REPLY.match(line.strip())
        if m:
            out.append((float(m["ts"]), int(m["seq"]), float(m["rtt"])))
    return out


def probe_stats(samples, t0=None, t1=None, interval=PROBE_INTERVAL_S):
    """Thống kê RTT và mất gói trong cửa sổ [t0, t1] (epoch giây).

    Thời điểm gửi của gói seq được ước lượng tuyến tính từ gói đầu tiên nhận được; nhờ đó gói bị mất
    (không có dòng trả lời) vẫn được gán vào đúng cửa sổ thời gian."""
    if not samples:
        return {"n_sent": 0, "n_recv": 0, "loss_pct": None, "avg": None, "p95": None, "p99": None, "max": None}
    ts0, seq0, rtt0 = samples[0]
    send0 = ts0 - rtt0 / 1000.0
    send_of = lambda s: send0 + (s - seq0) * interval
    last_seq = max(s for _, s, _ in samples)
    first_seq = min(seq0, min(s for _, s, _ in samples))
    seqs = range(first_seq, last_seq + 1)
    lo = t0 if t0 is not None else -math.inf
    hi = t1 if t1 is not None else math.inf
    expected = {s for s in seqs if lo <= send_of(s) <= hi}
    got = [(s, r) for _, s, r in samples if s in expected]
    rtts = [r for _, r in got]
    n_sent, n_recv = len(expected), len(got)
    return {"n_sent": n_sent, "n_recv": n_recv,
            "loss_pct": (100.0 * (n_sent - n_recv) / n_sent) if n_sent else None,
            "avg": mean(rtts), "p95": percentile(rtts, 95), "p99": percentile(rtts, 99),
            "max": max(rtts) if rtts else None}


def _iso_epoch(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def _read_csv(path: Path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def analyze_run(run_dir: Path) -> dict:
    """Tính toàn bộ chỉ số của một lượt chạy từ các file đã lưu trong run_dir."""
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    alarm = parse_ping((run_dir / "ping_alarm_dscp48.txt").read_text(encoding="utf-8")) \
        if (run_dir / "ping_alarm_dscp48.txt").exists() else []
    tele = parse_ping((run_dir / "ping_telemetry_dscp0.txt").read_text(encoding="utf-8")) \
        if (run_dir / "ping_telemetry_dscp0.txt").exists() else []

    # cửa sổ đo = khoảng thời gian probe của run_scenario (traffic đã chạy đủ), tránh phần khởi động
    t0 = tele[0][0] - tele[0][2] / 1000 if tele else None
    t1 = tele[-1][0] if tele else None
    ev = _read_csv(run_dir / "attack_events.csv")
    a0 = a1 = None
    if ev:
        a0, a1 = _iso_epoch(ev[-1]["start_utc"]), _iso_epoch(ev[-1]["end_utc"])

    res = {"run": run_dir.name, "scenario": meta["key"], "label": meta["label"], "repeat": meta.get("repeat"),
           "attack_type": meta.get("attack_type")}
    for name, samples, key in (("alarm", alarm, "alarm"), ("tele", tele, "tele")):
        whole = probe_stats(samples, t0, t1)
        res.update({f"{key}_avg": whole["avg"], f"{key}_p95": whole["p95"], f"{key}_p99": whole["p99"],
                    f"{key}_max": whole["max"], f"{key}_loss_pct": whole["loss_pct"], f"{key}_n": whole["n_sent"]})
        if a0 is not None:
            w = probe_stats(samples, a0, a1)
            res.update({f"{key}_atk_avg": w["avg"], f"{key}_atk_p95": w["p95"], f"{key}_atk_p99": w["p99"],
                        f"{key}_atk_loss_pct": w["loss_pct"]})

    cams = _read_csv(run_dir / "camera_metrics.csv")
    if cams:
        thr = [_f(c["throughput_mbps"]) or 0.0 for c in cams]
        lost = sum(_f(c["packets_lost"]) or 0 for c in cams)
        tot = sum(_f(c["packets_total"]) or 0 for c in cams)
        res.update({"cam_n": len(cams), "cam_throughput_total_mbps": sum(thr),
                    "cam_throughput_mean_mbps": mean(thr),
                    "cam_loss_pct": (100.0 * lost / tot) if tot else None,
                    "cam_jitter_ms": mean([_f(c["jitter_ms"]) or 0.0 for c in cams])})

    # thời gian phản ứng của Edge AI
    samples_f = run_dir / "live_samples.jsonl"
    if meta.get("ai") and a0 is not None and samples_f.exists():
        react = None
        for line in samples_f.read_text(encoding="utf-8").splitlines():
            s = json.loads(line)
            if s["t"] >= a0 and (s.get("blocked") or s.get("rate_limit") or s.get("status_key") == "mitigated"):
                react = s["t"] - a0
                break
        res["react_s"] = react
    return res


METRICS = ["alarm_avg", "alarm_p95", "alarm_p99", "alarm_loss_pct", "alarm_atk_avg", "alarm_atk_p95",
           "alarm_atk_p99", "alarm_atk_loss_pct", "tele_avg", "tele_p95", "tele_p99", "tele_atk_p95",
           "cam_throughput_total_mbps", "cam_loss_pct", "cam_jitter_ms", "react_s"]


def aggregate(runs: list[dict]) -> list[dict]:
    order, out = [], []
    for r in runs:
        if r["scenario"] not in order:
            order.append(r["scenario"])
    canon = [x["key"] for x in SCENARIOS + [QOS_ONLY]]
    order.sort(key=lambda k: canon.index(k) if k in canon else 99)
    for key in order:
        grp = [r for r in runs if r["scenario"] == key]
        row = {"scenario": key, "label": grp[0]["label"], "n_runs": len(grp)}
        for m in METRICS:
            vals = [r[m] for r in grp if r.get(m) is not None]
            row[m] = mean(vals)
            row[m + "_std"] = stdev(vals)
            row[m + "_n"] = len(vals)
        out.append(row)
    return out


def _fmt(v, nd=1, std=None, unit=""):
    if v is None:
        return "n/a"
    return f"{v:.{nd}f}" + (f" ± {std:.{nd}f}" if std not in (None, 0.0) else "") + unit


def verdict(row):
    """Đối chiếu KPI mục 2.1.3 (RTT: P99 trong cửa sổ liên quan; mất gói báo cháy = 0; phản ứng <= 3 s)."""
    atk = row["scenario"] != "normal"
    p99 = row.get("alarm_atk_p99") if atk else row.get("alarm_p99")
    lim = KPI_RTT_ATTACK if atk else KPI_RTT_NORMAL
    loss = row.get("alarm_atk_loss_pct") if atk else row.get("alarm_loss_pct")
    return {"rtt_ok": None if p99 is None else p99 <= lim, "loss_ok": None if loss is None else loss == 0,
            "react_ok": None if row.get("react_s") is None else row["react_s"] <= KPI_REACT_S}


def _ok(b):
    return "n/a" if b is None else ("Đạt" if b else "Không đạt")


def write_markdown(agg, path: Path, attack_type, n_runs):
    L = [f"# Bảng số liệu mục 2.4.2 ({attack_type}, {n_runs} lượt/kịch bản)", "",
         "Giá trị: trung bình ± độ lệch chuẩn giữa các lượt. Probe báo cháy = ping DSCP 48 (5 gói/giây).", "",
         "## Bảng A. RTT bản tin báo cháy (ms) và mất gói", "",
         "| Kịch bản | RTT TB | RTT P95 | RTT P99 | Mất gói | RTT TB (đoạn tấn công) | P95 (đoạn tấn công) | "
         "P99 (đoạn tấn công) | Mất gói (đoạn tấn công) | KPI RTT | KPI mất gói |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in agg:
        v = verdict(r)
        L.append(f"| {r['label']} | {_fmt(r['alarm_avg'], 1, r['alarm_avg_std'])} | {_fmt(r['alarm_p95'], 1, r['alarm_p95_std'])} | "
                 f"{_fmt(r['alarm_p99'], 1, r['alarm_p99_std'])} | {_fmt(r['alarm_loss_pct'], 2, None, '%')} | "
                 f"{_fmt(r['alarm_atk_avg'], 1)} | {_fmt(r['alarm_atk_p95'], 1)} | {_fmt(r['alarm_atk_p99'], 1)} | "
                 f"{_fmt(r['alarm_atk_loss_pct'], 2, None, '%')} | {_ok(v['rtt_ok'])} | {_ok(v['loss_ok'])} |")
    L += ["", "## Bảng B. Throughput camera, mất gói UDP camera, thời gian phản ứng AI", "",
          "| Kịch bản | Throughput 20 camera (Mbps) | Mất gói UDP camera | Jitter camera (ms) | RTT telemetry P95 (ms) | "
          "Thời gian phản ứng AI (s) | KPI ≤ 3 s |", "|---|---|---|---|---|---|---|"]
    for r in agg:
        v = verdict(r)
        L.append(f"| {r['label']} | {_fmt(r['cam_throughput_total_mbps'], 1, r['cam_throughput_total_mbps_std'])} | "
                 f"{_fmt(r['cam_loss_pct'], 2, None, '%')} | {_fmt(r['cam_jitter_ms'], 2)} | {_fmt(r['tele_p95'], 1)} | "
                 f"{_fmt(r['react_s'], 2, r['react_s_std'])} | {_ok(v['react_ok']) if r['react_s_n'] or r['scenario'].endswith('ai_qos') else 'không áp dụng'} |")
    L += ["", "Lưu ý: ping là mẫu đại diện cho độ trễ lớp báo cháy, không thay thế RTT MQTT đầy đủ. "
          "Mất gói tính theo số gói ping không có phản hồi, sai số tối đa ±1 gói ở biên cửa sổ."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def make_charts(agg, outdir: Path, attack_type):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = [r["label"].replace(", ", ",\n") for r in agg]
    x = range(len(agg))
    # Hình 1: RTT trong đoạn tấn công (hoặc cả lượt với kịch bản bình thường)
    fig, ax = plt.subplots(figsize=(9, 5))
    w = 0.26
    for i, (m, name, c) in enumerate((("avg", "Trung bình", "#2B6CB0"), ("p95", "P95", "#E08A00"), ("p99", "P99", "#C93A3A"))):
        vals = [(r[f"alarm_atk_{m}"] if r["scenario"] != "normal" else r[f"alarm_{m}"]) or 0 for r in agg]
        bars = ax.bar([k + (i - 1) * w for k in x], vals, w, label=name, color=c)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.0f}", ha="center", va="bottom", fontsize=8)
    ax.axhline(KPI_RTT_NORMAL, color="#555", ls=":", lw=1.2)
    ax.axhline(KPI_RTT_ATTACK, color="#C93A3A", ls="--", lw=1.2)
    ax.text(len(agg) - 0.5, KPI_RTT_ATTACK + 4, "Ngưỡng 200 ms", ha="right", fontsize=9, color="#C93A3A")
    ax.text(len(agg) - 0.5, KPI_RTT_NORMAL + 4, "Ngưỡng 50 ms", ha="right", fontsize=9, color="#555")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels); ax.set_ylabel("RTT bản tin báo cháy (ms)")
    ax.set_title(f"RTT theo kịch bản ({attack_type}; đoạn tấn công với kịch bản 2, 3)")
    ax.legend(); ax.grid(axis="y", alpha=0.3); fig.tight_layout()
    fig.savefig(outdir / "hinh_rtt.png", dpi=160); plt.close(fig)
    # Hình 2: throughput và mất gói camera
    fig, ax = plt.subplots(figsize=(9, 5))
    thr = [r["cam_throughput_total_mbps"] or 0 for r in agg]
    bars = ax.bar(list(x), thr, 0.5, color="#1E8E4E")
    for b, v in zip(bars, thr):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(list(x)); ax.set_xticklabels(labels); ax.set_ylabel("Throughput 20 camera (Mbps)")
    ax2 = ax.twinx()
    ax2.plot(list(x), [r["cam_loss_pct"] or 0 for r in agg], "o--", color="#C93A3A", label="Mất gói UDP camera (%)")
    ax2.set_ylabel("Mất gói UDP camera (%)"); ax2.legend(loc="upper right")
    ax.set_title(f"Throughput và mất gói camera ({attack_type})"); fig.tight_layout()
    fig.savefig(outdir / "hinh_throughput.png", dpi=160); plt.close(fig)


def analyze(batch_dir):
    batch = Path(batch_dir)
    run_dirs = sorted(d for d in batch.iterdir() if d.is_dir() and (d / "meta.json").exists())
    if not run_dirs:
        raise SystemExit(f"Không thấy lượt chạy nào trong {batch}")
    runs = [analyze_run(d) for d in run_dirs]
    agg = aggregate(runs)
    keys = sorted({k for r in runs for k in r})
    with (batch / "benchmark_runs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(runs)
    with (batch / "benchmark_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(agg[0])); w.writeheader(); w.writerows(agg)
    attack_type = runs[0].get("attack_type") or "?"
    write_markdown(agg, batch / "bang_2_4_2.md", attack_type, max(r["n_runs"] for r in agg))
    make_charts(agg, batch, attack_type)
    print((batch / "bang_2_4_2.md").read_text(encoding="utf-8"))
    print(f"Đã ghi: {batch}/benchmark_runs.csv, benchmark_summary.csv, bang_2_4_2.md, hinh_rtt.png, hinh_throughput.png")
    return agg


# ====================================================================== chạy trên Mininet
class MetricsSampler(threading.Thread):
    """Lưu lại live_metrics.json mỗi 0.5 s để tính thời gian phản ứng của AI."""

    def __init__(self, live_path, out_path):
        super().__init__(daemon=True)
        self.live_path, self.out_path, self._halt = live_path, out_path, threading.Event()

    def run(self):
        import dashboard_logic as dl
        with open(self.out_path, "w", encoding="utf-8") as f:
            while not self._halt.is_set():
                raw, _ = dl.load_json(self.live_path)
                if raw:
                    st = dl.normalize(raw)
                    f.write(json.dumps({"t": time.time(), "ts": st["ts"], "status_key": st["status"],
                                        "rtt_ms": st["rtt_ms"], "blocked": [b["ip"] for b in st["blocked"]],
                                        "rate_limit": bool((st.get("firewall") or {}).get("rate_limit_active"))}) + "\n")
                    f.flush()
                self._halt.wait(0.5)

    def stop(self):
        self._halt.set()
        self.join(timeout=2)


def _count(path: Path) -> int:
    return len(_read_csv(path))


def _copy_new_rows(src: Path, dst: Path, skip: int):
    rows = _read_csv(src)[skip:]
    if not rows:
        return
    with dst.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def run_one(net, sc, run_dir: Path, *, repeat, duration, attack_type, attack_rate, attack_duration,
            ai_cmd, reset_cmd, live_path, camera_bandwidth="4M"):
    from traffic.run_scenario import run_scenario
    from scenario_daemon import start_ai, stop_ai
    run_dir.mkdir(parents=True, exist_ok=True)
    cam0, ev0 = _count(T3_RESULTS / "camera_metrics.csv"), _count(T3_RESULTS / "attack_events.csv")
    sampler = MetricsSampler(live_path, run_dir / "live_samples.jsonl")
    sampler.start()
    # probe lớp báo cháy (DSCP 48 -> TOS 192); chạy dài hơn kịch bản, phân tích sẽ cắt theo cửa sổ của run_scenario
    probe = net.get("hs02").popen(["ping", "-D", "-i", str(PROBE_INTERVAL_S), "-Q", "192",
                                   "-w", str(duration + 45), "10.0.30.10"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ai = None
    started = datetime.now(timezone.utc).isoformat()
    try:
        if reset_cmd:
            net.get("gw").cmd(reset_cmd)
        if sc["ai"]:
            ai = start_ai(net, ai_cmd, run_dir / "gateway_ai.log")
            if ai is None:
                print("[benchmark] CẢNH BÁO: không tìm thấy gateway_ai.py, kịch bản 3 chỉ có QoS!")
        kw = {"camera_bandwidth": camera_bandwidth}
        if sc["run"] != "normal":
            kw.update(attack_type=attack_type, attack_rate=attack_rate, attack_duration=attack_duration)
        run_scenario(net, scenario=sc["run"], duration=duration, **kw)
    finally:
        stop_ai(net, ai, reset_cmd)
        sampler.stop()
        try:
            out, _ = probe.communicate(timeout=duration + 60)
        except subprocess.TimeoutExpired:
            probe.kill()
            out, _ = probe.communicate()
    (run_dir / "ping_alarm_dscp48.txt").write_text(out or "", encoding="utf-8")
    src = T3_RESULTS / f"ping_{sc['run']}.txt"
    if src.exists():
        shutil.copy(src, run_dir / "ping_telemetry_dscp0.txt")
    _copy_new_rows(T3_RESULTS / "camera_metrics.csv", run_dir / "camera_metrics.csv", cam0)
    _copy_new_rows(T3_RESULTS / "attack_events.csv", run_dir / "attack_events.csv", ev0)
    meta = {"key": sc["key"], "label": sc["label"], "ai": bool(sc["ai"] and ai is not None), "repeat": repeat,
            "duration": duration, "attack_type": attack_type if sc["run"] != "normal" else "none",
            "attack_rate": attack_rate, "attack_duration": attack_duration, "started_utc": started}
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")


def run_all(net, repeats=3, duration=60, attack_type="syn_flood", attack_rate=1000, attack_duration=20,
            ai_cmd=None, reset_cmd=None, include_qos_only=False, out_dir=None, live_path=None, camera_bandwidth="4M"):
    """Chạy lần lượt (bình thường, chưa AI+QoS, có AI+QoS) x repeats rồi phân tích.
    reset_cmd: lệnh chạy trong Gateway để gỡ luật chặn của Việt Anh giữa các lượt (ví dụ 'nft flush table inet ddos')."""
    import dashboard_logic as dl
    from scenario_daemon import DEFAULT_AI
    ai_cmd, live_path = ai_cmd or DEFAULT_AI, live_path or dl.LIVE_PATH
    batch = Path(out_dir) if out_dir else RESULTS / f"benchmark_{time.strftime('%Y%m%d_%H%M%S')}_{attack_type}"
    batch.mkdir(parents=True, exist_ok=True)
    scs = SCENARIOS + ([QOS_ONLY] if include_qos_only else [])
    for rep in range(1, repeats + 1):
        for sc in scs:
            print(f"\n===== Lượt {rep}/{repeats} - {sc['label']} =====", flush=True)
            run_one(net, sc, batch / f"{sc['key']}_r{rep:02d}", repeat=rep, duration=duration,
                    attack_type=attack_type, attack_rate=attack_rate, attack_duration=attack_duration,
                    ai_cmd=ai_cmd, reset_cmd=reset_cmd, live_path=live_path, camera_bandwidth=camera_bandwidth)
            time.sleep(5)                      # cho hàng đợi và socket ổn định giữa các lượt
    return analyze(batch)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "analyze":
        analyze(sys.argv[2])
    else:
        print(__doc__)