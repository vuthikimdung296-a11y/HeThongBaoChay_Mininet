# -*- coding: utf-8 -*-
"""simulate_live_metrics.py - Sinh live_metrics.json GIẢ LẬP để thử dashboard khi chưa có Gateway thật.

Chu kỳ: bình thường -> tấn công (AI chưa chặn) -> đã chặn -> bình thường ...
Mọi bản ghi mang "source": "simulator" nên dashboard hiện banner cảnh báo; KHÔNG dùng làm số liệu báo cáo.

  python3 dashboard/simulate_live_metrics.py [--out /tmp/live_metrics.json] [--cycles 0]
"""
import argparse
import random
import time

from dashboard_logic import LIVE_PATH, atomic_write


def make_record(phase, t_in_phase, ts, rnd):
    rec = {"timestamp": ts, "source": "simulator", "blocked_ips": []}
    if phase == "normal":
        rec.update(status="NORMAL", normal_packets=int(rnd.gauss(1100, 60)), syn_packets=rnd.randint(0, 3),
                   udp_packets=rnd.randint(0, 5), rtt_ms=round(max(5, rnd.gauss(22, 3)), 1))
    elif phase == "attack":
        rec.update(status="ATTACK", normal_packets=int(rnd.gauss(700, 80)), syn_packets=int(rnd.gauss(1000, 40)),
                   udp_packets=rnd.randint(0, 5), rtt_ms=round(rnd.gauss(260 + 10 * t_in_phase, 20), 1))
    else:  # blocked
        rec.update(status="BLOCKED", normal_packets=int(rnd.gauss(1100, 60)),
                   syn_packets=max(0, int(rnd.gauss(30 / (1 + t_in_phase), 5))), udp_packets=0,
                   rtt_ms=round(max(5, rnd.gauss(28, 4)), 1), blocked_ips=["192.168.100.100"])
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=LIVE_PATH)
    ap.add_argument("--cycles", type=int, default=0, help="0 = chạy mãi")
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    plan = [("normal", 15), ("attack", 3), ("blocked", 12)]
    n = 0
    print(f"[SIM] ghi dữ liệu GIẢ LẬP vào {a.out} (Ctrl+C để dừng)")
    try:
        while a.cycles == 0 or n < a.cycles:
            for phase, secs in plan:
                for i in range(secs):
                    atomic_write(a.out, make_record(phase, i, time.time(), rnd))
                    time.sleep(1)
            n += 1
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
