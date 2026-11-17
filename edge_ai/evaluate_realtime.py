# -*- coding: utf-8 -*-
"""evaluate_realtime.py - Danh gia o muc LUOT CHAY khi chay detector co lam muot (k-on, k-off, hold):
  - do tre phat hien = thoi gian tu luc tan cong bat dau toi luc bao TAN CONG dau tien
  - ti le luot tan cong bi bo sot (khong bao trong suot luot)
  - so lan bao TAN CONG nham tren luot binh thuong (C)
Chi dung cac luot thuoc TAP TEST (cung cach chia nhu train_model.py) de khong danh gia tren du lieu da hoc.
"""
import argparse
import json
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from gateway_detector import Detector

SEED = 42


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data', default='data/dataset.csv')
    ap.add_argument('--features', default='data/features_synth.csv')
    ap.add_argument('--log', default='data/attack_log_synth.csv')
    ap.add_argument('--model-dir', default='models')
    ap.add_argument('--out', default='results_realtime.json')
    a = ap.parse_args()

    d = pd.read_csv(a.data)
    _, te = next(GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=SEED).split(d, d.label, d.episode))
    test_eps = sorted(set(d.iloc[te].episode))
    feats = pd.read_csv(a.features)
    log = pd.read_csv(a.log).set_index('episode')

    delays, missed, n_attack, flips_attack, fa_normal, n_normal = [], 0, 0, [], 0, 0
    lat = []
    coverage, norm_total, norm_alarm, tail_alarm, tail_total = [], 0, 0, 0, 0
    for ep in test_eps:
        g = feats[feats.episode == ep].sort_values('window_start')
        det = Detector(a.model_dir, 0.5, 2, 3, '/tmp/_st.json', None, None, None, quiet=True, hold=10)
        for r in g.to_dict('records'):
            det.on_window(r)
        lat += det.latency_ms
        starts = [t for t, s in det.events if s == 1]
        # Xác định lượt tấn công dựa vào việc episode có trong log hay không (C1 - không dùng ep.startswith('D'))
        is_attack_ep = (ep in log.index) and (str(log.loc[ep, 'attack_type']).lower() != 'normal' if 'attack_type' in log.columns else True)
        t_a = float(log.loc[ep, 'start']) if is_attack_ep else None
        t_b = float(log.loc[ep, 'end']) if is_attack_ep else None
        in_atk = [st for (w, st) in det.states if t_a is not None and w >= t_a and w + 1 <= t_b]
        out_all = [(w, st) for (w, st) in det.states if t_a is None or w + 1 <= t_a or w >= t_b]
        # 'duoi nha luat': 5 giay dau sau khi tan cong ket thuc, nhan van TAN CONG do can k_off cua so binh thuong lien tiep
        tail = [st for (w, st) in out_all if t_b is not None and t_b <= w < t_b + 5]
        out_atk = [st for (w, st) in out_all if not (t_b is not None and t_b <= w < t_b + 5)]
        tail_total += len(tail)
        tail_alarm += sum(tail)
        if in_atk:
            coverage.append(sum(in_atk) / len(in_atk))   # ti le cua so trong doan tan cong duoc gan nhan TAN CONG
        norm_total += len(out_atk)
        norm_alarm += sum(out_atk)
        if is_attack_ep:
            n_attack += 1
            t_atk = float(log.loc[ep, 'start'])
            first = [t for t in starts if t >= t_atk - 1]
            if first:
                delays.append(first[0] + 1 - t_atk)   # + 1: quyet dinh co khi cua so dong
            else:
                missed += 1
            flips_attack.append(len(starts))
        else:
            n_normal += 1
            fa_normal += 1 if starts else 0
    res = dict(test_attack_episodes=n_attack, test_normal_episodes=n_normal, missed_attack_episodes=missed,
               detection_delay_mean_s=float(np.mean(delays)), detection_delay_median_s=float(np.median(delays)),
               detection_delay_max_s=float(np.max(delays)),
               coverage_mean=float(np.mean(coverage)), coverage_median=float(np.median(coverage)),
               episodes_coverage_below_50pct=int(sum(1 for c in coverage if c < 0.5)),
               smoothed_normal_windows=int(norm_total), smoothed_normal_windows_alarmed=int(norm_alarm),
               smoothed_fpr=float(norm_alarm / norm_total),
               release_tail_windows=int(tail_total), release_tail_windows_alarmed=int(tail_alarm),
               attack_episodes_with_flapping=int(sum(1 for x in flips_attack if x > 1)),
               normal_episodes_with_false_alarm=fa_normal,
               latency_mean_ms=float(np.mean(lat)), latency_p95_ms=float(np.percentile(lat, 95)))
    json.dump(res, open(a.out, 'w'), indent=2)
    print(json.dumps(res, indent=2))


if __name__ == '__main__':
    main()
