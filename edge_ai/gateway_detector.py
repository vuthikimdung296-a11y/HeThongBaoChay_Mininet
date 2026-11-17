# -*- coding: utf-8 -*-
"""gateway_detector.py - Chay mo hinh Edge AI tai Gateway, xuat nhan BINH THUONG / TAN CONG cho F (tuong lua).

Moi cua so 1 giay: trich dac trung -> Random Forest -> xac suat tan cong -> lam muot (tranh bao nhay):
  chuyen sang TAN CONG khi xac suat >= --threshold lien tiep --k-on cua so,
  tro ve BINH THUONG khi < threshold lien tiep --k-off cua so VA da giu TAN CONG it nhat --hold giay.
Khi trang thai doi, thuc hien lenh gan o --on-attack / --on-normal (vi du goi script nftables cua F).

Dau ra cho F:
  1) file trang thai JSON (ghi nguyen tu) --state-file, mac dinh /tmp/edge_ai_state.json:
       {"ts": 1.8e9, "label": "tan_cong", "prob": 0.98, "packet_rate": ..., "syn_count": ..., ...}
  2) nhat ky CSV --log (moi cua so mot dong)
  3) lenh hook (bien moi truong: EDGE_AI_LABEL, EDGE_AI_PROB, EDGE_AI_TS)

Chay:
  Truc tiep (tai gateway, can root, tai mininet> dung 'gw python3 gateway_detector.py ...'):
    sudo python3 gateway_detector.py --iface gw-eth0 gw-eth1 --on-attack "./firewall/apply.sh add" --on-normal "./firewall/apply.sh del"
  Phat lai de kiem tra:
    python3 gateway_detector.py --pcap a.pcap b.pcap     |   python3 gateway_detector.py --features-csv f.csv
"""
import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import time

import joblib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_metadata import read_pcaps, sniff_raw, sniff_tshark   # noqa: E402
from features import FEATURES_EXT, WindowAggregator                 # noqa: E402

LABELS = {0: 'binh_thuong', 1: 'tan_cong'}


class Detector:
    def __init__(self, model_dir, threshold, k_on, k_off, state_file, log_path, on_attack, on_normal, quiet=False, hold=10):
        self.model = joblib.load(os.path.join(model_dir, 'rf_edge.joblib'))
        self.feats = json.load(open(os.path.join(model_dir, 'rf_edge.json')))['features']
        self.th, self.k_on, self.k_off, self.hold = threshold, k_on, k_off, hold
        self.attack_since = None
        self.state_file, self.on_attack, self.on_normal, self.quiet = state_file, on_attack, on_normal, quiet
        self.state, self.up, self.down = 0, 0, 0
        self.states = []                       # (window_start, trang thai sau khi lam muot) moi cua so
        self.events = []                       # (window_start, trang thai moi) khi doi trang thai
        self.latency_ms = []
        self.log_f = open(log_path, 'w', newline='') if log_path else None
        self.log = csv.writer(self.log_f) if self.log_f else None
        if self.log:
            self.log.writerow(['window_start', 'prob_attack', 'raw_pred', 'state'] + FEATURES_EXT)

    def on_window(self, row):
        t0 = time.perf_counter()
        x = [[float(row[f]) for f in self.feats]]
        prob = float(self.model.predict_proba(x)[0][1])
        raw = 1 if prob >= self.th else 0
        if raw:
            self.up, self.down = self.up + 1, 0
        else:
            self.up, self.down = 0, self.down + 1
        prev = self.state
        if self.state == 0 and self.up >= self.k_on:
            self.state = 1
        elif (self.state == 1 and self.down >= self.k_off
              and row['window_start'] - self.attack_since >= self.hold):   # giu luat toi thieu `hold` giay
            self.state = 0
        if self.state == 1 and prev == 0:
            self.attack_since = row['window_start']
        self.states.append((row['window_start'], self.state))
        self.latency_ms.append((time.perf_counter() - t0) * 1000)
        self._emit(row, prob, raw)
        if self.state != prev:
            self.events.append((row['window_start'], self.state))
            self._hook(row, prob)

    def _emit(self, row, prob, raw):
        rec = {'ts': row['window_start'], 'label': LABELS[self.state], 'prob': round(prob, 4)}
        rec.update({k: row[k] for k in self.feats})
        tmp = self.state_file + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(rec, f)
        os.replace(tmp, self.state_file)                       # ghi nguyen tu, F doc khong bao gio thay file do dang
        if self.log:
            self.log.writerow([row['window_start'], round(prob, 4), raw, self.state] +
                              [round(float(row[k]), 4) for k in FEATURES_EXT])
        if not self.quiet:
            print('%.0f  %-12s p=%.3f  pps=%-8.0f syn=%-6d srcs=%d' % (
                row['window_start'], LABELS[self.state].upper(), prob, row['packet_rate'],
                row['syn_count'], row['ip_dispersion']), flush=True)

    def _hook(self, row, prob):
        cmd = self.on_attack if self.state == 1 else self.on_normal
        print('>>> CHUYEN TRANG THAI: %s' % LABELS[self.state].upper(), flush=True)
        if cmd:
            env = dict(os.environ, EDGE_AI_LABEL=LABELS[self.state], EDGE_AI_PROB='%.4f' % prob,
                       EDGE_AI_TS='%.0f' % row['window_start'])
            subprocess.Popen(shlex.split(cmd), env=env)

    def close(self):
        if self.log_f:
            self.log_f.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--iface', nargs='+')
    src.add_argument('--pcap', nargs='+')
    src.add_argument('--features-csv')
    ap.add_argument('--backend', choices=['raw', 'tshark'], default='raw')
    ap.add_argument('--duration', type=int, default=3600)
    ap.add_argument('--model-dir', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models'))
    ap.add_argument('--threshold', type=float, default=0.5)
    ap.add_argument('--k-on', type=int, default=2, help='so cua so lien tiep nghi tan cong de bao TAN CONG')
    ap.add_argument('--k-off', type=int, default=3, help='so cua so lien tiep binh thuong de ve BINH THUONG')
    ap.add_argument('--hold', type=float, default=10, help='so giay toi thieu giu trang thai TAN CONG (chong bat/tat luat lien tuc)')
    ap.add_argument('--state-file', default='/tmp/edge_ai_state.json')
    ap.add_argument('--log', default=None)
    ap.add_argument('--on-attack', default=None)
    ap.add_argument('--on-normal', default=None)
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()

    det = Detector(a.model_dir, a.threshold, a.k_on, a.k_off, a.state_file, a.log, a.on_attack, a.on_normal, a.quiet, a.hold)
    try:
        if a.features_csv:
            for r in csv.DictReader(open(a.features_csv)):
                det.on_window({k: (float(v) if k != 'episode' else v) for k, v in r.items()})
        else:
            agg = WindowAggregator(det.on_window)
            if a.pcap:
                read_pcaps(a.pcap, agg)
            elif a.backend == 'tshark':
                sniff_tshark(a.iface, a.duration, agg)
            else:
                sniff_raw(a.iface, a.duration, agg)
    except KeyboardInterrupt:
        pass
    finally:
        det.close()
    if det.latency_ms:
        l = sorted(det.latency_ms)
        print('Do tre suy luan/cua so: trung binh %.2f ms, p95 %.2f ms (%d cua so)' %
              (sum(l) / len(l), l[int(0.95 * (len(l) - 1))], len(l)))


if __name__ == '__main__':
    main()
