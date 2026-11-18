# -*- coding: utf-8 -*-
"""build_dataset.py - Gan nhan cho cua so 1 giay dua tren NHAT KY tan cong (khong gan 1 nhan cho ca file pcap).

Dau vao:
  --features : CSV tu collect_metadata.py (cot window_start + dac trung; co the co cot 'episode')
  --log      : CSV nhat ky tan cong, cot: start,end,attack_type[,episode]   (start/end = epoch giay)
               hoac start_utc,end_utc (ISO 8601) nhu traffic/results/attack_events.csv
               Tai thoi diem chay tan cong (hping3...), ghi start/end vao file nay.
Quy tac nhan cho cua so [t, t+1):
  - khong giao voi doan tan cong nao        -> nhan 0 (binh thuong)
  - nam tron trong mot doan tan cong        -> nhan 1 (tan cong) + attack_type
  - giao mot phan (cua so o bien start/end) -> BO (nhan khong chac chan)
Dau ra: CSV co them cot label, attack_type, episode.
"""
import argparse
import csv
import datetime
import sys


def _parse_time(val):
    """Chuyển đổi chuỗi ISO 8601 hoặc số epoch sang float timestamp."""
    try:
        return float(val)
    except ValueError:
        # Xử lý chuỗi ISO 8601 từ traffic/attack.py
        dt = datetime.datetime.fromisoformat(val.replace('Z', '+00:00'))
        return dt.timestamp()


def load_log(path):
    out = []
    for r in csv.DictReader(open(path)):
        # Hỗ trợ cả start/end (epoch) và start_utc/end_utc (ISO 8601 từ traffic/attack.py)
        start_val = r.get('start', r.get('start_utc'))
        end_val = r.get('end', r.get('end_utc'))
        if start_val is None or end_val is None:
            continue
        s = _parse_time(start_val)
        e = _parse_time(end_val)
        kind = r.get('attack_type', r.get('type', 'attack'))
        ep = r.get('episode', '')
        out.append((ep, s, e, kind))
    return out


def label_window(t, episode, log, win=1.0, match_episode=True):
    """Tra ve (label, attack_type) hoac None neu cua so bi bo.
    match_episode=True : chi xet cac dong nhat ky co cung ten luot (dung cho CSV dac trung co cot 'episode').
    match_episode=False: gan nhan theo THOI GIAN (epoch tuyet doi), khong phu thuoc ten luot trong nhat ky."""
    overlap_total, kind = 0.0, 'normal'
    for ep, s, e, k in log:
        if match_episode and ep != episode:
            continue
        ov = min(t + win, e) - max(t, s)
        if ov > 0:
            overlap_total += ov
            kind = k
    if overlap_total <= 1e-9:
        return 0, 'normal'
    if overlap_total >= win - 1e-9:
        return 1, kind
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--features', required=True)
    ap.add_argument('--log', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--episode', default='', help='ten luot chay (BAT BUOC neu CSV dac trung khong co cot episode); '
                    'se ghi vao cot episode cua dataset, dung de chia train/test theo luot')
    a = ap.parse_args()

    log = load_log(a.log)
    rows_in = list(csv.DictReader(open(a.features)))
    if not rows_in:
        sys.exit('LOI: file dac trung rong: %s' % a.features)
    if not log:
        sys.exit('LOI: nhat ky tan cong khong co dong hop le (can start/end hoac start_utc/end_utc): %s' % a.log)
    # CSV co cot episode (vi du du lieu tong hop): ghep theo ten luot.
    # CSV khong co cot episode (collect_metadata.py): ghep theo THOI GIAN, --episode chi dat ten cho luot.
    match_episode = 'episode' in rows_in[0]
    if match_episode:
        missing = {r['episode'] for r in rows_in} - {ep for ep, _, _, _ in log}
        if len(missing) == len({r['episode'] for r in rows_in}):
            sys.exit('LOI: khong co ten luot nao trong CSV dac trung khop voi cot episode cua nhat ky.\n'
                     '  Ten luot trong CSV dac trung: %s\n  Ten luot trong nhat ky: %s'
                     % (sorted({r['episode'] for r in rows_in})[:5], sorted({ep for ep, _, _, _ in log})[:5]))
    elif not a.episode:
        sys.exit('LOI: CSV dac trung khong co cot episode, can --episode <ten_luot_duy_nhat> (vi du kichban3_lan1)')
    fields = [c for c in rows_in[0].keys() if c != 'episode'] + ['label', 'attack_type', 'episode']
    kept = dropped = n_attack = 0
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows_in:
            ep = r.get('episode', a.episode)
            res = label_window(float(r['window_start']), ep, log, match_episode=match_episode)
            if res is None:
                dropped += 1
                continue
            r = {k: v for k, v in r.items() if k != 'episode'}
            r.update(label=res[0], attack_type=res[1], episode=ep)
            w.writerow(r)
            kept += 1
            n_attack += 1 if res[0] == 1 else 0
    print('Giu %d cua so (%d tan cong, %d binh thuong), bo %d cua so o bien doan tan cong -> %s'
          % (kept, n_attack, kept - n_attack, dropped, a.out))
    if n_attack == 0:
        print('CANH BAO: khong co cua so nao duoc gan nhan TAN CONG. Neu luot nay co tan cong, hay kiem tra: '
              'thoi gian nhat ky co nam trong khoang thoi gian cua file dac trung khong, va nhat ky co dung luot khong.',
              file=sys.stderr)


if __name__ == '__main__':
    main()