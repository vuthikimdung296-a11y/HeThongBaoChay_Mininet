#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""benchmark.py - Doc scenario_metrics.csv (do traffic/run_scenario.py / experiments/run_matrix.py ghi),
tinh bang tong hop theo (kich ban, loai tan cong, muc) va ve bieu do so sanh.

Chay (khong can Mininet, khong can root):
    python3 experiments/benchmark.py --results traffic/results --out experiments/results/summary
Tuy chon --camera: doc them camera_metrics.csv (throughput, mat goi UDP cua camera).
Dau ra: tong_hop.csv, tong_hop.md, bieu_do_rtt.png, bieu_do_mat_goi.png, (bieu_do_camera.png)

Quy uoc kich ban: normal = KB1 | attack_no_qos = KB2 | attack_qos = KB3 (hien moi co QoS; Edge AI + nftables noi sau)
Nguong cua co: RTT <= 50 ms (binh thuong), <= 200 ms (khi tan cong); mat goi canh bao 0%.
Luu y: RTT/mat goi o day do bang ping (goi DSCP 0), chua phai ban tin canh bao MQTT.
"""
import argparse
import os
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

LABEL = {'normal': 'KB1: Không tấn công', 'attack_no_qos': 'KB2: Tấn công, không bảo vệ',
         'attack_qos': 'KB3: Tấn công + QoS'}
COLOR = {'normal': '#7f8c8d', 'attack_no_qos': '#c0392b', 'attack_qos': '#2471a3'}
METRICS = ['rtt_avg_ms', 'rtt_p95_ms', 'rtt_p99_ms', 'ping_packet_loss_percent']


def load(results_dir):
    path = os.path.join(results_dir, 'scenario_metrics.csv')
    if not os.path.isfile(path):
        sys.exit('Khong thay %s' % path)
    df = pd.read_csv(path)
    df['attack_rate_pps'] = df['attack_rate_pps'].astype(int)
    return df


def summarize(df):
    g = df.groupby(['scenario', 'attack_type', 'attack_rate_pps'])
    out = g[METRICS].mean().round(1)
    out['so_luot'] = g.size()
    out = out.reset_index()
    out['dat_RTT'] = out.apply(lambda r: 'Đạt' if r['rtt_p99_ms'] <= (50 if r['scenario'] == 'normal' else 200)
                               else 'Không đạt', axis=1)
    order = {'normal': 0, 'attack_no_qos': 1, 'attack_qos': 2}
    return out.sort_values(['attack_type', 'attack_rate_pps', 'scenario'], key=lambda s: s.map(order) if s.name == 'scenario' else s)


def to_markdown(t):
    cols = list(t.columns)
    lines = ['| ' + ' | '.join(cols) + ' |', '|' + '---|' * len(cols)]
    for _, r in t.iterrows():
        lines.append('| ' + ' | '.join(str(r[c]) for c in cols) + ' |')
    return '\n'.join(lines)


def chart_rtt(df, out):
    base = df[df.scenario == 'normal']
    base_avg = base.rtt_avg_ms.mean() if len(base) else None
    types = [t for t in ['syn_flood', 'udp_flood'] if t in set(df.attack_type)]
    fig, axes = plt.subplots(1, len(types), figsize=(5.6 * len(types), 4.4), squeeze=False)
    for ax, t in zip(axes[0], types):
        sub = df[df.attack_type == t]
        rates = sorted(sub.attack_rate_pps.unique())
        w = 0.38
        for i, sc in enumerate(['attack_no_qos', 'attack_qos']):
            vals = [sub[(sub.scenario == sc) & (sub.attack_rate_pps == r)].rtt_avg_ms.mean() for r in rates]
            xs = [k + (i - 0.5) * w for k in range(len(rates))]
            bars = ax.bar(xs, vals, w, label=LABEL[sc], color=COLOR[sc])
            for b, v in zip(bars, vals):
                if v == v:
                    ax.text(b.get_x() + b.get_width() / 2, v + 10, '%.0f' % v, ha='center', fontsize=8)
        if base_avg:
            ax.axhline(base_avg, color=COLOR['normal'], ls='--', lw=1.2, label='KB1 (%.0f ms)' % base_avg)
        ax.axhline(200, color='k', ls=':', lw=1.2, label='Ngưỡng 200 ms (khi tấn công)')
        ax.axhline(50, color='g', ls=':', lw=1.2, label='Ngưỡng 50 ms (bình thường)')
        ax.set_xticks(range(len(rates)))
        ax.set_xticklabels(['%d' % r for r in rates])
        ax.set_xlabel('Mức tấn công (gói/giây)')
        ax.set_ylabel('RTT trung bình (ms)')
        ax.set_title('RTT khi tấn công %s' % ('SYN Flood' if t == 'syn_flood' else 'UDP Flood'))
        ax.set_ylim(0, max(950, df.rtt_avg_ms.max() * 1.15))
    axes[0][0].legend(fontsize=7, loc='upper left', bbox_to_anchor=(0, -0.18), ncol=2)
    fig.tight_layout()
    fig.savefig(out, dpi=170, bbox_inches='tight')
    plt.close(fig)


def chart_loss(df, out):
    d = df.copy()
    d['nhom'] = d.apply(lambda r: 'KB1' if r.scenario == 'normal' else
                        ('KB2 ' if r.scenario == 'attack_no_qos' else 'KB3 ') +
                        ('SYN' if r.attack_type == 'syn_flood' else 'UDP'), axis=1)
    m = d.groupby(['nhom', 'scenario']).ping_packet_loss_percent.mean().reset_index().sort_values('nhom')
    fig, ax = plt.subplots(figsize=(6.2, 3.8))
    ax.bar(m.nhom, m.ping_packet_loss_percent, color=[COLOR[s] for s in m.scenario])
    for x, v in zip(m.nhom, m.ping_packet_loss_percent):
        ax.text(x, v + 0.6, '%.1f' % v, ha='center', fontsize=8)
    ax.axhline(0, color='g', lw=1.5)
    ax.set_ylabel('Mất gói ping trung bình (%)')
    ax.set_title('Tỷ lệ mất gói ping (yêu cầu: 0%)')
    fig.tight_layout()
    fig.savefig(out, dpi=170)
    plt.close(fig)


def chart_camera(path, out):
    cam = pd.read_csv(path)
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.6))
    cam.groupby('camera_id').throughput_mbps.mean().plot.bar(ax=ax[0], color='#2471a3')
    ax[0].axhline(4, color='k', ls=':')
    ax[0].set_title('Throughput mỗi camera (yêu cầu 4 Mbps)')
    ax[0].set_ylabel('Mbps')
    cam.groupby('camera_id').packet_loss_percent.mean().plot.bar(ax=ax[1], color='#c0392b')
    ax[1].set_title('Mất gói UDP mỗi camera (%)')
    fig.tight_layout()
    fig.savefig(out, dpi=170)
    plt.close(fig)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', default=os.path.join(here, '..', 'traffic', 'results'))
    ap.add_argument('--out', default=os.path.join(here, 'results', 'summary'))
    ap.add_argument('--camera', action='store_true', help='ve them bieu do camera_metrics.csv')
    ap.add_argument('--window', action='store_true',
                    help='dung cot win_* (RTT/mat goi chi trong cua so tan cong) do run_scenario.py ban moi ghi')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    df = load(a.results)
    if a.window:
        if 'win_rtt_avg_ms' not in df.columns:
            sys.exit('Khong co cot win_* trong scenario_metrics.csv: can chay run_scenario.py ban moi.')
        df = df.dropna(subset=['win_rtt_avg_ms']).copy()
        for src, dst in [('win_rtt_avg_ms', 'rtt_avg_ms'), ('win_rtt_p95_ms', 'rtt_p95_ms'),
                         ('win_rtt_p99_ms', 'rtt_p99_ms'), ('win_loss_percent', 'ping_packet_loss_percent')]:
            df[dst] = df[src]
    t = summarize(df)
    t.to_csv(os.path.join(a.out, 'tong_hop.csv'), index=False)
    open(os.path.join(a.out, 'tong_hop.md'), 'w', encoding='utf-8').write(to_markdown(t) + '\n')
    chart_rtt(df, os.path.join(a.out, 'bieu_do_rtt.png'))
    chart_loss(df, os.path.join(a.out, 'bieu_do_mat_goi.png'))
    if a.camera:
        chart_camera(os.path.join(a.results, 'camera_metrics.csv'), os.path.join(a.out, 'bieu_do_camera.png'))
    print(to_markdown(t))
    print('\nDa ghi ket qua vao', os.path.abspath(a.out))


if __name__ == '__main__':
    main()