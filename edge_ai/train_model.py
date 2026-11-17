# -*- coding: utf-8 -*-
"""train_model.py - Huan luyen va danh gia mo hinh Edge AI (Random Forest va mo hinh so sanh).

Chia train/test THEO LUOT CHAY (episode), khong chia ngau nhien tung cua so, vi cac cua so lien tiep
trong cung mot luot rat giong nhau -> chia ngau nhien se bao hieu qua cao gia (ro ri du lieu).
Do: accuracy, precision, recall, F1, ti le bao gia (FPR = FP/(FP+TN)), ma tran nham lan,
    thoi gian suy luan (ms/cua so, 1 luong), kich thuoc mo hinh.
Dau ra (trong --outdir): models/rf_edge.joblib, models/rf_edge.json, results.json, cac anh PNG.
"""
import argparse
import json
import os
import time

import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import FEATURES_CORE, FEATURES_EXT

SEED = 42


def metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    acc = (tp + tn) / len(y)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp), accuracy=acc, precision=prec,
                recall=rec, f1=f1, fpr=fp / (fp + tn) if fp + tn else 0.0)


def infer_time_ms(model, X, n=500):
    """Thoi gian suy luan 1 cua so (ms), do tung cua so mot nhu khi chay thuc te tai Gateway."""
    X = np.asarray(X)
    for i in range(20):                                   # khoi dong
        model.predict(X[i:i + 1])
    ts = []
    for i in range(n):
        t = time.perf_counter()
        model.predict(X[i % len(X):i % len(X) + 1])
        ts.append((time.perf_counter() - t) * 1000)
    return dict(mean_ms=float(np.mean(ts)), p95_ms=float(np.percentile(ts, 95)))


def make_models():
    return {
        'RF-4 (dac trung loi)': (RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3,
                                                         n_jobs=1, random_state=SEED), FEATURES_CORE),
        'RF-7 (loi + bo sung)': (RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3,
                                                         n_jobs=1, random_state=SEED), FEATURES_EXT),
        'Cay quyet dinh-4': (DecisionTreeClassifier(max_depth=8, min_samples_leaf=3, random_state=SEED), FEATURES_CORE),
        'Hoi quy logistic-4': (make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)), FEATURES_CORE),
    }


def plot_cm(cm, path, title):
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    ax.imshow(cm, cmap='Blues')
    names = ['Bình thường', 'Tấn công']
    ax.set_xticks([0, 1], names)
    ax.set_yticks([0, 1], names)
    ax.set_xlabel('Dự đoán')
    ax.set_ylabel('Thực tế')
    ax.set_title(title, fontsize=10)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i][j], ha='center', va='center', fontsize=14,
                    color='white' if cm[i][j] > cm.max() / 2 else 'black')
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--data', default='data/dataset.csv')
    ap.add_argument('--outdir', default='.')
    ap.add_argument('--test-size', type=float, default=0.3)
    a = ap.parse_args()
    os.makedirs(os.path.join(a.outdir, 'models'), exist_ok=True)

    d = pd.read_csv(a.data)
    y = d['label'].values
    groups = d['episode'].values
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=a.test_size, random_state=SEED).split(d, y, groups))
    print('Train: %d cua so (%d luot), Test: %d cua so (%d luot)' %
          (len(tr), len(set(groups[tr])), len(te), len(set(groups[te]))))

    results = {'n_train': int(len(tr)), 'n_test': int(len(te)), 'test_attack': int(y[te].sum()),
               'test_normal': int((y[te] == 0).sum()), 'models': {}}
    fitted = {}
    for name, (m, feats) in make_models().items():
        m.fit(d.iloc[tr][feats].values, y[tr])
        pred = m.predict(d.iloc[te][feats].values)
        r = metrics(y[te], pred)
        r.update(infer_time_ms(m, d.iloc[te][feats].values))
        if hasattr(m, 'feature_importances_'):
            r['importance'] = dict(zip(feats, [float(v) for v in m.feature_importances_]))
        results['models'][name] = r
        fitted[name] = (m, feats, pred)
        print('%-24s acc=%.4f prec=%.4f rec=%.4f F1=%.4f FPR=%.4f  %.2f ms/cua so' %
              (name, r['accuracy'], r['precision'], r['recall'], r['f1'], r['fpr'], r['mean_ms']))

    # Ket qua theo loai tan cong (RF-4)
    m, feats, pred = fitted['RF-4 (dac trung loi)']
    sub = d.iloc[te].copy()
    sub['pred'] = pred
    per = {}
    for k, g in sub[sub.label == 1].groupby('attack_type'):
        per[k] = dict(n=int(len(g)), recall=float((g.pred == 1).mean()))
    results['rf4_recall_by_attack'] = per
    # Chia theo cuong do tan cong (can nhat ky co rate_pps) khong bat buoc -> bo qua

    # Kiem tra cheo 5 lan theo luot chay cho RF-4
    accs, fprs, recs = [], [], []
    for a_tr, a_te in GroupKFold(n_splits=5).split(d, y, groups):
        mm = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3, n_jobs=1, random_state=SEED)
        mm.fit(d.iloc[a_tr][FEATURES_CORE].values, y[a_tr])
        rr = metrics(y[a_te], mm.predict(d.iloc[a_te][FEATURES_CORE].values))
        accs.append(rr['accuracy']); fprs.append(rr['fpr']); recs.append(rr['recall'])
    results['rf4_cv5'] = dict(accuracy_mean=float(np.mean(accs)), accuracy_std=float(np.std(accs)),
                              fpr_mean=float(np.mean(fprs)), fpr_std=float(np.std(fprs)),
                              recall_mean=float(np.mean(recs)), recall_std=float(np.std(recs)))

    # Luu mo hinh trien khai: RF-4
    model_path = os.path.join(a.outdir, 'models', 'rf_edge.joblib')
    joblib.dump(m, model_path, compress=3)
    results['rf4_model_size_kb'] = round(os.path.getsize(model_path) / 1024, 1)
    json.dump({'features': feats, 'window_seconds': 1.0, 'classes': {'0': 'binh_thuong', '1': 'tan_cong'}},
              open(os.path.join(a.outdir, 'models', 'rf_edge.json'), 'w'), indent=2)
    json.dump(results, open(os.path.join(a.outdir, 'results.json'), 'w'), indent=2, ensure_ascii=False)

    # Anh
    cm = confusion_matrix(y[te], pred, labels=[0, 1])
    plot_cm(cm, os.path.join(a.outdir, 'confusion_matrix_rf4.png'), 'Random Forest (4 đặc trưng lõi)')
    imp = results['models']['RF-4 (dac trung loi)']['importance']
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.barh(list(imp.keys()), list(imp.values()), color='#2b6cb0')
    ax.set_xlabel('Độ quan trọng')
    ax.invert_yaxis()
    fig.tight_layout()
    fig.savefig(os.path.join(a.outdir, 'feature_importance_rf4.png'), dpi=180)
    plt.close(fig)
    print('Da luu mo hinh (%.1f KB), results.json va anh -> %s' % (results['rf4_model_size_kb'], a.outdir))


if __name__ == '__main__':
    main()
