#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_model.py - Huấn luyện và đánh giá mô hình Edge AI phát hiện tấn công DDoS tại Gateway
Hệ thống cảnh báo cháy thông minh - Mô phỏng Mininet

Đầu vào:
  - File dữ liệu thực tế: dataset_real.csv
Đặc trưng:
  - 4 đặc trưng lõi (Mô hình triển khai tại Gateway):
      packet_rate, byte_rate, syn_count, ip_dispersion
  - 3 đặc trưng mở rộng (Mô hình so sánh):
      src_entropy, udp_ratio, avg_pkt_len
Phân chia dữ liệu:
  - Chia theo LƯỢT CHẠY (GroupShuffleSplit theo cột episode) với tỷ lệ 70% train / 30% test
  - Đảm bảo không bị rò rỉ dữ liệu chuỗi thời gian giữa các cửa sổ 1 giây liên tiếp
Đánh giá:
  - Accuracy, Precision, Recall, F1-Score
  - Tỷ lệ báo giả FPR = FP / (FP + TN) (Tối quan trọng đối với hệ thống cảnh báo cháy)
  - Thời gian suy luận (Inference time: mean ms, p95 ms) cho 1 cửa sổ thời gian thực
  - Độ quan trọng đặc trưng (Feature Importance)
  - Ma trận nhầm lẫn (Confusion Matrix)
  - Kiểm tra chéo 5 phần theo lượt chạy (GroupKFold CV)
Đầu ra:
  - Mô hình: edge_ai_model.joblib (và models/rf_edge.joblib)
  - Ảnh biểu đồ: confusion_matrix.png, feature_importance.png
  - Bảng số liệu chi tiết phục vụ Mục 2.4.1 của Báo cáo/Đề tài
"""

import argparse
import json
import os
import sys
import time
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import GroupShuffleSplit, GroupKFold

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
EDGE_AI_DIR = os.path.join(CURRENT_DIR, "edge_ai")
if os.path.isdir(EDGE_AI_DIR) and EDGE_AI_DIR not in sys.path:
    sys.path.insert(0, EDGE_AI_DIR)

try:
    from features import FEATURES_CORE, FEATURES_EXT
except ImportError:
    FEATURES_CORE = ['packet_rate', 'byte_rate', 'syn_count', 'ip_dispersion']
    FEATURES_EXT = FEATURES_CORE + ['src_entropy', 'udp_ratio', 'avg_pkt_len']

SEED = 42


def calculate_metrics(y_true, y_pred):
    """Tính toán các chỉ số đánh giá chi tiết."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    total = len(y_true)
    acc = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
        'accuracy': float(acc), 'precision': float(prec),
        'recall': float(rec), 'f1': float(f1), 'fpr': float(fpr)
    }


def measure_inference_time(model, X, n_iter=500):
    """
    Đo thời gian suy luận (Inference time) cho từng cửa sổ đơn lẻ (1 luồng),
    mô phỏng chính xác quá trình thực thi thời gian thực trên Gateway.
    """
    X_arr = np.asarray(X)
    # Khởi động (warmup)
    for i in range(min(20, len(X_arr))):
        model.predict(X_arr[i:i+1])
    
    latencies = []
    n_samples = len(X_arr)
    for i in range(n_iter):
        sample = X_arr[i % n_samples: (i % n_samples) + 1]
        t0 = time.perf_counter()
        model.predict(sample)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    
    return {
        'mean_ms': float(np.mean(latencies)),
        'p95_ms': float(np.percentile(latencies, 95)),
        'min_ms': float(np.min(latencies)),
        'max_ms': float(np.max(latencies))
    }


def build_models():
    """Tập hợp các mô hình huấn luyện và so sánh."""
    return {
        'Random Forest (4 đặc trưng lõi)': (
            RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3,
                                   n_jobs=1, random_state=SEED),
            FEATURES_CORE
        ),
        'Random Forest (7 đặc trưng mở rộng)': (
            RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3,
                                   n_jobs=1, random_state=SEED),
            FEATURES_EXT
        ),
        'Cây quyết định (Decision Tree)': (
            DecisionTreeClassifier(max_depth=8, min_samples_leaf=3, random_state=SEED),
            FEATURES_CORE
        ),
        'Hồi quy Logistic (Logistic Regression)': (
            make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)),
            FEATURES_CORE
        )
    }


def draw_confusion_matrix(cm, output_path, title='Ma trận nhầm lẫn - Random Forest (4 đặc trưng lõi)'):
    """Vẽ ảnh biểu đồ Confusion Matrix chuẩn khoa học."""
    fig, ax = plt.subplots(figsize=(5.5, 4.8), dpi=200)
    cax = ax.imshow(cm, cmap='Blues', interpolation='nearest')
    fig.colorbar(cax, ax=ax, fraction=0.046, pad=0.04)

    classes = ['Bình thường\n(Normal)', 'Tấn công\n(Attack)']
    tick_marks = np.arange(len(classes))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(classes, fontsize=11, fontweight='medium')
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(classes, fontsize=11, fontweight='medium')

    ax.set_xlabel('Nhãn Dự Đoán (Predicted Label)', fontsize=12, labelpad=8)
    ax.set_ylabel('Nhãn Thực Tế (True Label)', fontsize=12, labelpad=8)
    ax.set_title(title, fontsize=12, fontweight='bold', pad=12)

    thresh = cm.max() / 2.0
    labels = [['TN', 'FP'], ['FN', 'TP']]
    for i in range(2):
        for j in range(2):
            val = cm[i, j]
            tag = labels[i][j]
            color = "white" if val > thresh else "black"
            ax.text(j, i, f"{tag} = {val:,}\n({val/cm.sum()*100:.2f}%)",
                    ha="center", va="center", color=color, fontsize=11, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close(fig)
    print(f"[✓] Đã xuất ảnh Confusion Matrix: {output_path}")


def draw_feature_importance(importances, feat_names, output_path):
    """Vẽ biểu đồ mức độ quan trọng của đặc trưng."""
    fig, ax = plt.subplots(figsize=(6.5, 3.8), dpi=200)
    y_pos = np.arange(len(feat_names))
    sorted_idx = np.argsort(importances)
    
    ax.barh(y_pos, [importances[i] for i in sorted_idx], color='#1f77b4', edgecolor='black', alpha=0.85)
    ax.set_yticks(y_pos)
    ax.set_yticklabels([feat_names[i] for i in sorted_idx], fontsize=11)
    ax.set_xlabel('Mức độ đóng góp quan trọng (Feature Importance)', fontsize=11)
    ax.set_title('Độ quan trọng của các đặc trưng Header Metadata (RF-4)', fontsize=12, fontweight='bold')
    
    for i, v in enumerate([importances[i] for i in sorted_idx]):
        ax.text(v + 0.01, i, f"{v*100:.1f}%", va='center', fontsize=10, fontweight='bold')

    ax.set_xlim(0, max(importances) * 1.18)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close(fig)
    print(f"[✓] Đã xuất ảnh Feature Importance: {output_path}")


def find_dataset(custom_path=None):
    """Tìm đường dẫn file dataset phù hợp."""
    candidates = [
        custom_path,
        os.path.join(CURRENT_DIR, "dataset_real.csv"),
        os.path.join(CURRENT_DIR, "edge_ai", "data", "dataset_real.csv"),
        os.path.join(CURRENT_DIR, "edge_ai", "data", "dataset.csv"),
        "dataset_real.csv",
        "edge_ai/data/dataset_real.csv",
        "edge_ai/data/dataset.csv"
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return None


def main():
    parser = argparse.ArgumentParser(description="Huấn luyện và đánh giá mô hình Edge AI cho Gateway")
    parser.add_argument('--data', default=None, help='Đường dẫn file dataset.csv hoặc dataset_real.csv')
    parser.add_argument('--outdir', default='.', help='Thư mục lưu mô hình và kết quả')
    parser.add_argument('--test-size', type=float, default=0.3, help='Tỷ lệ tập kiểm tra (mặc định: 0.3)')
    args = parser.parse_args()

    data_file = find_dataset(args.data)
    if not data_file:
        print("[-] Lỗi: Không tìm thấy file dataset! Hãy chạy collect_data.py trước để tạo dataset_real.csv.")
        sys.exit(1)

    print(f"[*] Sử dụng tập dữ liệu: {data_file}")
    df = pd.read_csv(data_file)
    print(f"[*] Tổng số mẫu cửa sổ: {len(df):,} dòng. Các cột: {list(df.columns)}")

    y = df['label'].values
    episodes = df['episode'].values

    # Phân chia dữ liệu theo lượt chạy (GroupShuffleSplit) để tránh data leakage
    splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=SEED)
    train_idx, test_idx = next(splitter.split(df, y, groups=episodes))

    n_train = len(train_idx)
    n_test = len(test_idx)
    train_eps = len(set(episodes[train_idx]))
    test_eps = len(set(episodes[test_idx]))

    print(f"[+] Phân chia tập dữ liệu theo Episode:")
    print(f"    - Tập huấn luyện (Train): {n_train:,} cửa sổ ({train_eps} lượt chạy)")
    print(f"    - Tập kiểm tra (Test):     {n_test:,} cửa sổ ({test_eps} lượt chạy)")
    print(f"    - Test Normal: {(y[test_idx] == 0).sum():,} | Test Attack: {(y[test_idx] == 1).sum():,}")

    models_dict = build_models()
    results = {
        'n_train': n_train,
        'n_test': n_test,
        'train_episodes': train_eps,
        'test_episodes': test_eps,
        'test_normal': int((y[test_idx] == 0).sum()),
        'test_attack': int((y[test_idx] == 1).sum()),
        'models': {}
    }

    trained_instances = {}
    print("\n" + "="*85)
    print(f"{'MÔ HÌNH':<36} | {'ACC':<7} | {'PREC':<7} | {'REC':<7} | {'F1':<7} | {'FPR':<7} | {'SUY LUẬN'}")
    print("="*85)

    for name, (model, feats) in models_dict.items():
        X_train = df.iloc[train_idx][feats].values
        y_train = y[train_idx]
        X_test = df.iloc[test_idx][feats].values
        y_test = y[test_idx]

        # Huấn luyện
        model.fit(X_train, y_train)

        # Dự đoán & đánh giá
        pred = model.predict(X_test)
        metrics = calculate_metrics(y_test, pred)
        latency = measure_inference_time(model, X_test)
        metrics.update(latency)

        if hasattr(model, 'feature_importances_'):
            metrics['importance'] = {f: float(v) for f, v in zip(feats, model.feature_importances_)}

        results['models'][name] = metrics
        trained_instances[name] = (model, feats, pred)

        print(f"{name:<36} | {metrics['accuracy']*100:6.2f}% | {metrics['precision']*100:6.2f}% | "
              f"{metrics['recall']*100:6.2f}% | {metrics['f1']*100:6.2f}% | {metrics['fpr']*100:6.2f}% | "
              f"{metrics['mean_ms']:5.2f} ms")

    print("="*85)

    # 1. Chi tiết theo từng loại tấn công cho Random Forest (4 đặc trưng lõi)
    rf4_model, rf4_feats, rf4_pred = trained_instances['Random Forest (4 đặc trưng lõi)']
    test_df = df.iloc[test_idx].copy()
    test_df['pred'] = rf4_pred

    print("\n[+] Độ nhạy (Recall) theo từng loại tấn công cụ thể:")
    attack_breakdown = {}
    for atk_name, group in test_df[test_df['label'] == 1].groupby('attack_type'):
        rec = float((group['pred'] == 1).mean())
        attack_breakdown[atk_name] = {'samples': int(len(group)), 'recall': rec}
        print(f"    - {atk_name:<18}: {rec*100:6.2f}% ({len(group)} mẫu)")
    results['rf4_recall_by_attack'] = attack_breakdown

    # 2. Kiểm tra chéo 5-Fold Group CV cho RF-4
    print("\n[+] Đang thực hiện 5-Fold Group Cross Validation theo Episode cho RF-4...")
    cv_acc, cv_fpr, cv_rec, cv_f1 = [], [], [], []
    gkf = GroupKFold(n_splits=5)
    for cv_tr, cv_te in gkf.split(df, y, groups=episodes):
        cv_m = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3,
                                      n_jobs=1, random_state=SEED)
        cv_m.fit(df.iloc[cv_tr][FEATURES_CORE].values, y[cv_tr])
        cv_pred = cv_m.predict(df.iloc[cv_te][FEATURES_CORE].values)
        r = calculate_metrics(y[cv_te], cv_pred)
        cv_acc.append(r['accuracy'])
        cv_fpr.append(r['fpr'])
        cv_rec.append(r['recall'])
        cv_f1.append(r['f1'])

    results['rf4_cv5'] = {
        'accuracy_mean': float(np.mean(cv_acc)), 'accuracy_std': float(np.std(cv_acc)),
        'fpr_mean': float(np.mean(cv_fpr)), 'fpr_std': float(np.std(cv_fpr)),
        'recall_mean': float(np.mean(cv_rec)), 'recall_std': float(np.std(cv_rec)),
        'f1_mean': float(np.mean(cv_f1)), 'f1_std': float(np.std(cv_f1))
    }
    print(f"    - Accuracy TB : {np.mean(cv_acc)*100:.2f}% (±{np.std(cv_acc)*100:.2f}%)")
    print(f"    - Recall TB   : {np.mean(cv_rec)*100:.2f}% (±{np.std(cv_rec)*100:.2f}%)")
    print(f"    - FPR TB      : {np.mean(cv_fpr)*100:.2f}% (±{np.std(cv_fpr)*100:.2f}%)")

    # 3. Lưu mô hình triển khai
    out_dir = args.outdir
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, 'models'), exist_ok=True)

    # Lưu file edge_ai_model.joblib theo đúng yêu cầu đề bài
    primary_model_path = os.path.join(out_dir, 'edge_ai_model.joblib')
    joblib.dump(rf4_model, primary_model_path, compress=3)
    
    # Đồng thời lưu bản sao tại models/rf_edge.joblib và edge_ai/models/
    alt_model_path = os.path.join(out_dir, 'models', 'rf_edge.joblib')
    joblib.dump(rf4_model, alt_model_path, compress=3)
    edge_ai_models_dir = os.path.join(CURRENT_DIR, 'edge_ai', 'models')
    if os.path.isdir(edge_ai_models_dir):
        joblib.dump(rf4_model, os.path.join(edge_ai_models_dir, 'edge_ai_model.joblib'), compress=3)
        joblib.dump(rf4_model, os.path.join(edge_ai_models_dir, 'rf_edge.joblib'), compress=3)

    model_size_kb = round(os.path.getsize(primary_model_path) / 1024, 1)
    results['model_size_kb'] = model_size_kb
    print(f"\n[✓] Đã xuất mô hình AI: {primary_model_path} ({model_size_kb} KB)")

    # Lưu file cấu hình mô hình
    config_data = {
        'model_file': 'edge_ai_model.joblib',
        'features': rf4_feats,
        'window_seconds': 1.0,
        'classes': {'0': 'normal', '1': 'attack'},
        'threshold': 0.5,
        'consecutive_windows_to_block': 2,
        'reaction_time_guarantee_sec': 2.0
    }
    with open(os.path.join(out_dir, 'edge_ai_model.json'), 'w') as f:
        json.dump(config_data, f, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, 'models', 'rf_edge.json'), 'w') as f:
        json.dump(config_data, f, indent=2, ensure_ascii=False)

    # 4. Xuất ma trận nhầm lẫn
    cm = confusion_matrix(y[test_idx], rf4_pred, labels=[0, 1])
    cm_path1 = os.path.join(out_dir, 'confusion_matrix.png')
    cm_path2 = os.path.join(out_dir, 'confusion_matrix_rf4.png')
    draw_confusion_matrix(cm, cm_path1, 'Ma trận nhầm lẫn - Random Forest (4 đặc trưng lõi)')
    draw_confusion_matrix(cm, cm_path2, 'Ma trận nhầm lẫn - Random Forest (4 đặc trưng lõi)')

    # 5. Xuất ảnh độ quan trọng đặc trưng
    imp_dict = results['models']['Random Forest (4 đặc trưng lõi)']['importance']
    feat_img_path = os.path.join(out_dir, 'feature_importance.png')
    draw_feature_importance(list(imp_dict.values()), list(imp_dict.keys()), feat_img_path)

    # 6. Ghi kết quả tổng thể ra results.json
    results_json_path = os.path.join(out_dir, 'results.json')
    with open(results_json_path, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[✓] Đã lưu kết quả phân tích đầy đủ: {results_json_path}")

    # In báo cáo phục vụ Mục 2.4.1
    print("\n" + "#"*70)
    print("### SỐ LIỆU ĐÁNH GIÁ MÔ HÌNH EDGE AI CHO MỤC 2.4.1 BÁO CÁO ###")
    print("#"*70)
    print(f"1. Tổng số mẫu kiểm tra: {n_test:,} cửa sổ ({test_eps} lượt chạy độc lập)")
    print(f"2. Random Forest 4 đặc trưng lõi:")
    rf4 = results['models']['Random Forest (4 đặc trưng lõi)']
    print(f"   - Accuracy (Độ chính xác)         : {rf4['accuracy']*100:.2f}%")
    print(f"   - Precision (Độ chuẩn xác)        : {rf4['precision']*100:.2f}%")
    print(f"   - Recall (Độ nhạy phát hiện)      : {rf4['recall']*100:.2f}%")
    print(f"   - F1-Score                        : {rf4['f1']*100:.2f}%")
    print(f"   - Tỷ lệ báo giả (FPR)             : {rf4['fpr']*100:.3f}% (Chỉ {rf4['fp']} cửa sổ bị báo nhầm)")
    print(f"   - Thời gian suy luận trung bình   : {rf4['mean_ms']:.2f} ms/cửa sổ (P95: {rf4['p95_ms']:.2f} ms)")
    print(f"   - Kích thước file mô hình         : {model_size_kb} KB (cực kỳ gọn nhẹ cho Edge Gateway)")
    print(f"3. Ma trận nhầm lẫn:")
    print(f"   - True Negative  (TN) = {rf4['tn']:,} (Nhận diện đúng bình thường)")
    print(f"   - False Positive (FP) = {rf4['fp']:,} (Báo giả bình thường thành tấn công)")
    print(f"   - False Negative (FN) = {rf4['fn']:,} (Bỏ sót tấn công)")
    print(f"   - True Positive  (TP) = {rf4['tp']:,} (Phát hiện đúng tấn công)")
    print("#"*70 + "\n")


if __name__ == '__main__':
    main()
