# Copyright (C) 2026 LinduCMint
"""LightGBM 训练脚本 - 使用完整 PE 结构特征（单线程调试版）"""

import os
import json
import time
import random
from pathlib import Path
from tqdm import tqdm
import sys
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, roc_auc_score, precision_score, recall_score,
    f1_score, confusion_matrix
)

from PEFeatureExtractor import PEFeatureExtractor


def scan_files(folder: str, max_files: int = 0) -> list:
    path = Path(folder)
    if not path.exists():
        return []
    files = [str(p) for p in path.rglob('*') if p.is_file()]
    if max_files > 0 and len(files) > max_files:
        random.seed(42)
        files = random.sample(files, max_files)
    return files


def extract_features_single_thread(black_files, white_files, cache_path='pe_features_quick.json'):
    """单线程特征提取，带进度条"""
    if os.path.exists(cache_path):
        print(f'[+] Loading cached features from {cache_path}')
        with open(cache_path, 'r') as f:
            return json.load(f)

    tasks = [(f, 1) for f in black_files] + [(f, 0) for f in white_files]
    results = []

    print(f'[+] Extracting features from {len(tasks)} files (single-thread)...')
    extractor = PEFeatureExtractor()
    start = time.time()

    for file_path, label in tqdm(tasks, desc='PE features', unit='file', file=sys.stdout, mininterval=1, ncols=80):
        try:
            features = extractor.extract(file_path)
            if features is not None:
                results.append({
                    'file': file_path,
                    'features': features.tolist(),
                    'label': int(label)
                })
        except Exception:
            pass
        if len(results) % 100 == 0:
            sys.stdout.flush()

    sys.stdout.flush()  # 确保 tqdm 最终输出

    elapsed = time.time() - start
    print(f'\n[+] Extracted {len(results)} features in {elapsed:.1f}s ({len(results)/elapsed:.1f} files/s)')

    with open(cache_path, 'w') as f:
        json.dump(results, f)
    print(f'[+] Saved features to {cache_path}')

    return results


def find_best_threshold(y_true, y_prob, target_fpr=0.001, target_recall=0.80):
    print(f'\n[+] Threshold Analysis (Target: FPR<{target_fpr*100:.1f}%, Recall>{target_recall*100:.1f}%)')
    print(f'    {"Threshold":<12} {"Recall":<10} {"FPR":<12} {"Precision":<12} {"F1":<10} {"Status"}')
    print(f'    {"-"*80}')

    best_threshold = None
    best_recall = 0

    for thresh in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.92, 0.94, 0.95, 0.96, 0.97, 0.98, 0.99, 0.995, 0.999, 0.9995, 0.9999]:
        y_pred = (y_prob >= thresh).astype(int)
        tn = np.sum((y_pred == 0) & (y_true == 0))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        tp = np.sum((y_pred == 1) & (y_true == 1))

        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        status = ""
        if fpr <= target_fpr and recall >= target_recall:
            status = "✓ BEST"
            if recall > best_recall:
                best_recall = recall
                best_threshold = thresh
        elif fpr <= target_fpr:
            status = "~ Low FPR"
        elif recall >= target_recall:
            status = "~ High Recall"

        print(f'    {thresh:<12.4f} {recall*100:<10.2f} {fpr*100:<12.2f} {precision*100:<12.2f} {f1*100:<10.2f} {status}')

    if best_threshold is not None:
        print(f'\n[✓] Best threshold: {best_threshold} (Recall={best_recall*100:.2f}%)')
    else:
        print(f'\n[✗] No threshold satisfies both conditions')

    return best_threshold


def train_lightgbm(X, y, feature_names):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f'\n[+] Training set: {len(X_train)} samples')
    print(f'[+] Test set: {len(X_test)} samples')

    scale_pos_weight = np.sum(y_train == 0) / np.sum(y_train == 1)
    print(f'[+] Scale pos weight: {scale_pos_weight:.2f}')

    train_data = lgb.Dataset(X_train, label=y_train)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

    params = {
        'objective': 'binary',
        'metric': 'auc',
        'boosting_type': 'gbdt',
        'num_leaves': 63,
        'max_depth': -1,
        'learning_rate': 0.05,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_child_samples': 30,
        'scale_pos_weight': scale_pos_weight,
        'verbose': -1,
        'random_state': 42,
    }

    print('\n[+] Training LightGBM...')
    model = lgb.train(
        params,
        train_data,
        num_boost_round=1000,
        valid_sets=[train_data, valid_data],
        valid_names=['train', 'valid'],
        callbacks=[lgb.log_evaluation(period=50), lgb.early_stopping(50)]
    )

    y_prob = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred = (y_prob >= 0.5).astype(int)

    print(f'\n[+] Evaluation Results:')
    print(f'    Accuracy:  {accuracy_score(y_test, y_pred)*100:.4f}%')
    print(f'    AUC:       {roc_auc_score(y_test, y_prob)*100:.4f}%')
    print(f'    Precision: {precision_score(y_test, y_pred)*100:.4f}%')
    print(f'    Recall:    {recall_score(y_test, y_pred)*100:.4f}%')
    print(f'    F1:        {f1_score(y_test, y_pred)*100:.4f}%')

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    print(f'    TN={tn}, FP={fp}, FN={fn}, TP={tp}')
    print(f'    FPR@0.5:   {fp/(fp+tn)*100:.4f}%')
    print(f'    FNR@0.5:   {fn/(fn+tp)*100:.4f}%')

    find_best_threshold(y_test, y_prob)

    print('\n[+] Top 20 Feature Importances:')
    importance = model.feature_importance(importance_type='gain')
    indices = np.argsort(importance)[::-1][:20]
    for i in indices:
        print(f'    {feature_names[i]:<40} {importance[i]:.2f}')

    model.save_model('Melix_LightGBM.txt')
    print('\n[+] Model saved to Melix_LightGBM.txt')

    return model


def main():
    black_folder = r'D:\Downloads\Black'
    white_folder = r'D:\Downloads\White'

    # 快速模式：黑白各 500
    max_files_per_class = 500

    print('[+] Scanning files...')
    black_files = scan_files(black_folder, max_files_per_class)
    white_files = scan_files(white_folder, max_files_per_class)
    print(f'[+] Quick mode: black={len(black_files)}, white={len(white_files)}')

    results = extract_features_single_thread(black_files, white_files)

    X = np.array([r['features'] for r in results])
    y = np.array([r['label'] for r in results])

    extractor = PEFeatureExtractor()
    feature_names = extractor.feature_names

    print(f'\n[+] Feature matrix shape: {X.shape}')
    print(f'[+] Black samples: {np.sum(y==1)}, White samples: {np.sum(y==0)}')

    train_lightgbm(X, y, feature_names)


if __name__ == '__main__':
    main()
