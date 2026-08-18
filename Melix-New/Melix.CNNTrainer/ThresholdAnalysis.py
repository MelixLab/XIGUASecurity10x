# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

"""阈值分析脚本 - 找到误报<0.1%且召回>80%的最佳阈值"""

import torch
import numpy as np
from pathlib import Path
from DataLoader import MelixFileDataset
from Model import MelixCNN
from sklearn.metrics import roc_curve, auc


def find_best_threshold(y_true, y_prob, target_fpr=0.001, target_recall=0.80):
    """
    分析不同阈值下的表现，找到最佳阈值
    
    目标：
    - FPR (误报率) < 0.1% (target_fpr=0.001)
    - TPR (召回率) > 80% (target_recall=0.80)
    """
    # 计算 ROC 曲线
    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)
    
    print(f"\n{'='*80}")
    print(f"ROC AUC: {roc_auc:.6f}")
    print(f"{'='*80}")
    
    # 打印不同阈值下的表现
    print(f"\n{'='*80}")
    print(f"Threshold Analysis (目标: FPR<{target_fpr*100:.1f}%, Recall>{target_recall*100:.1f}%)")
    print(f"{'='*80}")
    print(f"{'Threshold':<12} {'Recall':<10} {'FPR':<12} {'Precision':<12} {'F1':<10} {'Status'}")
    print(f"{'-'*80}")
    
    best_threshold = None
    best_recall = 0
    
    for thresh in [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.92, 0.94, 0.95, 0.96, 0.97, 0.98, 0.99, 0.995, 0.999, 0.9995, 0.9999]:
        y_pred = (y_prob >= thresh).astype(int)
        
        tp = np.sum((y_pred == 1) & (y_true == 1))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        tn = np.sum((y_pred == 0) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        status = ""
        if fpr_val <= target_fpr and recall >= target_recall:
            status = "✓ BEST"
            if recall > best_recall:
                best_recall = recall
                best_threshold = thresh
        elif fpr_val <= target_fpr:
            status = "~ Low FPR"
        elif recall >= target_recall:
            status = "~ High Recall"
        
        print(f"{thresh:<12.2f} {recall*100:<10.2f} {fpr_val*100:<12.2f} {precision*100:<12.2f} {f1*100:<10.2f} {status}")
    
    print(f"{'-'*80}")
    
    if best_threshold is not None:
        print(f"\n✓ Found optimal threshold: {best_threshold}")
        print(f"  - Recall: {best_recall*100:.2f}%")
        print(f"  - FPR: <= {target_fpr*100:.1f}%")
    else:
        print(f"\n✗ No threshold satisfies both FPR<{target_fpr*100:.1f}% AND Recall>{target_recall*100:.1f}%")
        print(f"  The model's probability distribution is not sufficiently separated.")
        print(f"  Consider:")
        print(f"    1. Training more epochs")
        print(f"    2. Increasing model capacity")
        print(f"    3. Better feature engineering")
    
    return best_threshold, roc_auc


def main():
    # 阈值分析用 CPU 避免显存不足
    device = torch.device('cpu')
    
    # 加载验证集
    print("Loading validation dataset...", flush=True)
    val_ds = MelixFileDataset(
        r"D:\xdows ai\机器学习\Melix-New\Melix.CNNTrainer\blackData",
        r"D:\xdows ai\机器学习\Melix-New\Melix.CNNTrainer\WhiteData",
        split='val',
        feature_dim=12288,
        train_ratio=0.8,
        augment=False
    )
    
    val_loader = torch.utils.data.DataLoader(
        val_ds,
        batch_size=128,
        shuffle=False,
        num_workers=0
    )
    
    # 自动查找最佳模型
    model_path = None
    for epoch in sorted([int(p.name.split('_')[1]) for p in Path("Melix").glob("Epoch_*") if p.name.startswith('Epoch_')], reverse=True):
        candidate = Path(f"Melix/Epoch_{epoch}/model.pth")
        if candidate.exists():
            model_path = candidate
            break
    
    if not model_path:
        model_path = Path("Melix/latest/checkpoint.pth")
    
    if not model_path.exists():
        print(f"Model not found: {model_path}")
        return
    
    print(f"Loading model from {model_path}...", flush=True)
    model = MelixCNN(num_classes=2).to(device)
    
    state = torch.load(model_path, map_location=device)
    if 'model_state_dict' in state:
        model.load_state_dict(state['model_state_dict'])
    else:
        model.load_state_dict(state)
    
    model.eval()
    
    # 收集所有预测概率和标签
    print("Running inference on validation set...", flush=True)
    all_probs = []
    all_labels = []
    
    with torch.no_grad():
        for raw_bytes, labels in val_loader:
            raw_bytes = raw_bytes.to(device)
            outputs = model(raw_bytes)
            probs = torch.softmax(outputs, dim=1)[:, 1]  # 恶意概率
            all_probs.append(probs.cpu().numpy())
            all_labels.append(labels.numpy())
    
    y_prob = np.concatenate(all_probs)
    y_true = np.concatenate(all_labels)
    
    print(f"Total samples: {len(y_true)}", flush=True)
    print(f"Black samples: {np.sum(y_true == 1)}", flush=True)
    print(f"White samples: {np.sum(y_true == 0)}", flush=True)
    
    # 分析阈值
    best_threshold, roc_auc = find_best_threshold(y_true, y_prob)
    
    return best_threshold


if __name__ == "__main__":
    main()
