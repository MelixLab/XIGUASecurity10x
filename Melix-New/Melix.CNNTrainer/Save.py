# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import os
import gc
import torch
import torch.onnx
from pathlib import Path
from typing import Dict, Any
import shutil


def save_epoch_models(
    model: torch.nn.Module,
    optimizer: torch.optim.Optimizer,
    scheduler: Any,
    epoch: int,
    global_step: int,
    best_dict: Dict[str, Any],
    save_dir: str = "Melix"
) -> Dict[str, str]:
    """
    保存每轮模型：pth + onnx + checkpoint
    """
    epoch_dir = Path(save_dir) / f"Epoch_{epoch}"
    epoch_dir.mkdir(parents=True, exist_ok=True)
    
    saved_paths = {}
    device = next(model.parameters()).device
    
    # 保存模型权重
    model_path = epoch_dir / "model.pth"
    torch.save(model.state_dict(), model_path)
    saved_paths['model'] = str(model_path)
    
    # 保存检查点
    ckpt_path = epoch_dir / "checkpoint.pth"
    checkpoint = {
        'epoch': epoch,
        'global_step': global_step,
        'model_state_dict': model.state_dict(),
        'optimizer_state_dict': optimizer.state_dict(),
        'scheduler_state_dict': scheduler.state_dict() if scheduler else None,
        'best_dict': best_dict
    }
    torch.save(checkpoint, ckpt_path)
    saved_paths['checkpoint'] = str(ckpt_path)
    
    # 每轮都导出ONNX (单输入)
    try:
        model.eval()
        dummy_input = torch.randn(1, 12288, device=device)
        
        deep_onnx_path = epoch_dir / "DeepMode.onnx"
        torch.onnx.export(
            model,
            dummy_input,
            deep_onnx_path,
            input_names=['input'],
            output_names=['output'],
            dynamic_axes={
                'input': {0: 'batch_size'},
                'output': {0: 'batch_size'}
            },
            opset_version=17,
            do_constant_folding=True
        )
        saved_paths['deep_onnx'] = str(deep_onnx_path)
        
        # 复制到latest
        latest_dir = Path(save_dir) / "latest"
        latest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(deep_onnx_path, latest_dir / "DeepMode.onnx")
        saved_paths['latest_onnx'] = str(latest_dir / "DeepMode.onnx")
        
        del dummy_input
        
    except Exception as e:
        print(f"⚠️  ONNX导出失败: {e}")
        saved_paths['deep_onnx'] = None
    
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    
    gc.collect()
    
    return saved_paths


def save_best_models(
    model,
    optimizer,
    epoch,
    best_auc,
    val_loss,
    val_acc,
    all_preds,
    all_labels,
    all_probs,
    save_dir="Melix"
):
    """保存最佳模型并返回当前AUC"""
    from sklearn.metrics import roc_auc_score
    import numpy as np
    
    current_auc = roc_auc_score(all_labels, all_probs)
    
    if current_auc > best_auc:
        print(f'\n✓ New Best ROC-AUC: {current_auc:.6f}\n')
        
        best_dict = {
            'epoch': epoch,
            'auc': current_auc,
            'val_loss': val_loss,
            'val_acc': val_acc
        }
        
        paths = save_epoch_models(
            model, optimizer, None, epoch, 0, best_dict, save_dir
        )
        
        print(f'\nSaving models to {paths.get("model", "")}...')
        for key, path in paths.items():
            if path:
                import os
                size_mb = os.path.getsize(path) / (1024 * 1024)
                print(f'   {os.path.basename(path):<25} ({size_mb:.2f} MB)')
        print('   Memory cleaned up')
    
    return current_auc


def print_metrics_full(
    y_true, 
    y_pred, 
    y_prob,
    val_loss: float,
    epoch: int,
    total_epochs: int
) -> Dict[str, float]:
    """打印完整的验证指标"""
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score, fbeta_score,
        matthews_corrcoef, cohen_kappa_score, log_loss, average_precision_score,
        roc_auc_score, confusion_matrix
    )
    import numpy as np
    
    metrics = {}
    
    metrics['accuracy'] = accuracy_score(y_true, y_pred)
    metrics['loss'] = val_loss
    
    metrics['roc_auc'] = roc_auc_score(y_true, y_prob)
    metrics['average_precision'] = average_precision_score(y_true, y_prob)
    metrics['gini_coefficient'] = 2 * metrics['roc_auc'] - 1
    
    metrics['precision'] = precision_score(y_true, y_pred, zero_division=0)
    metrics['recall'] = recall_score(y_true, y_pred, zero_division=0)
    metrics['f1_score'] = f1_score(y_true, y_pred, zero_division=0)
    metrics['f2_score'] = fbeta_score(y_true, y_pred, beta=2, zero_division=0)
    metrics['f0.5_score'] = fbeta_score(y_true, y_pred, beta=0.5, zero_division=0)
    
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        metrics['true_positives'] = int(tp)
        metrics['true_negatives'] = int(tn)
        metrics['false_positives'] = int(fp)
        metrics['false_negatives'] = int(fn)
        metrics['specificity'] = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics['false_negative_rate'] = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    else:
        metrics['specificity'] = 0.0
        metrics['false_positive_rate'] = 0.0
        metrics['false_negative_rate'] = 0.0
    
    metrics['matthews_correlation_coefficient'] = matthews_corrcoef(y_true, y_pred)
    metrics['cohen_kappa'] = cohen_kappa_score(y_true, y_pred)
    
    y_prob_clipped = np.clip(y_prob, 1e-7, 1 - 1e-7)
    metrics['log_loss'] = log_loss(y_true, y_prob_clipped)
    
    print(f"🔬 VALIDATION METRICS - Epoch {epoch}/{total_epochs}")
    
    print(f"\n📊 BASIC PERFORMANCE METRICS")
    print(f"   {'Accuracy (准确率):':<35} {metrics['accuracy']*100:>12.10f} %")
    print(f"   {'Loss (损失):':<35} {metrics['loss']:>12.10f}")
    
    print(f"\n🎯 RANKING & DISCRIMINATION METRICS")
    print(f"   {'ROC AUC (曲线下面积):':<35} {metrics['roc_auc']:>12.10f}")
    print(f"   {'Average Precision (平均精确率):':<35} {metrics['average_precision']:>12.10f}")
    print(f"   {'Gini Coefficient (基尼系数):':<35} {metrics['gini_coefficient']:>12.10f}")
    
    print(f"\n🎲 PRECISION & RECALL METRICS")
    print(f"   {'Precision (精确率):':<35} {metrics['precision']:>12.10f}")
    print(f"   {'Recall / Sensitivity (召回率/敏感度):':<35} {metrics['recall']:>12.10f}")
    print(f"   {'Specificity (特异度):':<35} {metrics['specificity']:>12.10f}")
    print(f"   {'F1-Score (F1分数):':<35} {metrics['f1_score']:>12.10f}")
    print(f"   {'F2-Score (F2分数, 侧重召回):':<35} {metrics['f2_score']:>12.10f}")
    print(f"   {'F0.5-Score (F0.5分数, 侧重精确):':<35} {metrics['f0.5_score']:>12.10f}")
    
    print(f"\n📅 CONFUSION MATRIX DETAILS")
    if cm.shape == (2, 2):
        print(f"   {'True Positives (真正例):':<35} {metrics['true_positives']:>12d}")
        print(f"   {'True Negatives (真负例):':<35} {metrics['true_negatives']:>12d}")
        print(f"   {'False Positives (假正例):':<35} {metrics['false_positives']:>12d}")
        print(f"   {'False Negatives (假负例):':<35} {metrics['false_negatives']:>12d}")
        print(f"   {'False Positive Rate (假正率):':<35} {metrics['false_positive_rate']:>12.10f}")
        print(f"   {'False Negative Rate (假负率):':<35} {metrics['false_negative_rate']:>12.10f}")
    
    print(f"\n📈 ADVANCED CORRELATION METRICS")
    print(f"   {'Matthews Correlation Coefficient (马氏相关系数):':<35} {metrics['matthews_correlation_coefficient']:>12.10f}")
    print(f"   {'Cohen Kappa (科恩卡帕系数):':<35} {metrics['cohen_kappa']:>12.10f}")
    print(f"   {'Log Loss (对数损失):':<35} {metrics['log_loss']:>12.10f}")
    
    print(f"\n{'='*80}\n")
    
    return metrics
