# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import torch
from tqdm import tqdm
import numpy as np
from sklearn.metrics import roc_auc_score

from Save import print_metrics_full, save_epoch_models


def validate_and_log(model, val_loader, criterion, device, epoch, total_epochs):
    """验证模型并返回详细指标"""
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    all_preds = []
    all_labels = []
    all_probs = []
    
    with torch.no_grad():
        for raw, labels in tqdm(val_loader, desc='Validating'):
            raw = raw.to(device)
            labels = labels.to(device)
            
            outputs = model(raw)
            loss = criterion(outputs, labels)
            
            total_loss += loss.item() * raw.size(0)
            probs = torch.softmax(outputs, dim=1)[:, 1]
            _, predicted = torch.max(outputs, 1)
            
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
            
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())
    
    val_loss = total_loss / total
    val_acc = correct / total
    
    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)
    all_probs = np.array(all_probs)
    
    print_metrics_full(all_labels, all_preds, all_probs, val_loss, epoch, total_epochs)
    
    return val_loss, val_acc, all_preds, all_labels, all_probs
