# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import os
import sys
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from tqdm import tqdm
import math
import numpy as np
import glob
from pathlib import Path

from Model import MelixCNN
from DataLoader import MelixFileDataset
from Metrics import validate_and_log
from Save import save_best_models


def train_epoch(model, loader, optimizer, criterion, scaler, device, use_amp):
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0
    
    for raw, labels in tqdm(loader, desc='Training'):
        raw = raw.to(device)
        labels = labels.to(device)
        
        optimizer.zero_grad()
        
        if use_amp:
            with torch.amp.autocast(device_type='cuda', dtype=torch.float16):
                outputs = model(raw)
                loss = criterion(outputs, labels)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            outputs = model(raw)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
        
        total_loss += loss.item() * raw.size(0)
        _, predicted = torch.max(outputs, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()
    
    return total_loss / total, correct / total


def train():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f'[+] Device: {device}')
    
    black_folder = r'D:\xdows ai\机器学习\Melix-New\Melix.CNNTrainer\blackData'
    white_folder = r'D:\xdows ai\机器学习\Melix-New\Melix.CNNTrainer\WhiteData'
    
    batch_size = 128
    lr = 1e-4          # 降低10倍，从Epoch 18开始精细微调
    num_epochs = 100   # 延续训练到100轮
    save_dir = "Melix"
    patience = 10      # 学习率降低后收敛变慢，放宽早停
    
    train_dataset = MelixFileDataset(
        black_folder, white_folder,
        split='train', augment=True
    )
    val_dataset = MelixFileDataset(
        black_folder, white_folder,
        split='val', augment=False
    )
    
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
        pin_memory=True if device.type == 'cuda' else False
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
        pin_memory=True if device.type == 'cuda' else False
    )
    
    model = MelixCNN(num_classes=2).to(device)

    # 类别权重：黑样本权重更高，提高召回率
    black_weight = max(1.0, len(train_dataset) / (2.0 * sum(1 for _, l in train_dataset if l == 1)))
    print(f'[+] Black class weight: {black_weight:.2f}')

    class_weights = torch.tensor([1.0, black_weight], dtype=torch.float32).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=num_epochs, eta_min=1e-6)

    use_amp = device.type == 'cuda'
    scaler = torch.amp.GradScaler() if use_amp else None

    # 新架构，从零开始训练
    start_epoch = 0
    best_auc = 0.0
    epochs_no_improve = 0
    
    print(f'[+] Model params: {sum(p.numel() for p in model.parameters()):,}')
    print(f'   Train: {len(train_dataset):,} | Val: {len(val_dataset):,}')
    print(f'[+] Training with {"AMP" if use_amp else "FP32"}')
    
    for epoch in range(start_epoch, num_epochs):
        print(f'\n{"="*80}\nEpoch {epoch+1}/{num_epochs}\n{"="*80}')
        
        train_loss, train_acc = train_epoch(model, train_loader, optimizer, criterion, scaler, device, use_amp)
        print(f'[+] Train Loss: {train_loss:.6f} | Acc: {train_acc:.4f}')
        
        val_loss, val_acc, all_preds, all_labels, all_probs = validate_and_log(model, val_loader, criterion, device, epoch+1, num_epochs)
        
        auc = save_best_models(model, optimizer, epoch+1, best_auc, val_loss, val_acc, all_preds, all_labels, all_probs)
        
        if auc > best_auc:
            best_auc = auc
            epochs_no_improve = 0
        else:
            epochs_no_improve += 1
            print(f'  ROC-AUC not improved ({epochs_no_improve}/{patience})')
        
        if epochs_no_improve >= patience:
            print(f'\n[!] Early stopping at epoch {epoch+1} (best AUC: {best_auc:.6f})')
            break
        
        scheduler.step()
    
    print(f'\n[+] Training complete. Best ROC-AUC: {best_auc:.6f}')
    return model


if __name__ == '__main__':
    train()
