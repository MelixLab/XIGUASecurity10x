# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import torch
import torch.nn as nn
import torch.nn.functional as F


class CNNBranch(nn.Module):
    """CNN分支：处理12288原始字节"""
    
    def __init__(self, dropout: float = 0.3):
        super().__init__()
        
        self.conv1 = nn.Conv1d(1, 32, kernel_size=16, stride=4)
        self.bn1 = nn.BatchNorm1d(32)
        
        self.conv2 = nn.Conv1d(32, 64, kernel_size=8, stride=4)
        self.bn2 = nn.BatchNorm1d(64)
        
        self.conv3 = nn.Conv1d(64, 128, kernel_size=4, stride=2)
        self.bn3 = nn.BatchNorm1d(128)
        
        self.pool = nn.AdaptiveAvgPool1d(1)
        
    def forward(self, x):
        x = x.unsqueeze(1)
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))
        x = F.relu(self.bn3(self.conv3(x)))
        x = self.pool(x)
        return x.view(x.size(0), -1)


class HandcraftedBranch(nn.Module):
    """手工特征分支：处理100维统计特征"""
    
    def __init__(self, input_dim: int = 100, dropout: float = 0.3):
        super().__init__()
        
        self.mlp = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 64)
        )
    
    def forward(self, x):
        return self.mlp(x)


class PEBranch(nn.Module):
    """PE结构特征分支：处理567维PE特征（LightGBM特征工程）"""
    
    def __init__(self, input_dim: int = 567, dropout: float = 0.3):
        super().__init__()
        
        self.mlp = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, 128)
        )
    
    def forward(self, x):
        return self.mlp(x)


class MelixFusion(nn.Module):
    """Melix三输入融合模型：CNN + 统计特征 + PE结构特征
    
    输入1: 12288原始字节 (raw_bytes)
    输入2: 100维统计特征 (handcrafted)
    输入3: 567维PE结构特征 (pe_features)
    
    融合策略: 128维(CNN) + 64维(统计) + 128维(PE) = 320维 -> 分类器
    """
    
    def __init__(
        self,
        raw_dim: int = 12288,
        feature_dim: int = 100,
        pe_dim: int = 567,
        num_classes: int = 2,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.cnn_branch = CNNBranch(dropout=dropout)
        self.feature_branch = HandcraftedBranch(feature_dim, dropout=dropout)
        self.pe_branch = PEBranch(pe_dim, dropout=dropout)
        
        # 融合分类器：128 + 64 + 128 = 320
        self.fusion = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(320, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes)
        )
        
        self._init_weights()
    
    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
    
    def forward(self, raw_bytes, handcrafted, pe_features):
        """
        Args:
            raw_bytes: (batch, 12288) 原始字节
            handcrafted: (batch, 100) 统计特征
            pe_features: (batch, 567) PE结构特征
        Returns:
            logits: (batch, 2)
        """
        cnn_features = self.cnn_branch(raw_bytes)              # (batch, 128)
        handcrafted_features = self.feature_branch(handcrafted)  # (batch, 64)
        pe_features_out = self.pe_branch(pe_features)          # (batch, 128)
        
        fused = torch.cat([cnn_features, handcrafted_features, pe_features_out], dim=1)  # (batch, 320)
        logits = self.fusion(fused)
        return logits
