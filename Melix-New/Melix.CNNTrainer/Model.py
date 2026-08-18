# Developed by Ice Zero Studio
# Developed using the OverClouded architecture
# The MINT v4 agreement has been signed

import sys
import os

# 将 AIModel 目录加入路径，以便导入 Bitremal.RB
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'AIModel'))

import torch
import torch.nn as nn
from Bitremal.RB import GateStage, ConvStage


class MelixCNN(nn.Module):
    def __init__(self, num_classes: int = 2) -> None:
        super().__init__()

        self.stage1: GateStage = GateStage(3, 16, stride=1)
        self.stage2: GateStage = GateStage(16, 24, stride=2)
        self.stage3: nn.Sequential = nn.Sequential(
            ConvStage(24, 48, rep_kernel=3, stride=2),
            ConvStage(48, 48, rep_kernel=3, stride=1),
        )
        self.stage4: nn.Sequential = nn.Sequential(
            ConvStage(48, 96, rep_kernel=5, stride=2),
            ConvStage(96, 96, rep_kernel=5, stride=1),
        )

        self.proj: nn.Linear = nn.Linear(96, 256)

        encoder_layer: nn.TransformerEncoderLayer = nn.TransformerEncoderLayer(
            d_model=256,
            nhead=8,
            dim_feedforward=256 * 4,
            dropout=0.0,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.transformer: nn.TransformerEncoder = nn.TransformerEncoder(
            encoder_layer, num_layers=4, enable_nested_tensor=False
        )
        self.norm: nn.LayerNorm = nn.LayerNorm(256)
        self.head: nn.Linear = nn.Linear(256, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x.reshape(x.size(0), 3, 64, 64).float()
        x = self.stage1(x)
        x = self.stage2(x)
        x = self.stage3(x)
        x = self.stage4(x)
        x = x.reshape(x.size(0), 96, 64)
        x = x.permute(0, 2, 1)
        x = self.proj(x)
        x = self.transformer(x)
        x = self.norm(x)
        x = x.mean(dim=1)
        x = self.head(x)
        return x
