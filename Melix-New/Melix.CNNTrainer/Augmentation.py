# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

"""数据增强模块 - 针对恶意软件字节数据（整数版本）"""

import torch
import numpy as np
import random


class ByteAugmentation:
    """字节级数据增强，模拟恶意软件变异（输入输出均为 0-255 整数）"""

    def __init__(
        self,
        noise_prob: float = 0.3,
        noise_intensity: int = 5,
        mask_prob: float = 0.2,
        mask_ratio: float = 0.05,
        shift_prob: float = 0.3,
        shift_max: int = 32
    ):
        self.noise_prob = noise_prob
        self.noise_intensity = noise_intensity
        self.mask_prob = mask_prob
        self.mask_ratio = mask_ratio
        self.shift_prob = shift_prob
        self.shift_max = shift_max

    def add_noise(self, x: torch.Tensor) -> torch.Tensor:
        """添加均匀分布整数噪声"""
        if random.random() > self.noise_prob:
            return x
        noise = torch.randint(-self.noise_intensity, self.noise_intensity + 1, x.shape, dtype=torch.long)
        x = torch.clamp(x + noise, 0, 255)
        return x

    def random_mask(self, x: torch.Tensor) -> torch.Tensor:
        """随机遮挡部分字节（模拟加密/压缩后的数据缺失）"""
        if random.random() > self.mask_prob:
            return x
        length = x.shape[0]
        mask_length = int(length * self.mask_ratio)
        start = random.randint(0, max(0, length - mask_length))
        x[start:start+mask_length] = 0
        return x

    def byte_shift(self, x: torch.Tensor) -> torch.Tensor:
        """字节值偏移（模拟不同的编码/加密方式）"""
        if random.random() > self.shift_prob:
            return x
        shift = random.randint(-self.shift_max, self.shift_max)
        x = torch.clamp(x + shift, 0, 255)
        return x

    def __call__(self, x: torch.Tensor) -> torch.Tensor:
        x = self.add_noise(x)
        x = self.random_mask(x)
        x = self.byte_shift(x)
        return x


class MixUpAugmentation:
    """MixUp数据增强，合并两个样本"""

    def __init__(self, alpha: float = 0.4, prob: float = 0.3):
        self.alpha = alpha
        self.prob = prob

    def __call__(self, x1: torch.Tensor, y1: int, x2: torch.Tensor, y2: int):
        if random.random() > self.prob or y1 != y2:
            return x1, y1, 1.0

        lam = np.random.beta(self.alpha, self.alpha)
        mixed_x = (lam * x1.float() + (1 - lam) * x2.float()).long().clamp(0, 255)
        return mixed_x, y1, lam
