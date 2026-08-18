# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import struct
import math
from pathlib import Path
import numpy as np


def extract_features_from_bytes(file_bytes: bytes, max_size: int = 10 * 1024 * 1024) -> np.ndarray:
    """从原始字节提取关键手工特征（约100维），用于与CNN融合
    
    优化版本：使用numpy向量化计算，大幅提升速度
    """
    if len(file_bytes) > max_size:
        file_bytes = file_bytes[:max_size]
    
    size = len(file_bytes)
    if size == 0:
        return np.zeros(100, dtype=np.float32)
    
    data = np.frombuffer(file_bytes, dtype=np.uint8)
    features = []
    
    # 1. 字节频率直方图 (256维) - 用numpy快速计算
    hist = np.bincount(data, minlength=256).astype(np.float32)
    hist = hist / size
    
    # 1.1 频率摘要（16维）：每16个桶合并
    for i in range(16):
        features.append(float(hist[i*16:(i+1)*16].sum()))
    
    # 2. 全局熵 - 向量化
    nonzero_hist = hist[hist > 0]
    entropy = float(-np.sum(nonzero_hist * np.log2(nonzero_hist)))
    features.append(entropy)
    
    # 3. 块熵（8个区域）- 向量化
    block_size = max(size // 8, 1)
    block_entropies = []
    for i in range(8):
        start = i * block_size
        end = min((i + 1) * block_size, size)
        if end <= start:
            block_entropies.append(0.0)
            continue
        block = data[start:end]
        block_hist = np.bincount(block, minlength=256).astype(np.float32)
        block_hist = block_hist / len(block)
        nonzero_block = block_hist[block_hist > 0]
        block_entropy = float(-np.sum(nonzero_block * np.log2(nonzero_block))) if len(nonzero_block) > 0 else 0.0
        block_entropies.append(block_entropy)
    
    features.extend(block_entropies)
    
    # 4. 块熵统计
    be_array = np.array(block_entropies, dtype=np.float32)
    features.append(float(np.mean(be_array)))
    features.append(float(np.std(be_array)))
    features.append(float(np.max(be_array) - np.min(be_array)))
    
    # 5. 字节统计 - 向量化
    printable = float(np.sum((data >= 32) & (data <= 126))) / size
    control = float(np.sum((data < 32) | (data == 127))) / size
    whitespace = float(np.sum((data == 9) | (data == 10) | (data == 13) | (data == 32))) / size
    letters = float(np.sum(((data >= 65) & (data <= 90)) | ((data >= 97) & (data <= 122)))) / size
    digits = float(np.sum((data >= 48) & (data <= 57))) / size
    high_bytes = float(np.sum(data >= 128)) / size
    
    features.extend([printable, control, whitespace, letters, digits, high_bytes])
    
    # 6. 零字节统计
    zeros = float(np.sum(data == 0)) / size
    features.append(zeros)
    
    # 最大连续零 - 向量化
    zero_mask = (data == 0).astype(np.int32)
    if zero_mask.any():
        diffs = np.diff(np.concatenate([[0], zero_mask, [0]]))
        run_starts = np.where(diffs == 1)[0]
        run_ends = np.where(diffs == -1)[0]
        if len(run_starts) > 0:
            max_zero_run = np.max(run_ends - run_starts)
        else:
            max_zero_run = 0
    else:
        max_zero_run = 0
    features.append(min(max_zero_run / 1000.0, 1.0))
    
    # 7. 字节分布统计
    nonzero_hist_vals = hist[hist > 0]
    if len(nonzero_hist_vals) > 0:
        features.append(float(np.mean(nonzero_hist_vals)))
        features.append(float(np.std(nonzero_hist_vals)))
    else:
        features.extend([0.0, 0.0])
    
    # 8. PE检测
    is_pe = 1.0 if size > 64 and file_bytes[:2] == b'MZ' else 0.0
    features.append(is_pe)
    
    # 9. 文件大小对数
    features.append(math.log1p(size) / 20.0)
    
    # 10. 熵与可打印字符比
    features.append(entropy / 8.0)
    features.append(entropy * printable)
    
    # 11. 前/后半段特征差异
    half = size // 2
    if half > 0:
        first_half = data[:half]
        second_half = data[half:]
        
        first_hist = np.bincount(first_half, minlength=256).astype(np.float32)
        first_hist = first_hist / len(first_half)
        nonzero_first = first_hist[first_hist > 0]
        first_entropy = float(-np.sum(nonzero_first * np.log2(nonzero_first))) if len(nonzero_first) > 0 else 0.0
        
        second_hist = np.bincount(second_half, minlength=256).astype(np.float32)
        second_hist = second_hist / len(second_half)
        nonzero_second = second_hist[second_hist > 0]
        second_entropy = float(-np.sum(nonzero_second * np.log2(nonzero_second))) if len(nonzero_second) > 0 else 0.0
        
        features.append(abs(first_entropy - second_entropy))
    else:
        features.append(0.0)
    
    # 12. 二元组统计（摘要，20维）- 采样前10000个位置
    bigram_counts = np.zeros(256, dtype=np.float32)
    sample_size = min(size - 1, 10000)
    if sample_size > 0:
        indices = data[:sample_size]
        next_indices = data[1:sample_size+1]
        idx = ((indices.astype(np.uint16) + next_indices.astype(np.uint16)) % 256).astype(np.int64)
        np.add.at(bigram_counts, idx, 1)
    if bigram_counts.sum() > 0:
        bigram_counts = bigram_counts / bigram_counts.sum()
    features.extend(bigram_counts[:20].tolist())
    
    # 13. 填充区域特征（最大连续相同字节）
    max_same_run = 1
    if size > 1:
        diffs = np.diff(data)
        same_mask = (diffs == 0).astype(np.int32)
        if same_mask.any():
            diffs2 = np.diff(np.concatenate([[0], same_mask, [0]]))
            run_starts = np.where(diffs2 == 1)[0]
            run_ends = np.where(diffs2 == -1)[0]
            if len(run_starts) > 0:
                max_same_run = int(np.max(run_ends - run_starts)) + 1
    features.append(min(max_same_run / 1000.0, 1.0))
    
    # 14. 常见恶意字节模式
    xor_pattern = 0
    if size > 1:
        sample = data[:min(size, 10000)]
        xor_pattern = int(np.sum((sample[:-1] == 0xFF) & (sample[1:] == 0x00)) + 
                         np.sum((sample[:-1] == 0x00) & (sample[1:] == 0xFF)))
    features.append(min(xor_pattern / 1000.0, 1.0))
    
    # 15. 低熵/高熵区域比例
    low_entropy_blocks = sum(1 for be in block_entropies if be < 1.0)
    high_entropy_blocks = sum(1 for be in block_entropies if be > 7.0)
    features.append(low_entropy_blocks / 8.0)
    features.append(high_entropy_blocks / 8.0)
    
    # 16. 尾部NULL比例
    tail_size = min(1024, size)
    if tail_size > 0:
        tail_nulls = float(np.sum(data[-tail_size:] == 0)) / tail_size
    else:
        tail_nulls = 0.0
    features.append(tail_nulls)
    
    # 17. 头部结构特征
    features.append(1.0 if size > 4 and file_bytes[:4] == b'\x7fELF' else 0.0)
    features.append(1.0 if size > 4 and file_bytes[:4] in [b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe'] else 0.0)
    
    # 18. 字节范围分布
    low_bytes = float(np.sum(data < 0x20)) / size
    mid_bytes = float(np.sum((data >= 0x20) & (data <= 0x7f))) / size
    high_bytes = float(np.sum(data > 0x7f)) / size
    features.extend([low_bytes, mid_bytes, high_bytes])
    
    # 填充到100维
    while len(features) < 100:
        features.append(0.0)
    
    return np.array(features[:100], dtype=np.float32)


def extract_pe_features_from_bytes(file_bytes: bytes, original_size: int = 0) -> np.ndarray:
    """
    提取567维PE结构特征（复用LightGBM的特征工程逻辑）- 优化版
    
    使用numpy向量化计算，比Python循环快10-20倍
    """
    size = len(file_bytes)
    if size < 16:
        features = np.zeros(567, dtype=np.float32)
        features[282] = math.log10(original_size + 1) if original_size > 0 else 0.0
        return features
    
    data = np.frombuffer(file_bytes, dtype=np.uint8)
    total = float(size)
    
    # === 1. 字节频率 (256维) - np.bincount ===
    byte_counts = np.bincount(data, minlength=256).astype(np.float32)
    features = np.zeros(567, dtype=np.float32)
    features[:256] = byte_counts / total
    
    # === 2. 全局熵 (1维) ===
    nonzero = byte_counts[byte_counts > 0] / total
    features[256] = float(-np.sum(nonzero * np.log2(nonzero)))
    
    # === 3. 块级熵 (16维) ===
    block_size = 256
    num_blocks = min(16, size // block_size)
    if num_blocks == 0:
        features[257:273] = features[256]
    else:
        for i in range(num_blocks):
            start = i * block_size
            end = start + block_size if i < num_blocks - 1 else size
            block = data[start:end]
            bc = np.bincount(block, minlength=256).astype(np.float32)
            bc = bc / len(block)
            nz = bc[bc > 0]
            features[257 + i] = float(-np.sum(nz * np.log2(nz))) if len(nz) > 0 else 0.0
        if num_blocks < 16:
            features[257 + num_blocks:273] = features[257 + num_blocks - 1]
    
    # === 4-13. 各种比例特征 ===
    features[273] = float(np.sum((data >= 32) & (data <= 126))) / total
    features[274] = float(np.sum((data < 32) | (data == 127))) / total
    features[275] = float(np.sum((data == 9) | (data == 10) | (data == 13) | (data == 32))) / total
    features[276] = float(np.sum(((data >= 65) & (data <= 90)) | ((data >= 97) & (data <= 122)))) / total
    features[277] = float(np.sum((data >= 48) & (data <= 57))) / total
    features[278] = float(np.sum(data >= 128)) / total
    
    # 最大零连续
    z = (data == 0).astype(np.int32)
    dz = np.diff(np.concatenate([[0], z, [0]]))
    rs = np.where(dz == 1)[0]
    re = np.where(dz == -1)[0]
    features[279] = float(np.max(re - rs)) if len(rs) > 0 else 0.0
    
    features[280] = float(byte_counts[0] / total)
    features[281] = 1.0 if _is_pe_fast(data) else 0.0
    features[282] = math.log10(original_size + 1) if original_size > 0 else math.log10(total + 1)
    
    # === 14. 字节二元组哈希 (256维) ===
    if size > 1:
        prev = data[:-1]
        curr = data[1:]
        idx = ((prev.astype(np.uint16) * 31 + curr) & 0xFF).astype(np.int64)
        bigram_counts = np.bincount(idx, minlength=256).astype(np.float32)
    else:
        bigram_counts = np.zeros(256, dtype=np.float32)
    
    max_pairs = max(1, size - 1)
    features[283:539] = bigram_counts / max_pairs
    
    # === 15. 字节分布统计 (8维) ===
    sorted_counts = np.sort(byte_counts.copy())
    mean_freq = total / 256.0
    variance = np.sum((byte_counts - mean_freq) ** 2) / 256.0
    std_dev = math.sqrt(variance)
    features[539] = float(std_dev / (mean_freq + 1e-10))
    
    if std_dev > 1e-10:
        z_scores = (byte_counts - mean_freq) / std_dev
        features[540] = float(np.mean(z_scores ** 3))
        features[541] = float(np.mean(z_scores ** 4) - 3.0)
    
    features[542] = float(sorted_counts[255] / total)
    features[543] = float(np.sum(sorted_counts[251:256]) / total)
    features[544] = float(np.sum(sorted_counts[246:256]) / total)
    features[545] = float(np.sum(byte_counts > 0) / 256.0)
    
    # Gini
    weighted_sum = np.sum(np.arange(1, 257, dtype=np.float32) * sorted_counts)
    features[546] = float(abs((2.0 * weighted_sum - 257.0 * total) / (256.0 * total + 1e-10)))
    
    # === 16. 区域熵 (8维) ===
    region_size = max(1, size // 8)
    for r in range(8):
        start = r * region_size
        end = start + region_size if r < 7 else size
        if end > start:
            rc = np.bincount(data[start:end], minlength=256).astype(np.float32)
            rc = rc / (end - start)
            nz = rc[rc > 0]
            features[547 + r] = float(-np.sum(nz * np.log2(nz))) if len(nz) > 0 else 0.0
    
    # === 17. 结构特征 (12维) ===
    # 非零连续段
    nz = (data != 0).astype(np.int32)
    dnz = np.diff(np.concatenate([[0], nz, [0]]))
    rs_nz = np.where(dnz == 1)[0]
    re_nz = np.where(dnz == -1)[0]
    if len(rs_nz) > 0:
        runs = re_nz - rs_nz
        features[555] = float(np.mean(runs) / total)
        features[556] = float(np.max(runs) / total)
    else:
        features[555] = 0.0
        features[556] = 0.0
    
    # 前1024/后1024零比例
    first = data[:min(1024, size)]
    rest = data[1024:size] if size > 1024 else np.array([], dtype=np.uint8)
    features[557] = float(np.sum(first == 0) / len(first)) if len(first) > 0 else 0.0
    features[558] = float(np.sum(rest == 0) / len(rest)) if len(rest) > 0 else 0.0
    
    # 前后半熵差
    half = size // 2
    if half > 0 and size - half > 0:
        h1 = data[:half]
        h2 = data[half:]
        bc1 = np.bincount(h1, minlength=256).astype(np.float32) / len(h1)
        bc2 = np.bincount(h2, minlength=256).astype(np.float32) / len(h2)
        nz1 = bc1[bc1 > 0]
        nz2 = bc2[bc2 > 0]
        e1 = float(-np.sum(nz1 * np.log2(nz1))) if len(nz1) > 0 else 0.0
        e2 = float(-np.sum(nz2 * np.log2(nz2))) if len(nz2) > 0 else 0.0
        features[559] = abs(e1 - e2)
    
    # 块熵标准差
    be = features[257:273]
    be_mean = np.mean(be)
    features[560] = float(math.sqrt(np.sum((be - be_mean) ** 2) / 16))
    
    # 自相关 (lag-1)
    if size > 1:
        x = data[:-1].astype(np.float64)
        y = data[1:].astype(np.float64)
        n = len(x)
        sx, sy, sxy, sx2, sy2 = x.sum(), y.sum(), (x*y).sum(), (x*x).sum(), (y*y).sum()
        cn = n * sxy - sx * sy
        cd = math.sqrt((n * sx2 - sx * sx) * (n * sy2 - sy * sy))
        features[561] = float(cn / cd) if cd > 1e-10 else 0.0
    
    features[562] = float(byte_counts[255] / total)
    features[563] = float(np.sum(data >= 192) / total)
    features[564] = float(np.sum((data > 0) & (data < 32)) / total)
    features[565] = float(np.sum(data[:-1] == data[1:]) / max(1, size - 1))
    features[566] = float(np.sum(bigram_counts > 0) / 256.0)
    
    return features


def _is_pe_fast(data: np.ndarray) -> bool:
    """快速PE检测"""
    if len(data) < 64:
        return False
    if data[0] != ord('M') or data[1] != ord('Z'):
        return False
    try:
        pe_offset = int(data[60]) + (int(data[61]) << 8) + (int(data[62]) << 16) + (int(data[63]) << 24)
        if pe_offset < 0 or pe_offset + 4 > len(data):
            return False
        return data[pe_offset] == ord('P') and data[pe_offset + 1] == ord('E')
    except:
        return False
