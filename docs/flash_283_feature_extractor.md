# Flash 283维 PE 特征工程参考文档

## 概述

本文档提供 Melix-Flash 模式的 **283 维特征提取** 完整参考实现。特征向量专为轻量 PE 恶意软件检测模型设计，仅使用字节统计和基本结构信息，无需完整 PE 解析。

## 特征维度总表

| 索引范围 | 特征组 | 维数 | 说明 |
|----------|--------|------|------|
| 0-255 | 字节频率直方图 | 256 | 每个字节值 (0x00-0xFF) 出现次数占总字节数的比例 |
| 256 | 全局熵 | 1 | 字节分布的香农熵 |
| 257-272 | 区块熵 | 16 | 将文件分成 16 块，每块分别计算熵 |
| 273 | 可打印字符比例 | 1 | 0x20-0x7E 范围字节占比 |
| 274 | 控制字符比例 | 1 | < 0x20 或 == 0x7F 的字节占比 |
| 275 | 空白字符比例 | 1 | 空格、\t(9)、\n(10)、\r(13) 占比 |
| 276 | 字母比例 | 1 | ASCII 字母 (A-Z a-z) 占比 |
| 277 | 数字比例 | 1 | ASCII 数字 (0-9) 占比 |
| 278 | 高位字节比例 | 1 | >= 0x80 字节占比 |
| 279 | 最长连续零段 | 1 | 最大连续 0x00 字节长度 |
| 280 | 零字节占比 | 1 | 0x00 字节出现比例 |
| 281 | 是否为 PE | 1 | 0 或 1（检查 MZ + PE 头） |
| 282 | log10(文件大小) | 1 | log10(file_size + 1) |

---

## Rust 完整实现（可直接调用）

```rust
use std::fs;
use std::io::Read;

/// 特征维度常量
pub const NDIM: usize = 283;

/// 提取 283 维特征向量
///
/// # 参数
/// * `data` - 文件完整字节内容
///
/// # 返回
/// * `None` - 文件太小 (< 16 字节)
/// * `Some(Vec<f32>)` - 283 维特征向量
pub fn extract(bytes: &[u8]) -> Option<Vec<f32>> {
    const MIN_SIZE: usize = 16;
    if bytes.len() < MIN_SIZE {
        return None;
    }

    let total = bytes.len();
    let total_f = total as f64;
    let mut f = vec![0.0f32; NDIM];

    // ── 单次遍历统计 ──
    let mut byte_counts = [0i64; 256];
    let mut printable = 0i64;
    let mut control = 0i64;
    let mut whitespace = 0i64;
    let mut letter = 0i64;
    let mut digit = 0i64;
    let mut high_byte = 0i64;
    let mut max_zero_run = 0u32;
    let mut cur_zero_run = 0u32;

    for &b in bytes {
        byte_counts[b as usize] += 1;

        // 可打印 ASCII
        if b >= 0x20 && b <= 0x7E {
            printable += 1;
            if b.is_ascii_alphabetic() { letter += 1; }
            else if b.is_ascii_digit() { digit += 1; }
        } else if b < 0x20 || b == 0x7F {
            control += 1;
        }

        // 空白字符
        if b == 9 || b == 10 || b == 13 || b == 32 {
            whitespace += 1;
        }

        // 高位字节
        if b >= 0x80 {
            high_byte += 1;
        }

        // 连续零监测
        if b == 0 {
            cur_zero_run += 1;
            if cur_zero_run > max_zero_run {
                max_zero_run = cur_zero_run;
            }
        } else {
            cur_zero_run = 0;
        }
    }

    // ── 1. 字节频率直方图 (0-255) ──
    for i in 0..256 {
        f[i] = (byte_counts[i] as f64 / total_f) as f32;
    }

    // ── 2. 全局熵 (256) ──
    f[256] = entropy(&byte_counts, total_f);

    // ── 3. 区块熵 (257-272) ──
    block_entropies(bytes, &mut f);

    // ── 4-11. 统计特征 (273-282) ──
    f[273] = (printable as f64 / total_f) as f32;
    f[274] = (control as f64 / total_f) as f32;
    f[275] = (whitespace as f64 / total_f) as f32;
    f[276] = (letter as f64 / total_f) as f32;
    f[277] = (digit as f64 / total_f) as f32;
    f[278] = (high_byte as f64 / total_f) as f32;
    f[279] = max_zero_run as f32;
    f[280] = (byte_counts[0] as f64 / total_f) as f32;
    f[281] = if is_pe(bytes) { 1.0 } else { 0.0 };
    f[282] = ((total + 1) as f64).log10() as f32;

    Some(f)
}

/// 香农熵计算
fn entropy(counts: &[i64; 256], total: f64) -> f32 {
    if total <= 0.0 {
        return 0.0;
    }
    let mut h = 0.0f64;
    for &c in counts {
        if c > 0 {
            let p = c as f64 / total;
            h -= p * p.log2();
        }
    }
    h as f32
}

/// 区块熵：将文件分成 16 块，每块 256 字节
fn block_entropies(bytes: &[u8], f: &mut [f32]) {
    const BLOCK: usize = 256;
    let n_blocks = (bytes.len() / BLOCK).min(16);

    if n_blocks == 0 {
        // 极小文件：直接用全局熵填充全部 16 个槽
        let mut counts = [0i64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let e = entropy(&counts, bytes.len() as f64);
        for i in 0..16 {
            f[257 + i] = e;
        }
        return;
    }

    for bi in 0..n_blocks {
        let start = bi * BLOCK;
        let len = BLOCK.min(bytes.len() - start);
        let mut counts = [0i64; 256];
        for j in 0..len {
            counts[bytes[start + j] as usize] += 1;
        }
        f[257 + bi] = entropy(&counts, len as f64);
    }

    // 不足 16 块时用最后一个值填充
    if n_blocks < 16 {
        let last = f[257 + n_blocks - 1];
        for i in n_blocks..16 {
            f[257 + i] = last;
        }
    }
}

/// 检查文件是否为 PE（MZ + PE 头）
fn is_pe(data: &[u8]) -> bool {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_off + 4 > data.len() {
        return false;
    }
    data[pe_off] == b'P' && data[pe_off + 1] == b'E'
}
```

---

## Python 参考实现

```python
import math
import struct

NDIM = 283

def extract(bytes_data: bytes):
    """提取 283 维特征向量"""
    if len(bytes_data) < 16:
        return None
    
    total = len(bytes_data)
    total_f = float(total)
    f = [0.0] * NDIM
    
    # ── 单次遍历统计 ──
    byte_counts = [0] * 256
    printable = 0
    control = 0
    whitespace = 0
    letter = 0
    digit = 0
    high_byte = 0
    max_zero_run = 0
    cur_zero_run = 0
    
    for b in bytes_data:
        byte_counts[b] += 1
        
        if 0x20 <= b <= 0x7E:
            printable += 1
            if chr(b).isalpha():
                letter += 1
            elif chr(b).isdigit():
                digit += 1
        elif b < 0x20 or b == 0x7F:
            control += 1
        
        if b in (9, 10, 13, 32):
            whitespace += 1
        
        if b >= 0x80:
            high_byte += 1
        
        if b == 0:
            cur_zero_run += 1
            max_zero_run = max(max_zero_run, cur_zero_run)
        else:
            cur_zero_run = 0
    
    # 1. 字节频率直方图 (0-255)
    for i in range(256):
        f[i] = byte_counts[i] / total_f
    
    # 2. 全局熵 (256)
    f[256] = _entropy(byte_counts, total_f)
    
    # 3. 区块熵 (257-272)
    _block_entropies(bytes_data, f)
    
    # 4-11. 统计特征 (273-282)
    f[273] = printable / total_f
    f[274] = control / total_f
    f[275] = whitespace / total_f
    f[276] = letter / total_f
    f[277] = digit / total_f
    f[278] = high_byte / total_f
    f[279] = float(max_zero_run)
    f[280] = byte_counts[0] / total_f
    f[281] = 1.0 if _is_pe(bytes_data) else 0.0
    f[282] = math.log10(total + 1)
    
    return f


def _entropy(counts, total):
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def _block_entropies(data, f):
    block = 256
    n_blocks = min(len(data) // block, 16)
    
    if n_blocks == 0:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        e = _entropy(counts, len(data))
        for i in range(16):
            f[257 + i] = e
        return
    
    for bi in range(n_blocks):
        start = bi * block
        length = min(block, len(data) - start)
        counts = [0] * 256
        for j in range(length):
            counts[data[start + j]] += 1
        f[257 + bi] = _entropy(counts, float(length))
    
    if n_blocks < 16:
        last = f[257 + n_blocks - 1]
        for i in range(n_blocks, 16):
            f[257 + i] = last


def _is_pe(data):
    if len(data) < 64 or data[0] != 0x4D or data[1] != 0x5A:
        return False
    pe_off = struct.unpack_from('<I', data, 60)[0]
    if pe_off + 4 > len(data):
        return False
    return data[pe_off] == 0x50 and data[pe_off + 1] == 0x45
```

---

## 使用示例

### Rust 调用方式

```rust
let data = std::fs::read("sample.exe").expect("读取文件失败");
if let Some(features) = flash_283::extract(&data) {
    assert_eq!(features.len(), 283);
    // features 可直接传给模型推理
}
```

### Python 调用方式

```python
with open("sample.exe", "rb") as f:
    data = f.read()
features = extract(data)
if features is not None:
    assert len(features) == 283
    # features 可直接传给模型推理
```

---

## 特征与 2568 维 EMBER V3 的差异

| 方面 | Flash 283 维 | EMBER V3 (2568 维) |
|------|-------------|-------------------|
| PE 解析 | 仅检查 MZ+PE 头 (2 次内存访问) | 完整 PE 解析 (goblin/pefile) |
| 字符串分析 | 无 | 正则匹配 77 种模式 |
| 导入/导出表 | 无 | 完整导入/导出特征 (1411 维) |
| 节区分析 | 无 | 224 维节区特征 |
| Rich Header | 无 | 33 维 Rich Header 特征 |
| 数字签名 | 无 | 8 维签名特征 |
| 计算开销 | ~O(n) 单次遍历 | ~O(n) + PE 解析 + 正则匹配 |
| 适用场景 | 快速预筛、低误报模式 | 全量深度检测 |
