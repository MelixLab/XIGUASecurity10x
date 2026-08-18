# HeySafe 本地 ML 模型调用器

给一个 PE（exe/dll/sys…）打分：输出**恶意概率**、**命中家族**和**最终判决**。
和 HeySafe 引擎内部用的是**同一份特征提取器 + 同一份树推理器**，所以对同一个文件、
同一个模型、同一个阈值，这里的结论和引擎里的完全一致（bit 级）。

- 纯 Rust，无 C/C++ 依赖，不连网、不落盘、不需要管理员权限。
- 模型加载后只读，推理可多线程并行；批量扫目录直接吃满多核。
- 处理畸形 PE 不会崩（`catch_unwind` 兜底，单个坏文件只标记「跳过」）。

## 一、准备

装 Rust（一次性）：<https://rustup.rs> 。装完命令行能跑 `cargo --version` 即可。

## 二、编译

在本目录下：

```powershell
cargo build --release
```

产物：`target/release/model-cli.exe`（Linux/macOS 下是 `target/release/model-cli`）。

也可以直接双击/运行 `build.ps1`（Windows），编完会把 exe 拷到本目录根下。

## 三、用法

```
model-cli <模型文件> <PE文件或目录> [更多路径...] [选项]
```

模型文件用随附的 `model/heysafe_local_model.trees.bin.xz` 即可（工具会自动识别 xz 并解压；
也支持明文 `.trees.bin`）。

例子：

```powershell
# 单个文件
.\target\release\model-cli.exe model\heysafe_local_model.trees.bin.xz C:\path\to\sample.exe

# 扫整个目录（递归，自动只挑 PE 扩展名）
.\target\release\model-cli.exe model\heysafe_local_model.trees.bin.xz C:\Windows\System32

# 只打印判为恶意的，机器可读 JSON，8 线程，自定义阈值
.\target\release\model-cli.exe model\...bin.xz C:\samples --quiet --json --jobs 8 --threshold 0.85
```

### 选项

| 选项 | 说明 |
|---|---|
| `--threshold <f>` | 恶意判定阈值，默认 **0.8488**。恶意概率 ≥ 阈值即判恶意 |
| `--jobs <n>` | 并行线程数，默认 = CPU 逻辑核心数 |
| `--json` | 每个文件输出一行 JSON |
| `--classes a,b,..` | 自定义类别名（默认按 HeySafe 10 类模型） |
| `--quiet` | 只打印判为恶意的文件 |

### 输出

人读格式：

```
[安全] p=0.0028 Benign           C:\...\OneDrive.Sync.Service.exe
[恶意] p=0.9931 Ransom           C:\samples\evil.exe
```

JSON 格式（`--json`）：

```json
{"path":"C:\\samples\\evil.exe","malicious":true,"probability":0.993100,"family":"Ransom","threshold":0.8488}
```

## 四、判决口径（重要）

- **恶意概率 = 1 − P(良性)**。模型是 10 类：class 0 是良性，1~9 是恶意家族
  （Ransom / Backdoor.RAT / Stealer / Loader / Miner / Worm / Spyware / HackTool / Trojan.Generic）。
- 判恶意时的「家族」取 1~9 类里概率最高的那个。
- **默认阈值 0.8488** 是这个模型在验证集 **假阳率 0.1%** 档校准出来的（对应检出率约 91.8%）。
  选这么严是「宁可漏报不可误报」的取向——中低分样本应交给签名库/云端/行为分析兜底，
  不靠单个 ML 分数就定罪。
- **换模型必须换阈值**：阈值是针对某个模型的验证集算的，换了模型直接沿用旧阈值没有意义。

## 五、模型文件格式（`HSTREE01`）

`.trees.bin` 是从 LightGBM 多分类模型抽出来的紧凑树集成二进制（小端）：

```
magic:          [u8;8] = "HSTREE01"
n_features:     u32          (= 2568，必须与特征提取器一致)
n_classes:      u32          (= 10)
post_transform: u32          (0=NONE, 1=SOFTMAX)
n_classlabels:  u32 ; classlabels: [i64; n]
n_trees:        u32
n_nodes:        u32
tree_offsets:   [u32; n_trees]
nodes:          n_nodes × { feature_id:i32(-1=叶子), threshold:f32,
                            true_child:i32, false_child:i32,
                            leaf_base:i32, leaf_count:i32 }
n_leafvals:     u32 ; leaf_vals: n × { class_id:i32, weight:f32 }
```

推理就是：逐树遍历（`feature <= threshold` 走 true 分支）→ 累加叶子权重到对应类 →
softmax → argmax 取家族、`1 - P(良性)` 取恶意概率。全部在 `src/tree.rs`，几十行、可读。

特征提取（`src/features.rs`）是 EMBER2024 v3 的 2568 维实现（字节直方图 / 熵直方图 /
字符串特征 / PE 头 / 节表 / 导入导出 / 数据目录 / Rich 头 / 签名 / 格式告警）。

## 六、性能

- 单文件（含特征提取）约 **200~300ms**（1MB 级 PE）。模型加载是一次性的（明文 ~130ms，
  xz 版含解压 ~1.1s）。
- 批量扫描按 `--jobs` 并行，实测多核下几十~上百文件/秒（取决于文件大小和磁盘）。
- 想更快：用明文 `.trees.bin`（省解压）、`--jobs` 拉到核心数、SSD。

## 七、文件清单

```
Cargo.toml           依赖与 release 性能档
build.ps1            一键编译脚本（Windows）
src/main.rs          命令行入口（参数/并行/输出）
src/tree.rs          树集成加载 + 推理（HSTREE01）
src/features.rs      EMBER2024 v3 特征提取（2568 维）
model/
  heysafe_local_model.trees.bin.xz    模型（xz 压缩，工具自动解压）
  heysafe_local_model_meta.json       模型元信息（类别名/各档阈值/训练信息）
```
