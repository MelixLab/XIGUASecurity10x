//! Pure-Rust LightGBM / ONNX `TreeEnsembleClassifier` evaluator.
//!
//! 替换 ONNX Runtime（`ort`，C++ FFI）做本地 AI 推理。动机：
//!   * `ort` 是 RC 不稳定版，重负载下会 `0xc0000374` 堆损坏（原先靠子进程隔离）。
//!   * 树模型推理本身只是「遍历树 + 累加叶子分 + softmax」，纯 Rust 几十行即可，
//!     无 C++、无子进程、无全局锁 —— 加载后只读，可在任意扫描线程并行调用。
//!
//! 模型来自构建期把 `heysafe_local_model.onnx` 里的 `TreeEnsembleClassifier`
//! 抽成的紧凑二进制 `heysafe_local_model.trees.bin`（见 `tools/convert_trees.py`）。
//! 该转换脚本已用 onnxruntime 做过 200 组随机输入的 bit 级对拍
//! （max_prob_err ≈ 1.6e-7，label 0 失配），所以本评估器与原 ONNX 输出一致。
//!
//! 二进制格式（小端，magic = b"HSTREE01"）：
//! ```text
//!   magic:          [u8; 8] = b"HSTREE01"
//!   n_features:     u32
//!   n_classes:      u32
//!   post_transform: u32            (0 = NONE, 1 = SOFTMAX)
//!   n_classlabels:  u32 ; classlabels: [i64; n_classlabels]
//!   n_trees:        u32
//!   n_nodes:        u32
//!   tree_offsets:   [u32; n_trees]   每棵树根节点在 nodes 中的绝对下标
//!   nodes:          n_nodes * {
//!       feature_id:  i32   (-1 表示叶子)
//!       threshold:   f32
//!       true_child:  i32   (绝对下标; 叶子为 -1)
//!       false_child: i32   (绝对下标; 叶子为 -1)
//!       leaf_base:   i32   (叶子权重在 leaf_vals 中的起始下标; 内部节点 -1)
//!       leaf_count:  i32   (该叶子的 (class,weight) 对数; 内部节点 0)
//!   }
//!   n_leafvals:     u32 ; leaf_vals: n_leafvals * { class_id: i32, weight: f32 }
//! ```
//!
//! ## 常驻内存布局（加载时转换，不改文件格式 / 不改安装包）
//!
//! 文件里的节点是 24 字节，全部读进来会占 ~100MB 常驻。加载时转成 12 字节紧凑节点：
//!   * `feature_id` 与左右子下标压成 `u16`（特征只有 2568 维；子下标改成「树内相对
//!     下标」，LightGBM 单树节点数只有几百，实测最大 509）；
//!   * 叶子权重直接内联进节点的 `f32` 字段，`leaf_vals` 扁平表整个消掉；
//!   * `class_id` 提到树级（LightGBM 多分类每棵树只贡献一个类，逐叶存 class 是浪费）。
//!
//! 这三条都是当前模型（LightGBM 多分类导出）的结构性事实，加载时逐一校验；任何一条
//! 不满足就返回 Err、拒绝加载（上层 fail-open，交签名/云端兜底）并在日志写明原因。
//! 将来若换成不满足假设的模型结构，请同步调整这里或转换脚本。
//!
//! 效果：~102MB → ~44MB 常驻；节点尺寸减半 + 树内切片顺序访问，缓存命中率更高，
//! 推理只快不慢。评估顺序（逐树、每叶单 (class,weight)、f64 累加）与原实现完全一致
//! → 输出 bit 级一致。

use std::path::Path;

const MAGIC: &[u8; 8] = b"HSTREE01";
const NODE_BYTES: usize = 24; // 文件内：i32 + f32 + i32*4
const LEAF_BYTES: usize = 8; // 文件内：i32 + f32

/// 紧凑节点里「这是叶子」的标记（真实特征号远小于 u16::MAX）。
const LEAF_MARKER: u16 = u16::MAX;

/// 常驻紧凑节点：12 字节。
///   * 内部节点：`thr_or_weight` = 分裂阈值，`true_child`/`false_child` = 树内相对下标；
///   * 叶子节点：`feature_id == LEAF_MARKER`，`thr_or_weight` = 该叶子权重，子下标未用。
#[derive(Clone, Copy)]
struct Node {
    thr_or_weight: f32,
    feature_id: u16,
    true_child: u16,
    false_child: u16,
}

/// 树级元数据：根节点在 `nodes` 中的绝对起点、节点数、该树贡献的类别。
#[derive(Clone, Copy)]
struct TreeMeta {
    first_node: u32,
    n_nodes: u16,
    class_id: u16,
}

pub struct TreeEnsemble {
    pub n_features: usize,
    pub n_classes: usize,
    softmax: bool,
    classlabels: Vec<i64>,
    /// 良性类（label == 0）在 classlabels 中的列下标；找不到时退回 0。
    benign_index: usize,
    trees: Vec<TreeMeta>,
    nodes: Vec<Node>,
}

/// 一次推理的完整输出，复刻原 ONNX 模型的两个输出张量。
pub struct TreeOutput {
    /// 预测类标签 = classlabels[argmax(probabilities)]。0 = 良性，1..9 = 恶意家族。
    pub label: i64,
    /// 全部类别的概率（softmax 后），长度 = n_classes。
    pub probabilities: Vec<f32>,
    /// 恶意概率 = 1 - P(良性)，clamp 到 [0,1]。与原 `extract_probability` 一致。
    pub malicious_prob: f32,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "模型数据越界: 需要 {} 字节 @ {}，总长 {}",
                n,
                self.pos,
                self.buf.len()
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn rd_i32(s: &[u8]) -> i32 {
    i32::from_le_bytes([s[0], s[1], s[2], s[3]])
}
fn rd_f32(s: &[u8]) -> f32 {
    f32::from_le_bytes([s[0], s[1], s[2], s[3]])
}
fn rd_i64(s: &[u8]) -> i64 {
    i64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
}

impl TreeEnsemble {
    pub fn load_from_file(path: &Path) -> Result<TreeEnsemble, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("读取模型失败: {}", e))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<TreeEnsemble, String> {
        let mut c = Cursor::new(bytes);
        let magic = c.take(8)?;
        if magic != MAGIC {
            return Err("模型 magic 不匹配（非 HSTREE01）".to_string());
        }
        let n_features = c.u32()? as usize;
        let n_classes = c.u32()? as usize;
        let post = c.u32()?;
        let softmax = post == 1;

        if n_features == 0 || n_features >= LEAF_MARKER as usize {
            return Err(format!("特征维数异常: {}", n_features));
        }
        if n_classes == 0 || n_classes > u16::MAX as usize {
            return Err(format!("类别数异常: {}", n_classes));
        }

        let n_classlabels = c.u32()? as usize;
        let mut classlabels = Vec::with_capacity(n_classlabels);
        {
            let raw = c.take(n_classlabels * 8)?;
            for i in 0..n_classlabels {
                classlabels.push(rd_i64(&raw[i * 8..]));
            }
        }
        if n_classlabels != n_classes {
            return Err(format!(
                "classlabels 数 {} 与类别数 {} 不一致",
                n_classlabels, n_classes
            ));
        }
        let benign_index = classlabels.iter().position(|&l| l == 0).unwrap_or(0);

        let n_trees = c.u32()? as usize;
        let n_nodes = c.u32()? as usize;
        if n_trees == 0 || n_nodes == 0 {
            return Err("模型无树/无节点".to_string());
        }

        let mut tree_offsets = Vec::with_capacity(n_trees);
        {
            let raw = c.take(n_trees * 4)?;
            for i in 0..n_trees {
                let s = &raw[i * 4..];
                tree_offsets.push(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize);
            }
        }
        for w in tree_offsets.windows(2) {
            if w[1] < w[0] {
                return Err("tree_offsets 非递增".to_string());
            }
        }
        if tree_offsets[0] != 0 {
            return Err("首棵树 offset 应为 0".to_string());
        }
        if *tree_offsets.last().unwrap() >= n_nodes {
            return Err("tree_offset 越界".to_string());
        }

        let raw_nodes = c.take(n_nodes * NODE_BYTES)?;

        let n_leafvals = c.u32()? as usize;
        let raw_leaves = c.take(n_leafvals * LEAF_BYTES)?;

        // 直接从原始字节构建紧凑布局，不先建 24 字节中间结构（省一份 ~100MB 峰值）。
        let mut nodes: Vec<Node> = Vec::with_capacity(n_nodes);
        let mut trees: Vec<TreeMeta> = Vec::with_capacity(n_trees);

        for t in 0..n_trees {
            let start = tree_offsets[t];
            let end = if t + 1 < n_trees {
                tree_offsets[t + 1]
            } else {
                n_nodes
            };
            if end <= start {
                return Err(format!("第 {} 棵树为空", t));
            }
            let size = end - start;
            if size > u16::MAX as usize {
                return Err(format!("第 {} 棵树节点数 {} 超出紧凑格式上限", t, size));
            }

            let mut tree_class: Option<u16> = None;
            for i in start..end {
                let s = &raw_nodes[i * NODE_BYTES..];
                let feature_id = rd_i32(&s[0..]);
                let threshold = rd_f32(&s[4..]);
                let true_child = rd_i32(&s[8..]);
                let false_child = rd_i32(&s[12..]);
                let leaf_base = rd_i32(&s[16..]);
                let leaf_count = rd_i32(&s[20..]);

                if feature_id < 0 {
                    // 叶子
                    if leaf_count != 1 || leaf_base < 0 {
                        return Err(format!(
                            "叶子权重数 {} != 1（节点 {}），紧凑格式不支持该模型结构",
                            leaf_count, i
                        ));
                    }
                    let lb = leaf_base as usize;
                    if lb >= n_leafvals {
                        return Err("叶子权重下标越界".to_string());
                    }
                    let ls = &raw_leaves[lb * LEAF_BYTES..];
                    let class_id = rd_i32(&ls[0..]);
                    let weight = rd_f32(&ls[4..]);
                    if class_id < 0 || class_id as usize >= n_classes {
                        return Err(format!("叶子 class_id 越界: {}", class_id));
                    }
                    let cid = class_id as u16;
                    match tree_class {
                        None => tree_class = Some(cid),
                        Some(prev) if prev != cid => {
                            return Err(format!(
                                "第 {} 棵树叶子类别不一致（{} vs {}），紧凑格式不支持",
                                t, prev, cid
                            ));
                        }
                        _ => {}
                    }
                    nodes.push(Node {
                        thr_or_weight: weight,
                        feature_id: LEAF_MARKER,
                        true_child: 0,
                        false_child: 0,
                    });
                } else {
                    if feature_id as usize >= n_features {
                        return Err(format!("特征号越界: {}", feature_id));
                    }
                    let tc = true_child as isize - start as isize;
                    let fc = false_child as isize - start as isize;
                    if tc < 0 || fc < 0 || tc as usize >= size || fc as usize >= size {
                        return Err(format!("内部节点子下标越界/跨树（节点 {}）", i));
                    }
                    nodes.push(Node {
                        thr_or_weight: threshold,
                        feature_id: feature_id as u16,
                        true_child: tc as u16,
                        false_child: fc as u16,
                    });
                }
            }

            trees.push(TreeMeta {
                first_node: start as u32,
                n_nodes: size as u16,
                class_id: tree_class.ok_or_else(|| format!("第 {} 棵树没有叶子", t))?,
            });
        }

        Ok(TreeEnsemble {
            n_features,
            n_classes,
            softmax,
            classlabels,
            benign_index,
            trees,
            nodes,
        })
    }

    pub fn n_features(&self) -> usize {
        self.n_features
    }
    pub fn n_classes(&self) -> usize {
        self.n_classes
    }
    pub fn n_trees(&self) -> usize {
        self.trees.len()
    }

    /// 对一条特征向量做推理。`&self` 只读 —— 可被多个扫描线程并行调用。
    pub fn evaluate(&self, features: &[f32]) -> TreeOutput {
        // f64 累加以贴近转换脚本的参考实现（与 onnxruntime 对拍通过）。
        let mut scores = vec![0.0_f64; self.n_classes];

        for t in &self.trees {
            let base = t.first_node as usize;
            let size = t.n_nodes as usize;
            let tree = &self.nodes[base..base + size];
            let mut idx = 0usize;
            let mut guard = 0usize;
            loop {
                let nd = &tree[idx];
                if nd.feature_id == LEAF_MARKER {
                    scores[t.class_id as usize] += nd.thr_or_weight as f64;
                    break;
                }
                let go_true = match features.get(nd.feature_id as usize) {
                    Some(&v) => v <= nd.thr_or_weight,
                    None => false,
                };
                idx = if go_true {
                    nd.true_child as usize
                } else {
                    nd.false_child as usize
                };
                guard += 1;
                if guard > size {
                    break;
                }
            }
        }

        let probabilities = if self.softmax {
            softmax(&scores)
        } else {
            scores.iter().map(|&s| s as f32).collect()
        };

        let mut best = 0usize;
        let mut best_v = f32::NEG_INFINITY;
        for (i, &p) in probabilities.iter().enumerate() {
            if p > best_v {
                best_v = p;
                best = i;
            }
        }
        let label = self.classlabels.get(best).copied().unwrap_or(best as i64);

        let benign_p = probabilities.get(self.benign_index).copied().unwrap_or(0.0);
        let malicious_prob = (1.0_f32 - benign_p).clamp(0.0, 1.0);

        TreeOutput {
            label,
            probabilities,
            malicious_prob,
        }
    }
}

fn softmax(scores: &[f64]) -> Vec<f32> {
    let mx = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let mut exps = Vec::with_capacity(scores.len());
    let mut sum = 0.0_f64;
    for &s in scores {
        let e = (s - mx).exp();
        exps.push(e);
        sum += e;
    }
    if sum <= 0.0 {
        return vec![0.0_f32; scores.len()];
    }
    exps.iter().map(|&e| (e / sum) as f32).collect()
}
