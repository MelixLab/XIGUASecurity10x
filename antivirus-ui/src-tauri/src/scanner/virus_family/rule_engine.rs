/// 规则引擎模块 - 从单一外部 JSON 文件加载病毒家族检测规则
/// 支持 behavior_categories、signatures 两种规则

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use super::types::{VirusFamily, string_to_family};

// ============================================================
// 规则数据结构
// ============================================================

/// 行为分类定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorCategory {
    pub name: String,
    #[serde(default)]
    pub high: Vec<String>,
    #[serde(default)]
    pub medium: Vec<String>,
}

/// 特征签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub name: String,
    pub malware_type: String,
    pub family: String,
    #[serde(default)]
    pub behavior_req: HashMap<String, usize>,
    #[serde(default)]
    pub unique_strings: Vec<String>,
    pub packer: Option<String>,
    pub compiler: Option<String>,
}

/// 规则文件顶层结构 (单一文件)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    pub version: String,
    #[serde(default)]
    pub behavior_categories: Vec<BehaviorCategory>,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

// ============================================================
// RuleEngine
// ============================================================

pub struct RuleEngine {
    pub behavior_categories: Vec<BehaviorCategory>,
    pub signatures: Vec<Signature>,
    pub source_path: Option<String>,
}

impl RuleEngine {
    /// 从单个 JSON 文件加载规则
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("无法加载规则文件 {}: {}", path, e))?;
        let file: RuleFile = serde_json::from_str(&content)
            .map_err(|e| format!("解析规则文件失败: {}", e))?;

        Ok(RuleEngine {
            behavior_categories: file.behavior_categories,
            signatures: file.signatures,
            source_path: Some(path.to_string()),
        })
    }

    /// 从 JSON 字符串字面量加载规则（用于嵌入式默认规则）
    pub fn load_from_json_str(json_str: &str) -> Result<Self, String> {
        let file: RuleFile = serde_json::from_str(json_str)
            .map_err(|e| format!("解析嵌入式默认规则失败: {}", e))?;

        Ok(RuleEngine {
            behavior_categories: file.behavior_categories,
            signatures: file.signatures,
            source_path: None,
        })
    }

    /// 对指定签名进行评分
    pub fn score_signature(
        &self,
        sig: &Signature,
        behavior_counts: &HashMap<&str, usize>,
        strings: &HashSet<String>,
        packer: Option<&str>,
        compiler: Option<&str>,
    ) -> (f32, Vec<String>) {
        let mut score = 0.0f32;
        let mut max_score = 0.0f32;
        let mut behavior_score = 0.0f32;
        let mut behavior_max = 0.0f32;
        let mut matched = Vec::new();

        // 1. 行为匹配（每个类别2分）
        for (cat, min_needed) in &sig.behavior_req {
            behavior_max += 2.0;
            max_score += 2.0;
            let actual = behavior_counts.get(cat.as_str()).copied().unwrap_or(0);
            let ratio = (actual as f32 / *min_needed as f32).min(1.0);
            if ratio >= 1.0 {
                score += 2.0;
                behavior_score += 2.0;
                matched.push(format!("行为: {} ({}/{})", cat, actual, min_needed));
            } else if ratio > 0.0 {
                score += ratio * 2.0;
                behavior_score += ratio * 2.0;
                matched.push(format!("部分行为: {} ({}/{})", cat, actual, min_needed));
            }
        }

        // 硬门槛：有行为要求的签名，行为匹配度必须 >= 50%
        if !sig.behavior_req.is_empty() && behavior_max > 0.0 {
            let behavior_ratio = behavior_score / behavior_max;
            if behavior_ratio < 0.5 {
                return (0.0, vec![format!("行为匹配不足 ({:.0}% < 50%)", behavior_ratio * 100.0)]);
            }
        }

        // 2. 唯一字符串匹配（每个3分）— strings 已是小写
        for us in &sig.unique_strings {
            max_score += 3.0;
            let us_lower = us.to_lowercase();
            if strings.iter().any(|s| s.contains(&us_lower)) {
                score += 3.0;
                matched.push(format!("字符串: {}", us));
            }
        }

        // 3. 加壳工具匹配（1分）
        if let Some(sig_packer) = &sig.packer {
            max_score += 1.0;
            if let Some(p) = packer {
                if p == sig_packer {
                    score += 1.0;
                    matched.push(format!("加壳: {}", p));
                }
            }
        }

        // 4. 编译器匹配（0.5分）
        if sig.compiler.is_some() {
            max_score += 0.5;
            if let Some(c) = compiler {
                if let Some(sig_comp) = &sig.compiler {
                    if c == sig_comp {
                        score += 0.5;
                        matched.push(format!("编译器: {}", c));
                    }
                }
            }
        }

        max_score = max_score.max(1.0);
        let confidence = score / max_score;

        (confidence, matched)
    }

    /// 签名匹配 - 返回 (family, base_name, score_percent, details)
    pub fn match_signatures(
        &self,
        behavior_counts: &HashMap<&str, usize>,
        strings: &HashSet<String>,
        packer: Option<&str>,
        compiler: Option<&str>,
    ) -> (VirusFamily, String, f32, Vec<String>) {
        // 预计算小写字符串集合（避免每条签名重复 to_lowercase）
        let strings_lower: HashSet<String> = strings.iter().map(|s| s.to_lowercase()).collect();

        let mut best_family = VirusFamily::Generic;
        let mut best_name = "HEUR:Trojan/Agent".to_string();
        let mut best_confidence = 0.0f32;
        let mut best_details = vec!["未匹配到特征".to_string()];

        for sig in &self.signatures {
            let (confidence, matched) = self.score_signature(sig, behavior_counts, &strings_lower, packer, compiler);
            if confidence > best_confidence {
                best_confidence = confidence;
                best_family = string_to_family(&sig.family);
                best_name = sig.name.clone();
                best_details = matched;
            }
        }

        // 阈值 >= 0.35（与Python脚本一致）
        if best_confidence >= 0.35 {
            (best_family, best_name, best_confidence * 100.0, best_details)
        } else {
            (VirusFamily::Generic, "HEUR:Trojan/Agent".to_string(), best_confidence * 100.0, best_details)
        }
    }

    /// 检查规则引擎中是否存在指定家族的签名
    pub fn has_signature_for_family(&self, family_name: &str) -> bool {
        self.signatures.iter().any(|s| s.family == family_name)
    }

    /// 获取已加载规则的完整数据（用于 Tauri 命令展示）
    pub fn get_loaded_rules_info(&self) -> serde_json::Value {
        serde_json::json!({
            "source_path": self.source_path,
            "signatures": self.signatures.iter().map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "malware_type": s.malware_type,
                    "family": s.family,
                    "behavior_req": s.behavior_req,
                    "unique_strings": s.unique_strings,
                    "packer": s.packer,
                    "compiler": s.compiler,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

// ============================================================
// 全局规则引擎实例
// ============================================================

static RULE_ENGINE: Mutex<Option<&'static RuleEngine>> = Mutex::new(None);

/// 获取规则引擎实例（懒加载）
pub fn get_engine() -> &'static RuleEngine {
    let mut guard = RULE_ENGINE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(Box::leak(Box::new(load_engine())));
    }
    guard.unwrap()
}

/// 重新加载规则引擎（从外部文件重新读取）
pub fn reload_engine() -> Result<(), String> {
    let mut guard = RULE_ENGINE.lock().map_err(|e| e.to_string())?;
    *guard = Some(Box::leak(Box::new(load_engine())));
    Ok(())
}

fn load_engine() -> RuleEngine {
    // 候选路径列表
    let mut candidates: Vec<String> = Vec::new();

    // 从 exe 所在目录向上查找 rulers 目录（适配开发/发布/自定义目录等场景）
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                // 先试 exe 同级
                candidates.push(exe_dir.join("rulers").join("virus_family_rules.json").to_string_lossy().to_string());
                // 再向上逐级查找（最多 10 层，适配各种部署结构）
                let mut dir = Some(exe_dir);
                for _ in 0..10 {
                    dir = dir.and_then(|d| d.parent());
                    if let Some(d) = dir {
                        let candidate = d.join("rulers").join("virus_family_rules.json");
                        if candidate.exists() {
                            candidates.push(candidate.to_string_lossy().to_string());
                            break;
                        }
                    }
                }
            }
        }

        // 尝试从候选路径加载
        for path in &candidates {
            if !path.is_empty() && std::path::Path::new(path).exists() {
                match RuleEngine::load_from_file(path) {
                    Ok(engine) => {
                        println!("[RuleEngine] - 规则文件加载成功 from: {}", path);
                        return engine;
                    }
                    Err(e) => {
                        eprintln!("[RuleEngine] - 从 {} 加载规则失败: {}", path, e);
                    }
                }
            }
        }

        // 尝试从 _up_ 的 rulers 子目录加载（Tauri 资源打包结构）
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                for entry in std::fs::read_dir(exe_dir).ok().into_iter().flatten() {
                    if let Ok(entry) = entry {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("_up_") {
                            let rules_path = entry.path().join("rulers").join("virus_family_rules.json");
                            if rules_path.exists() {
                                match RuleEngine::load_from_file(&rules_path.to_string_lossy()) {
                                    Ok(engine) => {
                                        println!("[RuleEngine] - 规则文件加载成功 from: {}", rules_path.display());
                                        return engine;
                                    }
                                    Err(e) => {
                                        eprintln!("[RuleEngine] - 从 {} 加载规则失败: {}", rules_path.display(), e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 无外部规则文件，返回空规则引擎
        eprintln!("[RuleEngine] - 未找到外部规则文件，使用空规则引擎");
        RuleEngine {
            behavior_categories: Vec::new(),
            signatures: Vec::new(),
            source_path: None,
        }
}

/// 获取已加载规则的信息（供 Tauri 命令调用）
pub fn get_loaded_rules_info() -> serde_json::Value {
    let engine = get_engine();
    engine.get_loaded_rules_info()
}
