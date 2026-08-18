/// 病毒家族分析模块 v3.0 - 火绒风格命名规范
/// 基于行为分类 + 特征签名库

pub mod types;
pub mod engine;
pub mod rule_engine;

pub use types::*;
pub use engine::analyze_family;

/// 获取病毒家族显示名称
pub fn get_family_display_name(family: &VirusFamily) -> String {
    family.to_string()
}

/// 获取家族描述
pub fn get_family_description(family: &VirusFamily) -> &'static str {
    family.description()
}
