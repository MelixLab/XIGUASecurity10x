/// 病毒家族类型定义 - 火绒风格命名规范

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VirusFamily {
    // 通用类别
    Generic,
    
    // 已知家族
    AgentTesla,
    AsyncRAT,
    DarkComet,
    DcRat,
    Emotet,
    Formbook,
    Gh0stRAT,
    KillDisk,
    Locky,
    NanoCoreRAT,
    Nimda,
    PoisonIvy,
    QuasarRAT,
    Ramnit,
    RaptorVirus,
    RedLine,
    RemcosRAT,
    RogueInstaller,
    SmileGhost,
    Spark,
    StoneCutter,
    SystemKiller,
    Terminator,
    Unfixable,
    VineMEMZ,
    WannaCry,
    Weidows,
    XMRig,
    XWorm,
    // PyInstaller 打包的勒索/恶意程序
    PyInstallerRansom,
    // 杀毒软件禁用工具（AV Kill）
    AVKill,
    // 银狐木马（SilverFox）- 针对中国用户的窃密/远控木马
    SilverFox,
}

impl VirusFamily {
    pub fn to_string(&self) -> String {
        match self {
            VirusFamily::Generic => "Trojan/Agent".to_string(),
            VirusFamily::AgentTesla => "Trojan/AgentTesla".to_string(),
            VirusFamily::AsyncRAT => "Trojan/AsyncRAT".to_string(),
            VirusFamily::DarkComet => "Trojan/DarkComet".to_string(),
            VirusFamily::DcRat => "Trojan/DcRat".to_string(),
            VirusFamily::Emotet => "Trojan/Emotet".to_string(),
            VirusFamily::Formbook => "Trojan/Formbook".to_string(),
            VirusFamily::Gh0stRAT => "Trojan/Gh0st".to_string(),
            VirusFamily::KillDisk => "Trojan/KillDisk".to_string(),
            VirusFamily::Locky => "Ransom/Locky".to_string(),
            VirusFamily::NanoCoreRAT => "Trojan/NanoCore".to_string(),
            VirusFamily::Nimda => "Worm/Nimda".to_string(),
            VirusFamily::PoisonIvy => "Trojan/PoisonIvy".to_string(),
            VirusFamily::QuasarRAT => "Trojan/Quasar".to_string(),
            VirusFamily::Ramnit => "Worm/Ramnit".to_string(),
            VirusFamily::RaptorVirus => "Trojan/RaptorVirus".to_string(),
            VirusFamily::RedLine => "Trojan/RedLine".to_string(),
            VirusFamily::RemcosRAT => "Trojan/REMCOS".to_string(),
            VirusFamily::RogueInstaller => "Trojan/RogueInstaller".to_string(),
            VirusFamily::SmileGhost => "Trojan/SmileGhost".to_string(),
            VirusFamily::Spark => "Trojan/Spark".to_string(),
            VirusFamily::StoneCutter => "Trojan/StoneCutter".to_string(),
            VirusFamily::SystemKiller => "Trojan/SystemKiller".to_string(),
            VirusFamily::Terminator => "Trojan/Terminator".to_string(),
            VirusFamily::Unfixable => "Trojan/Unfixable".to_string(),
            VirusFamily::VineMEMZ => "Trojan/VineMEMZ".to_string(),
            VirusFamily::WannaCry => "Ransom/WannaCry".to_string(),
            VirusFamily::Weidows => "Trojan/Weidows".to_string(),
            VirusFamily::XMRig => "Miner/XMRig".to_string(),
            VirusFamily::XWorm => "Trojan/XWorm".to_string(),
            VirusFamily::PyInstallerRansom => "PUA/PyInstallerRansom".to_string(),
            VirusFamily::AVKill => "Trojan/AVKill".to_string(),
            VirusFamily::SilverFox => "Trojan/SilverFox".to_string(),
        }
    }
    
    /// 返回火绒风格的中文分类标签（如"远程控制木马"、"勒索病毒"等）
    pub fn category_label(&self) -> &'static str {
        match self {
            // 远程控制木马 (RAT)
            VirusFamily::AsyncRAT | VirusFamily::DarkComet | VirusFamily::DcRat
            | VirusFamily::Gh0stRAT | VirusFamily::NanoCoreRAT | VirusFamily::PoisonIvy
            | VirusFamily::QuasarRAT | VirusFamily::RemcosRAT | VirusFamily::XWorm => "远程控制木马",

            // 窃密木马
            VirusFamily::AgentTesla | VirusFamily::Formbook | VirusFamily::RedLine
            | VirusFamily::Spark => "窃密木马",

            // 银行木马
            VirusFamily::Emotet => "银行木马",

            // 恶意安装程序
            VirusFamily::RogueInstaller => "恶意安装程序",

            // 恶意程序（多功能恶意软件）
            VirusFamily::SystemKiller | VirusFamily::Terminator => "恶意程序",

            // 勒索病毒
            VirusFamily::Locky | VirusFamily::WannaCry | VirusFamily::PyInstallerRansom => "勒索病毒",

            // 蠕虫病毒
            VirusFamily::Nimda | VirusFamily::Ramnit => "蠕虫病毒",

            // 挖矿程序
            VirusFamily::XMRig => "挖矿程序",

            // 破坏性病毒（MBR破坏、系统破坏等）
            VirusFamily::KillDisk | VirusFamily::RaptorVirus | VirusFamily::SmileGhost
            | VirusFamily::StoneCutter | VirusFamily::Unfixable | VirusFamily::VineMEMZ => "破坏性病毒",

            // 银狐木马
            VirusFamily::SilverFox => "银狐木马",

            // 其余归为木马病毒（如 Generic、Weidows 等常规木马）
            VirusFamily::AVKill => "木马病毒",
            _ => "木马病毒",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            VirusFamily::Generic => "通用木马代理",
            VirusFamily::AgentTesla => "信息窃取木马",
            VirusFamily::AsyncRAT => "远程控制木马",
            VirusFamily::DarkComet => "远程控制木马",
            VirusFamily::DcRat => "远程控制木马",
            VirusFamily::Emotet => "银行木马",
            VirusFamily::Formbook => "信息窃取木马",
            VirusFamily::Gh0stRAT => "远程控制木马",
            VirusFamily::KillDisk => "MBR破坏木马",
            VirusFamily::Locky => "勒索病毒",
            VirusFamily::NanoCoreRAT => "远程控制木马",
            VirusFamily::Nimda => "蠕虫病毒",
            VirusFamily::PoisonIvy => "远程控制木马",
            VirusFamily::QuasarRAT => "远程控制木马",
            VirusFamily::Ramnit => "蠕虫病毒",
            VirusFamily::RaptorVirus => "MBR破坏木马",
            VirusFamily::RedLine => "信息窃取木马",
            VirusFamily::RemcosRAT => "远程控制木马",
            VirusFamily::RogueInstaller => "恶意安装程序",
            VirusFamily::SmileGhost => "MBR破坏木马",
            VirusFamily::Spark => "信息窃取木马",
            VirusFamily::StoneCutter => "MBR破坏木马",
            VirusFamily::SystemKiller => "多功能恶意软件",
            VirusFamily::Terminator => "多功能恶意软件",
            VirusFamily::Unfixable => "MBR破坏木马",
            VirusFamily::VineMEMZ => "MBR破坏木马",
            VirusFamily::WannaCry => "勒索病毒",
            VirusFamily::Weidows => "伪装系统木马",
            VirusFamily::XMRig => "挖矿程序",
            VirusFamily::XWorm => "远程控制木马",
            VirusFamily::PyInstallerRansom => "PyInstaller打包勒索病毒",
            VirusFamily::AVKill => "杀毒软件禁用工具",
            VirusFamily::SilverFox => "银狐窃密远控木马",
        }
    }
}

/// 将字符串家族名解析为 VirusFamily 枚举
pub fn string_to_family(family_name: &str) -> VirusFamily {
    match family_name {
        "Generic" => VirusFamily::Generic,
        "AgentTesla" => VirusFamily::AgentTesla,
        "AsyncRAT" => VirusFamily::AsyncRAT,
        "DarkComet" => VirusFamily::DarkComet,
        "DcRat" => VirusFamily::DcRat,
        "Emotet" => VirusFamily::Emotet,
        "Formbook" => VirusFamily::Formbook,
        "Gh0stRAT" => VirusFamily::Gh0stRAT,
        "KillDisk" => VirusFamily::KillDisk,
        "Locky" => VirusFamily::Locky,
        "NanoCoreRAT" => VirusFamily::NanoCoreRAT,
        "Nimda" => VirusFamily::Nimda,
        "PoisonIvy" => VirusFamily::PoisonIvy,
        "QuasarRAT" => VirusFamily::QuasarRAT,
        "Ramnit" => VirusFamily::Ramnit,
        "RaptorVirus" => VirusFamily::RaptorVirus,
        "RedLine" => VirusFamily::RedLine,
        "RemcosRAT" => VirusFamily::RemcosRAT,
        "RogueInstaller" => VirusFamily::RogueInstaller,
        "SmileGhost" => VirusFamily::SmileGhost,
        "Spark" => VirusFamily::Spark,
        "StoneCutter" => VirusFamily::StoneCutter,
        "SystemKiller" => VirusFamily::SystemKiller,
        "Terminator" => VirusFamily::Terminator,
        "Unfixable" => VirusFamily::Unfixable,
        "VineMEMZ" => VirusFamily::VineMEMZ,
        "WannaCry" => VirusFamily::WannaCry,
        "Weidows" => VirusFamily::Weidows,
        "XMRig" => VirusFamily::XMRig,
        "XWorm" => VirusFamily::XWorm,
        "PyInstallerRansom" => VirusFamily::PyInstallerRansom,
        "AVKill" => VirusFamily::AVKill,
        "SilverFox" => VirusFamily::SilverFox,
        _ => VirusFamily::Generic,
    }
}

/// 家族分析结果
#[derive(Debug, Clone)]
pub struct FamilyAnalysisResult {
    pub primary_family: VirusFamily,
    pub detection_name: String,  // 完整检测名（含变种后缀，如 "HEUR:Trojan/Agent.06"）
    pub primary_score: f32,
    pub is_packed: bool,
    pub packer_name: Option<String>,
    pub hit_details: Vec<String>,
}
