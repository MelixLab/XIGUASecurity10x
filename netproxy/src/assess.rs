//! 动态域名风险评估引擎（启发式评分，纯本地，无联网依赖）
//!
//! 依据公开的仿冒/钓鱼域名研究成果与安全厂商公开特征，对未命中黑名单的域名
//! 做多维度打分，超过阈值判定为可疑并拦截：
//!
//! 1. 品牌撞名（typosquatting / combosquatting）：
//!    - 编辑距离 ≤2（拼写陷阱，含 0↔o、1↔l 等字符替换规范化后）
//!    - 品牌名 + 前缀/后缀/连字符（如 hd-huorong.com.cn 仿 huorong.cn）
//!    - 品牌名出现在子域段而注册域不同（子域混淆）
//! 2. TLD 偷换：与品牌注册域相同但顶级域不同（huorong.cn → .com.cn）
//! 3. 钓鱼关键词：verify/secure/account/login/refund/pay 等
//! 4. 非常规/免费 TLD：.tk .ml .ga .xyz .top 等
//! 5. 结构特征：连字符、数字混杂、超长域名、Punycode 同形词
//!
//! 评分 ≥ BLOCK_THRESHOLD(60) 判定为仿冒/恶意；评分 40-59 仅记录不拦截。
//! 内置品牌白名单（官方域名精确/子域）直接放行，绝不影响正常访问。

/// 拦截阈值
pub const BLOCK_THRESHOLD: i32 = 60;
/// 告警阈值（低于拦截，仅记录）
pub const WARN_THRESHOLD: i32 = 40;

/// 品牌信息
pub struct Brand {
    /// 品牌名（小写，用于相似度比对，如 "huorong"）
    pub name: &'static str,
    /// 官方注册域（含 TLD，白名单），如 "huorong.cn"
    pub domain: &'static str,
    /// 官方其他合法 TLD 变体（白名单），如 qq 的 ["com.cn"]
    pub alt_tlds: &'static [&'static str],
}

/// 内置品牌库（中文互联网主流品牌 + 常见被仿冒的国际品牌）
const BRANDS: &[Brand] = &[
    Brand { name: "huorong", domain: "huorong.cn", alt_tlds: &[] },
    Brand { name: "360", domain: "360.cn", alt_tlds: &["com.cn", "com"] },
    Brand { name: "qq", domain: "qq.com", alt_tlds: &["com.cn"] },
    Brand { name: "tencent", domain: "tencent.com", alt_tlds: &["com.cn"] },
    Brand { name: "weixin", domain: "weixin.qq.com", alt_tlds: &[] },
    Brand { name: "wechat", domain: "wechat.com", alt_tlds: &["com.cn"] },
    Brand { name: "alipay", domain: "alipay.com", alt_tlds: &["com.cn"] },
    Brand { name: "taobao", domain: "taobao.com", alt_tlds: &["com.cn"] },
    Brand { name: "tmall", domain: "tmall.com", alt_tlds: &["com.cn"] },
    Brand { name: "jd", domain: "jd.com", alt_tlds: &["com.cn"] },
    Brand { name: "baidu", domain: "baidu.com", alt_tlds: &["com.cn"] },
    Brand { name: "douyin", domain: "douyin.com", alt_tlds: &["com.cn"] },
    Brand { name: "kuaishou", domain: "kuaishou.com", alt_tlds: &["com.cn"] },
    Brand { name: "bilibili", domain: "bilibili.com", alt_tlds: &["com.cn"] },
    Brand { name: "weibo", domain: "weibo.com", alt_tlds: &["com.cn"] },
    Brand { name: "zhihu", domain: "zhihu.com", alt_tlds: &["com.cn"] },
    Brand { name: "163", domain: "163.com", alt_tlds: &["com.cn"] },
    Brand { name: "netease", domain: "netease.com", alt_tlds: &["com.cn"] },
    Brand { name: "sina", domain: "sina.com.cn", alt_tlds: &["com.cn"] },
    Brand { name: "meituan", domain: "meituan.com", alt_tlds: &["com.cn"] },
    Brand { name: "didi", domain: "didiglobal.com", alt_tlds: &["com.cn"] },
    Brand { name: "ctrip", domain: "ctrip.com", alt_tlds: &["com.cn"] },
    Brand { name: "icbc", domain: "icbc.com.cn", alt_tlds: &["cn"] },
    Brand { name: "ccb", domain: "ccb.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "abchina", domain: "abchina.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "boc", domain: "boc.cn", alt_tlds: &["com.cn", "com"] },
    Brand { name: "bankcomm", domain: "bankcomm.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "cmbchina", domain: "cmbchina.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "psbc", domain: "psbc.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "pingan", domain: "pingan.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "cmbc", domain: "cmbc.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "spdb", domain: "spdb.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "cib", domain: "cib.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "cebbank", domain: "cebbank.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "citicbank", domain: "citicbank.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "hxb", domain: "hxb.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "chinalife", domain: "chinalife.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "chinamobile", domain: "chinamobile.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "10086", domain: "10086.cn", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "chinaunicom", domain: "chinaunicom.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "chinatelecom", domain: "chinatelecom.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "huawei", domain: "huawei.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "xiaomi", domain: "xiaomi.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "oppo", domain: "oppo.com", alt_tlds: &["com.cn"] },
    Brand { name: "vivo", domain: "vivo.com", alt_tlds: &["com.cn"] },
    Brand { name: "honor", domain: "honor.cn", alt_tlds: &["com.cn", "com"] },
    Brand { name: "lenovo", domain: "lenovo.com.cn", alt_tlds: &["cn", "com"] },
    Brand { name: "dell", domain: "dell.com", alt_tlds: &["com.cn"] },
    Brand { name: "hp", domain: "hp.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "microsoft", domain: "microsoft.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "google", domain: "google.com", alt_tlds: &["com.cn", "cn", "com.hk"] },
    Brand { name: "apple", domain: "apple.com", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "amazon", domain: "amazon.com", alt_tlds: &["com.cn"] },
    Brand { name: "facebook", domain: "facebook.com", alt_tlds: &["com.cn"] },
    Brand { name: "twitter", domain: "twitter.com", alt_tlds: &[] },
    Brand { name: "linkedin", domain: "linkedin.com", alt_tlds: &[] },
    Brand { name: "youtube", domain: "youtube.com", alt_tlds: &["com.cn"] },
    Brand { name: "netflix", domain: "netflix.com", alt_tlds: &[] },
    Brand { name: "paypal", domain: "paypal.com", alt_tlds: &[] },
    Brand { name: "steam", domain: "steampowered.com", alt_tlds: &["com.cn"] },
    Brand { name: "epicgames", domain: "epicgames.com", alt_tlds: &[] },
    Brand { name: "sf-express", domain: "sf-express.com", alt_tlds: &["com.cn"] },
    Brand { name: "yto", domain: "yto.net.cn", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "zto", domain: "zto.com", alt_tlds: &["com.cn"] },
    Brand { name: "sto", domain: "sto.cn", alt_tlds: &["com.cn", "cn"] },
    Brand { name: "yundaex", domain: "yundaex.com", alt_tlds: &["com.cn"] },
    Brand { name: "12306", domain: "12306.cn", alt_tlds: &["com.cn"] },
    // —— 常见合法大站（避免近音误报，如 douban/doubao 与 taobao 编辑距离很近） ——
    Brand { name: "douban", domain: "douban.com", alt_tlds: &["com.cn"] },
    Brand { name: "doubao", domain: "doubao.com", alt_tlds: &["com.cn"] },
    Brand { name: "bytedance", domain: "bytedance.com", alt_tlds: &["com.cn"] },
    Brand { name: "tiktok", domain: "tiktok.com", alt_tlds: &["com.cn"] },
    Brand { name: "pinduoduo", domain: "pinduoduo.com", alt_tlds: &["com.cn"] },
    Brand { name: "iqiyi", domain: "iqiyi.com", alt_tlds: &["com.cn"] },
    Brand { name: "youku", domain: "youku.com", alt_tlds: &["com.cn"] },
    Brand { name: "ximalaya", domain: "ximalaya.com", alt_tlds: &["com.cn"] },
    Brand { name: "csdn", domain: "csdn.net", alt_tlds: &["net.cn"] },
    Brand { name: "github", domain: "github.com", alt_tlds: &["io"] },
    Brand { name: "gitee", domain: "gitee.com", alt_tlds: &["com.cn"] },
    Brand { name: "aliyun", domain: "aliyun.com", alt_tlds: &["com.cn"] },
    Brand { name: "alibaba", domain: "alibaba.com", alt_tlds: &["com.cn"] },
    Brand { name: "outlook", domain: "outlook.com", alt_tlds: &["com.cn"] },
    Brand { name: "office", domain: "office.com", alt_tlds: &["com.cn"] },
    Brand { name: "telegram", domain: "telegram.org", alt_tlds: &["com"] },
    Brand { name: "instagram", domain: "instagram.com", alt_tlds: &["com.cn"] },
    Brand { name: "whatsapp", domain: "whatsapp.com", alt_tlds: &["com.cn"] },
];

/// 钓鱼/恶意常用关键词（出现在注册域主体中时加分）
const PHISH_KEYWORDS: &[&str] = &[
    "verify", "verification", "secure", "security", "account", "accounts",
    "login", "logon", "signin", "signin", "password", "pwd", "alert",
    "update", "refund", "payment", "pay", "service", "support", "confirm",
    "authentication", "banking", "bank", "wallet", "token", "center",
    "help", "official", "customer", "renew", "activate", "suspend",
    "freeze", "lock", "recovery", "reset", "protection", "antivirus",
    "download", "driver", "coupon", "gift", "lucky", "prize", "winner",
];

/// 高危免费/异常 TLD（权重高）
const HIGH_RISK_TLDS: &[&str] = &[
    "tk", "ml", "ga", "gq", "cf", "xyz", "top", "icu", "work", "click",
    "link", "live", "buzz", "party",
];

/// 中等风险 TLD（较新/便宜，恶意使用率偏高）
const MID_RISK_TLDS: &[&str] = &[
    "online", "site", "tech", "club", "shop", "store", "support", "help",
    "services", "account", "secure", "verify", "sbs", "monster", "rest",
];

/// 字符替换混淆映射（0↔o、1↔l、5↔s 等，用于发现拼写陷阱）
fn skeleton(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            '2' => 'z',
            other => other,
        })
        .collect()
}

/// Levenshtein 编辑距离
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

/// 多段 TLD（如 com.cn、com.hk），判断时优先匹配
const MULTI_PART_TLDS: &[&str] = &[
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw",
    "com.sg", "com.au", "co.uk", "org.uk", "co.jp", "com.br", "com.mx",
    "com.tr", "com.vn", "com.my", "com.ph", "co.kr", "com.ru",
];

/// 域名拆分结果
#[derive(Debug, Clone)]
pub struct DomainParts {
    /// 完整域名（小写）
    pub host: String,
    /// 注册域主体（不含 TLD），如 hd-huorong
    pub e2ld: String,
    /// 顶级域，如 com.cn / cn / com
    pub tld: String,
    /// 子域部分（可为空）
    pub sub: String,
}

/// 拆分域名（简化 publicsuffix 规则，覆盖主流多段 TLD）
pub fn split_domain(host: &str) -> Option<DomainParts> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    // 多段 TLD：com.cn 等
    if labels.len() >= 3 {
        let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
        if MULTI_PART_TLDS.contains(&last_two.as_str()) {
            let e2ld = labels[labels.len() - 3].to_string();
            let sub = labels[..labels.len() - 3].join(".");
            return Some(DomainParts { host, e2ld, tld: last_two, sub });
        }
    }
    let e2ld = labels[labels.len() - 2].to_string();
    let tld = labels[labels.len() - 1].to_string();
    let sub = labels[..labels.len() - 2].join(".");
    Some(DomainParts { host, e2ld, tld, sub })
}

/// 评估结果
#[derive(Debug, Clone)]
pub struct AssessResult {
    pub score: i32,
    /// 命中的品牌名（若有）
    #[allow(dead_code)]
    pub brand: Option<String>,
    /// 主要原因描述
    pub reason: String,
    pub block: bool,
    pub warn: bool,
}

/// 动态评估器
pub struct DynamicAssessor;

impl DynamicAssessor {
    /// 官方白名单：host 等于品牌官方域或其子域 → 放行
    pub fn is_whitelisted(host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        BRANDS.iter().any(|b| {
            host == b.domain
                || host.ends_with(&format!(".{}", b.domain))
                || b.alt_tlds.iter().any(|t| {
                    // 品牌同主体其他官方 TLD（如 qq.com.cn）
                    let official = match split_domain(b.domain) {
                        Some(p) => format!("{}.{}", p.e2ld, t),
                        None => String::new(),
                    };
                    !official.is_empty()
                        && (host == official || host.ends_with(&format!(".{}", official)))
                })
        })
    }

    /// 对域名做综合评分
    pub fn assess(host: &str) -> Option<AssessResult> {
        // IP 直连不评估（由代理层直接放行）
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        if Self::is_whitelisted(host) {
            return None;
        }
        let parts = split_domain(host)?;
        let mut score: i32 = 0;
        let mut brand_hit: Option<String> = None;
        let mut reasons: Vec<String> = Vec::new();

        // 1. Punycode 同形词（IDN homograph）
        if parts.host.starts_with("xn--") || parts.e2ld.starts_with("xn--") {
            score += 30;
            reasons.push("Punycode/同形词域名".to_string());
        }

        // 2. 品牌撞名评估
        let e2ld_norm: String = parts.e2ld.chars().filter(|c| *c != '-').collect();
        let e2ld_skeleton = skeleton(&e2ld_norm);

        let mut best_brand_squat: i32 = 0;
        let mut best_brand_name: Option<String> = None;

        for brand in BRANDS {
            let bparts = match split_domain(brand.domain) {
                Some(p) => p,
                None => continue,
            };
            let brand_norm: String = brand.name.chars().filter(|c| *c != '-').collect();
            if brand_norm.is_empty() {
                continue;
            }
            // 品牌官方 TLD 集合（官方域 + alt 变体），用于"后缀异常"判定
            let official_tlds = [bparts.tld.as_str()]
                .into_iter()
                .chain(brand.alt_tlds.iter().copied())
                .collect::<Vec<_>>();
            let brand_skeleton = skeleton(&brand_norm);
            let mut b_score: i32 = 0;

            // 2a. TLD 偷换：主体与品牌完全相同但顶级域非官方（huorong.cn → huorong.net）
            if parts.e2ld == bparts.e2ld && !official_tlds.contains(&parts.tld.as_str()) {
                b_score = b_score.max(60);
                reasons.push(format!("仿冒品牌 {}（后缀不同）", brand_norm));
            }

            // 2b. 编辑距离撞名（拼写陷阱 + 数字替换规范化）。
            // 短品牌名（≤4 字符）易误伤（如 361.com 撞 360），权重减半。
            let d_raw = edit_distance(&e2ld_norm, &brand_norm);
            let d_skel = edit_distance(&e2ld_skeleton, &brand_skeleton);
            let d = d_raw.min(d_skel);
            let short_brand = brand_norm.chars().count() < 5;
            if d == 0 && d_raw > 0 {
                // skeleton 相同但原始不同 = 数字替换混淆（micros0ft → microsoft）
                b_score = b_score.max(if short_brand { 30 } else { 60 });
                reasons.push(format!("字符替换混淆品牌 {}", brand_norm));
            } else if d <= 2 && d > 0 {
                b_score = b_score.max(if short_brand { 25 } else { 60 });
                reasons.push(format!("与品牌 {} 拼写高度相似", brand_norm));
            } else if d <= 4 {
                // 距离 3-4 为弱信号（易误报，如 douban 与 taobao），权重压低
                b_score = b_score.max(if short_brand { 5 } else { 10 });
                reasons.push(format!("与品牌 {} 拼写相似", brand_norm));
            }

            // 2c. combosquatting：品牌名 + 额外前后缀（hd-huorong、xiaomi-service）
            if e2ld_norm.contains(&brand_norm) && e2ld_norm.len() > brand_norm.len() {
                let extra: String = e2ld_norm.replace(&brand_norm, "");
                let extra_has_hyphen = parts.e2ld.contains('-');
                let extra_is_keyword = !extra.is_empty()
                    && PHISH_KEYWORDS.iter().any(|k| {
                        extra.contains(k) || parts.e2ld.contains(k)
                    });
                if extra_has_hyphen || extra_is_keyword {
                    b_score = b_score.max(60);
                    reasons.push(format!("仿冒品牌 {}（拼接可疑前后缀）", brand_norm));
                } else {
                    b_score = b_score.max(25);
                    reasons.push(format!("名称包含品牌 {}", brand_norm));
                }
            }

            // 2d. 子域混淆：品牌名出现在子域，注册域不是品牌官方域
            if !parts.sub.is_empty() && parts.sub.contains(&brand_norm) && parts.e2ld != bparts.e2ld {
                b_score = b_score.max(30);
                reasons.push(format!("子域冒用品牌 {}（注册域非官方）", brand_norm));
            }

            // 2e. 后缀异常：已撞名但顶级域非品牌官方后缀（仿冒站常见 .com.cn/.net 混用）
            if b_score > 0
                && parts.e2ld != bparts.e2ld
                && !official_tlds.contains(&parts.tld.as_str())
            {
                b_score += 15;
            }

            if b_score > best_brand_squat {
                best_brand_squat = b_score;
                best_brand_name = Some(brand.name.to_string());
            }
        }

        if best_brand_squat > 0 {
            score += best_brand_squat;
            brand_hit = best_brand_name;
        }

        // 3. 钓鱼关键词（独立特征，弱于撞名）
        let kw_count = PHISH_KEYWORDS
            .iter()
            .filter(|k| parts.e2ld.contains(**k))
            .count();
        if kw_count >= 1 {
            score += if kw_count >= 2 { 15 } else { 5 };
            if kw_count >= 2 {
                reasons.push(format!("包含 {} 个可疑关键词", kw_count));
            }
        }

        // 4. 非常规 TLD
        if HIGH_RISK_TLDS.contains(&parts.tld.as_str()) {
            score += 20;
            reasons.push(format!("高危域名后缀 .{}", parts.tld));
        } else if MID_RISK_TLDS.contains(&parts.tld.as_str()) {
            score += 10;
        }

        // 5. 结构特征
        let hyphen_count = parts.e2ld.matches('-').count();
        if hyphen_count >= 2 {
            score += 8;
        } else if hyphen_count == 1 {
            score += 3;
        }
        let digit_count = parts.e2ld.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count >= 3 {
            score += 8;
            reasons.push("域名主体包含过多数字".to_string());
        }
        if parts.e2ld.chars().count() >= 20 {
            score += 5;
        }

        if score == 0 {
            return None;
        }

        Some(AssessResult {
            score,
            brand: brand_hit,
            reason: if reasons.is_empty() {
                "域名特征可疑".to_string()
            } else {
                reasons.join("；")
            },
            block: score >= BLOCK_THRESHOLD,
            warn: score >= WARN_THRESHOLD,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_domain() {
        let p = split_domain("www.huorong.cn").unwrap();
        assert_eq!(p.e2ld, "huorong");
        assert_eq!(p.tld, "cn");
        let p = split_domain("hd-huorong.com.cn").unwrap();
        assert_eq!(p.e2ld, "hd-huorong");
        assert_eq!(p.tld, "com.cn");
        let p = split_domain("a.b.baidu.com").unwrap();
        assert_eq!(p.e2ld, "baidu");
        assert_eq!(p.sub, "a.b");
    }

    #[test]
    fn test_whitelist() {
        assert!(DynamicAssessor::is_whitelisted("huorong.cn"));
        assert!(DynamicAssessor::is_whitelisted("www.huorong.cn"));
        assert!(DynamicAssessor::is_whitelisted("qq.com"));
        assert!(DynamicAssessor::is_whitelisted("qq.com.cn"));
        assert!(!DynamicAssessor::is_whitelisted("hd-huorong.com.cn"));
    }

    #[test]
    fn test_edit_distance() {
        assert_eq!(edit_distance("huorong", "huorong"), 0);
        assert_eq!(edit_distance("huorng", "huorong"), 1);
        assert_eq!(edit_distance("hdhuorong", "huorong"), 2);
    }

    #[test]
    fn test_assess_phishing_squat() {
        // 用户提供案例：仿冒火绒
        let r = DynamicAssessor::assess("hd-huorong.com.cn").unwrap();
        assert!(r.block, "hd-huorong.com.cn should block, score={}", r.score);
        assert!(r.score >= 60);
    }

    #[test]
    fn test_assess_normal_sites() {
        assert!(DynamicAssessor::assess("baidu.com").is_none());
        assert!(DynamicAssessor::assess("www.qq.com").is_none());
        assert!(DynamicAssessor::assess("qq.com.cn").is_none());
        // 正常新闻站点：无品牌撞名、无关键词、常规 TLD
        let r = DynamicAssessor::assess("news-site-xyz.com");
        if let Some(r) = r {
            assert!(!r.block, "normal site should not block, score={}", r.score);
        }
    }

    #[test]
    fn test_assess_short_brand_no_false_positive() {
        // 短品牌误伤防护：361.com 撞品牌 360（距离1）但这是正规体育品牌官网
        let r = DynamicAssessor::assess("361.com");
        if let Some(r) = r {
            assert!(!r.block, "361.com should not block, score={}", r.score);
        }
        // 淘宝子域
        assert!(DynamicAssessor::assess("item.taobao.com").is_none());
        // 合法大站白名单（豆包/豆瓣 与 taobao 近音，必须放行）
        assert!(DynamicAssessor::assess("www.doubao.com").is_none());
        assert!(DynamicAssessor::assess("douban.com").is_none());
        assert!(DynamicAssessor::assess("user.github.io").is_none());
    }

    #[test]
    fn test_assess_typo() {
        // 拼写陷阱：payapl（paypal 换位）/ micros0ft（数字替换 o）
        let r = DynamicAssessor::assess("micros0ft.com").unwrap();
        assert!(r.block, "micros0ft.com should block, score={}", r.score);
    }

    #[test]
    fn test_assess_combosquat() {
        let r = DynamicAssessor::assess("xiaomi-service.com").unwrap();
        assert!(r.block, "xiaomi-service.com should block, score={}", r.score);
    }

    #[test]
    fn test_assess_tld_switch() {
        let r = DynamicAssessor::assess("huorong.net").unwrap();
        assert!(r.block, "huorong.net should block, score={}", r.score);
    }
}
