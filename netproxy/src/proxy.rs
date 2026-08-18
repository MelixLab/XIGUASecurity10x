//! 本地 HTTP/HTTPS 代理服务器（纯用户态，tokio 实现）。
//!
//! - CONNECT（HTTPS）：校验目标域名，命中恶意库则直接 403 拒绝，否则建立隧道；
//! - 普通 HTTP：校验 Host 域名，命中则返回拦截页面，否则转发到上游。
//! - 黑名单未命中时进行动态风险评估（仿冒/钓鱼域名启发式评分）。
//! - 命中记录写入 JSONL 事件文件，并尝试通过 TCP 表反查发起进程。

use crate::assess::DynamicAssessor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 并发连接数上限（防恶意软件用大量连接打爆代理）
const MAX_CONCURRENT: usize = 512;

/// 请求头读取上限（64KB，防恶意超长请求头）
const MAX_HEADER_BYTES: usize = 65536;

/// 单域名事件去重窗口（毫秒），避免同一域名瞬间多次命中刷屏
const EVENT_DEDUP_MS: u64 = 1500;

/// 恶意域名规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    pub domain: String,
    #[serde(default = "default_category")]
    pub category: String,
}

fn default_category() -> String {
    "malware".to_string()
}

/// 域名库（内置 + 外部文件合并）
#[derive(Clone)]
pub struct DomainRules {
    rules: Arc<Vec<DomainRule>>,
}

impl DomainRules {
    pub fn new(embedded: &[(&str, &str)], external_path: Option<&Path>) -> Self {
        let mut map: HashMap<String, String> = HashMap::new();
        for (d, c) in embedded {
            map.insert(d.to_string().to_lowercase(), c.to_string());
        }
        // 合并外部规则文件（可选）：{"domains":[{"domain":"x.com","category":"phishing"}]}
        if let Some(path) = external_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(arr) = parsed.get("domains").and_then(|v| v.as_array()) {
                        for item in arr {
                            let domain = item.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                            let category = item.get("category").and_then(|v| v.as_str()).unwrap_or("malware").to_string();
                            if !domain.is_empty() {
                                map.insert(domain, category);
                            }
                        }
                    }
                }
            }
        }
        let rules = map
            .into_iter()
            .map(|(domain, category)| DomainRule { domain, category })
            .collect::<Vec<_>>();
        println!("[NetProxy] Loaded {} domain rules (external={:?})", rules.len(), external_path.map(|p| p.display().to_string()));
        Self {
            rules: Arc::new(rules),
        }
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }

    /// 命中判断：完全匹配或子域名后缀匹配（www.evil.com 命中 evil.com）
    pub fn match_rule(&self, host: &str) -> Option<&DomainRule> {
        let host = host.trim().to_lowercase();
        let host = host.trim_end_matches('.').to_string();
        if host.is_empty() {
            return None;
        }
        for rule in self.rules.iter() {
            if host == rule.domain || host.ends_with(&format!(".{}", rule.domain)) {
                return Some(rule);
            }
        }
        None
    }
}

/// 拦截事件（写入 JSONL）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    pub ts: String,
    pub domain: String,
    pub category: String,
    pub process: String,
    pub pid: u32,
    pub kind: String,
    /// 动态评估命中原因（可选）
    #[serde(default)]
    pub reason: Option<String>,
}

/// 事件记录器
pub struct EventLogger {
    path: std::path::PathBuf,
    dedup: Mutex<HashMap<String, Instant>>,
}

impl EventLogger {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            dedup: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(&self, event: &BlockEvent) {
        // 去重：同域名窗口内只记一次
        {
            let mut dedup = self.dedup.lock().unwrap();
            dedup.retain(|_, t| t.elapsed() < Duration::from_millis(EVENT_DEDUP_MS * 2));
            if let Some(last) = dedup.get(&event.domain) {
                if last.elapsed() < Duration::from_millis(EVENT_DEDUP_MS) {
                    return;
                }
            }
            dedup.insert(event.domain.clone(), Instant::now());
        }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(event) {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
                let _ = writeln!(f, "{}", json);
            }
        }
    }
}

// ==================== 拦截页面 ====================

fn block_page_html(domain: &str, category: &str) -> String {
    let category_zh = match category {
        "phishing" => "钓鱼网站",
        "malware" => "恶意软件",
        "scam" => "诈骗网站",
        "adware" => "广告软件",
        "tracker" => "跟踪器",
        "squatting" => "仿冒域名",
        _ => "恶意站点",
    };
    format!(
        r##"<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>连接已被阻止 - XIGUASecurity</title>
<style>
  body {{ margin:0; font-family:"Segoe UI","Microsoft YaHei UI","Microsoft YaHei",sans-serif; background:#f5f5f5; display:flex; align-items:center; justify-content:center; min-height:100vh; }}
  .card {{ background:#fff; border-radius:12px; box-shadow:0 8px 30px rgba(0,0,0,.12); padding:40px 48px; max-width:520px; text-align:center; }}
  .icon {{ width:64px; height:64px; margin:0 auto 20px; display:flex; align-items:center; justify-content:center; }}
  h1 {{ font-size:20px; color:#1a1a1a; margin:0 0 12px; }}
  p {{ font-size:14px; color:#666; line-height:1.7; margin:6px 0; }}
  .domain {{ font-size:15px; color:#d13438; font-weight:600; word-break:break-all; }}
  .tag {{ display:inline-block; margin-top:12px; padding:4px 12px; border-radius:12px; background:#fde7e9; color:#d13438; font-size:12px; }}
  .sub {{ font-size:12px; color:#999; margin-top:16px; }}
</style></head>
<body><div class="card">
  <div class="icon"><svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="#d13438" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.5 9.5-8 11-4.5-1.5-8-6-8-11V5l8-3z"/><path d="M12 8v4"/><circle cx="12" cy="15.5" r="1"/></svg></div>
  <h1>该网页存在危险，连接已被阻止</h1>
  <p class="domain">{}</p>
  <p>XIGUASecurity 网络防护已拦截对该域名的访问，因为它被识别为<span class="tag">{}</span>。</p>
  <p>Your connection to this site has been blocked by XIGUASecurity Network Protection.</p>
  <p class="sub">连接已中断 · 如需解除拦截请到 XIGUASecurity 设置中管理</p>
</div></body></html>"##,
        domain, category_zh
    )
}

// ==================== 进程反查（本地端口 → PID → 进程名） ====================

/// 通过 TCP 表反查占用指定本地端口的进程 PID
fn find_pid_by_local_port(listen_port: u16, client_port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_CLASS};
    unsafe {
        let mut size: u32 = 0;
        // 第一次调用用于获取所需大小：此时必然返回 ERROR_INSUFFICIENT_BUFFER(122)，
        // 返回值不能作为失败判断，只依赖 size 是否被填充。
        let _ = GetExtendedTcpTable(None, &mut size, false, 2, TCP_TABLE_CLASS(5), 0);
        if size == 0 || size > 4 * 1024 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let r = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            false,
            2, // AF_INET
            TCP_TABLE_CLASS(5), // TCP_TABLE_OWNER_PID_ALL
            0,
        );
        if r != 0 {
            return None;
        }
        // MIB_TCPTABLE_OWNER_PID: dwNumEntries + table[1]
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        if count > 0 && count <= 65536 {
            let rows: &[MIB_TCPROW_OWNER_PID] =
                std::slice::from_raw_parts(table.table.as_ptr(), count);
            let loopback = 0x0100_007Fu32; // 127.0.0.1（网络字节序存储）
            for row in rows {
                // 本端 = 客户端本地地址:客户端临时端口；对端 = 127.0.0.1:监听端口
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
                let remote_is_loopback = row.dwRemoteAddr == loopback;
                if remote_is_loopback && remote_port == listen_port && local_port == client_port {
                    return Some(row.dwOwningPid);
                }
            }
        }
        None
    }
}

/// PID → 进程名
fn process_name_by_pid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return None;
        };
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let r = QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR::from_raw(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        if r.is_err() || size == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&buf[..size as usize]);
        let name = name.replace('\\', "/");
        let base = name.rsplit('/').next().unwrap_or(&name).to_string();
        Some(base)
    }
}

/// 反查发起连接的进程（查不到时回退为 unknown）
fn lookup_client_process(listen_port: u16, client_addr: Option<SocketAddr>) -> (String, u32) {
    let Some(addr) = client_addr else {
        return ("unknown".to_string(), 0);
    };
    let pid = find_pid_by_local_port(listen_port, addr.port()).unwrap_or(0);
    if pid == 0 {
        return ("unknown".to_string(), 0);
    }
    let name = process_name_by_pid(pid).unwrap_or_else(|| "unknown".to_string());
    (name, pid)
}

// ==================== 代理连接处理 ====================

/// 解析请求头中的目标主机。优先取 CONNECT 目标 / 绝对 URL，其次取 Host 头。
/// 返回 (主机名, 端口)。
fn parse_target(method: &str, target: &str, headers: &str, default_port: u16) -> Option<(String, u16)> {
    if method == "CONNECT" {
        // target = host:port
        let t = target.trim();
        if let Some((host, port)) = t.rsplit_once(':') {
            if host.is_empty() {
                return None;
            }
            if let Ok(p) = port.parse::<u16>() {
                return Some((host.to_string(), p));
            }
        }
        return Some((t.to_string(), 443));
    }

    // 绝对 URL：http://host[:port]/path
    for scheme in ["http://", "https://"] {
        if let Some(rest) = target.to_lowercase().strip_prefix(scheme) {
            let authority = rest.split(['/', '?']).next().unwrap_or(rest);
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                    (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
                }
                _ => (authority.to_string(), if scheme == "https://" { 443 } else { default_port }),
            };
            return Some((host, port));
        }
    }

    // Host 头
    for line in headers.lines() {
        let l = line.trim();
        if let Some(value) = l.to_lowercase().strip_prefix("host:") {
            let authority = value.trim();
            if authority.is_empty() {
                return None;
            }
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                    (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
                }
                _ => (authority.to_string(), default_port),
            };
            return Some((host, port));
        }
    }
    None
}

/// 查找 \r\n\r\n 位置
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// 写入 HTTP 拦截响应
async fn write_block_response(stream: &mut TcpStream, domain: &str, category: &str) {
    let body = block_page_html(domain, category);
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nX-XIGUA-Security: blocked\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 双向转发
async fn tunnel(mut a: TcpStream, mut b: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
}

/// 处理单个客户端连接
async fn handle_connection(
    mut stream: TcpStream,
    listen_port: u16,
    rules: Arc<DomainRules>,
    logger: Arc<EventLogger>,
) {
    let client_addr = stream.peer_addr().ok();

    // 读取请求头（直到 \r\n\r\n 或超上限）
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut tmp).await {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > MAX_HEADER_BYTES {
                    return;
                }
                if let Some(pos) = find_header_end(&buf) {
                    break pos;
                }
            }
            Err(_) => return,
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let first_line = head.lines().next().unwrap_or("").trim().to_string();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();

    let default_port = if method == "CONNECT" { 443 } else { 80 };
    let Some((host, port)) = parse_target(&method, &target, &head, default_port) else {
        return;
    };

    // IP 直连地址无法做域名匹配，直接放行（本功能只拦域名）
    if let Ok(ip) = host.parse::<IpAddr>() {
        if method == "CONNECT" {
            if let Ok(upstream) = TcpStream::connect((ip, port)).await {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
                tunnel(stream, upstream).await;
            }
        } else {
            if let Ok(mut upstream) = TcpStream::connect((ip, port)).await {
                let _ = upstream.write_all(&buf).await;
                let _ = upstream.flush().await;
                tunnel(stream, upstream).await;
            }
        }
        return;
    }

    // 黑名单命中检查
    if let Some(rule) = rules.match_rule(&host) {
        let (process, pid) = lookup_client_process(listen_port, client_addr);
        println!("[NetProxy] BLOCKED {} ({}) by {} (pid {})", host, rule.category, process, pid);
        logger.record(&BlockEvent {
            ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            domain: host.clone(),
            category: rule.category.clone(),
            process,
            pid,
            kind: if method == "CONNECT" { "https" } else { "http" }.to_string(),
            reason: None,
        });
        write_block_response(&mut stream, &host, &rule.category).await;
        return;
    }

    // 动态风险评估（智能仿冒/钓鱼检测，未命中黑名单时生效）
    if let Some(result) = DynamicAssessor::assess(&host) {
        if result.block {
            let (process, pid) = lookup_client_process(listen_port, client_addr);
            println!(
                "[NetProxy] BLOCKED {} (squatting, score={}) by {} (pid {}) - {}",
                host, result.score, process, pid, result.reason
            );
            logger.record(&BlockEvent {
                ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                domain: host.clone(),
                category: "squatting".to_string(),
                process,
                pid,
                kind: if method == "CONNECT" { "https" } else { "http" }.to_string(),
                reason: Some(format!("score={} {}", result.score, result.reason)),
            });
            write_block_response(&mut stream, &host, "squatting").await;
            return;
        }
        if result.warn {
            // 未达拦截阈值：仅记录告警，不影响访问（避免误伤正常站点）
            println!(
                "[NetProxy] WARN domain {} score={} ({})",
                host, result.score, result.reason
            );
        }
    }

    // 放行：转发
    if method == "CONNECT" {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(upstream) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
                tunnel(stream, upstream).await;
            }
            Err(_) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        }
    } else {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(mut upstream) => {
                let _ = upstream.write_all(&buf).await;
                let _ = upstream.flush().await;
                tunnel(stream, upstream).await;
            }
            Err(_) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        }
    }
}

/// 启动代理服务器，返回监听器。绑定失败时返回 Err。
pub async fn start_proxy(port: u16) -> Result<TcpListener, String> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("代理端口 {} 绑定失败: {}", port, e))?;
    println!("[NetProxy] Proxy listening on {}", addr);
    Ok(listener)
}

/// 运行代理主循环（在调用方 tokio runtime 中执行）
pub async fn run_proxy_loop(
    listener: TcpListener,
    port: u16,
    rules: Arc<DomainRules>,
    logger: Arc<EventLogger>,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // 连接数超限：直接拒绝
                drop(stream);
                continue;
            }
        };
        let rules = rules.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            handle_connection(stream, port, rules, logger).await;
            drop(permit);
        });
    }
}
