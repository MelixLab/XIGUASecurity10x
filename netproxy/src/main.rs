//! XIGUASecurity 网络防护 - 本地代理进程（纯用户态）
//!
//! 职责：
//! 1. 设置 Windows 系统代理（WinINet）到本进程；
//! 2. 提供 HTTP/HTTPS 本地代理，拦截恶意域名；
//! 3. 监控父进程（主程序），父进程死亡时自动还原系统代理后退出；
//! 4. 被主程序优雅关闭时同样先还原系统代理。
//!
//! 安全原则：任何退出路径都必须先还原系统代理，确保"程序没了，网还在"。

mod assess;
mod proxy;
mod sys;

use proxy::{DomainRules, EventLogger};
use std::path::PathBuf;
use std::sync::Arc;

/// 代理监听端口（固定，主程序与备份/还原逻辑共用此值）
const DEFAULT_PORT: u16 = 37887;

/// 内置示例恶意域名库（钓鱼/仿冒/诈骗/恶意软件示例）
const EMBEDDED_RULES: &[(&str, &str)] = &[
    // —— 仿冒银行/支付（钓鱼） ——
    ("silverfox-bank.com", "phishing"),
    ("silverfox-secure.com", "phishing"),
    ("bank-secure-verify.com", "phishing"),
    ("icbc-verify.com", "phishing"),
    ("95588-service.com", "phishing"),
    ("ccb-secure.com", "phishing"),
    ("cmb-secure-verify.com", "phishing"),
    ("boc-verify.com", "phishing"),
    ("abchina-verify.com", "phishing"),
    ("paypal-secure-verify.com", "phishing"),
    ("paypal-account-alert.com", "phishing"),
    ("alipay-secure.com", "phishing"),
    ("alipay-verify-pay.com", "phishing"),
    ("wechat-pay-verify.com", "phishing"),
    ("jd-verify-pay.com", "phishing"),
    // —— 仿冒平台账号（钓鱼） ——
    ("appleid-verify.com", "phishing"),
    ("apple-icloud-verify.com", "phishing"),
    ("microsoft-account-verify.com", "phishing"),
    ("outlook-verify-alert.com", "phishing"),
    ("qq-secure-verify.com", "phishing"),
    ("taobao-verify.com", "phishing"),
    ("steam-account-verify.com", "phishing"),
    ("telegram-verify-alert.com", "phishing"),
    // —— 诈骗/中奖/退款 ——
    ("lottery-prize-claim.com", "scam"),
    ("free-bitcoin-giveaway.com", "scam"),
    ("bitcoin-wallet-verify.com", "scam"),
    ("gov-tax-refund.com", "scam"),
    ("express-refund-claim.com", "scam"),
    ("reimbursement-center.com", "scam"),
    // —— 恶意软件/钓鱼下载 ——
    ("security-alert-account.com", "malware"),
    ("webmail-login-alert.com", "malware"),
    ("crack-software-free.com", "malware"),
    ("free-movie-streaming.net", "malware"),
    ("driver-update-scan.com", "adware"),
    ("pc-cleaner-pro.com", "adware"),
    ("browser-hijack-home.com", "adware"),
    ("tracking-ads-net.com", "tracker"),
];

fn main() {
    // 解析命令行参数
    let args: Vec<String> = std::env::args().collect();
    let mut port = DEFAULT_PORT;
    let mut parent_pid: u32 = 0;
    let mut backup_path = sys::default_backup_path();
    let mut events_path = sys::default_events_path();
    let mut rules_path: Option<PathBuf> = None;
    let mut whitelist_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    port = v.parse().unwrap_or(DEFAULT_PORT);
                    i += 1;
                }
            }
            "--parent-pid" => {
                if let Some(v) = args.get(i + 1) {
                    parent_pid = v.parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--backup" => {
                if let Some(v) = args.get(i + 1) {
                    backup_path = PathBuf::from(v);
                    i += 1;
                }
            }
            "--events" => {
                if let Some(v) = args.get(i + 1) {
                    events_path = PathBuf::from(v);
                    i += 1;
                }
            }
            "--rules" => {
                if let Some(v) = args.get(i + 1) {
                    rules_path = Some(PathBuf::from(v));
                    i += 1;
                }
            }
            "--whitelist" => {
                if let Some(v) = args.get(i + 1) {
                    whitelist_path = Some(PathBuf::from(v));
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    println!("[NetProxy] Starting: port={} parent_pid={}", port, parent_pid);

    // 启动 tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(async_main(port, parent_pid, backup_path, events_path, rules_path, whitelist_path));
}

async fn async_main(
    port: u16,
    parent_pid: u32,
    backup_path: PathBuf,
    events_path: PathBuf,
    rules_path: Option<PathBuf>,
    whitelist_path: Option<PathBuf>,
) {
    // 1. 加载域名库与域名白名单
    let rules = Arc::new(DomainRules::new(EMBEDDED_RULES, rules_path.as_deref()));
    let whitelist = Arc::new(proxy::DomainWhitelist::new(whitelist_path));
    let logger = Arc::new(EventLogger::new(events_path));

    // 2. 备份并设置系统代理（失败则直接退出，不动任何东西）
    if let Err(e) = sys::set_proxy(port, &backup_path) {
        println!("ERROR: set system proxy failed: {}", e);
        std::process::exit(1);
    }

    // 3. 启动父进程看门狗（父进程死亡 → 触发关闭 → 还原代理）
    let shutdown_event = sys::create_shutdown_event();
    sys::spawn_parent_watchdog(parent_pid, shutdown_event.0 as isize);

    // 4. 启动代理服务器
    let listener = match proxy::start_proxy(port).await {
        Ok(l) => l,
        Err(e) => {
            println!("ERROR: {}", e);
            // 代理起不来必须还原系统代理，否则用户将无法上网
            sys::restore_proxy(port, &backup_path);
            std::process::exit(1);
        }
    };

    // 5. 通知主程序已就绪（READY 协议，附带端口与规则数，主程序可解析）
    println!("READY port={} rules={}", port, rules.count());
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // 6. 运行代理循环，同时等待关闭信号
    let proxy_task = tokio::spawn(proxy::run_proxy_loop(listener, port, rules, whitelist, logger.clone()));

    // 7. 等待关闭：Ctrl+C 或 关闭事件（主程序信号/父进程死亡）
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("[NetProxy] Ctrl+C received, shutting down");
        }
        _ = wait_event_async() => {
            println!("[NetProxy] Shutdown event received, shutting down");
        }
    }

    // 8. 优雅退出：先还原系统代理，再终止代理任务
    proxy_task.abort();
    sys::restore_proxy(port, &backup_path);
    println!("[NetProxy] Exited cleanly, system proxy restored");
}

/// 异步等待关闭事件（包装同步 WaitForSingleObject）
async fn wait_event_async() {
    tokio::task::spawn_blocking(|| {
        loop {
            if sys::wait_shutdown_event(500) {
                break;
            }
        }
    })
    .await
    .ok();
}
