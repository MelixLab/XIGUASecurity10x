//! Windows 原生 Toast 通知封装
//!
//! 使用 windows::UI::Notifications 发送带应用图标、操作按钮的系统级通知，
//! 失败时回退到 tauri-plugin-notification。

use tauri::AppHandle;
use windows::core::{HSTRING, IInspectable, Interface};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager, ToastNotificationPriority, ToastActivatedEventArgs, ToastDismissedEventArgs};

use std::sync::Mutex;
use std::collections::HashMap;
use std::time::Duration;

/// 通知类型，决定视觉风格（图标/颜色）
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NotificationType {
    /// 威胁检出（红色）
    Threat,
    /// 行为拦截（黄色）
    Block,
    /// 安全状态（绿色）
    Safe,
    /// 普通信息（蓝色）
    Info,
}

/// 通知来源：决定按钮行为
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NotificationSource {
    /// 基础防护：进程已终止，仅提供「确认」按钮
    Basic,
    /// 驱动防护：需要用户决策，提供「允许/拦截」按钮，超时自动拦截
    Driver,
}

impl NotificationType {
    fn as_str(&self) -> &'static str {
        match self {
            NotificationType::Threat => "threat",
            NotificationType::Block => "block",
            NotificationType::Safe => "safe",
            NotificationType::Info => "info",
        }
    }

    /// 返回对应的状态提示文本，用于通知 XML 的 alt 属性
    fn alt_text(&self) -> &'static str {
        match self {
            NotificationType::Threat => "威胁",
            NotificationType::Block => "拦截",
            NotificationType::Safe => "安全",
            NotificationType::Info => "信息",
        }
    }
}

/// 通知操作按钮
#[derive(Debug, Clone)]
pub struct NotificationAction {
    pub label: String,
    pub argument: String,
}

/// 通知选项
#[derive(Debug, Clone)]
pub struct NotificationOptions {
    pub notification_type: NotificationType,
    pub source: NotificationSource,
    pub title: String,
    pub body: String,
    pub file_name: String,
    pub file_path: String,
    pub resp_pipe: Option<String>,
    pub notification_id: String,
    pub actions: Vec<NotificationAction>,
}

lazy_static::lazy_static! {
    /// 记录每个通知是否已做出决策，避免重复写入响应管道
    static ref NOTIFICATION_DECISIONS: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    /// 保持 ToastNotification 对象存活，否则事件处理器会在函数返回后被释放
    static ref ACTIVE_TOASTS: Mutex<HashMap<String, ToastNotification>> = Mutex::new(HashMap::new());
    /// 最近通知时间戳，按文件路径去重，避免同一进程反复触发多个通知
    static ref RECENT_NOTIFICATIONS: Mutex<HashMap<String, std::time::Instant>> = Mutex::new(HashMap::new());
}

impl NotificationOptions {
    pub fn new(notification_type: NotificationType, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            notification_type,
            source: NotificationSource::Basic,
            title: title.into(),
            body: body.into(),
            file_name: String::new(),
            file_path: String::new(),
            resp_pipe: None,
            notification_id: format!("xigua_{}_{}", chrono::Local::now().timestamp_millis(), rand::random::<u32>()),
            actions: Vec::new(),
        }
    }

    pub fn with_source(mut self, source: NotificationSource) -> Self {
        self.source = source;
        self
    }

    pub fn with_file(mut self, file_name: impl Into<String>, file_path: impl Into<String>) -> Self {
        self.file_name = file_name.into();
        self.file_path = file_path.into();
        self
    }

    pub fn with_resp_pipe(mut self, resp_pipe: impl Into<String>) -> Self {
        self.resp_pipe = Some(resp_pipe.into());
        self
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.notification_id = id.into();
        self
    }

    pub fn with_action(mut self, label: impl Into<String>, argument: impl Into<String>) -> Self {
        self.actions.push(NotificationAction {
            label: label.into(),
            argument: argument.into(),
        });
        self
    }
}

/// 发送安全通知（Windows 原生 Toast，失败回退到 Tauri 通知）
pub fn show_security_notification(app: &AppHandle, options: NotificationOptions) -> Result<(), String> {
    #[cfg(windows)]
    {
        match show_winrt_toast(app, &options) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("[SecurityNotification] WinRT toast failed: {}, fallback to Tauri notification", e);
            }
        }
    }

    fallback_to_tauri_notification(app, &options)
}

/// 简化版：只发送标题和内容
pub fn show_security_notification_simple(
    app: &AppHandle,
    notification_type: NotificationType,
    title: &str,
    body: &str,
) -> Result<(), String> {
    show_security_notification(app, NotificationOptions::new(notification_type, title, body))
}

#[cfg(windows)]
fn show_winrt_toast(app: &AppHandle, options: &NotificationOptions) -> Result<(), String> {
    // 按文件路径去重：5 秒内同一文件路径只弹一次通知
    if !options.file_path.is_empty() {
        let now = std::time::Instant::now();
        let cooldown = std::time::Duration::from_secs(5);
        let mut recent = RECENT_NOTIFICATIONS.lock().unwrap();
        recent.retain(|_, t| now.duration_since(*t) < cooldown * 2);
        if let Some(last) = recent.get(&options.file_path) {
            if now.duration_since(*last) < cooldown {
                println!("[SecurityNotification] Suppressing duplicate notification for path: {}", options.file_path);
                return Ok(());
            }
        }
        recent.insert(options.file_path.clone(), now);
    }

    // 确保 AppUserModelID 已设置，否则通知可能不显示应用图标
    unsafe {
        use windows::Win32::System::Com::CoInitialize;
        use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
        let _ = CoInitialize(None);
        let _ = SetCurrentProcessExplicitAppUserModelID(&HSTRING::from("XIGUASecurity.App"));
    }

    let xml_doc = build_toast_xml(options)?;
    let toast = ToastNotification::CreateToastNotification(&xml_doc)
        .map_err(|e| format!("CreateToastNotification failed: {}", e))?;

    // 为每个通知设置唯一 tag 和 group，避免 Windows 合并/抑制重复通知
    let tag = format!("xigua_{}_{}", chrono::Local::now().timestamp_millis(), rand::random::<u32>());
    let _ = toast.SetTag(&HSTRING::from(&tag));
    let _ = toast.SetGroup(&HSTRING::from("xigua_security"));

    // 高优先级，确保通知能立即弹出
    let _ = toast.SetPriority(ToastNotificationPriority::High);

    let id = options.notification_id.clone();
    NOTIFICATION_DECISIONS.lock().unwrap().insert(id.clone(), false);

    // 绑定按钮点击事件
    #[cfg(not(feature = "ms_store"))]
    {
        let app_clone = app.clone();
        let id_clone = id.clone();
        let resp_pipe = options.resp_pipe.clone();
        let handler = TypedEventHandler::<ToastNotification, IInspectable>::new(
            move |_toast, args| {
                handle_toast_activated(&app_clone, args.as_ref(), &id_clone, resp_pipe.as_deref());
                Ok(())
            }
        );
        let _ = toast.Activated(&handler);
    }

    // Driver 场景：用户关闭/滑走通知后若未决策则自动拦截
    #[cfg(not(feature = "ms_store"))]
    if options.source == NotificationSource::Driver {
        if let Some(ref resp_pipe) = options.resp_pipe {
            let app_clone = app.clone();
            let id_clone = id.clone();
            let resp_pipe_clone = resp_pipe.clone();
            let handler = TypedEventHandler::<ToastNotification, ToastDismissedEventArgs>::new(
                move |_toast, args| {
                    handle_toast_dismissed(&app_clone, args.as_ref(), &id_clone, &resp_pipe_clone);
                    Ok(())
                }
            );
            let _ = toast.Dismissed(&handler);
        }
    }

    // Driver 场景：25 秒后若未决策则自动拦截
    #[cfg(not(feature = "ms_store"))]
    if options.source == NotificationSource::Driver {
        if let Some(ref resp_pipe) = options.resp_pipe {
            let app_clone = app.clone();
            let id_clone = id.clone();
            let resp_pipe_clone = resp_pipe.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(25));
                let mut decisions = NOTIFICATION_DECISIONS.lock().unwrap();
                if let Some(made) = decisions.get(&id_clone).copied() {
                    if !made {
                        println!("[SecurityNotification] Auto-block after timeout: {}", id_clone);
                        crate::apply_intercept_decision(&app_clone, "block", &resp_pipe_clone);
                        decisions.insert(id_clone.clone(), true);
                    }
                }
                decisions.remove(&id_clone);
                drop(decisions);
                release_toast(&id_clone);
            });
        }
    }

    // Basic 场景：30 秒后清理决策记录
    #[cfg(not(feature = "ms_store"))]
    if options.source == NotificationSource::Basic {
        let id_clone = id.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30));
            NOTIFICATION_DECISIONS.lock().unwrap().remove(&id_clone);
        });
    }

    let manager = ToastNotificationManager::GetDefault()
        .map_err(|e| format!("GetDefault failed: {}", e))?;
    let notifier = manager.CreateToastNotifierWithId(&HSTRING::from("XIGUASecurity.App"))
        .map_err(|e| format!("CreateToastNotifierWithId failed: {}", e))?;

    notifier.Show(&toast)
        .map_err(|e| format!("Show toast failed: {}", e))?;

    // 保持 ToastNotification 存活，确保 Activated / Dismissed 事件能被触发
    ACTIVE_TOASTS.lock().unwrap().insert(id.clone(), toast);
    Ok(())
}

#[cfg(all(windows, not(feature = "ms_store")))]
fn handle_toast_activated(app: &AppHandle, args: Option<&IInspectable>, id: &str, resp_pipe: Option<&str>) {
    println!("[SecurityNotification] Toast activated handler called: id={}", id);
    let Some(args) = args else {
        println!("[SecurityNotification] Activated args is None");
        return;
    };
    let Ok(activated_args) = args.cast::<ToastActivatedEventArgs>() else {
        println!("[SecurityNotification] Failed to cast activated args to ToastActivatedEventArgs");
        return;
    };
    let Ok(argument) = activated_args.Arguments() else {
        println!("[SecurityNotification] Failed to get Arguments from activated args");
        return;
    };
    let argument = argument.to_string();
    println!("[SecurityNotification] Toast activated: id={}, argument={}", id, argument);

    let mut decisions = NOTIFICATION_DECISIONS.lock().unwrap();
    if decisions.get(id).copied().unwrap_or(true) {
        return;
    }

    if argument == "xigua://notification/allow" {
        if let Some(pipe) = resp_pipe {
            crate::apply_intercept_decision(app, "allow", pipe);
            decisions.insert(id.to_string(), true);
        }
    } else if argument == "xigua://notification/block" {
        if let Some(pipe) = resp_pipe {
            crate::apply_intercept_decision(app, "block", pipe);
            decisions.insert(id.to_string(), true);
        }
    } else if argument.starts_with("xigua://notification/confirm") {
        decisions.insert(id.to_string(), true);
    }
    drop(decisions);
    release_toast(id);
}

/// 通知生命周期结束后从存活缓存中移除
#[cfg(all(windows, not(feature = "ms_store")))]
fn release_toast(id: &str) {
    ACTIVE_TOASTS.lock().unwrap().remove(id);
}

#[cfg(all(windows, not(feature = "ms_store")))]
fn handle_toast_dismissed(app: &AppHandle, args: Option<&ToastDismissedEventArgs>, id: &str, resp_pipe: &str) {
    let Some(_args) = args else {
        return;
    };
    println!("[SecurityNotification] Toast dismissed: id={}", id);

    let mut decisions = NOTIFICATION_DECISIONS.lock().unwrap();
    if decisions.get(id).copied().unwrap_or(true) {
        return;
    }

    if !resp_pipe.is_empty() {
        crate::apply_intercept_decision(app, "block", resp_pipe);
    }
    decisions.insert(id.to_string(), true);
    drop(decisions);
    release_toast(id);
}

#[cfg(windows)]
fn build_toast_xml(options: &NotificationOptions) -> Result<XmlDocument, String> {
    let icon_path = find_notification_icon();

    // 应用 Logo 覆盖：如果找到图标就显式指定，否则依赖 AppUserModelID 的默认图标
    let logo_xml = icon_path.as_ref().map(|path| {
        let file_uri = path_to_file_uri(path);
        format!(
            r#"<image placement="appLogoOverride" hint-crop="circle" src="{}" alt="{}"/>"#,
            xml_escape(&file_uri),
            options.notification_type.alt_text()
        )
    }).unwrap_or_default();

    // 正文：标题 / 文件 / 路径，以及调用方提供的额外说明（如脚本命令行）
    let mut body_lines = vec![format!("<text>{}</text>", xml_escape(&options.title))];
    if !options.file_name.is_empty() {
        body_lines.push(format!("<text>文件: {}</text>", xml_escape(&options.file_name)));
    }
    if !options.file_path.is_empty() {
        body_lines.push(format!("<text>路径: {}</text>", xml_escape(&options.file_path)));
    }
    // 附加 body 中的补充信息（按行拆分，最多再显示 3 行，避免通知过长）
    if !options.body.is_empty() {
        for line in options.body.lines().take(3) {
            body_lines.push(format!("<text>{}</text>", xml_escape(line.trim())));
        }
    }
    let body_xml = body_lines.join("\n      ");

    // 操作按钮：如果调用方自定义了按钮则优先使用，否则按来源生成默认按钮
    let actions_xml = if !options.actions.is_empty() {
        options.actions.iter().map(|action| {
            format!(r#"<action content="{}" arguments="{}"/>"#, xml_escape(&action.label), xml_escape(&action.argument))
        }).collect::<String>()
    } else {
        match options.source {
            NotificationSource::Basic => {
                let argument = format!("xigua://notification/confirm?id={}", options.notification_id);
                format!(
                    r#"<action content="确认" arguments="{}"/>"#,
                    xml_escape(&argument)
                )
            }
            NotificationSource::Driver => {
                if options.resp_pipe.as_deref().filter(|p| !p.is_empty()).is_some() {
                    format!(
                        r#"<action content="允许" arguments="xigua://notification/allow"/><action content="拦截" arguments="xigua://notification/block"/>"#
                    )
                } else {
                    let argument = format!("xigua://notification/confirm?id={}", options.notification_id);
                    format!(
                        r#"<action content="确认" arguments="{}"/>"#,
                        xml_escape(&argument)
                    )
                }
            }
        }
    };

    let payload = format!(
        r#"<toast launch="type={}" duration="long">
  <visual>
    <binding template="ToastGeneric">
      {}
      {}
    </binding>
  </visual>
  <actions>
    {}
  </actions>
</toast>"#,
        options.notification_type.as_str(),
        body_xml,
        logo_xml,
        actions_xml
    );

    let xml_doc = XmlDocument::new()
        .map_err(|e| format!("XmlDocument::new failed: {}", e))?;
    xml_doc.LoadXml(&HSTRING::from(&payload))
        .map_err(|e| format!("LoadXml failed: {}\nPayload: {}", e, payload))?;

    Ok(xml_doc)
}

#[cfg(windows)]
fn find_notification_icon() -> Option<String> {
    // 打包/安装后的路径：exe 同级 icons/icon.png
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let installed = dir.join("icons").join("icon.png");
            if installed.exists() {
                return Some(installed.to_string_lossy().to_string());
            }

            // 开发调试路径：向上查找项目根目录下的 src-tauri/icons/icon.png
            let mut cur = dir.to_path_buf();
            for _ in 0..6 {
                if let Some(parent) = cur.parent() {
                    cur = parent.to_path_buf();
                    let dev = cur.join("src-tauri").join("icons").join("icon.png");
                    if dev.exists() {
                        return Some(dev.to_string_lossy().to_string());
                    }
                } else {
                    break;
                }
            }
        }
    }

    None
}

#[cfg(windows)]
fn path_to_file_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("file:///") {
        normalized
    } else {
        format!("file:///{}", normalized.trim_start_matches('/'))
    }
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn fallback_to_tauri_notification(app: &AppHandle, options: &NotificationOptions) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;

    let body = if !options.file_name.is_empty() || !options.file_path.is_empty() {
        let mut lines = vec![options.title.clone()];
        if !options.file_name.is_empty() {
            lines.push(format!("文件: {}", options.file_name));
        }
        if !options.file_path.is_empty() {
            lines.push(format!("路径: {}", options.file_path));
        }
        lines.join("\n")
    } else {
        options.body.clone()
    };

    app.notification()
        .builder()
        .title(&options.title)
        .body(&body)
        .show()
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn show_winrt_toast(_app: &AppHandle, _options: &NotificationOptions) -> Result<(), String> {
    Err("WinRT toast only available on Windows".to_string())
}
