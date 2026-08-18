# 通知模式实现计划

## 1. 摘要

在软件设置中提供「通知模式」开关。开启后，**驱动防护 / 基础防护**的拦截事件不再弹出拦截窗口，仅通过 Windows 原生 Toast 通知提示；文件防护、EDR 等其他弹窗保持原样。通知内容简化为三行文本（防护类型、文件名、路径），按钮按场景区分：

- **基础防护**：进程已被终止，仅显示「确认」按钮。
- **驱动防护**：显示「允许」「拦截」按钮；通知消失（超时或被用户关闭）后若未点「允许」，自动执行拦截。

## 2. 当前状态分析

### 2.1 已具备的骨架

- Rust 端已有全局状态 `NOTIFICATION_MODE_ENABLED` 和命令 `set_notification_mode_enabled`（[lib.rs:114](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/lib.rs#L114)、[lib.rs:4846](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/lib.rs#L4846)）。
- Rust 端已提取 `apply_intercept_decision` 供 Toast 激活回调复用（[lib.rs:4799](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/lib.rs#L4799)）。
- `notification.rs` 已定义 `NotificationSource::Basic / Driver`、25 秒超时自动拦截、以及 3 行正文结构（[notification.rs:31](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/notification.rs#L31)、[notification.rs:195](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/notification.rs#L195)、[notification.rs:282](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/notification.rs#L282)）。
- 前端已有 `NotificationModeManager` 类、设置页 checkbox、以及 `sendInterceptNotification`（[main.ts:448](file:///D:/XIGUASecurity10x/antivirus-ui/src/main.ts#L448)、[main.ts:10135](file:///D:/XIGUASecurity10x/antivirus-ui/src/main.ts#L10135)、[main.ts:3427](file:///D:/XIGUASecurity10x/antivirus-ui/src/main.ts#L3427)）。
- 驱动防护的决策路径 `do_process_scan` 已根据通知模式选择弹窗或 Toast（[lib.rs:1307](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/lib.rs#L1307)）。

### 2.2 仍需补全的缺口

1. **通知「消失」未处理**：当前只处理了 25 秒超时自动拦截。用户手动关闭/滑走 Toast 时不会触发拦截，需要绑定 `Dismissed` 事件。
2. **通知正文仍可更简洁**：当前正文是 `驱动防护拦截 / 文件: xxx / 路径: xxx`，按用户要求应改为纯三行，不再加「文件:」「路径:」前缀。
3. **无 resp_pipe 的驱动通知行为不明确**：前端回调中某些驱动拦截日志只是「已阻止」的事后通知，没有 `resp_pipe`。这种场景下应退化为「确认」按钮，避免点击允许/拦截无效。
4. **前端传参可能传入空字符串**：`sendInterceptNotification` 会把 `respPipe || ''` 传给 Rust，Rust 会把空字符串当成 `Some("")`，可能导致 `apply_intercept_decision` 向空管道名写入。需要在 Rust 命令入口把空字符串转成 `None`。
5. **文件防护需确认不受影响**：文件防护走 `file-protection-event` → `handleThreat` → 独立的 `file-protection-alert.html`，未经过 `sendInterceptNotification`，逻辑上已隔离，但需在实现后复核。

## 3. 具体改动

### 3.1 `antivirus-ui/src-tauri/src/notification.rs`

#### 3.1.1 导入 `ToastDismissedEventArgs`

将现有的：

```rust
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager, ToastNotificationPriority, IToastActivatedEventArgs};
```

扩展为：

```rust
use windows::UI::Notifications::{
    ToastNotification, ToastNotificationManager, ToastNotificationPriority,
    IToastActivatedEventArgs, IToastDismissedEventArgs, ToastDismissalReason,
};
```

> 若 `ToastDismissalReason` 未暴露可用枚举，可直接监听 `Dismissed` 事件而不判断原因，任何消失都视为需自动拦截。

#### 3.1.2 绑定 `Dismissed` 事件（Driver 场景）

在 `show_winrt_toast` 中，对 `Driver` 来源且存在 `resp_pipe` 的通知，除了现有的 25 秒定时器，再绑定一次 `Dismissed` 事件：

```rust
if options.source == NotificationSource::Driver {
    if let Some(ref resp_pipe) = options.resp_pipe {
        let app_clone = app.clone();
        let id_clone = id.clone();
        let resp_pipe_clone = resp_pipe.clone();
        let handler = TypedEventHandler::<ToastNotification, IInspectable>::new(
            move |_toast, args| {
                handle_toast_dismissed(&app_clone, args, &id_clone, resp_pipe_clone.as_str());
                Ok(())
            }
        );
        let _ = toast.Dismissed(&handler);
    }
}
```

新增 `handle_toast_dismissed` 函数：

```rust
#[cfg(all(windows, not(feature = "ms_store")))]
fn handle_toast_dismissed(app: &AppHandle, args: &IInspectable, id: &str, resp_pipe: &str) {
    let Ok(_dismissed_args) = args.cast::<IToastDismissedEventArgs>() else {
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
}
```

> 说明：超时定时器和 `Dismissed` 事件都会尝试自动拦截，通过 `NOTIFICATION_DECISIONS` 保证只执行一次。

#### 3.1.3 简化通知正文

修改 `build_toast_xml` 中的 `body_lines` 生成逻辑：

```rust
let mut body_lines = vec![format!("<text>{}</text>", xml_escape(&options.title))];
if !options.file_name.is_empty() {
    body_lines.push(format!("<text>{}</text>", xml_escape(&options.file_name)));
}
if !options.file_path.is_empty() {
    body_lines.push(format!("<text>{}</text>", xml_escape(&options.file_path)));
}
```

同时修改 `fallback_to_tauri_notification` 中的 fallback 文本，保持三行一致：

```rust
let body = if !options.file_name.is_empty() || !options.file_path.is_empty() {
    let mut lines = vec![options.title.clone()];
    if !options.file_name.is_empty() {
        lines.push(options.file_name.clone());
    }
    if !options.file_path.is_empty() {
        lines.push(options.file_path.clone());
    }
    lines.join("\n")
} else {
    options.body.clone()
};
```

#### 3.1.4 Driver 按钮在无 resp_pipe 时退化

在 `build_toast_xml` 的 `NotificationSource::Driver` 分支中，若 `resp_pipe` 为空，则不渲染允许/拦截按钮，而是渲染一个「确认」按钮：

```rust
NotificationSource::Driver => {
    if let Some(pipe) = options.resp_pipe.as_deref().filter(|p| !p.is_empty()) {
        let allow_arg = format!("xigua://notification/allow?id={}&pipe={}", options.notification_id, pipe);
        let block_arg = format!("xigua://notification/block?id={}&pipe={}", options.notification_id, pipe);
        format!(
            r#"<action content="允许" arguments="{}"/><action content="拦截" arguments="{}"/>"#,
            xml_escape(&allow_arg),
            xml_escape(&block_arg)
        )
    } else {
        let argument = format!("xigua://notification/confirm?id={}", options.notification_id);
        format!(
            r#"<action content="确认" arguments="{}"/>"#,
            xml_escape(&argument)
        )
    }
}
```

### 3.2 `antivirus-ui/src-tauri/src/lib.rs`

#### 3.2.1 `send_intercept_notification` 空字符串转 `None`

在命令入口把空字符串的 `resp_pipe` 视为 `None`：

```rust
if let Some(pipe) = resp_pipe {
    if !pipe.is_empty() {
        options = options.with_resp_pipe(pipe);
    }
}
```

避免 `apply_intercept_decision` 拿到空管道名。

#### 3.2.2 确保 `apply_intercept_decision` 安全

当前实现已在写入前判断 `if !resp_pipe_name.is_empty()`，无需改动；但保留该检查。

#### 3.2.3 复核 `do_process_scan` 的通知模式分支

当前逻辑已正确：

- 静默模式 / 无 resp_pipe → 直接 block。
- 通知模式开启 → 调用 `show_security_notification` 发 Toast，不再弹窗。
- 通知模式关闭 → 保持 `show_intercept_window_internal` 弹窗。

无需改动，但需确认 `INTERCEPT_INFO_MAP` 在通知模式下仍然写入（当前 [lib.rs:1301](file:///D:/XIGUASecurity10x/antivirus-ui/src-tauri/src/lib.rs#L1301) 已在分支前写入，满足要求）。

### 3.3 `antivirus-ui/src/main.ts`

#### 3.3.1 调整 `sendInterceptNotification` 的 respPipe 传参

把：

```typescript
respPipe: respPipe || ''
```

改为只在有值时传入，避免传空字符串：

```typescript
const payload: any = {
  title,
  body: log,
  notificationType,
  source: isBasicProtection ? 'basic' : 'driver',
  fileName,
  filePath,
};
if (respPipe) {
  payload.respPipe = respPipe;
}
await invoke('send_intercept_notification', payload);
```

#### 3.3.2 复核基础防护回调

当前 [main.ts:3325](file:///D:/XIGUASecurity10x/antivirus-ui/src/main.ts#L3325) 已调用 `this.sendInterceptNotification(log, 'basic')`，无需 resp_pipe。该路径会生成 `NotificationSource::Basic` 通知，仅显示「确认」。符合要求。

#### 3.3.3 复核驱动防护前端回调

当前 [main.ts:3301](file:///D:/XIGUASecurity10x/antivirus-ui/src/main.ts#L3301) 在「新拦截窗口关闭或静默模式」时，对 `已阻止` 日志调用 `this.sendInterceptNotification(log)`。这类日志代表驱动已完成拦截，没有 resp_pipe。经过 3.1.4 的退化处理后，通知会只显示「确认」，避免无效按钮。

真正需要用户决策的驱动拦截由 Rust 端 `do_process_scan` 处理，resp_pipe 存在，会显示「允许/拦截」。符合要求。

#### 3.3.4 确认文件防护不受通知模式影响

文件防护事件监听 [main.ts:1199](file:///D:/XIGUASecurity10x/antivirus-ui/src/main.ts#L1199) 直接调用 `handleThreat`，最终弹出 `file-protection-alert.html`，不经过 `sendInterceptNotification`。实现后需再次确认该路径未读取 `notificationModeManager`。

## 4. 假设与决策

1. **「通知消失」包含超时和用户关闭**：同时绑定 `Dismissed` 事件和 25 秒定时器，二者通过决策表去重。
2. **无 resp_pipe 的驱动通知退化为确认**：已阻止的驱动事件没有可交互的决策管道，显示允许/拦截会误导用户。
3. **文件防护继续弹窗**：通知模式只影响驱动/基础防护的拦截窗口，不影响文件隔离、EDR 等窗口。
4. **通知正文不再显示概率/病毒家族**：用户明确要求只保留三行基础信息，概率等细节留给后续点击「查看详情」或打开日志查看。

## 5. 验证步骤

1. `cargo tauri build` / `cargo check` 编译通过。
2. 关闭通知模式：触发驱动/基础防护拦截，仍弹出原有拦截窗口，Toast 通知不再重复显示或按钮正确。
3. 开启通知模式：
   - 触发基础防护拦截 → 弹出 Toast，三行文本（基础防护拦截 / 文件名 / 路径），一个「确认」按钮；无拦截窗口。
   - 触发驱动防护拦截 → 弹出 Toast，三行文本（驱动防护拦截 / 文件名 / 路径），「允许」「拦截」按钮；25 秒未操作或手动关闭后进程被拦截；点「允许」后进程放行。
   - 触发文件防护隔离 → 仍正常弹出 `file-protection-alert.html` 隔离窗口。
4. 重复触发同一类拦截，确认每次都能收到新 Toast（通知 tag 已使用唯一时间戳，不会被 Windows 合并）。
