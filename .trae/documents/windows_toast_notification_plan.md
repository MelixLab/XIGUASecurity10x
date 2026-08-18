# Windows 原生 Toast 通知重构计划

## Context

当前软件使用 `tauri-plugin-notification` 发送系统通知，样式受系统限制：
- Windows 下经常不显示应用图标，只显示通用铃铛
- 无法自定义颜色、大图标、操作按钮
- 不适合杀毒软件的威胁/拦截/安全等状态展示

用户要求重新实现通知系统，支持图标和更适合杀毒软件的样式。

## Recommended Approach

使用 **Windows 原生 Toast Notification API**（`windows::UI::Notifications`）替代 Tauri 默认通知。

原因：
- 是系统级通知，稳定、不被游戏/勿扰模式屏蔽
- 支持应用 Logo、大图标、标题、内容、操作按钮
- 支持不同视觉状态（威胁红、拦截黄、安全绿、信息蓝）
- 不需要额外 crate，使用项目已有的 `windows` crate

## Implementation Steps

### 1. 启用 Windows Toast API

文件：`antivirus-ui/src-tauri/Cargo.toml`

在 `[target.'cfg(windows)'.dependencies]` 的 `windows` features 中追加 `UI_Notifications`。

### 2. 创建统一通知模块

文件：`antivirus-ui/src-tauri/src/notification.rs`（新建）

实现：
- `show_security_notification(app_handle, notification_type, title, body, options)`
- 通知类型：
  - `threat` — 红色主题，盾牌/病毒图标
  - `block` — 黄色主题，警告图标
  - `safe` — 绿色主题，对勾图标
  - `info` — 蓝色主题，信息图标
- 使用 `ToastNotificationManager::GetDefault()` 获取管理器
- 使用 `CreateToastNotifierWithId("XIGUASecurity.App")` 创建通知器
- 构造 Toast XML payload，包含：
  - 应用 Logo（自动从 AppUserModelID 获取）
  - 大图标（使用 `src-tauri/icons/` 下的图标，按类型选择）
  - 标题、内容
  - 可选操作按钮（如「查看详情」「忽略」）
- 错误时回退到 Tauri 通知插件，避免完全失效

### 3. 替换现有通知调用

文件：`antivirus-ui/src-tauri/src/lib.rs`

- 将 `send_intercept_notification` 改为调用新通知模块
- 将 `send_threat_notification`、`send_edr_notification` 的通知部分改为调用新模块（弹窗保留，Toast 作为补充）
- 更新 `send_simple_notification`：优先使用 Toast，失败再回退 MessageBox

文件：`antivirus-ui/src-tauri/src/script_protection.rs`

- 将 `send_native_notification` 替换为调用新通知模块

### 4. 前端调用调整

文件：`antivirus-ui/src/main.ts`

- `sendInterceptNotification` 增加 `notification_type` 参数（当前为 `warning`，改为 `block`）
- 其他调用通知的地方按需传入类型

### 5. 图标资源

复用现有 `src-tauri/icons/icon.png` 作为默认图标。若需要按类型区分的图标，可先用不同颜色滤镜的同一图标，后续再补充独立资源。

## Critical Files

- `antivirus-ui/src-tauri/Cargo.toml`
- `antivirus-ui/src-tauri/src/notification.rs`（新建）
- `antivirus-ui/src-tauri/src/lib.rs`
- `antivirus-ui/src-tauri/src/script_protection.rs`
- `antivirus-ui/src/main.ts`

## Verification

1. 运行 `npm run tauri build` 或 `cargo build` 验证编译通过
2. 触发一次驱动拦截或脚本防护，检查右下角 Toast 通知：
   - 是否显示 XIGUASecurity 应用图标
   - 是否显示大图标
   - 标题和内容是否正确
3. 测试不同通知类型的视觉区分
