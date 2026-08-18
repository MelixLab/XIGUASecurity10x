---
name: "xigua-security-dev"
description: "XIGUA Security 10x 项目开发助手。包含项目结构、Sandboxie 集成、Tauri 打包等所有技术细节。Invoke when working on XIGUASecurity10x project, especially for sandbox functionality, Tauri builds, or debugging packaged versions."
---

# XIGUA Security 10x 开发助手

## 项目结构

```
XIGUASecurity10x/
├── antivirus-ui/              # Tauri + Vue 前端
│   ├── src-tauri/src/lib.rs   # 主 Rust 代码
│   ├── src/                   # Vue 前端代码
│   ├── dist/                  # 构建输出
│   └── sandbox-monitor.html   # 沙盒监控独立页面
├── SandBoxie/                 # Sandboxie 便携版
│   ├── Sandboxie.ini          # 配置文件（已简化，无中文）
│   ├── Start.exe              # 启动沙盒
│   ├── SbieIni.exe            # IPC 配置工具
│   └── KmdUtil.exe            # 服务管理
├── Release/                   # 发布目录
├── Sandbox/                   # 沙盒文件存储
└── HeySandbox-source-*/       # 参考实现（HEY 沙盒）
```

## 当前进行中的工作

### 1. 沙盒监控窗口问题（打包版本）
**状态**: 已修复，等待验证

**问题**:
- 打包版本中 `sandbox-monitor.html` 无法正确加载 Tauri API
- 显示"分析编号 unknown"
- 提示"分析已完成"但实际上还在运行
- 按钮无法点击

**解决方案**:
1. 通过 CDN 引入 Tauri API:
```html
<script type="module">
  import { invoke, listen } from 'https://cdn.jsdelivr.net/npm/@tauri-apps/api@2.0.0/core.js';
  window.tauriInvoke = invoke;
  window.tauriListen = listen;
</script>
```

2. 使用事件监听替代 URL 参数传递分析ID:
- 后端: `window.emit("set-analysis-id", analysis_id)`
- 前端: `tauriListen('set-analysis-id', callback)`

3. 优先使用模块导入的 API:
```javascript
async function tauriInvoke(cmd, args = {}) {
  if (window.tauriInvoke) {
    return await window.tauriInvoke(cmd, args);
  }
  if (window.__TAURI__ && window.__TAURI__.core) {
    return await window.__TAURI__.core.invoke(cmd, args);
  }
  throw new Error('Tauri API not available');
}
```

### 2. Sandboxie 配置方式（已采用 HEY 方案）
**状态**: 已完成

**关键改动**:
1. 使用 `SbieIni.exe` IPC 方式配置，不直接写 ini 文件
2. 纯 ASCII 配置，无中文注释
3. 禁用自动更新 Sandboxie.ini 的逻辑

**配置项**:
```rust
let box_settings = [
    ("Enabled", "y"),
    ("AutoDelete", "n"),
    ("BlockNetworkFiles", "y"),
    ("ConfigLevel", "10"),
    ("BorderColor", "#00FFFF,ttl"),
    ("FileTrace", "wcd"),
    ("KeyTrace", "wcd"),
    ("PipeTrace", "w"),
    ("IpcTrace", "w"),
    ("NetFwTrace", "*"),
    ("TraceBufferPages", "2560"),
];
```

### 3. 已移除的功能
- 窗口关闭时自动停止沙盒（命令参数有误）
- 自动更新 Sandboxie.ini 的 FileRootPath

## 技术细节

### Tauri 配置
```json
{
  "build": {
    "withGlobalTauri": true  // 启用全局 Tauri API
  }
}
```

### Sandboxie 服务管理
```rust
// 启动服务
Command::new(&kmdutil).args(["start", "SbieSvc"])

// 安装服务（如需要）
Command::new(&kmdutil).args(["install", "SbieSvc", "path/to/SbieSvc.exe"])
Command::new(&kmdutil).args(["install", "SbieDrv", "path/to/SbieDrv.sys"])
```

### 沙盒名称配置
- 默认: "DefaultBox"
- 可通过环境变量 `SANDBOXIE_BOX_NAME` 自定义
- 存储在 `SANDBOX_STATE.box_name`

## 常见错误及解决方案

### 1. SBIE1405 配置文件错误
**原因**: 中文注释或特殊字符
**解决**: 使用纯 ASCII 配置，删除所有中文注释

### 2. C000000D 无效参数
**原因**: 配置文件格式错误或缺少必要字段
**解决**: 确保 `[GlobalSettings]` 在文件开头，包含 `FileRootPath`

### 3. 分析编号 unknown
**原因**: Tauri API 未加载或 URL 参数未传递
**解决**: 使用 CDN 引入 API，通过事件传递数据

### 4. 无效的沙箱名参数
**原因**: `/box:DefaultBox /terminate` 命令格式错误
**解决**: 已移除自动停止功能，改为手动停止

## 构建命令

```bash
# 开发模式
npm run tauri dev

# 发布构建
npm run build
npm run tauri build

# 复制到 Release 目录
copy target\release\XIGUASecurity.exe ..\Release\
copy target\release\bundle\nsis\XIGUASecurity_*.exe ..\Release\
```

## 关键文件位置

- 主程序: `antivirus-ui/src-tauri/src/lib.rs`
- 沙盒监控页面: `antivirus-ui/sandbox-monitor.html`
- Tauri 配置: `antivirus-ui/src-tauri/tauri.conf.json`
- Sandboxie 配置: `SandBoxie/Sandboxie.ini`

## 调试技巧

1. **检查 Tauri API 是否可用**:
   ```javascript
   console.log(window.__TAURI__);
   console.log(window.tauriInvoke);
   ```

2. **检查 Sandboxie 服务状态**:
   ```powershell
   sc query SbieSvc
   ```

3. **手动测试 SbieIni**:
   ```powershell
   .\SbieIni.exe query DefaultBox Enabled
   ```

## 下一步工作（待确认）

1. 验证打包版本是否正常工作
2. 如有问题，考虑使用 HEY 的完整方案（官方安装包 + PowerShell 脚本）
3. 优化沙盒监控窗口的 UI/UX
