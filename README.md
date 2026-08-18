# XIGUASecurity 10x

<div align="center">

<img src="new.png" width="128" height="128" alt="XIGUASecurity">

**A modern antivirus solution powered by AI and MiniFilter driver**

[English](#english) | [中文](#中文)

</div>

---

<a name="english"></a>
## English

### Overview

XIGUASecurity 10x is a next-generation antivirus software powered by the in-house Melix AI engine and kernel-mode KMDF drivers:

- **AI-Powered Detection**: Melix TreeEnsemble engine (pure Rust inference, EMBER V3 2568-dimension PE feature extraction), with AVModel (ONNX/ZeroEngine) as an alternative engine
- **Kernel-Mode Real-Time Protection**: Multiple KMDF MiniFilter drivers intercept process creation, registry writes, thread injection, ransomware behavior, and EDR endpoint events
- **Automatic Sandbox Analysis**: Unsigned executables run in Sandboxie with 60s of kernel-level behavior tracing, scored by 60+ IOA rules
- **EDR & Behavior Analysis**: ETW-based endpoint detection & response with threat classification and behavior-chain reports
- **Multi-Layer Scan Chain**: Signature rules + YARA + virus-family engine (SilverFox special) + script scanner + archive scanner + cloud hash lookup + cloud deep analysis
- **Multi-language Support**: English, Simplified Chinese, Traditional Chinese
- **Customizable UI**: Anime-style themes with opacity, background, and icon customization

### Features

| Feature | Description |
|---------|-------------|
| AI Engine | Melix TreeEnsemble (EMBER V3, 2568-dim) + AVModel (ONNX) fallback |
| Real-time Protection | KMDF drivers + WMI process monitoring |
| Sandbox Analysis | Sandboxie automation with IOA behavior scoring |
| Ransomware Protection | Driver callbacks + file backup & rollback |
| EDR Detection | ETW endpoint detection & response, behavior chain |
| Multiple Scan Modes | Quick / full / custom directory scan |
| System Tools | System repair, junk cleanup, process manager, popup interceptor |
| Multi-language | EN / 简中 / 繁中 |

### Tech Stack

- **Frontend**: Tauri 2.0 + TypeScript + Vite
- **Backend**: Rust
- **AI Engine**: Melix TreeEnsemble (pure Rust inference, EMBER V3 2568-dim) + AVModel (ONNX/ZeroEngine)
- **Drivers**: KMDF MiniFilter suite (XIGUASecurityAntiVirus.sys / XIGUAFileProtect.sys / XIGUASelfProtect.sys / XIGUAEndPoint.sys)
- **Service Layer**: AVSystem (XIGUASecurityAgent.exe), named pipe `\\.\pipe\AVSystemPipe` with HMAC-SHA256 authentication
- **Cloud Services**: AVIC intelligence center / cloud hash / Microstep cloud sandbox relay

### Project Structure

```
XIGUASecurity10x/
├── antivirus-ui/            # Tauri frontend + Rust backend (main app)
│   ├── src/                 # TypeScript source files
│   ├── src-tauri/src/       # Rust backend (lib.rs & 40+ modules)
│   └── src-tauri/engines/   # Melix local model
├── KMDF Driver/             # Kernel driver sources (process/registry/injection/ransom/EDR)
├── Melix-New/               # Melix AI training project
├── AVModel/                 # ONNX alternative engine
├── log-server/              # Cloud log/threat platform
├── rules_server/            # Rule update server
├── extensions/              # Browser protection extension
├── tools/                   # Helper scripts
└── docs/                    # Documentation
```

### Building from Source

#### Prerequisites

- Rust + Cargo
- Node.js + npm
- Visual Studio 2022 (for driver compilation)
- Windows SDK

#### Build Steps

```bash
# Clone repository
git clone https://github.com/MelixLab/XIGUASecurity10x.git
cd XIGUASecurity10x

# Install dependencies
cd antivirus-ui
npm install

# Run in development mode
npm run tauri dev

# Build release version
npm run tauri build
```

### Usage

1. **Scanning**: Click "Quick Scan" or "Custom Scan" to scan files
2. **Real-time Protection**: Enable driver protection in Settings
3. **Customization**: Adjust opacity, background, and icons in Settings
4. **Process Management**: View and manage running processes

### License

XIGUASecurity Non-Commercial License v1.0 — Non-commercial use only. Redistribution and derivative publication require explicit written permission from the author. See [LICENSE](LICENSE) file for details.

---

<a name="中文"></a>
## 中文

### 简介

XIGUASecurity 10x（西瓜杀毒）是一款由自研 Melix AI 引擎与内核驱动驱动的下一代杀毒软件：

- **AI 检测引擎**: Melix TreeEnsemble（纯 Rust 推理，EMBER V3 2568 维 PE 特征提取），另有 AVModel（ONNX/ZeroEngine）备选引擎
- **内核级实时防护**: 多套 KMDF MiniFilter 驱动，拦截进程创建、注册表写入、线程注入、勒索行为与 EDR 端点事件
- **自动沙盒分析**: 未签名可执行文件在 Sandboxie 中自动运行，60 秒内核级行为跟踪，60+ 条 IOA 规则评分
- **EDR 行为分析**: 基于 ETW 的端点检测与响应，威胁分类与行为链报告
- **多层检测链**: 特征码 + YARA + 病毒家族引擎（银狐专项）+ 脚本扫描 + 压缩包扫描 + 云端哈希 + 云端深度分析
- **多语言支持**: 英文、简体中文、繁体中文
- **可定制界面**: 二次元风格主题，支持透明度、背景和图标自定义

### 功能特性

| 功能 | 描述 |
|------|------|
| AI 引擎 | Melix TreeEnsemble（EMBER V3 2568 维特征）+ AVModel（ONNX）备选 |
| 实时防护 | KMDF 驱动 + WMI 进程监控 |
| 沙盒分析 | Sandboxie 自动化 + IOA 行为评分 |
| 勒索防护 | 驱动回调 + 文件备份与回滚 |
| EDR 检测 | ETW 端点检测与响应、行为链 |
| 多模式扫描 | 快速 / 全盘 / 自定义目录扫描 |
| 系统工具 | 系统修复、垃圾清理、进程管理、弹窗拦截 |
| 多语言 | 英文 / 简中 / 繁中 |

### 技术栈

- **前端**: Tauri 2.0 + TypeScript + Vite
- **后端**: Rust
- **AI 引擎**: Melix TreeEnsemble（纯 Rust 推理，EMBER V3 2568 维）+ AVModel（ONNX/ZeroEngine）
- **驱动**: KMDF MiniFilter 套件（XIGUASecurityAntiVirus.sys / XIGUAFileProtect.sys / XIGUASelfProtect.sys / XIGUAEndPoint.sys）
- **服务层**: AVSystem（XIGUASecurityAgent.exe），命名管道 `\\.\pipe\AVSystemPipe`，HMAC-SHA256 鉴权
- **云服务**: AVIC 情报中心 / 云哈希库 / 微步云沙箱中转

### 项目结构

```
XIGUASecurity10x/
├── antivirus-ui/            # Tauri 前端 + Rust 后端（主程序）
│   ├── src/                 # TypeScript 源文件
│   ├── src-tauri/src/       # Rust 后端（lib.rs 及 40+ 功能模块）
│   └── src-tauri/engines/   # Melix 本地模型
├── KMDF Driver/             # 内核驱动源码（进程/注册表/注入/勒索/EDR）
├── Melix-New/               # Melix AI 训练工程
├── AVModel/                 # ONNX 备选引擎
├── log-server/              # 云端日志/威胁平台
├── rules_server/            # 规则更新服务器
├── extensions/              # 浏览器防护扩展
├── tools/                   # 辅助脚本工具
└── docs/                    # 文档
```

### 从源码构建

#### 前置要求

- Rust + Cargo
- Node.js + npm
- Visual Studio 2022（用于驱动编译）
- Windows SDK

#### 构建步骤

```bash
# 克隆仓库
git clone https://github.com/MelixLab/XIGUASecurity10x.git
cd XIGUASecurity10x

# 安装依赖
cd antivirus-ui
npm install

# 开发模式运行
npm run tauri dev

# 构建发布版本
npm run tauri build
```

### 使用方法

1. **扫描**: 点击"快速扫描"或"自定义扫描"扫描文件
2. **实时防护**: 在设置中启用驱动防护
3. **界面定制**: 在设置中调整透明度、背景和图标
4. **进程管理**: 查看和管理运行中的进程

### 许可证

XIGUASecurity 非商业许可证 v1.0 — 仅限非商业使用。再分发与衍生作品发布须获得作者明确书面许可。详见 [LICENSE](LICENSE) 文件。
