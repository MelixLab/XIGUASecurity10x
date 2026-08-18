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

XIGUASecurity 10x is a next-generation antivirus software featuring:

- **AI-Powered Scanning**: Deep learning model (ONNX) for malware detection with 283-dimensional feature extraction
- **Real-time Protection**: MiniFilter driver for active file system protection
- **Multi-language Support**: English, Simplified Chinese, Traditional Chinese
- **Customizable UI**: Anime-style themes with opacity, background, and icon customization
- **Process Management**: View and manage running processes
- **Multiple Scan Modes**: Quick scan, full scan, and custom directory scan

### Features

| Feature | Description |
|---------|-------------|
| AI Scanning | ONNX-based deep learning model with 90%+ detection accuracy |
| Real-time Protection | MiniFilter driver intercepts suspicious file operations |
| Customizable UI | Opacity slider, custom backgrounds, status icons |
| Multi-language | EN / 简中 / 繁中 |
| Fast Scanning | Batch processing with optimized performance |
| Process Manager | View and terminate processes |

### Tech Stack

- **Frontend**: Tauri 2.0 + TypeScript + Vite
- **Backend**: Rust
- **AI Engine**: ONNX Runtime with custom Melix model
- **Driver**: Windows MiniFilter (ProcessFilter.sys)
- **Communication**: TCP socket (port 9527)

### Project Structure

```
XIGUASecurity10x/
├── antivirus-ui/          # Tauri frontend application
│   ├── src/              # TypeScript source files
│   └── src-tauri/        # Rust backend + ONNX engine
├── MiniFilter/           # Driver source and tools
│   ├── ProcessFilter.sys # Signed MiniFilter driver
│   └── SimpleLauncher.c  # Driver communication tool
├── Driver/               # Release driver binaries
├── Melix-New/            # ML.NET training project
└── Release/              # Release builds
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

XIGUASecurity 10x 是一款下一代杀毒软件，具有以下特性：

- **AI 驱动扫描**: 基于深度学习的 ONNX 模型，使用 283 维特征提取
- **实时防护**: MiniFilter 驱动主动防护文件系统
- **多语言支持**: 英文、简体中文、繁体中文
- **可定制界面**: 二次元风格主题，支持透明度、背景和图标自定义
- **进程管理**: 查看和管理运行中的进程
- **多种扫描模式**: 快速扫描、全盘扫描、自定义目录扫描

### 功能特性

| 功能 | 描述 |
|------|------|
| AI 扫描 | 基于 ONNX 的深度学习模型，检测准确率 90%+ |
| 实时防护 | MiniFilter 驱动拦截可疑文件操作 |
| 界面定制 | 透明度滑块、自定义背景、状态图标 |
| 多语言 | 英文 / 简中 / 繁中 |
| 快速扫描 | 批量处理，性能优化 |
| 进程管理 | 查看和终止进程 |

### 技术栈

- **前端**: Tauri 2.0 + TypeScript + Vite
- **后端**: Rust
- **AI 引擎**: ONNX Runtime + 自定义 Melix 模型
- **驱动**: Windows MiniFilter (ProcessFilter.sys)
- **通信**: TCP 套接字 (端口 9527)

### 项目结构

```
XIGUASecurity10x/
├── antivirus-ui/          # Tauri 前端应用
│   ├── src/              # TypeScript 源文件
│   └── src-tauri/        # Rust 后端 + ONNX 引擎
├── MiniFilter/           # 驱动源码和工具
│   ├── ProcessFilter.sys # 签名的 MiniFilter 驱动
│   └── SimpleLauncher.c  # 驱动通信工具
├── Driver/               # 发布版驱动二进制文件
├── Melix-New/            # ML.NET 训练项目
└── Release/              # 发布版本
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
