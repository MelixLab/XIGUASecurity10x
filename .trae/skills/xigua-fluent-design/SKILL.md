---
name: "xigua-fluent-design"
description: "Defines the minimalist Fluent Design system for XIGUASecurity10x UI. Invoke when designing or implementing any interface, component, window, dialog, alert, or visual update in the project."
---

# XIGUA Fluent Design System

为 `XIGUASecurity10x` 定义的简约 Fluent Design 设计体系。所有与界面、交互、视觉相关的实现都必须遵循本文档。

## 1. 核心理念

- **安全感与信任感**：界面应传递稳定、可靠、专业的安全产品气质，避免过度娱乐化。
- **内容优先**：减少装饰元素，让威胁信息、扫描结果、状态提示成为视觉焦点。
- **原生 Windows 体验**：与 Windows 11 设计语言保持一致，使用 Mica/Acrylic、Segoe UI Variable、系统圆角。
- **克制的高效**：动效、颜色、阴影都应为功能服务，不喧宾夺主。

## 2. 设计原则

| 原则 | 说明 |
|------|------|
| **清晰 (Clear)** | 信息层级明确，用户一眼可知当前状态与下一步操作。 |
| **简约 (Minimal)** | 每个像素都应有目的，删除不必要的线条、边框、图标。 |
| **流畅 (Fluid)** | 状态切换使用 subtle 的过渡动画，增强反馈但不打扰。 |
| **一致 (Consistent)** | 同类型组件在所有窗口（主界面、弹窗、托盘、时间线）中表现一致。 |
| **可信 (Trustworthy)** | 使用冷静的中性色与克制的品牌色，避免刺眼的高饱和色。 |

## 3. 视觉规范

### 3.1 颜色体系

#### 背景
- **主窗口背景**：`#F3F3F3`（浅色模式）/ `#202020`（深色模式），配合 Mica/Acrylic 材质。
- **卡片/面板背景**：`#FFFFFF` 80% 不透明度（浅色）/ `#2D2D2D` 80%（深色）。
- **浮层/弹窗背景**：Acrylic (`#FCFCFC` / `#2C2C2C` 配合背景模糊)。

#### 文本
- **主标题**：`#1A1A1A` / `#FFFFFF`，Font Weight 600，Size 20px。
- **正文**：`#1F1F1F` / `#E6E6E6`，Font Weight 400，Size 14px。
- **次要文本**：`#5F5F5F` / `#A0A0A0`，Size 12px。
- **禁用/占位**：`#9CA3AF` / `#6B7280`。

#### 功能色
- **安全/正常**：`#107C10`（绿色）。
- **警告/风险**：`#FFB900`（琥珀色）。
- **威胁/危险**：`#D13438`（红色）。
- **品牌强调色**：`#0078D4`（Windows 蓝），用于按钮、链接、选中态。

### 3.2 字体

- **字体族**：`Segoe UI Variable, Segoe UI, Microsoft YaHei UI, sans-serif`。
- **字号阶梯**：
  - 窗口标题：20px / 24px line-height
  - 区域标题：16px / 22px
  - 正文：14px / 20px
  - 辅助/标签：12px / 16px
- **字重**：正文 400，按钮/标题 600，强调 700。

### 3.3 间距系统

基于 **4px** 网格：

| Token | Value | 用途 |
|-------|-------|------|
| `space-1` | 4px | 图标与文本间距、紧凑内联间距 |
| `space-2` | 8px | 小元素间距、按钮内边距 |
| `space-3` | 12px | 列表项间距、卡片内边距 |
| `space-4` | 16px | 段落间距、卡片外边距 |
| `space-5` | 20px | 区域间距 |
| `space-6` | 24px | 大区块间距 |
| `space-8` | 32px | 页面级边距 |

### 3.4 圆角

- **大卡片 / 窗口**：`8px`
- **按钮 / 输入框 / 小卡片**：`4px`
- **徽章 / 标签**：`12px`（胶囊形）
- **圆形按钮 / 头像**：`50%`

### 3.5 阴影与深度

使用分层阴影模拟 Fluent 深度：

```css
--shadow-rest: 0 0 0.5px rgba(0, 0, 0, 0.13), 0 2px 4px rgba(0, 0, 0, 0.06);
--shadow-hover: 0 0 0.5px rgba(0, 0, 0, 0.13), 0 4px 8px rgba(0, 0, 0, 0.08);
--shadow-flyout: 0 0 0.5px rgba(0, 0, 0, 0.13), 0 8px 16px rgba(0, 0, 0, 0.14);
```

## 4. 组件规范

### 4.1 按钮

#### 主按钮（Accent）
- 背景：`#0078D4`
- 文字：白色
- 圆角：4px
- 内边距：8px 16px
- Hover：背景 `#006CBE`，阴影 `shadow-hover`
- Active：背景 `#005BA1`

#### 标准按钮
- 背景：`#FFFFFF` 80% / `#2D2D2D` 80%
- 边框：1px solid `#E5E5E5` / `#404040`
- Hover：背景 `#F5F5F5` / `#383838`

#### 文字/链接按钮
- 背景：透明
- 文字：`#0078D4`
- Hover：文字下划线或背景出现 4% 主题色叠加

### 4.2 卡片

- 背景：`#FFFFFF` 80% 不透明度
- 圆角：8px
- 内边距：16px
- 边框：0.5px solid `#EBEBEB` / `#3A3A3A`（可选）
- Hover：轻微上浮 `translateY(-1px)` + `shadow-hover`

### 4.3 列表项

- 高度：40px（单行道）/ 64px（双行道）
- 内边距：12px 16px
- Hover：背景 `#F5F5F5` / `#333333`
- 选中：左侧 3px 主题色竖线 + 背景 `#E6F2FB` / `#1E3A55`

### 4.4 弹窗 / Alert

- 尺寸：按内容自适应，最小宽度 360px
- 背景：Acrylic
- 圆角：8px
- 标题栏：可拖拽区域，高度 32px，无默认标题文字
- 按钮区：右对齐，间距 8px
- 威胁弹窗：顶部使用对应状态色条（红/黄/绿）

### 4.5 输入框

- 高度：32px
- 圆角：4px
- 背景：`#FBFBFB` / `#292929`
- 边框：1px solid `#E0E0E0` / `#404040`
- Focus：边框 `#0078D4`，外发光 `0 0 0 2px rgba(0, 120, 212, 0.25)`

### 4.6 图标

- 风格： outlined / 线性，2px 描边，圆角端点
- 尺寸：16px（常规）、20px（工具栏）、24px（空状态/大图标）
- 颜色：与当前文本色一致，或按功能色使用

## 5. 动效与交互

### 5.1 时长

| 类型 | 时长 | 用途 |
|------|------|------|
| 即时反馈 | 0ms | 按下、焦点环 |
| 快速 | 100ms | 按钮 hover、颜色变化 |
| 常规 | 200ms | 卡片状态、弹窗出现 |
| 舒缓 | 300ms | 页面切换、大元素进入 |

### 5.2 缓动

- 默认：`cubic-bezier(0.4, 0.0, 0.2, 1)`（Fluent 标准）
- 进入：`cubic-bezier(0.0, 0.0, 0.2, 1)`
- 退出：`cubic-bezier(0.4, 0.0, 1, 1)`

### 5.3 常见动效

- **按钮 Hover**：背景色 100ms，阴影 200ms
- **卡片 Hover**：`translateY(-1px)` + 阴影，200ms
- **弹窗出现**：从 0.95 缩放到 1，透明度 0→1，200ms
- **列表项 Hover**：背景色 100ms
- **进度/扫描动画**：使用平滑的 indeterminate 动画，避免闪烁

## 6. 布局与导航

### 6.1 窗口布局

- 主窗口采用侧边导航 + 内容区结构。
- 侧边栏宽度：240px（可折叠为 64px）。
- 内容区最小边距：24px。
- 标题栏区域集成到内容顶部，不额外占用独立标题栏。

### 6.2 侧边导航

- 项目高度：40px
- 图标 + 文本间距：12px
- 选中：背景 `#E6F2FB` / `#1E3A55`，左侧 3px 主题色竖线
- Hover：背景 `#F5F5F5` / `#333333`

### 6.3 内容区

- 顶部可放置页面标题与全局操作按钮。
- 信息使用卡片分组，组间距 16px。
- 避免满屏填充，保持呼吸感。

## 7. Tauri / Web 实现指南

### 7.1 HTML 结构建议

```html
<div class="fluent-window">
  <nav class="fluent-nav">
    <!-- 导航项 -->
  </nav>
  <main class="fluent-content">
    <header class="fluent-page-header">
      <h1>页面标题</h1>
      <button class="fluent-btn fluent-btn--accent">主要操作</button>
    </header>
    <section class="fluent-card">
      <h2 class="fluent-card-title">卡片标题</h2>
      <p class="fluent-body">内容...</p>
    </section>
  </main>
</div>
```

### 7.2 CSS 变量建议

```css
:root {
  --fluent-bg-page: #F3F3F3;
  --fluent-bg-card: rgba(255, 255, 255, 0.8);
  --fluent-text-primary: #1F1F1F;
  --fluent-text-secondary: #5F5F5F;
  --fluent-accent: #0078D4;
  --fluent-accent-hover: #006CBE;
  --fluent-radius-lg: 8px;
  --fluent-radius-sm: 4px;
  --fluent-shadow-rest: 0 0 0.5px rgba(0, 0, 0, 0.13), 0 2px 4px rgba(0, 0, 0, 0.06);
  --fluent-shadow-hover: 0 0 0.5px rgba(0, 0, 0, 0.13), 0 4px 8px rgba(0, 0, 0, 0.08);
  --fluent-transition-fast: 100ms cubic-bezier(0.4, 0.0, 0.2, 1);
  --fluent-transition-normal: 200ms cubic-bezier(0.4, 0.0, 0.2, 1);
}
```

### 7.3 深色模式

使用 `prefers-color-scheme` 或 Tauri 暴露的主题状态切换变量值。避免写两套样式，只覆盖变量。

```css
@media (prefers-color-scheme: dark) {
  :root {
    --fluent-bg-page: #202020;
    --fluent-bg-card: rgba(45, 45, 45, 0.8);
    --fluent-text-primary: #E6E6E6;
    --fluent-text-secondary: #A0A0A0;
  }
}
```

### 7.4 Tauri 窗口建议

- 主窗口启用 `transparent: true` 和 `shadows: true`，配合 CSS 实现 Mica/Acrylic 效果。
- 弹窗使用独立窗口，`decorations: false`，由 HTML/CSS 绘制圆角与标题栏。
- 保持 `titleBarStyle: overlay` 或隐藏原生标题栏以获得沉浸式体验。

## 8. 反模式

以下设计在 XIGUASecurity10x 中应避免：

- ❌ 使用高饱和渐变背景（如红到紫的渐变）。
- ❌ 使用 sharp 90° 直角大卡片。
- ❌ 使用过于复杂的拟物化图标。
- ❌ 动效超过 400ms 或大量弹跳效果。
- ❌ 一个页面使用超过 3 种主色。
- ❌ 无意义的装饰性动画（如 endlessly floating shapes）。
- ❌ 阴影过重或过淡导致层级不清。

## 9. 检查清单

在提交任何 UI 改动前，确认：

- [ ] 使用了文档中的颜色变量。
- [ ] 圆角符合规范（大 8px / 小 4px）。
- [ ] 间距使用了 4px 网格（4/8/12/16/20/24/32）。
- [ ] 动效时长不超过 300ms，使用 Fluent 缓动。
- [ ] 深色模式下颜色已覆盖。
- [ ] 所有按钮都有 Hover/Active 状态。
- [ ] 弹窗/Alert 有明确的状态色指示。
- [ ] 没有使用反模式中的任何一项。

## 10. 参考

- [Microsoft Fluent Design System](https://fluent2.microsoft.design/)
- Windows 11 设计规范
- XIGUASecurity10x 现有页面：`index.html`、`threat-alert.html`、`intercept-alert.html`、`timeline.html`、`sandbox-monitor.html`
