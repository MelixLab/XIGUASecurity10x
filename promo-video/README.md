# XIGUASecurity 10x 宣传片

使用 [Remotion](https://www.remotion.dev/) 制作的 60 秒产品宣传片，全 React 代码实现，无需外部素材。

## 分镜脚本

| 时间 | 场景 | 内容 |
|------|------|------|
| 0-4s | **开场** | Logo 淡入 + 粒子特效 + 品牌名 |
| 4-10s | **标语** | "下一代智能安全防护" + 四大核心能力标签 |
| 10-16s | **AI 引擎** | Melix TreeEnsemble 神经网络可视化 + 2568D 特征/毫秒级推理 |
| 16-22s | **内核防护** | KMDF MiniFilter 四大驱动环绕护盾动画 |
| 22-32s | **UI 展示** | 概览面板 + 病毒扫描进度模拟 |
| 32-40s | **实时防护** | 六维一体防护模块卡片 |
| 40-48s | **EDR & 沙盒** | 行为链时间线 + 终端打字机效果 |
| 48-54s | **多层检测** | 七层纵深检测链流程图 |
| 54-60s | **结尾** | Logo + 标语 + CTA |

## 技术栈

- React 18 + TypeScript
- Remotion 4.x
- 全 SVG/CSS 动画，无外部图片/视频素材

## 背景音乐

`public/bgm.wav` 由 `generate-music.js` 程序化合成（60 秒无版权配乐）。

如需更换音乐，将新的音频文件放到 `public/` 并修改 `src/Video.tsx` 中的 `<Audio src={staticFile("bgm.wav")} />`。

重新生成默认配乐：
```bash
node generate-music.js
```

## 运行

```bash
# 安装依赖
npm install

# 预览编辑
npm start

# 渲染导出 (out/video.mp4)
npm run build
```

## 自定义

修改 `src/components/` 下的场景组件即可调整内容、颜色、动画时长。
调整 `src/Root.tsx` 中的 `durationInFrames` 可改变总时长。
