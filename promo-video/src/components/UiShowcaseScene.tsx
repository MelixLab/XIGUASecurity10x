import React from "react";
import { useCurrentFrame, interpolate, staticFile } from "remotion";

interface Props {
  frameOffset: number;
}

const SHOTS = [
  { file: "home.png",          title: "概览",     desc: "系统状态一目了然" },
  { file: "protection.png",    title: "防护",     desc: "六维一体实时防护" },
  { file: "endpoint-rules.png", title: "端点规则", desc: "HIPS / 文件信任 / 行为链" },
  { file: "quarantine-real.png", title: "隔离区", desc: "威胁安全隔离与恢复" },
];

const INTRO = 30;   // 标题展示帧数
const FADE = 15;    // 淡入淡出帧数
const HOLD = 70;    // 每张图停留帧数
const SHOT_DURATION = HOLD + FADE; // 85 帧/张，切换完全串行无重叠

export const UiShowcaseScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;

  const titleOpacity = interpolate(frame, [0, 25], [0, 1], { extrapolateRight: "clamp" });

  // 每张图严格只在各自的时间区间内显示，区间不重叠 → 无闪烁
  const shotsToRender = SHOTS.map((shot, i) => {
    const start = INTRO + i * SHOT_DURATION;
    const localFrame = frame - start;
    if (localFrame < 0 || localFrame >= HOLD) return null;

    // 纯 interpolate 淡入淡出，无 spring、无 CSS transition
    const fadeIn = interpolate(localFrame, [0, FADE], [0, 1], {
      extrapolateRight: "clamp",
    });
    const fadeOut = interpolate(localFrame, [HOLD - FADE, HOLD], [1, 0], {
      extrapolateLeft: "clamp",
    });
    const opacity = Math.min(fadeIn, fadeOut);

    return (
      <div
        key={i}
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          opacity,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <div
          style={{
            width: 1060,
            height: 690,
            borderRadius: 16,
            background: "#ffffff",
            boxShadow: "0 25px 80px rgba(0,0,0,0.12), 0 8px 24px rgba(0,0,0,0.06)",
            overflow: "hidden",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <img
            src={staticFile(shot.file)}
            alt={shot.title}
            style={{
              width: "100%",
              height: "100%",
              objectFit: "contain",
            }}
          />
        </div>

        {/* Caption card */}
        <div
          style={{
            position: "absolute",
            bottom: -4,
            left: "50%",
            transform: "translateX(-50%)",
            padding: "10px 24px",
            borderRadius: 12,
            background: "#ffffff",
            boxShadow: "0 8px 24px rgba(0,0,0,0.08)",
            display: "flex",
            alignItems: "center",
            gap: 12,
            whiteSpace: "nowrap",
          }}
        >
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "#00BFA5",
            }}
          />
          <span
            style={{
              fontSize: 18,
              fontWeight: 600,
              color: "#1d1d1f",
              fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            }}
          >
            {shot.title}
          </span>
          <span
            style={{
              fontSize: 14,
              color: "#86868b",
              fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            }}
          >
            {shot.desc}
          </span>
        </div>
      </div>
    );
  });

  // 指示条：纯 interpolate 计算宽度，无 CSS transition
  const indicatorOpacity = interpolate(frame, [INTRO - 10, INTRO], [0, 1], {
    extrapolateRight: "clamp",
  });

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: "#f0f2f5",
        position: "relative",
        overflow: "hidden",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {/* Header */}
      <div
        style={{
          position: "absolute",
          top: 50,
          left: 0,
          right: 0,
          textAlign: "center",
          opacity: titleOpacity,
          zIndex: 10,
        }}
      >
        <div
          style={{
            fontSize: 18,
            color: "#00BFA5",
            letterSpacing: 4,
            marginBottom: 6,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            fontWeight: 600,
          }}
        >
          CLEAN & INTUITIVE
        </div>
        <h2
          style={{
            fontSize: 44,
            fontWeight: 700,
            color: "#1d1d1f",
            margin: 0,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          简洁直观的交互体验
        </h2>
      </div>

      {/* Screenshot container */}
      <div
        style={{
          position: "relative",
          width: 1100,
          height: 720,
          marginTop: 30,
        }}
      >
        {shotsToRender}
      </div>

      {/* Page indicator dots - 纯 interpolate */}
      <div
        style={{
          position: "absolute",
          bottom: 50,
          display: "flex",
          gap: 8,
          opacity: indicatorOpacity,
        }}
      >
        {SHOTS.map((_, i) => {
          // 当前激活下标，基于帧数计算
          const activeIndex = Math.min(
            SHOTS.length - 1,
            Math.floor((frame - INTRO) / SHOT_DURATION)
          );
          const active = i === activeIndex;
          return (
            <div
              key={i}
              style={{
                width: active ? 26 : 8,
                height: 8,
                borderRadius: 4,
                background: active ? "#00BFA5" : "#d2d6dc",
              }}
            />
          );
        })}
      </div>
    </div>
  );
};
