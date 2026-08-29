import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

interface Props {
  frameOffset: number;
}

export const SloganScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const titleY = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 80 },
    delay: 10,
  });

  const subtitleOpacity = interpolate(frame, [45, 70], [0, 1], { extrapolateRight: "clamp" });

  const featureItems = ["AI 驱动检测", "内核级防护", "行为链分析", "勒索软件防护"];

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: "#f0f2f5",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Subtle ring */}
      <div
        style={{
          position: "absolute",
          width: 500,
          height: 500,
          borderRadius: "50%",
          border: "1px solid rgba(0,191,165,0.15)",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
        }}
      />

      {/* Main title */}
      <div
        style={{
          transform: `translateY(${30 - titleY * 30}px)`,
          zIndex: 2,
          textAlign: "center",
        }}
      >
        <h2
          style={{
            fontSize: 56,
            fontWeight: 700,
            color: "#1d1d1f",
            margin: 0,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            lineHeight: 1.3,
          }}
        >
          下一代智能安全防护
        </h2>
        <p
          style={{
            fontSize: 24,
            color: "#86868b",
            marginTop: 16,
            opacity: subtitleOpacity,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          重新定义终端安全的边界
        </p>
      </div>

      {/* Feature pills */}
      <div
        style={{
          display: "flex",
          gap: 16,
          marginTop: 48,
          zIndex: 2,
        }}
      >
        {featureItems.map((item, i) => {
          const itemDelay = 70 + i * 12;
          const itemOpacity = interpolate(frame, [itemDelay, itemDelay + 18], [0, 1], {
            extrapolateRight: "clamp",
          });
          const itemY = interpolate(frame, [itemDelay, itemDelay + 18], [12, 0], {
            extrapolateRight: "clamp",
          });

          return (
            <div
              key={i}
              style={{
                padding: "10px 24px",
                borderRadius: 24,
                background: "#ffffff",
                border: "1px solid #e5e5ea",
                color: "#1d1d1f",
                fontSize: 16,
                fontWeight: 500,
                opacity: itemOpacity,
                transform: `translateY(${itemY}px)`,
                boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
                fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
              }}
            >
              {item}
            </div>
          );
        })}
      </div>
    </div>
  );
};
