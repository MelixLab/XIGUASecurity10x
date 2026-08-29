import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

interface Props {
  frameOffset: number;
}

export const AiEngineScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" });
  const titleX = spring({ frame, fps, config: { damping: 14, stiffness: 100 }, delay: 0 });

  const metricScale = spring({ frame, fps, config: { damping: 12, stiffness: 100 }, delay: 60 });

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
          top: 60,
          left: 0,
          right: 0,
          textAlign: "center",
          opacity: titleOpacity,
          transform: `translateY(${(1 - titleX) * -15}px)`,
          zIndex: 10,
        }}
      >
        <div
          style={{
            fontSize: 15,
            color: "#00BFA5",
            letterSpacing: 3,
            marginBottom: 12,
            fontWeight: 600,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          AI DETECTION ENGINE
        </div>
        <h2
          style={{
            fontSize: 56,
            fontWeight: 700,
            color: "#1d1d1f",
            margin: 0,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          自研 Melix 智能引擎
        </h2>
        <p
          style={{
            fontSize: 22,
            color: "#86868b",
            marginTop: 14,
            maxWidth: 640,
            lineHeight: 1.6,
            margin: "14px auto 0",
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          全新自研 AI 检测引擎，毫秒级识别未知威胁
        </p>
      </div>

      {/* Simple abstract visualization - larger cards */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 36,
          marginTop: 50,
          padding: "0 60px",
        }}
      >
        {[
          { label: "文件输入", color: "#00BFA5" },
          { label: "特征提取", color: "#00BFA5" },
          { label: "模型推理", color: "#00BFA5" },
          { label: "威胁判定", color: "#ff3b30" },
        ].map((step, i) => {
          const delay = 30 + i * 18;
          const s = spring({ frame, fps, config: { damping: 14, stiffness: 100 }, delay });
          const op = interpolate(frame, [delay, delay + 18], [0, 1], { extrapolateRight: "clamp" });

          return (
            <React.Fragment key={i}>
              <div
                style={{
                  width: 190,
                  height: 190,
                  borderRadius: 24,
                  background: "#ffffff",
                  border: `2px solid ${step.color}30`,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  transform: `scale(${0.85 + s * 0.15})`,
                  opacity: op,
                  boxShadow: "0 6px 30px rgba(0,0,0,0.08)",
                }}
              >
                <div
                  style={{
                    width: 20,
                    height: 20,
                    borderRadius: "50%",
                    background: step.color,
                    marginBottom: 18,
                    boxShadow: `0 0 16px ${step.color}80`,
                  }}
                />
                <div
                  style={{
                    fontSize: 24,
                    color: "#1d1d1f",
                    fontWeight: 600,
                    fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
                  }}
                >
                  {step.label}
                </div>
              </div>
              {i < 3 && (
                <div
                  style={{
                    width: 40,
                    height: 2,
                    background: "#e5e5ea",
                    opacity: interpolate(frame, [delay + 10, delay + 25], [0, 1], { extrapolateRight: "clamp" }),
                  }}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Performance metrics - larger */}
      <div
        style={{
          position: "absolute",
          bottom: 70,
          display: "flex",
          gap: 48,
          transform: `scale(${0.9 + metricScale * 0.1})`,
          opacity: interpolate(frame, [60, 85], [0, 1], { extrapolateRight: "clamp" }),
        }}
      >
        {[
          { label: "特征维度", value: "2568D" },
          { label: "推理速度", value: "<1ms" },
          { label: "准确率", value: "99.8%" },
        ].map((m, i) => (
          <div
            key={i}
            style={{
              textAlign: "center",
              padding: "28px 48px",
              borderRadius: 18,
              background: "#ffffff",
              border: "1px solid #e5e5ea",
              boxShadow: "0 4px 20px rgba(0,0,0,0.06)",
            }}
          >
            <div
              style={{
                fontSize: 16,
                color: "#86868b",
                marginBottom: 8,
                fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
              }}
            >
              {m.label}
            </div>
            <div
              style={{
                fontSize: 44,
                fontWeight: 800,
                color: "#00BFA5",
                fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
              }}
            >
              {m.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
