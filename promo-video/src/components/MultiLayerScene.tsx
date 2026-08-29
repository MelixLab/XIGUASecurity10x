import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

interface Props {
  frameOffset: number;
}

export const MultiLayerScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" });

  const layers = [
    { name: "文件采集", desc: "样本预处理", color: "#007aff", delay: 10 },
    { name: "AI 检测", desc: "自研 Melix 引擎", color: "#00BFA5", delay: 20 },
    { name: "脚本分析", desc: "JS/VBS/PS 脚本", color: "#00BFA5", delay: 30 },
    { name: "云端哈希比对", desc: "已知威胁库", color: "#34c759", delay: 40 },
    { name: "自动化沙箱", desc: "隔离运行行为", color: "#ff9500", delay: 50 },
    { name: "动态检测", desc: "实时行为判定", color: "#af52de", delay: 60 },
    { name: "威胁隔离", desc: "查杀与隔离", color: "#ff3b30", delay: 70 },
  ];

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
          top: 70,
          left: 0,
          right: 0,
          textAlign: "center",
          opacity: titleOpacity,
          zIndex: 10,
        }}
      >
        <div
          style={{
            fontSize: 14,
            color: "#00BFA5",
            letterSpacing: 3,
            marginBottom: 10,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            fontWeight: 600,
          }}
        >
          MULTI-LAYER DETECTION
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
          七层纵深检测链
        </h2>
      </div>

      {/* Flow */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 0,
          marginTop: 20,
          position: "relative",
        }}
      >
        {/* File input */}
        <div
          style={{
            padding: "14px 36px",
            borderRadius: 10,
            background: "#ffffff",
            border: "1px solid #e5e5ea",
            color: "#1d1d1f",
            fontSize: 16,
            fontWeight: 600,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            marginBottom: 16,
            transform: `scale(${interpolate(frame, [0, 18], [0.9, 1], { extrapolateRight: "clamp" })})`,
            opacity: interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" }),
            boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
          }}
        >
          unknown_file.exe
        </div>

        <div
          style={{
            width: 2,
            height: 16,
            background: "#e5e5ea",
            opacity: interpolate(frame, [10, 22], [0, 1], { extrapolateRight: "clamp" }),
          }}
        />

        {/* Layers */}
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "center",
            gap: 12,
            maxWidth: 900,
            padding: "16px 0",
          }}
        >
          {layers.map((layer, i) => {
            const layerScale = spring({
              frame,
              fps,
              config: { damping: 14, stiffness: 100 },
              delay: layer.delay,
            });
            const layerOpacity = interpolate(frame, [layer.delay, layer.delay + 16], [0, 1], {
              extrapolateRight: "clamp",
            });

            return (
              <div
                key={i}
                style={{
                  padding: "12px 20px",
                  borderRadius: 10,
                  background: "#ffffff",
                  border: `1px solid ${layer.color}25`,
                  transform: `scale(${0.92 + layerScale * 0.08})`,
                  opacity: layerOpacity,
                  textAlign: "center",
                  minWidth: 140,
                  boxShadow: "0 2px 8px rgba(0,0,0,0.03)",
                }}
              >
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 600,
                    color: layer.color,
                    marginBottom: 2,
                    fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
                  }}
                >
                  {layer.name}
                </div>
                <div style={{ fontSize: 11, color: "#86868b", fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif" }}>{layer.desc}</div>
              </div>
            );
          })}
        </div>

        <div
          style={{
            width: 2,
            height: 16,
            background: "#e5e5ea",
            opacity: interpolate(frame, [100, 115], [0, 1], { extrapolateRight: "clamp" }),
          }}
        />

        {/* Result */}
        <div
          style={{
            padding: "14px 36px",
            borderRadius: 10,
            background: "#ffffff",
            border: "1px solid #ff3b3030",
            color: "#ff3b30",
            fontSize: 16,
            fontWeight: 600,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            marginTop: 16,
            display: "flex",
            alignItems: "center",
            gap: 10,
            transform: `scale(${interpolate(frame, [110, 130], [0.9, 1], { extrapolateRight: "clamp" })})`,
            opacity: interpolate(frame, [110, 130], [0, 1], { extrapolateRight: "clamp" }),
            boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
          }}
        >
          <span style={{ fontSize: 18 }}>!</span>
          <span>THREAT DETECTED & QUARANTINED</span>
        </div>
      </div>

      {/* Bottom tagline */}
      <div
        style={{
          position: "absolute",
          bottom: 80,
          opacity: interpolate(frame, [120, 140], [0, 1], { extrapolateRight: "clamp" }),
          color: "#86868b",
          fontSize: 15,
          textAlign: "center",
          fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
        }}
      >
        从本地特征到云端 AI，层层过滤，让威胁无处遁形
      </div>
    </div>
  );
};
