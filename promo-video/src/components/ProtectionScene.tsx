import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

interface Props {
  frameOffset: number;
}

export const ProtectionScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" });

  const modules = [
    { name: "文件系统防护", desc: "MiniFilter 驱动监控", color: "#00BFA5" },
    { name: "实时防护", desc: "进程/线程行为拦截", color: "#007aff" },
    { name: "网页防护", desc: "恶意 URL 实时拦截", color: "#34c759" },
    { name: "网络安全", desc: "流量分析与威胁阻断", color: "#ff9500" },
    { name: "身份保护", desc: "凭据与隐私防护", color: "#af52de" },
    { name: "增强端点防护", desc: "EDR 行为链检测", color: "#ff3b30" },
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
          REAL-TIME PROTECTION
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
          六维一体实时防护
        </h2>
      </div>

      {/* Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: 20,
          marginTop: 40,
          maxWidth: 960,
        }}
      >
        {modules.map((mod, i) => {
          const delay = 20 + i * 10;
          const modScale = spring({
            frame,
            fps,
            config: { damping: 14, stiffness: 100 },
            delay,
          });
          const modOpacity = interpolate(frame, [delay, delay + 18], [0, 1], {
            extrapolateRight: "clamp",
          });

          return (
            <div
              key={i}
              style={{
                padding: "24px 28px",
                borderRadius: 14,
                background: "#ffffff",
                border: "1px solid #e5e5ea",
                transform: `scale(${0.95 + modScale * 0.05})`,
                opacity: modOpacity,
                boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
                <div
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background: mod.color,
                  }}
                />
                <div
                  style={{
                    fontSize: 17,
                    fontWeight: 600,
                    color: "#1d1d1f",
                    fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
                  }}
                >
                  {mod.name}
                </div>
              </div>
              <div
                style={{
                  fontSize: 14,
                  color: "#86868b",
                  lineHeight: 1.5,
                  paddingLeft: 22,
                  fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
                }}
              >
                {mod.desc}
              </div>
            </div>
          );
        })}
      </div>

      {/* Bottom status */}
      <div
        style={{
          position: "absolute",
          bottom: 80,
          display: "flex",
          gap: 48,
          opacity: interpolate(frame, [90, 115], [0, 1], { extrapolateRight: "clamp" }),
        }}
      >
        {[
          { label: "防护状态", value: "全面开启", color: "#34c759" },
          { label: "最后更新", value: "刚刚", color: "#00BFA5" },
          { label: "拦截次数", value: "2,847", color: "#ff3b30" },
        ].map((item, i) => (
          <div key={i} style={{ textAlign: "center" }}>
            <div style={{ fontSize: 14, color: "#86868b", marginBottom: 4 }}>{item.label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: item.color, fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif" }}>
              {item.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
