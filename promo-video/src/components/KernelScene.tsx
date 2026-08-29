import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

interface Props {
  frameOffset: number;
}

export const KernelScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" });

  const drivers = [
    { name: "AntiVirus.sys", desc: "文件系统监控", color: "#00BFA5" },
    { name: "FileProtect.sys", desc: "文件防篡改", color: "#007aff" },
    { name: "SelfProtect.sys", desc: "自我保护", color: "#34c759" },
    { name: "EndPoint.sys", desc: "端点检测", color: "#ff9500" },
  ];

  const shieldScale = spring({ frame, fps, config: { damping: 12, stiffness: 80 }, delay: 15 });

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
          top: 80,
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
          KERNEL PROTECTION
        </div>
        <h2
          style={{
            fontSize: 48,
            fontWeight: 700,
            color: "#1d1d1f",
            margin: 0,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          内核级实时防护
        </h2>
      </div>

      {/* Center + Drivers */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 48,
          marginTop: 20,
        }}
      >
        {/* Drivers list */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {drivers.slice(0, 2).map((driver, i) => {
            const delay = 25 + i * 15;
            const s = spring({ frame, fps, config: { damping: 14, stiffness: 100 }, delay });
            const op = interpolate(frame, [delay, delay + 18], [0, 1], { extrapolateRight: "clamp" });

            return (
              <div
                key={i}
                style={{
                  padding: "18px 28px",
                  borderRadius: 14,
                  background: "#ffffff",
                  border: `1px solid ${driver.color}25`,
                  boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
                  transform: `translateX(${(1 - s) * -20}px) scale(${0.95 + s * 0.05})`,
                  opacity: op,
                  minWidth: 220,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                  <div style={{ width: 10, height: 10, borderRadius: "50%", background: driver.color }} />
                  <span style={{ fontSize: 15, fontWeight: 600, color: "#1d1d1f", fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif" }}>
                    {driver.name}
                  </span>
                </div>
                <span style={{ fontSize: 13, color: "#86868b", paddingLeft: 20 }}>{driver.desc}</span>
              </div>
            );
          })}
        </div>

        {/* Center shield */}
        <div
          style={{
            width: 160,
            height: 160,
            borderRadius: "50%",
            background: "#ffffff",
            border: "2px solid #00BFA530",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            transform: `scale(${0.85 + shieldScale * 0.15})`,
            boxShadow: "0 4px 20px rgba(0,0,0,0.06)",
          }}
        >
          <span
            style={{
              fontSize: 48,
              fontWeight: 800,
              color: "#00BFA5",
              fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            }}
          >
            R0
          </span>
        </div>

        {/* Drivers list right */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {drivers.slice(2, 4).map((driver, i) => {
            const delay = 40 + i * 15;
            const s = spring({ frame, fps, config: { damping: 14, stiffness: 100 }, delay });
            const op = interpolate(frame, [delay, delay + 18], [0, 1], { extrapolateRight: "clamp" });

            return (
              <div
                key={i}
                style={{
                  padding: "18px 28px",
                  borderRadius: 14,
                  background: "#ffffff",
                  border: `1px solid ${driver.color}25`,
                  boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
                  transform: `translateX(${(1 - s) * 20}px) scale(${0.95 + s * 0.05})`,
                  opacity: op,
                  minWidth: 220,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                  <div style={{ width: 10, height: 10, borderRadius: "50%", background: driver.color }} />
                  <span style={{ fontSize: 15, fontWeight: 600, color: "#1d1d1f", fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif" }}>
                    {driver.name}
                  </span>
                </div>
                <span style={{ fontSize: 13, color: "#86868b", paddingLeft: 20 }}>{driver.desc}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom labels */}
      <div
        style={{
          position: "absolute",
          bottom: 80,
          display: "flex",
          gap: 40,
          opacity: interpolate(frame, [90, 115], [0, 1], { extrapolateRight: "clamp" }),
        }}
      >
        {["KMDF MiniFilter", "ETW 遥测", "回调监控", "IRP 拦截"].map((label, i) => (
          <div
            key={i}
            style={{
              padding: "8px 20px",
              borderRadius: 8,
              background: "#ffffff",
              border: "1px solid #e5e5ea",
              color: "#86868b",
              fontSize: 14,
              fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
              boxShadow: "0 2px 8px rgba(0,0,0,0.03)",
            }}
          >
            {label}
          </div>
        ))}
      </div>
    </div>
  );
};
