import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";

interface Props {
  frameOffset: number;
}

export const EdrSandboxScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 18], [0, 1], { extrapolateRight: "clamp" });

  const events = [
    { time: "T+0ms", action: "进程创建", detail: "suspicious.exe", risk: "low" },
    { time: "T+50ms", action: "注册表写入", detail: "HKLM\\Run", risk: "medium" },
    { time: "T+120ms", action: "网络连接", detail: "185.220.101.x:443", risk: "high" },
    { time: "T+200ms", action: "内存注入", detail: "explorer.exe", risk: "critical" },
    { time: "T+280ms", action: "IOA 评分触发", detail: "Score: 96/100", risk: "blocked" },
  ];

  const riskColors: Record<string, string> = {
    low: "#34c759",
    medium: "#ff9500",
    high: "#ff3b30",
    critical: "#ff3b30",
    blocked: "#00BFA5",
  };

  const terminalLines = [
    "> Initializing Sandboxie...",
    "> Hooking process callbacks...",
    "> Capturing telemetry...",
    "> [ALERT] Memory injection detected",
    "> [IOA] Rule MEM_INJECT_001 matched",
    "> [ACTION] Process terminated",
    "> Analysis complete.",
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
          top: 60,
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
          EDR & SANDBOX
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
          行为链分析与沙盒检测
        </h2>
      </div>

      <div
        style={{
          display: "flex",
          gap: 32,
          marginTop: 20,
          width: "90%",
          maxWidth: 1300,
          height: 540,
        }}
      >
        {/* Timeline Panel */}
        <div
          style={{
            flex: 1,
            borderRadius: 14,
            background: "#ffffff",
            border: "1px solid #e5e5ea",
            padding: 24,
            overflow: "hidden",
            boxShadow: "0 2px 12px rgba(0,0,0,0.04)",
          }}
        >
          <div
            style={{
              fontSize: 15,
              color: "#1d1d1f",
              fontWeight: 600,
              marginBottom: 16,
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            }}
          >
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ff9500" }} />
            行为链时间线
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
            {events.map((ev, i) => {
              const delay = 25 + i * 16;
              const evOpacity = interpolate(frame, [delay, delay + 14], [0, 1], {
                extrapolateRight: "clamp",
              });
              const evX = spring({
                frame,
                fps,
                config: { damping: 16, stiffness: 100 },
                delay,
              });

              return (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 14,
                    padding: "12px 0",
                    borderLeft: `2px solid ${riskColors[ev.risk]}30`,
                    paddingLeft: 16,
                    opacity: evOpacity,
                    transform: `translateX(${(1 - evX) * -12}px)`,
                    position: "relative",
                  }}
                >
                  <div
                    style={{
                      position: "absolute",
                      left: -5,
                      top: 18,
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: riskColors[ev.risk],
                    }}
                  />
                  <div style={{ fontSize: 12, color: "#86868b", fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif", minWidth: 60 }}>
                    {ev.time}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 14, color: "#1d1d1f", fontWeight: 600 }}>{ev.action}</div>
                    <div style={{ fontSize: 12, color: "#86868b", marginTop: 2, fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif" }}>
                      {ev.detail}
                    </div>
                  </div>
                  <div
                    style={{
                      padding: "3px 8px",
                      borderRadius: 4,
                      background: `${riskColors[ev.risk]}15`,
                      color: riskColors[ev.risk],
                      fontSize: 10,
                      fontWeight: 700,
                      fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
                      textTransform: "uppercase",
                    }}
                  >
                    {ev.risk}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Terminal Panel */}
        <div
          style={{
            flex: 1,
            borderRadius: 14,
            background: "#1d1d1f",
            border: "1px solid #333",
            padding: 24,
            overflow: "hidden",
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            boxShadow: "0 2px 12px rgba(0,0,0,0.08)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 14,
              paddingBottom: 12,
              borderBottom: "1px solid #333",
            }}
          >
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f57" }} />
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#febc2e" }} />
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#28c840" }} />
            <span style={{ fontSize: 12, color: "#666", marginLeft: 8 }}>sandbox_analyzer</span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {terminalLines.map((line, i) => {
              const charsToShow = Math.max(0, Math.floor((frame - (35 + i * 16)) * 1.5));
              const visibleText = line.slice(0, charsToShow);
              const lineOpacity = interpolate(frame, [30 + i * 12, 40 + i * 12], [0, 1], {
                extrapolateRight: "clamp",
              });

              const isAlert = line.includes("[ALERT]") || line.includes("[IOA]") || line.includes("[ACTION]");
              const isComplete = line.includes("complete");

              return (
                <div
                  key={i}
                  style={{
                    fontSize: 13,
                    color: isAlert ? "#ff5f57" : isComplete ? "#28c840" : "#aaa",
                    opacity: lineOpacity,
                    lineHeight: 1.5,
                  }}
                >
                  {visibleText}
                  {charsToShow > 0 && charsToShow < line.length && (
                    <span style={{ color: "#00BFA5" }}>|</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
