import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig, staticFile } from "remotion";

interface Props {
  frameOffset: number;
}

export const EndingScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const bgOpacity = interpolate(frame, [0, 25], [0, 1], { extrapolateRight: "clamp" });

  const logoScale = spring({
    frame,
    fps,
    config: { damping: 12, stiffness: 80 },
    delay: 15,
  });

  const textOpacity = interpolate(frame, [40, 65], [0, 1], { extrapolateRight: "clamp" });

  const ctaScale = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 100 },
    delay: 75,
  });

  const features = ["AI 驱动", "内核防护", "行为分析", "勒索防护", "EDR 检测"];

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
        opacity: bgOpacity,
      }}
    >
      {/* Subtle blob */}
      <div
        style={{
          position: "absolute",
          width: 500,
          height: 500,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(0,191,165,0.06) 0%, transparent 70%)",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
        }}
      />

      {/* Logo */}
      <div
        style={{
          transform: `scale(${0.8 + logoScale * 0.2})`,
          zIndex: 2,
        }}
      >
        <img
          src={staticFile("logo.png")}
          alt="XIGUASecurity"
          style={{ width: 100, height: 100, objectFit: "contain" }}
        />
      </div>

      {/* Brand Name */}
      <div
        style={{
          zIndex: 2,
          marginTop: 24,
          textAlign: "center",
          opacity: textOpacity,
        }}
      >
        <h1
          style={{
            fontSize: 52,
            fontWeight: 700,
            color: "#1d1d1f",
            margin: 0,
            letterSpacing: 2,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          XIGUASecurity 10x
        </h1>
        <p
          style={{
            fontSize: 22,
            color: "#86868b",
            marginTop: 10,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          守护每一次点击，捍卫每一行代码
        </p>
      </div>

      {/* Feature tags */}
      <div
        style={{
          display: "flex",
          gap: 12,
          marginTop: 28,
          opacity: textOpacity,
        }}
      >
        {features.map((f, i) => (
          <div
            key={i}
            style={{
              padding: "6px 16px",
              borderRadius: 16,
              background: "#ffffff",
              border: "1px solid #e5e5ea",
              color: "#1d1d1f",
              fontSize: 13,
              fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
              boxShadow: "0 2px 8px rgba(0,0,0,0.03)",
            }}
          >
            {f}
          </div>
        ))}
      </div>

      {/* CTA */}
      <div
        style={{
          marginTop: 40,
          transform: `scale(${0.95 + ctaScale * 0.05})`,
          opacity: interpolate(frame, [75, 95], [0, 1], { extrapolateRight: "clamp" }),
        }}
      >
        <div
          style={{
            padding: "14px 44px",
            borderRadius: 10,
            background: "#00BFA5",
            color: "#fff",
            fontSize: 18,
            fontWeight: 600,
            boxShadow: "0 4px 16px rgba(0,191,165,0.25)",
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
            letterSpacing: 2,
          }}
        >
          立即体验
        </div>
      </div>

      {/* Copyright */}
      <div
        style={{
          position: "absolute",
          bottom: 36,
          opacity: interpolate(frame, [95, 120], [0, 0.5], { extrapolateRight: "clamp" }),
          color: "#86868b",
          fontSize: 13,
          fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
        }}
      >
        © 2026 XIGUASecurity. All rights reserved.
      </div>
    </div>
  );
};
