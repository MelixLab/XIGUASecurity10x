import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig, staticFile } from "remotion";

interface Props {
  frameOffset: number;
}

export const IntroScene: React.FC<Props> = ({ frameOffset }) => {
  const frame = useCurrentFrame() - frameOffset;
  const { fps } = useVideoConfig();

  const logoScale = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 80 },
    delay: 10,
  });

  const logoOpacity = interpolate(frame, [10, 35], [0, 1], { extrapolateRight: "clamp" });

  const textY = spring({
    frame,
    fps,
    config: { damping: 16, stiffness: 80 },
    delay: 35,
  });

  const subOpacity = interpolate(frame, [55, 80], [0, 1], { extrapolateRight: "clamp" });

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
      {/* Subtle gradient blob */}
      <div
        style={{
          position: "absolute",
          width: 600,
          height: 600,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(0,191,165,0.08) 0%, transparent 70%)",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
        }}
      />

      {/* Logo */}
      <div
        style={{
          transform: `scale(${0.7 + logoScale * 0.3})`,
          opacity: logoOpacity,
          zIndex: 2,
        }}
      >
        <img
          src={staticFile("logo.png")}
          alt="西瓜杀毒"
          style={{ width: 170, height: 170, objectFit: "contain" }}
        />
      </div>

      {/* Brand Name */}
      <div
        style={{
          transform: `translateY(${20 - textY * 20}px)`,
          opacity: logoOpacity,
          zIndex: 2,
          marginTop: 36,
          textAlign: "center",
        }}
      >
        <h1
          style={{
            fontSize: 72,
            fontWeight: 700,
            color: "#1d1d1f",
            margin: 0,
            letterSpacing: 2,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          西瓜杀毒
        </h1>
        <div
          style={{
            fontSize: 26,
            fontWeight: 400,
            color: "#86868b",
            marginTop: 14,
            letterSpacing: 4,
            opacity: subOpacity,
            fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          }}
        >
          XIGUASecurity
        </div>
      </div>

      {/* Tagline */}
      <div
        style={{
          position: "absolute",
          bottom: 90,
          opacity: subOpacity,
          color: "#00BFA5",
          fontSize: 20,
          letterSpacing: 6,
          fontWeight: 500,
          fontFamily: "Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
        }}
      >
        下一代智能安全防护
      </div>
    </div>
  );
};
