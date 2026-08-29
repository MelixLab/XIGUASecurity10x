import React from "react";
import { useCurrentFrame, useVideoConfig, interpolate, Easing, Audio, staticFile } from "remotion";
import { IntroScene } from "./components/IntroScene";
import { SloganScene } from "./components/SloganScene";
import { AiEngineScene } from "./components/AiEngineScene";
import { KernelScene } from "./components/KernelScene";
import { UiShowcaseScene } from "./components/UiShowcaseScene";
import { ProtectionScene } from "./components/ProtectionScene";
import { EdrSandboxScene } from "./components/EdrSandboxScene";
import { MultiLayerScene } from "./components/MultiLayerScene";
import { EndingScene } from "./components/EndingScene";

const SCENES = [
  { start: 0,    end: 120,  component: IntroScene },
  { start: 120,  end: 300,  component: SloganScene },
  { start: 300,  end: 480,  component: AiEngineScene },
  { start: 480,  end: 660,  component: KernelScene },
  { start: 660,  end: 960,  component: UiShowcaseScene },
  { start: 960,  end: 1200, component: ProtectionScene },
  { start: 1200, end: 1440, component: EdrSandboxScene },
  { start: 1440, end: 1620, component: MultiLayerScene },
  { start: 1620, end: 1800, component: EndingScene },
];

export const Video: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const activeScenes = SCENES.map((scene, index) => {
    const Component = scene.component;
    const isActive = frame >= scene.start && frame < scene.end;
    const nextScene = SCENES[index + 1];
    const prevScene = SCENES[index - 1];

    // Transition opacity for crossfade
    let opacity = 1;
    const transitionFrames = 15;

    if (frame >= scene.start && frame < scene.start + transitionFrames && prevScene) {
      opacity = interpolate(frame, [scene.start, scene.start + transitionFrames], [0, 1], {
        extrapolateLeft: "clamp",
        extrapolateRight: "clamp",
      });
    } else if (frame >= scene.end - transitionFrames && frame < scene.end && nextScene) {
      opacity = interpolate(frame, [scene.end - transitionFrames, scene.end], [1, 0], {
        extrapolateLeft: "clamp",
        extrapolateRight: "clamp",
      });
    }

    if (!isActive) return null;

    return (
      <div
        key={index}
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          opacity,
        }}
      >
        <Component frameOffset={scene.start} />
      </div>
    );
  });

  return (
    <>
      {activeScenes}
      <Audio src={staticFile("bgm.wav")} />
    </>
  );
};
