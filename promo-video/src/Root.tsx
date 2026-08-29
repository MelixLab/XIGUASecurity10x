import { Composition } from "remotion";
import { Video } from "./Video";

export const Root: React.FC = () => {
  return (
    <Composition
      id="XIGUASecurityPromo"
      component={Video}
      durationInFrames={1800}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
