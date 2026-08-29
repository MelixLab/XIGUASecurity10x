import { Config } from "@remotion/cli/config";

Config.setVideoImageFormat("jpeg");
Config.setOverwriteOutput(true);

// 使用本机已安装的 Edge 浏览器渲染，避免下载 Chrome Headless Shell
Config.setBrowserExecutable(
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
);
