# 设置 Tauri 构建使用国内镜像
$env:TAURI_BUNDLER_TOOLS_GITHUB_MIRROR = "https://ghfast.top/https://github.com"
$env:TAURI_BUNDLER_WIX_GITHUB_MIRROR = "https://ghfast.top/https://github.com"

# 运行构建
npm run tauri build
