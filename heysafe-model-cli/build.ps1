# 一键编译（Windows）。编完把 exe 拷到本目录根下，方便直接调用。
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "== 编译 HeySafe 模型调用器（release）==" -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "编译失败" }

$exe = Join-Path $PSScriptRoot "target\release\model-cli.exe"
Copy-Item -Force $exe (Join-Path $PSScriptRoot "model-cli.exe")

Write-Host "`n完成：model-cli.exe 已生成。" -ForegroundColor Green
Write-Host "示例：" -ForegroundColor Yellow
Write-Host "  .\model-cli.exe model\heysafe_local_model.trees.bin.xz C:\path\to\sample.exe"
