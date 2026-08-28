$path = 'd:\XIGUASecurity10x\XIGUASecurity10x\src-tauri\src\lib.rs'
$lines = [System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::UTF8)
# 找到起始注释和 add_scan_timeline_event 前的边界
$start = -1
$end = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i].Trim() -eq '// ==================== 安全日志命令 ====================') { $start = $i }
    if ($start -ge 0 -and $lines[$i].Trim() -eq '// 记录扫描事件到时间线') { $end = $i; break }
}
if ($start -lt 0 -or $end -lt 0) { Write-Host "markers not found"; exit 1 }
$new = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($i -lt $start -or $i -ge $end) { $new.Add($lines[$i]) }
}
[System.IO.File]::WriteAllLines($path, $new, (New-Object System.Text.UTF8Encoding $false))
Write-Host "Del $start..$end. Original=$($lines.Count) New=$($new.Count)"
