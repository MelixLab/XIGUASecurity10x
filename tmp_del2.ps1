$path = 'd:\XIGUASecurity10x\XIGUASecurity10x\src-tauri\src\lib.rs'
$lines = [System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::UTF8)
# 找到安全日志区块起止行（1-based）
$start = -1
$end = -1
$commentStart = '// ==================== 安全日志命令 ===================='
$afterMarker = '// 记录扫描事件到时间线'
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i].TrimEnd() -eq $commentStart) { $start = $i }  # 0-based
    if ($lines[$i].TrimStart().StartsWith('fn add_scan_timeline_event')) { $end = $i; break }
}
Write-Host "start(0-based)=$start end(0-based)=$end"
if ($start -ge 0 -and $end -gt $start) {
    $new = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($i -lt $start -or $i -ge $end) { $new.Add($lines[$i]) }
    }
    [System.IO.File]::WriteAllLines($path, $new, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Done. Original=$($lines.Count) New=$($new.Count)"
} else {
    Write-Host "Markers not found, no change."
}
