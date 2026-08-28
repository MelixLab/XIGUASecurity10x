$targets = @(
    'd:\XIGUASecurity10x\XIGUASecurity10x\src-tauri\target\debug',
    'd:\XIGUASecurity10x\XIGUASecurity10x\src-tauri\target\debug\incremental',
    'd:\XIGUASecurity10x\XIGUASecurity10x\src-tauri\target\debug\build'
)
foreach ($t in $targets) {
    if (Test-Path $t) {
        $size = (Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        Write-Host "$t => $([math]::Round($size/1MB,1)) MB"
    } else {
        Write-Host "$t => NOT FOUND"
    }
}
