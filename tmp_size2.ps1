$paths = @(
    'd:\XIGUASecurity10x\antivirus-ui\src-tauri\target',
    'd:\cargo-cache',
    'C:\Users\MEMZ-UAC\AppData\Local\npm-cache',
    'C:\Users\MEMZ-UAC\AppData\Local\Temp'
)
foreach ($t in $paths) {
    if (Test-Path $t) {
        $size = (Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        Write-Host "$t => $([math]::Round($size/1MB,1)) MB"
    } else {
        Write-Host "$t => NOT FOUND"
    }
}
