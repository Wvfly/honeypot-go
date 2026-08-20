# 冒烟测试：构建蜜罐 -> 后台启动(测试配置) -> 运行 smoketest 客户端 -> 清理
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== build honeypot =="
go build -o data\honeypot.exe ./cmd\honeypot
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "== start honeypot (data\test.yaml, port 23222) =="
$p = Start-Process -FilePath "data\honeypot.exe" `
    -ArgumentList "-config","data\test.yaml" `
    -WorkingDirectory $root `
    -RedirectStandardOutput "data\server.log" `
    -RedirectStandardError "data\server.err" `
    -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    Write-Host "== run smoketest client =="
    go run ./cmd\smoketest
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    # 给 store 消费循环留出落盘时间
    Start-Sleep -Seconds 1
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Write-Host "== honeypot stopped =="
}

Write-Host "== artifacts =="
Get-ChildItem data -Recurse -File | Where-Object { $_.Name -match "honeypot.db|\.jsonl|\.ttyrec" } | ForEach-Object { Write-Host "  $($_.FullName) ($($_.Length) bytes)" }
