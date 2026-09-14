# build-win.ps1 编译 honeypot / ttyshow 到 Windows 本机，并校验产物为 PE。
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build-win.ps1 [-Arch amd64|arm64]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

$env:GOOS = "windows"
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"

try {
    go build -trimpath -ldflags "-s -w" -o "target/honeypot-windows-$Arch.exe" ./cmd/honeypot
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go build -trimpath -ldflags "-s -w" -o "target/ttyshow-windows-$Arch.exe" ./cmd/ttyshow
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go build -trimpath -ldflags "-s -w" -o "target/dbquery-windows-$Arch.exe" ./cmd/dbquery
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    # 恢复环境变量，避免影响后续交叉编译
    $env:GOOS = $null
    $env:GOARCH = $null
    $env:CGO_ENABLED = $null
}

# 校验产物：前 2 字节必须是 DOS 头魔数 'M' 'Z'（0x4D 0x5A），确认是 Windows PE
foreach ($name in @("target/honeypot-windows-$Arch.exe", "target/ttyshow-windows-$Arch.exe", "target/dbquery-windows-$Arch.exe")) {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $name))[0..1]
    $isPE = ($bytes[0] -eq 0x4D) -and ($bytes[1] -eq 0x5A)
    if (-not $isPE) {
        Write-Error "$name is NOT a Windows PE binary - GOOS env not applied. Delete it and rebuild."
    }
    Write-Host "OK: $name (windows/$Arch, PE verified)"
}
