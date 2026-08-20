# build-linux.ps1 交叉编译 honeypot / ttyshow 到 Linux，并校验产物为 ELF。
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build-linux.ps1 [-Arch amd64|arm64]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

$env:GOOS = "linux"
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"

try {
    go build -trimpath -ldflags "-s -w" -o "honeypot-linux-$Arch" ./cmd/honeypot
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go build -trimpath -ldflags "-s -w" -o "ttyshow-linux-$Arch" ./cmd/ttyshow
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    # 恢复环境变量，避免影响后续本机编译
    $env:GOOS = $null
    $env:GOARCH = $null
    $env:CGO_ENABLED = $null
}

# 校验产物：前 4 字节必须是 ELF 魔数 0x7F 'E' 'L' 'F'
foreach ($name in @("honeypot-linux-$Arch", "ttyshow-linux-$Arch")) {
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $name))[0..3]
    $isELF = ($bytes[0] -eq 0x7F) -and ($bytes[1] -eq 0x45) -and ($bytes[2] -eq 0x4C) -and ($bytes[3] -eq 0x46)
    if (-not $isELF) {
        Write-Error "$name is NOT a Linux ELF binary - GOOS env not applied. Delete it and rebuild."
    }
    Write-Host "OK: $name (linux/$Arch, ELF verified)"
}
