$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root "yumeclient"
New-Item -ItemType Directory -Force $out | Out-Null
$env:CGO_ENABLED = "1"
if (-not $env:CC) { $env:CC = "gcc" }
go -C (Join-Path $root "native") build -trimpath -buildmode=c-shared -o (Join-Path $out "yumeclient.dll") .
Remove-Item (Join-Path $out "yumeclient.h") -Force -ErrorAction SilentlyContinue
