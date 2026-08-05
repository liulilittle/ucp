# ===========================================================================
# run_pair_test.ps1 — CTest wrapper for the paired echo tests.
#
# Starts echo_smoke_server.exe on 127.0.0.1:19001, runs the given client
# executable against it, then stops the server. Used by CTest via
# add_test(COMMAND powershell -ExecutionPolicy Bypass -File run_pair_test.ps1
#             <client-exe> [<test-name>]).
#
# The echo server serves a single connection and exits, so we restart it
# fresh for every client invocation. Exit code mirrors the client's.
# ===========================================================================
param(
    [Parameter(Mandatory = $true)][string]$ClientExe,
    [Parameter(Mandatory = $false)][string]$ClientName = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$clientPath = if ([System.IO.Path]::IsPathRooted($ClientExe)) {
    $ClientExe
} else {
    Join-Path $scriptDir $ClientExe
}

# The server executable lives in the same build directory as the client.
$clientDir = Split-Path -Parent $clientPath
if (-not $clientDir) { $clientDir = $scriptDir }
$serverExe = Join-Path $clientDir "echo_smoke_server.exe"

if (-not (Test-Path -LiteralPath $serverExe)) {
    Write-Host "FAIL: echo_smoke_server.exe not found at $serverExe"
    exit 2
}
if (-not (Test-Path -LiteralPath $clientPath)) {
    Write-Host "FAIL: client executable not found at $clientPath"
    exit 2
}

$serverProc = $null
try {
    Write-Host "starting echo_smoke_server.exe"
    $serverProc = Start-Process -FilePath $serverExe -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    if ($ClientName) { Write-Host "running $ClientName" }
    & $clientPath 2>&1 | ForEach-Object { Write-Host "  $_" }
    $exitCode = $LASTEXITCODE
    Write-Host "client exit code: $exitCode"
    exit $exitCode
}
finally {
    if ($null -ne $serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "stopped echo_smoke_server.exe"
    }
}
