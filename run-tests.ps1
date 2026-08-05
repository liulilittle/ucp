<#
.SYNOPSIS
    Build and test script for UCP C# library and C++ library.
.DESCRIPTION
    Builds and runs tests for both Debug and Release configurations.
    Supports both C# (.NET) and C++ (CMake + vcpkg) builds.
.PARAMETER Configuration
    Build configuration: Debug or Release (defaults to both).
.PARAMETER Architecture
    Target platform architecture: x86 or x64 (defaults to x64).
.PARAMETER Language
    Which language to test: CSharp, Cpp, or All (defaults to All).
.PARAMETER ToolchainFile
    Path to vcpkg toolchain file for C++ build.
.EXAMPLE
    .\run-tests.ps1
    .\run-tests.ps1 -Configuration Release -Language Cpp
    .\run-tests.ps1 -ToolchainFile "D:\vcpkg\scripts\buildsystems\vcpkg.cmake"
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "",

    [ValidateSet("x86", "x64")]
    [string]$Architecture = "x64",

    [ValidateSet("CSharp", "Cpp", "All")]
    [string]$Language = "All",

    [string]$ToolchainFile = ""
)

$ErrorActionPreference = "Stop"

$globalExitCode = 0

# Determine configurations
$configs = if ($Configuration) { @($Configuration) } else { @("Debug", "Release") }

# Architecture argument for dotnet
$archArg = @()
if ($Architecture -eq "x86") { $archArg = @("--arch", "x86") }

# =============================================================================
#  C# Build & Test
# =============================================================================
function Test-CSharp {
    param([string]$config)

    $libraryProject = ".\Ucp\UcpLibrary.csproj"
    $testProject = ".\Ucp.Tests\UcpTest.csproj"
    $currentReportDir = ".\Ucp.Tests\bin\$config\net8.0\reports"

    Write-Host ""
    Write-Host "============================================"
    Write-Host "  UCP C# Test Runner"
    Write-Host "  Config  : $config"
    Write-Host "  Arch    : $Architecture"
    Write-Host "============================================"
    Write-Host ""

    if (Test-Path $currentReportDir) {
        Remove-Item -Recurse -Force $currentReportDir -ErrorAction SilentlyContinue
    }
    [void][System.IO.Directory]::CreateDirectory($currentReportDir)

    Write-Host "[1/2] build C# ($config)"
    & dotnet build $libraryProject -c $config @archArg
    if ($LASTEXITCODE -ne 0) { throw "C# library build failed ($config, exit $LASTEXITCODE)" }

    & dotnet build $testProject -c $config @archArg
    if ($LASTEXITCODE -ne 0) { throw "C# test build failed ($config, exit $LASTEXITCODE)" }
    Write-Host "  -> build OK"

    Write-Host ""
    Write-Host "[2/2] test C# ($config)"
    & dotnet test $testProject -c $config --no-build @archArg
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  -> FAILURE: C# tests failed ($config)" -ForegroundColor Red
        $script:globalExitCode = 1
    } else {
        Write-Host "  -> SUCCESS: C# tests passed ($config)" -ForegroundColor Green
    }
}

# =============================================================================
#  C++ Build & Test
# =============================================================================
function Test-Cpp {
    param([string]$config)

    Write-Host ""
    Write-Host "============================================"
    Write-Host "  UCP C++ Test Runner"
    Write-Host "  Config  : $config"
    Write-Host "  Arch    : $Architecture"
    Write-Host "============================================"
    Write-Host ""

    $cppScript = Join-Path $PSScriptRoot "cpp\run-tests.ps1"
    if (-not (Test-Path $cppScript)) {
        Write-Host "  -> FAIL: C++ test script not found: $cppScript" -ForegroundColor Red
        $script:globalExitCode = 1
        return
    }

    & $cppScript -Configuration $config -Architecture $Architecture
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  -> FAILURE: C++ tests failed ($config)" -ForegroundColor Red
        $script:globalExitCode = 1
    } else {
        Write-Host "  -> SUCCESS: C++ tests passed ($config)" -ForegroundColor Green
    }
}

# =============================================================================
#  Main
# =============================================================================
foreach ($config in $configs) {
    try {
        if ($Language -in @("CSharp", "All")) { Test-CSharp -config $config }
        if ($Language -in @("Cpp", "All")) { Test-Cpp -config $config }
    } catch {
        Write-Host ""
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $globalExitCode = 1
    }
}

if ($globalExitCode -ne 0) {
    Write-Host ""
    Write-Host "One or more configurations FAILED." -ForegroundColor Red
    exit $globalExitCode
}

Write-Host ""
Write-Host "All configurations completed successfully." -ForegroundColor Green
exit 0
