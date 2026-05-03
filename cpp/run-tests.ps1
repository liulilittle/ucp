$ErrorActionPreference = "Stop"

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x86", "x64")]
    [string]$Architecture = "x64"
)

$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceDir   = $scriptDir
$buildDir    = Join-Path $scriptDir "build_ninja"
$reportFile  = Join-Path $buildDir "test_report.txt"

function Find-VcpkgRoot {
    if ($env:VCPKG_ROOT -and (Test-Path $env:VCPKG_ROOT)) {
        return $env:VCPKG_ROOT
    }

    $candidates = @(
        "C:\vcpkg",
        "C:\dev\vcpkg",
        "C:\src\vcpkg",
        "$env:USERPROFILE\vcpkg",
        "$env:USERPROFILE\dev\vcpkg",
        "$env:SystemDrive\vcpkg"
    )

    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "scripts\buildsystems\vcpkg.cmake")) {
            return $c
        }
    }

    return $null
}

$vcpkgRoot = Find-VcpkgRoot
$vcpkgToolchain = ""
if ($vcpkgRoot) {
    $vcpkgToolchain = Join-Path $vcpkgRoot "scripts\buildsystems\vcpkg.cmake"
    Write-Host "[vcpkg] found at $vcpkgRoot"
} else {
    Write-Host "[vcpkg] not found -- building without vcpkg toolchain"
}

Write-Host "[0/3] configure"
if (Test-Path $buildDir) {
    Remove-Item -Recurse -Force $buildDir
}
[void][System.IO.Directory]::CreateDirectory($buildDir)

Push-Location $buildDir
try {
    $cmakeArgs = @(
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=$Configuration",
        "-DCMAKE_MAKE_PROGRAM=ninja"
    )

    if ($vcpkgToolchain) {
        $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain"
    }

    $cmakeArgs += $sourceDir

    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configure failed"
    }

    Write-Host "[1/3] build"
    & cmake --build . --config $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    Write-Host "[2/3] test"
    $testExe = Join-Path $buildDir "tests" "ucp_tests.exe"
    $testOutput = ""
    if (Test-Path $testExe) {
        $testOutput = & $testExe 2>&1 | Out-String
    } else {
        $testOutput = "TEST EXECUTABLE NOT FOUND: $testExe"
    }

    $passed = ($LASTEXITCODE -eq 0)

    Write-Host "[3/3] report"
    $summary = @"
===== UCP C++ Test Report =====
Date:       $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Config:     $Configuration
Arch:       $Architecture
Vcpkg:      $(if ($vcpkgRoot) { $vcpkgRoot } else { "not used" })

Result:     $(if ($passed) { "PASS" } else { "FAIL" })

$testOutput
===============================
"@

    Set-Content -Path $reportFile -Value $summary
    Write-Host $summary

    if (-not $passed) {
        Write-Host "ERROR: Tests failed" -ForegroundColor Red
        exit 1
    }

    Write-Host "All tests passed" -ForegroundColor Green
} finally {
    Pop-Location
}
