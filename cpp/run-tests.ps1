<#
.SYNOPSIS
    Build and test script for the ucp C++ library.
.DESCRIPTION
    Performs the following steps:
      1. Detects vcpkg from environment variables or well-known paths
      2. Configures CMake with the Ninja generator
      3. Builds the library, tests, and samples in parallel
      4. Runs every test executable found in the build tree
      5. Prints a per-test pass/fail summary
      6. Exits with a non-zero code if any test fails

    Supports both Windows (.exe) and Unix (executable bit) test discovery.
.PARAMETER Configuration
    Build configuration: Debug or Release (defaults to Release).
.PARAMETER Architecture
    Target architecture: x86 or x64 (defaults to x64).
.PARAMETER Clean
    If set, deletes the existing build directory before re-configuring.
.EXAMPLE
    .\run-tests.ps1
    .\run-tests.ps1 -Configuration Debug -Architecture x64 -Clean
#>

param(
    # Build configuration: Debug or Release (defaults to Release)
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    # Target architecture: x86 or x64 (defaults to x64)
    [ValidateSet("x86", "x64")]
    [string]$Architecture = "x64",

    # If set, delete the existing build directory before re-configuring
    [switch]$Clean = $false
)

# Halt execution immediately on any error
$ErrorActionPreference = "Stop"

# Determine the directory that contains this script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Source directory is the script directory itself
$sourceDir = $scriptDir

# Dedicated build output directory named after configuration and architecture
$buildDir = Join-Path $scriptDir "build_$($Configuration.ToLower())_$($Architecture.ToLower())"

# ------------------------------------------------------------------
# Helper: detect the vcpkg installation root directory
# ------------------------------------------------------------------
function Find-VcpkgRoot {
    # Priority 1: VCPKG_CMAKE_TOOLCHAIN_FILE environment variable (direct path to vcpkg.cmake)
    if ($env:VCPKG_CMAKE_TOOLCHAIN_FILE -and (Test-Path $env:VCPKG_CMAKE_TOOLCHAIN_FILE)) {
        # Derive the root from the toolchain file location: vcpkg_root/scripts/buildsystems/vcpkg.cmake
        $file = New-Object System.IO.FileInfo $env:VCPKG_CMAKE_TOOLCHAIN_FILE
        $root = $file.Directory.Parent.Parent.FullName
        if (Test-Path $root) { return $root }
    }

    # Priority 2: VCPKG_ROOT environment variable
    if ($env:VCPKG_ROOT -and (Test-Path $env:VCPKG_ROOT)) {
        return $env:VCPKG_ROOT
    }

    # Priority 3: On Windows, check vcpkg.path.txt written by the vcpkg installer
    $vcpkgPathTxt = Join-Path $env:LOCALAPPDATA "vcpkg\vcpkg.path.txt"
    if ($IsWindows -or (-not $IsLinux -and -not $IsMacOS)) {
        if (-not (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -or $IsWindows) {
            if (Test-Path $vcpkgPathTxt) {
                $pathFromTxt = Get-Content $vcpkgPathTxt -First 1 -ErrorAction SilentlyContinue
                if ($pathFromTxt -and (Test-Path $pathFromTxt)) { return $pathFromTxt.Trim() }
            }
        }
    }

    # Priority 4: Well-known installation paths (Windows)
    $candidates = @()
    if ($IsWindows -or (-not (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -or $IsWindows)) {
        $candidates += @(
            "C:\vcpkg",
            "C:\dev\vcpkg",
            "C:\src\vcpkg",
            "$env:USERPROFILE\vcpkg",
            "$env:USERPROFILE\dev\vcpkg",
            "$env:SystemDrive\vcpkg"
        )
    }

    # Priority 5: Well-known installation paths (Linux / macOS)
    if ($IsLinux -or $IsMacOS) {
        $candidates += @(
            "$HOME/vcpkg",
            "/usr/local/vcpkg",
            "/opt/vcpkg",
            "/usr/share/vcpkg"
        )
    }

    # Priority 6: A vcpkg directory next to the project (sibling of the repo root)
    $candidates += (Join-Path (Get-Item $sourceDir).Parent.FullName "vcpkg")

    # Return the first candidate that contains the vcpkg toolchain file
    foreach ($c in $candidates) {
        $tc = Join-Path $c "scripts\buildsystems\vcpkg.cmake"
        if (Test-Path $tc) { return $c }
        $tc2 = Join-Path $c "scripts/buildsystems/vcpkg.cmake"
        if (Test-Path $tc2) { return $c }
    }

    # No vcpkg installation was found
    return $null
}

# ------------------------------------------------------------------
# Helper: detect the vcpkg CMake toolchain file path
# ------------------------------------------------------------------
function Find-VcpkgToolchain {
    # If VCPKG_CMAKE_TOOLCHAIN_FILE is set and valid, use it directly
    if ($env:VCPKG_CMAKE_TOOLCHAIN_FILE -and (Test-Path $env:VCPKG_CMAKE_TOOLCHAIN_FILE)) {
        return $env:VCPKG_CMAKE_TOOLCHAIN_FILE
    }

    # Otherwise derive from the detected vcpkg root
    $root = Find-VcpkgRoot
    if ($root) {
        $tc = Join-Path $root "scripts\buildsystems\vcpkg.cmake"
        if (Test-Path $tc) { return (Resolve-Path $tc).Path }
        $tc2 = Join-Path $root "scripts/buildsystems/vcpkg.cmake"
        if (Test-Path $tc2) { return (Resolve-Path $tc2).Path }
    }

    return $null
}

# ------------------------------------------------------------------
# Helper: determine the number of logical processors (cross-platform)
# ------------------------------------------------------------------
function Get-CpuCount {
    # On PowerShell Core (6+), Environment.ProcessorCount works on all platforms
    $count = [Environment]::ProcessorCount
    if ($count -and $count -gt 0) { return $count }

    # Fallback for older Windows PowerShell: try WMI
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.NumberOfLogicalProcessors -gt 0) { return $cs.NumberOfLogicalProcessors }
    } catch {
        # WMI is not available (non-Windows or restricted)
    }

    # Safest fallback
    return 4
}

# ------------------------------------------------------------------
# Helper: resolve the full path to all test executables in the build tree.
# Works cross-platform: on Windows matches .exe extension; on Unix matches
# files without a recognized text extension (assumed to be executables).
# ------------------------------------------------------------------
# ------------------------------------------------------------------
# Helper: resolve the full path to sample executables in the build tree.
# ------------------------------------------------------------------
function Find-SampleExecutables {
    param([string]$BuildDir)

    $sampleExes = @()
    $samplesDir = Join-Path $BuildDir "samples"
    $multiConfigSamplesDir = Join-Path $samplesDir $Configuration

    $patterns = @("ucp_benchmark*", "ucp_benchmark_diag*")
    $searchDirs = @($samplesDir, $multiConfigSamplesDir)

    foreach ($sd in $searchDirs) {
        foreach ($p in $patterns) {
            $matches = Get-ChildItem -Path (Join-Path $sd $p) -ErrorAction SilentlyContinue
            foreach ($m in $matches) {
                if ($m.Extension -eq ".exe" -or ($IsWindows -eq $false -and -not $m.PSIsContainer)) {
                    $sampleExes += $m.FullName
                }
            }
        }
    }
    return ($sampleExes | Select-Object -Unique)
}

function Find-TestExecutables {
    param([string]$BuildDir)

    $testExes = @()

    # Helper to join an arbitrary number of path segments (works in PS 5.1+).
    function Join-PathSegments {
        param([string]$Base, [string[]]$Segments)
        $result = $Base
        foreach ($seg in $Segments) { $result = Join-Path $result $seg }
        return $result
    }

    # Build the base test directory: buildDir/tests
    $testsDir = Join-Path $BuildDir "tests"

    # Under Ninja (single-config), test executables are directly in tests/
    $ninjaPatterns = @(
        "ucp_tests*",
        "*_tests*",
        "*_test*"
    )

    # Under multi-config generators (Visual Studio), tests are in tests/<Config>/
    $multiConfigDir = Join-Path $testsDir $Configuration
    $multiConfigPatterns = $ninjaPatterns

    # Collect all base-directory + pattern combinations
    $allSearches = @()
    foreach ($p in $ninjaPatterns) {
        $allSearches += @{ Base = $testsDir; Pattern = $p }
    }
    foreach ($p in $multiConfigPatterns) {
        $allSearches += @{ Base = $multiConfigDir; Pattern = $p }
    }

    # Extensions to skip on Unix (text files that match the pattern but are not executables)
    $skipExtensions = @(".cpp", ".hpp", ".h", ".c", ".txt", ".md", ".cmake", ".json")

    foreach ($search in $allSearches) {
        $patternPath = Join-Path $search.Base $search.Pattern
        $matches = Get-ChildItem -Path $patternPath -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            # On Windows: accept only .exe files
            if ($m.Extension -eq ".exe") {
                $testExes += $m.FullName
                continue
            }
            # On Unix: accept files with no extension or an unrecognised one,
            # provided they are not directories and are not in the skip list.
            if ($IsWindows -eq $false) {
                if ($m.PSIsContainer) { continue }
                if ($skipExtensions -contains $m.Extension) { continue }
                # Any remaining file is assumed to be a test executable.
                $testExes += $m.FullName
            }
        }
    }

    return ($testExes | Select-Object -Unique)
}

# ------------------------------------------------------------------
# Detect vcpkg
# ------------------------------------------------------------------
$vcpkgRoot = Find-VcpkgRoot
$vcpkgToolchain = Find-VcpkgToolchain
if ($vcpkgToolchain) {
    Write-Host "[vcpkg] toolchain: $vcpkgToolchain"
    if ($vcpkgRoot) { Write-Host "[vcpkg] root:      $vcpkgRoot" }
} else {
    Write-Host "[vcpkg] not found -- building without vcpkg toolchain"
}

# ------------------------------------------------------------------
# Detect CPU count for parallel builds
# ------------------------------------------------------------------
$cpuCount = Get-CpuCount
Write-Host "[cpu]   detected $cpuCount logical processors"

# ------------------------------------------------------------------
# Step 0: Clean previous build directory (if requested) and re-configure
# ------------------------------------------------------------------
Write-Host ""
Write-Host "============================================"
Write-Host "  UCP C++ Build & Test Script"
Write-Host "  Config  : $Configuration"
Write-Host "  Arch    : $Architecture"
Write-Host "  Cores   : $cpuCount"
Write-Host "============================================"
Write-Host ""

# ------------------------------------------------------------------
# Initialize MSVC compiler environment (vcvarsall.bat)
# Required so that cl.exe can find standard headers like <cstdio>.
# ------------------------------------------------------------------
function Initialize-VisualStudioEnvironment {
    param([string]$Arch)
    $vsArch = if ($Arch -eq "x86") { "x86" } else { "x64" }
    $pf64 = [Environment]::GetEnvironmentVariable('ProgramW6432')
    if (-not $pf64) { $pf64 = "C:\Program Files" }
    $pf86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { "C:\Program Files (x86)" }
    $vcvarsPaths = @(
        "$pf64\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf64\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf64\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf86\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf86\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf86\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf86\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf86\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "$pf86\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    )
    $vcvars = $null
    foreach ($p in $vcvarsPaths) {
        if (Test-Path -LiteralPath $p) { $vcvars = $p; break }
    }
    if ($null -eq $vcvars) {
        # Last resort: try vswhere.exe from 64-bit path
        $vswhereCandidates = @(
            "$pf64\Microsoft Visual Studio\Installer\vswhere.exe",
            "$pf86\Microsoft Visual Studio\Installer\vswhere.exe"
        )
        foreach ($vswCandidate in $vswhereCandidates) {
            if (Test-Path -LiteralPath $vswCandidate) {
                $vsPath = & $vswCandidate -latest -property installationPath 2>$null
                if ($vsPath) {
                    $candidate = "$vsPath\VC\Auxiliary\Build\vcvarsall.bat"
                    if (Test-Path -LiteralPath $candidate) { $vcvars = $candidate; break }
                }
            }
        }
    }
    if ($null -eq $vcvars) {
        Write-Host "[env]  WARNING: cannot locate vcvarsall.bat - MSVC compiler may not be available"
        return
    }
    Write-Host "[env]  vcvarsall: $vcvars $vsArch"
    $envBlock = cmd /c "`"$vcvars`" $vsArch > nul 2>&1 && set"
    foreach ($line in $envBlock -split "\r?\n") {
        $line = $line.Trim()
        if ($line -match "^(.*?)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
    Write-Host "[env]  MSVC environment initialized for $vsArch"
}

try {
    Initialize-VisualStudioEnvironment -Arch $Architecture
} catch {
    Write-Host "[env]  WARNING: $($_.Exception.Message) -- continuing anyway"
}

Write-Host "[0/5] configure"
if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "  -> removing existing build directory: $buildDir"
    Remove-Item -Recurse -Force $buildDir
}

# Create the build directory if it does not exist
if (-not (Test-Path $buildDir)) {
    [void][System.IO.Directory]::CreateDirectory($buildDir)
}

# Change into the build directory for CMake commands
Push-Location $buildDir
try {
    # ------------------------------------------------------------------
    # CMake generator: prefer Ninja for speed.
    # ------------------------------------------------------------------
    $vcpkgTriplet = if ($Architecture -eq "x86") { "x86-windows-static" } else { "x64-windows-static" }

    $cmakeArgs = @(
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=$Configuration",
        "-DCMAKE_MAKE_PROGRAM=ninja",
        "-DVCPKG_TARGET_TRIPLET=$vcpkgTriplet"
    )

    # Append the vcpkg toolchain file if one was found
    if ($vcpkgToolchain) {
        $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain"
    }

    # Append the source directory as the last argument
    $cmakeArgs += $sourceDir

    # Run CMake configure step
    Write-Host "  -> cmake configure"
    & cmake --no-warn-unused-cli @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configure failed (exit code $LASTEXITCODE)"
    }
    Write-Host "  -> configure completed successfully"

    # ------------------------------------------------------------------
    # Step 1: Build all targets (library, tests, samples) in parallel
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "[1/5] build all targets"
    Write-Host "  -> cmake --build . --parallel $cpuCount"
    & cmake --build . --parallel $cpuCount
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed (exit code $LASTEXITCODE)"
    }
    Write-Host "  -> build completed successfully"

    # ------------------------------------------------------------------
    # Step 2: Locate all test executables in the build tree
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "[2/5] locate test and sample executables"
    $testExes = Find-TestExecutables -BuildDir $buildDir

    if ($testExes.Count -eq 0) {
        Write-Host "  -> WARNING: no test executables found in build tree"
        Write-Host "  -> searched patterns: tests/ucp_tests* etc."
    } else {
        Write-Host "  -> found $($testExes.Count) test executable(s):"
        foreach ($exe in $testExes) {
            Write-Host "       $exe"
        }
    }

    $sampleBenchExes = Find-SampleExecutables -BuildDir $buildDir
    if ($sampleBenchExes.Count -gt 0) {
        Write-Host "  -> found $($sampleBenchExes.Count) sample benchmark(s):"
        foreach ($exe in $sampleBenchExes) {
            Write-Host "       $exe"
        }
        $testExes += $sampleBenchExes
    }

    # ------------------------------------------------------------------
    # Step 3: Run every test executable and collect results
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "[3/5] run tests"
    $globalResult = $true
    $testResults = @()

    if ($testExes.Count -eq 0) {
        Write-Host "  -> SKIP (no test executables)"
        $globalResult = $false
    } else {
        # Pair tests (client connects to 127.0.0.1:19001) need the echo smoke
        # server running first; start it once before the first pair test and
        # stop it after the last one.
        $serverProc = $null
        $serverExe = Join-Path $buildDir "tests\echo_smoke_server.exe"
        $pairTestNames = @("big_echo_test.exe", "echo_smoke_test.exe")
        $ranPairTest = $false

        foreach ($exe in $testExes) {
            $exeName = Split-Path $exe -Leaf
            Write-Host "  -> running: $exeName"

            if ($pairTestNames -contains $exeName) {
                # The echo smoke server serves a single connection then exits,
                # so restart it fresh before every pair test.
                if ($null -ne $serverProc) {
                    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
                    $serverProc = $null
                }
                if (Test-Path -LiteralPath $serverExe) {
                    Write-Host "     (starting echo_smoke_server.exe for pair test)"
                    $serverProc = Start-Process -FilePath $serverExe -PassThru -WindowStyle Hidden
                    Start-Sleep -Seconds 2
                    $ranPairTest = $true
                }
            }

            $output = & $exe 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
            $passed = ($exitCode -eq 0)

            $testResults += [PSCustomObject]@{
                Name   = $exeName
                Passed = $passed
                Output = $output
            }

            if ($passed) {
                Write-Host "     PASS (exit code $exitCode)"
            } else {
                Write-Host "     FAIL (exit code $exitCode)" -ForegroundColor Red
                $globalResult = $false
            }
        }

        if ($null -ne $serverProc) {
            Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
            Write-Host "  -> stopped echo_smoke_server.exe"
        }
    }

    # ------------------------------------------------------------------
    # Step 4: Generate and display the test report
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "[4/5] report"

    $totalTests = $testResults.Count
    $passedCount = ($testResults | Where-Object { $_.Passed }).Count
    $failedCount = ($testResults | Where-Object { -not $_.Passed }).Count

    $reportLines = @()
    $reportLines += "=================================================="
    $reportLines += "  UCP C++ Test Report"
    $reportLines += "  Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $reportLines += "  Config:     $Configuration"
    $reportLines += "  Arch:       $Architecture"
    $reportLines += "  Cores:      $cpuCount"
    $reportLines += "  Vcpkg:      $(if ($vcpkgRoot) { $vcpkgRoot } else { 'not used' })"
    $reportLines += "  Build dir:  $buildDir"
    $reportLines += "=================================================="
    $reportLines += ""

    if ($totalTests -eq 0) {
        $reportLines += "  WARNING: No test executables were found or run."
        $reportLines += ""
    } else {
        $reportLines += "  Executables found : $totalTests"
        $reportLines += "  Passed            : $passedCount"
        $reportLines += "  Failed            : $failedCount"
        $reportLines += ""
        $reportLines += "  ------------------------------------------------"

        foreach ($tr in $testResults) {
            $status = if ($tr.Passed) { "PASS" } else { "FAIL" }
            $reportLines += "  [$status] $($tr.Name)"
        }

        $reportLines += "  ------------------------------------------------"
        $reportLines += ""

        $failedTests = $testResults | Where-Object { -not $_.Passed }
        if ($failedTests.Count -gt 0) {
            $reportLines += "  ---------- FAILED TEST OUTPUT ----------"
            foreach ($ft in $failedTests) {
                $reportLines += ""
                $reportLines += "  --- $($ft.Name) ---"
                $ft.Output -split "`r`n|`n" | ForEach-Object {
                    $reportLines += "  $_"
                }
            }
            $reportLines += "  -----------------------------------------"
        }

        $overallStatus = if ($globalResult) { "PASS" } else { "FAIL" }
        $reportLines += ""
        $reportLines += "  Overall: $overallStatus"
    }

    $reportLines += ""
    $reportLines += "=================================================="

    $reportContent = $reportLines -join "`r`n"
    $detailedReportFile = Join-Path $buildDir "test_report.txt"
    $reportFile = $detailedReportFile
    Set-Content -Path $reportFile -Value $reportContent
    Write-Host "  -> report written to: $reportFile"

    Write-Host ""
    Write-Host $reportContent

    # ------------------------------------------------------------------
    # Step 5: Exit with the appropriate status code
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "[5/5] exit"

    if (-not $globalResult) {
        Write-Host "  -> FAILURE: one or more tests failed" -ForegroundColor Red
        exit 1
    }

    Write-Host "  -> SUCCESS: all tests passed" -ForegroundColor Green
    exit 0

} catch {
    # Provide a clear error message on any failure
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  at line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    exit 1
} finally {
    # Always restore the original working directory
    Pop-Location
}
