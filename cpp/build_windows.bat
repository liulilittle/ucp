@echo off
rem ============================================================================
rem build_windows.bat -- Build ucp C++ library, tests, and samples on Windows
rem
rem Copyright (c) 2024-2026 UCP Project.
rem
rem Usage:
rem   build_windows.bat                    (builds Release x64 with default vcpkg)
rem   build_windows.bat Debug              (builds Debug x64)
rem   build_windows.bat Release            (builds Release x64)
rem   build_windows.bat x86                (builds Release x86)
rem   build_windows.bat x64                (builds Release x64)
rem   build_windows.bat all                (builds Release for both x86 and x64)
rem   build_windows.bat Debug x86          (builds Debug x86)
rem   build_windows.bat x86 Debug          (same as above, order is flexible)
rem   build_windows.bat /?                 (show this help)
rem   build_windows.bat help               (show this help)
rem
rem Features:
rem   - Detects vcpkg via environment variables or well-known paths
rem   - Uses cmake with Ninja generator by default (falls back to default)
rem   - Supports Debug and Release configurations
rem   - Supports x86 and x64 architectures
rem   - Links Boost::system via vcpkg
rem   - Builds library (ucp), tests (ucp_tests), and samples (echo_server, etc.)
rem   - Runs tests automatically after a successful build
rem   - Exits with a non-zero error code if any step fails
rem   - Enables IPv6 support via CMAKE_BUILD_TYPE and vcpkg triplet
rem ============================================================================

setlocal EnableExtensions EnableDelayedExpansion

rem --- Script root directory (where this batch file lives) ---
set "ROOT_DIR=%~dp0"

rem --- Default configuration and target ---
set "CONFIG=Release"
set "TARGET=all"
set "BUILD_ALL=0"

rem --- Use all available processors for parallel builds ---
set "BUILD_JOBS=%NUMBER_OF_PROCESSORS%"

rem --- Show help flag ---
set "SHOW_HELP=0"

rem --- vcpkg triplet for static Windows libraries ---
set "VCPKG_TRIPLET=x64-windows-static"

rem ============================================================================
rem Parse command-line arguments (flexible order, case-insensitive)
rem ============================================================================
call :parse_args %*
if errorlevel 1 goto :help
if "%SHOW_HELP%"=="1" goto :help
goto :start

rem ============================================================================
rem Help screen
rem ============================================================================
:help
echo Usage:
echo   build_windows.bat [options]
echo.
echo Options:
echo   Debug^|Release         Build configuration (default: Release)
echo   x86^|x64^|all          Target architecture(s) (default: all)
echo   help^|/?               Show this help message
echo.
echo Examples:
echo   build_windows.bat              Build Release for both x86 and x64
echo   build_windows.bat Debug        Build Debug x64
echo   build_windows.bat Release x86  Build Release x86
echo   build_windows.bat x64 Debug    Build Debug x64
echo   build_windows.bat all          Build Release for both x86 and x64
echo.
echo vcpkg discovery priority:
echo   1. VCPKG_CMAKE_TOOLCHAIN_FILE environment variable (direct path)
echo   2. VCPKG_ROOT environment variable
echo   3. %%LOCALAPPDATA%%\vcpkg\vcpkg.path.txt (vcpkg installer file)
echo   4. ..\vcpkg (sibling directory next to the project)
echo   5. Common installation paths (C:\vcpkg, C:\dev\vcpkg, %%USERPROFILE%%\vcpkg)
echo   6. Visual Studio integrated vcpkg
echo.
echo Environment variables:
echo   VCPKG_ROOT               - Path to vcpkg root (e.g. C:\vcpkg)
echo   VCPKG_CMAKE_TOOLCHAIN_FILE - Direct path to vcpkg.cmake toolchain file
echo.
exit /b 0

rem ============================================================================
rem Startup: validate configuration and prepare environment
rem ============================================================================
:start
rem Validate that CONFIG is either Debug or Release
if /I not "%CONFIG%"=="Debug" if /I not "%CONFIG%"=="Release" (
    echo ERROR: Build configuration must be Debug or Release, got '%CONFIG%'.
    exit /b 1
)

rem Validate that TARGET is one of x86, x64, or all
if /I not "%TARGET%"=="x86" if /I not "%TARGET%"=="x64" if /I not "%TARGET%"=="all" (
    echo ERROR: Target architecture must be x86, x64, or all, got '%TARGET%'.
    exit /b 1
)

rem Set the BUILD_ALL flag if "all" was specified
if /I "%TARGET%"=="all" set "BUILD_ALL=1"

rem Locate Visual Studio installation (required for MSVC compiler and vcvars)
call :find_vs_install
if errorlevel 1 exit /b 1

rem ============================================================================
rem Main build loop: build for each requested architecture
rem ============================================================================

rem If BUILD_ALL is set, build x86 first, then x64
if "%BUILD_ALL%"=="1" (
    echo ============================================
    echo Building all architectures
    echo ============================================
    echo.
    call :build_for_arch x86
    if errorlevel 1 exit /b 1
    call :build_for_arch x64
    if errorlevel 1 exit /b 1
    echo.
    echo ============================================
    echo All builds completed successfully
    echo ============================================
    exit /b 0
)

rem Otherwise, build only the specified architecture
call :build_for_arch %TARGET%
exit /b %errorlevel%

rem ============================================================================
rem Build for a single architecture (%1 = x86 or x64)
rem ============================================================================
:build_for_arch
set "ARCH=%~1"

rem Map architecture to vcpkg triplet
if /I "%ARCH%"=="x86" (
    set "VCPKG_TRIPLET=x86-windows-static"
) else (
    set "VCPKG_TRIPLET=x64-windows-static"
)

rem Derive the build and output directory names
set "BUILD_DIR=%ROOT_DIR%build_%CONFIG%_%ARCH%"
set "OUTPUT_DIR=%ROOT_DIR%bin\%CONFIG%\%ARCH%"

echo --------------------------------------------------
echo Building %ARCH% %CONFIG%
echo   Build dir:  %BUILD_DIR%
echo   Output dir: %OUTPUT_DIR%
echo   Vcpkg trip: %VCPKG_TRIPLET%
echo   Parallel:   %BUILD_JOBS% jobs
echo --------------------------------------------------

rem Create the output directory if it does not exist
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

rem Prepare the environment for the requested architecture
call :prepare_env %ARCH%
if errorlevel 1 exit /b 1

rem Run the CMake configure and build steps
call :build_one %ARCH% %VCPKG_TRIPLET%
if errorlevel 1 exit /b 1

echo Finished %ARCH% %CONFIG%
exit /b 0

rem ============================================================================
rem Build one configuration: CMake configure + build + test
rem %1 = architecture (x86 or x64)
rem %2 = vcpkg triplet (x86-windows-static or x64-windows-static)
rem ============================================================================
:build_one
set "ARCH=%~1"
set "TRIPLET=%~2"

rem Remove the existing build directory to ensure a clean configure
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"

pushd "%BUILD_DIR%"

echo.
echo [1/3] Configuring %ARCH% %CONFIG% with Ninja generator
echo   Toolchain:  %TOOLCHAIN_FILE%
echo   Vcpkg root: %VCPKG_ROOT_DIR%
echo   Triplet:    %TRIPLET%

rem Run CMake configure step.  IPv6 is enabled via the vcpkg triplet
rem (x64-windows-static or x86-windows-static both support IPv6).
cmake -G Ninja ^
    -DCMAKE_BUILD_TYPE=%CONFIG% ^
    -DCMAKE_TOOLCHAIN_FILE="%TOOLCHAIN_FILE%" ^
    -DVCPKG_TARGET_TRIPLET=%TRIPLET% ^
    -DVCPKG_HOST_TRIPLET=x64-windows ^
    "%ROOT_DIR%"
if errorlevel 1 (
    echo ERROR: CMake configure failed for %ARCH% %CONFIG%
    popd
    exit /b 1
)

echo.
echo [2/3] Building all targets for %ARCH% %CONFIG%
echo   Targets: library (ucp), tests (ucp_tests), samples (echo_server, echo_client, benchmark)

rem Build all targets using Ninja with parallel jobs
cmake --build . -- -j %BUILD_JOBS%
if errorlevel 1 (
    echo ERROR: Build failed for %ARCH% %CONFIG%
    popd
    exit /b 1
)

echo.
echo [3/3] Running tests for %ARCH% %CONFIG%

rem Locate the test executable in the Ninja single-config build tree
set "TEST_EXE=%BUILD_DIR%\tests\ucp_tests.exe"

if exist "%TEST_EXE%" (
    echo   Test executable: %TEST_EXE%
    echo.
    "%TEST_EXE%"
    set "TEST_EXITCODE=!errorlevel!"
    if !TEST_EXITCODE! neq 0 (
        echo   FAILED: ucp_tests.exe exited with code !TEST_EXITCODE!
        popd
        exit /b !TEST_EXITCODE!
    ) else (
        echo   PASSED: all tests in ucp_tests.exe
    )
) else (
    echo   WARNING: Test executable not found at %TEST_EXE%
    echo   Searched: %BUILD_DIR%\tests\ucp_tests.exe
)

popd
exit /b 0

rem ============================================================================
rem Parse command-line arguments (flexible order, case-insensitive)
rem ============================================================================
:parse_args
set "ARG_COUNT=0"

:parse_args_loop
if "%~1"=="" goto :parse_args_done
set /a ARG_COUNT+=1

rem Check for help flags
if /I "%~1"=="help" (
    set "SHOW_HELP=1"
    exit /b 0
)
if /I "%~1"=="/?" (
    set "SHOW_HELP=1"
    exit /b 0
)

rem Check for configuration argument
if /I "%~1"=="Debug" (
    set "CONFIG=Debug"
    shift
    goto :parse_args_loop
)
if /I "%~1"=="Release" (
    set "CONFIG=Release"
    shift
    goto :parse_args_loop
)

rem Check for architecture argument
if /I "%~1"=="x86" (
    set "TARGET=x86"
    shift
    goto :parse_args_loop
)
if /I "%~1"=="x64" (
    set "TARGET=x64"
    shift
    goto :parse_args_loop
)
if /I "%~1"=="all" (
    set "TARGET=all"
    shift
    goto :parse_args_loop
)

rem Unknown argument: return error
exit /b 1

:parse_args_done
rem Validate that at most 2 arguments were provided
if %ARG_COUNT% gtr 2 exit /b 1
exit /b 0

rem ============================================================================
rem Prepare environment for a given architecture:
rem   1. Detect vcpkg toolchain
rem   2. Run vcvarsall.bat for the MSVC compiler
rem
rem vcpkg discovery order (as documented in help):
rem   1. VCPKG_CMAKE_TOOLCHAIN_FILE  (direct path, highest priority)
rem   2. VCPKG_ROOT                  (vcpkg root directory)
rem   3. %%LOCALAPPDATA%%\vcpkg\vcpkg.path.txt  (vcpkg installer)
rem   4. ..\vcpkg                    (sibling directory)
rem   5. Visual Studio integrated vcpkg
rem %1 = target architecture (x86 or x64)
rem ============================================================================
:prepare_env
set "TARGET_ARCH=%~1"

rem --- Step 1: Detect vcpkg root directory ---
set "VCPKG_ROOT_DIR="
set "TOOLCHAIN_FILE="

rem Priority 1: VCPKG_CMAKE_TOOLCHAIN_FILE environment variable (direct path)
if defined VCPKG_CMAKE_TOOLCHAIN_FILE (
    if exist "%VCPKG_CMAKE_TOOLCHAIN_FILE%" set "TOOLCHAIN_FILE=%VCPKG_CMAKE_TOOLCHAIN_FILE%"
)

rem Priority 2: VCPKG_ROOT environment variable
if not defined TOOLCHAIN_FILE if defined VCPKG_ROOT (
    set "VCPKG_ROOT_DIR=%VCPKG_ROOT%"
)
if not defined TOOLCHAIN_FILE if defined VCPKG_ROOT_DIR (
    if exist "%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake" (
        set "TOOLCHAIN_FILE=%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake"
    )
)

rem Priority 3: vcpkg.path.txt written by the vcpkg Windows installer
if not defined TOOLCHAIN_FILE (
    if exist "%LOCALAPPDATA%\vcpkg\vcpkg.path.txt" (
        set /p VCPKG_ROOT_DIR=<"%LOCALAPPDATA%\vcpkg\vcpkg.path.txt"
    )
)
if not defined TOOLCHAIN_FILE if defined VCPKG_ROOT_DIR (
    if exist "%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake" (
        set "TOOLCHAIN_FILE=%VCPKG_ROOT_DIR%\scripts\buildsystems\vcpkg.cmake"
    )
)

rem Priority 4: Sibling vcpkg directory (next to the project root)
if not defined TOOLCHAIN_FILE (
    if exist "%ROOT_DIR%..\vcpkg\scripts\buildsystems\vcpkg.cmake" (
        set "VCPKG_ROOT_DIR=%ROOT_DIR%..\vcpkg"
        set "TOOLCHAIN_FILE=%ROOT_DIR%..\vcpkg\scripts\buildsystems\vcpkg.cmake"
    )
)

rem Priority 5: Visual Studio integrated vcpkg
if not defined TOOLCHAIN_FILE (
    call :find_vs_install
    if defined VS_INSTALL if exist "%VS_INSTALL%\VC\vcpkg\scripts\buildsystems\vcpkg.cmake" (
        set "TOOLCHAIN_FILE=%VS_INSTALL%\VC\vcpkg\scripts\buildsystems\vcpkg.cmake"
    )
)

rem If no toolchain file was found, abort with a clear error message
if not defined TOOLCHAIN_FILE (
    echo ERROR: Unable to locate vcpkg toolchain file.
    echo   Tried: VCPKG_CMAKE_TOOLCHAIN_FILE, VCPKG_ROOT, %%LOCALAPPDATA%%\vcpkg\vcpkg.path.txt,
    echo          ..\vcpkg, and Visual Studio integrated vcpkg.
    echo   Install vcpkg via: git clone https://github.com/Microsoft/vcpkg.git
    echo   Then run: .\vcpkg\bootstrap-vcpkg.bat
    echo   And: set VCPKG_ROOT=C:\path\to\vcpkg
    exit /b 1
)

rem If VCPKG_ROOT_DIR is still empty, derive it from the toolchain file path
if not defined VCPKG_ROOT_DIR (
    for %%I in ("%TOOLCHAIN_FILE%") do set "TOOLCHAIN_DIR=%%~dpI"
    for %%I in ("%TOOLCHAIN_DIR%..\..") do set "VCPKG_ROOT_DIR=%%~fI"
)

rem Normalize backslashes in paths
if defined VCPKG_ROOT_DIR set "VCPKG_ROOT_DIR=%VCPKG_ROOT_DIR:/=\%"
if defined TOOLCHAIN_FILE set "TOOLCHAIN_FILE=%TOOLCHAIN_FILE:/=\%"

rem --- Step 2: Set up MSVC compiler environment ---
call :run_vs_dev_cmd %TARGET_ARCH%
if errorlevel 1 exit /b 1

exit /b 0

rem ============================================================================
rem Run vcvarsall.bat for the specified architecture
rem %1 = target architecture (x86 or x64)
rem ============================================================================
:run_vs_dev_cmd
set "TARGET_ARCH=%~1"
set "VCVARS="

rem Map architecture shorthand to vcvarsall argument
if /I "%TARGET_ARCH%"=="x86" set "VCVARS_ARCH=x86"
if /I "%TARGET_ARCH%"=="x64" set "VCVARS_ARCH=amd64"

rem Try using the VSINSTALLDIR variable set by a previous vcvars invocation
if defined VSINSTALLDIR (
    if exist "%VSINSTALLDIR%VC\Auxiliary\Build\vcvarsall.bat" (
        set "VCVARS=%VSINSTALLDIR%VC\Auxiliary\Build\vcvarsall.bat"
    )
)

rem Fallback: use VS_INSTALL found by vswhere
if not defined VCVARS (
    if defined VS_INSTALL (
        if exist "%VS_INSTALL%\VC\Auxiliary\Build\vcvarsall.bat" (
            set "VCVARS=%VS_INSTALL%\VC\Auxiliary\Build\vcvarsall.bat"
        )
    )
)

rem If vcvarsall.bat was not found, abort
if not defined VCVARS (
    echo ERROR: Unable to locate vcvarsall.bat.
    echo   Make sure Visual Studio is installed with the "Desktop development with C++" workload.
    exit /b 1
)

rem Run vcvarsall.bat to set up compiler environment variables
call "%VCVARS%" %VCVARS_ARCH%
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed for architecture %VCVARS_ARCH%.
    exit /b 1
)

exit /b 0

rem ============================================================================
rem Locate Visual Studio installation using vswhere.exe
rem ============================================================================
:find_vs_install
set "VS_INSTALL="

rem vswhere is bundled with Visual Studio 2017 and later
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    rem vswhere not found; assume vcvars is already in PATH or VSINSTALLDIR is set
    exit /b 0
)

rem Query vswhere for the latest Visual Studio installation path
for /f "usebackq delims=" %%i in (
    `"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2^>nul`
) do set "VS_INSTALL=%%i"

if not defined VS_INSTALL (
    echo WARNING: vswhere found but no Visual Studio installation detected.
    echo   The build may still succeed if MSVC is available via other means.
)

exit /b 0
