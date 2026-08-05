@echo off
setlocal EnableExtensions
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvarsall.bat failed
    exit /b 1
)
echo MSVC environment prepared successfully.

cd /d "%~dp0"
if exist build_verify rmdir /s /q build_verify
mkdir build_verify
cd build_verify

echo Running CMake configure...
cmake -G Ninja ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_TOOLCHAIN_FILE=D:/dd/vcpkg/scripts/buildsystems/vcpkg.cmake ^
    -DVCPKG_TARGET_TRIPLET=x64-windows-static ^
    ..
if errorlevel 1 (
    echo ERROR: CMake configure failed
    exit /b 1
)
echo CMake configure succeeded.

echo Building...
cmake --build . --parallel %NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)
echo Build succeeded.

cd tests
if exist ucp_tests.exe (
    echo Running tests...
    ucp_tests.exe
    if errorlevel 1 (
        echo ERROR: Tests failed
        exit /b 1
    )
    echo Tests passed.
) else (
    echo WARNING: ucp_tests.exe not found
)
exit /b 0
