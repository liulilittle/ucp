# =============================================================================
# @file CMakeLists.txt
# @brief Top-level CMake build script for the ucp C++ static library.
#
# Copyright (c) 2024-2026 PPP PRIVATE NETWORK™ X.
#
# Build targets:
#   - ucp          : Static library (core protocol implementation)
#   - ucp_tests    : Unit and integration test executable
#   - ucp_echo_server, ucp_echo_client, ucp_benchmark : Sample executables
#
# Dependencies:
#   - Boost.Asio (header-only; located via find_path or vcpkg toolchain)
#   - C++17-capable compiler (MSVC 2019+, GCC 7+, Clang 7+)
#
# Platform notes:
#   - Windows: links ws2_32.lib for Winsock; uses /MP, /WX, /utf-8
#   - Unix    : links and compiles with -pthread for threading support
# =============================================================================

# Specify the minimum CMake version required to process this file.
# 3.16 provides first-class support for CUDA, but for C++-only builds
# this also works cleanly with CMake >= 3.10.
cmake_minimum_required(VERSION 3.10)

# Define the project name, version, and language (C++).
project(ucp VERSION 1.0.0 LANGUAGES CXX)

# Require the C++17 standard (no compiler extensions).
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ensure the NULLPTR macro is available project-wide so that every
# translation unit can use it without relying on a specific #include.
add_definitions(-DNULLPTR=nullptr)

# List all source files that make up the ucp static library.
set(SOURCES
    src/ucp_packet_codec.cpp
    src/ucp_pcb.cpp
    src/ucp_cc.cpp
    src/ucp_pacing.cpp
    src/ucp_fec_codec.cpp
    src/ucp_time.cpp
    src/ucp_rto_estimator.cpp
    src/ucp_global_kf_estimator.cpp
    src/ucp_sack_generator.cpp
    src/ucp_configuration.cpp
    src/ucp_connection.cpp
    src/ucp_server.cpp
    src/ucp_network.cpp
    src/ucp_datagram_network.cpp
    src/udp_socket_transport.cpp
    src/dtls_transport.cpp
    src/quic_transport.cpp
)

# Create the static library target from the source list.
add_library(ucp STATIC ${SOURCES})

# Make the 'include' directory available to consumers of the library.
target_include_directories(ucp PUBLIC include)

# Locate the Boost include directory (provided by vcpkg via the toolchain file).
# We use find_path instead of find_package(Boost) to avoid the "New Boost version
# may have incorrect or missing dependencies" warning emitted by CMake's built-in
# FindBoost.cmake module for Boost versions >= 1.77 on CMake < 3.25.
find_path(BOOST_INCLUDE_DIR boost/asio.hpp
    HINTS
        "${CMAKE_SOURCE_DIR}/../vcpkg/installed/x64-windows/include"
        "${CMAKE_SOURCE_DIR}/../vcpkg/installed/x86-windows/include"
        "${CMAKE_SOURCE_DIR}/../vcpkg/installed/x64-windows-static/include"
)
if(NOT BOOST_INCLUDE_DIR)
    message(FATAL_ERROR "boost/asio.hpp not found. Install Boost via vcpkg: vcpkg install boost")
endif()
target_include_directories(ucp PUBLIC ${BOOST_INCLUDE_DIR})

# Use std::error_code instead of boost::system::error_code so no link-time
# dependency on libboost_system is needed (asio is header-only with C++17).
target_compile_definitions(ucp PUBLIC BOOST_ASIO_HAS_STD_SYSTEM_ERROR)

# Apply MSVC-specific compiler options.
if(MSVC)
    # Enable warning level 4 for better diagnostic coverage.
    target_compile_options(ucp PRIVATE /W4)
    # Treat warnings as errors.
    target_compile_options(ucp PRIVATE /WX)
    # Enable C++ exceptions (required by std::vector, etc. with /WX).
    target_compile_options(ucp PRIVATE /EHsc)
    # Force the source and execution character sets to UTF-8 (fixes C4819).
    target_compile_options(ucp PRIVATE "/utf-8")
    # Enable multi-process compilation to speed up builds.
    target_compile_options(ucp PRIVATE "/MP")
    # Suppress deprecation warnings for standard C and POSIX functions.
    target_compile_definitions(ucp PRIVATE _CRT_SECURE_NO_WARNINGS)
    # Suppress deprecation warnings for inet_addr etc.
    target_compile_definitions(ucp PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS)
    # Define Windows target version.
    target_compile_definitions(ucp PRIVATE _WIN32_WINNT=0x0601)
endif()

# Link platform-specific system libraries needed by the UDP transport layer.
if(WIN32)
    # Windows requires ws2_32 for Winsock API.
    target_link_libraries(ucp PUBLIC ws2_32 winmm)
elseif(UNIX)
    # Unix-like systems require pthread for threading.
    target_link_libraries(ucp PUBLIC pthread)
endif()

# Enable CTest integration for automated test discovery and execution.
include(CTest)

# Recursively process the tests and samples subdirectories.
add_subdirectory(tests)
add_subdirectory(samples)

# ----------------------------------------------------------------------------
# CTest integration for sample executables
# ----------------------------------------------------------------------------

# Benchmarks: verify the benchmark can start and complete (config-dependent)
add_test(NAME Sample_Benchmark COMMAND ucp_benchmark)
add_test(NAME Sample_BenchmarkDiag COMMAND ucp_benchmark_diag)
set_tests_properties(Sample_Benchmark Sample_BenchmarkDiag PROPERTIES TIMEOUT 20)

# Echo integration test: client can't run standalone without server.
# Use manual testing: start echo_server then echo_client separately.
