# =============================================================================
# @file samples/CMakeLists.txt
# @brief Build script for ucp sample executables.
#
# Builds five sample targets (echo server, echo client, benchmark, benchmark_diag, self_test) and links
# each against the ucp static library.  Compiler warning flags are factored
# into a reusable list to avoid duplication across targets.
#
# Boost.Asio is required as header-only dependency for the underlying UDP
# transport (async receive, sync send_to).
#
# Copyright (c) 2024-2026 PPP PRIVATE NETWORK™ X
# =============================================================================

# --------------------------------------------------------------------------
# Locate Boost.Asio headers (header-only dependency).
# The parent CMakeLists.txt may have already set BOOST_INCLUDE_DIR.
# --------------------------------------------------------------------------
if(NOT BOOST_INCLUDE_DIR)
    find_path(BOOST_INCLUDE_DIR boost/asio.hpp)
    if(NOT BOOST_INCLUDE_DIR)
        message(FATAL_ERROR "boost/asio.hpp not found. Install Boost via vcpkg: vcpkg install boost")
    endif()
endif()

# --------------------------------------------------------------------------
# Define a reusable list of MSVC compile flags so each sample target does
# not need to repeat the same block.  This list is applied with a helper
# function below.
# --------------------------------------------------------------------------
set(UCP_SAMPLE_MSVC_FLAGS
    /W4                      # Warning level 4
    /WX                      # Treat warnings as errors
    /EHsc                    # Enable C++ exceptions
    "/utf-8"                 # Source/execution character sets: UTF-8
    "/MP"                    # Multi-process compilation
)

set(UCP_SAMPLE_MSVC_DEFINES
    _CRT_SECURE_NO_WARNINGS  # Suppress POSIX deprecation warnings
    _WIN32_WINNT=0x0601      # Windows target version (Win7+)
)

# --------------------------------------------------------------------------
# Helper function: applies compiler flags and definitions to a single target.
# On MSVC the flags/defines above are used; on non-MSVC -Wall -Wextra -Werror.
# --------------------------------------------------------------------------
function(ucp_setup_sample_target TARGET)
    target_include_directories(${TARGET} PRIVATE ${BOOST_INCLUDE_DIR})
    target_link_libraries(${TARGET} PRIVATE ucp)
    if(MSVC)
        target_compile_options(${TARGET} PRIVATE ${UCP_SAMPLE_MSVC_FLAGS})
        foreach(def ${UCP_SAMPLE_MSVC_DEFINES})
            target_compile_definitions(${TARGET} PRIVATE ${def})
        endforeach()
    else()
        target_compile_options(${TARGET} PRIVATE -Wall -Wextra -Werror)
    endif()
endfunction()

# --------------------------------------------------------------------------
# Echo server sample -- mirrors C# samples/cs/Server/Program.cs
# --------------------------------------------------------------------------
add_executable(ucp_echo_server echo_server.cpp)
ucp_setup_sample_target(ucp_echo_server)

# --------------------------------------------------------------------------
# Echo client sample -- mirrors C# samples/cs/Client/Program.cs
# --------------------------------------------------------------------------
add_executable(ucp_echo_client echo_client.cpp)
ucp_setup_sample_target(ucp_echo_client)

# --------------------------------------------------------------------------
# Benchmark sample -- minimal smoke test (not a full benchmark framework like C#)
# --------------------------------------------------------------------------
add_executable(ucp_benchmark benchmark.cpp)
ucp_setup_sample_target(ucp_benchmark)

# --------------------------------------------------------------------------
# Diagnostic benchmark sample -- extended performance reporting
# --------------------------------------------------------------------------
add_executable(ucp_benchmark_diag benchmark_diag.cpp)
ucp_setup_sample_target(ucp_benchmark_diag)

# --------------------------------------------------------------------------
# Self-test sample -- single-process echo test (in-process server + client)
# Mirrors C# samples/cs/SelfTest/Program.cs
# --------------------------------------------------------------------------
add_executable(ucp_self_test self_test.cpp)
ucp_setup_sample_target(ucp_self_test)
