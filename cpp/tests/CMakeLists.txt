# =============================================================================
# @file tests/CMakeLists.txt
# @brief Build script for the ucp test suite.
#
# Builds the ucp_tests executable from the listed sources and links it
# against the main ucp static library.  Compiler warning flags are kept
# consistent with the parent library target.
#
# Copyright (c) 2024-2026 UCP Project.
# =============================================================================

# Enumerate the source files used to build the test executable.
set(TEST_SOURCES
    test_main.cpp
    ucp_core_tests.cpp
    ucp_extended_tests.cpp
    ucp_kcc_alignment_tests.cpp
    ucp_stress_tests.cpp
    network_simulator.cpp
)

# Build the test executable from the listed sources.
add_executable(ucp_tests ${TEST_SOURCES})

# Add the current source directory to the include path for test-local headers.
target_include_directories(ucp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link the ucp library (Boost headers provided via toolchain include path).
target_link_libraries(ucp_tests PRIVATE ucp)

# Cross-validation interop server executable (used by C# interop tests).
add_executable(interop_server interop_server.cpp)
target_link_libraries(interop_server PRIVATE ucp)
if(MSVC)
    target_compile_options(interop_server PRIVATE /W4 /WX /EHsc "/utf-8" "/MP")
    target_compile_definitions(interop_server PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
else()
    target_compile_options(interop_server PRIVATE -Wall -Wextra -Werror -Wno-error=type-limits -Wno-error=unused-function)
endif()

# Cross-language interop CLIENT (C++ client against a C# UcpServer; the
# reverse direction of interop_server).
add_executable(interop_client interop_client.cpp)
target_link_libraries(interop_client PRIVATE ucp)
if(MSVC)
    target_compile_options(interop_client PRIVATE /W4 /WX /EHsc "/utf-8" "/MP")
    target_compile_definitions(interop_client PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
else()
    target_compile_options(interop_client PRIVATE -Wall -Wextra -Werror -Wno-error=type-limits -Wno-error=unused-function)
endif()

# Apply compiler options consistent with the main library target.
if(MSVC)
    # Enable warning level 4.
    target_compile_options(ucp_tests PRIVATE /W4)
    # Treat warnings as errors.
    target_compile_options(ucp_tests PRIVATE /WX)
    # Enable C++ exceptions (required by std::vector, etc.).
    target_compile_options(ucp_tests PRIVATE /EHsc)
    # Force UTF-8 encoding for source and execution character sets.
    target_compile_options(ucp_tests PRIVATE "/utf-8")
    # Enable parallel compilation across multiple CPU cores.
    target_compile_options(ucp_tests PRIVATE "/MP")
    # Suppress deprecation warnings for standard C and POSIX functions.
    target_compile_definitions(ucp_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    # Define Windows target version for Boost.Asio headers.
    target_compile_definitions(ucp_tests PRIVATE _WIN32_WINNT=0x0601)
else()
    # For non-MSVC compilers: enable common warning flags and treat as errors.
    target_compile_options(ucp_tests PRIVATE -Wall -Wextra -Werror -Wno-error=type-limits -Wno-error=unused-function)
endif()

enable_testing()
add_test(NAME ucp_tests COMMAND ucp_tests)
# Per-test hard timeout is 10s; with 787 test cases the worst case is bounded
# by the aggregate CTest timeout below rather than 800s.
# Set CTest timeout to 300s (5 min) — sufficient for a normal pass where
# all tests complete well under their individual 10s deadline.
set_tests_properties(ucp_tests PROPERTIES TIMEOUT 300)

# ---------------------------------------------------------------------------
# Paired echo tests. The client executables connect to 127.0.0.1:19001 which
# is served by echo_smoke_server.exe; the wrapper script starts the server,
# runs the client, then stops the server (mirroring run-tests.ps1).
# ---------------------------------------------------------------------------
if(WIN32)
    add_test(NAME big_echo_test COMMAND powershell -ExecutionPolicy Bypass -File
        ${CMAKE_CURRENT_SOURCE_DIR}/run_pair_test.ps1
        "$<TARGET_FILE:big_echo_test>" "big_echo_test")
    set_tests_properties(big_echo_test PROPERTIES TIMEOUT 300)

    add_test(NAME echo_smoke_test COMMAND powershell -ExecutionPolicy Bypass -File
        ${CMAKE_CURRENT_SOURCE_DIR}/run_pair_test.ps1
        "$<TARGET_FILE:echo_smoke_test>" "echo_smoke_test")
    set_tests_properties(echo_smoke_test PROPERTIES TIMEOUT 120)
endif()

# Quick test executable for spot-testing simulator (not part of main suite)
add_executable(quick_test test_quick.cpp network_simulator.cpp)
target_include_directories(quick_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(quick_test PRIVATE ucp)

# Echo smoke test executables (manual testing)
add_executable(echo_smoke_server echo_smoke_server.cpp)
target_link_libraries(echo_smoke_server PRIVATE ucp)
add_executable(echo_smoke_test echo_smoke_test.cpp)
target_link_libraries(echo_smoke_test PRIVATE ucp)
add_executable(big_echo_test big_echo_test.cpp)
target_link_libraries(big_echo_test PRIVATE ucp)
if(MSVC)
    target_compile_options(quick_test PRIVATE /W4 /WX /EHsc "/utf-8" "/MP")
    target_compile_definitions(quick_test PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
    target_compile_options(echo_smoke_server PRIVATE /W4 /WX /EHsc "/utf-8" "/MP")
    target_compile_definitions(echo_smoke_server PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
    target_compile_options(echo_smoke_test PRIVATE /W4 /WX /EHsc "/utf-8" "/MP")
    target_compile_definitions(echo_smoke_test PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
    target_compile_options(big_echo_test PRIVATE /W4 /WX /EHsc "/utf-8" "/MP")
    target_compile_definitions(big_echo_test PRIVATE _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0601)
else()
    target_compile_options(quick_test PRIVATE -Wall -Wextra)
    target_compile_options(echo_smoke_server PRIVATE -Wall -Wextra)
    target_compile_options(echo_smoke_test PRIVATE -Wall -Wextra)
    target_compile_options(big_echo_test PRIVATE -Wall -Wextra)
endif()


