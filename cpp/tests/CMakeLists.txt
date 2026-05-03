set(TEST_SOURCES
    test_main.cpp
)

add_executable(ucp_tests ${TEST_SOURCES})
target_include_directories(ucp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ucp_tests PRIVATE ucp)

if(MSVC)
    target_compile_options(ucp_tests PRIVATE /W4)
else()
    target_compile_options(ucp_tests PRIVATE -Wall -Wextra)
endif()
