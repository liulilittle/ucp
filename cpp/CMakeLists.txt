cmake_minimum_required(VERSION 3.16)
project(ucp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCES
    src/ucp_packet_codec.cpp
    src/ucp_pcb.cpp
    src/ucp_bbr.cpp
    src/ucp_pacing.cpp
    src/ucp_fec_codec.cpp
    src/ucp_time.cpp
    src/ucp_rto_estimator.cpp
    src/ucp_sack_generator.cpp
    src/ucp_configuration.cpp
    src/ucp_connection.cpp
    src/ucp_server.cpp
    src/ucp_network.cpp
    src/ucp_datagram_network.cpp
)

add_library(ucp STATIC ${SOURCES})
target_include_directories(ucp PUBLIC include)

if(MSVC)
    target_compile_options(ucp PRIVATE /W4)
else()
    target_compile_options(ucp PRIVATE -Wall -Wextra)
endif()

if(WIN32)
    target_link_libraries(ucp PUBLIC ws2_32)
elseif(UNIX)
    target_link_libraries(ucp PUBLIC pthread)
endif()

add_subdirectory(tests)
add_subdirectory(samples)
