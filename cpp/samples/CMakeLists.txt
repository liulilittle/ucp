add_executable(ucp_echo_server echo_server.cpp)
target_link_libraries(ucp_echo_server PRIVATE ucp)

add_executable(ucp_echo_client echo_client.cpp)
target_link_libraries(ucp_echo_client PRIVATE ucp)

add_executable(ucp_benchmark benchmark.cpp)
target_link_libraries(ucp_benchmark PRIVATE ucp)
