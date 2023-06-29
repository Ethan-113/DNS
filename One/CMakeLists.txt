include_directories(.)
add_executable(One dnsrelay.c)
target_link_libraries(One ws2_32)