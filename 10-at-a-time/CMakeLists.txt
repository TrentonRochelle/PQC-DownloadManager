cmake_minimum_required(VERSION 3.00)

add_executable(10-at-a-time src/10-at-a-time.cpp)

include_directories(.)

target_link_libraries(10-at-a-time curl)

set_target_properties(10-at-a-time PROPERTIES CXX_STANDARD 17)
