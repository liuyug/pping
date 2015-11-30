
cmake_minimum_required(VERSION 2.6)

set(CMAKE_LEGACY_CYGWIN_WIN32 0)

project(pping C)

aux_source_directory(src SRCS)
add_definitions(-Wall -g)
add_definitions(-std=gnu99)

add_definitions(-D__${CMAKE_SYSTEM_NAME}__)

add_executable(pping ${SRCS})

target_link_libraries(pping curl)
