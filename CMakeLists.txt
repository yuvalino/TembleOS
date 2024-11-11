cmake_minimum_required(VERSION 3.20)
project(tvm)

file(GLOB_RECURSE TVM_SOURCES ${CMAKE_CURRENT_LIST_DIR}/tvm/src/**.c)
set(TVM_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/tvm/include)

add_subdirectory(vendor)

add_executable(forkless ${TVM_SOURCES})
target_include_directories(forkless PRIVATE ${TVM_INCLUDE})

target_link_libraries(forkless
    dropbear
    mksh
    toybox
    pthread
    util
    m
    z
)

if (UNIX)
    target_link_libraries(forkless crypt)
endif (UNIX)
