cmake_minimum_required(VERSION 3.20)
project(tvm)

set(TVM_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/tvm/include)

add_subdirectory(vendor)
add_subdirectory(tvm)
add_subdirectory(forkless)

option(BUILD_TESTS "Build Tests" OFF)

if (BUILD_TESTS)
    add_subdirectory(tests)
endif (BUILD_TESTS)