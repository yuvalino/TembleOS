project(forkless)

file(GLOB_RECURSE FORKLESS_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/**.c)
set(FORKLESS_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/include)

add_executable(${PROJECT_NAME} ${FORKLESS_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${FORKLESS_INCLUDE})

target_link_libraries(${PROJECT_NAME}
    tvm
    dropbear
    mksh
    toybox
    m
    z
)

if (NOT APPLE)
    target_link_libraries(${PROJECT_NAME} crypt)
endif (NOT APPLE)
