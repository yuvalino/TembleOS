project(tvm)

file(GLOB_RECURSE TVM_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/**.c)

add_library(${PROJECT_NAME} STATIC ${TVM_SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC 
    pthread
    util
)
target_include_directories(${PROJECT_NAME} PUBLIC ${TVM_INCLUDE})