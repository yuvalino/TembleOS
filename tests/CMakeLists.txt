project(tests)

add_executable(tvm_test test_tvm.c)
target_link_libraries(tvm_test tvm)