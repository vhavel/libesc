# Simple test placeholder
add_executable(test_basic test_basic.cpp)
target_link_libraries(test_basic PRIVATE libesc Zydis)

add_test(NAME BasicTest COMMAND test_basic)
