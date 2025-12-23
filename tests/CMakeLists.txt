# Simple test placeholder
add_executable(test_basic test_basic.cpp)
target_link_libraries(test_basic PRIVATE libesc Zydis)

add_test(NAME BasicTest COMMAND test_basic)

# Disassembler unit tests with assembly snippets
add_executable(test_disassembler test_disassembler.cpp)
target_link_libraries(test_disassembler PRIVATE libesc Zydis)

add_test(NAME DisassemblerTest COMMAND test_disassembler)
