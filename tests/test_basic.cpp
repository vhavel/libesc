#include <libesc/libesc.hpp>
#include <iostream>
#include <cassert>

int main() {
    std::cout << "Running basic tests...\n";
    
    // Test version
    const char* version = libesc::get_version();
    assert(version != nullptr);
    std::cout << "Library version: " << version << "\n";
    
    std::cout << "All tests passed!\n";
    return 0;
}
