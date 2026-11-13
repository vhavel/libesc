#include <libesc/libesc.hpp>
#include <iostream>
#include <iomanip>

int main() {
    try {
        // Analyze syscalls in the binary
        auto syscalls = libesc::analyze_elf_syscalls("../test_syscall");
        
        std::cout << "=== Syscall Analysis ===\n";
        std::cout << "Found " << std::dec << syscalls.size() << " syscalls\n\n";
        
        for (const auto& sc : syscalls) {
            std::cout << "0x" << std::hex << sc.address << ": ";
            if (sc.number.has_value()) {
                std::cout << "syscall " << std::dec << *sc.number;
                if (!sc.name.empty()) {
                    std::cout << " (" << sc.name << ")";
                }
            } else {
                std::cout << "syscall (number unknown)";
            }
            std::cout << "\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
