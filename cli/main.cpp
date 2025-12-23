#include <libesc/libesc.hpp>
#include <iostream>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc != 2 || std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
        std::cerr << "Usage: " << argv[0] << " <elf_binary>\n";
        return (argc == 2) ? 0 : 1;
    }

    const char* binary_path = argv[1];

    try {
        libesc::ElfInspector inspector(binary_path);
        libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
        auto cfg = disasm.disassemble(inspector.get_code_section(), inspector.get_text_base());
        auto syscalls = libesc::analyze_syscalls(cfg);
        
        for (const auto& sc : syscalls) {
            std::cout << "0x" << std::hex << sc.address << ": ";
            if (sc.number >= 0) {
                std::cout << "syscall " << std::dec << sc.number;
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
