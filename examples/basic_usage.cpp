#include <libesc/libesc.hpp>
#include <iostream>
#include <iomanip>

int main() {
    try {
        // Load ELF binary
        libesc::ElfInspector inspector("../test_syscall");
        
        // Get binary information
        auto info = inspector.get_info();
        std::cout << "=== ELF Binary Information ===\n";
        std::cout << "Architecture: " << info.architecture << "\n";
        std::cout << "Entry point: 0x" << std::hex << info.entry_point << "\n\n";
        
        // Disassemble and build CFG
        auto arch = libesc::Disassembler::Architecture::X86_64;
        libesc::Disassembler disasm(arch);
        
        // Get code and disassemble
        auto code = inspector.get_code_section();
        auto cfg = disasm.disassemble(code, inspector.get_text_base());
        
        std::cout << "=== Control Flow Graph ===\n";
        std::cout << "Basic blocks: " << std::dec << cfg.blocks.size() << "\n\n";
        
        // Show blocks with syscalls
        std::cout << "=== Blocks containing syscalls ===\n";
        for (const auto& block : cfg.blocks) {
            if (block.contains_syscall) {
                std::cout << "Block [0x" << std::hex << block.start_address 
                         << " - 0x" << block.end_address << "]\n";
                if (block.last_rax_value >= 0) {
                    std::cout << "  RAX value: " << std::dec << block.last_rax_value << "\n";
                }
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
