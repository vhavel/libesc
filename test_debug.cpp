#include <libesc/libesc.hpp>
#include <iostream>

int main() {
    libesc::ElfFile inspector("test_syscall");
    auto arch = libesc::Disassembler::Architecture::X86_64;
    libesc::Disassembler disasm(arch);
    auto code = inspector.get_code_section();
    auto cfg = disasm.disassemble(code, inspector.get_text_base());
    
    std::cout << "Entry point: 0x" << std::hex << inspector.get_entry_point() << "\n";
    std::cout << "Text base: 0x" << inspector.get_text_base() << "\n";
    std::cout << "Blocks: " << std::dec << cfg.blocks.size() << "\n";
    
    auto* entry_block = cfg.find_block(inspector.get_entry_point());
    if (entry_block) {
        std::cout << "Found entry block: [0x" << std::hex << entry_block->start_address 
                  << " - 0x" << entry_block->end_address << "]\n";
        std::cout << "Entry block successors: " << std::dec << entry_block->successors.size() << "\n";
        for (auto succ : entry_block->successors) {
            std::cout << "  Successor: 0x" << std::hex << succ << "\n";
        }
    } else {
        std::cout << "Entry block NOT FOUND!\n";
        std::cout << "First few blocks:\n";
        for (size_t i = 0; i < std::min<size_t>(10, cfg.blocks.size()); i++) {
            std::cout << "  Block " << i << ": [0x" << std::hex << cfg.blocks[i].start_address 
                      << " - 0x" << cfg.blocks[i].end_address << "]\n";
        }
    }
    
    int syscall_blocks = 0;
    for (const auto& block : cfg.blocks) {
        if (block.syscall_address.has_value()) {
            syscall_blocks++;
        }
    }
    std::cout << "\nBlocks with syscalls: " << std::dec << syscall_blocks << "\n";
    
    return 0;
}
