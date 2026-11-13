#include <libesc/libesc.hpp>
#include <iostream>

int main() {
    libesc::ElfFile inspector("test_syscall");
    auto arch = libesc::Disassembler::Architecture::X86_64;
    libesc::Disassembler disasm(arch);
    auto code = inspector.get_code_section();
    auto instructions = disasm.disassemble(code, inspector.get_text_base());
    
    std::cout << "Total significant instructions: " << instructions.size() << "\n";
    std::cout << "Entry point: 0x" << std::hex << inspector.get_entry_point() << "\n";
    std::cout << "Text base: 0x" << inspector.get_text_base() << "\n";
    
    // Find first few instructions
    for (size_t i = 0; i < std::min<size_t>(20, instructions.size()); i++) {
        auto inst = instructions[i];
        std::cout << "  [" << i << "] 0x" << std::hex << inst.address();
        if (inst.is_branch()) std::cout << " BRANCH";
        if (inst.is_call()) std::cout << " CALL";
        if (inst.is_ret()) std::cout << " RET";
        if (inst.is_syscall()) std::cout << " SYSCALL";
        if (inst.is_mov_to_rax()) std::cout << " MOV_RAX=" << std::dec << inst.imm_value();
        std::cout << "\n";
    }
    
    libesc::ReachabilityAnalyzer analyzer;
    auto syscalls = analyzer.find_reachable_syscalls(instructions, inspector.get_entry_point());
    std::cout << "\nReachable syscalls: " << syscalls.size() << "\n";
    
    return 0;
}
