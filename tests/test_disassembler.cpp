#include <libesc/libesc.hpp>
#include "test_helpers.hpp"
#include <iostream>
#include <cassert>

void test_simple_syscall() {
    std::cout << "Test: Simple syscall with immediate RAX\n";
    
    auto code = make_code({
        MOV_EAX_IMM32(0x1),
        SYSCALL()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x1000);
    
    assert(cfg.blocks.size() == 1);
    assert(cfg.blocks[0].contains_syscall == true);
    assert(cfg.blocks[0].syscall_address == 0x1005);
    assert(cfg.blocks[0].syscall_rax_value == 1);
    
    std::cout << "  ✓ Detected syscall with RAX=1\n";
}

void test_syscall_with_fallthrough() {
    std::cout << "Test: Syscall with fall-through\n";
    
    auto code = make_code({
        MOV_EAX_IMM32(0x3c),  // exit
        SYSCALL(),
        RET()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x2000);
    
    assert(cfg.blocks.size() == 2);
    
    // First block: syscall
    assert(cfg.blocks[0].contains_syscall == true);
    assert(cfg.blocks[0].syscall_rax_value == 0x3c);
    assert(cfg.blocks[0].successors.size() == 1);
    assert(cfg.blocks[0].successors[0] == 0x2007);
    
    // Second block: ret
    assert(cfg.blocks[1].contains_syscall == false);
    assert(cfg.blocks[1].ends_with_ret == true);
    
    std::cout << "  ✓ Two blocks created with proper successors\n";
}

void test_conditional_branch() {
    std::cout << "Test: Conditional branch\n";
    
    auto code = make_code({
        TEST_EAX_EAX(),
        JZ_REL8(5),
        MOV_EAX_IMM32(0x1),
        SYSCALL(),
        RET()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x3000);
    
    // Block 1: test + jz (should have 2 successors)
    bool found_branch_block = false;
    for (const auto& block : cfg.blocks) {
        if (block.start_address == 0x3000) {
            assert(block.successors.size() == 2);
            found_branch_block = true;
        }
    }
    assert(found_branch_block);
    
    std::cout << "  ✓ Conditional branch creates multiple successors\n";
}

void test_rax_tracking_through_block() {
    std::cout << "Test: RAX tracking through block\n";
    
    auto code = make_code({
        MOV_EAX_IMM32(0x5),
        MOV_EBX_IMM32(0xa),
        MOV_EAX_IMM32(0x10),  // overwrites
        SYSCALL()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x4000);
    
    assert(cfg.blocks.size() == 1);
    assert(cfg.blocks[0].syscall_rax_value == 0x10);  // Should use last value
    
    std::cout << "  ✓ Uses most recent RAX value before syscall\n";
}

void test_rax_after_syscall() {
    std::cout << "Test: RAX modified after syscall\n";
    
    auto code = make_code({
        MOV_EAX_IMM32(0xc),   // brk
        SYSCALL(),
        MOV_EAX_IMM32(0xff),  // after syscall
        RET()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x5000);
    
    assert(cfg.blocks.size() == 2);
    
    // First block: syscall
    assert(cfg.blocks[0].syscall_rax_value == 0xc);   // Syscall uses 0xc
    assert(cfg.blocks[0].last_rax_value == 0xc);       // Exit value still 0xc (after syscall is new block)
    
    // Second block: after syscall
    assert(cfg.blocks[1].last_rax_value == 0xff);      // This block has 0xff
    
    std::cout << "  ✓ Syscall block correctly separated from post-syscall code\n";
}

void test_call_instruction() {
    std::cout << "Test: Call instruction creates edges\n";
    
    auto code = make_code({
        CALL_REL32(1),
        RET(),
        MOV_EAX_IMM32(0x1),
        SYSCALL()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x1005);
    
    // Should have blocks for: call, ret, and syscall
    assert(cfg.blocks.size() >= 2);
    
    // Call block should have 2 successors (target + fallthrough)
    bool found_call = false;
    for (const auto& block : cfg.blocks) {
        if (block.ends_with_call) {
            assert(block.successors.size() == 2);
            found_call = true;
        }
    }
    assert(found_call);
    
    std::cout << "  ✓ Call creates both target and fall-through edges\n";
}

void test_register_move_to_rax() {
    std::cout << "Test: Register-to-register move makes RAX unknown\n";
    
    auto code = make_code({
        MOV_EDX_IMM32(0x5),
        MOV_EAX_EDX(),  // register move - not immediate
        SYSCALL()
    });
    
    libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
    auto cfg = disasm.disassemble(code, 0x6000);
    
    assert(cfg.blocks.size() == 1);
    // syscall_rax_value should be -1 (unknown) because we only track immediates
    assert(cfg.blocks[0].syscall_rax_value == -1);
    
    std::cout << "  ✓ Register moves correctly mark RAX as unknown\n";
}

int main() {
    std::cout << "Running disassembler unit tests...\n\n";
    
    try {
        test_simple_syscall();
        test_syscall_with_fallthrough();
        test_conditional_branch();
        test_rax_tracking_through_block();
        test_rax_after_syscall();
        test_call_instruction();
        test_register_move_to_rax();
        
        std::cout << "\n✓ All disassembler tests passed!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}
