#include <libesc/libesc.hpp>
#include "test_helpers.hpp"
#include <iostream>
#include <cassert>

void test_simple_syscall() {
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
}

void test_syscall_with_fallthrough() {
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
}

void test_conditional_branch() {
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
}

void test_rax_tracking_through_block() {
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
}

void test_rax_after_syscall() {
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
}

void test_call_instruction() {
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
}

void test_register_move_to_rax() {
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
}

int main() {
    test_simple_syscall();
    test_syscall_with_fallthrough();
    test_conditional_branch();
    test_rax_tracking_through_block();
    test_rax_after_syscall();
    test_call_instruction();
    test_register_move_to_rax();
    return 0;
}
