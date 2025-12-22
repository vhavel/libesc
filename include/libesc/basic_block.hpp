#pragma once

#include <cstdint>
#include <vector>

namespace libesc {

/**
 * @brief Basic block with metadata extracted during disassembly
 */
struct BasicBlock {
    uint64_t start_address;          // First instruction address
    uint64_t end_address;            // Last instruction address
    
    std::vector<uint64_t> successors;  // Jump targets and fall-through addresses
    
    // Metadata extracted during disassembly
    bool contains_syscall = false;
    uint64_t syscall_address = 0;        // Address of syscall instruction (if contains_syscall)
    int64_t syscall_rax_value = -1;      // RAX value at syscall (-1 = unknown, needs propagation)
    int64_t last_rax_value = -1;         // RAX value at block exit (-1 = unknown)
    
    // Block terminator type
    bool ends_with_ret = false;
    bool ends_with_unconditional_jump = false;
    bool ends_with_call = false;
};

/**
 * @brief Control flow graph represented as blocks with metadata
 */
struct ControlFlowGraph {
    std::vector<BasicBlock> blocks;
    
    // Helper to find block containing an address
    const BasicBlock* find_block(uint64_t address) const {
        for (const auto& block : blocks) {
            if (address >= block.start_address && address <= block.end_address) {
                return &block;
            }
        }
        return nullptr;
    }
};

} // namespace libesc
