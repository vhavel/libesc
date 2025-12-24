#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <variant>
#include <set>

namespace libesc {

/**
 * @brief Marker type for tainted/unknown register values
 */
struct Tainted {
    bool operator==(const Tainted&) const { return true; }
    bool operator<(const Tainted&) const { return false; }
};

/**
 * @brief Register value that can be concrete or tainted
 */
using RaxValue = std::variant<uint64_t, Tainted>;

/**
 * @brief Basic block with metadata extracted during disassembly
 */
struct BasicBlock {
    uint64_t start_address;          // First instruction address
    uint64_t end_address;            // Last instruction address
    
    std::vector<uint64_t> successors;  // Jump targets and fall-through addresses
    
    // Metadata extracted during disassembly
    std::optional<uint64_t> syscall_address;     // Address of syscall instruction
    RaxValue syscall_rax_value = Tainted{};      // RAX value at syscall (Tainted = unknown/needs propagation)
    RaxValue last_rax_value = Tainted{};         // RAX value at block exit (Tainted = doesn't set RAX)
    
    // Block terminator type
    bool ends_with_ret = false;
    bool ends_with_call = false;
};

/**
 * @brief Information about a detected syscall
 */
struct SyscallInfo {
    uint64_t address;              // Address of the syscall instruction
    std::optional<uint64_t> number; // Syscall number (nullopt if unknown/tainted)
    std::string name;              // Syscall name (empty if unknown or unnamed)
};

/**
 * @brief Control flow graph represented as blocks with metadata
 */
struct ControlFlowGraph {
    std::vector<BasicBlock> blocks;
    
    /**
     * @brief Analyze syscalls in the CFG
     * 
     * Uses iterative dataflow analysis to propagate RAX values through
     * the CFG and identify syscall numbers.
     * 
     * @return Vector of detected syscalls with addresses, numbers, and names
     */
    std::vector<SyscallInfo> analyze_syscalls() const;
    
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
