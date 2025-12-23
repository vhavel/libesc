#pragma once

#include "basic_block.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace libesc {

/**
 * @brief Information about a detected syscall
 */
struct SyscallInfo {
    uint64_t address;     // Address of the syscall instruction
    int64_t number;       // Syscall number (-1 if unknown)
    std::string name;     // Syscall name (empty if unknown or unnamed)
};

/**
 * @brief Analyze a CFG to detect syscalls and their numbers
 * 
 * Uses backward propagation through the CFG to determine RAX values
 * at syscall sites. Searches up to depth 5 backwards for RAX values.
 * 
 * @param cfg Control flow graph to analyze
 * @return Vector of detected syscalls with addresses, numbers, and names
 */
std::vector<SyscallInfo> analyze_syscalls(const ControlFlowGraph& cfg);

} // namespace libesc
