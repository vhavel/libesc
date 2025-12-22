#pragma once

#include "disassembler.hpp"
#include "cfg_analyzer.hpp"
#include <string>
#include <vector>
#include <set>
#include <map>

namespace libesc {

/**
 * @brief Information about a detected syscall
 */
struct SyscallInfo {
    uint64_t address;           // Address of syscall instruction
    int syscall_number;         // Syscall number (-1 if unknown)
    std::string syscall_name;   // Name of syscall (if known)
};

/**
 * @brief Detects and analyzes syscalls in ELF binaries
 */
class SyscallDetector {
public:
    SyscallDetector();
    ~SyscallDetector();

    /**
     * @brief Find all syscalls in disassembled code
     * @param instructions Instruction stream
     * @return Vector of detected syscalls
     */
    std::vector<SyscallInfo> find_syscalls(const InstructionStream& instructions);

    /**
     * @brief Find syscalls reachable from a specific address using CFG
     * @param instructions Instruction stream (needed to access basic block contents)
     * @param cfg Control flow graph
     * @param start_address Starting address
     * @return Vector of reachable syscalls
     */
    std::vector<SyscallInfo> find_reachable_syscalls(
        const InstructionStream& instructions,
        const std::map<uint64_t, BasicBlock>& cfg,
        uint64_t start_address);

    /**
     * @brief Get syscall name from number (x86_64 Linux)
     * @param syscall_num Syscall number
     * @return Syscall name or empty string if unknown
     */
    static std::string get_syscall_name(int syscall_num);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace libesc
