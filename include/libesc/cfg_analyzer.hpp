#pragma once

#include "disassembler.hpp"
#include <vector>
#include <set>
#include <map>
#include <memory>

namespace libesc {

/**
 * @brief Represents a basic block in the control flow graph
 */
struct BasicBlock {
    uint64_t start_address;
    uint64_t end_address;
    size_t start_idx;  // Index into instruction stream
    size_t end_idx;    // Inclusive end index
    std::vector<uint64_t> successors;  // Addresses of successor blocks
};

/**
 * @brief Control Flow Graph analyzer
 */
class CfgAnalyzer {
public:
    CfgAnalyzer();
    ~CfgAnalyzer();

    /**
     * @brief Build a control flow graph from disassembled instructions
     * @param instructions Instruction stream
     * @return Map of address to BasicBlock
     */
    std::map<uint64_t, BasicBlock> build_cfg(const InstructionStream& instructions);

    /**
     * @brief Find all reachable blocks from a given address
     * @param cfg Control flow graph
     * @param start_address Starting address
     * @return Set of reachable block addresses
     */
    std::set<uint64_t> find_reachable_blocks(
        const std::map<uint64_t, BasicBlock>& cfg,
        uint64_t start_address);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace libesc
