#include "libesc/cfg_analyzer.hpp"
#include <queue>
#include <algorithm>
#include <Zydis/Zydis.h>

namespace libesc {

class CfgAnalyzer::Impl {
public:
    Impl() = default;

    bool is_unconditional_jump(const InstructionStream::View& inst) {
        // jmp has no condition
        return inst.is_branch() && inst.insn.mnemonic == ZYDIS_MNEMONIC_JMP;
    }

    std::map<uint64_t, BasicBlock> build_cfg(const InstructionStream& stream) {
        std::map<uint64_t, BasicBlock> cfg;
        
        if (stream.size() == 0) {
            return cfg;
        }

        // Step 1: Identify basic block boundaries
        std::set<uint64_t> block_starts;
        block_starts.insert(stream[0].address());

        for (size_t i = 0; i < stream.size(); i++) {
            auto inst = stream[i];
            
            // Branch targets start new blocks
            if (inst.is_branch() || inst.is_call()) {
                if (inst.jump_target() != 0) {
                    block_starts.insert(inst.jump_target());
                }
                
                // Instruction after branch/call starts new block (except unconditional jump and ret)
                if (i + 1 < stream.size() && 
                    !is_unconditional_jump(stream[i]) && !inst.is_ret()) {
                    block_starts.insert(stream[i + 1].address());
                }
            }
            
            // Instruction after terminator starts new block
            if ((inst.is_ret() || inst.is_syscall()) && i + 1 < stream.size()) {
                block_starts.insert(stream[i + 1].address());
            }
        }

        // Step 2: Build basic blocks
        std::map<uint64_t, size_t> addr_to_idx;
        for (size_t i = 0; i < stream.size(); i++) {
            addr_to_idx[stream[i].address()] = i;
        }

        auto starts_vec = std::vector<uint64_t>(block_starts.begin(), block_starts.end());
        std::sort(starts_vec.begin(), starts_vec.end());

        for (size_t i = 0; i < starts_vec.size(); i++) {
            uint64_t start_addr = starts_vec[i];
            
            auto it = addr_to_idx.find(start_addr);
            if (it == addr_to_idx.end()) {
                continue;
            }

            size_t start_idx = it->second;
            size_t end_idx = start_idx;

            // Find end of basic block
            for (size_t j = start_idx; j < stream.size(); j++) {
                end_idx = j;
                auto inst = stream[j];
                
                // Block ends at branch, call, or terminator
                if (inst.is_branch() || inst.is_call() || inst.is_ret() || inst.is_syscall()) {
                    break;
                }
                
                // Block ends before next block start
                if (j + 1 < stream.size() && 
                    block_starts.count(stream[j + 1].address())) {
                    break;
                }
            }

            BasicBlock block;
            block.start_address = start_addr;
            block.end_address = stream[end_idx].address();
            block.start_idx = start_idx;
            block.end_idx = end_idx;

            cfg[start_addr] = std::move(block);
        }

        // Step 3: Build successor relationships
        for (auto& [addr, block] : cfg) {
            auto last_inst = stream[block.end_idx];
            
            if (last_inst.is_branch()) {
                if (last_inst.jump_target() != 0 && cfg.count(last_inst.jump_target())) {
                    block.successors.push_back(last_inst.jump_target());
                }
                
                // Conditional branches have fall-through
                if (!is_unconditional_jump(last_inst)) {
                    uint64_t next_addr = last_inst.address() + last_inst.size();
                    if (cfg.count(next_addr)) {
                        block.successors.push_back(next_addr);
                    }
                }
            } else if (last_inst.is_call()) {
                // After call, execution continues to next instruction
                uint64_t next_addr = last_inst.address() + last_inst.size();
                if (cfg.count(next_addr)) {
                    block.successors.push_back(next_addr);
                }
            } else if (!last_inst.is_ret() && !last_inst.is_syscall()) {
                // Fall through to next block
                uint64_t next_addr = last_inst.address() + last_inst.size();
                if (cfg.count(next_addr)) {
                    block.successors.push_back(next_addr);
                }
            }
        }

        return cfg;
    }

    std::set<uint64_t> find_reachable_blocks(
        const std::map<uint64_t, BasicBlock>& cfg,
        uint64_t start_address) {
        
        std::set<uint64_t> reachable;
        std::queue<uint64_t> worklist;

        worklist.push(start_address);

        while (!worklist.empty()) {
            uint64_t current = worklist.front();
            worklist.pop();

            if (reachable.count(current)) {
                continue;
            }

            reachable.insert(current);

            auto it = cfg.find(current);
            if (it != cfg.end()) {
                for (uint64_t successor : it->second.successors) {
                    if (!reachable.count(successor)) {
                        worklist.push(successor);
                    }
                }
            }
        }

        return reachable;
    }
};

CfgAnalyzer::CfgAnalyzer()
    : pimpl_(std::make_unique<Impl>()) {}

CfgAnalyzer::~CfgAnalyzer() = default;

std::map<uint64_t, BasicBlock> CfgAnalyzer::build_cfg(const InstructionStream& instructions) {
    return pimpl_->build_cfg(instructions);
}

std::set<uint64_t> CfgAnalyzer::find_reachable_blocks(
    const std::map<uint64_t, BasicBlock>& cfg,
    uint64_t start_address) {
    return pimpl_->find_reachable_blocks(cfg, start_address);
}

} // namespace libesc
