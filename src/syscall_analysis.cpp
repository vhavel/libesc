#include "libesc/syscall_analysis.hpp"
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <vector>

namespace libesc {

namespace {

// Limited syscall name table for Linux x86-64
const char* get_syscall_name(int64_t syscall_number) {
    switch (syscall_number) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 8: return "lseek";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 13: return "rt_sigaction";
        case 14: return "rt_sigprocmask";
        case 16: return "ioctl";
        case 21: return "access";
        case 39: return "getpid";
        case 56: return "clone";
        case 57: return "fork";
        case 59: return "execve";
        case 60: return "exit";
        case 61: return "wait4";
        case 62: return "kill";
        case 63: return "uname";
        case 72: return "fcntl";
        case 79: return "getcwd";
        case 80: return "chdir";
        case 89: return "readlink";
        case 96: return "gettimeofday";
        case 102: return "getuid";
        case 104: return "getgid";
        case 107: return "geteuid";
        case 108: return "getegid";
        case 131: return "sigaltstack";
        case 158: return "arch_prctl";
        case 186: return "gettid";
        case 202: return "futex";
        case 218: return "set_tid_address";
        case 228: return "clock_gettime";
        case 231: return "exit_group";
        case 257: return "openat";
        case 273: return "set_robust_list";
        case 318: return "getrandom";
        default: return "";
    }
}

} // anonymous namespace

std::vector<SyscallInfo> analyze_syscalls(const ControlFlowGraph& cfg) {
    // Build address-to-block map for fast lookups
    std::unordered_map<uint64_t, const BasicBlock*> addr_to_block;
    addr_to_block.reserve(cfg.blocks.size());
    for (const auto& block : cfg.blocks) {
        addr_to_block[block.start_address] = &block;
    }
    
    // Build predecessor map (blocks that jump TO each block)
    std::unordered_map<const BasicBlock*, std::vector<const BasicBlock*>> predecessors;
    for (const auto& block : cfg.blocks) {
        for (uint64_t succ_addr : block.successors) {
            auto it = addr_to_block.find(succ_addr);
            if (it != addr_to_block.end()) {
                predecessors[it->second].push_back(&block);
            }
        }
    }
    
    // Lambda to find RAX values for a syscall block using backward propagation
    auto find_rax_values = [&](const BasicBlock* syscall_block) -> std::set<int64_t> {
        std::set<int64_t> rax_values;
        
        // If block sets RAX before syscall, use that
        if (syscall_block->syscall_rax_value >= 0) {
            rax_values.insert(syscall_block->syscall_rax_value);
            return rax_values;
        }
        
        // Otherwise, search backwards through predecessors
        std::unordered_set<const BasicBlock*> visited;
        std::vector<std::pair<const BasicBlock*, int>> worklist; // (block, depth)
        
        for (auto* pred : predecessors[syscall_block]) {
            worklist.push_back({pred, 1});
        }
        
        while (!worklist.empty()) {
            auto [block, depth] = worklist.back();
            worklist.pop_back();
            
            if (visited.count(block) || depth > 5) {  // Constant depth limit
                continue;
            }
            visited.insert(block);
            
            // If this block sets RAX at exit, use that value
            if (block->last_rax_value >= 0) {
                rax_values.insert(block->last_rax_value);
            } else {
                // Keep searching backwards
                for (auto* pred : predecessors[block]) {
                    worklist.push_back({pred, depth + 1});
                }
            }
        }
        
        // If no RAX value found, mark as unknown
        if (rax_values.empty()) {
            rax_values.insert(-1);
        }
        
        return rax_values;
    };
    
    // Collect all syscalls
    std::vector<SyscallInfo> syscalls;
    for (const auto& block : cfg.blocks) {
        if (block.contains_syscall) {
            auto rax_values = find_rax_values(&block);
            
            // Take the first value (or -1 if multiple/unknown)
            int64_t syscall_num = -1;
            if (rax_values.size() == 1) {
                syscall_num = *rax_values.begin();
            }
            
            SyscallInfo info;
            info.address = block.syscall_address;
            info.number = syscall_num;
            if (syscall_num >= 0) {
                const char* name = get_syscall_name(syscall_num);
                if (name && *name) {
                    info.name = name;
                }
            }
            
            syscalls.push_back(info);
        }
    }
    
    return syscalls;
}

} // namespace libesc
