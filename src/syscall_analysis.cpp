#include "libesc/syscall_analysis.hpp"
#include <unordered_map>
#include <set>
#include <functional>

namespace libesc {

namespace {

// Limited syscall name table for Linux x86-64
const char* get_syscall_name(uint64_t syscall_number) {
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

std::vector<SyscallInfo> ControlFlowGraph::analyze_syscalls() const {
    // Build address-to-block map for fast lookups
    std::unordered_map<uint64_t, BasicBlock*> addr_to_block;
    addr_to_block.reserve(blocks.size());
    for (auto& block : blocks) {
        addr_to_block[block.start_address] = const_cast<BasicBlock*>(&block);
    }
    
    // Build predecessor map (blocks that jump TO each block)
    std::unordered_map<BasicBlock*, std::vector<BasicBlock*>> predecessors;
    for (auto& block : blocks) {
        for (uint64_t succ_addr : block.successors) {
            auto it = addr_to_block.find(succ_addr);
            if (it != addr_to_block.end()) {
                predecessors[it->second].push_back(const_cast<BasicBlock*>(&block));
            }
        }
    }
    
    // Track possible RAX values at each block's syscall (if it has one)
    std::unordered_map<BasicBlock*, std::set<RaxValue>> syscall_rax_values;
    
    // Track possible RAX values at each block's exit
    std::unordered_map<BasicBlock*, std::set<RaxValue>> exit_rax_values;
    
    // Initialize with local information
    for (auto& block : blocks) {
        BasicBlock* b = const_cast<BasicBlock*>(&block);
        
        if (!std::holds_alternative<Tainted>(block.last_rax_value)) {
            exit_rax_values[b].insert(block.last_rax_value);
        }
        if (block.syscall_address.has_value() && !std::holds_alternative<Tainted>(block.syscall_rax_value)) {
            exit_rax_values[b].insert(block.syscall_rax_value);
            syscall_rax_values[b].insert(block.syscall_rax_value);
        }
    }
    
    // Floyd-Warshall style iterations until convergence
    bool changed = true;
    int iteration = 0;
    while (changed && iteration < 100) {
        changed = false;
        iteration++;
        
        for (auto& block : blocks) {
            BasicBlock* b = const_cast<BasicBlock*>(&block);
            
            // Merge all incoming RAX values from predecessors
            std::set<RaxValue> incoming_rax;
            for (auto* pred : predecessors[b]) {
                if (exit_rax_values.count(pred)) {
                    for (const auto& val : exit_rax_values[pred]) {
                        incoming_rax.insert(val);
                    }
                }
            }
            
            // If multiple different concrete values flow in, mark as tainted
            if (incoming_rax.size() > 1) {
                bool has_concrete = false;
                std::optional<uint64_t> first_concrete;
                for (const auto& val : incoming_rax) {
                    if (std::holds_alternative<uint64_t>(val)) {
                        if (!has_concrete) {
                            first_concrete = std::get<uint64_t>(val);
                            has_concrete = true;
                        } else if (*first_concrete != std::get<uint64_t>(val)) {
                            // Different concrete values - mark as tainted
                            incoming_rax.clear();
                            incoming_rax.insert(Tainted{});
                            break;
                        }
                    }
                }
            }
            
            // If block has syscall and no local RAX assignment before syscall
            if (block.syscall_address.has_value() && std::holds_alternative<Tainted>(block.syscall_rax_value)) {
                auto& current = syscall_rax_values[b];
                size_t old_size = current.size();
                for (const auto& val : incoming_rax) {
                    current.insert(val);
                }
                if (current.size() != old_size) {
                    changed = true;
                }
            }
            
            // If block doesn't set RAX locally, propagate incoming values
            if (std::holds_alternative<Tainted>(block.last_rax_value) && !incoming_rax.empty()) {
                auto& current = exit_rax_values[b];
                size_t old_size = current.size();
                for (const auto& val : incoming_rax) {
                    current.insert(val);
                }
                if (current.size() != old_size) {
                    changed = true;
                }
            }
        }
    }
    
    // Collect all syscalls
    std::vector<SyscallInfo> syscalls;
    for (const auto& block : blocks) {
        if (block.syscall_address.has_value()) {
            BasicBlock* b = const_cast<BasicBlock*>(&block);
            
            // Determine syscall number
            std::optional<uint64_t> syscall_num;
            
            // First check if block sets RAX before syscall
            if (!std::holds_alternative<Tainted>(block.syscall_rax_value)) {
                const auto& val = block.syscall_rax_value;
                if (std::holds_alternative<uint64_t>(val)) {
                    syscall_num = std::get<uint64_t>(val);
                }
            } else if (syscall_rax_values.count(b) && syscall_rax_values[b].size() == 1) {
                // Single propagated value
                const auto& val = *syscall_rax_values[b].begin();
                if (std::holds_alternative<uint64_t>(val)) {
                    syscall_num = std::get<uint64_t>(val);
                }
            }
            
            SyscallInfo info;
            info.address = *block.syscall_address;
            info.number = syscall_num;
            if (syscall_num.has_value()) {
                const char* name = get_syscall_name(*syscall_num);
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