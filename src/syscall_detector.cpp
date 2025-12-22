#include "libesc/syscall_detector.hpp"
#include <string>
#include <algorithm>
#include <queue>

namespace libesc {

class SyscallDetector::Impl {
public:
    Impl() = default;

    // Track RAX value by looking backward through instruction stream
    int64_t find_rax_value(const InstructionStream& stream, size_t syscall_idx) {
        // Look backward from syscall instruction
        for (int i = syscall_idx - 1; i >= 0; i--) {
            auto inst = stream[i];
            
            // Check for mov rax/eax, <imm> using structured data
            if (inst.is_mov_to_rax() && inst.imm_value() >= 0) {
                return inst.imm_value();
            }
            
            // Stop at control flow instructions (basic block boundary)
            if (inst.is_branch() || inst.is_call() || inst.is_ret()) {
                break;
            }
        }
        
        return -1;
    }

    std::vector<SyscallInfo> find_syscalls(const InstructionStream& stream) {
        std::vector<SyscallInfo> syscalls;

        for (size_t i = 0; i < stream.size(); i++) {
            auto inst = stream[i];
            
            // Check for syscall instruction using pre-computed flag
            if (inst.is_syscall()) {
                
                SyscallInfo info;
                info.address = inst.address();
                
                // Try to determine syscall number from register tracking
                int64_t syscall_num = find_rax_value(stream, i);
                
                if (syscall_num >= 0) {
                    info.syscall_number = syscall_num;
                    info.syscall_name = get_syscall_name(syscall_num);
                } else {
                    info.syscall_number = -1;
                    info.syscall_name = "unknown";
                }
                
                syscalls.push_back(info);
            }
        }

        return syscalls;
    }

    std::vector<SyscallInfo> find_reachable_syscalls(
        const InstructionStream& stream,
        const std::map<uint64_t, BasicBlock>& cfg,
        uint64_t start_address) {
        
        // Map: block_address -> set of possible RAX values at block entry
        std::map<uint64_t, std::set<int64_t>> block_rax_values;
        
        // Worklist: blocks to process
        std::queue<uint64_t> worklist;
        std::set<uint64_t> processed;
        
        // Initialize with start block (RAX unknown)
        block_rax_values[start_address].insert(-1);
        worklist.push(start_address);
        
        // Dataflow analysis: propagate RAX values through CFG
        while (!worklist.empty()) {
            uint64_t block_addr = worklist.front();
            worklist.pop();
            
            if (processed.count(block_addr)) {
                continue;
            }
            processed.insert(block_addr);
            
            auto cfg_it = cfg.find(block_addr);
            if (cfg_it == cfg.end()) {
                continue;
            }
            
            const BasicBlock& block = cfg_it->second;
            std::set<int64_t> current_rax_values = block_rax_values[block_addr];
            
            // Process instructions in block to track RAX modifications
            for (size_t i = block.start_idx; i <= block.end_idx; i++) {
                auto inst = stream[i];
                if (inst.is_mov_to_rax() && inst.imm_value() >= 0) {
                    current_rax_values.clear();
                    current_rax_values.insert(inst.imm_value());
                }
            }
            
            // Propagate to successors
            for (uint64_t succ : block.successors) {
                bool changed = false;
                
                // Merge RAX values into successor
                for (int64_t val : current_rax_values) {
                    if (block_rax_values[succ].insert(val).second) {
                        changed = true;
                    }
                }
                
                // If changed, reprocess successor
                if (changed) {
                    processed.erase(succ);
                    worklist.push(succ);
                }
            }
        }
        
        // Now find syscalls and assign RAX values
        std::vector<SyscallInfo> syscalls;
        
        for (const auto& [block_addr, block] : cfg) {
            const auto& rax_values = block_rax_values[block_addr];
            std::set<int64_t> current_values = rax_values;
            
            for (size_t i = block.start_idx; i <= block.end_idx; i++) {
                auto inst = stream[i];
                
                // Update RAX tracking
                if (inst.is_mov_to_rax() && inst.imm_value() >= 0) {
                    current_values.clear();
                    current_values.insert(inst.imm_value());
                }
                
                // Check for syscall
                if (inst.is_syscall()) {
                    
                    // Create syscall info for each possible RAX value
                    for (int64_t rax_val : current_values) {
                        SyscallInfo info;
                        info.address = inst.address();
                        
                        if (rax_val >= 0) {
                            info.syscall_number = rax_val;
                            info.syscall_name = get_syscall_name(rax_val);
                        } else {
                            info.syscall_number = -1;
                            info.syscall_name = "unknown";
                        }
                        
                        syscalls.push_back(info);
                        break; // Only add once per syscall location
                    }
                }
            }
        }
        
        return syscalls;
    }
};

SyscallDetector::SyscallDetector()
    : pimpl_(std::make_unique<Impl>()) {}

SyscallDetector::~SyscallDetector() = default;

std::vector<SyscallInfo> SyscallDetector::find_syscalls(const InstructionStream& instructions) {
    return pimpl_->find_syscalls(instructions);
}

std::vector<SyscallInfo> SyscallDetector::find_reachable_syscalls(
    const InstructionStream& instructions,
    const std::map<uint64_t, BasicBlock>& cfg,
    uint64_t start_address) {
    return pimpl_->find_reachable_syscalls(instructions, cfg, start_address);
}

std::string SyscallDetector::get_syscall_name(int syscall_num) {
    // x86_64 Linux syscall table
    static const std::map<int, std::string> syscall_table = {
        {0, "read"}, {1, "write"}, {2, "open"}, {3, "close"},
        {4, "stat"}, {5, "fstat"}, {6, "lstat"}, {7, "poll"},
        {8, "lseek"}, {9, "mmap"}, {10, "mprotect"}, {11, "munmap"},
        {12, "brk"}, {13, "rt_sigaction"}, {14, "rt_sigprocmask"},
        {15, "rt_sigreturn"}, {16, "ioctl"}, {17, "pread64"},
        {18, "pwrite64"}, {19, "readv"}, {20, "writev"},
        {21, "access"}, {22, "pipe"}, {23, "select"},
        {24, "sched_yield"}, {25, "mremap"}, {26, "msync"},
        {27, "mincore"}, {28, "madvise"}, {29, "shmget"},
        {30, "shmat"}, {31, "shmctl"}, {32, "dup"},
        {33, "dup2"}, {34, "pause"}, {35, "nanosleep"},
        {56, "clone"}, {57, "fork"}, {58, "vfork"},
        {59, "execve"}, {60, "exit"}, {61, "wait4"},
        {62, "kill"}, {63, "uname"}, {72, "fcntl"},
        {78, "getdents"}, {79, "getcwd"}, {80, "chdir"},
        {89, "readlink"}, {96, "gettimeofday"},
        {158, "arch_prctl"}, {186, "gettid"}, {202, "futex"},
        {217, "getdents64"}, {231, "exit_group"}, {234, "tgkill"},
        {257, "openat"}, {262, "newfstatat"}, {292, "dup3"}
    };

    auto it = syscall_table.find(syscall_num);
    return (it != syscall_table.end()) ? it->second : "";
}

} // namespace libesc
