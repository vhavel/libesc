#include <libesc/libesc.hpp>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <queue>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <map>

void print_usage(const char* program_name) {
    std::cout << "ELF Syscall Inspector v" << libesc::get_version() << "\n\n";
    std::cout << "Usage: " << program_name << " <elf_binary>\n\n";
    std::cout << "Analyzes Linux ELF binaries and detects syscall invocations.\n";
}

std::string get_syscall_name(int syscall_num) {
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
        {217, "getdents64"}, {218, "set_tid_address"}, {231, "exit_group"},
        {234, "tgkill"}, {257, "openat"}, {262, "newfstatat"}, {267, "readlinkat"},
        {273, "set_robust_list"}, {292, "dup3"}, {302, "prlimit64"},
        {318, "getrandom"}, {322, "execveat"}, {334, "rseq"}
    };

    auto it = syscall_table.find(syscall_num);
    return (it != syscall_table.end()) ? it->second : "";
}

int main(int argc, char* argv[]) {
    if (argc != 2 || std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return (argc == 2) ? 0 : 1;
    }

    const char* binary_path = argv[1];

    try {
        libesc::ElfInspector inspector(binary_path);
        
        auto arch = libesc::Disassembler::Architecture::X86_64;
        libesc::Disassembler disasm(arch);
        
        auto code = inspector.get_code_section();
        auto cfg = disasm.disassemble(code, inspector.get_text_base());
        // Pre-build address-to-block map for fast lookups
        std::unordered_map<uint64_t, const libesc::BasicBlock*> addr_to_block;
        addr_to_block.reserve(cfg.blocks.size());
        for (const auto& block : cfg.blocks) {
            addr_to_block[block.start_address] = &block;
        }
        
        // Build predecessor map (blocks that jump TO each block)
        std::unordered_map<const libesc::BasicBlock*, std::vector<const libesc::BasicBlock*>> predecessors;
        for (const auto& block : cfg.blocks) {
            for (uint64_t succ_addr : block.successors) {
                auto it = addr_to_block.find(succ_addr);
                if (it != addr_to_block.end()) {
                    predecessors[it->second].push_back(&block);
                }
            }
        }
        
        // For syscall blocks without RAX set, search backwards to find RAX values
        // Limit search depth to avoid performance issues
        const int MAX_BACKWARD_DEPTH = 5;
        
        auto find_rax_values = [&](const libesc::BasicBlock* syscall_block) -> std::set<int64_t> {
            std::set<int64_t> rax_values;
            
            // If block sets RAX before syscall, use that
            if (syscall_block->syscall_rax_value >= 0) {
                rax_values.insert(syscall_block->syscall_rax_value);
                return rax_values;
            }
            
            // Otherwise, search backwards through predecessors
            std::unordered_set<const libesc::BasicBlock*> visited;
            std::vector<std::pair<const libesc::BasicBlock*, int>> worklist; // (block, depth)
            
            for (auto* pred : predecessors[syscall_block]) {
                worklist.push_back({pred, 1});
            }
            
            while (!worklist.empty()) {
                auto [block, depth] = worklist.back();
                worklist.pop_back();
                
                if (visited.count(block) || depth > MAX_BACKWARD_DEPTH) {
                    continue;
                }
                visited.insert(block);
                
                // If this block sets RAX, use that value
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
        
        // Collect syscalls
        std::cout << "=== Syscalls ===\n";
        int syscall_count = 0;
        for (const auto& block : cfg.blocks) {
            if (block.contains_syscall) {
                auto rax_values = find_rax_values(&block);
                
                for (int64_t rax_val : rax_values) {
                    std::cout << "0x" << std::hex << block.syscall_address << ": ";
                    if (rax_val >= 0) {
                        std::cout << "syscall " << std::dec << rax_val;
                        std::string name = get_syscall_name(rax_val);
                        if (!name.empty()) {
                            std::cout << " (" << name << ")";
                        }
                    } else {
                        std::cout << "syscall (number unknown)";
                    }
                    std::cout << "\n";
                    syscall_count++;
                    break;  // Only count each syscall location once
                }
            }
        }
        if (syscall_count == 0) {
            std::cout << "No syscalls detected\n";
        }
        std::cout << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
