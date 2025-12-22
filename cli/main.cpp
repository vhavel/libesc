#include <libesc/libesc.hpp>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <queue>
#include <set>
#include <map>

void print_usage(const char* program_name) {
    std::cout << "ELF Syscall Inspector v" << libesc::get_version() << "\n\n";
    std::cout << "Usage: " << program_name << " [options] <elf_binary>\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --info        Display ELF binary information\n";
    std::cout << "  -s, --syscalls    Detect syscalls\n";
    std::cout << "  -c, --cfg         Perform CFG analysis\n";
    std::cout << "  -h, --help        Show this help message\n";
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
        {217, "getdents64"}, {231, "exit_group"}, {234, "tgkill"},
        {257, "openat"}, {262, "newfstatat"}, {292, "dup3"}
    };

    auto it = syscall_table.find(syscall_num);
    return (it != syscall_table.end()) ? it->second : "";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    bool show_info = false;
    bool detect_syscalls = false;
    bool analyze_cfg = false;
    const char* binary_path = nullptr;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "-i") == 0 || std::strcmp(argv[i], "--info") == 0) {
            show_info = true;
        } else if (std::strcmp(argv[i], "-s") == 0 || std::strcmp(argv[i], "--syscalls") == 0) {
            detect_syscalls = true;
        } else if (std::strcmp(argv[i], "-c") == 0 || std::strcmp(argv[i], "--cfg") == 0) {
            analyze_cfg = true;
        } else {
            binary_path = argv[i];
        }
    }

    if (!binary_path) {
        std::cerr << "Error: No binary path specified\n";
        print_usage(argv[0]);
        return 1;
    }

    try {
        libesc::ElfInspector inspector(binary_path);

        if (show_info) {
            auto info = inspector.get_info();
            std::cout << "=== ELF Information ===\n";
            std::cout << "Path: " << info.path << "\n";
            std::cout << "Architecture: " << info.architecture << "\n";
            std::cout << "64-bit: " << (info.is_64bit ? "Yes" : "No") << "\n";
            std::cout << "Entry point: 0x" << std::hex << info.entry_point << "\n\n";
        }

        if (detect_syscalls || analyze_cfg) {
            auto arch = libesc::Disassembler::Architecture::X86_64;
            libesc::Disassembler disasm(arch);
            
            auto code = inspector.get_code_section();
            auto cfg = disasm.disassemble(code, inspector.get_text_base());

            if (analyze_cfg) {
                std::cout << "=== Control Flow Graph ===\n";
                std::cout << "Basic blocks: " << cfg.blocks.size() << "\n\n";
            }
                
            if (detect_syscalls) {
                // Find reachable blocks from entry point
                std::set<const libesc::BasicBlock*> reachable;
                std::queue<const libesc::BasicBlock*> worklist;
                
                auto* entry_block = cfg.find_block(inspector.get_entry_point());
                if (entry_block) {
                    worklist.push(entry_block);
                    
                    while (!worklist.empty()) {
                        auto* block = worklist.front();
                        worklist.pop();
                        
                        if (reachable.count(block)) {
                            continue;
                        }
                        reachable.insert(block);
                        
                        // Follow successors
                        for (uint64_t succ_addr : block->successors) {
                            auto* succ = cfg.find_block(succ_addr);
                            if (succ && !reachable.count(succ)) {
                                worklist.push(succ);
                            }
                        }
                    }
                }
                
                // Propagate RAX values and collect syscalls
                std::map<const libesc::BasicBlock*, std::set<int64_t>> block_rax_values;
                block_rax_values[entry_block].insert(-1);  // Unknown at entry
                
                std::queue<const libesc::BasicBlock*> dataflow_worklist;
                std::set<const libesc::BasicBlock*> processed;
                dataflow_worklist.push(entry_block);
                
                while (!dataflow_worklist.empty()) {
                    auto* block = dataflow_worklist.front();
                    dataflow_worklist.pop();
                    
                    if (processed.count(block)) {
                        continue;
                    }
                    processed.insert(block);
                    
                    auto current_rax = block_rax_values[block];
                    
                    // Update RAX value if block modifies it
                    if (block->last_rax_value >= 0) {
                        current_rax.clear();
                        current_rax.insert(block->last_rax_value);
                    }
                    
                    // Propagate to successors
                    for (uint64_t succ_addr : block->successors) {
                        auto* succ = cfg.find_block(succ_addr);
                        if (succ && reachable.count(succ)) {
                            bool changed = false;
                            for (int64_t val : current_rax) {
                                if (block_rax_values[succ].insert(val).second) {
                                    changed = true;
                                }
                            }
                            if (changed) {
                                processed.erase(succ);
                                dataflow_worklist.push(succ);
                            }
                        }
                    }
                }
                
                // Collect syscalls
                std::cout << "=== Reachable Syscalls ===\n";
                int syscall_count = 0;
                for (const auto& block : cfg.blocks) {
                    if (reachable.count(&block) && block.contains_syscall) {
                        const auto& rax_values = block_rax_values[&block];
                        for (int64_t rax_val : rax_values) {
                            std::cout << "0x" << std::hex << block.end_address << ": ";
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
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
