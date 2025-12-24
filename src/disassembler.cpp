#include "libesc/disassembler.hpp"
#include <capstone/capstone.h>
#include <stdexcept>
#include <map>
#include <set>
#include <algorithm>

namespace libesc {

class Disassembler::Impl {
public:
    explicit Impl(Architecture arch) : arch_(arch) {
        cs_arch cs_arch_val;
        cs_mode cs_mode_val;
        
        switch (arch) {
            case Architecture::X86_64:
                cs_arch_val = CS_ARCH_X86;
                cs_mode_val = CS_MODE_64;
                break;
            case Architecture::X86_32:
                cs_arch_val = CS_ARCH_X86;
                cs_mode_val = CS_MODE_32;
                break;
            case Architecture::ARM:
                cs_arch_val = CS_ARCH_ARM;
                cs_mode_val = CS_MODE_ARM;
                break;
            case Architecture::ARM64:
                cs_arch_val = CS_ARCH_ARM64;
                cs_mode_val = CS_MODE_ARM;
                break;
            default:
                throw std::runtime_error("Unsupported architecture");
        }
        
        if (cs_open(cs_arch_val, cs_mode_val, &handle_) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone");
        }
        
        // Enable detail mode for operand information
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    }
    
    ~Impl() {
        cs_close(&handle_);
    }

    ControlFlowGraph disassemble(const std::vector<uint8_t>& code, 
                                 uint64_t base_address) const {
        if (code.empty()) {
            return ControlFlowGraph{};
        }

        ControlFlowGraph cfg;
        std::set<uint64_t> processed;  // Blocks we've already built
        std::set<uint64_t> worklist;   // Block starts to process
        
        // Start from entry point
        worklist.insert(base_address);
        
        while (!worklist.empty()) {
            uint64_t block_start = *worklist.begin();
            worklist.erase(worklist.begin());
            
            // Skip if already processed or out of bounds
            if (processed.count(block_start) || block_start < base_address) {
                continue;
            }
            size_t offset = block_start - base_address;
            if (offset >= code.size()) {
                continue;
            }
            
            processed.insert(block_start);
            
            // Build this block by decoding instructions until terminator
            BasicBlock block;
            block.start_address = block_start;
            std::optional<uint64_t> current_rax;  // Track current RAX value through the block
            
            size_t remaining = code.size() - offset;
            const uint8_t* code_ptr = code.data() + offset;
            uint64_t current_address = block_start;
            
            auto insn_deleter = [](cs_insn* p) { if (p) cs_free(p, 1); };
            
            while (remaining > 0) {
                std::unique_ptr<cs_insn, decltype(insn_deleter)> insn(cs_malloc(handle_), insn_deleter);
                if (!cs_disasm_iter(handle_, &code_ptr, &remaining, &current_address, insn.get())) {
                    break;
                }
                block.end_address = insn->address;
                
                // Determine instruction type
                bool is_branch = (insn->id >= X86_INS_JAE && insn->id <= X86_INS_JS) || 
                                 insn->id == X86_INS_JMP ||
                                 insn->id == X86_INS_LOOP || insn->id == X86_INS_LOOPE || insn->id == X86_INS_LOOPNE;
                bool is_call = (insn->id == X86_INS_CALL);
                bool is_ret = (insn->id == X86_INS_RET || insn->id == X86_INS_RETF ||
                               insn->id == X86_INS_HLT || insn->id == X86_INS_UD2);
                bool is_syscall = (insn->id == X86_INS_SYSCALL || insn->id == X86_INS_SYSENTER ||
                                   (insn->id == X86_INS_INT && insn->detail &&
                                    insn->detail->x86.op_count > 0 &&
                                    insn->detail->x86.operands[0].type == X86_OP_IMM &&
                                    insn->detail->x86.operands[0].imm == 0x80));
                
                // Track mov rax/eax, imm
                if (insn->id == X86_INS_MOV && insn->detail && insn->detail->x86.op_count == 2) {
                    auto& op0 = insn->detail->x86.operands[0];
                    auto& op1 = insn->detail->x86.operands[1];
                    if (op0.type == X86_OP_REG && 
                        (op0.reg == X86_REG_RAX || op0.reg == X86_REG_EAX) &&
                        op1.type == X86_OP_IMM) {
                        current_rax = static_cast<uint64_t>(op1.imm);
                    }
                }
                // Any other write to RAX/EAX makes it unknown
                else if (insn->detail && insn->detail->x86.op_count > 0) {
                    auto& op0 = insn->detail->x86.operands[0];
                    if (op0.type == X86_OP_REG &&
                        (op0.reg == X86_REG_RAX || op0.reg == X86_REG_EAX) &&
                        (op0.access & CS_AC_WRITE)) {
                        current_rax = std::nullopt;  // Unknown value
                    }
                }
                
                // Track syscall
                if (is_syscall) {
                    block.syscall_address = insn->address;
                    if (current_rax.has_value()) {
                        block.syscall_rax_value = *current_rax;
                    } else {
                        block.syscall_rax_value = Tainted{};
                    }
                }
                
                uint64_t next_addr = insn->address + insn->size;
                
                // Handle block terminators
                if (is_branch) {
                    bool is_unconditional = (insn->id == X86_INS_JMP);
                    
                    // Add jump target
                    if (insn->detail && insn->detail->x86.op_count > 0) {
                        auto& op = insn->detail->x86.operands[0];
                        if (op.type == X86_OP_IMM) {
                            uint64_t target = op.imm;
                            block.successors.push_back(target);
                            worklist.insert(target);
                        }
                    }
                    
                    // Conditional branches fall through
                    if (!is_unconditional) {
                        block.successors.push_back(next_addr);
                        worklist.insert(next_addr);
                    }
                    
                    break;
                } else if (is_call) {
                    block.ends_with_call = true;
                    
                    // Add call target
                    if (insn->detail && insn->detail->x86.op_count > 0) {
                        auto& op = insn->detail->x86.operands[0];
                        if (op.type == X86_OP_IMM) {
                            uint64_t target = op.imm;
                            block.successors.push_back(target);
                            worklist.insert(target);
                        }
                    }
                    
                    // Calls fall through
                    block.successors.push_back(next_addr);
                    worklist.insert(next_addr);
                    
                    break;
                } else if (is_ret) {
                    block.ends_with_ret = true;
                    break;
                } else if (is_syscall) {
                    // Syscalls continue
                    block.successors.push_back(next_addr);
                    worklist.insert(next_addr);
                    break;
                }
                
                // Check if we've hit a block start (from another path)
                if (processed.count(next_addr) || worklist.count(next_addr)) {
                    block.successors.push_back(next_addr);
                    break;
                }
            }
            
            // Set exit RAX value
            if (current_rax.has_value()) {
                block.last_rax_value = *current_rax;
            } else {
                block.last_rax_value = Tainted{};
            }
            cfg.blocks.push_back(std::move(block));
        }
        
        return cfg;
    }

private:
    Architecture arch_;
    csh handle_;
};

Disassembler::Disassembler(Architecture arch)
    : pimpl_(std::make_unique<Impl>(arch)) {}

Disassembler::~Disassembler() = default;

ControlFlowGraph Disassembler::disassemble(const std::vector<uint8_t>& code, 
                                           uint64_t address) const {
    return pimpl_->disassemble(code, address);
}

} // namespace libesc
