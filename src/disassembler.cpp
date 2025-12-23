#include "libesc/disassembler.hpp"
#include <Zydis/Zydis.h>
#include <stdexcept>
#include <map>
#include <set>
#include <algorithm>

namespace libesc {

class Disassembler::Impl {
public:
    explicit Impl(Architecture arch) : arch_(arch) {
        ZydisMachineMode machine_mode;
        ZydisStackWidth stack_width;
        
        switch (arch) {
            case Architecture::X86_64:
                machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
                stack_width = ZYDIS_STACK_WIDTH_64;
                break;
            case Architecture::X86_32:
                machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
                stack_width = ZYDIS_STACK_WIDTH_32;
                break;
            default:
                throw std::runtime_error("Unsupported architecture (Zydis only supports x86/x86-64)");
        }
        
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder_, machine_mode, stack_width))) {
            throw std::runtime_error("Failed to initialize Zydis decoder");
        }
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
            
            while (offset < code.size()) {
                ZydisDecodedInstruction insn;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_,
                                                         code.data() + offset,
                                                         code.size() - offset,
                                                         &insn,
                                                         operands))) {
                    // Bad instruction - end block here
                    break;
                }
                
                uint64_t insn_addr = base_address + offset;
                block.end_address = insn_addr;
                
                bool is_branch = (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                                  insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
                bool is_call = (insn.meta.category == ZYDIS_CATEGORY_CALL);
                bool is_ret = (insn.meta.category == ZYDIS_CATEGORY_RET ||
                               insn.mnemonic == ZYDIS_MNEMONIC_HLT ||
                               insn.mnemonic == ZYDIS_MNEMONIC_UD2);
                bool is_syscall = (insn.mnemonic == ZYDIS_MNEMONIC_SYSCALL ||
                                   insn.mnemonic == ZYDIS_MNEMONIC_SYSENTER ||
                                   (insn.mnemonic == ZYDIS_MNEMONIC_INT && 
                                    insn.operand_count > 0 &&
                                    operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                                    operands[0].imm.value.u == 0x80));
                
                // Track mov rax/eax, imm
                if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && insn.operand_count == 2 &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operands[0].reg.value == ZYDIS_REGISTER_RAX ||
                     operands[0].reg.value == ZYDIS_REGISTER_EAX) &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    current_rax = static_cast<uint64_t>(operands[1].imm.value.u);
                }
                // Any other write to RAX/EAX makes it unknown
                else if (insn.operand_count > 0 &&
                         operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                         (operands[0].reg.value == ZYDIS_REGISTER_RAX ||
                          operands[0].reg.value == ZYDIS_REGISTER_EAX)) {
                    // Check if this instruction writes to RAX (not just reads)
                    bool writes_rax = false;
                    for (size_t i = 0; i < insn.operand_count; i++) {
                        if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            (operands[i].reg.value == ZYDIS_REGISTER_RAX ||
                             operands[i].reg.value == ZYDIS_REGISTER_EAX) &&
                            (operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE)) {
                            writes_rax = true;
                            break;
                        }
                    }
                    if (writes_rax) {
                        current_rax = std::nullopt;  // Unknown value
                    }
                }
                
                // Track syscall
                if (is_syscall) {
                    block.contains_syscall = true;
                    block.syscall_address = insn_addr;
                    if (current_rax.has_value()) {
                        block.syscall_rax_value = *current_rax;
                    }
                    // If current_rax is nullopt, syscall_rax_value stays nullopt (needs propagation)
                }
                
                offset += insn.length;
                uint64_t next_addr = insn_addr + insn.length;
                
                // Handle block terminators
                if (is_branch) {
                    bool is_unconditional = (insn.mnemonic == ZYDIS_MNEMONIC_JMP);
                    block.ends_with_unconditional_jump = is_unconditional;
                    
                    // Add jump target
                    if (insn.operand_count > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        uint64_t target;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operands[0], insn_addr, &target))) {
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
                    if (insn.operand_count > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        uint64_t target;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operands[0], insn_addr, &target))) {
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
            block.last_rax_value = current_rax;
            cfg.blocks.push_back(std::move(block));
        }
        
        return cfg;
    }

private:
    Architecture arch_;
    ZydisDecoder decoder_;
};

Disassembler::Disassembler(Architecture arch)
    : pimpl_(std::make_unique<Impl>(arch)) {}

Disassembler::~Disassembler() = default;

ControlFlowGraph Disassembler::disassemble(const std::vector<uint8_t>& code, 
                                           uint64_t address) const {
    return pimpl_->disassemble(code, address);
}

} // namespace libesc
