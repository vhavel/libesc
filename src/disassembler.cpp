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

        // First pass: decode all instructions and identify block boundaries
        struct DecodedInstruction {
            uint64_t address;
            uint32_t length;
            bool is_branch;
            bool is_call;
            bool is_ret;
            bool is_syscall;
            bool is_mov_to_rax;
            int64_t rax_value;
            uint64_t jump_target;
            bool is_unconditional_jump;
        };
        
        std::vector<DecodedInstruction> instructions;
        std::set<uint64_t> block_starts;
        
        // Entry point is a block start
        block_starts.insert(base_address);
        
        size_t offset = 0;
        while (offset < code.size()) {
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_,
                                                    code.data() + offset,
                                                    code.size() - offset,
                                                    &insn,
                                                    operands))) {
                DecodedInstruction decoded;
                decoded.address = base_address + offset;
                decoded.length = insn.length;
                decoded.is_branch = (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                                   insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
                decoded.is_call = (insn.meta.category == ZYDIS_CATEGORY_CALL);
                decoded.is_ret = (insn.meta.category == ZYDIS_CATEGORY_RET);
                decoded.is_syscall = (insn.mnemonic == ZYDIS_MNEMONIC_SYSCALL ||
                                    insn.mnemonic == ZYDIS_MNEMONIC_SYSENTER ||
                                    (insn.mnemonic == ZYDIS_MNEMONIC_INT && 
                                     insn.operand_count > 0 &&
                                     operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                                     operands[0].imm.value.u == 0x80));
                
                // Check for mov rax/eax, imm
                decoded.is_mov_to_rax = false;
                decoded.rax_value = -1;
                if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && insn.operand_count == 2 &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operands[0].reg.value == ZYDIS_REGISTER_RAX ||
                     operands[0].reg.value == ZYDIS_REGISTER_EAX) &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    decoded.is_mov_to_rax = true;
                    decoded.rax_value = operands[1].imm.value.s;
                }
                
                // Calculate jump target
                decoded.jump_target = 0;
                decoded.is_unconditional_jump = (insn.mnemonic == ZYDIS_MNEMONIC_JMP);
                if (decoded.is_branch && insn.operand_count > 0 &&
                    operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t result;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operands[0], 
                                                              decoded.address, &result))) {
                        decoded.jump_target = result;
                        // Jump target starts a new block
                        block_starts.insert(result);
                    }
                }
                
                // Instruction after branch/call/ret/syscall starts a new block
                if (decoded.is_branch || decoded.is_call || decoded.is_ret || decoded.is_syscall) {
                    if (!decoded.is_unconditional_jump) {
                        block_starts.insert(decoded.address + decoded.length);
                    }
                }
                
                instructions.push_back(decoded);
                offset += insn.length;
            } else {
                // Skip bad byte
                offset++;
            }
        }
        
        // Second pass: build basic blocks
        std::map<uint64_t, size_t> addr_to_idx;
        for (size_t i = 0; i < instructions.size(); i++) {
            addr_to_idx[instructions[i].address] = i;
        }
        
        std::vector<uint64_t> sorted_starts(block_starts.begin(), block_starts.end());
        std::sort(sorted_starts.begin(), sorted_starts.end());
        
        ControlFlowGraph cfg;
        
        for (size_t i = 0; i < sorted_starts.size(); i++) {
            uint64_t block_start = sorted_starts[i];
            
            auto it = addr_to_idx.find(block_start);
            if (it == addr_to_idx.end()) {
                continue;  // Block start not in valid instructions
            }
            
            size_t start_idx = it->second;
            size_t end_idx = start_idx;
            
            BasicBlock block;
            block.start_address = block_start;
            
            // Find end of block
            for (size_t j = start_idx; j < instructions.size(); j++) {
                const auto& insn = instructions[j];
                end_idx = j;
                
                // Track metadata
                if (insn.is_syscall) {
                    block.contains_syscall = true;
                    block.syscall_address = insn.address;
                }
                if (insn.is_mov_to_rax) {
                    block.last_rax_value = insn.rax_value;
                }
                
                // Check for block terminator
                if (insn.is_branch) {
                    block.ends_with_unconditional_jump = insn.is_unconditional_jump;
                    
                    // Add jump target as successor
                    if (insn.jump_target != 0) {
                        block.successors.push_back(insn.jump_target);
                    }
                    
                    // Conditional branches fall through
                    if (!insn.is_unconditional_jump) {
                        block.successors.push_back(insn.address + insn.length);
                    }
                    break;
                } else if (insn.is_call) {
                    block.ends_with_call = true;
                    // Calls fall through
                    block.successors.push_back(insn.address + insn.length);
                    break;
                } else if (insn.is_ret) {
                    block.ends_with_ret = true;
                    break;
                } else if (insn.is_syscall) {
                    // Syscalls continue to next instruction
                    block.successors.push_back(insn.address + insn.length);
                    break;
                }
                
                // Check if next instruction starts a new block
                if (j + 1 < instructions.size() && 
                    block_starts.count(instructions[j + 1].address)) {
                    // Fall through to next block
                    block.successors.push_back(instructions[j + 1].address);
                    break;
                }
            }
            
            block.end_address = instructions[end_idx].address;
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
