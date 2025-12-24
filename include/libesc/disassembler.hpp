#pragma once

#include "syscall_analysis.hpp"
#include <vector>
#include <cstdint>
#include <memory>

namespace libesc {

/**
 * @brief Disassembler that extracts basic blocks with metadata
 */
class Disassembler {
public:
    enum class Architecture {
        X86_64,
        X86_32,
        ARM,
        ARM64
    };

    /**
     * @brief Construct a new Disassembler
     * @param arch Target architecture
     */
    explicit Disassembler(Architecture arch);
    ~Disassembler();

    // Disable copy
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    /**
     * @brief Disassemble code and extract basic blocks with metadata
     * @param code Code buffer
     * @param address Base address for disassembly
     * @return Control flow graph with basic blocks and metadata
     */
    ControlFlowGraph disassemble(const std::vector<uint8_t>& code, 
                                 uint64_t address = 0) const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace libesc
