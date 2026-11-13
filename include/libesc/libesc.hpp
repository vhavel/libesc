#pragma once

/**
 * @file libesc.hpp
 * @brief Main header file for libesc - ELF Syscall Inspector library
 */

#include "elf_file.hpp"
#include "disassembler.hpp"
#include "syscall_analysis.hpp"

namespace libesc {

/**
 * @brief Analyze syscalls in an ELF binary
 * 
 * Function that loads an ELF binary, disassembles
 * the code section, performs dataflow analysis, and returns all detected
 * syscalls with their numbers and names.
 * 
 * @param binary_path Path to the ELF binary file
 * @param arch Architecture of the binary (default: X86_64)
 * @return Vector of detected syscalls
 * @throws std::runtime_error if binary cannot be loaded or analyzed
 * 
 * @example
 * auto syscalls = libesc::analyze_elf_syscalls("./mybinary");
 * for (const auto& sc : syscalls) {
 *     if (sc.number.has_value()) {
 *         std::cout << sc.name << "\n";
 *     }
 * }
 */
inline std::vector<SyscallInfo> analyze_elf_syscalls(
    const char* binary_path,
    Disassembler::Architecture arch = Disassembler::Architecture::X86_64)
{
    ElfFile inspector(binary_path);
    Disassembler disasm(arch);
    auto cfg = disasm.disassemble(inspector.get_code_section(), inspector.get_text_base());
    return cfg.analyze_syscalls();
}

} // namespace libesc
