#pragma once

/**
 * @file libesc.hpp
 * @brief Main header file for libesc - ELF Syscall Inspector library
 */

#include "elf_inspector.hpp"
#include "disassembler.hpp"
#include "syscall_analysis.hpp"

namespace libesc {

constexpr const char* VERSION = "0.1.0";

/**
 * @brief Get the library version
 * @return Version string
 */
inline const char* get_version() {
    return VERSION;
}

} // namespace libesc
