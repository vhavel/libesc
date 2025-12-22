#pragma once

#include <string>
#include <vector>
#include <memory>

namespace libesc {

/**
 * @brief Represents basic information about an ELF binary
 */
struct ElfInfo {
    std::string path;
    std::string architecture;
    bool is_64bit;
    uint64_t entry_point;
};

/**
 * @brief Main class for inspecting ELF binaries
 */
class ElfInspector {
public:
    /**
     * @brief Construct a new ELF Inspector object
     * @param binary_path Path to the ELF binary
     */
    explicit ElfInspector(const std::string& binary_path);
    ~ElfInspector();

    // Disable copy
    ElfInspector(const ElfInspector&) = delete;
    ElfInspector& operator=(const ElfInspector&) = delete;

    /**
     * @brief Get basic information about the ELF binary
     * @return ElfInfo structure containing binary information
     */
    ElfInfo get_info() const;

    /**
     * @brief Get the raw binary data for disassembly
     * @return Vector of bytes
     */
    std::vector<uint8_t> get_code_section() const;

    /**
     * @brief Get entry point address
     * @return Entry point address
     */
    uint64_t get_entry_point() const;

    /**
     * @brief Get .text section base address
     * @return Base address of .text section
     */
    uint64_t get_text_base() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace libesc
