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


class ElfFile {
public:
    /**
     * @brief Open ELF file given by path
     * @param binary_path Path to the ELF binary
     */
    explicit ElfFile(const std::string& binary_path);
    ~ElfFile();

    ElfFile(const ElfFile&) = delete;
    ElfFile& operator=(const ElfFile&) = delete;

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
