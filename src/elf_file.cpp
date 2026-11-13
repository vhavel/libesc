#include "libesc/elf_file.hpp"
#include <fstream>
#include <stdexcept>

namespace libesc {

class ElfFile::Impl {
public:
    explicit Impl(const std::string& binary_path) : path_(binary_path) {
        // TODO: Use LIEF library to parse ELF binary
        // For now, basic implementation
        load_binary();
    }

    void load_binary() {
        std::ifstream file(path_, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Failed to open binary: " + path_);
        }

        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        data_.resize(size);
        if (!file.read(reinterpret_cast<char*>(data_.data()), size)) {
            throw std::runtime_error("Failed to read binary");
        }

        // Basic ELF header validation
        if (size < 64 || data_[0] != 0x7f || data_[1] != 'E' || 
            data_[2] != 'L' || data_[3] != 'F') {
            throw std::runtime_error("Not a valid ELF file");
        }

        is_64bit_ = (data_[4] == 2);
        
        // Read entry point (offset 0x18 for 64-bit, 0x18 for 32-bit)
        if (is_64bit_) {
            entry_point_ = *reinterpret_cast<const uint64_t*>(&data_[0x18]);
        } else {
            entry_point_ = *reinterpret_cast<const uint32_t*>(&data_[0x18]);
        }
    }

    std::vector<uint8_t> get_code_section() const {
        // Parse ELF section headers to find .text section
        if (is_64bit_) {
            return get_text_section_64();
        } else {
            return get_text_section_32();
        }
    }

    std::vector<uint8_t> get_text_section_64() const {
        // Read section header offset and count
        uint64_t shoff = *reinterpret_cast<const uint64_t*>(&data_[0x28]);
        uint16_t shentsize = *reinterpret_cast<const uint16_t*>(&data_[0x3A]);
        uint16_t shnum = *reinterpret_cast<const uint16_t*>(&data_[0x3C]);
        uint16_t shstrndx = *reinterpret_cast<const uint16_t*>(&data_[0x3E]);
        
        if (shoff == 0 || shnum == 0) {
            return {};
        }
        
        // Get string table section
        size_t strtab_offset = shoff + shstrndx * shentsize;
        uint64_t strtab_addr = *reinterpret_cast<const uint64_t*>(&data_[strtab_offset + 24]);
        
        // Search for .text section
        for (uint16_t i = 0; i < shnum; i++) {
            size_t sh_offset = shoff + i * shentsize;
            uint32_t sh_name = *reinterpret_cast<const uint32_t*>(&data_[sh_offset]);
            uint64_t sh_addr = *reinterpret_cast<const uint64_t*>(&data_[sh_offset + 16]);  // Virtual address
            uint64_t sh_offset_data = *reinterpret_cast<const uint64_t*>(&data_[sh_offset + 24]);
            uint64_t sh_size = *reinterpret_cast<const uint64_t*>(&data_[sh_offset + 32]);
            
            // Check if section name is ".text"
            const char* name = reinterpret_cast<const char*>(&data_[strtab_addr + sh_name]);
            if (std::string(name) == ".text" && sh_size > 0 && sh_offset_data < data_.size()) {
                const_cast<Impl*>(this)->text_base_ = sh_addr;  // Store virtual address
                std::vector<uint8_t> text_section(data_.begin() + sh_offset_data,
                                                  data_.begin() + sh_offset_data + sh_size);
                return text_section;
            }
        }
        
        return {};
    }

    std::vector<uint8_t> get_text_section_32() const {
        // Similar logic for 32-bit ELF
        // TODO: Implement if needed
        return {};
    }

    uint64_t get_entry_point() const {
        return entry_point_;
    }

    uint64_t get_text_base() const {
        return text_base_;
    }

private:
    std::string path_;
    std::vector<uint8_t> data_;
    bool is_64bit_ = true;
    uint64_t entry_point_ = 0;
    mutable uint64_t text_base_ = 0;  // Mutable because it's set during get_code_section
};

ElfFile::ElfFile(const std::string& binary_path)
    : pimpl_(std::make_unique<Impl>(binary_path)) {}

ElfFile::~ElfFile() = default;

std::vector<uint8_t> ElfFile::get_code_section() const {
    return pimpl_->get_code_section();
}

uint64_t ElfFile::get_entry_point() const {
    return pimpl_->get_entry_point();
}

uint64_t ElfFile::get_text_base() const {
    return pimpl_->get_text_base();
}

} // namespace libesc
