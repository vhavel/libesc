#include <libesc/libesc.hpp>
#include <iostream>
#include <chrono>

using namespace std::chrono;

#define TIME_BLOCK(name) \
    auto start_##name = high_resolution_clock::now(); \
    for(bool once = true; once; \
        once = false, \
        std::cout << #name << ": " << duration_cast<milliseconds>(high_resolution_clock::now() - start_##name).count() << "ms\n")

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    try {
        TIME_BLOCK(total) {
            libesc::ElfFile inspector(argv[1]);
            
            TIME_BLOCK(get_code_section) {
                auto code = inspector.get_code_section();
                std::cout << "Code size: " << code.size() << " bytes\n";
            }
            
            TIME_BLOCK(disassemble_and_build_cfg) {
                auto arch = libesc::Disassembler::Architecture::X86_64;
                libesc::Disassembler disasm(arch);
                auto code = inspector.get_code_section();
                auto cfg = disasm.disassemble(code, inspector.get_text_base());
                std::cout << "Basic blocks: " << cfg.blocks.size() << "\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
