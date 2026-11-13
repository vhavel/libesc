#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <cstring>
#include <libesc/elf_file.hpp>

// Capstone
#include <capstone/capstone.h>

// Distorm3
#include <distorm3/distorm.h>

// Zydis
#include <Zydis/Zydis.h>

using namespace std::chrono;

std::vector<uint8_t> read_file(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file");
    }
    
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

// Extract .text section (simplified - reads from offset 0x1000 for now)
std::vector<uint8_t> get_text_section(const std::vector<uint8_t>& binary) {
    // Simple heuristic: assume .text starts at 0x1000 and is ~600KB
    if (binary.size() < 0x1000 + 600000) {
        return std::vector<uint8_t>(binary.begin() + 0x1000, binary.end());
    }
    return std::vector<uint8_t>(binary.begin() + 0x1000, binary.begin() + 0x1000 + 600000);
}

struct BenchResult {
    const char* name;
    size_t instruction_count;
    double time_ms;
    bool detail_mode;
};

// Benchmark Capstone
BenchResult benchmark_capstone(const std::vector<uint8_t>& code, bool detail) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone");
    }
    
    if (detail) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    
    auto start = high_resolution_clock::now();
    
    cs_insn* insn;
    size_t count = cs_disasm(handle, code.data(), code.size(), 0x400000, 0, &insn);
    
    auto end = high_resolution_clock::now();
    double time_ms = duration_cast<microseconds>(end - start).count() / 1000.0;
    
    if (count > 0) {
        cs_free(insn, count);
    }
    
    cs_close(&handle);
    
    return BenchResult{
        detail ? "Capstone (detail)" : "Capstone (fast)",
        count,
        time_ms,
        detail
    };
}

// Benchmark Distorm3
BenchResult benchmark_distorm3(const std::vector<uint8_t>& code) {
    auto start = high_resolution_clock::now();
    
    _DecodedInst instructions[1000];
    unsigned int instruction_count = 0;
    unsigned int total_count = 0;
    
    _DecodeResult res;
    _OffsetType offset = 0;
    
    while (offset < code.size()) {
        res = distorm_decode64(0x400000 + offset,
                              code.data() + offset,
                              code.size() - offset,
                              Decode64Bits,
                              instructions,
                              1000,
                              &instruction_count);
        
        if (res == DECRES_INPUTERR) break;
        
        total_count += instruction_count;
        
        if (res == DECRES_SUCCESS || instruction_count == 0) break;
        
        // Move to next chunk
        offset = instructions[instruction_count - 1].offset - 0x400000 + instructions[instruction_count - 1].size;
    }
    
    auto end = high_resolution_clock::now();
    double time_ms = duration_cast<microseconds>(end - start).count() / 1000.0;
    
    return BenchResult{"Distorm3", total_count, time_ms, false};
}

// Benchmark Zydis
BenchResult benchmark_zydis(const std::vector<uint8_t>& code) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    
    auto start = high_resolution_clock::now();
    
    ZydisDecodedInstruction instruction;
    size_t offset = 0;
    size_t count = 0;
    ZyanU64 runtime_address = 0x400000;
    
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, code.data() + offset,
                                                 code.size() - offset, &instruction))) {
        count++;
        offset += instruction.length;
        runtime_address += instruction.length;
        
        if (offset >= code.size()) break;
    }
    
    auto end = high_resolution_clock::now();
    double time_ms = duration_cast<microseconds>(end - start).count() / 1000.0;
    
    return BenchResult{"Zydis", count, time_ms, false};
}

void print_result(const BenchResult& result) {
    if (result.instruction_count == 0) {
        std::cout << result.name << ": NOT AVAILABLE\n";
        return;
    }
    
    std::cout << result.name << ":\n";
    std::cout << "  Instructions: " << result.instruction_count << "\n";
    std::cout << "  Time: " << result.time_ms << " ms\n";
    std::cout << "  Speed: " << (result.instruction_count / result.time_ms) << " insns/ms\n";
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }
    
    try {
        std::cout << "Reading binary: " << argv[1] << "\n";
        libesc::ElfFile inspector(argv[1]);
        auto code = inspector.get_code_section();
        
        std::cout << "Code section size: " << code.size() << " bytes\n";
        std::cout << "\n=== Disassembler Benchmark ===\n\n";
        
        // Run benchmarks multiple times and average
        const int runs = 5;
        std::vector<BenchResult> results;
        
        // Capstone fast mode
        {
            BenchResult avg{"Capstone (fast)", 0, 0.0, false};
            for (int i = 0; i < runs; i++) {
                auto r = benchmark_capstone(code, false);
                avg.instruction_count = r.instruction_count;
                avg.time_ms += r.time_ms;
            }
            avg.time_ms /= runs;
            results.push_back(avg);
        }
        
        // Capstone detail mode
        {
            BenchResult avg{"Capstone (detail)", 0, 0.0, true};
            for (int i = 0; i < runs; i++) {
                auto r = benchmark_capstone(code, true);
                avg.instruction_count = r.instruction_count;
                avg.time_ms += r.time_ms;
            }
            avg.time_ms /= runs;
            results.push_back(avg);
        }
        
        // Distorm3
        results.push_back(benchmark_distorm3(code));
        
        // Zydis
        results.push_back(benchmark_zydis(code));
        
        // Print results
        for (const auto& r : results) {
            print_result(r);
        }
        
        // Print comparison table
        std::cout << "=== Relative Performance ===\n";
        if (results[1].instruction_count > 0) {
            double baseline = results[1].time_ms; // Capstone detail as baseline
            for (const auto& r : results) {
                if (r.instruction_count > 0) {
                    double speedup = baseline / r.time_ms;
                    std::cout << r.name << ": " << speedup << "x";
                    if (speedup < 1.0) {
                        std::cout << " (" << (1.0/speedup) << "x slower)";
                    } else {
                        std::cout << " faster";
                    }
                    std::cout << "\n";
                }
            }
        }
        std::cout << "\n";
        
        // Print comparison
        if (results.size() >= 2 && results[0].instruction_count > 0 && results[1].instruction_count > 0) {
            double overhead = (results[1].time_ms - results[0].time_ms) / results[0].time_ms * 100.0;
            std::cout << "Capstone detail mode overhead: " << overhead << "%\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
