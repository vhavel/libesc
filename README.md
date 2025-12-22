# libesc - ELF Syscall Inspector

A C++ library and command-line tool for analyzing Linux ELF binaries, disassembling code, and detecting syscall invocations through control flow graph analysis.

## Features

- **ELF Binary Inspection**: Parse and extract information from Linux ELF binaries
- **Disassembly**: Disassemble binary code using the Capstone engine
- **CFG Analysis**: Build and analyze control flow graphs
- **Syscall Detection**: Identify and track syscall invocations in binary code

## Project Structure

```
libesc/
├── include/libesc/     # Public API headers
│   ├── libesc.hpp      # Main header
│   ├── elf_inspector.hpp
│   ├── disassembler.hpp
│   ├── cfg_analyzer.hpp
│   └── syscall_detector.hpp
├── src/                # Library implementation
│   ├── elf_inspector.cpp
│   ├── disassembler.cpp
│   ├── cfg_analyzer.cpp
│   └── syscall_detector.cpp
├── cli/                # Command-line tool
│   └── main.cpp
├── tests/              # Unit tests
│   └── test_basic.cpp
├── examples/           # Usage examples
│   └── basic_usage.cpp
└── CMakeLists.txt      # Build configuration
```

## Dependencies

- **CMake** 3.15 or higher
- **C++17** compatible compiler
- **Capstone Engine** - Disassembly framework (https://github.com/capstone-engine/capstone)
- **LIEF** - ELF parsing library (https://lief-project.github.io/) [Optional, basic implementation included]

## Building

### Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install cmake build-essential libcapstone-dev

# Build the project
mkdir build && cd build
cmake ..
make

# Run tests
ctest
```

### Windows (Cross-compilation or WSL)

This library is designed for analyzing Linux ELF binaries. For Windows development:

1. Use WSL (Windows Subsystem for Linux)
2. Or use a cross-compilation toolchain
3. Or build natively on Linux

## Usage

### Command-line Tool

```bash
# Display ELF information
./esc -i /bin/ls

# Disassemble binary
./esc -d /bin/ls

# Detect syscalls
./esc -s /bin/ls

# Perform CFG analysis
./esc -c /bin/ls

# Combine options
./esc -i -s -c /bin/ls
```

### Library API

```cpp
#include <libesc/libesc.hpp>

// Create ELF inspector
libesc::ElfInspector inspector("/path/to/binary");

// Get binary information
auto info = inspector.get_info();
std::cout << "Architecture: " << info.architecture << "\n";

// Disassemble code
libesc::Disassembler disasm(libesc::Disassembler::Architecture::X86_64);
auto code = inspector.get_code_section();
auto instructions = disasm.disassemble(code, info.entry_point);

// Detect syscalls
libesc::SyscallDetector detector;
auto syscalls = detector.find_syscalls(instructions);

// Build control flow graph
libesc::CfgAnalyzer analyzer;
auto cfg = analyzer.build_cfg(instructions);
```

## Current Status

**Version 0.1.0** - Initial implementation with placeholder code

### Implemented
- ✅ Project structure and build system
- ✅ Basic ELF header parsing
- ✅ API design and interfaces
- ✅ Command-line tool skeleton
- ✅ Basic syscall name lookup

### TODO
- ⬜ Integrate Capstone engine for real disassembly
- ⬜ Integrate LIEF for comprehensive ELF parsing
- ⬜ Implement proper CFG construction algorithm
- ⬜ Add register tracking for syscall number detection
- ⬜ Implement reachability analysis
- ⬜ Add support for multiple architectures (ARM, ARM64)
- ⬜ Comprehensive unit tests
- ⬜ Documentation improvements

## Contributing

Contributions are welcome! Please ensure:
- Code follows modern C++ practices (RAII, smart pointers)
- Public APIs are documented with Doxygen-style comments
- Tests are included for new features
- CMake configuration is updated as needed

## License

[Specify your license here]

## References

- [Capstone Engine](https://github.com/capstone-engine/capstone) - Disassembly framework
- [LIEF](https://lief-project.github.io/) - Library for Instrumentation of Executable Formats
- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Linux Syscall Reference](https://syscalls.w3challs.com/)
