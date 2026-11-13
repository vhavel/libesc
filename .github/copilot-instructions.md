<!-- Workspace instructions for libesc project -->

# Project Overview
This is a C++ library (with CLI tool) for analyzing Linux ELF binaries. It can:
- Inspect ELF binary structure
- Disassemble code using Capstone engine
- Perform Control Flow Graph (CFG) analysis
- Detect and analyze syscall invocations

# Build System
- CMake-based build system
- C++17 standard
- Dependencies: Capstone engine, LIEF (ELF parsing)

# Project Structure
- `include/libesc/` - Public library headers
- `src/` - Library implementation
- `cli/` - Command-line tool
- `tests/` - Unit tests
- `examples/` - Usage examples

# Development Guidelines
- Follow modern C++ practices (RAII, smart pointers)
- Use namespaces to organize code
- Document public APIs with Doxygen-style comments
- Keep platform-specific code isolated
