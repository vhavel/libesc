cmake_minimum_required(VERSION 3.15)
project(libesc VERSION 0.1.0 LANGUAGES CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_CLI "Build command-line tool" ON)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)

# Fetch Zydis disassembler
include(FetchContent)

# Use native Linux temp directory to avoid WSL/Windows filesystem issues
set(FETCHCONTENT_BASE_DIR "${CMAKE_BINARY_DIR}/_deps" CACHE PATH "FetchContent base directory")

FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

# Configure Zydis options
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(zydis)

# Library sources
set(LIBESC_SOURCES
    src/elf_inspector.cpp
    src/disassembler.cpp
)

# Create library
add_library(libesc ${LIBESC_SOURCES})
target_include_directories(libesc
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${zydis_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link dependencies
target_link_libraries(libesc PRIVATE Zydis)

# Set library properties
set_target_properties(libesc PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    OUTPUT_NAME esc
)

# CLI tool
if(BUILD_CLI)
    add_subdirectory(cli)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Profile test
add_executable(profile_test profile_test.cpp)
target_link_libraries(profile_test PRIVATE libesc Zycore)

# Installation rules
install(TARGETS libesc
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/libesc
    DESTINATION include
)
