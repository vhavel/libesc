#pragma once

#include <vector>
#include <cstdint>

// Helper to create test code from raw x86-64 bytes
inline std::vector<uint8_t> make_code(std::initializer_list<uint8_t> bytes) {
    return std::vector<uint8_t>(bytes);
}

// x86-64 instruction encoding helpers
// These expand to comma-separated byte sequences for use in initializer lists

// MOV instructions
#define MOV_EAX_IMM32(val) \
    0xb8, (val) & 0xff, ((val) >> 8) & 0xff, ((val) >> 16) & 0xff, ((val) >> 24) & 0xff

#define MOV_EBX_IMM32(val) \
    0xbb, (val) & 0xff, ((val) >> 8) & 0xff, ((val) >> 16) & 0xff, ((val) >> 24) & 0xff

#define MOV_ECX_IMM32(val) \
    0xb9, (val) & 0xff, ((val) >> 8) & 0xff, ((val) >> 16) & 0xff, ((val) >> 24) & 0xff

#define MOV_EDX_IMM32(val) \
    0xba, (val) & 0xff, ((val) >> 8) & 0xff, ((val) >> 16) & 0xff, ((val) >> 24) & 0xff

#define MOV_EAX_EDX() \
    0x89, 0xd0

#define MOV_EAX_EBX() \
    0x89, 0xd8

// Control flow
#define SYSCALL() \
    0x0f, 0x05

#define RET() \
    0xc3

#define NOP() \
    0x90

#define HLT() \
    0xf4

// Jumps (relative 8-bit offset)
#define JMP_REL8(offset) \
    0xeb, (offset) & 0xff

#define JZ_REL8(offset) \
    0x74, (offset) & 0xff

#define JNZ_REL8(offset) \
    0x75, (offset) & 0xff

// Call (relative 32-bit offset)
#define CALL_REL32(offset) \
    0xe8, (offset) & 0xff, ((offset) >> 8) & 0xff, ((offset) >> 16) & 0xff, ((offset) >> 24) & 0xff

// Arithmetic/Logic
#define TEST_EAX_EAX() \
    0x85, 0xc0

#define TEST_EBX_EBX() \
    0x85, 0xdb

#define XOR_EDI_EDI() \
    0x31, 0xff

#define DEC_EBX() \
    0xff, 0xcb

// Common multi-instruction patterns
#define SETUP_SYSCALL_AND_CALL(syscall_num) \
    MOV_EAX_IMM32(syscall_num), SYSCALL()

#define CONDITIONAL_JMP_PATTERN(test_reg, jump_offset) \
    TEST_##test_reg##_##test_reg(), JZ_REL8(jump_offset)
