#include <cstdint>
#include "TinyMachine.hpp"
#include <gtest/gtest.h>

using namespace tinymachine;

TEST(VirtualMachineFixesTest, sar_imm8_is_arithmetic_shift)
{
    std::string src = R"(
        main:
            mov b, 176
            sar b, 4
            xor a, a
            syscall
    )";
    Assembler m(src);
    VirtualMachine vm(m.getByteCode(), 2048);
    uint64_t out = 0;
    bool finished = false;
    vm.registersSyscallHandler(0, [&](uint64_t* regs, std::vector<uint8_t>&) {
        out = regs['b' - 'a'];
        finished = true;
    });
    for (int i = 0; i < 500 && !finished; ++i)
        vm.step();
    EXPECT_EQ(static_cast<int64_t>(out), -5);
}

TEST(VirtualMachineFixesTest, sar_reg_reg_uses_shift_amount_register)
{
    std::string src = R"(
        main:
            mov b, 176
            mov d, 4
            sar b, d
            xor a, a
            syscall
    )";
    Assembler m(src);
    VirtualMachine vm(m.getByteCode(), 2048);
    uint64_t out = 0;
    bool finished = false;
    vm.registersSyscallHandler(0, [&](uint64_t* regs, std::vector<uint8_t>&) {
        out = regs['b' - 'a'];
        finished = true;
    });
    for (int i = 0; i < 500 && !finished; ++i)
        vm.step();
    EXPECT_EQ(static_cast<int64_t>(out), -5);
}

TEST(VirtualMachineFixesTest, jmp_through_register_runs_target)
{
    std::string src = R"(
        main:
            mov b, target
            jmp b
            xor a, a
            mov b, 0
            syscall
        target:
            mov b, 42
            xor a, a
            syscall
    )";
    Assembler m(src);
    VirtualMachine vm(m.getByteCode(), 4096);
    uint64_t out = 0;
    vm.registersSyscallHandler(0, [&](uint64_t* regs, std::vector<uint8_t>&) {
        out = regs['b' - 'a'];
    });
    int steps = 0;
    for (; steps < 2000 && out != 42; ++steps)
        vm.step();
    ASSERT_LT(steps, 2000);
    EXPECT_EQ(out, 42u);
}

TEST(VirtualMachineFixesTest, cmp_equal_clears_sign_flag_bit)
{
    constexpr uint64_t FLAG_SIGN = 8;
    std::string src = R"(
        main:
            mov c, 0
            mov d, 1
            cmp c, d
            mov x, 5
            mov y, 5
            cmp x, y
            xor a, a
            syscall
    )";
    Assembler m(src);
    VirtualMachine vm(m.getByteCode(), 4096);
    uint64_t flags = 0;
    bool finished = false;
    vm.registersSyscallHandler(0, [&](uint64_t* regs, std::vector<uint8_t>&) {
        flags = regs['f' - 'a'];
        finished = true;
    });
    for (int i = 0; i < 2000 && !finished; ++i)
        vm.step();
    EXPECT_TRUE(finished);
    EXPECT_EQ(flags & FLAG_SIGN, 0u);
}

TEST(VirtualMachineFixesTest, cmp_with_wide_immediate_behaves)
{
    std::string src = R"(
        main:
            mov a, 300
            cmp a, 256
            jl fail
            mov b, 1
            jmp done
        fail:
            mov b, 0
        done:
            xor a, a
            syscall
    )";
    Assembler m(src);
    VirtualMachine vm(m.getByteCode(), 4096);
    uint64_t ok = 999;
    bool finished = false;
    vm.registersSyscallHandler(0, [&](uint64_t* regs, std::vector<uint8_t>&) {
        ok = regs['b' - 'a'];
        finished = true;
    });
    for (int i = 0; i < 3000 && !finished; ++i)
        vm.step();
    EXPECT_TRUE(finished);
    EXPECT_EQ(ok, 1u);
}
