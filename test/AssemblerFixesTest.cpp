#include <cstdint>
#include <sstream>
#include <iomanip>
#include "TinyMachine.hpp"
#include <gtest/gtest.h>

using namespace tinymachine;

static std::string hexify(uint8_t* pData, size_t pCount)
{
    std::stringstream ss;
    for (size_t i = 0; i < pCount; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << unsigned(pData[i]);
    return ss.str();
}

TEST(AssemblerFixesTest, shift_immediates_emit_imm8_opcodes)
{
    std::string src = R"(
        main:
            sar a, 4
            shr b, 2
            shl c, 1
    )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "290004"   // sar a, 4  (0x29 = I_SAR_R64_I8_T)
        "2a0102"   // shr b, 2
        "2b0201"   // shl c, 1
    );
}

TEST(AssemblerFixesTest, shift_reg_reg_emits_rr_opcodes)
{
    std::string src = R"(
        main:
            sar a, b
            shr c, d
            shl e, f
    )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "260001"   // sar a, b
        "270203"   // shr c, d
        "280405"   // shl e, f
    );
}

TEST(AssemblerFixesTest, reg_destination_jumps_call_push_use_register_index)
{
    std::string src = R"(
        main:
            je a
            jg b
            call c
            jmp d
            push e
            pop f
    )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "3700"     // je a  -> reg 0
        "3801"     // jg b
        "4102"     // call c
        "4203"     // jmp d
        "4f04"     // push e
        "5005"     // pop f
    );
}

TEST(AssemblerFixesTest, cmp_and_logical_accept_wide_immediates)
{
    std::string src = R"(
        main:
            cmp a, 256
            and b, 65535
            or c, 4294967295
            xor d, 4096
    )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "36000001000000000000"              // cmp a, 256
        "3201ffff000000000000"              // and b, 65535
        "3302ffffffff00000000"              // or c, 4294967295
        "34030010000000000000"              // xor d, 4096
    );
}
