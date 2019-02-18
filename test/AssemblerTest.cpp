#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "TinyMachine.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace tinymachine;
using namespace ::testing;

std::string hexify(uint8_t *pData, size_t pCount)
{
    std::stringstream ss;
    for (size_t i=0; i<pCount; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << unsigned(pData[i]);
    return ss.str();
}

struct AssemblerTest : Test
{
};


TEST_F(AssemblerTest, should_getOperandType_register)
{
    EXPECT_EQ(Assembler::OperandType::R64, Assembler::getOperandType("a"));
    EXPECT_EQ(Assembler::OperandType::R64, Assembler::getOperandType("b"));
    EXPECT_EQ(Assembler::OperandType::R64, Assembler::getOperandType("z"));
}

TEST_F(AssemblerTest, should_getOperandType_ptr_reg)
{
    EXPECT_EQ(Assembler::OperandType::BPR64, Assembler::getOperandType("byte ptr[a]"));
    EXPECT_EQ(Assembler::OperandType::BPR64, Assembler::getOperandType("byte ptr[z]"));
    EXPECT_EQ(Assembler::OperandType::WPR64, Assembler::getOperandType("word ptr[a]"));
    EXPECT_EQ(Assembler::OperandType::WPR64, Assembler::getOperandType("word ptr[a]"));
    EXPECT_EQ(Assembler::OperandType::DPR64, Assembler::getOperandType("dword ptr[z]"));
    EXPECT_EQ(Assembler::OperandType::DPR64, Assembler::getOperandType("dword ptr[z]"));
    EXPECT_EQ(Assembler::OperandType::QPR64, Assembler::getOperandType("qword ptr[z]"));
    EXPECT_EQ(Assembler::OperandType::QPR64, Assembler::getOperandType("qword ptr[z]"));
}

TEST_F(AssemblerTest, should_getOperandType_ptr_imm_named)
{
    EXPECT_EQ(Assembler::OperandType::BPIN64, Assembler::getOperandType("byte ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::BPIN64, Assembler::getOperandType("byte ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::WPIN64, Assembler::getOperandType("word ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::WPIN64, Assembler::getOperandType("word ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::DPIN64, Assembler::getOperandType("dword ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::DPIN64, Assembler::getOperandType("dword ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::QPIN64, Assembler::getOperandType("qword ptr[labelname]"));
    EXPECT_EQ(Assembler::OperandType::QPIN64, Assembler::getOperandType("qword ptr[labelname]"));
}

TEST_F(AssemblerTest, should_getOperandType_ptr_imm)
{
    EXPECT_EQ(Assembler::OperandType::BPI64, Assembler::getOperandType("byte ptr[1]"));
    EXPECT_EQ(Assembler::OperandType::BPI64, Assembler::getOperandType("byte ptr[-1]"));
    EXPECT_EQ(Assembler::OperandType::WPI64, Assembler::getOperandType("word ptr[1]"));
    EXPECT_EQ(Assembler::OperandType::WPI64, Assembler::getOperandType("word ptr[-1]"));
    EXPECT_EQ(Assembler::OperandType::DPI64, Assembler::getOperandType("dword ptr[1]"));
    EXPECT_EQ(Assembler::OperandType::DPI64, Assembler::getOperandType("dword ptr[-1]"));
    EXPECT_EQ(Assembler::OperandType::QPI64, Assembler::getOperandType("qword ptr[1]"));
    EXPECT_EQ(Assembler::OperandType::QPI64, Assembler::getOperandType("qword ptr[-1]"));
}

TEST_F(AssemblerTest, should_getOperandType_imm)
{
    EXPECT_EQ(Assembler::OperandType::I8, Assembler::getOperandType("255"));
    EXPECT_EQ(Assembler::OperandType::I16, Assembler::getOperandType("65535"));
    EXPECT_EQ(Assembler::OperandType::I32, Assembler::getOperandType("4294967295"));
    EXPECT_EQ(Assembler::OperandType::I64, Assembler::getOperandType("-1"));
}

TEST_F(AssemblerTest, should_generateInstruction_mov)
{
    std::string src = R"(
            main:
                mov a, b
                mov a, 255
                mov a, 65535
                mov a, 4294967295
                mov a, -1
                mov byte ptr[c], b
                mov word ptr[c], b
                mov dword ptr[c], b
                mov qword ptr[c], b
                mov byte ptr[after_main], b
                mov word ptr[after_main], b
                mov dword ptr[after_main], b
                mov qword ptr[after_main], b
                mov byte ptr[main], b
                mov byte ptr[-1], b
                mov byte ptr[-2], b
            after_main:
        )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "010001"                //  mov a, b
        "0200ff"                //  mov a, 255
        "0300ffff"              //  mov a, 65535
        "0400ffffffff"          //  mov a, 4294967295
        "0500ffffffffffffffff"  //  mov a, -1
        "160201"                //  mov byte ptr[c], b
        "170201"                //  mov word ptr[c], b
        "180201"                //  mov dword ptr[c], b
        "190201"                //  mov qword ptr[c], b
        "1a6c0000000000000001"  //  mov byte ptr[after_main], b
        "1b6c0000000000000001"  //  mov word ptr[after_main], b
        "1c6c0000000000000001"  //  mov dword ptr[after_main], b
        "1d6c0000000000000001"  //  mov qword ptr[after_main], b
        "1a000000000000000001"  //  mov byte ptr[main], b
        "1affffffffffffffff01"  //  mov byte ptr[-1], b
        "1afeffffffffffffff01"  //  mov byte ptr[-2], b
    );
}

TEST_F(AssemblerTest, should_generateInstruction_movzx)
{
    std::string src = R"(
            main:
                movzx b, byte ptr [c]
                movzx b, word ptr [c]
                movzx b, dword ptr[c]
                movzx b, qword ptr[c]
                movzx b, byte ptr [1]
                movzx b, word ptr [2]
                movzx b, dword ptr[3]
                movzx b, qword ptr[4]
                movzx b, byte ptr [after_main]
                movzx b, word ptr [after_main]
                movzx b, dword ptr[after_main]
                movzx b, qword ptr[after_main]
            after_main:
        )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "060102"                //  movzx b, byte ptr [c]
        "070102"                //  movzx b, word ptr [c]
        "080102"                //  movzx b, dword ptr[c]
        "090102"                //  movzx b, qword ptr[c]
        "0e010100000000000000"  //  movzx b, byte ptr [1]
        "0f010200000000000000"  //  movzx b, word ptr [2]
        "10010300000000000000"  //  movzx b, dword ptr[3]
        "11010400000000000000"  //  movzx b, qword ptr[4]
        "0e015c00000000000000"  //  movzx b, byte ptr [after_main]
        "0f015c00000000000000"  //  movzx b, word ptr [after_main]
        "10015c00000000000000"  //  movzx b, dword ptr[after_main]
        "11015c00000000000000"  //  movzx b, qword ptr[after_main]
    );
}

TEST_F(AssemblerTest, should_generateInstruction_movsx)
{
    std::string src = R"(
            main:
                movsx b, byte ptr [c]
                movsx b, word ptr [c]
                movsx b, dword ptr[c]
                movsx b, qword ptr[c]
                movsx b, byte ptr [1]
                movsx b, word ptr [2]
                movsx b, dword ptr[3]
                movsx b, qword ptr[4]
                movsx b, byte ptr [after_main]
                movsx b, word ptr [after_main]
                movsx b, dword ptr[after_main]
                movsx b, qword ptr[after_main]
            after_main:
        )";
    Assembler m(src);
    EXPECT_EQ(hexify(m.getByteCode().data(), m.getByteCode().size()),
        "0a0102"                //  movsx b, byte ptr [c]
        "0b0102"                //  movsx b, word ptr [c]
        "0c0102"                //  movsx b, dword ptr[c]
        "0d0102"                //  movsx b, qword ptr[c]
        "12010100000000000000"  //  movsx b, byte ptr [1]
        "13010200000000000000"  //  movsx b, word ptr [2]
        "14010300000000000000"  //  movsx b, dword ptr[3]
        "15010400000000000000"  //  movsx b, qword ptr[4]
        "12015c00000000000000"  //  movsx b, byte ptr [after_main]
        "13015c00000000000000"  //  movsx b, word ptr [after_main]
        "14015c00000000000000"  //  movsx b, dword ptr[after_main]
        "15015c00000000000000"  //  movsx b, qword ptr[after_main]
    );
}
