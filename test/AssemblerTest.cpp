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
    ss << "hexify: ";
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

                mov byte ptr[a], b
                mov word ptr[a], b
                mov dword ptr[a], b
                mov qword ptr[a], b

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
    std::cout << hexify(m.getByteCode().data(), m.getByteCode().size()) << "\n";
}
