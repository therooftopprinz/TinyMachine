#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "TinyMachine.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace tinymachine;
using namespace ::testing;

inline std::string hexify(uint8_t *pData, size_t pCount)
{
    std::stringstream ss;
    for (size_t i=0; i<pCount; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << unsigned(pData[i]);
    return ss.str();
}

TEST(VirtualMachineTest, hellohellohellotinymachine)
{
    std::string src = R"(
        main:
            mov b, msg0
            xor a, a
            xor c, c
        main_loop0:
            add c, 1
            call print
            cmp c, 3
            jb main_loop0
            mov b, msg1
            call print
            call halt
        print: # accept asciiz on b
            xor a, a
            syscall
            ret
        halt:
            mov a, 1
            syscall
        msg0:
            ascii 'hello'
        msg1:
            ascii 'tinymachine'
    )";
    Assembler m(src);
    VirtualMachine vm(m.getByteCode(), 1024);
    vm.registersSyscallHandler(0, [](uint64_t *regs, std::vector<uint8_t>& mem){
        uint64_t msgPtr = regs[1];
        uint8_t* msg = mem.data()+msgPtr;
        std::cout << msg;
    });
    bool halted = false;
    vm.registersSyscallHandler(1, [&halted](uint64_t *regs, std::vector<uint8_t>& mem){
        halted = 1;
    });

    while(!halted)vm.step();
}

struct CmpTestStruct
{
    template <typename T, typename U>
    CmpTestStruct(T a, U b, uint8_t c, bool res)
        : a(uint64_t(a))
        , b(uint64_t(b))
        , c(c)
        , res(res)
    {}
    uint64_t a;
    uint64_t b;
    uint8_t c;
    bool res;
};

struct CmpTest : Test, WithParamInterface<CmpTestStruct> 
{
    CmpTest()
    {
        mVm.registersSyscallHandler(0, [this](uint64_t *regs, std::vector<uint8_t>& mem){
            mHalted = true;
        });
        mVm.registersSyscallHandler(1, [this](uint64_t *regs, std::vector<uint8_t>& mem){
            uint64_t xPtr = regs[1];
            uint64_t yPtr = regs[2];
            uint64_t zPtr = regs[3];
            void* x = mem.data()+xPtr;
            void* y = mem.data()+yPtr;
            void* z = mem.data()+zPtr;
            new (x) uint64_t(mX);
            new (y) uint64_t(mY);
            new (z) uint8_t(mZ);
        });
        mVm.registersSyscallHandler(2, [this](uint64_t *regs, std::vector<uint8_t>& mem){
            uint64_t res = regs[1];
            mSet = true;
            mRes = res;
        });
    }
    template<typename T>
    void test(T a, T b, uint8_t c)
    {
        mX = (uint64_t)a;
        mY = (uint64_t)b;
        mZ = c;
        mSet = false;
        mHalted = false;

        mVm.hotReset();
        while(!mHalted) mVm.step();
    }

    static VirtualMachine mVm;// = VirtualMachine(mM.getByteCode(), 1024);
    bool mHalted;
    uint64_t mX, mY;
    uint8_t mZ;
    bool mSet;
    bool mRes;
};

static std::string cmpTestSrc = R"(
        start:
            jmp main
        _x:
            qword 0
        _y:
            qword 0
        _z:
            byte 0
        main:
            mov a,1 # syscall 1 - fill test data
            mov b, _x
            mov c, _y
            mov d, _z
            syscall
            movzx a, qword ptr[_x]
            movzx b, qword ptr[_y]
            movzx d, byte ptr[_z]
            cmp d, 0 # ja
            je test_ja
            cmp d, 1 # jae
            je test_jae
            cmp d, 2 # jb
            je test_jb
            cmp d, 3 # jbe
            je test_jbe
            cmp d, 4 # jg
            je test_jg
            cmp d, 5 # jge
            je test_jge
            cmp d, 6 # jl
            je test_jl
            cmp d, 7 # jle
            je test_jle
            xor a, a
            syscall
        test_ja:
            cmp a, b
            ja true
            jmp false
        test_jae:
            cmp a, b
            jae true
            jmp false
        test_jb:
            cmp a, b
            jb true
            jmp false
        test_jbe:
            cmp a, b
            jbe true
            jmp false
        test_jg:
            cmp a, b
            jg true
            jmp false
        test_jge:
            cmp a, b
            jge true
            jmp false
        test_jl:
            cmp a, b
            jl true
            jmp false
        test_jle:
            cmp a, b
            jle true
            jmp false
        true:
            mov b, 1
            jmp set_result
        false:
            xor b, b
        set_result:
            mov a, 2 # syscall 2 - set test result
            syscall
            xor a, a
            syscall
    )";

static auto cmpTestSrcAssembler = Assembler(cmpTestSrc);
VirtualMachine CmpTest::mVm = VirtualMachine(cmpTestSrcAssembler.getByteCode(), 1024);

enum {JA, JAE, JB, JBE, JG, JGE, JL, JLE};

TEST_P(CmpTest, tsts)
{
    const auto& param = GetParam();
    test(param.a, param.b, param.c);
    EXPECT_TRUE(true);
    EXPECT_EQ(mRes, param.res);
}

CmpTestStruct cmptestvals[] = {
    CmpTestStruct(   0,    0,  JA, false),
    CmpTestStruct( 100,    0,  JA, true),
    CmpTestStruct(   2,    2, JAE, true),
    CmpTestStruct( 200,    0, JAE, true),
    CmpTestStruct(   0,  222, JAE, false),
    CmpTestStruct( 200, -200,  JG, true),
    CmpTestStruct(-200,  200,  JG, false),
    CmpTestStruct(-200, -200, JGE, true),
    CmpTestStruct(   1,    1, JGE, true),
    CmpTestStruct(  -1,    1, JGE, false),
    CmpTestStruct(-200,   -1,  JL, true),
    CmpTestStruct(  12,    1,  JL, false),
    CmpTestStruct(-123, -123, JLE, true),
    CmpTestStruct(-321,    1, JLE, true),
    CmpTestStruct( 321,   -1, JLE, false)
};

INSTANTIATE_TEST_CASE_P(CmpTest, CmpTest, ValuesIn(cmptestvals));
