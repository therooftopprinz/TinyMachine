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

struct VirtualMachineTest : Test
{
};

TEST_F(VirtualMachineTest, testRun)
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