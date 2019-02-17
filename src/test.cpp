#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "TinyMachine.hpp"

using namespace tinymachine;

std::string hexify(uint8_t *pData, size_t pCount)
{
    std::stringstream ss;
    ss << "hexify: ";
    for (size_t i=0; i<pCount; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << unsigned(pData[i]);
    return ss.str();

}
int main()
{
   std::string code = R"(
    main:
        xor a, a
        mov b, msg_configure_error
        syscall
        ret
    msg_configure_error:
        ascii 'configuring error.'
    )";

    Assembler myasm(code);
}