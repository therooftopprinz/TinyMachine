#ifndef __TINYMACHINE_MACHINE_HPP__
#define __TINYMACHINE_MACHINE_HPP__

#include <string_view>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include <regex>
#include <list>
#include <map>

namespace tinymachine
{

template<size_t N, bool IsDecode, typename Operands, typename... Ts>
struct Codec
{
    Codec(uint8_t* pPC, Operands& pOperands){}
};        

template<size_t N, bool IsDecode, typename Operands, typename T, typename... Ts>
struct Codec<N, IsDecode, Operands, T, Ts...> : Codec<N+1, IsDecode, Operands, Ts...>
{
    Codec(uint8_t* pPC, Operands& pOperands)
        : Codec<N+1, IsDecode, Operands, Ts...>(pPC+sizeof(T), pOperands)
    {
        if constexpr (IsDecode)
        {
            std::memcpy(&std::get<N>(pOperands), pPC, sizeof(T));
        }
        else
        {
            std::memcpy(pPC, &std::get<N>(pOperands), sizeof(T));
        }
    }
};

template<uint8_t OpCode, typename... Operands>
struct Instruction
{
public:
    static constexpr uint8_t opcode = OpCode;

    Instruction(uint8_t* pPC)
        : mPC(pPC)
    {
    }

    constexpr static size_t size()
    {
        return sizeof(opcode) + (sizeof(Operands)+...);
    }

    uint8_t* next()
    {
        return mPC + size();
    }

    void decode()
    {
        Codec<0, true, decltype(mOperands), Operands...> decode(mPC + sizeof(opcode), mOperands);
    }

    void encode()
    {
        *mPC = opcode;
        Codec<0, false, decltype(mOperands), Operands...> decode(mPC + sizeof(opcode), mOperands);
    }

    template<size_t N>
    typename std::tuple_element<N, std::tuple<Operands...>>::type& get()
    {
        return std::get<N>(mOperands);
    }
private:
    uint8_t* mPC;
    std::tuple<Operands...> mOperands;
};

using I_MOV_R64_R64_T                    = Instruction<0x01, uint8_t, uint8_t>;
using I_MOV_R64_I8_T                     = Instruction<0x02, uint8_t, uint8_t>;
using I_MOV_R64_I16_T                    = Instruction<0x03, uint8_t, uint16_t>;
using I_MOV_R64_I32_T                    = Instruction<0x04, uint8_t, uint32_t>;
using I_MOV_R64_I64_T                    = Instruction<0x05, uint8_t, uint64_t>;
using I_MOVZX_R64_BYTE_PTR_R64_T         = Instruction<0x06, uint8_t, uint8_t>;
using I_MOVZX_R64_WORD_PTR_R64_T         = Instruction<0x07, uint8_t, uint8_t>;
using I_MOVZX_R64_DWORD_PTR_R64_T        = Instruction<0x08, uint8_t, uint8_t>;
using I_MOVZX_R64_QWORD_PTR_R64_T        = Instruction<0x09, uint8_t, uint8_t>;
using I_MOVSX_R64_BYTE_PTR_R64_T         = Instruction<0x0A, uint8_t, uint8_t>;
using I_MOVSX_R64_WORD_PTR_R64_T         = Instruction<0x0B, uint8_t, uint8_t>;
using I_MOVSX_R64_DWORD_PTR_R64_T        = Instruction<0x0C, uint8_t, uint8_t>;
using I_MOVSX_R64_QWORD_PTR_R64_T        = Instruction<0x0D, uint8_t, uint8_t>;
using I_MOVZX_R64_BYTE_PTR_I64_T         = Instruction<0x0E, uint8_t, uint64_t>;
using I_MOVZX_R64_WORD_PTR_I64_T         = Instruction<0x0F, uint8_t, uint64_t>;
using I_MOVZX_R64_DWORD_PTR_I64_T        = Instruction<0x10, uint8_t, uint64_t>;
using I_MOVZX_R64_QWORD_PTR_I64_T        = Instruction<0x11, uint8_t, uint64_t>;
using I_MOVSX_R64_BYTE_PTR_I64_T         = Instruction<0x12, uint8_t, uint64_t>;
using I_MOVSX_R64_WORD_PTR_I64_T         = Instruction<0x13, uint8_t, uint64_t>;
using I_MOVSX_R64_DWORD_PTR_I64_T        = Instruction<0x14, uint8_t, uint64_t>;
using I_MOVSX_R64_QWORD_PTR_I64_T        = Instruction<0x15, uint8_t, uint64_t>;
using I_MOV_BYTE_PTR_R64_R64_T           = Instruction<0x16, uint8_t, uint8_t>;
using I_MOV_WORD_PTR_R64_R64_T           = Instruction<0x17, uint8_t, uint8_t>;
using I_MOV_DWORD_PTR_R64_R64_T          = Instruction<0x18, uint8_t, uint8_t>;
using I_MOV_QWORD_PTR_R64_R64_T          = Instruction<0x19, uint8_t, uint8_t>;
using I_MOV_BYTE_PTR_I64_R64_T           = Instruction<0x1A, uint8_t, uint64_t>;
using I_MOV_WORD_PTR_I64_R64_T           = Instruction<0x1B, uint8_t, uint64_t>;
using I_MOV_DWORD_PTR_I64_R64_T          = Instruction<0x1C, uint8_t, uint64_t>;
using I_MOV_QWORD_PTR_I64_R64_T          = Instruction<0x1D, uint8_t, uint64_t>;
using I_ADD_R64_R64_T                    = Instruction<0x1E, uint8_t, uint8_t>;
using I_SUB_R64_R64_T                    = Instruction<0x1F, uint8_t, uint8_t>;
using I_MUL_R64_R64_T                    = Instruction<0x20, uint8_t, uint8_t>;
using I_DIV_R64_R64_T                    = Instruction<0x21, uint8_t, uint8_t>;
using I_ADD_R64_I64_T                    = Instruction<0x22, uint8_t, uint64_t>;
using I_SUB_R64_I64_T                    = Instruction<0x23, uint8_t, uint64_t>;
using I_MUL_R64_I64_T                    = Instruction<0x24, uint8_t, uint64_t>;
using I_DIV_R64_I64_T                    = Instruction<0x25, uint8_t, uint64_t>;
using I_SAR_R64_R64_T                    = Instruction<0x26, uint8_t, uint8_t>;
using I_SHR_R64_R64_T                    = Instruction<0x27, uint8_t, uint8_t>;
using I_SHL_R64_R64_T                    = Instruction<0x28, uint8_t, uint8_t>;
using I_SAR_R64_I8_T                     = Instruction<0x29, uint8_t, uint8_t>;
using I_SHR_R64_I8_T                     = Instruction<0x2A, uint8_t, uint8_t>;
using I_SHL_R64_I8_T                     = Instruction<0x2B, uint8_t, uint8_t>;
using I_AND_R64_R64_T                    = Instruction<0x2C, uint8_t, uint8_t>;
using I_OR_R64_R64_T                     = Instruction<0x2E, uint8_t, uint8_t>;
using I_XOR_R64_R64_T                    = Instruction<0x2F, uint8_t, uint8_t>;
using I_NOT_R64_R64_T                    = Instruction<0x30, uint8_t, uint8_t>;
using I_CMP_R64_R64_T                    = Instruction<0x31, uint8_t, uint8_t>;
using I_AND_R64_I64_T                    = Instruction<0x32, uint8_t, uint64_t>;
using I_OR_R64_I64_T                     = Instruction<0x33, uint8_t, uint64_t>;
using I_XOR_R64_I64_T                    = Instruction<0x34, uint8_t, uint64_t>;
using I_NOT_R64_I64_T                    = Instruction<0x35, uint8_t, uint64_t>;
using I_CMP_R64_I64_T                    = Instruction<0x36, uint8_t, uint64_t>;
using I_JE_R64_T                         = Instruction<0x37, uint8_t>;
using I_JG_R64_T                         = Instruction<0x38, uint8_t>;
using I_JGE_R64_T                        = Instruction<0x39, uint8_t>;
using I_JL_R64_T                         = Instruction<0x3A, uint8_t>;
using I_JLE_R64_T                        = Instruction<0x3B, uint8_t>;
using I_JA_R64_T                         = Instruction<0x3C, uint8_t>;
using I_JAE_R64_T                        = Instruction<0x3E, uint8_t>;
using I_JB_R64_T                         = Instruction<0x3F, uint8_t>;
using I_JBE_R64_T                        = Instruction<0x40, uint8_t>;
using I_CALL_R64_T                       = Instruction<0x41, uint8_t>;
using I_JE_I64_T                         = Instruction<0x42, uint64_t>;
using I_JG_I64_T                         = Instruction<0x43, uint64_t>;
using I_JGE_I64_T                        = Instruction<0x44, uint64_t>;
using I_JL_I64_T                         = Instruction<0x45, uint64_t>;
using I_JLE_I64_T                        = Instruction<0x46, uint64_t>;
using I_JA_I64_T                         = Instruction<0x47, uint64_t>;
using I_JAE_I64_T                        = Instruction<0x48, uint64_t>;
using I_JB_I64_T                         = Instruction<0x49, uint64_t>;
using I_JBE_I64_T                        = Instruction<0x4A, uint64_t>;
using I_CALL_I64_T                       = Instruction<0x4B, uint64_t>;
using I_RET_T                            = Instruction<0x4C>;
using I_PUSH_R64_T                       = Instruction<0x4E, uint8_t>;
using I_POP_R64_T                        = Instruction<0x4F, uint8_t>;
using I_SYSCALL_T                        = Instruction<0x50>;

struct UnresolvedAddress
{
    size_t pc;
    size_t address;
    size_t sz;
    std::string symbol;
    size_t number;
};

struct SymbolInfo
{
    size_t address;
    size_t number;
};

class Assembler
{
public:
    Assembler(std::string pCode)
    {
        std::istringstream ss(pCode);
        std::string line;
        size_t number = 0;
        while (std::getline(ss, line))
        {
            parse(number++, line);
        }
    };
private:
    std::vector<std::string> split(const std::string& s, char delimiter)
    {
       std::vector<std::string> tokens;
       std::string token;
       std::istringstream tokenStream(s);
       while (std::getline(tokenStream, token, delimiter))
       {
          if (token.size())
            tokens.push_back(token);
       }
       return tokens;
    }
 
    void parse(size_t pNumber, std::string pLine)
    {
        auto tokens = split(pLine, ' ');
        if (!tokens.size())
            return;
        if (':' == tokens[0].back())
            return label(pNumber, std::string(tokens[0].data(), tokens[0].size()-1));
        if (std::any_of(mKeywordData.begin(), mKeywordData.end(), [&tokens](const auto& i){return i==tokens[0];}))
            return dataKeyword(pNumber, pLine, tokens);
        return instruction(pNumber, pLine);
    }

    void label(size_t pNumber, std::string pLabel)
    {
        auto it = mSymbolTable.find(pLabel);
        if (mSymbolTable.end()!=it)
            throw std::runtime_error(std::string{} + "Label is existing: " + pLabel + " first defined in line number: " + std::to_string(it->second.number));
        std::cout << "label: " << pLabel << "\n";
        mSymbolTable.emplace(std::pair<std::string, SymbolInfo>(pLabel, {mByteCode.size(), pNumber}));
    }

    void dataKeyword(size_t pNumber, std::string& pLine, std::vector<std::string>& pToken)
    {
        if ("ascii"==pToken[0])
        {
            std::regex pattern(".*?'(.*?)'.*?");
            std::smatch match;
            if (!std::regex_match(pLine, match, pattern))
                throw std::runtime_error(std::string{} + "Ascii data failed: in line number: " + std::to_string(pNumber));

            auto ascii = match[1].str();
            std::cout << "ascii: " << ascii << "\n";
            auto base = mByteCode.size();
            mByteCode.resize(base+ascii.size()+1);
            std::memcpy(mByteCode.data()+base, ascii.data(), ascii.size());
            mByteCode.back() = 0;
            return;
        }
        throw std::runtime_error(std::string{} + "Unimplemented data keyword! line: " + pLine);
    }

    enum class OperandType {NA, R64, RF64, I64, IN64, IF64, I8, BPR64, WPR64, DPR64, QPR64, BPI64, WPI64, DPI64, QPI64, BPIN64, WPIN64, DPIN64, QPIN64};
    OperandType getRegType(const std::string& pOperand)
    {
        if (1 == pOperand.size() && (pOperand[0]>='a' || pOperand[0]<='z'))
            return OperandType::R64;
        else if (2 == pOperand.size() && pOperand[0]=='f' && (pOperand[1]>='a' || pOperand[1]<='z'))
            return OperandType::RF64;
        return OperandType::NA;
    }

    OperandType getOperandType(const std::string& pOperand)
    {
        auto regtype = getRegType(pOperand)
        if (OperandType::NA != regtype)
            return regtype;
            std::regex pattern("(.*?)[ ]+ptr[ ]+(\\[(.*?)*\\])");
        std::smatch match;
        if (std::regex_match(pOperand, match, pattern) && 3==match.size())
        {
            auto ptrval = match[2].str();
            auto regtype = getRegType(ptrval);
            auto ptrsize = match[1].str();
            if (OperandType::R64 == regtype)
                if ("byte" == ptrsize) return OperandType::BPR64;
                else if ("word" == ptrsize) return OperandType::WPR64;
                else if ("dword" == ptrsize) return OperandType::DPR64;
                else if ("qword" == ptrsize) return OperandType::QPR64;
                else throw std::runtime_error(std::string{} + "Unknown pointer size: " + ptrsize);
            try
            {
                std::stoul(ptrval);
                if ("byte" == ptrsize) return OperandType::BPI64;
                else if ("word" == ptrsize) return OperandType::WPI64;
                else if ("dword" == ptrsize) return OperandType::DPI64;
                else if ("qword" == ptrsize) return OperandType::QPI64;
                throw std::runtime_error(std::string{} + "Unknown pointer size: " + ptrsize);
            }
            catch (...)
            {
                if ("byte" == ptrsize) return OperandType::BPIN64;
                else if ("word" == ptrsize) return OperandType::WPIN64;
                else if ("dword" == ptrsize) return OperandType::DPIN64;
                else if ("qword" == ptrsize) return OperandType::QPIN64;
                throw std::runtime_error(std::string{} + "Unknown pointer size: " + ptrsize);
            }
            [[unreachable]];
        }
    }

    void instruction(size_t pNumber, std::string& pLine)
    {
        std::regex pattern("^[ ]*([a-z]+)(?:[ ]+([A-Za-z0-9_]+))*(?:[ ]*,[ ]*([A-Za-z0-9_]+))*[ ]*(?:#.*)*");
        std::smatch match;
        if (!std::regex_match(pLine, match, pattern))
            throw std::runtime_error(std::string{} + "Ascii data failed: in line number: " + std::to_string(pNumber));
        auto ins = match[1].str();
        auto a = match.size()>2 ? match[2].str() : std::string{};
        auto b = match.size()>3 ? match[3].str() : std::string{};
        std::cout << "ins: " << ins << "\n";
        std::cout << "a: " << a << "\n";
        std::cout << "b: " << b << "\n";
        // if ("mov"==pToken[0]) {}
        // else if ("movzx"==pToken[0]) {}
        // else if ("movsx"==pToken[0]) {}
        // else if ("add"==pToken[0]) {}
        // else if ("sub"==pToken[0]) {}
        // else if ("mul"==pToken[0]) {}
        // else if ("div"==pToken[0]) {}
        // else if ("sar"==pToken[0]) {}
        // else if ("shr"==pToken[0]) {}
        // else if ("shl"==pToken[0]) {}
        // else if ("and"==pToken[0]) {}
        // else if ("or"==pToken[0]) {}
        // else if ("xor"==pToken[0]) {}
        // else if ("not"==pToken[0]) {}
        // else if ("cmp"==pToken[0]) {}
        // else if ("je"==pToken[0]) {}
        // else if ("jg"==pToken[0]) {}
        // else if ("jge"==pToken[0]) {}
        // else if ("jl"==pToken[0]) {}
        // else if ("jle"==pToken[0]) {}
        // else if ("ja"==pToken[0]) {}
        // else if ("jae"==pToken[0]) {}
        // else if ("jb"==pToken[0]) {}
        // else if ("jbe"==pToken[0]) {}
        // else if ("call"==pToken[0]) {}
        // else if ("ret"==pToken[0]) {}
        // else if ("push"==pToken[0]) {}
        // else if ("pop"==pToken[0]) {}
        // else if ("syscall"==pToken[0]) {}
    }

    std::vector<std::string> mKeywordData = {"ascii", "byte", "word", "dword", "qword"};
    std::vector<uint8_t> mByteCode;
    std::map<std::string, SymbolInfo> mSymbolTable;
    std::list<UnresolvedAddress> mUnresolvedAddress;
};

} // namespace tinymachine

#endif //__TINYMACHINE_MACHINE_HPP__s