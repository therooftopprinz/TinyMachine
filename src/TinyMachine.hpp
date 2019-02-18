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
        if constexpr (sizeof...(Operands))
            return sizeof(opcode) + (sizeof(Operands)+...);
        else
            return sizeof(opcode);
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
using I_MOV_BYTE_PTR_I64_R64_T           = Instruction<0x1A, uint64_t, uint8_t>;
using I_MOV_WORD_PTR_I64_R64_T           = Instruction<0x1B, uint64_t, uint8_t>;
using I_MOV_DWORD_PTR_I64_R64_T          = Instruction<0x1C, uint64_t, uint8_t>;
using I_MOV_QWORD_PTR_I64_R64_T          = Instruction<0x1D, uint64_t, uint8_t>;
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
    size_t offset;
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
            parse(number++, line);
        fillUnresolved();
    };

    enum class OperandType {NA, R64, IN64, I64, I32, I16, I8, BPR64, WPR64, DPR64, QPR64, BPI64, WPI64, DPI64, QPI64, BPIN64, WPIN64, DPIN64, QPIN64};
    static OperandType getRegType(const std::string& pOperand)
    {
        if (1 == pOperand.size() && pOperand[0]>='a' && pOperand[0]<='z')
            return OperandType::R64;
        return OperandType::NA;
    }

    static OperandType getOperandType(const std::string& pOperand)
    {
        auto regtype = getRegType(pOperand);
        if (OperandType::NA != regtype)
            return regtype;
        std::regex pattern("^(.*?)[ ]+ptr[ ]*\\[(.*?)\\]$");
        std::smatch match;
        if (std::regex_match(pOperand, match, pattern))
        {
            auto ptrval = match[2].str();
            auto regtype = getRegType(ptrval);
            auto ptrsize = match[1].str();
            if (OperandType::R64 == regtype)
            {
                if ("byte" == ptrsize) return OperandType::BPR64;
                else if ("word" == ptrsize) return OperandType::WPR64;
                else if ("dword" == ptrsize) return OperandType::DPR64;
                else if ("qword" == ptrsize) return OperandType::QPR64;
                else throw std::runtime_error(std::string{} + "Unknown pointer size: " + ptrsize);
            }
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
        }
        try
        {
            // TODO: Parse hex, bin, or octal and double
            size_t sval = std::stoul(pOperand);
            if (!(sval&0xFFFFFFFFFFFFFF00)) return OperandType::I8;
            else if (!(sval&0xFFFFFFFFFFFF0000)) return OperandType::I16;
            else if (!(sval&0xFFFFFFFF00000000)) return OperandType::I32;
            else return OperandType::I64;
        }
        catch (...)
        {
            // TODO: Validate if label is valid
            return OperandType::IN64;
        }
    }

    std::vector<uint8_t>& getByteCode()
    {
        return mByteCode;
    }
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
        if (std::any_of(mKeywordData.begin(), mKeywordData.end(), [&tokens](const auto& i){return i==tokens[0]; }))
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
        // TODO: byte word dword qword array
        throw std::runtime_error(std::string{} + "Unimplemented data keyword! line: " + pLine);
    }

    std::string getPtrValue(const std::string& pPtr)
    {
        std::regex pattern("^(.*?)[ ]+ptr[ ]*\\[(.*?)\\]$");
        std::smatch match;
        std::string ptrval;
        if (std::regex_match(pPtr, match, pattern))
            ptrval = match[2].str();
        return ptrval;
    }

    template <typename T>
    void encodeMov8_8(const std::string& a, const std::string& b)
    {
        auto basesize = mByteCode.size();
        mByteCode.resize(basesize + T::size());
        T i(mByteCode.data()+basesize);
        i.template get<0>() = a.back()-'a';
        i.template get<1>() = b.back()-'a';
        i.encode();
    }

    template <typename T>
    void encodeMov8_S(const std::string& a, const std::string& b)
    {
        auto basesize = mByteCode.size();
        mByteCode.resize(basesize + T::size());
        T i(mByteCode.data()+basesize);
        i.template get<0>() = a.back()-'a';
        i.template get<1>() = std::stoul(b);
        i.encode();
    }

    template <typename T>
    void encodeMov8_SN(size_t pNumber, const std::string& a, const std::string& b)
    {
        auto found = mSymbolTable.find(b);
        if (mSymbolTable.end()!=found)
            return encodeMov8_S<T>(a, std::to_string(found->second.address));
        auto basesize = mByteCode.size();
        mUnresolvedAddress.emplace_back(UnresolvedAddress{basesize, sizeof(T::opcode) +
            1, b, pNumber});
            // TODO: reform to this:
            // sizeof(decltype(T().template get<0>())), b, pNumber});
        return encodeMov8_S<T>(a, "0");
    }

    template <typename T>
    void encodeMov64_8(const std::string& a, const std::string& b)
    {
        auto basesize = mByteCode.size();
        mByteCode.resize(basesize + T::size());
        T i(mByteCode.data()+basesize);
        i.template get<0>() = size_t(std::stoul(a));
        i.template get<1>() = b.back()-'a';
        i.encode();
    }

    template <typename T>
    void encodeMov64N_8(size_t pNumber, const std::string& a, const std::string& b)
    {
        auto found = mSymbolTable.find(a);
        if (mSymbolTable.end()!=found)
            return encodeMov64_8<T>(std::to_string(found->second.address), b);
        auto basesize = mByteCode.size();
        mUnresolvedAddress.emplace_back(UnresolvedAddress{basesize, sizeof(T::opcode), a, pNumber});
        return encodeMov64_8<T>("0", b);
    }

    template <typename T>
    void encodeIns8(const std::string& a)
    {
        auto basesize = mByteCode.size();
        mByteCode.resize(basesize + T::size());
        T i(mByteCode.data()+basesize);
        i.template get<0>() = a.back()-'a';
        i.encode();
    }

    template <typename T>
    void encodeInsS(const std::string& a)
    {
        auto basesize = mByteCode.size();
        mByteCode.resize(basesize + T::size());
        T i(mByteCode.data()+basesize);
        i.template get<0>() = std::stoul(a);
        i.encode();
    }

    template <typename T>
    void encodeInsSN(size_t pNumber, const std::string& a)
    {
        auto found = mSymbolTable.find(a);
        if (mSymbolTable.end()!=found)
            return encodeInsS<T>(std::to_string(found->second.address));
        auto basesize = mByteCode.size();
        mUnresolvedAddress.emplace_back(UnresolvedAddress{basesize, sizeof(T::opcode), a, pNumber});
        return encodeInsS<T>("0");
    }

    template <typename T>
    void encodeIns()
    {
        auto basesize = mByteCode.size();
        mByteCode.resize(basesize + T::size());
        T i(mByteCode.data()+basesize);
        i.encode();
    }

    void instruction(size_t pNumber, std::string& pLine)
    {
        std::regex pattern("^[ ]*([a-z]+)(?:[ ]+([A-Za-z0-9_\\-\\[\\] ]+))*(?:[ ]*,[ ]*([A-Za-z0-9_\\-\\[\\] ]+))*[ ]*(?:#.*)*");
        std::smatch match;

        if (!std::regex_match(pLine, match, pattern))
            throw std::runtime_error(std::string{} + "Instruction parse failed: in line number: " + std::to_string(pNumber));

        auto ins = match[1].str();
        auto a = match.size()>2 ? match[2].str() : std::string{};
        auto b = match.size()>3 ? match[3].str() : std::string{};
        OperandType at = {};
        OperandType bt = {};

        if (a.size())
            at = getOperandType(a);
        if (b.size())
            bt = getOperandType(b);

        std::cout << "ins: " << ins << "\n";
        std::cout << "a: " << a << "\n";
        std::cout << "b: " << b << "\n";
        if ("mov"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_MOV_R64_R64_T>(a, b);

            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_MOV_R64_I8_T>(a, b);
            if (OperandType::R64==at && OperandType::I16==bt)
                return encodeMov8_S<I_MOV_R64_I16_T>(a, b);
            if (OperandType::R64==at && OperandType::I32==bt)
                return encodeMov8_S<I_MOV_R64_I32_T>(a, b);
            if (OperandType::R64==at && OperandType::I64==bt)
                return encodeMov8_S<I_MOV_R64_I64_T>(a, b);

            if (OperandType::R64==at && OperandType::IN64==bt)
            {
                auto basesize = mByteCode.size();
                mByteCode.resize(basesize + I_MOV_R64_I64_T::size());
                I_MOV_R64_I64_T i(mByteCode.data()+basesize);
                i.get<0>() = a.back()-'a';
                auto found = mSymbolTable.find(b);
                if (mSymbolTable.end()==found)
                {
                    i.get<1>() = 0;
                    mUnresolvedAddress.emplace_back(UnresolvedAddress{basesize, sizeof(I_MOV_R64_I64_T::opcode)+1, b, pNumber});
                }
                else
                {
                    i.get<1>() = found->second.address;
                }
                i.encode();
                return;
            }

            // TODO: reuse from getOperandType
            auto ptrval = getPtrValue(a);

            if (OperandType::BPR64==at && OperandType::R64==bt)
                return encodeMov8_8<I_MOV_BYTE_PTR_R64_R64_T>(ptrval, b);
            if (OperandType::WPR64==at && OperandType::R64==bt)
                return encodeMov8_8<I_MOV_WORD_PTR_R64_R64_T>(ptrval, b);
            if (OperandType::DPR64==at && OperandType::R64==bt)
                return encodeMov8_8<I_MOV_DWORD_PTR_R64_R64_T>(ptrval, b);
            if (OperandType::QPR64==at && OperandType::R64==bt)
                return encodeMov8_8<I_MOV_QWORD_PTR_R64_R64_T>(ptrval, b);

            if (OperandType::BPI64==at && OperandType::R64==bt)
                return encodeMov64_8<I_MOV_BYTE_PTR_I64_R64_T>(ptrval, b);
            if (OperandType::WPI64==at && OperandType::R64==bt)
                return encodeMov64_8<I_MOV_WORD_PTR_I64_R64_T>(ptrval, b);
            if (OperandType::DPI64==at && OperandType::R64==bt)
                return encodeMov64_8<I_MOV_DWORD_PTR_I64_R64_T>(ptrval, b);
            if (OperandType::QPI64==at && OperandType::R64==bt)
                return encodeMov64_8<I_MOV_QWORD_PTR_I64_R64_T>(ptrval, b);

            if (OperandType::BPIN64==at && OperandType::R64==bt)
                return encodeMov64N_8<I_MOV_BYTE_PTR_I64_R64_T>(pNumber, ptrval, b);
            if (OperandType::WPIN64==at && OperandType::R64==bt)
                return encodeMov64N_8<I_MOV_WORD_PTR_I64_R64_T>(pNumber, ptrval, b);
            if (OperandType::DPIN64==at && OperandType::R64==bt)
                return encodeMov64N_8<I_MOV_DWORD_PTR_I64_R64_T>(pNumber, ptrval, b);
            if (OperandType::QPIN64==at && OperandType::R64==bt)
                return encodeMov64N_8<I_MOV_QWORD_PTR_I64_R64_T>(pNumber, ptrval, b);
        }
        else if ("movzx"==ins)
        {
            auto ptrval = getPtrValue(b);
            if (OperandType::R64==at && OperandType::BPR64==bt)
                return encodeMov8_8<I_MOVZX_R64_BYTE_PTR_R64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::WPR64==bt)
                return encodeMov8_8<I_MOVZX_R64_WORD_PTR_R64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::DPR64==bt)
                return encodeMov8_8<I_MOVZX_R64_DWORD_PTR_R64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::QPR64==bt)
                return encodeMov8_8<I_MOVZX_R64_QWORD_PTR_R64_T>(a, ptrval);

            if (OperandType::R64==at && OperandType::BPI64==bt)
                return encodeMov8_S<I_MOVZX_R64_BYTE_PTR_I64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::WPI64==bt)
                return encodeMov8_S<I_MOVZX_R64_WORD_PTR_I64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::DPI64==bt)
                return encodeMov8_S<I_MOVZX_R64_DWORD_PTR_I64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::QPI64==bt)
                return encodeMov8_S<I_MOVZX_R64_QWORD_PTR_I64_T>(a, ptrval);

            if (OperandType::R64==at && OperandType::BPI64==bt)
                return encodeMov8_SN<I_MOVZX_R64_BYTE_PTR_I64_T>(pNumber, a, ptrval);
            if (OperandType::R64==at && OperandType::WPI64==bt)
                return encodeMov8_SN<I_MOVZX_R64_WORD_PTR_I64_T>(pNumber, a, ptrval);
            if (OperandType::R64==at && OperandType::DPI64==bt)
                return encodeMov8_SN<I_MOVZX_R64_DWORD_PTR_I64_T>(pNumber, a, ptrval);
            if (OperandType::R64==at && OperandType::QPI64==bt)
                return encodeMov8_SN<I_MOVZX_R64_QWORD_PTR_I64_T>(pNumber, a, ptrval);
        }
        else if ("movsx"==ins)
        {
            auto ptrval = getPtrValue(b);
            if (OperandType::R64==at && OperandType::BPR64==bt)
                return encodeMov8_8<I_MOVSX_R64_BYTE_PTR_R64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::WPR64==bt)
                return encodeMov8_8<I_MOVSX_R64_WORD_PTR_R64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::DPR64==bt)
                return encodeMov8_8<I_MOVSX_R64_DWORD_PTR_R64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::QPR64==bt)
                return encodeMov8_8<I_MOVSX_R64_QWORD_PTR_R64_T>(a, ptrval);

            if (OperandType::R64==at && OperandType::BPI64==bt)
                return encodeMov8_S<I_MOVSX_R64_BYTE_PTR_I64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::WPI64==bt)
                return encodeMov8_S<I_MOVSX_R64_WORD_PTR_I64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::DPI64==bt)
                return encodeMov8_S<I_MOVSX_R64_DWORD_PTR_I64_T>(a, ptrval);
            if (OperandType::R64==at && OperandType::QPI64==bt)
                return encodeMov8_S<I_MOVSX_R64_QWORD_PTR_I64_T>(a, ptrval);

            if (OperandType::R64==at && OperandType::BPIN64==bt)
                return encodeMov8_SN<I_MOVSX_R64_BYTE_PTR_I64_T>(pNumber, a, ptrval);
            if (OperandType::R64==at && OperandType::WPIN64==bt)
                return encodeMov8_SN<I_MOVSX_R64_WORD_PTR_I64_T>(pNumber, a, ptrval);
            if (OperandType::R64==at && OperandType::DPIN64==bt)
                return encodeMov8_SN<I_MOVSX_R64_DWORD_PTR_I64_T>(pNumber, a, ptrval);
            if (OperandType::R64==at && OperandType::QPIN64==bt)
                return encodeMov8_SN<I_MOVSX_R64_QWORD_PTR_I64_T>(pNumber, a, ptrval);
        }
        else if ("add"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_ADD_R64_I64_T>(a, b);
            if (OperandType::R64==at && (OperandType::I64==bt||OperandType::I32==bt||OperandType::I16==bt||OperandType::I8==bt))
                return encodeMov8_S<I_ADD_R64_I64_T>(a, b);
        }
        else if ("sub"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_SUB_R64_I64_T>(a, b);
            if (OperandType::R64==at && (OperandType::I64==bt||OperandType::I32==bt||OperandType::I16==bt||OperandType::I8==bt))
                return encodeMov8_S<I_SUB_R64_I64_T>(a, b);
        }
        else if ("mul"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_MUL_R64_I64_T>(a, b);
            if (OperandType::R64==at && (OperandType::I64==bt||OperandType::I32==bt||OperandType::I16==bt||OperandType::I8==bt))
                return encodeMov8_S<I_MUL_R64_I64_T>(a, b);
        }
        else if ("div"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_DIV_R64_I64_T>(a, b);
            if (OperandType::R64==at && (OperandType::I64==bt||OperandType::I32==bt||OperandType::I16==bt||OperandType::I8==bt))
                return encodeMov8_S<I_DIV_R64_I64_T>(a, b);
        }
        else if ("sar"==ins)
        {
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_SAR_R64_R64_T>(a, b);
        }
        else if ("shr"==ins)
        {
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_SHR_R64_R64_T>(a, b);
        }
        else if ("shl"==ins)
        {
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_SHL_R64_R64_T>(a, b);
        }
        else if ("and"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_AND_R64_R64_T>(a, b);
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_AND_R64_I64_T>(a, b);
        }
        else if ("or"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_OR_R64_R64_T>(a, b);
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_OR_R64_I64_T>(a, b);
        }
        else if ("xor"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_XOR_R64_R64_T>(a, b);
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_XOR_R64_I64_T>(a, b);
        }
        else if ("not"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_NOT_R64_R64_T>(a, b);
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_NOT_R64_I64_T>(a, b);
        }
        else if ("cmp"==ins)
        {
            if (OperandType::R64==at && OperandType::R64==bt)
                return encodeMov8_8<I_CMP_R64_R64_T>(a, b);
            if (OperandType::R64==at && OperandType::I8==bt)
                return encodeMov8_S<I_CMP_R64_I64_T>(a, b);
        }
        else if ("je"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JE_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JE_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JE_I64_T>(pNumber, a);
        }
        else if ("jg"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JG_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JG_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JG_I64_T>(pNumber, a);
        }
        else if ("jge"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JGE_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JGE_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JGE_I64_T>(pNumber, a);
        }
        else if ("jl"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JL_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JL_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JL_I64_T>(pNumber, a);
        }
        else if ("jle"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JLE_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JLE_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JLE_I64_T>(pNumber, a);
        }
        else if ("ja"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JA_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JA_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JA_I64_T>(pNumber, a);
        }
        else if ("jae"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JAE_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JAE_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JAE_I64_T>(pNumber, a);
        }
        else if ("jb"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JB_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JB_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JB_I64_T>(pNumber, a);
        }
        else if ("jbe"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_JBE_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_JBE_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_JBE_I64_T>(pNumber, a);
        }
        else if ("call"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_CALL_R64_T>(a);
            if (OperandType::I64==at)
                return encodeInsS<I_CALL_I64_T>(a);
            if (OperandType::IN64==at)
                return encodeInsSN<I_CALL_I64_T>(pNumber, a);
        }
        else if ("ret"==ins)
        {
            return encodeIns<I_RET_T>();
        }
        else if ("push"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_PUSH_R64_T>(a);
        }
        else if ("pop"==ins)
        {
            if (OperandType::R64==at)
                return encodeInsS<I_POP_R64_T>(a);
        }
        else if ("syscall"==ins)
        {
            return encodeIns<I_SYSCALL_T>();
        }
        throw std::runtime_error(std::string{} + "unhandled instruction: " + ins + " at line: " + std::to_string(pNumber));
    }

    void fillUnresolved()
    {
        for (const auto& i : mUnresolvedAddress)
        {
            auto found = mSymbolTable.find(i.symbol);
            if (mSymbolTable.end() == found)
                throw std::runtime_error(std::string{} + "Unreference symbol: " + i.symbol + " at line: " + std::to_string(i.number));

            new (mByteCode.data()+i.pc+i.offset) size_t(found->second.address);
        }
    }

    std::vector<std::string> mKeywordData = {"ascii", "byte", "word", "dword", "qword"};
    std::vector<uint8_t> mByteCode;
    std::map<std::string, SymbolInfo> mSymbolTable;
    std::list<UnresolvedAddress> mUnresolvedAddress;
};

class VirtualMachine
{
public:
    VirtualMachine(std::vector<uint8_t>& pByteCode)
        : mByteCode(pByteCode)
    {}
    void run()
    {
        while(1)
        {
            uint8_t* ins = mByteCode.data() + mProgramCounter;
            process(ins);
        }
    }
private:
    void process(uint8_t* pIns)
    {
        auto opCode = *pIns;
        switch(opCode)
        {
            case I_MOV_R64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_R64_I8_T::opcode:
            {
                break;
            }

            case I_MOV_R64_I16_T::opcode:
            {
                break;
            }

            case I_MOV_R64_I32_T::opcode:
            {
                break;
            }

            case I_MOV_R64_I64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_BYTE_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_WORD_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_DWORD_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_QWORD_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_BYTE_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_WORD_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_DWORD_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_QWORD_PTR_R64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_BYTE_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_WORD_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_DWORD_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVZX_R64_QWORD_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_BYTE_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_WORD_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_DWORD_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOVSX_R64_QWORD_PTR_I64_T::opcode:
            {
                break;
            }

            case I_MOV_BYTE_PTR_R64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_WORD_PTR_R64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_DWORD_PTR_R64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_QWORD_PTR_R64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_BYTE_PTR_I64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_WORD_PTR_I64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_DWORD_PTR_I64_R64_T::opcode:
            {
                break;
            }

            case I_MOV_QWORD_PTR_I64_R64_T::opcode:
            {
                break;
            }

            case I_ADD_R64_R64_T::opcode:
            {
                break;
            }

            case I_SUB_R64_R64_T::opcode:
            {
                break;
            }

            case I_MUL_R64_R64_T::opcode:
            {
                break;
            }

            case I_DIV_R64_R64_T::opcode:
            {
                break;
            }

            case I_ADD_R64_I64_T::opcode:
            {
                break;
            }

            case I_SUB_R64_I64_T::opcode:
            {
                break;
            }

            case I_MUL_R64_I64_T::opcode:
            {
                break;
            }

            case I_DIV_R64_I64_T::opcode:
            {
                break;
            }

            case I_SAR_R64_R64_T::opcode:
            {
                break;
            }

            case I_SHR_R64_R64_T::opcode:
            {
                break;
            }

            case I_SHL_R64_R64_T::opcode:
            {
                break;
            }

            case I_SAR_R64_I8_T::opcode:
            {
                break;
            }

            case I_SHR_R64_I8_T::opcode:
            {
                break;
            }

            case I_SHL_R64_I8_T::opcode:
            {
                break;
            }

            case I_AND_R64_R64_T::opcode:
            {
                break;
            }

            case I_OR_R64_R64_T::opcode:
            {
                break;
            }

            case I_XOR_R64_R64_T::opcode:
            {
                break;
            }

            case I_NOT_R64_R64_T::opcode:
            {
                break;
            }

            case I_CMP_R64_R64_T::opcode:
            {
                break;
            }

            case I_AND_R64_I64_T::opcode:
            {
                break;
            }

            case I_OR_R64_I64_T::opcode:
            {
                break;
            }

            case I_XOR_R64_I64_T::opcode:
            {
                break;
            }

            case I_NOT_R64_I64_T::opcode:
            {
                break;
            }

            case I_CMP_R64_I64_T::opcode:
            {
                break;
            }

            case I_JE_R64_T::opcode:
            {
                break;
            }

            case I_JG_R64_T::opcode:
            {
                break;
            }

            case I_JGE_R64_T::opcode:
            {
                break;
            }

            case I_JL_R64_T::opcode:
            {
                break;
            }

            case I_JLE_R64_T::opcode:
            {
                break;
            }

            case I_JA_R64_T::opcode:
            {
                break;
            }

            case I_JAE_R64_T::opcode:
            {
                break;
            }

            case I_JB_R64_T::opcode:
            {
                break;
            }

            case I_JBE_R64_T::opcode:
            {
                break;
            }

            case I_CALL_R64_T::opcode:
            {
                break;
            }

            case I_JE_I64_T::opcode:
            {
                break;
            }

            case I_JG_I64_T::opcode:
            {
                break;
            }

            case I_JGE_I64_T::opcode:
            {
                break;
            }

            case I_JL_I64_T::opcode:
            {
                break;
            }

            case I_JLE_I64_T::opcode:
            {
                break;
            }

            case I_JA_I64_T::opcode:
            {
                break;
            }

            case I_JAE_I64_T::opcode:
            {
                break;
            }

            case I_JB_I64_T::opcode:
            {
                break;
            }

            case I_JBE_I64_T::opcode:
            {
                break;
            }

            case I_CALL_I64_T::opcode:
            {
                break;
            }

            case I_RET_T::opcode:
            {
                break;
            }

            case I_PUSH_R64_T::opcode:
            {
                break;
            }

            case I_POP_R64_T::opcode:
            {
                break;
            }

            case I_SYSCALL_T::opcode:
            {
                break;
            }

        };
    }

    uint64_t mRegisters[26]{};
    uint64_t& mAccumulator    = mRegisters['a'-'a'];
    uint64_t& mProgramCounter = mRegisters['p'-'a'];
    uint64_t& mStackPointer   = mRegisters['s'-'a'];
    uint64_t& mFlagRegister   = mRegisters['f'-'a'];

    std::vector<uint8_t>& mByteCode;
};

} // namespace tinymachine

#endif //__TINYMACHINE_MACHINE_HPP__s