#include "TinyMachineMCTargetDesc.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/MC/MCInst.h"
#include "llvm/Support/EndianStream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

class TinyMachineMCCodeEmitter : public MCCodeEmitter {
public:
  TinyMachineMCCodeEmitter() = default;
  ~TinyMachineMCCodeEmitter() override = default;

private:
  static uint8_t encodeReg(const MCOperand &Op) {
    if (!Op.isReg()) {
      report_fatal_error("TinyMachineMCCodeEmitter: expected register operand");
    }

    switch (Op.getReg()) {
    case A:
      return 0;
    case B:
      return 1;
    case C:
      return 2;
    case D:
      return 3;
    case E:
      return 4;
    case F:
      return 5;
    case G:
      return 6;
    case H:
      return 7;
    case I:
      return 8;
    case J:
      return 9;
    case K:
      return 10;
    case L:
      return 11;
    case M:
      return 12;
    case N:
      return 13;
    case O:
      return 14;
    case P:
      return 15;
    case Q:
      return 16;
    case R:
      return 17;
    case S:
      return 18;
    case T:
      return 19;
    case U:
      return 20;
    case V:
      return 21;
    case W:
      return 22;
    case X:
      return 23;
    case Y:
      return 24;
    case Z:
      return 25;
    default:
      report_fatal_error("TinyMachineMCCodeEmitter: unknown physical register");
    }
  }

  static uint64_t getImm64(const MCOperand &Op) {
    if (!Op.isImm()) {
      report_fatal_error("TinyMachineMCCodeEmitter: expected immediate operand");
    }
    return static_cast<uint64_t>(Op.getImm());
  }

  static void encodeImm8(raw_ostream &OS, uint64_t Imm) {
    support::endian::write<uint8_t>(OS, static_cast<uint8_t>(Imm),
                                    llvm::endianness::little);
  }

  static void encodeImm16(raw_ostream &OS, uint64_t Imm) {
    support::endian::write<uint16_t>(OS, static_cast<uint16_t>(Imm),
                                     llvm::endianness::little);
  }

  static void encodeImm32(raw_ostream &OS, uint64_t Imm) {
    support::endian::write<uint32_t>(OS, static_cast<uint32_t>(Imm),
                                     llvm::endianness::little);
  }

  static void encodeImm64(raw_ostream &OS, uint64_t Imm) {
    support::endian::write<uint64_t>(OS, Imm, llvm::endianness::little);
  }

  static void expectNumOperands(const MCInst &MI, unsigned N) {
    if (MI.getNumOperands() != N) {
      report_fatal_error("TinyMachineMCCodeEmitter: unexpected operand count");
    }
  }

  static void emitRR(raw_ostream &OS, const MCInst &MI) {
    expectNumOperands(MI, 2);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
    encodeImm8(OS, encodeReg(MI.getOperand(1)));
  }

  static void emitRImm8(raw_ostream &OS, const MCInst &MI) {
    expectNumOperands(MI, 2);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
    encodeImm8(OS, getImm64(MI.getOperand(1)));
  }

  static void emitRImm16(raw_ostream &OS, const MCInst &MI) {
    expectNumOperands(MI, 2);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
    encodeImm16(OS, getImm64(MI.getOperand(1)));
  }

  static void emitRImm32(raw_ostream &OS, const MCInst &MI) {
    expectNumOperands(MI, 2);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
    encodeImm32(OS, getImm64(MI.getOperand(1)));
  }

  static void emitRImm64(raw_ostream &OS, const MCInst &MI) {
    expectNumOperands(MI, 2);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
    encodeImm64(OS, getImm64(MI.getOperand(1)));
  }

  /// reg, imm64 or reg, expr — fixup at offset \p ImmOffset from insn start.
  static void emitRImm64OrFixup(raw_ostream &OS, const MCInst &MI,
                                SmallVectorImpl<MCFixup> &Fixups,
                                uint64_t ImmOffset) {
    expectNumOperands(MI, 2);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
    const MCOperand &ImmOp = MI.getOperand(1);
    if (ImmOp.isExpr()) {
      Fixups.push_back(MCFixup::create(ImmOffset, ImmOp.getExpr(), FK_Data_8));
      encodeImm64(OS, 0);
      return;
    }
    encodeImm64(OS, getImm64(ImmOp));
  }

  static void emitImm64R(raw_ostream &OS, const MCInst &MI,
                         SmallVectorImpl<MCFixup> &Fixups, uint64_t ImmOffset) {
    expectNumOperands(MI, 2);
    const MCOperand &AddrOp = MI.getOperand(0);
    if (AddrOp.isExpr()) {
      Fixups.push_back(MCFixup::create(ImmOffset, AddrOp.getExpr(), FK_Data_8));
      encodeImm64(OS, 0);
    } else {
      encodeImm64(OS, getImm64(AddrOp));
    }
    encodeImm8(OS, encodeReg(MI.getOperand(1)));
  }

  static void emitImm64OrFixup(raw_ostream &OS, const MCOperand &Op,
                                 SmallVectorImpl<MCFixup> &Fixups,
                                 uint64_t ImmOffset) {
    if (Op.isExpr()) {
      Fixups.push_back(MCFixup::create(ImmOffset, Op.getExpr(), FK_Data_8));
      encodeImm64(OS, 0);
      return;
    }
    encodeImm64(OS, getImm64(Op));
  }

  static void emitR(raw_ostream &OS, const MCInst &MI) {
    expectNumOperands(MI, 1);
    encodeImm8(OS, encodeReg(MI.getOperand(0)));
  }

public:
  void encodeInstruction(const MCInst &MI, SmallVectorImpl<char> &CB,
                         SmallVectorImpl<MCFixup> &Fixups,
                         const MCSubtargetInfo &STI) const override {
    raw_svector_ostream OS(CB);
    (void)STI;

    // Architectural opcode byte matches TableGen `Opcode` field / VM
    // `Instruction<OpCode,...>`. Do not use MI.getOpcode() as the byte.
    switch (MI.getOpcode()) {
    case TinyMachine::MOVrr:
      encodeImm8(OS, 0x01);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVri8:
      encodeImm8(OS, 0x02);
      emitRImm8(OS, MI);
      return;
    case TinyMachine::MOVri16:
      encodeImm8(OS, 0x03);
      emitRImm16(OS, MI);
      return;
    case TinyMachine::MOVri32:
      encodeImm8(OS, 0x04);
      emitRImm32(OS, MI);
      return;
    case TinyMachine::MOVri64:
      encodeImm8(OS, 0x05);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVZX_R64_BPR64:
      encodeImm8(OS, 0x06);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVZX_R64_WPR64:
      encodeImm8(OS, 0x07);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVZX_R64_DPR64:
      encodeImm8(OS, 0x08);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVZX_R64_QPR64:
      encodeImm8(OS, 0x09);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVSX_R64_BPR64:
      encodeImm8(OS, 0x0A);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVSX_R64_WPR64:
      encodeImm8(OS, 0x0B);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVSX_R64_DPR64:
      encodeImm8(OS, 0x0C);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOVSX_R64_QPR64:
      encodeImm8(OS, 0x0D);
      emitRR(OS, MI);
      return;

    case TinyMachine::MOVZX_R64_BPI64:
      encodeImm8(OS, 0x0E);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVZX_R64_WPI64:
      encodeImm8(OS, 0x0F);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVZX_R64_DPI64:
      encodeImm8(OS, 0x10);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVZX_R64_QPI64:
      encodeImm8(OS, 0x11);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVSX_R64_BPI64:
      encodeImm8(OS, 0x12);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVSX_R64_WPI64:
      encodeImm8(OS, 0x13);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVSX_R64_DPI64:
      encodeImm8(OS, 0x14);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;
    case TinyMachine::MOVSX_R64_QPI64:
      encodeImm8(OS, 0x15);
      emitRImm64OrFixup(OS, MI, Fixups, 2);
      return;

    case TinyMachine::MOV_BPR64_R64:
      encodeImm8(OS, 0x16);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOV_WPR64_R64:
      encodeImm8(OS, 0x17);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOV_DPR64_R64:
      encodeImm8(OS, 0x18);
      emitRR(OS, MI);
      return;
    case TinyMachine::MOV_QPR64_R64:
      encodeImm8(OS, 0x19);
      emitRR(OS, MI);
      return;

    case TinyMachine::MOV_BPI64_R64:
      encodeImm8(OS, 0x1A);
      emitImm64R(OS, MI, Fixups, 1);
      return;
    case TinyMachine::MOV_WPI64_R64:
      encodeImm8(OS, 0x1B);
      emitImm64R(OS, MI, Fixups, 1);
      return;
    case TinyMachine::MOV_DPI64_R64:
      encodeImm8(OS, 0x1C);
      emitImm64R(OS, MI, Fixups, 1);
      return;
    case TinyMachine::MOV_QPI64_R64:
      encodeImm8(OS, 0x1D);
      emitImm64R(OS, MI, Fixups, 1);
      return;

    case TinyMachine::ADDrr:
      encodeImm8(OS, 0x1E);
      emitRR(OS, MI);
      return;
    case TinyMachine::SUBrr:
      encodeImm8(OS, 0x1F);
      emitRR(OS, MI);
      return;
    case TinyMachine::MULrr:
      encodeImm8(OS, 0x20);
      emitRR(OS, MI);
      return;
    case TinyMachine::DIVrr:
      encodeImm8(OS, 0x21);
      emitRR(OS, MI);
      return;

    case TinyMachine::ADDri:
      encodeImm8(OS, 0x22);
      emitRImm64(OS, MI);
      return;
    case TinyMachine::SUBri:
      encodeImm8(OS, 0x23);
      emitRImm64(OS, MI);
      return;
    case TinyMachine::MULri:
      encodeImm8(OS, 0x24);
      emitRImm64(OS, MI);
      return;
    case TinyMachine::DIVri:
      encodeImm8(OS, 0x25);
      emitRImm64(OS, MI);
      return;

    case TinyMachine::SARrr:
      encodeImm8(OS, 0x26);
      emitRR(OS, MI);
      return;
    case TinyMachine::SHRrr:
      encodeImm8(OS, 0x27);
      emitRR(OS, MI);
      return;
    case TinyMachine::SHLrr:
      encodeImm8(OS, 0x28);
      emitRR(OS, MI);
      return;

    case TinyMachine::SARri8:
      encodeImm8(OS, 0x29);
      emitRImm8(OS, MI);
      return;
    case TinyMachine::SHRri8:
      encodeImm8(OS, 0x2A);
      emitRImm8(OS, MI);
      return;
    case TinyMachine::SHLri8:
      encodeImm8(OS, 0x2B);
      emitRImm8(OS, MI);
      return;

    case TinyMachine::ANDrr:
      encodeImm8(OS, 0x2C);
      emitRR(OS, MI);
      return;
    case TinyMachine::ORrr:
      encodeImm8(OS, 0x2E);
      emitRR(OS, MI);
      return;
    case TinyMachine::XORrr:
      encodeImm8(OS, 0x2F);
      emitRR(OS, MI);
      return;

    case TinyMachine::NOT_R64:
      encodeImm8(OS, 0x30);
      // Tied operands may appear as one or two MC register operands.
      if (MI.getNumOperands() == 1) {
        emitR(OS, MI);
      } else if (MI.getNumOperands() == 2) {
        encodeImm8(OS, encodeReg(MI.getOperand(0)));
      } else {
        report_fatal_error("TinyMachineMCCodeEmitter: NOT_R64 operand count");
      }
      return;

    case TinyMachine::CMPrr:
      encodeImm8(OS, 0x31);
      emitRR(OS, MI);
      return;

    case TinyMachine::ANDri:
      encodeImm8(OS, 0x32);
      emitRImm64(OS, MI);
      return;
    case TinyMachine::ORri:
      encodeImm8(OS, 0x33);
      emitRImm64(OS, MI);
      return;
    case TinyMachine::XORri:
      encodeImm8(OS, 0x34);
      emitRImm64(OS, MI);
      return;

    case TinyMachine::NOP:
      encodeImm8(OS, 0x35);
      expectNumOperands(MI, 0);
      return;

    case TinyMachine::CMPri:
      encodeImm8(OS, 0x36);
      emitRImm64(OS, MI);
      return;

    case TinyMachine::JE_R64:
      encodeImm8(OS, 0x37);
      emitR(OS, MI);
      return;
    case TinyMachine::JG_R64:
      encodeImm8(OS, 0x38);
      emitR(OS, MI);
      return;
    case TinyMachine::JGE_R64:
      encodeImm8(OS, 0x39);
      emitR(OS, MI);
      return;
    case TinyMachine::JL_R64:
      encodeImm8(OS, 0x3A);
      emitR(OS, MI);
      return;
    case TinyMachine::JLE_R64:
      encodeImm8(OS, 0x3B);
      emitR(OS, MI);
      return;
    case TinyMachine::JA_R64:
      encodeImm8(OS, 0x3C);
      emitR(OS, MI);
      return;
    case TinyMachine::JAE_R64:
      encodeImm8(OS, 0x3E);
      emitR(OS, MI);
      return;
    case TinyMachine::JB_R64:
      encodeImm8(OS, 0x3F);
      emitR(OS, MI);
      return;
    case TinyMachine::JBE_R64:
      encodeImm8(OS, 0x40);
      emitR(OS, MI);
      return;

    case TinyMachine::CALL_R64:
      encodeImm8(OS, 0x41);
      emitR(OS, MI);
      return;
    case TinyMachine::JMP_R64:
      encodeImm8(OS, 0x42);
      emitR(OS, MI);
      return;

    case TinyMachine::JE_I64:
      encodeImm8(OS, 0x43);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JG_I64:
      encodeImm8(OS, 0x44);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JGE_I64:
      encodeImm8(OS, 0x45);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JL_I64:
      encodeImm8(OS, 0x46);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JLE_I64:
      encodeImm8(OS, 0x47);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JA_I64:
      encodeImm8(OS, 0x48);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JAE_I64:
      encodeImm8(OS, 0x49);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JB_I64:
      encodeImm8(OS, 0x4A);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JBE_I64:
      encodeImm8(OS, 0x4B);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;

    case TinyMachine::CALLi64:
      encodeImm8(OS, 0x4C);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;
    case TinyMachine::JMPi64:
      encodeImm8(OS, 0x4D);
      expectNumOperands(MI, 1);
      emitImm64OrFixup(OS, MI.getOperand(0), Fixups, 1);
      return;

    case TinyMachine::RET:
      encodeImm8(OS, 0x4E);
      expectNumOperands(MI, 0);
      return;
    case TinyMachine::PUSH_R64:
      encodeImm8(OS, 0x4F);
      emitR(OS, MI);
      return;
    case TinyMachine::POP_R64:
      encodeImm8(OS, 0x50);
      emitR(OS, MI);
      return;
    case TinyMachine::SYSCALL:
      encodeImm8(OS, 0x51);
      expectNumOperands(MI, 0);
      return;

    default:
      report_fatal_error("TinyMachineMCCodeEmitter: unsupported opcode");
    }
  }
};

} // namespace

MCCodeEmitter *llvm::createTinyMachineMCCodeEmitter(const MCInstrInfo &MCII,
                                                    MCContext &Ctx) {
  (void)MCII;
  (void)Ctx;
  return new TinyMachineMCCodeEmitter();
}
