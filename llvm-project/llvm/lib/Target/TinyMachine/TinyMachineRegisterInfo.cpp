#include "TinyMachineRegisterInfo.h"
#include "TinyMachineFrameLowering.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/Support/ErrorHandling.h"

#define GET_REGINFO_ENUM
#include "TinyMachineGenRegisterInfo.inc"

#define GET_REGINFO_TARGET_DESC
#include "TinyMachineGenRegisterInfo.inc"

using namespace llvm;

TinyMachineRegisterInfo::TinyMachineRegisterInfo() : TinyMachineGenRegisterInfo(0) {}

const MCPhysReg *
TinyMachineRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
  (void)MF;
  static const MCPhysReg CalleeSavedRegs[] = {0};
  return CalleeSavedRegs;
}

BitVector TinyMachineRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
  (void)MF;
  BitVector Reserved(getNumRegs());
  // VirtualMachine aliases (src/TinyMachine.hpp): f=flags, p=PC, s=stack.
  Reserved.set(F);
  Reserved.set(P);
  Reserved.set(S);
  return Reserved;
}

Register TinyMachineRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  (void)MF;
  return S;
}

bool TinyMachineRegisterInfo::eliminateFrameIndex(
    MachineBasicBlock::iterator II, int SPAdj, unsigned FIOperandNum,
    RegScavenger *RS) const {
  (void)RS;
  assert(SPAdj == 0 && "TinyMachine eliminateFrameIndex: non-zero SPAdj");

  MachineInstr &MI = *II;
  MachineFunction &MF = *MI.getParent()->getParent();

  if (MI.isDebugValue()) {
    Register FrameReg = getFrameRegister(MF);
    int FI = MI.getOperand(FIOperandNum).getIndex();
    MI.getOperand(FIOperandNum).ChangeToRegister(FrameReg, false);
    MI.getOperand(FIOperandNum + 1).ChangeToImmediate(
        MF.getFrameInfo().getObjectOffset(FI));
    return false;
  }

  report_fatal_error("TinyMachine: frame index elimination not implemented for "
                     "this instruction");
}
