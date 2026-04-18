#include "TinyMachineRegisterInfo.h"
#include "llvm/CodeGen/MachineFunction.h"

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
  Reserved.set(TinyMachine::F);
  Reserved.set(TinyMachine::P);
  Reserved.set(TinyMachine::S);
  return Reserved;
}

Register TinyMachineRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  (void)MF;
  return TinyMachine::S;
}
