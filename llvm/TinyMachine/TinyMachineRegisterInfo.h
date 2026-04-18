#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEREGISTERINFO_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEREGISTERINFO_H

#include "llvm/CodeGen/TargetRegisterInfo.h"

#define GET_REGINFO_HEADER
#include "TinyMachineGenRegisterInfo.inc"

namespace llvm {

class TinyMachineRegisterInfo : public TinyMachineGenRegisterInfo {
public:
  TinyMachineRegisterInfo();

  const MCPhysReg *getCalleeSavedRegs(const MachineFunction *MF) const override;
  BitVector getReservedRegs(const MachineFunction &MF) const override;
  Register getFrameRegister(const MachineFunction &MF) const override;
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEREGISTERINFO_H
