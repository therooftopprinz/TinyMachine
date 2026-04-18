#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEFRAMELOWERING_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEFRAMELOWERING_H

#include "llvm/CodeGen/TargetFrameLowering.h"

namespace llvm {

class TinyMachineSubtarget;
class MachineFunction;
class MachineBasicBlock;

class TinyMachineFrameLowering : public TargetFrameLowering {
public:
  explicit TinyMachineFrameLowering(const TinyMachineSubtarget &STI);

  void emitPrologue(MachineFunction &MF, MachineBasicBlock &MBB) const override;
  void emitEpilogue(MachineFunction &MF, MachineBasicBlock &MBB) const override;
  bool hasFP(const MachineFunction &MF) const override;
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEFRAMELOWERING_H
