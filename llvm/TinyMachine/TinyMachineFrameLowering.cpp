#include "TinyMachineFrameLowering.h"

using namespace llvm;

TinyMachineFrameLowering::TinyMachineFrameLowering(const TinyMachineSubtarget &STI)
    : TargetFrameLowering(StackGrowsDown, Align(8), 0, Align(8)) {}

void TinyMachineFrameLowering::emitPrologue(MachineFunction &MF,
                                            MachineBasicBlock &MBB) const {}

void TinyMachineFrameLowering::emitEpilogue(MachineFunction &MF,
                                            MachineBasicBlock &MBB) const {}

bool TinyMachineFrameLowering::hasFP(const MachineFunction &MF) const {
  return false;
}
