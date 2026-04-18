#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEINSTRINFO_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEINSTRINFO_H

#include "TinyMachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

#define GET_INSTRINFO_HEADER
#include "TinyMachineGenInstrInfo.inc"

namespace llvm {

class TinyMachineSubtarget;

class TinyMachineInstrInfo : public TinyMachineGenInstrInfo {
  TinyMachineRegisterInfo RI;

public:
  explicit TinyMachineInstrInfo(const TinyMachineSubtarget &STI);

  const TinyMachineRegisterInfo &getRegisterInfo() const { return RI; }
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEINSTRINFO_H
