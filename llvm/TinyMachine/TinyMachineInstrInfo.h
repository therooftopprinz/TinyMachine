#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEINSTRINFO_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEINSTRINFO_H

#include "TinyMachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"

#define GET_INSTRINFO_HEADER
#include "TinyMachineGenInstrInfo.inc"

namespace llvm {

class TinyMachineInstrInfo : public TinyMachineGenInstrInfo {
  TinyMachineRegisterInfo RI;

public:
  TinyMachineInstrInfo();

  const TinyMachineRegisterInfo &getRegisterInfo() const { return RI; }
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEINSTRINFO_H
