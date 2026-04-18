#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINESUBTARGET_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINESUBTARGET_H

#include "TinyMachineFrameLowering.h"
#include "TinyMachineInstrInfo.h"
#include "TinyMachineISelLowering.h"
#include "llvm/CodeGen/SelectionDAGTargetInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"

#define GET_SUBTARGETINFO_HEADER
#include "TinyMachineGenSubtargetInfo.inc"

namespace llvm {

class StringRef;
class Triple;
class TinyMachineTargetMachine;

class TinyMachineSubtarget : public TinyMachineGenSubtargetInfo {
  TinyMachineInstrInfo InstrInfo;
  TinyMachineFrameLowering FrameLowering;
  TinyMachineTargetLowering TLInfo;
  SelectionDAGTargetInfo TSInfo;

public:
  TinyMachineSubtarget(const Triple &TT, StringRef CPU, StringRef FS,
                       const TinyMachineTargetMachine &TM);

  void ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS);

  const TinyMachineInstrInfo *getInstrInfo() const override { return &InstrInfo; }
  const TinyMachineFrameLowering *getFrameLowering() const override {
    return &FrameLowering;
  }
  const TinyMachineRegisterInfo *getRegisterInfo() const override {
    return &InstrInfo.getRegisterInfo();
  }
  const TinyMachineTargetLowering *getTargetLowering() const override {
    return &TLInfo;
  }
  const SelectionDAGTargetInfo *getSelectionDAGInfo() const override {
    return &TSInfo;
  }
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINESUBTARGET_H
