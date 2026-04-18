#include "TinyMachineSubtarget.h"
#include "TinyMachineTargetMachine.h"
#include "llvm/IR/Function.h"

#define DEBUG_TYPE "tinymachine-subtarget"

#define GET_SUBTARGETINFO_TARGET_DESC
#define GET_SUBTARGETINFO_CTOR
#include "TinyMachineGenSubtargetInfo.inc"

using namespace llvm;

TinyMachineSubtarget::TinyMachineSubtarget(const Triple &TT, StringRef CPU,
                                           StringRef FS,
                                           const TinyMachineTargetMachine &TM)
    : TinyMachineGenSubtargetInfo(TT, CPU, /*TuneCPU=*/CPU, FS),
      InstrInfo(*this), FrameLowering(*this), TLInfo(TM, *this) {
  ParseSubtargetFeatures(CPU, /*TuneCPU=*/CPU, FS);
}
