#include "TinyMachineMCTargetDesc.h"
#include "TinyMachine.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"

using namespace llvm;

#define GET_INSTRINFO_MC_DESC
#include "TinyMachineGenInstrInfo.inc"

#define GET_REGINFO_MC_DESC
#include "TinyMachineGenRegisterInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "TinyMachineGenSubtargetInfo.inc"

static MCInstrInfo *createTinyMachineMCInstrInfo() {
  auto *X = new MCInstrInfo();
  InitTinyMachineMCInstrInfo(X);
  return X;
}

static MCRegisterInfo *createTinyMachineMCRegisterInfo(const Triple &TT) {
  (void)TT;
  auto *X = new MCRegisterInfo();
  InitTinyMachineMCRegisterInfo(X, 0);
  return X;
}

static MCSubtargetInfo *createTinyMachineMCSubtargetInfo(const Triple &TT,
                                                         StringRef CPU,
                                                         StringRef FS) {
  if (CPU.empty()) {
    CPU = "generic";
  }
  return createTinyMachineMCSubtargetInfoImpl(TT, CPU, CPU, FS);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineTargetMC() {
  Target &T = getTheTinyMachineTarget();

  TargetRegistry::RegisterMCInstrInfo(T, createTinyMachineMCInstrInfo);
  TargetRegistry::RegisterMCRegInfo(T, createTinyMachineMCRegisterInfo);
  TargetRegistry::RegisterMCSubtargetInfo(T, createTinyMachineMCSubtargetInfo);
  TargetRegistry::RegisterMCAsmInfo(T, createTinyMachineMCAsmInfo);
  TargetRegistry::RegisterMCCodeEmitter(T, createTinyMachineMCCodeEmitter);
}
