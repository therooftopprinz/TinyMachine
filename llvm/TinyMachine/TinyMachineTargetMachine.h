#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINETARGETMACHINE_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINETARGETMACHINE_H

#include "TinyMachineSubtarget.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/Target/TargetMachine.h"
#include <optional>

namespace llvm {

class FunctionPass;

class TinyMachineTargetMachine : public LLVMTargetMachine {
  TinyMachineSubtarget Subtarget;

public:
  TinyMachineTargetMachine(const Target &T, const Triple &TT, StringRef CPU,
                           StringRef FS, const TargetOptions &Options,
                           std::optional<Reloc::Model> RM,
                           std::optional<CodeModel::Model> CM,
                           CodeGenOptLevel OL, bool JIT);

  const TinyMachineSubtarget *getSubtargetImpl(const Function &) const override {
    return &Subtarget;
  }

  TargetPassConfig *createPassConfig(PassManagerBase &PM) override;
};

class TinyMachinePassConfig : public TargetPassConfig {
public:
  TinyMachinePassConfig(TinyMachineTargetMachine &TM, PassManagerBase &PM)
      : TargetPassConfig(TM, PM) {}

  TinyMachineTargetMachine &getTinyMachineTargetMachine() const {
    return getTM<TinyMachineTargetMachine>();
  }

  bool addInstSelector() override;
};

FunctionPass *createTinyMachineISelDag(TinyMachineTargetMachine &TM,
                                       CodeGenOptLevel OptLevel);

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINETARGETMACHINE_H
