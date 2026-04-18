#include "TinyMachineTargetMachine.h"
#include "TinyMachine.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/PassRegistry.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/TargetParser/Triple.h"

using namespace llvm;

static StringRef computeDataLayout() { return "e-m:e-p:64:64-i64:64-n64-S64"; }

TinyMachineTargetMachine::TinyMachineTargetMachine(
    const Target &T, const Triple &TT, StringRef CPU, StringRef FS,
    const TargetOptions &Options, std::optional<Reloc::Model> RM,
    std::optional<CodeModel::Model> CM, CodeGenOptLevel OL, bool JIT)
    : CodeGenTargetMachineImpl(T, computeDataLayout(), TT, CPU, FS, Options,
                               RM.value_or(Reloc::Static),
                               CM.value_or(CodeModel::Small), OL),
      Subtarget(TT, CPU, FS, *this) {
  initAsmInfo();
}

TargetPassConfig *TinyMachineTargetMachine::createPassConfig(PassManagerBase &PM) {
  return new TinyMachinePassConfig(*this, PM);
}

bool TinyMachinePassConfig::addInstSelector() {
  addPass(createTinyMachineISelDag(getTinyMachineTargetMachine(), getOptLevel()));
  return false;
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineTarget() {
  auto *PR = PassRegistry::getPassRegistry();
  initializeTinyMachineDAGToDAGISelLegacyPass(*PR);
  RegisterTargetMachine<TinyMachineTargetMachine> X(getTheTinyMachineTarget());
}
