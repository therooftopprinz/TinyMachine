#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "TinyMachine.h"

using namespace llvm;

Target &llvm::getTheTinyMachineTarget() {
  static Target TheTinyMachineTarget;
  return TheTinyMachineTarget;
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineTargetInfo() {
  RegisterTarget<Triple::UnknownArch, false> X(
      getTheTinyMachineTarget(), "tinymachine", "TinyMachine", "TinyMachine");
}
