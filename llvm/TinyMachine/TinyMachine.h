#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINE_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINE_H

#include "llvm/Support/Compiler.h"

namespace llvm {
class Target;

Target &getTheTinyMachineTarget();
} // namespace llvm

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineTargetInfo();
extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineTarget();
extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineTargetMC();
extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineAsmPrinter();

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINE_H
