#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEASMPRINTER_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEASMPRINTER_H

#include "llvm/CodeGen/AsmPrinter.h"
#include "llvm/MC/MCStreamer.h"

namespace llvm {

class TinyMachineAsmPrinter : public AsmPrinter {
public:
  explicit TinyMachineAsmPrinter(TargetMachine &TM,
                                 std::unique_ptr<MCStreamer> Streamer)
      : AsmPrinter(TM, std::move(Streamer)) {}

  StringRef getPassName() const override { return "TinyMachine Assembly Printer"; }
  void emitInstruction(const MachineInstr *MI) override;
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEASMPRINTER_H
