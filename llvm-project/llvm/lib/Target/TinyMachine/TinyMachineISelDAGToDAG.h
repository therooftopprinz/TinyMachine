#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEISELDAGTODAG_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEISELDAGTODAG_H

#include "TinyMachineTargetMachine.h"
#include "llvm/CodeGen/SelectionDAGISel.h"

namespace llvm {

class TinyMachineDAGToDAGISel : public SelectionDAGISel {
  const TinyMachineSubtarget *Subtarget = nullptr;

public:
  explicit TinyMachineDAGToDAGISel(TinyMachineTargetMachine &TM,
                                    CodeGenOptLevel OptLevel)
      : SelectionDAGISel(TM, OptLevel) {}

  void Select(SDNode *Node) override;

  bool runOnMachineFunction(MachineFunction &MF) override {
    Subtarget = &MF.getSubtarget<TinyMachineSubtarget>();
    return SelectionDAGISel::runOnMachineFunction(MF);
  }

// TableGen selector helpers / matcher (SelectCode, etc.).
#define GET_DAGISEL_DECL
#include "TinyMachineGenDAGISel.inc"
};

class TinyMachineDAGToDAGISelLegacy : public SelectionDAGISelLegacy {
public:
  static char ID;
  explicit TinyMachineDAGToDAGISelLegacy(TinyMachineTargetMachine &TM,
                                         CodeGenOptLevel OptLevel);
};

} // namespace llvm

#endif
