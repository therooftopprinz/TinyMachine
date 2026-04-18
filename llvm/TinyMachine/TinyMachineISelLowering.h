#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEISELLOWERING_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEISELLOWERING_H

#include "llvm/CodeGen/TargetLowering.h"

namespace llvm {

class TinyMachineSubtarget;
class TinyMachineTargetMachine;

namespace TinyMachineISD {
enum NodeType : unsigned {
  FIRST_NUMBER = ISD::BUILTIN_OP_END,
  RET,
  /// Chain, LHS, RHS — selected to CMPrr/CMPri; defines implicit flags reg F.
  CMP,
  /// Chain, MBB, target constant holding a TinyMachine::* branch opcode.
  BRCOND,
};
} // namespace TinyMachineISD

class TinyMachineTargetLowering : public TargetLowering {
public:
  explicit TinyMachineTargetLowering(const TinyMachineTargetMachine &TM,
                                     const TinyMachineSubtarget &STI);

  const char *getTargetNodeName(unsigned Opcode) const override;

  SDValue LowerOperation(SDValue Op, SelectionDAG &DAG) const override;

  SDValue LowerFormalArguments(SDValue Chain, CallingConv::ID CallConv,
                               bool IsVarArg,
                               const SmallVectorImpl<ISD::InputArg> &Ins,
                               const SDLoc &DL, SelectionDAG &DAG,
                               SmallVectorImpl<SDValue> &InVals) const override;

  SDValue LowerReturn(SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
                      const SmallVectorImpl<ISD::OutputArg> &Outs,
                      const SmallVectorImpl<SDValue> &OutVals, const SDLoc &DL,
                      SelectionDAG &DAG) const override;

private:
  static SDValue lowerBR_CC(SDValue Op, SelectionDAG &DAG);
};

} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEISELLOWERING_H
