#include "TinyMachineISelLowering.h"
#include "TinyMachineSubtarget.h"
#include "TinyMachineTargetMachine.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

#define GET_INSTRINFO_ENUM
#include "TinyMachineGenInstrInfo.inc"
#undef GET_INSTRINFO_ENUM

#define GET_REGINFO_ENUM
#include "TinyMachineGenRegisterInfo.inc"
#undef GET_REGINFO_ENUM

namespace {

unsigned mapCondCodeToBranchOpc(ISD::CondCode CC) {
  switch (CC) {
  case ISD::SETEQ:
  case ISD::SETUEQ:
    return TinyMachine::JE_I64;
  case ISD::SETGT:
    return TinyMachine::JG_I64;
  case ISD::SETGE:
    return TinyMachine::JGE_I64;
  case ISD::SETLT:
    return TinyMachine::JL_I64;
  case ISD::SETLE:
    return TinyMachine::JLE_I64;
  case ISD::SETUGT:
    return TinyMachine::JA_I64;
  case ISD::SETUGE:
    return TinyMachine::JAE_I64;
  case ISD::SETULT:
    return TinyMachine::JB_I64;
  case ISD::SETULE:
    return TinyMachine::JBE_I64;
  default:
    return 0;
  }
}

} // namespace

TinyMachineTargetLowering::TinyMachineTargetLowering(
    const TinyMachineTargetMachine &TM, const TinyMachineSubtarget &STI)
    : TargetLowering(TM, STI) {
  addRegisterClass(MVT::i64, &TinyMachine::GPR64RegClass);
  computeRegisterProperties(STI.getRegisterInfo());

  for (MVT VT : {MVT::i1, MVT::i8, MVT::i16, MVT::i32, MVT::i64})
    setOperationAction(ISD::BR_CC, VT, Custom);

  // VM DIV is unsigned quotient; remainder is side-effected into ‘a’ (see VM).
  // Until custom ISel models that, expand signed div/rem and urem like many
  // small backends do before matching hardware quirks.
  setOperationAction(ISD::SDIV, MVT::i64, Expand);
  setOperationAction(ISD::SREM, MVT::i64, Expand);
  setOperationAction(ISD::UREM, MVT::i64, Expand);
}

const char *TinyMachineTargetLowering::getTargetNodeName(unsigned Opcode) const {
  switch (Opcode) {
  case TinyMachineISD::RET:
    return "TinyMachineISD::RET";
  case TinyMachineISD::CMP:
    return "TinyMachineISD::CMP";
  case TinyMachineISD::BRCOND:
    return "TinyMachineISD::BRCOND";
  default:
    return nullptr;
  }
}

SDValue TinyMachineTargetLowering::LowerOperation(SDValue Op,
                                                 SelectionDAG &DAG) const {
  switch (Op.getOpcode()) {
  case ISD::BR_CC:
    return lowerBR_CC(Op, DAG);
  default:
    return SDValue();
  }
}

SDValue TinyMachineTargetLowering::lowerBR_CC(SDValue Op, SelectionDAG &DAG) {
  SDLoc DL(Op);
  SDValue Chain = Op.getOperand(0);
  ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
  SDValue LHS = Op.getOperand(2);
  SDValue RHS = Op.getOperand(3);
  SDValue Dest = Op.getOperand(4);

  if (CC == ISD::SETNE || CC == ISD::SETUNE)
    report_fatal_error(
        "TinyMachine BR_CC: SETNE needs inverted compare + split edge (TODO)");

  unsigned BrOpc = mapCondCodeToBranchOpc(CC);
  if (!BrOpc)
    report_fatal_error("TinyMachine BR_CC: unsupported cond code");

  auto *DestBBN = dyn_cast<BasicBlockSDNode>(Dest.getNode());
  if (!DestBBN)
    report_fatal_error("TinyMachine BR_CC: expected BasicBlockSDNode dest");
  MachineBasicBlock *DestMBB = DestBBN->getBasicBlock();

  SDValue CmpChain =
      DAG.getNode(TinyMachineISD::CMP, DL, MVT::Other, {Chain, LHS, RHS});
  SDValue Tgt = DAG.getTargetConstant(BrOpc, DL, MVT::i32);
  return DAG.getNode(TinyMachineISD::BRCOND, DL, MVT::Other,
                     {CmpChain, DAG.getBasicBlock(DestMBB), Tgt});
}

SDValue TinyMachineTargetLowering::LowerFormalArguments(
    SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, const SDLoc &DL,
    SelectionDAG &DAG, SmallVectorImpl<SDValue> &InVals) const {
  (void)CallConv;
  (void)IsVarArg;
  (void)DL;
  (void)DAG;
  (void)InVals;

  if (!Ins.empty()) {
    report_fatal_error(
        "TinyMachineTargetLowering: function arguments are not implemented");
  }

  return Chain;
}

SDValue TinyMachineTargetLowering::LowerReturn(
    SDValue Chain, CallingConv::ID CallConv, bool IsVarArg,
    const SmallVectorImpl<ISD::OutputArg> &Outs,
    const SmallVectorImpl<SDValue> &OutVals, const SDLoc &DL,
    SelectionDAG &DAG) const {
  (void)CallConv;
  (void)IsVarArg;

  SDValue Glue;
  if (!Outs.empty()) {
    if (Outs.size() != 1 || OutVals.size() != 1) {
      report_fatal_error(
          "TinyMachineTargetLowering: multiple return values are not implemented");
    }

    Chain = DAG.getCopyToReg(Chain, DL, Register(A), OutVals[0], Glue);
    Glue = Chain.getValue(1);
  }

  SmallVector<SDValue, 2> Ops;
  Ops.push_back(Chain);
  if (Glue.getNode()) {
    Ops.push_back(Glue);
  }
  return DAG.getNode(TinyMachineISD::RET, DL, MVT::Other, Ops);
}
