// Instruction selection follows the same split as RISC-V / AArch64: TableGen
// Pat<> for straight-line i64 ops (TinyMachineInstrInfo.td), manual Select() for
// constants and ABI glue; for compare/branch and memory, borrow ideas from X86
// (CMP + flag consumer) and generic FrameIndex lowering.

#include "TinyMachine.h"
#include "TinyMachineISelDAGToDAG.h"
#include "TinyMachineISelLowering.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/InitializePasses.h"

using namespace llvm;

#define DEBUG_TYPE "tinymachine-isel"
#define PASS_NAME "TinyMachine DAG->DAG Pattern Instruction Selection"

#define GET_INSTRINFO_ENUM
#include "TinyMachineGenInstrInfo.inc"
#undef GET_INSTRINFO_ENUM

#define GET_DAGISEL_BODY TinyMachineDAGToDAGISel
#include "TinyMachineGenDAGISel.inc"

void TinyMachineDAGToDAGISel::Select(SDNode *Node) {
  SDLoc DL(Node);

  if (Node->isMachineOpcode()) {
    Node->setNodeId(-1);
    return;
  }

  switch (Node->getOpcode()) {
  case ISD::Constant: {
    EVT VT = Node->getValueType(0);
    if (!VT.isInteger() || VT.getSizeInBits() > 64) {
      break;
    }

    auto *CN = cast<ConstantSDNode>(Node);
    const APInt &C = CN->getAPIntValue();
    unsigned Opcode = TinyMachine::MOVri64;
    if (C.isSignedIntN(8))
      Opcode = TinyMachine::MOVri8;
    else if (C.isSignedIntN(16))
      Opcode = TinyMachine::MOVri16;
    else if (C.isSignedIntN(32))
      Opcode = TinyMachine::MOVri32;

    uint64_t Value = C.getZExtValue();
    SDValue Imm = CurDAG->getTargetConstant(Value, DL, MVT::i64);
    ReplaceNode(Node, CurDAG->getMachineNode(Opcode, DL, MVT::i64, Imm));
    return;
  }
  case TinyMachineISD::RET: {
    SDValue Chain = Node->getOperand(0);
    if (Node->getNumOperands() == 2) {
      SDValue Glue = Node->getOperand(1);
      ReplaceNode(Node, CurDAG->getMachineNode(TinyMachine::RET, DL, MVT::Other,
                                               MVT::Glue, Chain, Glue));
    } else {
      ReplaceNode(Node,
                  CurDAG->getMachineNode(TinyMachine::RET, DL, MVT::Other, Chain));
    }
    return;
  }
  case TinyMachineISD::CMP: {
    SDValue Chain = Node->getOperand(0);
    SDValue LHS = Node->getOperand(1);
    SDValue RHS = Node->getOperand(2);
    if (RHS.getOpcode() == ISD::Constant) {
      auto *CN = cast<ConstantSDNode>(RHS);
      SDValue TImm =
          CurDAG->getTargetConstant(CN->getZExtValue(), DL, MVT::i64);
      ReplaceNode(Node, CurDAG->getMachineNode(TinyMachine::CMPri, DL, MVT::Other,
                                               {Chain, LHS, TImm}));
      return;
    }
    ReplaceNode(Node, CurDAG->getMachineNode(TinyMachine::CMPrr, DL, MVT::Other,
                                             {Chain, LHS, RHS}));
    return;
  }
  case TinyMachineISD::BRCOND: {
    SDValue Chain = Node->getOperand(0);
    SDValue BrTgt = Node->getOperand(1);
    unsigned Opc = cast<ConstantSDNode>(Node->getOperand(2))->getZExtValue();
    ReplaceNode(Node, CurDAG->getMachineNode(Opc, DL, MVT::Other, {Chain, BrTgt}));
    return;
  }
  default:
    break;
  }

  SelectCode(Node);
}

char TinyMachineDAGToDAGISelLegacy::ID = 0;

TinyMachineDAGToDAGISelLegacy::TinyMachineDAGToDAGISelLegacy(
    TinyMachineTargetMachine &TM, CodeGenOptLevel OptLevel)
    : SelectionDAGISelLegacy(
          ID, std::make_unique<TinyMachineDAGToDAGISel>(TM, OptLevel)) {}

FunctionPass *llvm::createTinyMachineISelDag(TinyMachineTargetMachine &TM,
                                              CodeGenOptLevel OptLevel) {
  return new TinyMachineDAGToDAGISelLegacy(TM, OptLevel);
}

INITIALIZE_PASS(TinyMachineDAGToDAGISelLegacy, DEBUG_TYPE, PASS_NAME, false,
                false)
