#include "TinyMachineAsmPrinter.h"
#include "TinyMachine.h"
#include "MCTargetDesc/TinyMachineMCTargetDesc.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

void TinyMachineAsmPrinter::emitInstruction(const MachineInstr *MI) {
  MCInst OutMI;
  OutMI.setOpcode(MI->getOpcode());

  for (const MachineOperand &MO : MI->operands()) {
    switch (MO.getType()) {
    case MachineOperand::MO_Register:
      if (!MO.isImplicit()) {
        OutMI.addOperand(MCOperand::createReg(MO.getReg()));
      }
      break;
    case MachineOperand::MO_Immediate:
      OutMI.addOperand(MCOperand::createImm(MO.getImm()));
      break;
    case MachineOperand::MO_GlobalAddress:
      OutMI.addOperand(MCOperand::createExpr(
          MCSymbolRefExpr::create(getSymbol(MO.getGlobal()), OutContext)));
      break;
    case MachineOperand::MO_MCSymbol:
      OutMI.addOperand(MCOperand::createExpr(
          MCSymbolRefExpr::create(MO.getMCSymbol(), OutContext)));
      break;
    case MachineOperand::MO_MachineBasicBlock:
      OutMI.addOperand(MCOperand::createExpr(
          MCSymbolRefExpr::create(MO.getMBB()->getSymbol(), OutContext)));
      break;
    case MachineOperand::MO_ExternalSymbol: {
      MCSymbol *Sym = GetExternalSymbolSymbol(MO.getSymbolName());
      OutMI.addOperand(
          MCOperand::createExpr(MCSymbolRefExpr::create(Sym, OutContext)));
      break;
    }
    case MachineOperand::MO_RegisterMask:
    case MachineOperand::MO_RegisterLiveOut:
    case MachineOperand::MO_Metadata:
    case MachineOperand::MO_CFIIndex:
    case MachineOperand::MO_IntrinsicID:
    case MachineOperand::MO_Predicate:
    case MachineOperand::MO_ShuffleMask:
      // Non-encodable metadata/control operands are ignored by design.
      break;
    default:
      report_fatal_error("TinyMachineAsmPrinter: unsupported MachineOperand type");
    }
  }

  EmitToStreamer(*OutStreamer, OutMI);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeTinyMachineAsmPrinter() {
  RegisterAsmPrinter<TinyMachineAsmPrinter> X(getTheTinyMachineTarget());
}
