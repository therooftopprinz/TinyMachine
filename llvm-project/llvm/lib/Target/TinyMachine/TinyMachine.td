include "llvm/Target/Target.td"

def TinyMachineInstrInfo : InstrInfo;

def TinyMachine : Target {
  let InstructionSet = TinyMachineInstrInfo;
}

// Incomplete scheduling is normal during target bring-up; TableGen rejects a
// "complete" model until every opcode (including COPY, etc.) has Sched data.
def TinyMachineModel : SchedMachineModel {
  let CompleteModel = 0;
}
def TinyMachineGenericProc : ProcessorModel<"generic", TinyMachineModel, []>;

include "TinyMachineRegisterInfo.td"

// Map target-independent pseudos that use ptr_rc (e.g. LOAD_STACK_GUARD) to R64.
defm : RemapAllTargetPseudoPointerOperands<GPR64>;

include "TinyMachineInstrInfo.td"
