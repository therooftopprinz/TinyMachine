include "llvm/Target/Target.td"

def TinyMachineInstrInfo : InstrInfo;

def TinyMachine : Target {
  let InstructionSet = TinyMachineInstrInfo;
}

def TinyMachineModel : SchedMachineModel;
def TinyMachineGenericProc : ProcessorModel<"generic", TinyMachineModel, []>;

include "TinyMachineRegisterInfo.td"
include "TinyMachineInstrInfo.td"
