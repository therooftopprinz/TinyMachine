add_llvm_component_group(TinyMachine)

set(LLVM_TARGET_DEFINITIONS TinyMachine.td)

tablegen(LLVM TinyMachineGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM TinyMachineGenInstrInfo.inc -gen-instr-info)
tablegen(LLVM TinyMachineGenSubtargetInfo.inc -gen-subtarget)
tablegen(LLVM TinyMachineGenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM TinyMachineGenMCCodeEmitter.inc -gen-emitter)
tablegen(LLVM TinyMachineGenDAGISel.inc -gen-dag-isel)
add_public_tablegen_target(TinyMachineCommonTableGen)

add_llvm_target(TinyMachineCodeGen
  TinyMachineAsmPrinter.cpp
  TinyMachineFrameLowering.cpp
  TinyMachineInstrInfo.cpp
  TinyMachineISelDAGToDAG.cpp
  TinyMachineISelLowering.cpp
  TinyMachineMCAsmInfo.cpp
  TinyMachineMCCodeEmitter.cpp
  TinyMachineMCTargetDesc.cpp
  TinyMachineRegisterInfo.cpp
  TinyMachineSubtarget.cpp
  TinyMachineTargetMachine.cpp
  TinyMachineTargetInfo.cpp

  LINK_COMPONENTS
  AsmPrinter
  CodeGen
  Core
  MC
  Support
  Target

  ADD_TO_COMPONENT
  TinyMachine
  )

add_dependencies(LLVMTinyMachineCodeGen TinyMachineCommonTableGen)
