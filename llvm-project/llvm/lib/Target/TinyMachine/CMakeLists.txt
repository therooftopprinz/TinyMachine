add_llvm_component_group(TinyMachine)

set(LLVM_TARGET_DEFINITIONS TinyMachine.td)

tablegen(LLVM TinyMachineGenRegisterInfo.inc -gen-register-info)
tablegen(LLVM TinyMachineGenInstrInfo.inc -gen-instr-info)
tablegen(LLVM TinyMachineGenSubtargetInfo.inc -gen-subtarget)
tablegen(LLVM TinyMachineGenAsmWriter.inc -gen-asm-writer)
tablegen(LLVM TinyMachineGenMCCodeEmitter.inc -gen-emitter)
tablegen(LLVM TinyMachineGenDAGISel.inc -gen-dag-isel)
add_public_tablegen_target(TinyMachineCommonTableGen)

# TableGen emits `const MCPhysReg GPR64[]` in an anonymous namespace and also
# `enum RegisterPressureSets { GPR64 = 0, ... }` in namespace llvm. The
# MCRegisterClasses initializer then resolves `GPR64` to the enumerator.
set(_tm_mcdesc "${CMAKE_CURRENT_BINARY_DIR}/TinyMachineGenRegisterInfoMCDesc.inc")
add_custom_command(
  TARGET TinyMachineCommonTableGen POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E echo "Patching TinyMachineGenRegisterInfoMCDesc.inc (GPR64 / RegisterPressureSets clash)"
  COMMAND sed -i "s/const MCPhysReg GPR64\\[\\]/const MCPhysReg GPR64RegList[]/" "${_tm_mcdesc}"
  COMMAND sed -i "s/{ GPR64, GPR64Bits/{ GPR64RegList, GPR64Bits/" "${_tm_mcdesc}"
  VERBATIM)

# Match other LLVM targets: Info/Desc live in subdirs so llvm-ar's
# AllTargetsInfos / AllTargetsDescs link LLVMTinyMachineInfo / LLVMTinyMachineDesc.
include_directories(BEFORE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(TargetInfo)
add_subdirectory(MCTargetDesc)

add_llvm_target(TinyMachineCodeGen
  TinyMachineAsmPrinter.cpp
  TinyMachineFrameLowering.cpp
  TinyMachineInstrInfo.cpp
  TinyMachineISelDAGToDAG.cpp
  TinyMachineISelLowering.cpp
  TinyMachineRegisterInfo.cpp
  TinyMachineSubtarget.cpp
  TinyMachineTargetMachine.cpp

  LINK_COMPONENTS
  AsmPrinter
  CodeGen
  Core
  MC
  Support
  Target
  TinyMachineDesc
  TinyMachineInfo

  ADD_TO_COMPONENT
  TinyMachine
  )

add_dependencies(LLVMTinyMachineCodeGen TinyMachineCommonTableGen)
