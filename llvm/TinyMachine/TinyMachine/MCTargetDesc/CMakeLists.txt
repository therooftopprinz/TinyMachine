add_llvm_component_library(LLVMTinyMachineDesc
  TinyMachineMCTargetDesc.cpp
  TinyMachineMCAsmInfo.cpp
  TinyMachineMCCodeEmitter.cpp

  LINK_COMPONENTS
  TinyMachineInfo
  MC
  Support
  TargetParser

  ADD_TO_COMPONENT
  TinyMachine
  )

add_dependencies(LLVMTinyMachineDesc TinyMachineCommonTableGen)
