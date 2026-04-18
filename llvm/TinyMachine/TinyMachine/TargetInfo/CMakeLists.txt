add_llvm_component_library(LLVMTinyMachineInfo
  TinyMachineTargetInfo.cpp

  LINK_COMPONENTS
  MC
  Support

  ADD_TO_COMPONENT
  TinyMachine
  )
