#include "TinyMachineInstrInfo.h"
#include "TinyMachineSubtarget.h"

using namespace llvm;

// Instruction enum lives under GET_INSTRINFO_ENUM; needed for ReturnOpcode.
#define GET_INSTRINFO_ENUM
#include "TinyMachineGenInstrInfo.inc"
#undef GET_INSTRINFO_ENUM

#define GET_INSTRINFO_CTOR_DTOR
#include "TinyMachineGenInstrInfo.inc"

TinyMachineInstrInfo::TinyMachineInstrInfo(const TinyMachineSubtarget &STI)
    : TinyMachineGenInstrInfo(STI, RI, /*CFSetupOpcode=*/~0u,
                              /*CFDestroyOpcode=*/~0u,
                              /*CatchRetOpcode=*/~0u,
                              /*ReturnOpcode=*/TinyMachine::RET),
      RI() {}
