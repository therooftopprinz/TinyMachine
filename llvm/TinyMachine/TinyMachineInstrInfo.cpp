#include "TinyMachineInstrInfo.h"

#define GET_INSTRINFO_CTOR_DTOR
#include "TinyMachineGenInstrInfo.inc"

using namespace llvm;

TinyMachineInstrInfo::TinyMachineInstrInfo() : TinyMachineGenInstrInfo() {}
