#ifndef LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEMCTARGETDESC_H
#define LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEMCTARGETDESC_H

#include "llvm/Support/DataTypes.h"

namespace llvm {
class MCAsmInfo;
class MCCodeEmitter;
class MCContext;
class MCInstrInfo;
class MCTargetOptions;
class MCObjectTargetWriter;
class MCRegisterInfo;
class MCSubtargetInfo;
class StringRef;
class Target;
class Triple;

MCCodeEmitter *createTinyMachineMCCodeEmitter(const MCInstrInfo &MCII,
                                              MCContext &Ctx);
MCAsmInfo *createTinyMachineMCAsmInfo(const MCRegisterInfo &MRI,
                                      const Triple &TT,
                                      const MCTargetOptions &Options);
} // namespace llvm

// Pull in the generated enum definitions (registers, instructions, subtarget).
#define GET_REGINFO_ENUM
#include "TinyMachineGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "TinyMachineGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "TinyMachineGenSubtargetInfo.inc"

namespace llvm {
namespace TinyMachine {
constexpr unsigned GPR64RegClassID = llvm::GPR64RegClassID;
} // namespace TinyMachine
} // namespace llvm

#endif // LLVM_LIB_TARGET_TINYMACHINE_TINYMACHINEMCTARGETDESC_H
