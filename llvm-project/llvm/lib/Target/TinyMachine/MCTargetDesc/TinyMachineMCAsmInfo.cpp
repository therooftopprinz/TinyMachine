#include "TinyMachineMCTargetDesc.h"
#include "llvm/MC/MCAsmInfoELF.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCTargetOptions.h"

using namespace llvm;

namespace {
class TinyMachineMCAsmInfo : public MCAsmInfoELF {
public:
  TinyMachineMCAsmInfo() {
    CodePointerSize = 8;
    CalleeSaveStackSlotSize = 8;
    IsLittleEndian = true;
    MinInstAlignment = 1;
    MaxInstLength = 10; // e.g. 0x1A + imm64 + reg = 1+8+1
    CommentString = ";";
  }
};
} // namespace

MCAsmInfo *llvm::createTinyMachineMCAsmInfo(const MCRegisterInfo &MRI,
                                            const Triple &TT,
                                            const MCTargetOptions &Options) {
  (void)MRI;
  (void)TT;
  (void)Options;
  return new TinyMachineMCAsmInfo();
}
