// Full opcode map for VM `Instruction<opcode, ...>` in src/TinyMachine.hpp.
// Each `def` below uses the same opcode byte and operand byte layout (after
// the opcode): same order as the VM tuple (little-endian multi-byte imms).
//
// VM typedef                      LLVM TableGen def
// ------------------------------  ----------------------
// I_MOV_R64_R64_T                 MOVrr
// I_MOV_R64_I8_T                  MOVri8
// I_MOV_R64_I16_T                 MOVri16
// I_MOV_R64_I32_T                 MOVri32
// I_MOV_R64_I64_T                 MOVri64
// I_MOVZX_R64_BYTE_PTR_R64_T      MOVZX_R64_BPR64
// ... (see defs in order 0x06–0x51)

let Namespace = "TinyMachine" in {

// MVT::Other / token chain and branch targets (see XCoreInstrInfo.td, etc.).
def chain : Operand<OtherVT>;
def brtarget : Operand<OtherVT>;

// Opcode byte matches src/TinyMachine.hpp Instruction<OpCode, ...>.
class TinyMachineInst<bits<8> op, dag outs, dag ins, string asmstr>
    : Instruction {
  bits<8> Opcode = op;
  let OutOperandList = outs;
  let InOperandList = ins;
  let AsmString = asmstr;
  let Size = 1;
}

//===----------------------------------------------------------------------===//
// 0x01–0x05: MOV immediate / register
//===----------------------------------------------------------------------===//

def MOVrr : TinyMachineInst<0x01, (outs GPR64:$dst), (ins GPR64:$src),
                            "mov $dst, $src">;
def MOVri8 : TinyMachineInst<0x02, (outs GPR64:$dst), (ins i8imm:$imm),
                             "mov $dst, $imm">;
def MOVri16 : TinyMachineInst<0x03, (outs GPR64:$dst), (ins i16imm:$imm),
                              "mov $dst, $imm">;
def MOVri32 : TinyMachineInst<0x04, (outs GPR64:$dst), (ins i32imm:$imm),
                              "mov $dst, $imm">;
def MOVri64 : TinyMachineInst<0x05, (outs GPR64:$dst), (ins i64imm:$imm),
                              "mov $dst, $imm">;

//===----------------------------------------------------------------------===//
// 0x06–0x0D: MOVZX / MOVSX from [reg]
//===----------------------------------------------------------------------===//

def MOVZX_R64_BPR64 : TinyMachineInst<0x06, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movzx $dst, byte ptr [$base]">;
def MOVZX_R64_WPR64 : TinyMachineInst<0x07, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movzx $dst, word ptr [$base]">;
def MOVZX_R64_DPR64 : TinyMachineInst<0x08, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movzx $dst, dword ptr [$base]">;
def MOVZX_R64_QPR64 : TinyMachineInst<0x09, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movzx $dst, qword ptr [$base]">;

def MOVSX_R64_BPR64 : TinyMachineInst<0x0A, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movsx $dst, byte ptr [$base]">;
def MOVSX_R64_WPR64 : TinyMachineInst<0x0B, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movsx $dst, word ptr [$base]">;
def MOVSX_R64_DPR64 : TinyMachineInst<0x0C, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movsx $dst, dword ptr [$base]">;
def MOVSX_R64_QPR64 : TinyMachineInst<0x0D, (outs GPR64:$dst), (ins GPR64:$base),
                                      "movsx $dst, qword ptr [$base]">;

//===----------------------------------------------------------------------===//
// 0x0E–0x15: MOVZX / MOVSX from absolute [imm]
//===----------------------------------------------------------------------===//

def MOVZX_R64_BPI64 : TinyMachineInst<0x0E, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movzx $dst, byte ptr [$addr]">;
def MOVZX_R64_WPI64 : TinyMachineInst<0x0F, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movzx $dst, word ptr [$addr]">;
def MOVZX_R64_DPI64 : TinyMachineInst<0x10, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movzx $dst, dword ptr [$addr]">;
def MOVZX_R64_QPI64 : TinyMachineInst<0x11, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movzx $dst, qword ptr [$addr]">;

def MOVSX_R64_BPI64 : TinyMachineInst<0x12, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movsx $dst, byte ptr [$addr]">;
def MOVSX_R64_WPI64 : TinyMachineInst<0x13, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movsx $dst, word ptr [$addr]">;
def MOVSX_R64_DPI64 : TinyMachineInst<0x14, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movsx $dst, dword ptr [$addr]">;
def MOVSX_R64_QPI64 : TinyMachineInst<0x15, (outs GPR64:$dst), (ins i64imm:$addr),
                                      "movsx $dst, qword ptr [$addr]">;

//===----------------------------------------------------------------------===//
// 0x16–0x19: MOV to [reg]
//===----------------------------------------------------------------------===//

def MOV_BPR64_R64 : TinyMachineInst<0x16, (outs), (ins GPR64:$ptr, GPR64:$src),
                                    "mov byte ptr [$ptr], $src">;
def MOV_WPR64_R64 : TinyMachineInst<0x17, (outs), (ins GPR64:$ptr, GPR64:$src),
                                    "mov word ptr [$ptr], $src">;
def MOV_DPR64_R64 : TinyMachineInst<0x18, (outs), (ins GPR64:$ptr, GPR64:$src),
                                    "mov dword ptr [$ptr], $src">;
def MOV_QPR64_R64 : TinyMachineInst<0x19, (outs), (ins GPR64:$ptr, GPR64:$src),
                                    "mov qword ptr [$ptr], $src">;

//===----------------------------------------------------------------------===//
// 0x1A–0x1D: MOV to [imm]
//===----------------------------------------------------------------------===//

def MOV_BPI64_R64 : TinyMachineInst<0x1A, (outs), (ins i64imm:$addr, GPR64:$src),
                                    "mov byte ptr [$addr], $src">;
def MOV_WPI64_R64 : TinyMachineInst<0x1B, (outs), (ins i64imm:$addr, GPR64:$src),
                                    "mov word ptr [$addr], $src">;
def MOV_DPI64_R64 : TinyMachineInst<0x1C, (outs), (ins i64imm:$addr, GPR64:$src),
                                    "mov dword ptr [$addr], $src">;
def MOV_QPI64_R64 : TinyMachineInst<0x1D, (outs), (ins i64imm:$addr, GPR64:$src),
                                    "mov qword ptr [$addr], $src">;

//===----------------------------------------------------------------------===//
// 0x1E–0x21: ADD / SUB / MUL / DIV (rr)
// VM updates the flags register ‘f’ only for add/sub (see VirtualMachine::process).
//===----------------------------------------------------------------------===//

let Defs = [F] in {
def ADDrr : TinyMachineInst<0x1E, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "add $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
  let isCommutable = 1;
}
def SUBrr : TinyMachineInst<0x1F, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "sub $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
} // Defs = [F]

def MULrr : TinyMachineInst<0x20, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "mul $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
  let isCommutable = 1;
}
def DIVrr : TinyMachineInst<0x21, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "div $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}

//===----------------------------------------------------------------------===//
// 0x22–0x25: ADD / SUB / MUL / DIV (ri64)
//===----------------------------------------------------------------------===//

let Defs = [F] in {
def ADDri : TinyMachineInst<0x22, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                            "add $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
def SUBri : TinyMachineInst<0x23, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                            "sub $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
} // Defs = [F]

def MULri : TinyMachineInst<0x24, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                            "mul $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
def DIVri : TinyMachineInst<0x25, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                            "div $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}

//===----------------------------------------------------------------------===//
// 0x26–0x28: SAR / SHR / SHL (rr)
//===----------------------------------------------------------------------===//

def SARrr : TinyMachineInst<0x26, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "sar $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
def SHRrr : TinyMachineInst<0x27, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "shr $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
def SHLrr : TinyMachineInst<0x28, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "shl $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}

//===----------------------------------------------------------------------===//
// 0x29–0x2B: SAR / SHR / SHL (ri8)
//===----------------------------------------------------------------------===//

def SARri8 : TinyMachineInst<0x29, (outs GPR64:$dst), (ins GPR64:$lhs, i8imm:$imm),
                             "sar $lhs, $imm"> {
  let Constraints = "$dst = $lhs";
}
def SHRri8 : TinyMachineInst<0x2A, (outs GPR64:$dst), (ins GPR64:$lhs, i8imm:$imm),
                             "shr $lhs, $imm"> {
  let Constraints = "$dst = $lhs";
}
def SHLri8 : TinyMachineInst<0x2B, (outs GPR64:$dst), (ins GPR64:$lhs, i8imm:$imm),
                             "shl $lhs, $imm"> {
  let Constraints = "$dst = $lhs";
}

//===----------------------------------------------------------------------===//
// 0x2C, 0x2E, 0x2F: AND / OR / XOR (rr) — VM skips 0x2D
//===----------------------------------------------------------------------===//

def ANDrr : TinyMachineInst<0x2C, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "and $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
  let isCommutable = 1;
}
def ORrr : TinyMachineInst<0x2E, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                           "or $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
  let isCommutable = 1;
}
def XORrr : TinyMachineInst<0x2F, (outs GPR64:$dst), (ins GPR64:$lhs, GPR64:$rhs),
                            "xor $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
  let isCommutable = 1;
}

//===----------------------------------------------------------------------===//
// 0x30: NOT
//===----------------------------------------------------------------------===//

def NOT_R64 : TinyMachineInst<0x30, (outs GPR64:$dst), (ins GPR64:$src), "not $dst"> {
  let Constraints = "$dst = $src";
}

//===----------------------------------------------------------------------===//
// 0x31, 0x36: CMP
//===----------------------------------------------------------------------===//

def CMPrr : TinyMachineInst<0x31, (outs), (ins chain:$c, GPR64:$lhs, GPR64:$rhs),
                            "cmp $lhs, $rhs"> {
  let Defs = [F];
}
def CMPri : TinyMachineInst<0x36, (outs), (ins chain:$c, GPR64:$lhs, i64imm:$rhs),
                            "cmp $lhs, $rhs"> {
  let Defs = [F];
}

//===----------------------------------------------------------------------===//
// 0x32–0x34: AND / OR / XOR (ri64)
//===----------------------------------------------------------------------===//

def ANDri : TinyMachineInst<0x32, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                            "and $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
def ORri : TinyMachineInst<0x33, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                           "or $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}
def XORri : TinyMachineInst<0x34, (outs GPR64:$dst), (ins GPR64:$lhs, i64imm:$rhs),
                            "xor $lhs, $rhs"> {
  let Constraints = "$dst = $lhs";
}

//===----------------------------------------------------------------------===//
// 0x35: padding / unused opcode byte in VM
//===----------------------------------------------------------------------===//

def NOP : TinyMachineInst<0x35, (outs), (ins), "nop">;

//===----------------------------------------------------------------------===//
// 0x37–0x40: conditional branches (target in register)
//===----------------------------------------------------------------------===//

let Uses = [F] in {
def JE_R64 : TinyMachineInst<0x37, (outs), (ins GPR64:$target), "je $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JG_R64 : TinyMachineInst<0x38, (outs), (ins GPR64:$target), "jg $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JGE_R64 : TinyMachineInst<0x39, (outs), (ins GPR64:$target), "jge $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JL_R64 : TinyMachineInst<0x3A, (outs), (ins GPR64:$target), "jl $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JLE_R64 : TinyMachineInst<0x3B, (outs), (ins GPR64:$target), "jle $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JA_R64 : TinyMachineInst<0x3C, (outs), (ins GPR64:$target), "ja $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JAE_R64 : TinyMachineInst<0x3E, (outs), (ins GPR64:$target), "jae $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JB_R64 : TinyMachineInst<0x3F, (outs), (ins GPR64:$target), "jb $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JBE_R64 : TinyMachineInst<0x40, (outs), (ins GPR64:$target), "jbe $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
} // Uses = [F]

//===----------------------------------------------------------------------===//
// 0x41–0x42: CALL / JMP (register)
//===----------------------------------------------------------------------===//

def CALL_R64 : TinyMachineInst<0x41, (outs), (ins GPR64:$target), "call $target">;
def JMP_R64 : TinyMachineInst<0x42, (outs), (ins GPR64:$target), "jmp $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}

//===----------------------------------------------------------------------===//
// 0x43–0x4B: conditional branches (absolute i64 or basic-block label)
//===----------------------------------------------------------------------===//

let Uses = [F] in {
def JE_I64 : TinyMachineInst<0x43, (outs), (ins chain:$c, brtarget:$target),
                            "je $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JG_I64 : TinyMachineInst<0x44, (outs), (ins chain:$c, brtarget:$target),
                            "jg $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JGE_I64 : TinyMachineInst<0x45, (outs), (ins chain:$c, brtarget:$target),
                            "jge $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JL_I64 : TinyMachineInst<0x46, (outs), (ins chain:$c, brtarget:$target),
                            "jl $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JLE_I64 : TinyMachineInst<0x47, (outs), (ins chain:$c, brtarget:$target),
                            "jle $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JA_I64 : TinyMachineInst<0x48, (outs), (ins chain:$c, brtarget:$target),
                            "ja $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JAE_I64 : TinyMachineInst<0x49, (outs), (ins chain:$c, brtarget:$target),
                            "jae $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JB_I64 : TinyMachineInst<0x4A, (outs), (ins chain:$c, brtarget:$target),
                            "jb $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
def JBE_I64 : TinyMachineInst<0x4B, (outs), (ins chain:$c, brtarget:$target),
                            "jbe $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}
} // Uses = [F]

//===----------------------------------------------------------------------===//
// 0x4C–0x4D: CALL / JMP (absolute i64)
//===----------------------------------------------------------------------===//

def CALLi64 : TinyMachineInst<0x4C, (outs), (ins i64imm:$target), "call $target">;
def JMPi64 : TinyMachineInst<0x4D, (outs), (ins i64imm:$target), "jmp $target"> {
  let isBranch = 1;
  let isTerminator = 1;
}

//===----------------------------------------------------------------------===//
// 0x4E–0x51: RET / PUSH / POP / SYSCALL
//===----------------------------------------------------------------------===//

def RET : TinyMachineInst<0x4E, (outs), (ins), "ret"> {
  let isReturn = 1;
  let isTerminator = 1;
  let isBarrier = 1;
}
def PUSH_R64 : TinyMachineInst<0x4F, (outs), (ins GPR64:$src), "push $src">;
def POP_R64 : TinyMachineInst<0x50, (outs GPR64:$dst), (ins), "pop $dst">;
def SYSCALL : TinyMachineInst<0x51, (outs), (ins), "syscall">;

//===----------------------------------------------------------------------===//
// SelectionDAG Pat<> (same technique as in-tree RISC-V / AArch64: map legal
// i64 DAG nodes to rr / ri machine ops). Memory, FrameIndex, and compare +
// branch lowering are still done in C++ — follow X86 ISel / stack lowering for
// “base + offset” style and CMP + conditional jump fusion patterns.
//===----------------------------------------------------------------------===//

def : Pat<(i64 (add GPR64:$l, GPR64:$r)), (ADDrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (sub GPR64:$l, GPR64:$r)), (SUBrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (mul GPR64:$l, GPR64:$r)), (MULrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (udiv GPR64:$l, GPR64:$r)), (DIVrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (and GPR64:$l, GPR64:$r)), (ANDrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (or GPR64:$l, GPR64:$r)), (ORrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (xor GPR64:$l, GPR64:$r)), (XORrr GPR64:$l, GPR64:$r)>;
def : Pat<(i64 (not GPR64:$x)), (NOT_R64 GPR64:$x)>;
def : Pat<(i64 (shl GPR64:$v, GPR64:$a)), (SHLrr GPR64:$v, GPR64:$a)>;
def : Pat<(i64 (srl GPR64:$v, GPR64:$a)), (SHRrr GPR64:$v, GPR64:$a)>;
def : Pat<(i64 (sra GPR64:$v, GPR64:$a)), (SARrr GPR64:$v, GPR64:$a)>;

def : Pat<(i64 (add GPR64:$l, (i64 timm:$imm))), (ADDri GPR64:$l, timm:$imm)>;
def : Pat<(i64 (sub GPR64:$l, (i64 timm:$imm))), (SUBri GPR64:$l, timm:$imm)>;
def : Pat<(i64 (mul GPR64:$l, (i64 timm:$imm))), (MULri GPR64:$l, timm:$imm)>;
def : Pat<(i64 (udiv GPR64:$l, (i64 timm:$imm))), (DIVri GPR64:$l, timm:$imm)>;
def : Pat<(i64 (and GPR64:$l, (i64 timm:$imm))), (ANDri GPR64:$l, timm:$imm)>;
def : Pat<(i64 (or GPR64:$l, (i64 timm:$imm))), (ORri GPR64:$l, timm:$imm)>;
def : Pat<(i64 (xor GPR64:$l, (i64 timm:$imm))), (XORri GPR64:$l, timm:$imm)>;

// Flat i64 pointer in address space 0 (matches data layout p:64:64).
def : Pat<(i64 (load (i64 GPR64:$base))), (MOVZX_R64_QPR64 GPR64:$base)>;
def : Pat<(store (i64 GPR64:$v), (i64 GPR64:$ptr)),
          (MOV_QPR64_R64 GPR64:$ptr, GPR64:$v)>;

def : Pat<(i64 (sextloadi8 (i64 GPR64:$p))), (MOVSX_R64_BPR64 GPR64:$p)>;
def : Pat<(i64 (zextloadi8 (i64 GPR64:$p))), (MOVZX_R64_BPR64 GPR64:$p)>;
def : Pat<(i64 (sextloadi16 (i64 GPR64:$p))), (MOVSX_R64_WPR64 GPR64:$p)>;
def : Pat<(i64 (zextloadi16 (i64 GPR64:$p))), (MOVZX_R64_WPR64 GPR64:$p)>;
def : Pat<(i64 (sextloadi32 (i64 GPR64:$p))), (MOVSX_R64_DPR64 GPR64:$p)>;
def : Pat<(i64 (zextloadi32 (i64 GPR64:$p))), (MOVZX_R64_DPR64 GPR64:$p)>;

} // end namespace TinyMachine
