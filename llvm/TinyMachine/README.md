# TinyMachine LLVM Target Skeleton

This directory contains an out-of-tree LLVM backend starter for TinyMachine.

## What this includes

- Target registration entry point (`TinyMachineTargetInfo.cpp`)
- TableGen target root (`TinyMachine.td`)
- Register definitions (`TinyMachineRegisterInfo.td`)
- Instruction definitions for key opcodes (`TinyMachineInstrInfo.td`)

## What this does not include yet

- Instruction selector / lowering (`SelectionDAG` or `GlobalISel`)
- Asm parser / printer and disassembler
- MC code emitter and ELF/object writer
- Calling convention lowering beyond a basic declaration

## How to use this

1. Copy this folder into an LLVM source checkout (typically under `llvm/lib/Target/TinyMachine`).
2. Wire it into LLVM build files (`llvm/lib/Target/CMakeLists.txt` and `llvm/lib/Target/LLVMBuild.txt` in older trees).
3. Implement missing backend pieces (subtarget, frame lowering, ISel, MC layer).

This scaffold intentionally models TinyMachine's simple fixed-width opcode-first encoding style and register file (`a`-`z`).
