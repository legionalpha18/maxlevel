#include "AArch64.h"
#include "AArch64Subtarget.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <cstdio>
#include <functional>
#include <random>
#include <string>
#include <vector>

using namespace llvm;

#define DEBUG_TYPE "aarch64-obfuscation"

static cl::opt<bool> EnableAArch64Obfuscation(
    "aarch64-obfu", cl::init(false), cl::Hidden,
    cl::desc("Enable AArch64 backend obfuscation (anti-dump, anti-decompile)"));

namespace {
class AArch64RubbishCodePass : public MachineFunctionPass {
public:
  static char ID;
  AArch64RubbishCodePass() : MachineFunctionPass(ID) {}
  StringRef getPassName() const override { return "AArch64 Obfuscation"; }

  bool runOnMachineFunction(MachineFunction &MF) override;
};
} // namespace

char AArch64RubbishCodePass::ID = 0;
INITIALIZE_PASS(AArch64RubbishCodePass, DEBUG_TYPE, DEBUG_TYPE, false, false)

FunctionPass *llvm::createAArch64RubbishCodePassPass() {
  return new AArch64RubbishCodePass();
}

// ---------------------------------------------------------------------------
// SVE instruction encodings placed in never-executed dead blocks.
// These live in the code section between real functions and confuse static
// disassemblers / decompilers (Ghidra, IDA) that do not expect SVE opcodes.
//
// Encoding space: 0x25xxxxxx (Scalable Vector Extension).
// On CPUs without SVE these bytes are UNDEFINED (raise SIGILL), but since
// the dead blocks are never reached at runtime the program behaves correctly.
//
// Pattern selection rationale:
//  - cmphi / cmphs: creates phantom SVE predicate registers (pN) and Z
//    vector register operands in Ghidra's decompiled output
//  - whilehs / whilels: creates loop-like patterns that mislead the CFG
//    reconstructor
//  - ptrue: creates an unexpected predicate initialisation
//  - 0x00000000 / 0x0000001F: UNDEFINED encodings; shown as "??" by Ghidra
// ---------------------------------------------------------------------------
static const uint32_t kSveJunk[] = {
  0x25BE96E7u, // cmphi  p7.s, p6/z, z23.s, #0x5f
  0x2526D027u, // cmphi  p7.s, p5/z, z1.s,  #0x16
  0x253E96C7u, // cmphi  p7.s, p5/z, z22.s, #0x1f
  0x2526D0E7u, // cmphi  p7.s, p5/z, z7.s,  #0x16
  0x25405027u, // whilehs p7.s, x1, x0
  0x2540D827u, // whilels p7.s, x1, x0
  0x25415027u, // whilehs p7.s, x9, x1
  0x25224027u, // ptrue  p7.s
  0x25204027u, // cmpeq  p7.s, p0/z, z1.s,  z0.s
  0x252096E7u, // cmplt  p7.s, p0/z, z23.s, z0.s
  0x04A0E420u, // SVE MUL (z0.s, z0.s, z0.s)
  0x04A03400u, // SVE LSR (z0.s)
  0x2530C820u, // SVE CNTP
  0xD503201Fu, // nop    (valid — creates rhythm in the byte stream)
  0x00000000u, // UNDEFINED (shown as "??" in Ghidra)
  0x0000001Fu, // UNDEFINED
};

bool AArch64RubbishCodePass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableAArch64Obfuscation)
    return false;

  // Only process functions that contain the "backend-obfu" inline asm marker.
  const Function &IRF = MF.getFunction();
  bool hasMarker = false;
  for (const BasicBlock &BB : IRF) {
    for (const Instruction &I : BB) {
      if (const auto *CB = dyn_cast<CallBase>(&I)) {
        if (CB->isInlineAsm()) {
          const InlineAsm *IA = dyn_cast<InlineAsm>(CB->getCalledOperand());
          if (IA && StringRef(IA->getAsmString()).contains("backend-obfu")) {
            hasMarker = true;
            break;
          }
        }
      }
    }
    if (hasMarker)
      break;
  }
  if (!hasMarker)
    return false;

  const AArch64Subtarget &STI = MF.getSubtarget<AArch64Subtarget>();
  const TargetInstrInfo *TII = STI.getInstrInfo();
  DebugLoc DL;

  // Per-function deterministic RNG so each function gets unique junk.
  std::mt19937 RNG(std::hash<std::string>{}(IRF.getName().str()));
  auto pickJunk = [&]() -> uint32_t {
    return kSveJunk[RNG() % (sizeof(kSveJunk) / sizeof(kSveJunk[0]))];
  };

  // Append 2–4 dead MachineBasicBlocks after the function's last real block.
  // The CPU never executes past the function's real `ret`, but static
  // disassemblers decode these bytes linearly and produce confusing output.
  unsigned NumBlocks = 2 + (RNG() % 3);
  for (unsigned B = 0; B < NumBlocks; B++) {
    MachineBasicBlock *JunkMBB = MF.CreateMachineBasicBlock();
    MF.push_back(JunkMBB); // always after the last real block

    // Build the raw-byte asm template (4–8 .inst directives per block).
    unsigned Count = 4 + (RNG() % 5);
    std::string AsmStr;
    for (unsigned i = 0; i < Count; i++) {
      char Buf[32];
      std::snprintf(Buf, sizeof(Buf), ".inst 0x%08X", pickJunk());
      if (!AsmStr.empty())
        AsmStr += "\n\t";
      AsmStr += Buf;
    }
    // Terminate with an architecturally-defined trap so that if a debugger
    // somehow lands here it raises SIGTRAP rather than executing garbage.
    AsmStr += "\n\tbrk #0xDEAD";

    // Store the asm string in the function's allocator (lifetime = MF).
    const char *AsmCStr = MF.createExternalSymbolName(AsmStr);

    // Emit as INLINEASM so the AsmPrinter passes it verbatim to the
    // integrated assembler. Extra_HasSideEffects prevents removal.
    BuildMI(*JunkMBB, JunkMBB->end(), DL,
            TII->get(TargetOpcode::INLINEASM))
        .addExternalSymbol(AsmCStr)
        .addImm(InlineAsm::Extra_HasSideEffects);
  }

  return true;
}
