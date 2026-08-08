#include "Obfuscation/ConstantEncryption.h"
#include "Obfuscation/Utils.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include <random>
#include <vector>
using namespace llvm;

// Returns false for constants the optimizer or ABI requires to stay literal
static bool shouldEncrypt(ConstantInt *CI) {
  unsigned Bits = cast<IntegerType>(CI->getType())->getBitWidth();
  if (Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64)
    return false;
  if (CI->isZero() || CI->isOne() || CI->isAllOnesValue())
    return false;
  return true;
}

PreservedAnalyses ConstantEncryption::run(Function &F,
                                           FunctionAnalysisManager &AM) {
  if (!enabled &&
      getFunctionAnnotation(&F).find("constenc") == std::string::npos)
    return PreservedAnalyses::all();
  if (F.isDeclaration() || F.empty())
    return PreservedAnalyses::all();

  Module *M = F.getParent();
  // Deterministic per-function seed → same keys across identical builds
  std::mt19937_64 RNG(std::hash<std::string>{}(F.getName().str()));

  struct WorkItem { Instruction *I; unsigned Op; ConstantInt *C; };
  std::vector<WorkItem> Tasks;

  for (Instruction &I : instructions(F)) {
    // switch case values, PHI incoming values, and alloca sizes must stay literal
    if (isa<SwitchInst>(I) || isa<PHINode>(I) || isa<AllocaInst>(I))
      continue;
    if (!isa<BinaryOperator>(I) && !isa<ICmpInst>(I) &&
        !isa<StoreInst>(I) && !isa<CallInst>(I))
      continue;

    // For CallInst, stop before the callee operand
    unsigned Limit = isa<CallInst>(I) ? cast<CallInst>(I).arg_size()
                                      : I.getNumOperands();
    for (unsigned i = 0; i < Limit; i++) {
      if (auto *CI = dyn_cast<ConstantInt>(I.getOperand(i)))
        if (shouldEncrypt(CI))
          Tasks.push_back({&I, i, CI});
    }
  }

  if (Tasks.empty())
    return PreservedAnalyses::all();

  for (auto &T : Tasks) {
    IntegerType *Ty   = cast<IntegerType>(T.C->getType());
    unsigned Bits = Ty->getBitWidth();
    uint64_t Mask = (Bits < 64) ? ((1ULL << Bits) - 1) : ~0ULL;
    uint64_t Orig = T.C->getZExtValue() & Mask;
    uint64_t Key  = RNG() & Mask;
    uint64_t Enc  = Orig ^ Key;

    // Each constant gets its own private volatile global for the XOR key.
    // Volatile prevents the optimizer from folding (Enc ^ Key) back to Orig.
    auto *KeyGV = new GlobalVariable(*M, Ty, /*isConst=*/false,
                                     GlobalValue::PrivateLinkage,
                                     ConstantInt::get(Ty, Key), "__obfu_cek");

    IRBuilder<NoFolder> IRB(T.I);
    auto *KLoad = IRB.CreateLoad(Ty, KeyGV, /*isVolatile=*/true);
    auto *Dec   = IRB.CreateXor(ConstantInt::get(Ty, Enc), KLoad);
    T.I->setOperand(T.Op, Dec);
  }

  return PreservedAnalyses::none();
}
