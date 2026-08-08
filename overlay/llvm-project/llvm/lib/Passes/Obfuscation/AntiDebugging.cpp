#include "Obfuscation/AntiDebugging.h"
#include "Obfuscation/Utils.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"

using namespace llvm;

PreservedAnalyses AntiDebugging::run(Function &F, FunctionAnalysisManager &AM) {
  if (enabled || getFunctionAnnotation(&F).find("antidbg") != std::string::npos) {
    process(F);
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

void AntiDebugging::process(Function &F) {
  if (F.isDeclaration() || F.empty())
    return;

  Module *M = F.getParent();
  Triple TT(M->getTargetTriple());
  if (!TT.isOSLinux() && !TT.isAndroid())
    return;

  LLVMContext &Ctx = M->getContext();
  BasicBlock &Entry = F.getEntryBlock();
  // splitBasicBlock needs at least one non-terminator instruction before InsertPt
  if (Entry.size() <= 1)
    return;
  Instruction *InsertPt = &*Entry.getFirstInsertionPt();
  Type *I32Ty  = Type::getInt32Ty(Ctx);
  Type *I64Ty  = Type::getInt64Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);

  // Shared volatile guard — accumulates debugger-state-dependent values
  GlobalVariable *adbGuard = M->getGlobalVariable("__obfu_adb_guard");
  if (!adbGuard)
    adbGuard = new GlobalVariable(*M, I32Ty, false, GlobalValue::CommonLinkage,
                                   ConstantInt::get(I32Ty, 0), "__obfu_adb_guard");

  // One-shot ptrace(PTRACE_TRACEME=0) check per process.
  // Returns 0 when not traced, -1 (EPERM) when a debugger is already attached.
  // The done-flag global prevents calling TRACEME twice (second call always returns -1).
  GlobalVariable *adbDone = M->getGlobalVariable("__obfu_adb_done");
  if (!adbDone)
    adbDone = new GlobalVariable(*M, I32Ty, false, GlobalValue::CommonLinkage,
                                  ConstantInt::get(I32Ty, 0), "__obfu_adb_done");

  // Declare ptrace — long ptrace(long request, long pid, void *addr, void *data)
  FunctionCallee PtraceF = M->getOrInsertFunction(
      "ptrace",
      FunctionType::get(I64Ty, {I32Ty, I32Ty, PtrTy, PtrTy}, false));

  IRBuilder<> IRB(InsertPt);

  // Guard block: only call ptrace once per process execution
  BasicBlock *CheckBB  = Entry.splitBasicBlock(InsertPt, "adb_check");
  BasicBlock *PtraceBB = BasicBlock::Create(Ctx, "adb_ptrace", &F, CheckBB);
  BasicBlock *MergeBB  = BasicBlock::Create(Ctx, "adb_merge",  &F, CheckBB);

  // Entry → guard test
  Entry.getTerminator()->eraseFromParent();
  IRB.SetInsertPoint(&Entry);
  LoadInst *Done = IRB.CreateLoad(I32Ty, adbDone, /*isVolatile=*/true);
  Value *NotDone = IRB.CreateICmpEQ(Done, ConstantInt::get(I32Ty, 0));
  IRB.CreateCondBr(NotDone, PtraceBB, MergeBB);

  // PtraceBB: call ptrace and mix result into guard
  IRB.SetInsertPoint(PtraceBB);
  IRB.CreateStore(ConstantInt::get(I32Ty, 1), adbDone, /*isVolatile=*/true);
  Value *Zero32  = ConstantInt::get(I32Ty, 0);
  Value *NullPtr = ConstantPointerNull::get(PtrTy);
  // ptrace(PTRACE_TRACEME=0, 0, NULL, NULL) → 0 clean, -1 debugger attached
  CallInst *PtraceRet = IRB.CreateCall(PtraceF, {Zero32, Zero32, NullPtr, NullPtr});
  PtraceRet->setCallingConv(CallingConv::C);
  Value *Ret32   = IRB.CreateTrunc(PtraceRet, I32Ty);
  LoadInst *Cur  = IRB.CreateLoad(I32Ty, adbGuard, /*isVolatile=*/true);
  // Guard value becomes debugger-state-dependent; optimizer cannot simplify
  Value *Mixed   = IRB.CreateAdd(IRB.CreateXor(Cur, Ret32), Ret32);
  IRB.CreateStore(Mixed, adbGuard, /*isVolatile=*/true);
  IRB.CreateBr(MergeBB);

  // MergeBB → rest of original entry block (CheckBB)
  IRB.SetInsertPoint(MergeBB);
  IRB.CreateBr(CheckBB);
}
