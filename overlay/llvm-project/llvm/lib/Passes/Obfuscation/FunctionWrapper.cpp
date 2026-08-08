#include "Obfuscation/FunctionWrapper.h"
#include "Obfuscation/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"
#include <vector>

using namespace llvm;

PreservedAnalyses FunctionWrapper::run(Module &M, ModuleAnalysisManager &AM) {
  bool Changed = process(M);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool FunctionWrapper::process(Module &M) {
  LLVMContext &Ctx = M.getContext();
  std::vector<Function *> ToWrap;

  for (Function &F : M) {
    if (F.isDeclaration() || F.empty())
      continue;
    if (!enabled &&
        getFunctionAnnotation(&F).find("funcwrap") == std::string::npos)
      continue;
    ToWrap.push_back(&F);
  }

  for (Function *F : ToWrap) {
    if (F->isVarArg())
      continue;

    std::string wrapperName = "__wrap_" + F->getName().str();
    if (M.getFunction(wrapperName))
      continue;

    std::vector<Type *> ParamTypes;
    for (Argument &Arg : F->args())
      ParamTypes.push_back(Arg.getType());

    FunctionType *FT = FunctionType::get(F->getReturnType(), ParamTypes, false);
    Function *Wrapper = Function::Create(FT, GlobalValue::InternalLinkage,
                                         wrapperName, M);
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Wrapper);
    IRBuilder<> IRB(Entry);
    Type *I32Ty = Type::getInt32Ty(Ctx);

    // Junk computation before real call (volatile, can't be optimized out)
    GlobalVariable *wrapGuard = M.getGlobalVariable("__obfu_wrap_guard");
    if (!wrapGuard) {
      wrapGuard = new GlobalVariable(M, I32Ty, false,
                                     GlobalValue::CommonLinkage,
                                     ConstantInt::get(I32Ty, 0),
                                     "__obfu_wrap_guard");
    }

    Value *g1 = IRB.CreateLoad(I32Ty, wrapGuard, true);
    Value *g2 = IRB.CreateLoad(I32Ty, wrapGuard, true);
    Value *g3 = IRB.CreateXor(g1, g2);
    Value *g4 = IRB.CreateOr(g3, ConstantInt::get(I32Ty, 0xD00DF00D));
    Value *g5 = IRB.CreateAdd(g4, g2);
    IRB.CreateStore(g5, wrapGuard, true);

    // Call the real function with forwarded arguments
    std::vector<Value *> Args;
    for (Argument &Arg : Wrapper->args())
      Args.push_back(&Arg);

    CallInst *InnerCall = IRB.CreateCall(FunctionCallee(F), Args);
    InnerCall->setCallingConv(F->getCallingConv());
    Value *Result = InnerCall;
    if (F->getReturnType()->isVoidTy())
      IRB.CreateRetVoid();
    else
      IRB.CreateRet(Result);

    // Rewrite only direct CallInst sites; invoke sites are left untouched.
    std::vector<CallInst *> ToReplace;
    for (User *U : F->users()) {
      if (CallInst *CI = dyn_cast<CallInst>(U)) {
        if (CI->getCalledFunction() == F && CI->getParent()->getParent() != Wrapper)
          ToReplace.push_back(CI);
      }
    }

    for (CallInst *CI : ToReplace) {
      CI->setCalledFunction(FunctionCallee(Wrapper));
    }
  }

  return !ToWrap.empty();
}
