#pragma once
#include "llvm/Passes/PassBuilder.h"
using namespace llvm;

// Hikari-style: each integer constant C is replaced at runtime with
//   (C ^ Key) ^ load volatile(@key_global)
// so static analysis cannot recover original values.
struct ConstantEncryption : PassInfoMixin<ConstantEncryption> {
  bool enabled;
  ConstantEncryption(bool enabled = false) : enabled(enabled) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  static bool isRequired() { return true; }
};
