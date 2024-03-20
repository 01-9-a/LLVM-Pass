#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/LLVMContext.h"
#include <iostream>
#include <string>
#include <set>
#include <utility>
#include "llvm/Analysis/AliasAnalysis.h"

using namespace llvm;
using namespace std;

// Comment out the line below to turn off all debug statements.
// **Note** For final submission of this assignment,
//          please comment out the line below.
//#define __DEBUG__

// Output strings for debugging
std::string debug_str;
raw_string_ostream debug(debug_str);

// Strings for output
std::string output_str;
raw_string_ostream output(output_str);

// Function to attach debug Metadata to an instruction
void addDebugMetaData(Instruction *I, char *debugInfo) {
  LLVMContext &C = I->getContext();
  MDNode *N = MDNode::get(C, MDString::get(C, debugInfo));
  char DebugMetadata[100];
  strcpy(DebugMetadata, "cpenDebug.");
  strcat(DebugMetadata, debugInfo);
  I->setMetadata(DebugMetadata, N);
}

// Returns the source code line number corresponding to the LLVM 
instruction.
// Returns -1 if the instruction has no associated Metadata.
int getSourceCodeLine(Instruction *I) {
  // Get debugInfo associated with every instruction.
  llvm::DebugLoc debugInfo = I->getDebugLoc();

  int line = -1;
  if (debugInfo)
    line = debugInfo.getLine();

  return line;
}

namespace {
struct Assignment3 : public FunctionPass {
    static char ID;

    Assignment3() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
        LLVMContext &Context = F.getContext();
        set<Value*> ptrsToHeap;
        // Get Alias Analysis results
        AliasAnalysis &AA = 
getAnalysis<AAResultsWrapperPass>().getAAResults();

        for (auto &B : F) {
            for (auto It = B.begin(), E = B.end(); It != E; ) {
		        Instruction *Inst = &*It;
		        int line = getSourceCodeLine(Inst);
                ++It;
                IRBuilder<> Builder(Inst);

                // Instrument memory allocation and deallocation calls.
                if (auto *Call = dyn_cast<CallInst>(Inst)) {

                    Function *CalledFunc = Call->getCalledFunction();

                    if (CalledFunc && CalledFunc->getName() == "malloc") {
                        // Replace with mymalloc.
                        FunctionCallee mymallocFunc = 
F.getParent()->getOrInsertFunction("mymalloc", 
FunctionType::get(Type::getInt8PtrTy(Context),
                                                        
{Type::getInt64Ty(Context)}, false));

                        vector<Value*> Args(Call->arg_begin(), 
Call->arg_end()); // Get original arguments

                        Builder.SetInsertPoint(&B, It);

                        CallInst *NewCall = 
Builder.CreateCall(mymallocFunc, Args);

                        // Add to ptrsToHeap set
                        ptrsToHeap.insert(NewCall);

                        Call->replaceAllUsesWith(NewCall);
                        Call->eraseFromParent();

                    } else if (CalledFunc && CalledFunc->getName() == 
"calloc") {
                        // Replace with mycalloc.
                        FunctionCallee mycallocFunc = 
F.getParent()->getOrInsertFunction("mycalloc", 
FunctionType::get(Type::getInt8PtrTy(Context), 
                                                        
{Type::getInt64Ty(Context), Type::getInt64Ty(Context)}, false));

                        vector<Value*> Args(Call->arg_begin(), 
Call->arg_end()); // Get original arguments

                        Builder.SetInsertPoint(&B, It);
                        CallInst *NewCall = 
Builder.CreateCall(mycallocFunc, Args);

                        // Add to ptrsToHeap set
                        ptrsToHeap.insert(NewCall);

			            Call->replaceAllUsesWith(NewCall);
                        Call->eraseFromParent();

                    } else if (CalledFunc && CalledFunc->getName() == 
"free") {
                        // Replace with myfree.
                        FunctionCallee myfreeFunc = 
F.getParent()->getOrInsertFunction("myfree", 
FunctionType::get(Type::getVoidTy(Context),
                                                    
{Type::getInt8PtrTy(Context), Type::getInt32Ty(Context)}, false));

                        Value *ptrArg = Call->getArgOperand(0);
                        Value *lineArg = 
ConstantInt::get(Type::getInt32Ty(Context), line);

                        // Add to ptrsToHeap set
                        ptrsToHeap.insert(ptrArg);

                        // Create the new call instruction
                        vector<Value *> Args = {ptrArg, lineArg};
                        Builder.SetInsertPoint(&B, It);
                        CallInst *NewCall = Builder.CreateCall(myfreeFunc, 
Args);

                        Call->replaceAllUsesWith(NewCall);
                        Call->eraseFromParent();
                    }
                }
            }
        }

        // Find their aliases
        set<Value*> aliases;
        for (auto &B : F) {
            for (auto It = B.begin(), E = B.end(); It != E; ) {
                Instruction *Inst = &*It;
                ++It;
                for (auto &U : Inst->operands()) {
                    Value *operand = U.get();
                    for (Value *v : ptrsToHeap){
                        // Use alias analysis between targetPtr and each 
operand
                        if (AA.alias(operand, v) != 
llvm::AliasResult::NoAlias) {
                            aliases.insert(operand);
                        }
                    }
                }
            }
        }


        for (auto &B : F) {
            for (auto It = B.begin(), E = B.end(); It != E; ) {
                Instruction *Inst = &*It;
                int line = getSourceCodeLine(Inst);
                ++It;
                IRBuilder<> Builder(Inst);
                // Instrument pointer manipulations.
                if ((isa<CallInst>(Inst) && 
(dyn_cast<CallInst>(Inst))->getCalledFunction()->getName() != "myfree") || 
isa<LoadInst>(Inst) || isa<StoreInst>(Inst) || 
isa<GetElementPtrInst>(Inst)) {
                    Value *ptrArg = nullptr;
                    bool inHeap = false;

                    for (auto &U : Inst->operands()) {
                        if(aliases.find(U) != aliases.end() || 
ptrsToHeap.find(U) != ptrsToHeap.end()){
                            inHeap = true;
                            ptrArg = U;
                      	    break;
                        }
                    }

                    // The instruction manipulates or uses a pointer
                    if(inHeap && 
ptrArg->getType()->getPointerElementType()->isIntegerTy(8)){
                        // Inject call to validatePointer.
                        FunctionCallee validatePointerFunc = 
F.getParent()->getOrInsertFunction("validatePointer", 
FunctionType::get(Type::getVoidTy(Context),
                                                            
{Type::getInt8PtrTy(Context), Type::getInt32Ty(Context)}, false));

                        Value *lineArg = 
ConstantInt::get(Type::getInt32Ty(Context), line);

                        // Create the new call instruction
                        vector<Value *> Args = {ptrArg, lineArg};
                        Builder.SetInsertPoint(Inst);
                        Builder.CreateCall(validatePointerFunc, Args);
                    }
                }
            }
        }


        // Print debug string if __DEBUG__ is enabled.
        #ifdef __DEBUG__
            errs() << debug.str();
        #endif
            debug.flush();

            // Print output
            errs() << output.str();
            output.flush();

        return true;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        // https://llvm.org/doxygen/classllvm_1_1AAResultsWrapperPass.html
        // AAResultsWrapperPass is a Function Pass but RunOnModule() is 
used
        AU.addRequired<AAResultsWrapperPass>();
        AU.setPreservesAll();
    }

};


} // namespace

char Assignment3::ID = 0;
static RegisterPass<Assignment3> X("heapbugs",
                                   "Pass to find heap memory bugs");
