#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <cxxabi.h>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <utility>

using namespace llvm;
using namespace std;

// Comment out the line below to turn off all debug statements.
// **Note** For final submission of this assignment,
//          please comment out the line below.
#define __DEBUG__

// Output strings for debugging
std::string debug_str;
raw_string_ostream debug(debug_str);

// Strings for output
std::string output_str;
raw_string_ostream output(output_str);

// Demangles the function name.
std::string demangle(const char *name) {
  int status = -1;

  std::unique_ptr<char, void (*)(void *)> res{
      abi::__cxa_demangle(name, NULL, NULL, &status), std::free};
  return (status == 0) ? res.get() : std::string(name);
}

// Function to attach debug Metadata to an instruction
void addDebugMetaData(Instruction *I, char *debugInfo) {
  LLVMContext &C = I->getContext();
  MDNode *N = MDNode::get(C, MDString::get(C, debugInfo));
  char DebugMetadata[100];
  strcpy(DebugMetadata, "cpenDebug.");
  strcat(DebugMetadata, debugInfo);
  I->setMetadata(DebugMetadata, N);
}

// Returns the source code line number cooresponding to the LLVM instruction.
// Returns -1 if the instruction has no associated Metadata.
int getSourceCodeLine(Instruction *I) {
  // Get debugInfo associated with every instruction.
  llvm::DebugLoc debugInfo = I->getDebugLoc();

  int line = -1;
  if (debugInfo)
    line = debugInfo.getLine();

  return line;
}

// Topologically sort all the basic blocks in a function.
// Handle cycles in the directed graph using Tarjan's algorithm
// of Strongly Connected Components (SCCs).
vector<BasicBlock *> topoSortBBs(Function &F) {
  vector<BasicBlock *> tempBB;
  for (scc_iterator<Function *> I = scc_begin(&F), IE = scc_end(&F); I != IE;
       ++I) {

    // Obtain the vector of BBs in this SCC and print it out.
    const std::vector<BasicBlock *> &SCCBBs = *I;

    for (std::vector<BasicBlock *>::const_iterator BBI = SCCBBs.begin(),
                                                   BBIE = SCCBBs.end();
         BBI != BBIE; ++BBI) {

      BasicBlock *b = const_cast<llvm::BasicBlock *>(*BBI);
      tempBB.push_back(b);
    }
  }

  reverse(tempBB.begin(), tempBB.end());
  return tempBB;
}

namespace {
struct Assignment2 : public FunctionPass {
  static char ID;

  // Map to store the line numbers at which a variable is tainted or untainted
  // eg. {11, {"x", 1}} with 11 representing line number and 1 representing tainted
  // (0 for untainted)
  map<int, pair<string, int>> BuggyLines;

  // Keep track of all the functions we have encountered so far.
  unordered_map<string, bool> funcNames;

  // Code added:
  // Initialize sets
  unordered_set<llvm::Value*> EntrySet;
  unordered_set<llvm::Value*> ExitSet;
  unordered_set<llvm::Value*> UnionSet;

  // Reset all global variables when a new function is called.
  void cleanGlobalVariables() {
    EntrySet.clear();
    ExitSet.clear();
    UnionSet.clear();
    BuggyLines.clear();
    output_str = "";
    debug_str = "";
  }

  Assignment2() : FunctionPass(ID) {}

  // Complete this function.
  // The function should insert the line number of the lines
  // that are affected by tainted variables in the "BuggyLines" vector.
  void checkIsTainted(Instruction *I, BasicBlock *b, unordered_set<llvm::Value*> &EntrySet, unordered_set<llvm::Value*> &UnionSet) {

    char store[] = "This_is_a_store_instruction";
    char load[] = "This_is_a_load_instruction";
    char call[] = "This_is_a_call_instruction";
    int line = getSourceCodeLine(I);

    // Add MetaData to a Call instruction
    if (isa<llvm::CallInst>(I)) {
      addDebugMetaData(I, call);
      
      CallInst *callInst = dyn_cast<llvm::CallInst>(I);
      //identify the function being called
      if(Function *function = callInst->getCalledFunction()){
        string functionName = function->getName().str();
	      //if calling to llvm.dbg.decalre or cout, ignore
	      if(functionName == "llvm.dbg.declare" || functionName == "_ZNSolsEi"){}
	      //if calling to cin, the variable is tainted
	      else if(functionName == "_ZNSirsERi"){
	        Value *var = callInst->getArgOperand(1);
	        //if already exists, overwrite
	        if(BuggyLines.find(getSourceCodeLine(I)) != BuggyLines.end()){
	          BuggyLines[getSourceCodeLine(I)] = make_pair(var->getName().str(), 1);
	        }
	        else{
	          BuggyLines.insert(make_pair(getSourceCodeLine(I), make_pair(var->getName().str(), 1)));
	        }
	        EntrySet.insert(var);
	      }
	      //if calling to some other function
	      //if at least one of the argument is tainted, the return value is also tainted
	      else{
	        bool isTaintedArgument = false;
	        for(unsigned i=0; i<callInst->getNumArgOperands(); i++){
	          Value *arg = callInst->getArgOperand(i);
	          if(EntrySet.count(arg)>0){
	            isTaintedArgument = true;
	          }

	          if (isTaintedArgument) {
	          //if already exists, overwrite
              if(BuggyLines.find(getSourceCodeLine(I)) != BuggyLines.end()){
                BuggyLines[getSourceCodeLine(I)] = make_pair(I->getName().str(), 1);
              }
	            else{
	              BuggyLines.insert(make_pair(getSourceCodeLine(I), make_pair(I->getName().str(), 1)));
	            }
	            EntrySet.insert(I);
	          }
	        }
	      }
	
      }
    }
      
    // Add MetaData to a Store instruction
    else if (isa<llvm::StoreInst>(I)) {
      addDebugMetaData(I, store);

      Value *srcVal = I->getOperand(0); // Source value is the first operand
      Value *destPtr = I->getOperand(1); // Destination pointer is the second operand
      //store any member of the Entry Set into any other variable, then the variable is tainted
      if (EntrySet.count(srcVal)>0) {
        EntrySet.insert(destPtr);
        if(destPtr->hasName()){
	      //if already exists, overwrite
          if(BuggyLines.find(getSourceCodeLine(I)) != BuggyLines.end()){
            BuggyLines[getSourceCodeLine(I)] = make_pair(destPtr->getName().str(), 1);
          }
	        else{
	          BuggyLines.insert(make_pair(getSourceCodeLine(I), make_pair(destPtr->getName().str(), 1)));
	        }
        }
      }
      //store a constant or any other value not in the Entry set into a variable in the Entry Set
      //and the current block is not conditional, then the variable is untainted
      else {
        Instruction *terminator = b->getTerminator();
        if (!llvm::isa<llvm::BranchInst>(terminator) || (llvm::isa<llvm::BranchInst>(terminator) && !llvm::cast<llvm::BranchInst>(terminator)->isConditional())){
          if(EntrySet.count(destPtr)>0){
            EntrySet.erase(destPtr);
	          if(destPtr->hasName()){
	            //if already exists, overwrite
              if(BuggyLines.find(getSourceCodeLine(I)) != BuggyLines.end()){
                BuggyLines[getSourceCodeLine(I)] = make_pair(destPtr->getName().str(), 1);
              }
	            else{
		            BuggyLines.insert(make_pair(getSourceCodeLine(I), make_pair(destPtr->getName().str(), 0)));
              }
            }
            if(UnionSet.count(destPtr)>0){
              UnionSet.erase(destPtr);
            }
          }
        }
      }
    } 
    // Add MetaData to a Load instruction
    else if (isa<llvm::LoadInst>(I)) {
      addDebugMetaData(I, load);

      // Check if the instruction is loading from a variable that is in the Entry Set
      LoadInst* loadInst = dyn_cast<llvm::LoadInst>(I);
      Value* op = loadInst->getPointerOperand();
      if(EntrySet.count(op)>0){
        EntrySet.insert(I);
        if(I->hasName()){
	      //if already exists, overwrite
          if(BuggyLines.find(getSourceCodeLine(I)) != BuggyLines.end()){
            BuggyLines[getSourceCodeLine(I)] = make_pair(I->getName().str(), 1);
          }
	        else{
            BuggyLines.insert(make_pair(getSourceCodeLine(I), make_pair(I->getName().str(), 1)));
          }
	      }
      } 
    }
    
    return;
  }

  // Function to return the line numbers that uses an undefined variable.
  bool runOnFunction(Function &F) override {
    if (F.getName() != "main")
	    return false;
    std::string funcName = demangle(F.getName().str().c_str());

    // Remove all non user-defined functions and functions
    // that starts with '_' or has 'std'.
    if (F.isDeclaration() || funcName[0] == '_' ||
        funcName.find("std") != std::string::npos)
      return false;

    // Remove all functions that we have previously encountered.
    if (funcNames.find(funcName) != funcNames.end())
      return false;

    funcNames.insert(make_pair(funcName, true));

    // Iterate through basic blocks of the function topologically.
    for (auto b : topoSortBBs(F)) {
      // Code Added:
      // EntrySet is initialized as the union of ExitSets of the current basic block's predecessors
      EntrySet = UnionSet; 
      ExitSet.clear();

      // Iterate over all the instructions within a basic block.
      for (BasicBlock::const_iterator It = b->begin(); It != b->end(); ++It) {
        Instruction *ins = const_cast<llvm::Instruction *>(&*It);
        checkIsTainted(ins, b, EntrySet, UnionSet);
      }

      // Code added:
      ExitSet = EntrySet;
      UnionSet.insert(ExitSet.begin(), ExitSet.end());
    }

    // Print out the line numbers that are affected by tainted variables
    for (auto it = BuggyLines.begin(); it != BuggyLines.end();) {
      if (it->second.second == 1) {
        output << "Line " << it->first << ": " << it->second.first << " is tainted\n";
        ++ it;
      }
      else {
        output << "Line " << it->first << ": " << it->second.first << " is now untainted\n";

        for (auto next = BuggyLines.begin(); next != BuggyLines.end(); next ++){
	        if (next->second.first == it->second.first && next->second.second == 1) {
		        BuggyLines.erase(next);
	        }
        }
        it = BuggyLines.erase(it);
      }
    }

    output << "Tainted: {";
    bool isFirst = true;
    for (auto &pair : BuggyLines) {
	    if (pair.second.second == 1) { 
            if (!isFirst) {
                output << ", ";
            }
            isFirst = false;
            output << pair.second.first;
      }
    }
    output << "}\n";


// Print debug string if __DEBUG__ is enabled.
#ifdef __DEBUG__
    errs() << debug.str();
#endif
    debug.flush();

    // Print output
    errs() << output.str();
    output.flush();

    cleanGlobalVariables();
    return false;
  }
};
} // namespace

char Assignment2::ID = 0;
static RegisterPass<Assignment2> X("taintanalysis",
                                   "Pass to find tainted variables");
