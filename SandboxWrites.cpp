/*
 * SandboxWrites.cpp
 */

#include "FunctionManager.hpp"
#include "TypeManager.hpp"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/MemoryLocation.h"
using namespace llvm;

namespace {
  struct SandboxWritesPass : public ModulePass {
    static char ID;
    SandboxWritesPass() : ModulePass(ID)
    {
    	m_pFreeMemBlockHead = NULL;
    	m_pHaveAllocedMem = NULL;
    	m_pPtrToHeap = NULL;
    	m_pSizeOfHeap = NULL;
    }
    virtual bool runOnModule(Module &M);
    void SandBoxWrites(Module *pMod, StoreInst* inst, Function::iterator *BB,
    		Value* upperBound, Value* lowerBound);
    void InsertGlobalVars(Module *pMod, TypeManager* typeManager);

    // Make inserted globals members for now for easy access
    GlobalVariable *m_pFreeMemBlockHead;
    GlobalVariable *m_pHaveAllocedMem;
    GlobalVariable *m_pPtrToHeap;
    GlobalVariable *m_pSizeOfHeap;
  };
}

bool SandboxWritesPass::runOnModule(Module &M)
{
	TypeManager typeManager (&M);
	InsertGlobalVars(&M, &typeManager);
	FunctionManager funcManager(&M, &typeManager, m_pFreeMemBlockHead, m_pHaveAllocedMem,
			m_pPtrToHeap);

	for (Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F)
	{
		Function *func = dyn_cast<Function>(F);
		StringRef funcName1("llvm_add_memory_block");
		StringRef funcName2("llvm_split_memory_block");
		StringRef funcName3("llvm_remove_memory_block");
		StringRef funcName4("llvm_malloc");
		StringRef funcName5("llvm_scan_merge");
		StringRef funcName6("llvm_free");

		if ((func->getName()).equals(funcName1) ||
				(func->getName()).equals(funcName2) ||
				(func->getName()).equals(funcName3) ||
				(func->getName()).equals(funcName4) ||
				(func->getName()).equals(funcName5) ||
				(func->getName()).equals(funcName6))
		{
			// We don't want to instrument on our own inserted functions.
			// We don't want to instrument on system calls either. Even though
			// the function system calls will be looped through here (if used)
			// it seems that LLVM doesn't have the BB's or instructions to loop
			// through. This makes sense since we only compile our own source code,
			// and not source code which implements system calls like printf.
			continue;
		}
		for (Function::iterator BB = F->begin(), FE = F->end(); BB != FE; ++BB)
		{
			for (BasicBlock::iterator Inst = BB->begin(), BBE = BB->end();
					Inst != BBE; ++Inst)
			{
				// every time we allocate memory we want to store
				// the memory address of the allocated memory
				if (isa<AllocaInst>(Inst))
				{
/*
					// Test for mmap / malloc:
					AllocaInst* inst = dyn_cast<AllocaInst>(Inst);

					//CallInst *ptr_test = funcManager.insertMmapCall(
					//		dyn_cast<Instruction>(Inst));
					errs()<<"Inserted Malloc\n";
					CallInst *ptr_test = funcManager.insertMallocCall(dyn_cast<Instruction>(Inst),
							NULL);

					// 1. Have pointer variable point to new mmaped memory
					// 2. Assign a value to the memory
					// 3. Print from the actual source file
					//LoadInst* ptr_23 = new LoadInst(ptr_test, "", false, inst);
					//ptr_23->setAlignment(8);
					ConstantInt* const_int32_99 = ConstantInt::get(M.getContext(),
							APInt(64, StringRef("999"), 10));
					StoreInst* void_24 = new StoreInst(const_int32_99, ptr_test, false, inst);
					void_24->setAlignment(4);

		    		StoreInst *store_inst = new StoreInst(ptr_test, inst,
		    				dyn_cast<Instruction>(Inst)->getNextNode());
		    		LoadInst *loadInst = new LoadInst(m_pPtrToHeap, "", store_inst->getNextNode());
		    		CallInst *call2 = funcManager.insertPrintfCall(loadInst, true, loadInst->getNextNode());
		    		LoadInst *loadInst2 = new LoadInst(inst, "", call2->getNextNode());
		    		CallInst *call3 = funcManager.insertPrintfCall(loadInst2, true, loadInst2->getNextNode());
		    		CastInst *cast = new BitCastInst(loadInst2, PointerType::get(IntegerType::get(M.getContext(), 32), 0), "",
		    				call3->getNextNode());
		    		LoadInst *loadInst3 = new LoadInst(cast, "", cast->getNextNode());
		    		CallInst *call4 = funcManager.insertPrintfCall(loadInst3, false, loadInst3->getNextNode());
*/
				}

				if (isa<StoreInst>(Inst))
				{
					StoreInst *inst = dyn_cast<StoreInst>(Inst);
					CastInst * ptrToHeapToInt = new PtrToIntInst(m_pPtrToHeap,
							IntegerType::get(M.getContext(), 32), "", inst);

					// remove this line in Android, since ARMv7 is 32-bits
					CastInst *zeroExt = new ZExtInst(ptrToHeapToInt,
							IntegerType::get(M.getContext(), 64), "", inst);

					LoadInst *sizeOfHeap = new LoadInst(m_pSizeOfHeap, "", false, inst);
					sizeOfHeap->setAlignment(8);

					// zeroExt arg will be ptrToHeapToInt in Android
					BinaryOperator* addInst = BinaryOperator::Create(Instruction::Add,
							zeroExt, sizeOfHeap, "", inst);

					CastInst* upperBound = new IntToPtrInst(addInst,
							PointerType::get(IntegerType::get(M.getContext(), 8), 0), "", inst);

					funcManager.insertPrintfCall(m_pPtrToHeap, true, inst);
					funcManager.insertPrintfCall(upperBound, true, inst);

					//SandBoxWrites(&M, inst, &BB, m_pPtrToHeap, upperBound);

					// Break since current iterator is invalidated after
					// we split a basic block.
					//break;
				}

				if (isa<CallInst>(Inst))
				{
					CallInst *callInst = dyn_cast<CallInst>(Inst);
					if (funcManager.isMallocCall(callInst))
					{
						errs() << "Malloc\n";
						Value *args = funcManager.
								extractMallocArgs(callInst);
						Instruction* newInst = funcManager.replaceMallocWithMalloc(callInst, args);
						BasicBlock::iterator BI(newInst);
						Inst = BI;

					}
					if (funcManager.isFreeCall(callInst))
					{
						errs() << "Free\n";
						Value *args = funcManager.extractFreeArgs(callInst);
						Instruction* newInst = funcManager.replaceFreeWithFree(callInst, args);
						BasicBlock::iterator BI(newInst);
						Inst = BI;
					}
					if (funcManager.isMmapCall(callInst))
					{
/*						// Test for inserted AddMemoryBlock()
						AllocaInst* secBlock = new AllocaInst(
								typeManager.GetFreeMemBlockPtTy(), "secBlock", callInst);
						StoreInst *storeMmapInGvar = new StoreInst(callInst,
								m_pFreeMemBlockHead, false, callInst->getNextNode());
						CastInst* ptrCast = new PtrToIntInst(callInst,
								IntegerType::get(M.getContext(), 64), "",
								storeMmapInGvar->getNextNode());
						ConstantInt* int8192 = ConstantInt::get(M.getContext(),
								APInt(32, StringRef("8192"), 10));
						BinaryOperator* addInst = BinaryOperator::Create(Instruction::Add,
							  ptrCast, int8192, "", ptrCast->getNextNode());
						CastInst* ptr_127 = new IntToPtrInst(addInst,
								typeManager.GetFreeMemBlockPtTy(), "", addInst->getNextNode());
						StoreInst *last = new StoreInst(ptr_127, secBlock,
								typeManager.GetFreeMemBlockPtTy(),
								false, ptr_127->getNextNode());
						LoadInst *load = new LoadInst(secBlock, "", false, last->getNextNode());
						funcManager.insertAddMemoryBlockCall(load->getNextNode(), load);*/
					}
				}
			}
		}
	}
	return false;
}

/*** Function summary - SandboxWritesPass::SandBoxWrites ***
Takes in a module and an instruction, and inserts a call to mmap()
before the given instruction.

@Inputs:
- pMod: pointer to a Module
- inst: pointer to a (store) instruction
- BB: address of a basic block iterator
- upperBound: upper address bound to allow memory writes
- lowerBound: lower address bound to allow memory writes

@brief
An if statement is wrapped around the (store) instruction, and the
write only takes place if it is within the upper/lower bound address
range

@Outputs:
- none
*/
// TODO: Currently not using arguments upperBound and lowerBound
// Eventually these will be used for the address bounds, and
// not the dummy address range defined inside the function
void SandboxWritesPass::SandBoxWrites(Module *pMod, StoreInst* inst, Function::iterator *BB,
		Value* lowerBound, Value* upperBound)
{
	// For now use void ptr type to store memory addresses
	PointerType* voidPtrType = PointerType::get(IntegerType::get(pMod->getContext(), 8), 0);

	// this is the address that will be compared (i.e. is it > and < some range)
	CastInst *intAddrToVoid = new BitCastInst(inst->getOperand(1), voidPtrType,
			"", inst);

	// First if statement (i.e. if address >= X)
	ICmpInst *cmpInst = new ICmpInst(inst,
			CmpInst::Predicate::ICMP_SGE, intAddrToVoid, lowerBound, "");
	TerminatorInst *outerIfTerm = SplitBlockAndInsertIfThen(cmpInst,
			inst, false);
	BasicBlock* outerIfBB = outerIfTerm->getParent();

	// Second if statement (i.e. if address <= Y)
	ICmpInst *cmpInst2 = new ICmpInst(outerIfTerm,
			CmpInst::Predicate::ICMP_SLE, intAddrToVoid, upperBound, "");
	BasicBlock* innerIfBB = outerIfBB->splitBasicBlock(outerIfTerm->getIterator());

	// BB iterator is new pointing at the "Tail" of the original BasicBlock that was split:
	// Head > If (then), else goto Tail > if (then), else goto Tail > Tail
	*BB = inst->getParent()->getIterator();

	// the TerminatorInst of the outerIfBlock changed after we split it
	outerIfTerm = outerIfBB->getTerminator();
	TerminatorInst *newOuterIfTerm = BranchInst::Create(/*ifTrue*/innerIfBB,
			/*ifFalse*/dyn_cast<BasicBlock>(*BB), cmpInst2);
	ReplaceInstWithInst(outerIfTerm, newOuterIfTerm);

	// On the next iteration of the for loop, BB iterator will increment,
	// so we decrement here since we want to apply this same algorithm
	// on other store instructions in the "Tail" basic block
	// (before the decrement BB was pointing to Tail)
	(*BB)--;
	inst->removeFromParent();
	inst->insertBefore(innerIfBB->getTerminator());

	// For testing, write a value to the variable  that we
	// put inside the "if" statement
	Constant *const_int = ConstantInt::get(Type::getInt32Ty(pMod->getContext()),
			1234, true);

	StoreInst *store_inst2 = new StoreInst(const_int, inst->getOperand(1),
			innerIfBB->getTerminator());

}

void SandboxWritesPass::InsertGlobalVars(Module *pMod, TypeManager* typeManager)
{
	/*Head of free memory linked list*/
	m_pFreeMemBlockHead = new GlobalVariable(/*Module=*/*pMod,
			 /*Type=*/typeManager->GetFreeMemBlockPtTy(),
			 /*isConstant=*/false,
			 /*Linkage=*/GlobalValue::ExternalLinkage,
			 /*Initializer=*/0, // has initializer, specified below
			 /*Name=*/"llvm_head");
	m_pFreeMemBlockHead->setAlignment(8);
	m_pFreeMemBlockHead->setInitializer(typeManager->GetFreeMemBlockNull());

	/*Boolean to keep track if mem has been alloced*/
	m_pHaveAllocedMem = new GlobalVariable(/*Module=*/*pMod,
			 /*Type=*/IntegerType::get(pMod->getContext(), 32),
			 /*isConstant=*/false,
			 /*Linkage=*/GlobalValue::ExternalLinkage,
			 /*Initializer=*/0, // has initializer, specified below
			 /*Name=*/"llvm_haveAllocedMem");
	m_pHaveAllocedMem->setAlignment(4);
	ConstantInt* const_int32_val0 = ConstantInt::get(pMod->getContext(),
			APInt(32, StringRef("0"), 10));
	m_pHaveAllocedMem->setInitializer(const_int32_val0);

	/* Size of sfi heap*/
	m_pSizeOfHeap = new GlobalVariable(/*Module=*/*pMod,
	/*Type=*/IntegerType::get(pMod->getContext(), 64),
	/*isConstant=*/false,
	/*Linkage=*/GlobalValue::ExternalLinkage,
	/*Initializer=*/0, // has initializer, specified below
	/*Name=*/"llvm_sizeOfHeap");
	m_pSizeOfHeap->setAlignment(8);
	ConstantInt* const_int64_22 = ConstantInt::get(pMod->getContext(),
		 APInt(64, StringRef("20480"), 10));
	m_pSizeOfHeap->setInitializer(const_int64_22);

	/* Pointer to beginning of sfi heap */
	PointerType* voidPtrType = PointerType::get(IntegerType::get(pMod->getContext(), 8), 0);
	m_pPtrToHeap = new GlobalVariable(/*Module=*/*pMod,
	/*Type=*/voidPtrType,
	/*isConstant=*/false,
	/*Linkage=*/GlobalValue::ExternalLinkage,
	/*Initializer=*/0, // has initializer, specified below
	/*Name=*/"llvm_ptrToHeap");
	m_pPtrToHeap->setAlignment(8);
	ConstantPointerNull* nullForVoidPtr = ConstantPointerNull::get(voidPtrType);
	m_pPtrToHeap->setInitializer(nullForVoidPtr);
}

char SandboxWritesPass::ID = 0;

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerSandboxWritesPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new SandboxWritesPass());
}
static RegisterStandardPasses
  RegisterMyPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
                 registerSandboxWritesPass);

static RegisterStandardPasses
    RegisterMyPass0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerSandboxWritesPass);
