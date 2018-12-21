/*
 * FunctionManager.cpp
 */
#include "FunctionManager.hpp"

#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/CallSite.h"
#include <stdio.h>

using namespace llvm;

FunctionManager::FunctionManager(Module *mod)
{
	m_pMod = mod;
	// Put function arguments into vector
	 std::vector<Type*> mmapFuncParams;
	 PointerType* voidPtrType =
			 PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
	 mmapFuncParams.push_back(voidPtrType);
	 mmapFuncParams.push_back(IntegerType::get(mod->getContext(), 64));
	 mmapFuncParams.push_back(IntegerType::get(mod->getContext(), 32));
	 mmapFuncParams.push_back(IntegerType::get(mod->getContext(), 32));
	 mmapFuncParams.push_back(IntegerType::get(mod->getContext(), 32));
	 mmapFuncParams.push_back(IntegerType::get(mod->getContext(), 64));

	 // Create the function type, used for creating the function
	 // specifies return type, parameters, variable arguments
	 FunctionType* mmapFuncType = FunctionType::get(
	  /*Result=*/voidPtrType,
	  /*Params=*/mmapFuncParams,
	  /*isVarArg=*/false);

	 // Get or create function:
	 // If the function is already in the modules symbol table, we can just get it.
	 // Otherwise it must be declared for use (i.e. created)
	 m_pFuncMmap = mod->getFunction("mmap");
	 if (!m_pFuncMmap)
	 {
		 m_pFuncMmap = Function::Create(
				  /*Type=*/mmapFuncType,
				  /*Linkage=*/GlobalValue::ExternalLinkage,
				  /*Name=*/"mmap", mod); // (external, no body)
		 m_pFuncMmap->setCallingConv(CallingConv::C);
	 }

	 AttributeSet func_mmap_PAL;
	 {
	  SmallVector<AttributeSet, 4> Attrs;
	  AttributeSet PAS;
	   {
	    AttrBuilder B;
	    B.addAttribute(Attribute::NoUnwind);
	    PAS = AttributeSet::get(mod->getContext(), ~0U, B);
	   }

	  Attrs.push_back(PAS);
	  func_mmap_PAL = AttributeSet::get(mod->getContext(), Attrs);

	 }
	 m_pFuncMmap->setAttributes(func_mmap_PAL);

}

/*** Function summary - FunctionManager::insertMmapCall ***
Takes in a module and an instruction, and inserts a call to mmap()
before the given instruction.

@Inputs:
- pMod: pointer to a Module
- inst: pointer to an instruction

@brief:
The call to mmap() is inserted before inst

@Outputs:
- allocVar: "address" of newly allocated memory (represented in the LLVM C++ API)
It's an "instruction", but can be simply thought of as the address of the newly
allocated memory

*/
AllocaInst* FunctionManager::insertMmapCall(Module *pMod, Instruction *inst)
{
	 // Constant Definitions
	PointerType* voidPtrType = PointerType::get(IntegerType::get(pMod->getContext(), 8), 0);

	// TODO: The address we map memory to should not be a constant
	ConstantInt* addrToMapMem = ConstantInt::get(pMod->getContext(), APInt(64, StringRef("196608"), 10));
	Constant* ptrToMmapAddr = ConstantExpr::getCast(Instruction::IntToPtr, addrToMapMem, voidPtrType);
	ConstantInt* bytesToAlloc = ConstantInt::get(pMod->getContext(), APInt(64, StringRef("4"), 10));
	ConstantInt* mmap_prot_arg = ConstantInt::get(pMod->getContext(), APInt(32, StringRef("3"), 10));
	ConstantInt* mmap_flags_arg = ConstantInt::get(pMod->getContext(), APInt(32, StringRef("50"), 10));
	ConstantInt* mmap_fd_arg = ConstantInt::get(pMod->getContext(), APInt(32, StringRef("-1"), 10));
	ConstantInt* mmap_offset_arg = ConstantInt::get(pMod->getContext(), APInt(64, StringRef("0"), 10));

	// TODO: The final pointer type we cast to is not always int, likely need to get the type
	// from the malloc/new inst or the AllocInst that's originally being stored to...
	PointerType* intPtrType = PointerType::get(IntegerType::get(pMod->getContext(), 32), 0);

	AllocaInst* pMmapAddr = new AllocaInst(voidPtrType, "pMmapAddr", inst);
	pMmapAddr->setAlignment(8);
	AllocaInst* allocVar = new AllocaInst(intPtrType, "AllocVar", inst);
	allocVar->setAlignment(8);
	StoreInst* void_17 = new StoreInst(ptrToMmapAddr, pMmapAddr, false, inst);
	void_17->setAlignment(8);
	LoadInst* mmapAddr = new LoadInst(pMmapAddr, "", false, inst);
	mmapAddr->setAlignment(8);
	std::vector<Value*> mmapFuncParams;
	mmapFuncParams.push_back(mmapAddr);
	mmapFuncParams.push_back(bytesToAlloc);
	mmapFuncParams.push_back(mmap_prot_arg);
	mmapFuncParams.push_back(mmap_flags_arg);
	mmapFuncParams.push_back(mmap_fd_arg);
	mmapFuncParams.push_back(mmap_offset_arg);
	CallInst* mmapCallInst = CallInst::Create(m_pFuncMmap,
			mmapFuncParams, "", inst);
	mmapCallInst->setCallingConv(CallingConv::C);
	mmapCallInst->setTailCall(false);
	AttributeSet mmap_PAL;
	{
	SmallVector<AttributeSet, 4> Attrs;
	AttributeSet PAS;
	{
	 AttrBuilder B;
	 B.addAttribute(Attribute::NoUnwind);
	 PAS = AttributeSet::get(pMod->getContext(), ~0U, B);
	}

	Attrs.push_back(PAS);
	mmap_PAL = AttributeSet::get(pMod->getContext(), Attrs);

	}
	mmapCallInst->setAttributes(mmap_PAL);

	// cast the result of the mmap call from void pointer type to int pointer type
	CastInst* castedAddress = new BitCastInst(mmapCallInst, intPtrType, "", inst);

	// store the address returned from mmap in a newly allocated integer pointer variable
	StoreInst* storeInst = new StoreInst(castedAddress, allocVar, false, inst);
	storeInst->setAlignment(8);

	return allocVar;
}

Function* FunctionManager::getMmapFunction()
{
	return m_pFuncMmap;
}

bool FunctionManager::isMallocCall(CallInst* callInst)
{
	Function* funcCalled = callInst->getCalledFunction();
	StringRef funcName = funcCalled->getName();
	StringRef strMalloc("malloc");
	if (funcName.equals(strMalloc))
	{
		return true;
	}
	return false;
}

bool FunctionManager::isFreeCall(CallInst* callInst)
{
	Function* funcCalled = callInst->getCalledFunction();
	StringRef funcName = funcCalled->getName();
	StringRef strFree("free");
	if (funcName.equals(strFree))
	{
		return true;
	}
	return false;
}

FunctionManager::MallocArgs FunctionManager::extractMallocArgs(CallInst *callInst)
{
	MallocArgs args;
	CallSite CS(callInst);
	for (auto arg = CS.arg_begin(); arg != CS.arg_end(); arg++)
	{
		printf("Count\n");

		// For constant args, cast to ConstantInt. Pass this
		// value into call to mmap()
		if (ConstantInt* CI = dyn_cast<ConstantInt>(arg))
		{
			args.isConstantArg = true;
			args.constArg = CI;
		}
		// For non-const args, cast to Inst. Load the value from
		// this inst (then store it), and pass the loaded value
		// into call to mmap()
		else if (Instruction* Inst = dyn_cast<Instruction>(arg))
		{
			 // Constant Definitions
			PointerType* intPtrType = PointerType::get(IntegerType::get(m_pMod->getContext(), 32), 0);
			args.isConstantArg = false;
			args.allocaInst = new AllocaInst(intPtrType, "mallocSize", callInst);
			printf("%p\n", args.allocaInst);
		}
	}
	return args;
}











void FunctionManager::testFunction()
{
	printf("Test\n");
}

