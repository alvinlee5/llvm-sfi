/*
 * FunctionManager.cpp
 */
#include "FunctionManager.hpp"

#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
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

/***Function summary - FunctionManager::insertMmapCall***
Takes in a module and an instruction, and inserts a call to mmap()
before the given instruction.
Inputs:
- inst: pointer to an instruction
The call to mmap() is inserted before inst
Outputs:
- allocVar: "address" of newly allocated memory (represented in the LLVM C++ API)
It's an "instruction", but can be simply thought of as the address of the newly
allocated memory
*/
AllocaInst* FunctionManager::insertMmapCall(Instruction *inst)
{
	 // Constant Definitions
	PointerType* voidPtrType = PointerType::get(IntegerType::get(m_pMod->getContext(), 8), 0);

/*	ConstantInt* addrToMapMem = ConstantInt::get(m_pMod->getContext(), APInt(64, StringRef("196608"), 10));
	Constant* ptrToMmapAddr = ConstantExpr::getCast(Instruction::IntToPtr, addrToMapMem, voidPtrType);*/

	ConstantPointerNull* nullPtr = ConstantPointerNull::get(voidPtrType);
	ConstantInt* bytesToAlloc = ConstantInt::get(m_pMod->getContext(),
			APInt(64, StringRef("20480" /*Hardcode to 5 pages worth of memory for now...*/), 10));
	ConstantInt* mmap_prot_arg = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("3"), 10));
	// 34 == MAP_PRIVATE|MAP_ANONYMOUS
	ConstantInt* mmap_flags_arg = ConstantInt::get(m_pMod->getContext(), APInt(32,
			StringRef("34"/*"50" 50 == MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED*/), 10));
	ConstantInt* mmap_fd_arg = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("-1"), 10));
	ConstantInt* mmap_offset_arg = ConstantInt::get(m_pMod->getContext(), APInt(64, StringRef("0"), 10));

	AllocaInst* allocVar = new AllocaInst(voidPtrType, "AllocVar", inst);
	allocVar->setAlignment(8);

	std::vector<Value*> mmapFuncParams;
	mmapFuncParams.push_back(nullPtr/*ptrToMmapAddr*/);
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
	 PAS = AttributeSet::get(m_pMod->getContext(), ~0U, B);
	}

	Attrs.push_back(PAS);
	mmap_PAL = AttributeSet::get(m_pMod->getContext(), Attrs);

	}
	mmapCallInst->setAttributes(mmap_PAL);

	// store the address returned from mmap in a newly allocated void pointer variable
	StoreInst* storeInst = new StoreInst(mmapCallInst, allocVar, false, inst);
	storeInst->setAlignment(8);

	return allocVar;
}


/*** Function summary - FunctionManager::replaceMallocWithMmap ***
Takes in an instruction, and replaces it with a call to
before the given instruction.

@Inputs:
- inst: pointer to an instruction (should be the CallInst to malloc)

@brief:
The CallInst to malloc() is replaced with a call to mmap()

@Outputs:
- mmapCallInst: The CallInst to mmap() that replaced the CallInst to malloc()
*/

// MallocArgs should also be an argument to choose size of the mapping
Instruction* FunctionManager::replaceMallocWithMmap(Instruction *inst/*, MallocArgs args*/)
{
	 // Constant Definitions
	PointerType* voidPtrType = PointerType::get(IntegerType::get(m_pMod->getContext(), 8), 0);

	// TODO: The address we map memory to should not be a constant, and the byte to alloc as well
	// Address to mmap must be read from a variable at runtime (inserting a global to keep track
	// is probably required)
	ConstantInt* addrToMapMem = ConstantInt::get(m_pMod->getContext(), APInt(64, StringRef("196608"), 10));
	Constant* ptrToMmapAddr = ConstantExpr::getCast(Instruction::IntToPtr, addrToMapMem, voidPtrType);
	ConstantInt* bytesToAlloc = ConstantInt::get(m_pMod->getContext(), APInt(64, StringRef("4"), 10));
	ConstantInt* mmap_prot_arg = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("3"), 10));
	ConstantInt* mmap_flags_arg = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("50"), 10));
	ConstantInt* mmap_fd_arg = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("-1"), 10));
	ConstantInt* mmap_offset_arg = ConstantInt::get(m_pMod->getContext(), APInt(64, StringRef("0"), 10));

	AllocaInst* pMmapAddr = new AllocaInst(voidPtrType, "pMmapAddr", inst);
	pMmapAddr->setAlignment(8);
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
			mmapFuncParams, ""/*, inst*/);
	mmapCallInst->setCallingConv(CallingConv::C);
	mmapCallInst->setTailCall(false);
	AttributeSet mmap_PAL;
	{
	SmallVector<AttributeSet, 4> Attrs;
	AttributeSet PAS;
	{
	 AttrBuilder B;
	 B.addAttribute(Attribute::NoUnwind);
	 PAS = AttributeSet::get(m_pMod->getContext(), ~0U, B);
	}

	Attrs.push_back(PAS);
	mmap_PAL = AttributeSet::get(m_pMod->getContext(), Attrs);

	}
	mmapCallInst->setAttributes(mmap_PAL);

	ReplaceInstWithInst(inst, mmapCallInst);
	return mmapCallInst;
}

Function* FunctionManager::getMmapFunction()
{
	return m_pFuncMmap;
}

bool FunctionManager::isMallocCall(CallInst* callInst)
{
	Function* funcCalled = callInst->getCalledFunction();
	if (!funcCalled)
	{
		Value* v = callInst->getCalledValue();
		Value* sv = v->stripPointerCasts();
		StringRef funcName = sv->getName();
		StringRef strMalloc("malloc");
		if (funcName.equals(strMalloc))
		{
			return true;
		}
		return false;
	}

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
	if (!funcCalled)
	{
		Value* v = callInst->getCalledValue();
		Value* sv = v->stripPointerCasts();
		StringRef funcName = sv->getName();
		StringRef strFree("free");
		if (funcName.equals(strFree))
		{
			return true;
		}
		return false;
	}

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
			Type* intType = IntegerType::get(m_pMod->getContext(), 64);
			args.isConstantArg = false;
			// Insert Variable to store the argument passed to malloc
			// This is required for the new call to mmap (size to map)
			args.allocaInst = new AllocaInst(intType, "mallocSize", callInst);
			new StoreInst(Inst, args.allocaInst, callInst);
		}
	}
	return args;
}

void FunctionManager::testFunction()
{
	printf("Test\n");
}

