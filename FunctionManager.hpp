/*
 * FunctionManager.hpp
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "TypeManager.hpp"
using namespace llvm;


#ifndef LIB_TRANSFORMS_SANDBOXWRITES_FUNCTIONMANAGER_HPP_
#define LIB_TRANSFORMS_SANDBOXWRITES_FUNCTIONMANAGER_HPP_

class FunctionManager
{
	// Private by default, might need to specify public
	public:
		struct MallocArgs
		{
			// Union because the argument is either constant or not
			// If not, we will store the value in a newly alloc'd variable
			union
			{
				ConstantInt* constArg;
				Instruction* allocaInst; // will be an allocInst
			};
			bool isConstantArg;
		};

	public:
		FunctionManager(Module *pMod, TypeManager *pTypeManager,
				GlobalVariable *freeMemBlockHead, GlobalVariable *haveAllocedMem);

		// mmap related functions
		Instruction* replaceMallocWithMmap(Instruction *inst);
		Function* getMmapFunction();
		CallInst* insertMmapCall(Instruction *inst);

		// Malloc related calls
		bool isMallocCall(CallInst *callInst);
		bool isFreeCall(CallInst *callInst);
		bool isMmapCall(CallInst *callInst); // for debugging
		MallocArgs extractMallocArgs(CallInst *callInst);

		// custom malloc functions
		CallInst* insertAddMemoryBlockCall(Instruction *inst, Value *param);

		void testFunction();

	//members
	private:
		Function *m_pFuncMmap;
		Module *m_pMod;
		TypeManager* m_pTypeManager;

		// custom malloc functions
		Function* m_pFuncAddMemBlock;

		// Globals we need access to (makes sense to put them here?)
	    GlobalVariable *m_pFreeMemBlockHead;
	    GlobalVariable *m_pHaveAllocedMem;

	// helpers
	private:
		void declareMmap();
		void declareAddMemoryBlock();
		void defineAddMemoryBlock();
};



#endif /* LIB_TRANSFORMS_SANDBOXWRITES_FUNCTIONMANAGER_HPP_ */
