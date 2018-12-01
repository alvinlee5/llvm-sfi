/*
 * FunctionManager.hpp
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
using namespace llvm;


#ifndef LIB_TRANSFORMS_SANDBOXWRITES_FUNCTIONMANAGER_HPP_
#define LIB_TRANSFORMS_SANDBOXWRITES_FUNCTIONMANAGER_HPP_

class FunctionManager
{
	public:
		FunctionManager(Module *mod);
		AllocaInst* insertMmapCall(Module *M, Instruction *inst);
		Function* getMmapFunction();
		void testFunction();

	//members
	private:
		Function *m_pFuncMmap;

	// helpers
	private:


};



#endif /* LIB_TRANSFORMS_SANDBOXWRITES_FUNCTIONMANAGER_HPP_ */
