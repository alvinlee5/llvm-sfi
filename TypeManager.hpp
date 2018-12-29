/*
 * TypeManager.hpp
 */
#ifndef LIB_TRANSFORMS_SANDBOXWRITES_TYPEMANAGER_HPP_
#define LIB_TRANSFORMS_SANDBOXWRITES_TYPEMANAGER_HPP_


#include "llvm/IR/Module.h"
using namespace llvm;

// This class will manage/hold the "non basic" types which are inserted
// into the source code via instrumentation / a pass.

class TypeManager
{
	public:
		TypeManager(Module *mod);
		void InitFreeMemBlockTy();

	private:
		Module *m_pMod;
		PointerType *m_pFreeMemBlockPtTy;
		StructType *m_pFreeMemBlockStructTy;

};


#endif /* LIB_TRANSFORMS_SANDBOXWRITES_TYPEMANAGER_HPP_ */
