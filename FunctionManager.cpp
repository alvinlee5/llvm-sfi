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

FunctionManager::FunctionManager(Module* pMod, TypeManager *pTypeManager,
		GlobalVariable *freeMemBlockHead, GlobalVariable *haveAllocedMem)
: m_pMod(pMod), m_pTypeManager(pTypeManager), m_pFreeMemBlockHead(freeMemBlockHead),
  m_pHaveAllocedMem(haveAllocedMem)
{
	declareMmap();
	declareAddMemoryBlock();
	defineAddMemoryBlock();

	declareSplitMemBlock();
	defineSplitMemBlock();

	declareRemoveMemBlock();
	defineRemoveMemBlock();
}

void FunctionManager::declareMmap()
{
	// Put function arguments into vector
	 std::vector<Type*> mmapFuncParams;
	 PointerType* voidPtrType =
			 PointerType::get(IntegerType::get(m_pMod->getContext(), 8), 0);
	 mmapFuncParams.push_back(voidPtrType);
	 mmapFuncParams.push_back(IntegerType::get(m_pMod->getContext(), 64));
	 mmapFuncParams.push_back(IntegerType::get(m_pMod->getContext(), 32));
	 mmapFuncParams.push_back(IntegerType::get(m_pMod->getContext(), 32));
	 mmapFuncParams.push_back(IntegerType::get(m_pMod->getContext(), 32));
	 mmapFuncParams.push_back(IntegerType::get(m_pMod->getContext(), 64));

	 // Create the function type, used for creating the function
	 // specifies return type, parameters, variable arguments
	 FunctionType* mmapFuncType = FunctionType::get(
	  /*Result=*/voidPtrType,
	  /*Params=*/mmapFuncParams,
	  /*isVarArg=*/false);

	 // Get or create function:
	 // If the function is already in the modules symbol table, we can just get it.
	 // Otherwise it must be declared for use (i.e. created)
	 m_pFuncMmap = m_pMod->getFunction("mmap");
	 if (!m_pFuncMmap)
	 {
		 m_pFuncMmap = Function::Create(
				  /*Type=*/mmapFuncType,
				  /*Linkage=*/GlobalValue::ExternalLinkage,
				  /*Name=*/"mmap", m_pMod); // (external, no body)
		 m_pFuncMmap->setCallingConv(CallingConv::C);
	 }

	 AttributeSet func_mmap_PAL;
	 {
	  SmallVector<AttributeSet, 4> Attrs;
	  AttributeSet PAS;
	   {
	    AttrBuilder B;
	    B.addAttribute(Attribute::NoUnwind);
	    PAS = AttributeSet::get(m_pMod->getContext(), ~0U, B);
	   }

	  Attrs.push_back(PAS);
	  func_mmap_PAL = AttributeSet::get(m_pMod->getContext(), Attrs);

	 }
	 m_pFuncMmap->setAttributes(func_mmap_PAL);
}

void FunctionManager::declareAddMemoryBlock()
{
	 std::vector<Type*>addMemBlock_Args;
	 addMemBlock_Args.push_back(m_pTypeManager->GetFreeMemBlockPtTy());
	 FunctionType* addMemBlockType = FunctionType::get(
	  /*Result=*/Type::getVoidTy(m_pMod->getContext()),
	  /*Params=*/addMemBlock_Args,
	  /*isVarArg=*/false);

	m_pFuncAddMemBlock = m_pMod->getFunction("llvm_add_memory_block");
	if (!m_pFuncAddMemBlock)
	{
		m_pFuncAddMemBlock = Function::Create(
				  /*Type=*/addMemBlockType,
				  /*Linkage=*/GlobalValue::ExternalLinkage,
				  /*Name=*/"llvm_add_memory_block", m_pMod);
		m_pFuncAddMemBlock->setCallingConv(CallingConv::C);
	}

	AttributeSet FuncAddMemBlock_PAL;
	{
		SmallVector<AttributeSet, 4> Attrs;
		AttributeSet PAS;
		{
			AttrBuilder B;
			B.addAttribute(Attribute::NoUnwind);
			B.addAttribute(Attribute::UWTable);
			PAS = AttributeSet::get(m_pMod->getContext(), ~0U, B);
		}
		Attrs.push_back(PAS);
		FuncAddMemBlock_PAL = AttributeSet::get(m_pMod->getContext(), Attrs);
	}
	m_pFuncAddMemBlock->setAttributes(FuncAddMemBlock_PAL);
}

void FunctionManager::defineAddMemoryBlock()
{
	ConstantInt* int_val_0 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("0"), 10));
	ConstantInt* int_val_1 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("1"), 10));
	ConstantInt* int_val_2 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("2"), 10));
	ConstantInt* one_bit_0 = ConstantInt::get(m_pMod->getContext(), APInt(1, StringRef("0"), 10));

	Function::arg_iterator args = m_pFuncAddMemBlock->arg_begin();
	Value *ptr_b = &(*args);
	ptr_b->setName("b");

	BasicBlock* label_22 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_23 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_24 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_25 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_26 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_27 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_28 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_29 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_30 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_31 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_32 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);
	BasicBlock* label_33 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncAddMemBlock,0);

	// Block  (label_22) - Initializes variables and checks first cond of if statement (!head)
	AllocaInst* ptr_34 = new AllocaInst(m_pTypeManager->GetFreeMemBlockPtTy(), "", label_22);
	ptr_34->setAlignment(8);
	AllocaInst* ptr_curr = new AllocaInst(m_pTypeManager->GetFreeMemBlockPtTy(), "curr", label_22);
	ptr_curr->setAlignment(8);
	StoreInst* void_35 = new StoreInst(ptr_b, ptr_34, false, label_22);
	void_35->setAlignment(8);
	LoadInst* ptr_36 = new LoadInst(ptr_34, "", false, label_22);
	ptr_36->setAlignment(8);
	GetElementPtrInst* ptr_37 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(), ptr_36,
			{int_val_0, int_val_2}, "", label_22);
	StoreInst* void_38 = new StoreInst(m_pTypeManager->GetFreeMemBlockNull(),
			ptr_37, false, label_22);
	void_38->setAlignment(8);
	LoadInst* ptr_39 = new LoadInst(ptr_34, "", false, label_22);
	ptr_39->setAlignment(8);
	GetElementPtrInst* ptr_40 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(), ptr_39,
			{int_val_0, int_val_1}, "", label_22);
	StoreInst* void_41 = new StoreInst(m_pTypeManager->GetFreeMemBlockNull(),
			ptr_40, false, label_22);
	void_41->setAlignment(8);
	LoadInst* ptr_42 = new LoadInst(m_pFreeMemBlockHead, "", false, label_22);
	ptr_42->setAlignment(8);
	ICmpInst* int1_43 = new ICmpInst(*label_22, ICmpInst::ICMP_NE, ptr_42,
			m_pTypeManager->GetFreeMemBlockNull(), "");
	BranchInst::Create(label_23, label_24, int1_43, label_22);

	// Block  (label_23) - check second condition of if statement
	// if ((unsigned long)head > (unsigned long)b)
	LoadInst* ptr_45 = new LoadInst(m_pFreeMemBlockHead, "", false, label_23);
	ptr_45->setAlignment(8);
	CastInst* int64_46 = new PtrToIntInst(ptr_45, IntegerType::get(m_pMod->getContext(), 64), "", label_23);
	LoadInst* ptr_47 = new LoadInst(ptr_34, "", false, label_23);
	ptr_47->setAlignment(8);
	CastInst* int64_48 = new PtrToIntInst(ptr_47, IntegerType::get(m_pMod->getContext(), 64), "", label_23);
	ICmpInst* int1_49 = new ICmpInst(*label_23, ICmpInst::ICMP_UGT, int64_46, int64_48, "");
	BranchInst::Create(label_24, label_27, int1_49, label_23);

	// Block  (label_24) - if (head) [inner if statement]
	LoadInst* ptr_51 = new LoadInst(m_pFreeMemBlockHead, "", false, label_24);
	ptr_51->setAlignment(8);
	ICmpInst* int1_52 = new ICmpInst(*label_24, ICmpInst::ICMP_NE, ptr_51, m_pTypeManager->GetFreeMemBlockNull(), "");
	BranchInst::Create(label_25, label_26, int1_52, label_24);

	// Block  (label_25) - head->prev = b;
	LoadInst* ptr_54 = new LoadInst(ptr_34, "", false, label_25);
	ptr_54->setAlignment(8);
	LoadInst* ptr_55 = new LoadInst(m_pFreeMemBlockHead, "", false, label_25);
	ptr_55->setAlignment(8);
	GetElementPtrInst* ptr_56 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_55, {int_val_0, int_val_2}, "", label_25);
	StoreInst* void_57 = new StoreInst(ptr_54, ptr_56, false, label_25);
	void_57->setAlignment(8);
	BranchInst::Create(label_26, label_25);

	// Block  (label_26) - b->next = head; head = b;
	LoadInst* ptr_59 = new LoadInst(m_pFreeMemBlockHead, "", false, label_26);
	ptr_59->setAlignment(8);
	LoadInst* ptr_60 = new LoadInst(ptr_34, "", false, label_26);
	ptr_60->setAlignment(8);
	GetElementPtrInst* ptr_61 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_60, {int_val_0, int_val_1}, "", label_26);
	StoreInst* void_62 = new StoreInst(ptr_59, ptr_61, false, label_26);
	void_62->setAlignment(8);
	LoadInst* ptr_63 = new LoadInst(ptr_34, "", false, label_26);
	ptr_63->setAlignment(8);
	StoreInst* void_64 = new StoreInst(ptr_63, m_pFreeMemBlockHead, false, label_26);
	void_64->setAlignment(8);
	BranchInst::Create(label_33, label_26);

	// Block  (label_27) - curr = head;
	LoadInst* ptr_66 = new LoadInst(m_pFreeMemBlockHead, "", false, label_27);
	ptr_66->setAlignment(8);
	StoreInst* void_67 = new StoreInst(ptr_66, ptr_curr, false, label_27);
	void_67->setAlignment(8);
	BranchInst::Create(label_28, label_27);

	// Block  (label_28) - if (curr->next)
	LoadInst* ptr_69 = new LoadInst(ptr_curr, "", false, label_28);
	ptr_69->setAlignment(8);
	GetElementPtrInst* ptr_70 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_69, {int_val_0, int_val_1}, "", label_28);
	LoadInst* ptr_71 = new LoadInst(ptr_70, "", false, label_28);
	ptr_71->setAlignment(8);
	ICmpInst* int1_72 = new ICmpInst(*label_28, ICmpInst::ICMP_NE, ptr_71,
			m_pTypeManager->GetFreeMemBlockNull(), "");
	BranchInst::Create(label_29, label_30, int1_72, label_28);

	// Block  (label_29) - if ((unsigned long)curr->next < (unsigned long)b)
	LoadInst* ptr_74 = new LoadInst(ptr_curr, "", false, label_29);
	ptr_74->setAlignment(8);
	GetElementPtrInst* ptr_75 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_74, {int_val_0, int_val_1}, "", label_29);
	LoadInst* ptr_76 = new LoadInst(ptr_75, "", false, label_29);
	ptr_76->setAlignment(8);
	CastInst* int64_77 = new PtrToIntInst(ptr_76, IntegerType::get(m_pMod->getContext(), 64),
			"", label_29);
	LoadInst* ptr_78 = new LoadInst(ptr_34, "", false, label_29);
	ptr_78->setAlignment(8);
	CastInst* int64_79 = new PtrToIntInst(ptr_78, IntegerType::get(m_pMod->getContext(), 64),
			"", label_29);
	ICmpInst* int1_80 = new ICmpInst(*label_29, ICmpInst::ICMP_ULT, int64_77, int64_79, "");
	BranchInst::Create(label_30, label_29);

	// Block  (label_30) - This phi node probably isn't necessary...
	PHINode* int1_82 = PHINode::Create(IntegerType::get(m_pMod->getContext(), 1),
			2, "", label_30);
	int1_82->addIncoming(one_bit_0, label_28);
	int1_82->addIncoming(int1_80, label_29);
	BranchInst::Create(label_31, label_32, int1_82, label_30);

	// Block  (label_31) - curr = curr->next
	LoadInst* ptr_84 = new LoadInst(ptr_curr, "", false, label_31);
	ptr_84->setAlignment(8);
	GetElementPtrInst* ptr_85 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_84, {int_val_0, int_val_1}, "", label_31);
	LoadInst* ptr_86 = new LoadInst(ptr_85, "", false, label_31);
	ptr_86->setAlignment(8);
	StoreInst* void_87 = new StoreInst(ptr_86, ptr_curr, false, label_31);
	void_87->setAlignment(8);
	BranchInst::Create(label_28, label_31);

	// Block  (label_32) - b->next = curr->next; curr->next = b
	LoadInst* ptr_89 = new LoadInst(ptr_curr, "", false, label_32);
	ptr_89->setAlignment(8);
	GetElementPtrInst* ptr_90 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(), ptr_89,
			{int_val_0, int_val_1}, "", label_32);
	LoadInst* ptr_91 = new LoadInst(ptr_90, "", false, label_32);
	ptr_91->setAlignment(8);
	LoadInst* ptr_92 = new LoadInst(ptr_34, "", false, label_32);
	ptr_92->setAlignment(8);
	GetElementPtrInst* ptr_93 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(), ptr_92,
			{int_val_0, int_val_1}, "", label_32);
	StoreInst* void_94 = new StoreInst(ptr_91, ptr_93, false, label_32);
	void_94->setAlignment(8);
	LoadInst* ptr_95 = new LoadInst(ptr_34, "", false, label_32);
	ptr_95->setAlignment(8);
	LoadInst* ptr_96 = new LoadInst(ptr_curr, "", false, label_32);
	ptr_96->setAlignment(8);
	GetElementPtrInst* ptr_97 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(), ptr_96,
			{int_val_0, int_val_1}, "", label_32);
	StoreInst* void_98 = new StoreInst(ptr_95, ptr_97, false, label_32);
	void_98->setAlignment(8);
	BranchInst::Create(label_33, label_32);

	// Block  (label_33)
	ReturnInst::Create(m_pMod->getContext(), label_33);

}

// This is just used for testing.
CallInst* FunctionManager::insertAddMemoryBlockCall(Instruction *inst, Value *param)
{
	CallInst* addMemBlockCall = CallInst::Create(m_pFuncAddMemBlock, param, "", inst);
	addMemBlockCall->setCallingConv(CallingConv::C);
	addMemBlockCall->setTailCall(false);
	AttributeSet addMemBlockCall_PAL;
	addMemBlockCall->setAttributes(addMemBlockCall_PAL);
	return addMemBlockCall;
}

void FunctionManager::declareSplitMemBlock()
{
	std::vector<Type*>splitMemBlock_Args;
	splitMemBlock_Args.push_back(m_pTypeManager->GetFreeMemBlockPtTy());
	splitMemBlock_Args.push_back(IntegerType::get(m_pMod->getContext(), 64));
	FunctionType* splitMemBlockType = FunctionType::get(
	/*Result=*/m_pTypeManager->GetFreeMemBlockPtTy(),
	/*Params=*/splitMemBlock_Args,
	/*isVarArg=*/false);

	m_pFuncSplitMemBlock = m_pMod->getFunction("llvm_split_memory_block");
	if (!m_pFuncSplitMemBlock)
	{
		m_pFuncSplitMemBlock = Function::Create(
				  /*Type=*/splitMemBlockType,
				  /*Linkage=*/GlobalValue::ExternalLinkage,
				  /*Name=*/"llvm_split_memory_block", m_pMod);
		m_pFuncSplitMemBlock->setCallingConv(CallingConv::C);
	}
	AttributeSet func_split_PAL;
	{
		SmallVector<AttributeSet, 4> Attrs;
		AttributeSet PAS;
		{
			AttrBuilder B;
			B.addAttribute(Attribute::NoUnwind);
			B.addAttribute(Attribute::UWTable);
			PAS = AttributeSet::get(m_pMod->getContext(), ~0U, B);
		}

		Attrs.push_back(PAS);
		func_split_PAL = AttributeSet::get(m_pMod->getContext(), Attrs);
	}
	m_pFuncSplitMemBlock->setAttributes(func_split_PAL);
}

void FunctionManager::defineSplitMemBlock()
{
	PointerType* voidPtrType =
		 PointerType::get(IntegerType::get(m_pMod->getContext(), 8), 0);
	ConstantInt* int_val_0 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("0"), 10));
	// This is the size of block_t, need to be careful in case we change the structure and the
	// size of the struct changes.
	ConstantInt* int_val_24 = ConstantInt::get(m_pMod->getContext(), APInt(64, StringRef("24"), 10));

	Function::arg_iterator args = m_pFuncSplitMemBlock->arg_begin();
	Value* ptr_b = &(*args);
	ptr_b->setName("b");
	args++;
	Value *size = &(*args);
	size->setName("size");

	BasicBlock* label_12 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncSplitMemBlock,0);

	// Block  (label_12)
	AllocaInst* ptr_13 = new AllocaInst(m_pTypeManager->GetFreeMemBlockPtTy(), "", label_12);
	ptr_13->setAlignment(8);
	AllocaInst* ptr_14 = new AllocaInst(IntegerType::get(m_pMod->getContext(), 64), "", label_12);
	ptr_14->setAlignment(8);
	AllocaInst* ptr_mem_block = new AllocaInst(voidPtrType, "mem_block", label_12);
	ptr_mem_block->setAlignment(8);
	AllocaInst* ptr_newptr = new AllocaInst(m_pTypeManager->GetFreeMemBlockPtTy(), "newptr", label_12);
	ptr_newptr->setAlignment(8);
	StoreInst* void_15 = new StoreInst(ptr_b, ptr_13, false, label_12);
	void_15->setAlignment(8);
	StoreInst* void_16 = new StoreInst(size, ptr_14, false, label_12);
	void_16->setAlignment(8);
	LoadInst* ptr_17 = new LoadInst(ptr_13, "", false, label_12);
	ptr_17->setAlignment(8);
	CastInst* int64_18 = new PtrToIntInst(ptr_17, IntegerType::get(m_pMod->getContext(), 64), "", label_12);
	BinaryOperator* int64_19 = BinaryOperator::Create(Instruction::Add, int64_18, int_val_24, "", label_12);
	CastInst* ptr_20 = new IntToPtrInst(int64_19, voidPtrType, "", label_12);
	StoreInst* void_21 = new StoreInst(ptr_20, ptr_mem_block, false, label_12);
	void_21->setAlignment(8);
	LoadInst* ptr_22 = new LoadInst(ptr_mem_block, "", false, label_12);
	ptr_22->setAlignment(8);
	CastInst* int64_23 = new PtrToIntInst(ptr_22, IntegerType::get(m_pMod->getContext(), 64), "", label_12);
	LoadInst* int64_24 = new LoadInst(ptr_14, "", false, label_12);
	int64_24->setAlignment(8);
	BinaryOperator* int64_25 = BinaryOperator::Create(Instruction::Add, int64_23, int64_24, "", label_12);
	CastInst* ptr_26 = new IntToPtrInst(int64_25, m_pTypeManager->GetFreeMemBlockPtTy(), "", label_12);
	StoreInst* void_27 = new StoreInst(ptr_26, ptr_newptr, false, label_12);
	void_27->setAlignment(8);
	LoadInst* ptr_28 = new LoadInst(ptr_13, "", false, label_12);
	ptr_28->setAlignment(8);
	GetElementPtrInst* ptr_29 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_28, {int_val_0, int_val_0}, "", label_12);
	LoadInst* int64_30 = new LoadInst(ptr_29, "", false, label_12);
	int64_30->setAlignment(8);
	LoadInst* int64_31 = new LoadInst(ptr_14, "", false, label_12);
	int64_31->setAlignment(8);
	BinaryOperator* int64_32 = BinaryOperator::Create(Instruction::Add, int64_31, int_val_24, "", label_12);
	BinaryOperator* int64_33 = BinaryOperator::Create(Instruction::Sub, int64_30, int64_32, "", label_12);
	LoadInst* ptr_34 = new LoadInst(ptr_newptr, "", false, label_12);
	ptr_34->setAlignment(8);
	GetElementPtrInst* ptr_35 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_34, {int_val_0, int_val_0}, "", label_12);
	StoreInst* void_36 = new StoreInst(int64_33, ptr_35, false, label_12);
	void_36->setAlignment(8);
	LoadInst* int64_37 = new LoadInst(ptr_14, "", false, label_12);
	int64_37->setAlignment(8);
	LoadInst* ptr_38 = new LoadInst(ptr_13, "", false, label_12);
	ptr_38->setAlignment(8);
	GetElementPtrInst* ptr_39 = GetElementPtrInst::Create(m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_38, {int_val_0, int_val_0}, "", label_12);
	StoreInst* void_40 = new StoreInst(int64_37, ptr_39, false, label_12);
	void_40->setAlignment(8);
	LoadInst* ptr_41 = new LoadInst(ptr_newptr, "", false, label_12);
	ptr_41->setAlignment(8);
	ReturnInst::Create(m_pMod->getContext(), ptr_41, label_12);

}

void FunctionManager::declareRemoveMemBlock()
{
	std::vector<Type*>removeMemBlock_Args;
	removeMemBlock_Args.push_back(m_pTypeManager->GetFreeMemBlockPtTy());
	FunctionType* removeMemBlockTy = FunctionType::get(
	/*Result=*/Type::getVoidTy(m_pMod->getContext()),
	/*Params=*/removeMemBlock_Args,
	/*isVarArg=*/false);

	m_pFuncRemovemMemBlock = m_pMod->getFunction("llvm_remove_memory_block");
	if (!m_pFuncRemovemMemBlock) {
		m_pFuncRemovemMemBlock = Function::Create(
		/*Type=*/removeMemBlockTy,
		/*Linkage=*/GlobalValue::ExternalLinkage,
		/*Name=*/"llvm_remove_memory_block", m_pMod);
		m_pFuncRemovemMemBlock->setCallingConv(CallingConv::C);
	}
	AttributeSet func_fl_remove_PAL;
	{
		SmallVector<AttributeSet, 4> Attrs;
		AttributeSet PAS;
		{
			AttrBuilder B;
			B.addAttribute(Attribute::NoUnwind);
			B.addAttribute(Attribute::UWTable);
			PAS = AttributeSet::get(m_pMod->getContext(), ~0U, B);
		}

		Attrs.push_back(PAS);
		func_fl_remove_PAL = AttributeSet::get(m_pMod->getContext(), Attrs);

	}
	m_pFuncRemovemMemBlock->setAttributes(func_fl_remove_PAL);
}

void FunctionManager::defineRemoveMemBlock()
{
	ConstantInt* int_val_0 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("0"), 10));
	ConstantInt* int_val_1 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("1"), 10));
	ConstantInt* int_val_2 = ConstantInt::get(m_pMod->getContext(), APInt(32, StringRef("2"), 10));

	Function::arg_iterator args = m_pFuncRemovemMemBlock->arg_begin();
	Value* ptr_b_45 = &(*args);
	ptr_b_45->setName("b");

	BasicBlock* label_46 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_47 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_48 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_49 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_50 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_51 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_52 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_53 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);
	BasicBlock* label_54 = BasicBlock::Create(m_pMod->getContext(), "",m_pFuncRemovemMemBlock,0);

	// Block  (label_46)
	AllocaInst* ptr_55 = new AllocaInst(m_pTypeManager->GetFreeMemBlockPtTy(), "", label_46);
	ptr_55->setAlignment(8);
	StoreInst* void_56 = new StoreInst(ptr_b_45, ptr_55, false, label_46);
	void_56->setAlignment(8);
	LoadInst* ptr_57 = new LoadInst(ptr_55, "", false, label_46);
	ptr_57->setAlignment(8);
	GetElementPtrInst* ptr_58 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_57, {int_val_0, int_val_2}, "", label_46);
	LoadInst* ptr_59 = new LoadInst(ptr_58, "", false, label_46);
	ptr_59->setAlignment(8);
	ICmpInst* int1_60 = new ICmpInst(*label_46, ICmpInst::ICMP_NE, ptr_59,
			m_pTypeManager->GetFreeMemBlockNull(), "");
	BranchInst::Create(label_51, label_47, int1_60, label_46);

	// Block  (label_47)
	LoadInst* ptr_62 = new LoadInst(ptr_55, "", false, label_47);
	ptr_62->setAlignment(8);
	GetElementPtrInst* ptr_63 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_62, {int_val_0, int_val_1}, "", label_47);
	LoadInst* ptr_64 = new LoadInst(ptr_63, "", false, label_47);
	ptr_64->setAlignment(8);
	ICmpInst* int1_65 = new ICmpInst(*label_47, ICmpInst::ICMP_NE, ptr_64,
			m_pTypeManager->GetFreeMemBlockNull(), "");
	BranchInst::Create(label_48, label_49, int1_65, label_47);

	// Block  (label_48)
	LoadInst* ptr_67 = new LoadInst(ptr_55, "", false, label_48);
	ptr_67->setAlignment(8);
	GetElementPtrInst* ptr_68 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_67, {int_val_0, int_val_1}, "", label_48);
	LoadInst* ptr_69 = new LoadInst(ptr_68, "", false, label_48);
	ptr_69->setAlignment(8);
	StoreInst* void_70 = new StoreInst(ptr_69, m_pFreeMemBlockHead, false, label_48);
	void_70->setAlignment(8);
	BranchInst::Create(label_50, label_48);

	// Block  (label_49)
	StoreInst* void_72 = new StoreInst(m_pTypeManager->GetFreeMemBlockNull(), m_pFreeMemBlockHead, false, label_49);
	void_72->setAlignment(8);
	BranchInst::Create(label_50, label_49);

	// Block  (label_50)
	BranchInst::Create(label_52, label_50);

	// Block  (label_51)
	LoadInst* ptr_75 = new LoadInst(ptr_55, "", false, label_51);
	ptr_75->setAlignment(8);
	GetElementPtrInst* ptr_76 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_75, {int_val_0, int_val_1}, "", label_51);
	LoadInst* ptr_77 = new LoadInst(ptr_76, "", false, label_51);
	ptr_77->setAlignment(8);
	LoadInst* ptr_78 = new LoadInst(ptr_55, "", false, label_51);
	ptr_78->setAlignment(8);
	GetElementPtrInst* ptr_79 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_78, {int_val_0, int_val_2}, "", label_51);
	LoadInst* ptr_80 = new LoadInst(ptr_79, "", false, label_51);
	ptr_80->setAlignment(8);
	GetElementPtrInst* ptr_81 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_80, {int_val_0, int_val_1}, "", label_51);
	StoreInst* void_82 = new StoreInst(ptr_77, ptr_81, false, label_51);
	void_82->setAlignment(8);
	BranchInst::Create(label_52, label_51);

	// Block  (label_52)
	LoadInst* ptr_84 = new LoadInst(ptr_55, "", false, label_52);
	ptr_84->setAlignment(8);
	GetElementPtrInst* ptr_85 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_84, {int_val_0, int_val_1}, "", label_52);
	LoadInst* ptr_86 = new LoadInst(ptr_85, "", false, label_52);
	ptr_86->setAlignment(8);
	ICmpInst* int1_87 = new ICmpInst(*label_52, ICmpInst::ICMP_NE, ptr_86, m_pTypeManager->GetFreeMemBlockNull(), "");
	BranchInst::Create(label_53, label_54, int1_87, label_52);

	// Block  (label_53)
	LoadInst* ptr_89 = new LoadInst(ptr_55, "", false, label_53);
	ptr_89->setAlignment(8);
	GetElementPtrInst* ptr_90 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_89, {int_val_0, int_val_2}, "", label_53);
	LoadInst* ptr_91 = new LoadInst(ptr_90, "", false, label_53);
	ptr_91->setAlignment(8);
	LoadInst* ptr_92 = new LoadInst(ptr_55, "", false, label_53);
	ptr_92->setAlignment(8);
	GetElementPtrInst* ptr_93 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_92, {int_val_0, int_val_1}, "", label_53);
	LoadInst* ptr_94 = new LoadInst(ptr_93, "", false, label_53);
	ptr_94->setAlignment(8);
	GetElementPtrInst* ptr_95 = GetElementPtrInst::Create(
			m_pTypeManager->GetFreeMemBlockStructTy(),
			ptr_94, {int_val_0, int_val_2}, "", label_53);
	StoreInst* void_96 = new StoreInst(ptr_91, ptr_95, false, label_53);
	void_96->setAlignment(8);
	BranchInst::Create(label_54, label_53);

	// Block  (label_54)
	ReturnInst::Create(m_pMod->getContext(), label_54);
}

/***Function summary - FunctionManager::insertMmapCall***
Takes in a module and an instruction, and inserts a call to mmap()
before the given instruction.
Inputs:
- inst: pointer to an instruction
The call to mmap() is inserted before inst
Outputs:
- mmapCallInst: "address" of newly allocated memory (represented in the LLVM C++ API)
It's an "instruction", but can be simply thought of as the address of the newly
allocated memory. Effectively it's what the mmap called returned.
*/

CallInst* FunctionManager::insertMmapCall(Instruction *inst)
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

/*	// store the address returned from mmap in a newly allocated void pointer variable
	StoreInst* storeInst = new StoreInst(mmapCallInst, allocVar, false, inst);
	storeInst->setAlignment(8);*/

	return mmapCallInst;
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

bool FunctionManager::isMmapCall(CallInst *callInst)
{
	Function* funcCalled = callInst->getCalledFunction();
	if (!funcCalled)
	{
		Value* v = callInst->getCalledValue();
		Value* sv = v->stripPointerCasts();
		StringRef funcName = sv->getName();
		StringRef strMmap("mmap");
		if (funcName.equals(strMmap))
		{
			return true;
		}
		return false;
	}

	StringRef funcName = funcCalled->getName();
	StringRef strMmap("mmap");
	if (funcName.equals(strMmap))
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

