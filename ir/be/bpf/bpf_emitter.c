/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   emit assembler for a backend graph
 */
#include "bpf_emitter.h"

#include "bpf_new_nodes.h"
#include "bearch.h"
#include "beblocksched.h"
#include "beemithlp.h"
#include "beemitter.h"
#include "begnuas.h"
#include "benode.h"
#include "besched.h"
#include "gen_bpf_regalloc_if.h"
#include "gen_bpf_emitter.h"
#include "irgwalk.h"
#include "panic.h"
#include "util.h"

#include <errno.h>


static struct bpf_emitter *global_emitter = NULL;

void *bpf_get_bytecode(void)	{
	return global_emitter->insns;
}
int bpf_bytecode_size(void) {
	return global_emitter->pos;
}

void bpf_emitter_add_ret(unsigned short offset)
{
	ARR_APP1(struct bpf_insn,global_emitter->ret_jmp, offset );
}

int bpf_emitter_ret_size()
{
	return ARR_LEN(global_emitter->ret_jmp);
}

unsigned short get_bpf_emitter_ret(int pos)
{
	return global_emitter->ret_jmp[pos];
}

void bpf_emitter_fix_jmp(unsigned short src, unsigned short dst)
{
	assert(src <= dst);
	assert(dst != 0xffff);
	global_emitter->insns[src].off = dst - src;
	printf("%d -> %d fix jmp: %d\n",src, dst, dst - src);
}

static void emit(struct bpf_insn insn)
{
	global_emitter->insns[global_emitter->pos] = insn;
	global_emitter->pos++;
}

static void emit2(struct bpf_insn insn1, struct bpf_insn insn2)
{
	emit(insn1);
	emit(insn2);
}

/**
 * Emits code for a unconditional jump.
 */
static void emit_bpf_Jmp(const ir_node *node)
{
	printf("todo: emit_bpf_Jmp\n");
}

static void emit_be_IncSP(const ir_node *node)
{
	printf("todo: emit_be_IncSP\n");
}

static void emit_Return(const ir_node *node)
{
	printf("%d: goto pc+0\n", global_emitter->pos);
	emit(BPF_JMP_A(0));
	bpf_emitter_add_ret(global_emitter->pos);
}

static void emit_bpf_add(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	if (left_reg->index == dest_reg->index) {
		printf("%d: r%d += r%d\n", global_emitter->pos, dest_reg->index, right_reg->index);
		emit(BPF_ALU64_REG(BPF_ADD, dest_reg->index, right_reg->index));
	} else if (right_reg->index == dest_reg->index) {
		printf("%d: r%d += r%d\n", global_emitter->pos, dest_reg->index, left_reg->index);
		emit(BPF_ALU64_REG(BPF_ADD, dest_reg->index, left_reg->index));
	} else {
		printf("%d: r%d = r%d\n", global_emitter->pos, dest_reg->index, left_reg->index);
		emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
		printf("%d: r%d += r%d\n", global_emitter->pos, dest_reg->index, right_reg->index);
		emit(BPF_ALU64_REG(BPF_ADD, dest_reg->index, right_reg->index));
	}
}

static void emit_bpf_and(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos, dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d &= r%d\n", global_emitter->pos, dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_AND, dest_reg->index, right_reg->index));
}

static void emit_be_Copy(const ir_node *irn)
{
	arch_register_t const *const in = arch_get_irn_register_in(irn, 0);
	arch_register_t const *const out = arch_get_irn_register_out(irn, 0);
	if (in == out) {
		/* omitted Copy */
		return;
	}

	arch_register_class_t const *const cls = out->cls;
	if (cls != &bpf_reg_classes[CLASS_bpf_gp]) 
		panic("Wrong register class\n");
	
	printf("%d: r%d = r%d\n", global_emitter->pos, out->index,in->index);
	emit(BPF_ALU64_REG(BPF_MOV, out->index, in->index));
}


static void emit_bpf_FrameAddr(const ir_node *node)
{
	const bpf_member_attr_t *attr   = get_bpf_member_attr_const(node);
	int32_t             offset = attr->offset;
	arch_register_t const *const in = arch_get_irn_register_in(node, 0);
	arch_register_t const *const out = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos, out->index, in->index);
	emit(BPF_ALU64_REG(BPF_MOV, out->index, in->index));
	printf("%d: r%d += %d\n",global_emitter->pos, out->index, offset);
	emit(BPF_ALU64_IMM(BPF_ADD, out->index, offset));
}


static void emit_bpf_const(const ir_node *node)
{
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);
	const bpf_const_attr_t *attr = get_bpf_const_attr_const(node);

	if (attr->is_mapfd) {
		printf("%d: r%d = map[%lld]\n", global_emitter->pos, dest_reg->index, attr->value);
		emit2(BPF_LD_MAP_FD(dest_reg->index, attr->value));
	
	}else {

		if (attr->mode == mode_Lu) {
			if (attr->value >= 0xffffffff) {
				printf("%d: r%d = %lld\n", global_emitter->pos, dest_reg->index, attr->value);
				emit2(BPF_LD_IMM64(dest_reg->index, attr->value));
				return;
			}
			// printf("constant is %llu\n", attr->value);
		}

		
		printf("%d: r%d = %lld\n", global_emitter->pos, dest_reg->index, attr->value);
		emit(BPF_ALU64_IMM(BPF_MOV, dest_reg->index, attr->value));
	}
	
}

static void emit_bpf_call(const ir_node *node)
{
	bpf_call_attr_t *attr = get_bpf_call_attr_const(node);

	ident *id = get_entity_ident(attr->entity);

	printf("%d: call %s\n", global_emitter->pos, id);
	emit(BPF_EMIT_CALL(attr->func_id));
}

static void emit_bpf_div(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos, dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d /= r%d\n", global_emitter->pos, dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_DIV, dest_reg->index, right_reg->index));
}

static void emit_bpf_xor(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos, dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d ^= r%d\n", global_emitter->pos, dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_XOR, dest_reg->index, right_reg->index));
}

// dst_reg = *(size *) (src_reg + off)
static void emit_bpf_load(const ir_node *node)
{
	const arch_register_t *ptr_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);
	const bpf_load_attr_t *attr = get_bpf_load_attr_const(node);

	int sz = get_mode_size_bits(attr->mode);
	
	printf("%d: r%d = *(u%d *)(r%d + %d)\n", global_emitter->pos,dest_reg->index, sz, ptr_reg->index,  attr->offset);

	switch(sz) {
		case 8:
		emit(BPF_LDX_MEM(BPF_B, dest_reg->index, ptr_reg->index, attr->offset));
		break;
		case 16:
		emit(BPF_LDX_MEM(BPF_H, dest_reg->index, ptr_reg->index, attr->offset));
		break;
		case 32:
		emit(BPF_LDX_MEM(BPF_W, dest_reg->index, ptr_reg->index, attr->offset));
		break;
		case 64:
		emit(BPF_LDX_MEM(BPF_DW, dest_reg->index, ptr_reg->index, attr->offset));
		break;
		default:
		panic("load size is wrong: %d", sz);
	}
	
}

static void emit_bpf_minus(const ir_node *node)
{
	printf("minus todo\n");
}

static void emit_bpf_mul(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos,dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d *= r%d\n", global_emitter->pos,dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_MUL, dest_reg->index, right_reg->index));
}

static void emit_bpf_or(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos,dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d |= r%d\n", global_emitter->pos,dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_OR, dest_reg->index, right_reg->index));
}

static void emit_bpf_shl(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n",  global_emitter->pos,dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d >>= r%d\n",  global_emitter->pos,dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_LSH, dest_reg->index, right_reg->index));
}

static void emit_bpf_shr(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos,dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d <<= r%d\n", global_emitter->pos,dest_reg->index, right_reg->index);
	emit(BPF_ALU64_REG(BPF_RSH, dest_reg->index, right_reg->index));
}


// *(size *) (dst_reg + off) = src_reg
static void emit_bpf_store(const ir_node *node)
{
	const arch_register_t *val_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *ptr_reg = arch_get_irn_register_in(node, 2);
	const bpf_store_attr_t *attr = get_bpf_store_attr_const(node);
	printf("%d: *(u64 *)(r%d + %d) = r%d\n", global_emitter->pos,ptr_reg->index, attr->offset, val_reg->index);

	emit(BPF_STX_MEM(BPF_DW, ptr_reg->index, val_reg->index, attr->offset));
}

static void emit_bpf_sub(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("%d: r%d = r%d\n", global_emitter->pos, dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("%d: r%d -= r%d\n", global_emitter->pos,dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_SUB, dest_reg->index, right_reg->index));
}

static void emit_bpf_cmp(const ir_node *irn)
{
	// printf("emit cmp\n");
}

static void emit_bpf_condjmp(const ir_node *irn)
{
	be_cond_branch_projs_t projs = be_get_cond_branch_projs(irn);

	ir_node *const op1 = get_irn_n(irn, n_bpf_CondJmp_flags);
	assert(is_bpf_Cmp(op1));

	bpf_cmp_attr_t const *const cmp_attr = get_bpf_cmp_attr_const(op1);
	bpf_condjmp_attr_t const *const condjmp_attr = get_bpf_condjmp_attr_const(irn);

	ir_relation relation = condjmp_attr->relation;
	// if (cmp_attr->ins_permuted)
	// 	relation = get_inversed_relation(relation);

	assert(relation != ir_relation_false);
	assert(relation != ir_relation_true);

	if (be_is_fallthrough(projs.t)) {
		/* exchange both proj's so the second one can be omitted */
		ir_node *const t = projs.t;
		projs.t  = projs.f;
		projs.f  = t;
		relation = get_negated_relation(relation);
	}

	int op;
	char const *op_str;
	switch (relation & (ir_relation_less_equal_greater)) {
		case ir_relation_equal: op = BPF_JEQ; op_str = "=";break;
		case ir_relation_less:  op = BPF_JLT; op_str = "<";break;
		case ir_relation_less_equal: op = BPF_JLE; op_str = "<=";break;
		case ir_relation_greater: op = BPF_JGT; op_str = ">";break;
		case ir_relation_greater_equal: op = BPF_JGE; op_str = ">=";break;
		case ir_relation_less_greater:  op = BPF_JNE; op_str = "!=";break;
		default: panic("Cmp has unsupported relation");
	}

	if (cmp_attr->is_imm) {
		const arch_register_t *left_reg = arch_get_irn_register_in(op1, 0);
		printf("%d: if r%d %s %d goto pc+0\n", global_emitter->pos,left_reg->index, op_str, cmp_attr->imm32);
		emit(BPF_JMP_IMM(op, left_reg->index, cmp_attr->imm32, 0));
	} else {
		const arch_register_t *left_reg = arch_get_irn_register_in(op1, 0);
		const arch_register_t *right_reg = arch_get_irn_register_in(op1, 1);
		printf("%d: if r%d %s r%d goto pc+0\n", global_emitter->pos,left_reg->index, right_reg->index, cmp_attr->imm32);
		emit(BPF_JMP_REG(op, left_reg->index, right_reg->index, 0));
	}

	add_Block_fix_jmp(be_emit_get_cfop_target(projs.t), global_emitter->pos);
	printf("%d: goto pc+0\n", global_emitter->pos);
	emit(BPF_JMP_A(0));
	add_Block_fix_jmp(be_emit_get_cfop_target(projs.f), global_emitter->pos);
}

/**
 * Enters the emitter functions for handled nodes into the generic
 * pointer of an opcode.
 */
static void bpf_register_emitters(void)
{
	be_init_emitters();

	/* register all emitter functions defined in spec */
	bpf_register_spec_emitters();

	be_set_emitter(op_bpf_Add, emit_bpf_add);
	be_set_emitter(op_bpf_And, emit_bpf_and);
	be_set_emitter(op_be_Copy,         emit_be_Copy);
	be_set_emitter(op_be_CopyKeep,     emit_be_Copy);
	be_set_emitter(op_bpf_FrameAddr, emit_bpf_FrameAddr);
	be_set_emitter(op_bpf_Const, emit_bpf_const);
	be_set_emitter(op_bpf_Call, emit_bpf_call);
	be_set_emitter(op_bpf_Div, emit_bpf_div);
	be_set_emitter(op_bpf_Xor, emit_bpf_xor);
	be_set_emitter(op_bpf_Jmp, emit_bpf_Jmp);
	be_set_emitter(op_bpf_Load, emit_bpf_load);
	be_set_emitter(op_bpf_Minus, emit_bpf_minus);
	be_set_emitter(op_bpf_Mul, emit_bpf_mul);
	be_set_emitter(op_bpf_Or, emit_bpf_or);
	be_set_emitter(op_bpf_Return, emit_Return);
	be_set_emitter(op_bpf_Shl, emit_bpf_shl);
	be_set_emitter(op_bpf_Shr, emit_bpf_shr);
	be_set_emitter(op_bpf_Store, emit_bpf_store);
	be_set_emitter(op_bpf_Sub, emit_bpf_sub);
	be_set_emitter(op_bpf_Cmp, emit_bpf_cmp);
	be_set_emitter(op_bpf_CondJmp, emit_bpf_condjmp);
	/* custom emitters not provided by the spec */
}

/**
 * Walks over the nodes in a block connected by scheduling edges
 * and emits code for each node.
 */
static void bpf_emit_block(ir_node *block)
{
	be_gas_begin_block(block);
	set_Block_first_insn(block, global_emitter->pos);
	sched_foreach(block, node)
	{
		be_emit_node(node);
	}
}

void bpf_emit_function(ir_graph *irg)
{

	if (global_emitter == NULL)
		global_emitter = malloc(sizeof(struct bpf_emitter));

	global_emitter->ret_jmp = NEW_ARR_F(struct bpf_insn, 0);

	global_emitter->pos = 0;
	
	emit(BPF_ALU64_IMM(BPF_MOV, 2, 0));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -8));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -16));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -24));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -32));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -40));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -48));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -56));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -64));
	emit(BPF_STX_MEM(BPF_DW, 10, 2, -72));

	/* register all emitter functions */
	bpf_register_emitters();

	/* create the block schedule */
	ir_node **block_schedule = be_create_block_schedule(irg);

	/* emit assembler prolog */
	ir_entity *entity = get_irg_entity(irg);
	be_gas_emit_function_prolog(entity, 8, NULL);

	/* populate jump link fields with their destinations */
	ir_reserve_resources(irg, IR_RESOURCE_IRN_LINK);

	be_emit_init_cf_links(block_schedule);

	for (size_t i = 0, n = ARR_LEN(block_schedule); i < n; ++i)
	{
		ir_node *block = block_schedule[i];
		block->attr.block.fix_jmps = NEW_ARR_F(unsigned short, 0);
	}

	for (size_t i = 0, n = ARR_LEN(block_schedule); i < n; ++i)
	{
		ir_node *block = block_schedule[i];
		bpf_emit_block(block);
	}

	for (size_t i = 0, n = ARR_LEN(block_schedule); i < n; ++i)
	{
		ir_node *block = block_schedule[i];
		unsigned short offset = get_Block_first_insn(block);
		for (size_t j = 0, n = get_Block_fix_jmp_size(block); j < n; j++)
		{
			bpf_emitter_fix_jmp(get_Block_fix_jmp(block, j), offset);
		}
		DEL_ARR_F(block->attr.block.fix_jmps);
	}

	for (size_t i = 0, n = bpf_emitter_ret_size(); i< n;i++)
	{
		bpf_emitter_fix_jmp(get_bpf_emitter_ret(i), global_emitter->pos);
	}

	printf("%d: r0 = 0\n", global_emitter->pos);
	emit(BPF_ALU64_IMM(BPF_MOV, 0, 0));
	printf("%d: exit\n", global_emitter->pos);
	emit(BPF_EXIT_INSN());

	ir_free_resources(irg, IR_RESOURCE_IRN_LINK);

	be_gas_emit_function_epilog(entity);
}
