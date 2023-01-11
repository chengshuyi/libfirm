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
	printf("todo: emit_Return\n");
	emit(BPF_ALU64_IMM(BPF_MOV, 0, 0));
	emit(BPF_EXIT_INSN());
}

static void emit_bpf_add(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	if (left_reg->index == dest_reg->index) {
		printf("r%d += r%d\n", dest_reg->index, right_reg->index);
		emit(BPF_ALU64_REG(BPF_ADD, dest_reg->index, right_reg->index));
	} else if (right_reg->index == dest_reg->index) {
		printf("r%d += r%d\n", dest_reg->index, left_reg->index);
		emit(BPF_ALU64_REG(BPF_ADD, dest_reg->index, left_reg->index));
	} else {
		printf("r%d = r%d\n", dest_reg->index, left_reg->index);
		emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
		printf("r%d += r%d\n", dest_reg->index, right_reg->index);
		emit(BPF_ALU64_REG(BPF_ADD, dest_reg->index, right_reg->index));
	}
}

static void emit_bpf_and(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	printf("r%d &= r%d\n", dest_reg->index, right_reg->index);
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
	
	printf("r%d = r%d\n", out->index,in->index);
	emit(BPF_ALU64_REG(BPF_MOV, out->index, in->index));
}


static void emit_bpf_FrameAddr(const ir_node *node)
{
	const bpf_member_attr_t *attr   = get_bpf_member_attr_const(node);
	int32_t             offset = attr->offset;
	arch_register_t const *const in = arch_get_irn_register_in(node, 0);
	arch_register_t const *const out = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d + %d\n", out->index, in->index, offset);
	
	emit(BPF_ALU64_REG(BPF_MOV, out->index, in->index));
	emit(BPF_ALU64_IMM(BPF_ADD, out->index, offset));
}


static void emit_bpf_const(const ir_node *node)
{
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);
	const bpf_const_attr_t *attr = get_bpf_const_attr_const(node);
	printf("r%d = %lld\n", dest_reg->index, attr->val);
	emit(BPF_ALU64_IMM(BPF_MOV, dest_reg->index, attr->val));
}

static void emit_bpf_call(const ir_node *node)
{
	bpf_call_attr_t *attr = get_bpf_call_attr_const(node);

	ident *id = get_entity_ident(attr->entity);

	printf("call %s\n", id);
	emit(BPF_EMIT_CALL(attr->func_id));
}

static void emit_bpf_div(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d /= r%d\n", dest_reg->index, right_reg->index);
	
	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_DIV, dest_reg->index, right_reg->index));
}

static void emit_bpf_xor(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d ^= r%d\n", dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_XOR, dest_reg->index, right_reg->index));
}

// dst_reg = *(size *) (src_reg + off)
static void emit_bpf_load(const ir_node *node)
{
	const arch_register_t *ptr_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);
	const bpf_load_attr_t *attr = get_bpf_load_attr_const(node);
	printf("r%d = *(u64 *)(r%d + %d)\n", dest_reg->index, ptr_reg->index,  attr->offset);

	emit(BPF_LDX_MEM(8, dest_reg->index, ptr_reg->index, attr->offset));
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

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d *= r%d\n", dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_MUL, dest_reg->index, right_reg->index));
}

static void emit_bpf_or(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d |= r%d\n", dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_OR, dest_reg->index, right_reg->index));
}

static void emit_bpf_shl(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d >>= r%d\n", dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_LSH, dest_reg->index, right_reg->index));
}

static void emit_bpf_shr(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d <<= r%d\n", dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_RSH, dest_reg->index, right_reg->index));
}


// *(size *) (dst_reg + off) = src_reg
static void emit_bpf_store(const ir_node *node)
{
	const arch_register_t *val_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *ptr_reg = arch_get_irn_register_in(node, 2);
	const bpf_store_attr_t *attr = get_bpf_store_attr_const(node);
	printf("*(u64 *)(r%d + %d) = r%d\n", ptr_reg->index, attr->offset, val_reg->index);

	emit(BPF_STX_MEM(8, ptr_reg->index, val_reg->index, attr->offset));
}

static void emit_bpf_sub(const ir_node *node)
{
	const arch_register_t *left_reg = arch_get_irn_register_in(node, 0);
	const arch_register_t *right_reg = arch_get_irn_register_in(node, 1);
	const arch_register_t *dest_reg = arch_get_irn_register_out(node, 0);

	printf("r%d = r%d\n", dest_reg->index, left_reg->index);
	printf("r%d -= r%d\n", dest_reg->index, right_reg->index);

	emit(BPF_ALU64_REG(BPF_MOV, dest_reg->index, left_reg->index));
	emit(BPF_ALU64_REG(BPF_SUB, dest_reg->index, right_reg->index));
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
	/* custom emitters not provided by the spec */
}

/**
 * Walks over the nodes in a block connected by scheduling edges
 * and emits code for each node.
 */
static void bpf_emit_block(ir_node *block)
{
	be_gas_begin_block(block);

	sched_foreach(block, node)
	{
		be_emit_node(node);
	}
}

void bpf_emit_function(ir_graph *irg)
{

	if (global_emitter == NULL)
		global_emitter = malloc(sizeof(struct bpf_emitter));

	/* register all emitter functions */
	bpf_register_emitters();

	/* create the block schedule */
	ir_node **block_schedule = be_create_block_schedule(irg);

	/* emit assembler prolog */
	ir_entity *entity = get_irg_entity(irg);
	be_gas_emit_function_prolog(entity, 4, NULL);

	/* populate jump link fields with their destinations */
	ir_reserve_resources(irg, IR_RESOURCE_IRN_LINK);

	be_emit_init_cf_links(block_schedule);

	for (size_t i = 0, n = ARR_LEN(block_schedule); i < n; ++i)
	{
		ir_node *block = block_schedule[i];
		bpf_emit_block(block);
	}
	ir_free_resources(irg, IR_RESOURCE_IRN_LINK);

	be_gas_emit_function_epilog(entity);
}
