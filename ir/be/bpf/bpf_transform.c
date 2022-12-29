/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   code selection (transform FIRM into bpf FIRM)
 */
#include "bpf_transform.h"

#include "bpf_new_nodes.h"
#include "bpf_nodes_attr.h"
#include "beirg.h"
#include "benode.h"
#include "betranshlp.h"
#include "debug.h"
#include "gen_bpf_regalloc_if.h"
#include "ircons.h"
#include "iredges_t.h"
#include "irgmod.h"
#include "irgraph_t.h"
#include "irmode_t.h"
#include "irnode_t.h"
#include "iropt_t.h"
#include "panic.h"
#include "bpf_cconv.h"
#include "util.h"

static unsigned const reg_params[] = {
	REG_R1,
	REG_R2,
	REG_R3,
	REG_R4,
	REG_R5,
};

DEBUG_ONLY(static firm_dbg_module_t *dbg = NULL;)

typedef ir_node *(*new_binop_func)(dbg_info *dbgi, ir_node *block,
								   ir_node *left, ir_node *right);

typedef ir_node *(*new_binop_reg_func)(dbg_info *dbgi, ir_node *block, ir_node *op1, ir_node *op2);
typedef ir_node *(*new_binop_imm_func)(dbg_info *dbgi, ir_node *block, ir_node *op1, ir_entity *entity, int32_t immediate);

static ir_node *transform_const(ir_node *const node, ir_entity *const entity, ir_tarval *const value)
{
	ir_node *const block = be_transform_nodes_block(node);
	dbg_info *const dbgi = get_irn_dbg_info(node);
	return new_bd_bpf_Const(dbgi, block, entity, value);
}

static ir_node *transform_binop(ir_node *node, new_binop_func new_func)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *left = get_binop_left(node);
	ir_node *new_left = be_transform_node(left);
	ir_node *right = get_binop_right(node);
	ir_node *new_right = be_transform_node(right);

	return new_func(dbgi, new_block, new_left, new_right);
}

static ir_node *gen_helper_binop_args(ir_node *node,
									  ir_node *op1,
									  ir_node *op2,
									  new_binop_reg_func new_reg,
									  new_binop_imm_func new_imm)
{

	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *block = be_transform_nodes_block(node);

	ir_node *new_op1 = be_transform_node(op1);

	if (is_Const(op2))
	{
		int32_t const imm = get_Const_long(op2);
		return new_imm(dbgi, block, new_op1, NULL, imm);
	}

	ir_node *new_op2 = be_transform_node(op2);
	return new_reg(dbgi, block, new_op1, new_op2);
}

static ir_node *gen_And(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_And_reg);
}

static ir_node *gen_Or(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Or_reg);
}

static ir_node *gen_Eor(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Xor_reg);
}

static ir_node *gen_Div(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Div_reg);
}

static ir_node *gen_Shl(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Shl_reg);
}

static ir_node *gen_Shr(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Add_reg);
}

static ir_node *gen_Add(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Add_reg);
}

static ir_node *gen_Sub(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Sub_reg);
}

static ir_node *gen_Mul(ir_node *node)
{
	return transform_binop(node, new_bd_bpf_Mul_reg);
}

typedef ir_node *(*new_unop_func)(dbg_info *dbgi, ir_node *block, ir_node *op);

static ir_node *transform_unop(ir_node *node, int op_index, new_unop_func new_func)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *op = get_irn_n(node, op_index);
	ir_node *new_op = be_transform_node(op);

	return new_func(dbgi, new_block, new_op);
}

static ir_node *gen_Minus(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);

	if (mode_is_float(mode))
	{
		panic("eBPF doesn't support float point");
	}
	// return transform_binop(node, new_bd_bpf_Minus_reg);
	return NULL;
}

static ir_node *gen_Not(ir_node *node)
{
	panic("eBPF doesn't support Not operator, we should use if statement to construct Not operator.");
}

static ir_node *gen_Const(ir_node *node)
{
	ir_tarval *const value = get_Const_tarval(node);
	return transform_const(node, NULL, value);
}

static const arch_register_t *const caller_saves[] = {
	&bpf_registers[REG_R0],
	&bpf_registers[REG_R1],
	&bpf_registers[REG_R2],
	&bpf_registers[REG_R3],
	&bpf_registers[REG_R4],
	&bpf_registers[REG_R5],
};

static ir_node *gen_Call(ir_node *node)
{
	ir_graph *irg = get_irn_irg(node);
	ir_node *callee = get_Call_ptr(node);
	ir_node *new_block = be_transform_nodes_block(node);
	ir_node *mem = get_Call_mem(node);
	ir_node *new_mem = be_transform_node(mem);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_type *type = get_Call_type(node);
	size_t n_params = get_Call_n_params(node);
	size_t n_ress = get_method_n_ress(type);
	int in_arity = 0;

	calling_convention_t *cconv = bpf_decide_calling_convention(type, NULL);
	size_t n_param_regs = cconv->n_param_regs;

	ir_node **in = ALLOCAN(ir_node *, 5);
	arch_register_req_t const **const in_req = be_allocate_in_reqs(irg, 5);

	/* memory input */
	in_req[in_arity] = arch_memory_req;
	in[in_arity] = new_mem;
	++in_arity;

	for (size_t p = 0; p < n_params; ++p)
	{
		ir_node *value = get_Call_param(node, p);
		ir_node *new_value = be_transform_node(value);
		const reg_or_stackslot_t *param = &cconv->parameters[p];

		in[in_arity] = new_value;
		in_req[in_arity] = param->reg0->single_req;
		++in_arity;
	}

	// 1 is R0
	// 5 is R1 - R5
	unsigned out_arity = pn_bpf_Call_first_result + ARRAY_SIZE(caller_saves);
	// create call node;
	ir_node *res;
	assert(is_Const(callee));
	int32_t func_id = get_Const_long(callee);
	res = new_bd_bpf_Call_imm(dbgi, new_block, in_arity, in, in_req, out_arity, NULL, func_id);

	for (size_t o = 0; o < 6; ++o)
	{
		const arch_register_t *reg = caller_saves[o];
		arch_set_irn_register_req_out(res, pn_bpf_Call_first_result + o, reg->single_req);
	}
	set_irn_pinned(res, get_irn_pinned(node));

	bpf_free_calling_convention(cconv);
	return res;
}

typedef struct address_t {
	ir_node   *ptr;
	ir_entity *entity;
	uint16_t    offset;
} address_t;

static void match_address(ir_node *ptr, address_t *address)
{
	ir_node *base = ptr;
	uint16_t offset = 0;

	if (is_Add(base)) {
		ir_node *right = get_Add_right(base);
		if (is_Const(right)) {
			base = get_Add_left(base);
			offset = get_Const_long(right);
		}
	}
	// todo: handle Member node
	// base = ptr;
	// if (is_Member(base)) {
	// 	base = get_Member_ptr(base);
	// 	assert(is_Proj(base) && is_Start(get_Proj_pred(base)));
	// }
	// base = be_transform_node(base);

	address->ptr = base;
	address->offset = offset;
}

static ir_node *gen_Load(ir_node *node)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *ptr = get_Load_ptr(node);
	ir_node *new_ptr = be_transform_node(ptr);
	ir_node *mem = get_Load_mem(node);
	ir_node *new_mem = be_transform_node(mem);
	ir_mode *mode = get_Load_mode(node);

	if (mode_is_float(mode))
	{
		return new_bd_bpf_fLoad(dbgi, new_block, new_mem, new_ptr);
	}
	return new_bd_bpf_Load(dbgi, new_block, new_mem, new_ptr);
}

static ir_node *gen_Store(ir_node *node)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	ir_node *ptr = get_Store_ptr(node);
	ir_node *val = get_Store_value(node);
	ir_node *mem = get_Store_mem(node);
	ir_node *new_mem = be_transform_node(mem);
	ir_mode *mode = get_irn_mode(node);
	address_t address;
	match_address(ptr, &address);
	
	val = be_skip_downconv(val, false);
	if (is_Const(val)) {
		int32_t imm = get_Const_long(val);
		return new_bd_bpf_Store_imm(dbgi, new_block, new_mem, address.ptr, address.offset, imm);
	}
	val = be_transform_node(val);
	return new_bd_bpf_Store_reg(dbgi, new_block, new_mem, val, address.ptr, address.offset);
}

static ir_node *gen_Jmp(ir_node *node)
{
	ir_node *new_block = be_transform_nodes_block(node);
	dbg_info *dbgi = get_irn_dbg_info(node);
	return new_bd_bpf_Jmp(dbgi, new_block);
}

// set Start node outs
static ir_node *gen_Start(ir_node *node)
{
	be_start_out outs[N_BPF_REGISTERS] = {
		[REG_R0] = BE_START_IGNORE,
		[REG_R6] = BE_START_IGNORE,
		[REG_R7] = BE_START_IGNORE,
		[REG_R8] = BE_START_IGNORE,
		[REG_R9] = BE_START_IGNORE,
		[REG_R10] = BE_START_IGNORE,
	};

	/* function parameters in registers */
	for (size_t i = 0; i != ARRAY_SIZE(reg_params); ++i)
	{
		outs[reg_params[i]] = BE_START_REG;
	}

	ir_graph *const irg = get_irn_irg(node);
	return be_new_Start(irg, outs);
}

static ir_node *gen_Return(ir_node *node)
{
	(void)node;
	panic("eBPF doesn't support return op");
}

static ir_node *gen_Phi(ir_node *node)
{
	ir_mode *mode = get_irn_mode(node);
	const arch_register_req_t *req;
	if (be_mode_needs_gp_reg(mode))
	{
		req = &bpf_class_reg_req_gp;
	}
	else
	{
		req = arch_memory_req;
	}

	return be_transform_phi(node, req);
}

static ir_node *gen_Proj_Proj(ir_node *node)
{
	ir_node *pred = get_Proj_pred(node);
	ir_node *pred_pred = get_Proj_pred(pred);
	if (is_Start(pred_pred))
	{
		if (get_Proj_num(pred) == pn_Start_T_args)
		{
			// assume everything is passed in gp registers
			unsigned arg_num = get_Proj_num(node);
			if (arg_num >= ARRAY_SIZE(reg_params))
				panic("more than 5 arguments not supported");
			ir_graph *const irg = get_irn_irg(node);
			return be_get_Start_proj(irg, &bpf_registers[reg_params[arg_num]]);
		}
	}
	panic("No transformer for %+F -> %+F -> %+F", node, pred, pred_pred);
}

static ir_node *gen_Proj_Load(ir_node *node)
{
	ir_node *load = get_Proj_pred(node);
	ir_node *new_load = be_transform_node(load);
	switch ((pn_Load)get_Proj_num(node))
	{
	case pn_Load_M:
		return be_new_Proj(new_load, pn_bpf_Load_M);
	case pn_Load_res:
		return be_new_Proj(new_load, pn_bpf_Load_res);
	case pn_Load_X_regular:
	case pn_Load_X_except:
		panic("exception handling not supported yet");
	}
	panic("invalid Proj %+F -> %+F", node, load);
}

static ir_node *gen_Proj_Store(ir_node *node)
{
	ir_node *store = get_Proj_pred(node);
	ir_node *new_store = be_transform_node(store);
	switch ((pn_Store)get_Proj_num(node))
	{
	case pn_Store_M:
		return new_store;
	case pn_Store_X_regular:
	case pn_Store_X_except:
		panic("exception handling not supported yet");
	}
	panic("invalid Proj %+F -> %+F", node, store);
}

static ir_node *gen_Proj_Start(ir_node *node)
{
	ir_graph *const irg = get_irn_irg(node);
	unsigned const pn = get_Proj_num(node);
	// switch ((pn_Start)pn)
	// {
	// case pn_Start_M:
	// 	return be_get_Start_mem(irg);
	// case pn_Start_T_args:
	// 	return new_r_Bad(irg, mode_T);
	// case pn_Start_P_frame_base:
	// 	return be_get_Start_proj(irg, &bpf_registers[REG_SP]);
	// }
	panic("unexpected Start proj %u", pn);
}

static void bpf_register_transformers(void)
{
	be_start_transform_setup();

	be_set_transform_function(op_Add, gen_Add);
	be_set_transform_function(op_And, gen_And);
	be_set_transform_function(op_Const, gen_Const);
	be_set_transform_function(op_Call, gen_Call);
	be_set_transform_function(op_Div, gen_Div);
	be_set_transform_function(op_Eor, gen_Eor); // XoR
	be_set_transform_function(op_Jmp, gen_Jmp);
	be_set_transform_function(op_Load, gen_Load);
	be_set_transform_function(op_Minus, gen_Minus);
	be_set_transform_function(op_Mul, gen_Mul);
	be_set_transform_function(op_Not, gen_Not);
	be_set_transform_function(op_Or, gen_Or);
	be_set_transform_function(op_Phi, gen_Phi);
	be_set_transform_function(op_Return, gen_Return);
	be_set_transform_function(op_Shl, gen_Shl);
	be_set_transform_function(op_Shr, gen_Shr);
	be_set_transform_function(op_Start, gen_Start);
	be_set_transform_function(op_Store, gen_Store);
	be_set_transform_function(op_Sub, gen_Sub);

	be_set_transform_proj_function(op_Load, gen_Proj_Load);
	be_set_transform_proj_function(op_Proj, gen_Proj_Proj);
	be_set_transform_proj_function(op_Start, gen_Proj_Start);
	be_set_transform_proj_function(op_Store, gen_Proj_Store);
}

static const unsigned ignore_regs[] = {
	REG_R10, // fp
	REG_R0,	 // return register
};

static void setup_calling_convention(ir_graph *irg)
{
	be_irg_t *birg = be_birg_from_irg(irg);
	struct obstack *obst = &birg->obst;

	unsigned *allocatable_regs = rbitset_obstack_alloc(obst, N_BPF_REGISTERS);
	rbitset_set_all(allocatable_regs, N_BPF_REGISTERS);
	for (size_t r = 0, n = ARRAY_SIZE(ignore_regs); r < n; ++r)
	{
		rbitset_clear(allocatable_regs, ignore_regs[r]);
	}
	birg->allocatable_regs = allocatable_regs;
}

/**
 * Transform generic IR-nodes into bpf machine instructions
 */
void bpf_transform_graph(ir_graph *irg)
{
	assure_irg_properties(irg, IR_GRAPH_PROPERTY_NO_TUPLES | IR_GRAPH_PROPERTY_NO_BADS);

	bpf_register_transformers();

	setup_calling_convention(irg);

	be_transform_graph(irg, NULL);
}

void bpf_init_transform(void)
{
	FIRM_DBG_REGISTER(dbg, "firm.be.bpf.transform");
}
