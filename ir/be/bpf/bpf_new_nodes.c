/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   This file implements the creation of the achitecture specific firm
 *          opcodes and the coresponding node constructors for the bpf
 *          assembler irg.
 */
#include "bpf_new_nodes_t.h"

#include "bpf_nodes_attr.h"
#include "bedump.h"
#include "gen_bpf_regalloc_if.h"
#include "ircons_t.h"
#include "irgraph_t.h"
#include "irmode_t.h"
#include "irnode_t.h"
#include "irop_t.h"
#include "iropt_t.h"
#include "irprintf.h"
#include "irprog_t.h"
#include "xmalloc.h"
#include <stdlib.h>

bool bpf_has_load_store_attr(const ir_node *node)
{
	return is_bpf_Load(node) || is_bpf_Store(node);
}

void bpf_dump_node(FILE *F, const ir_node *n, dump_reason_t reason)
{
	switch (reason) {
	case dump_node_opcode_txt:
		fprintf(F, "%s", get_irn_opname(n));
		break;

	case dump_node_mode_txt:
		break;

	case dump_node_nodeattr_txt:

		/* TODO: dump some attributes which should show up */
		/* in node name in dump (e.g. consts or the like)  */

		break;

	case dump_node_info_txt:
		break;
	}
}

void bpf_set_imm_attr(ir_node *res, int32_t imm)
{
	bpf_imm_attr_t *attr = (bpf_imm_attr_t *)get_irn_generic_attr(res);
	attr->imm32 = imm;
	arch_add_irn_flags(res, (arch_irn_flags_t)bpf_arch_irn_flag_immediate_form);
}

void init_bpf_member_attr(ir_node *res, ir_entity *entity, int32_t offset)
{
	bpf_member_attr_t *attr = (bpf_member_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->offset = offset;
}

void init_bpf_load_attr(ir_node *res, ir_entity *entity, int16_t offset)
{
	bpf_load_attr_t *attr = (bpf_load_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->offset = offset;
}

void init_bpf_store_attr(ir_node *res, ir_entity *entity, int16_t offset)
{
	bpf_store_attr_t *attr = (bpf_store_attr_t *)get_irn_generic_attr(res);
	attr->entity = entity;
	attr->offset = offset;
}

bpf_load_store_attr_t *get_bpf_load_store_attr(ir_node *node)
{
	assert(bpf_has_load_store_attr(node));
	return (bpf_load_store_attr_t*) get_irn_generic_attr_const(node);
}

void init_bpf_load_store_attributes(ir_node *res, uint16_t offset, int32_t imm, bool is_imm)
{
	bpf_load_store_attr_t *attr     = get_bpf_load_store_attr(res);
	attr->imm = imm;
	attr->is_imm = is_imm;
	attr->offset = offset;
}

const bpf_attr_t *get_bpf_attr_const(const ir_node *node)
{
	assert(is_bpf_irn(node) && "need bpf node to get attributes");
	return (const bpf_attr_t *)get_irn_generic_attr_const(node);
}

bpf_attr_t *get_bpf_attr(ir_node *node)
{
	assert(is_bpf_irn(node) && "need bpf node to get attributes");
	return (bpf_attr_t *)get_irn_generic_attr(node);
}

void set_bpf_value(ir_node *const node, ir_entity *const entity,
                        ir_tarval *const value)
{
	(void)node;
	(void)value;
	(void)entity;
	
	// bpf_attr_t *attr = get_bpf_attr(node);
	// attr->entity = entity;
	// attr->value  = value;
}

int bpf_attrs_equal(const ir_node *a, const ir_node *b)
{
	(void)a;
	(void)b;
	// const bpf_attr_t *attr_a = get_bpf_attr_const(a);
	// const bpf_attr_t *attr_b = get_bpf_attr_const(b);
	// return attr_a->value == attr_b->value
	//     && attr_a->entity == attr_b->entity;
	return 0;
}

int bpf_member_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_load_attr_t *attr_a = (bpf_load_attr_t *)get_irn_generic_attr(a);
	const bpf_load_attr_t *attr_b = (bpf_load_attr_t *)get_irn_generic_attr(b);
	return attr_a->entity == attr_b->entity && attr_a->offset == attr_b->offset;
}

int bpf_load_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_load_attr_t *attr_a = (bpf_load_attr_t *)get_irn_generic_attr(a);
	const bpf_load_attr_t *attr_b = (bpf_load_attr_t *)get_irn_generic_attr(b);
	return attr_a->entity == attr_b->entity && attr_a->offset == attr_b->offset;
}

int bpf_store_attrs_equal(const ir_node *a, const ir_node *b)
{
	const bpf_store_attr_t *attr_a = (bpf_store_attr_t *)get_irn_generic_attr(a);
	const bpf_store_attr_t *attr_b = (bpf_store_attr_t *)get_irn_generic_attr(b);
	return attr_a->entity == attr_b->entity && attr_a->offset == attr_b->offset;
}


const bpf_store_attr_t *get_bpf_store_attr_const(const ir_node *node)
{
	return (const bpf_store_attr_t*) get_irn_generic_attr_const(node);
}

const bpf_store_attr_t *get_bpf_load_attr_const(const ir_node *node)
{
	return (const bpf_load_attr_t*) get_irn_generic_attr_const(node);
}