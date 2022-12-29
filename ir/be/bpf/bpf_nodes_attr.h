/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   attributes attached to all bpf nodes
 */
#ifndef FIRM_BE_BPF_BPF_NODES_ATTR_H
#define FIRM_BE_BPF_BPF_NODES_ATTR_H

#include <stdint.h>

#include "be_types.h"
#include "beasm.h"
#include "benode.h"
#include "firm_types.h"
#include "irnode_t.h"


enum sparc_arch_irn_flags_t {
	bpf_arch_irn_flag_needs_64bit_spillslot = arch_irn_flag_backend << 0,
	bpf_arch_irn_flag_immediate_form        = arch_irn_flag_backend << 1,
	bpf_arch_irn_flag_aggregate_return      = arch_irn_flag_backend << 2,
	bpf_arch_irn_flag_has_delay_slot        = arch_irn_flag_backend << 3,
};


struct bpf_imm_attr_t
{
	int32_t imm32;
};

/**
 * base eBPF attribute
 */
typedef struct bpf_attr_t bpf_attr_t;
struct bpf_attr_t
{
	int32_t imm;		/* immediate value */
	ir_entity *entity;  /* immediate entity */
};


/**
 * attributes for load/store addressing modes
 */
typedef struct bpf_load_store_attr_t bpf_load_store_attr_t;
struct bpf_load_store_attr_t {
	bpf_attr_t base;
	uint16_t offset;
	int32_t imm;
	bool is_imm: 1;
};

/**
 * attributes for conditional jumps
 */
typedef struct sparc_jmp_cond_attr_t sparc_jmp_cond_attr_t;
struct sparc_jmp_cond_attr_t {
	bpf_attr_t base;    /**< generic attribute */
	ir_relation  relation;
	bool         is_unsigned      : 1;
	bool         annul_delay_slot : 1;
};


/**
 * attributes for conditional jumps
 */
typedef struct bpf_jmp_cond_attr_t bpf_jmp_cond_attr_t;
struct bpf_jmp_cond_attr_t {
	bpf_attr_t base;    /**< generic attribute */
	ir_relation  relation;
	bool         is_unsigned      : 1;
	bool         annul_delay_slot : 1;
};


#endif
