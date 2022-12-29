/*
 * This file is part of libFirm.
 * Copyright (C) 2016 Matthias Braun
 */

/**
 * @file
 * @brief   Internal declarations used by gen_new_nodes.c
 */
#ifndef FIRM_BE_BPF_BPF_NEW_NODES_T_H
#define FIRM_BE_BPF_BPF_NEW_NODES_T_H

#include "bpf_new_nodes.h"

void bpf_dump_node(FILE *F, const ir_node *n, dump_reason_t reason);

void set_bpf_value(ir_node *const node, ir_entity *const entity,
                        ir_tarval *const value);

int bpf_attrs_equal(const ir_node *a, const ir_node *b);


void bpf_set_imm_attr(ir_node *res, int32_t imm);
void init_bpf_load_store_attributes(ir_node *res, uint16_t offset, int32_t imm, bool is_imm);

void init_bpf_load_attr(ir_node *res, uint16_t offset, int64_t imm, bool is_imm);

bpf_load_store_attr_t *get_bpf_load_store_attr(ir_node *res);

#endif
