/*
 * This file is part of libFirm.
 * Copyright (C) 2012 University of Karlsruhe.
 */

/**
 * @file
 * @brief   Function prototypes for the assembler ir node constructors.
 */
#ifndef FIRM_BE_BPF_BPF_NEW_NODES_H
#define FIRM_BE_BPF_BPF_NEW_NODES_H

#include "bpf_nodes_attr.h"

/**
 * Returns the attributes of an bpf node.
 */
bpf_attr_t *get_bpf_attr(ir_node *node);

const bpf_attr_t *get_bpf_attr_const(const ir_node *node);


const bpf_store_attr_t *get_bpf_store_attr_const(const ir_node *node);
const bpf_store_attr_t *get_bpf_load_attr_const(const ir_node *node);

/* Include the generated headers */
#include "gen_bpf_new_nodes.h"

#endif
