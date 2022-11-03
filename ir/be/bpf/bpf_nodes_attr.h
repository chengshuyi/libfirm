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

#include "firm_types.h"

typedef struct bpf_attr_t bpf_attr_t;

struct bpf_attr_t
{
	ir_tarval *value;
	ir_entity *entity;
};

#endif
