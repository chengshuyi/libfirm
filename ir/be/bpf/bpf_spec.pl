# the cpu architecture (ia32, ia64, mips, sparc, ppc, ...)
$arch = "bpf";

# Modes
$mode_gp = "mode_Iu"; # mode used by general purpose registers

# The node description is done as a perl hash initializer with the
# following structure:
#
# %nodes = (
#
# <op-name> => {
#   state     => "floats|pinned|mem_pinned|exc_pinned", # optional, default floats
#   comment   => "any comment for constructor",  # optional
#   in_reqs   => [ "reg_class|register" ] | "...",
#   out_reqs  => [ "reg_class|register|in_rX" ] | "...",
#   ins       => { "in1", "in2" },  # optional, creates n_op_in1, ... consts
#   outs      => { "out1", "out2" },# optional, creates pn_op_out1, ... consts
#   mode      => "first" | "<mode>" # optional, determines the mode, auto-detected by default
#   emit      => "emit code with templates",   # optional for virtual nodes
#   attr      => "additional attribute arguments for constructor", # optional
#   init      => "emit attribute initialization template",         # optional
#   hash_func => "name of the hash function for this operation",   # optional, get the default hash function else
#   attr_type => "name of the attribute struct",                   # optional
# },
#
# ... # (all nodes you need to describe)
#
# );

%reg_classes = (
	gp => {
		mode => $mode_gp,
		registers => [
			{ name => "r0"  }, 
			{ name => "r1"  }, # r1 - r5: arguments
			{ name => "r2"  },
			{ name => "r3"  },
			{ name => "r4"  },
			{ name => "r5"  },
			{ name => "r6"  },  # context pointer
			{ name => "r7"  },
			{ name => "r8"  },
			{ name => "r9"  },
			{ name => "r10" },  # framepointer
		]
	},
);

# 定义一些私有的attr类型
%init_attr = (
	bpf_attr_t => "",
	bpf_mapfd_attr_t => "",
	bpf_member_attr_t => "",
	bpf_load_attr_t => "",
	bpf_store_attr_t => "",
	bpf_load_store_attr_t => ""
);

# rematerializable: 表示是否可以重新计算，而不用spill/reload
my $binop = {
	irn_flags => [ "rematerializable" ],
	out_reqs  => [ "gp" ],

	constructors => {
		imm => {
			attr => "int32_t imm32_value",
			init => "bpf_set_imm_attr(res, imm32_value);",
			in_reqs => ["gp"],
			ins => ["left"],
		},
		reg => {
			in_reqs => ["gp", "gp"],
			ins => ["left", "right"],
		}
	}
};

# constant value
my $constop = {
	op_flags   => [ "constlike" ],
	irn_flags  => [ "rematerializable" ],
	out_reqs   => [ "gp" ],
};


my $unop = {
	irn_flags => [ "rematerializable" ],
	in_reqs   => [ "gp" ],
	out_reqs  => [ "gp" ],
};

%nodes = (

# Integer nodes

Add => { template => $binop },

Mul => { template => $binop },

Div => { template => $binop },

And => { template => $binop },

Or => { template => $binop },

Xor => { template => $binop },

Sub => { template => $binop },

Shl => { template => $binop },

Shr => { template => $binop },

# todo: change Minus to Neg
Minus => { template => $unop },

# Not => { template => $unop },

Const => {
	template => $constop,
	attr     => "ir_entity *entity, ir_tarval *value",
	init     => "set_bpf_value(res, entity, value);",
},

# Control Flow

Jmp => {
	state     => "pinned",
	op_flags  => [ "cfopcode" ],
	irn_flags => [ "simple_jump", "fallthrough" ],
	out_reqs  => [ "exec" ],
},

Return => {
	state    => "pinned",
	op_flags => [ "cfopcode" ],
	in_reqs  => "...",
	out_reqs => [ "exec" ],
	ins      => [ "mem", "first_result" ],
	outs     => [ "X" ],
},


FrameAddr => {
	op_flags  => [ "constlike" ],
	irn_flags => [ "rematerializable" ],
	attr      => "ir_entity *entity, int32_t offset",
	in_reqs   => [ "gp" ],
	out_reqs  => [ "gp" ],
	ins       => [ "base" ],
	init      => "init_bpf_member_attr(res, entity, offset);",
	attr_type => "bpf_member_attr_t",
},

# Load / Store

# BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn
# pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd
# Memory load, dst_reg = *(uint *) (src_reg + off16)
Load => {
	op_flags  => [ "uses_memory" ],
	state     => "exc_pinned",

	constructors => {
		# imm => {
		# 	in_reqs => [ "mem", "gp"],
		# 	ins  => ["mem", "ptr"],
		# 	attr => "int64_t offset",
		# 	init => "init_bpf_load_store_attributes(res, ls_mode, entity, offset, is_frame_entity, false);",
		# },
		reg => {
			in_reqs => ["mem", "gp"],
			ins => ["mem", "ptr"],
			attr => "ir_entity *entity, int16_t offset",
			init => "init_bpf_load_attr(res, entity, offset);",
		},
	},

	# ins   => [ "mem", "ptr" ],
	out_reqs  => [ "gp", "mem" ],
	outs      => [ "res", "M" ],
	attr_type => "bpf_load_attr_t",
},

MapFd => {
	op_flags   => [ "constlike" ],
	irn_flags  => [ "rematerializable" ],
	out_reqs   => [ "gp" ],
	attr     => "int32_t fd",
	init     => "init_bpf_mapfd_attr(res, fd);",
},

# Memory store, *(uint *) (dst_reg + off16) = src_reg
# Memory store, *(uint *) (dst_reg + off16) = imm32
Store => {
	op_flags  => [ "uses_memory" ],
	state     => "exc_pinned",

	constructors => {
		# imm => {
		# 	in_reqs => ["mem", "gp"],
		# 	ins => ["mem", "ptr"],
		# 	attr => "int16_t offset, int32_t imm",
		# 	init => "init_bpf_store_attr(res, offset, imm, true);",
		# },

		reg => {
			in_reqs => ["mem", "gp", "gp"],
			ins => ["mem", "val", "ptr"],
			attr => "ir_entity *entity, uint16_t offset",
			init => "init_bpf_store_attr(res, entity, offset);",
		},
	},

	out_reqs  => [ "mem" ],
	outs      => [ "M" ],
	attr_type => "bpf_store_attr_t",
},

# BPF_EMIT_CALL
Call => {
	irn_flags => ["has_delay_slot"],
	in_reqs => "...",
	out_reqs  => "...",
	outs      => [ "M", "first_result" ],
	# fixed     => "if (aggregate_return) arch_add_irn_flags(res, (arch_irn_flags_t)sparc_arch_irn_flag_aggregate_return);",
	constructors => {
		imm => {
			attr => "ir_entity *entity, int32_t func_id",
			init => "\tbpf_set_imm_attr(res, func_id);",
		},
	},
},

);
