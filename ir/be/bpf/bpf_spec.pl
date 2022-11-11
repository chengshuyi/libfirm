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
	bpf_attr_t => ""
);

# rematerializable: 表示是否可以重新计算，而不用spill/reload
my $binop = {
	irn_flags => [ "rematerializable" ],
	in_reqs   => [ "gp", "gp" ],
	out_reqs  => [ "gp" ],
	emit      => '%D0 = {name} %S0, %S1',
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
	emit      => '%D0 = {name} %S0',
};

%nodes = (

# Integer nodes

Add => { template => $binop },

Mul => { template => $binop },

And => { template => $binop },

Or => { template => $binop },

Xor => { template => $binop },

Sub => { template => $binop },

Shl => { template => $binop },

Shr => { template => $binop },

Minus => { template => $unop },

Not => { template => $unop },

Const => {
	template => $constop,
	attr     => "ir_entity *entity, ir_tarval *value",
	init     => "set_bpf_value(res, entity, value);",
	emit     => '%D0 = const %I',
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
	ins      => [ "mem", "stack", "first_result" ],
	outs     => [ "X" ],
},

# Load / Store

Load => {
	op_flags  => [ "uses_memory" ],
	irn_flags => [ "rematerializable" ],
	state     => "exc_pinned",
	in_reqs   => [ "mem", "gp" ],
	out_reqs  => [ "gp", "mem" ],
	ins       => [ "mem", "ptr" ],
	outs      => [ "res", "M" ],
	emit      => '%D0 = load (%S1)',
},

Store => {
	op_flags  => [ "uses_memory" ],
	irn_flags => [ "rematerializable" ],
	state     => "exc_pinned",
	in_reqs   => [ "mem", "gp", "gp" ],
	out_reqs  => [ "mem" ],
	ins       => [ "mem", "ptr", "val" ],
	outs      => [ "M" ],
	emit      => '(%S1) = store %S2',
},

);
