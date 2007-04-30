#!/usr/bin/perl -w

#
# Copyright (C) 1995-2007 University of Karlsruhe.  All right reserved.
#
# This file is part of libFirm.
#
# This file may be distributed and/or modified under the terms of the
# GNU General Public License version 2 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.
#
# Licensees holding valid libFirm Professional Edition licenses may use
# this file in accordance with the libFirm Commercial License.
# Agreement provided with the Software.
#
# This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
# WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE.
#

# This script generates C code which emits assembler code for the
# assembler ir nodes. It takes a "emit" key from the node specification
# and substitutes lines starting with . with a corresponding fprintf().
# Creation: 2005/11/07
# $Id$

use strict;
use Data::Dumper;
use File::Basename;

my $myname = $0;
our $specfile   = $ARGV[0];
our $target_dir = $ARGV[1];

our $arch;
our $comment_string = "/*";
our $comment_string_end = "*/" ;
our %nodes;
our $new_emit_syntax = 0;

# include spec file

my $return;

no strict "subs";
unless ($return = do $specfile) {
	die "couldn't parse $specfile: $@" if $@;
	die "couldn't do $specfile: $!"    unless defined $return;
	die "couldn't run $specfile"       unless $return;
}
use strict "subs";

if ($new_emit_syntax) {
	my $newscript = dirname($myname) . "/generate_emitter_new.pl";
	unless ($return = do "$newscript") {
		die "couldn't parse $newscript: $@" if $@;
		die "couldn't do $newscript: $!"    unless defined $return;
		die "couldn't run $newscript"       unless $return;
	}
	exit;
}

my $comment_string_quoted = quotemeta($comment_string);

my $target_c = $target_dir."/gen_".$arch."_emitter.c";
my $target_h = $target_dir."/gen_".$arch."_emitter.h";

# stacks for output
my @obst_func;   # stack for the emit functions
my @obst_register;  # stack for emitter register code
my $line;

foreach my $op (keys(%nodes)) {
	my %n = %{ $nodes{"$op"} };

	# skip this node description if no emit information is available
	next if (!defined($n{"emit"}));

	$line = "static void emit_".$arch."_".$op."(const ir_node *n, $arch\_emit_env_t *env)";

	push(@obst_register, "  BE_EMIT($op);\n");

	if($n{"emit"} eq "") {
		push(@obst_func, $line." {\n");
		push(@obst_func, "}\n\n");
		next;
	}

	push(@obst_func, $line." {\n  FILE *F = env->out;\n");
	push(@obst_func, "  char cmd_buf[256], cmnt_buf[256];\n");
	push(@obst_func, "  const lc_arg_env_t *arg_env = $arch\_get_arg_env();\n\n");
	my @emit = split(/\n/, $n{"emit"});

	foreach my $template (@emit) {
		# substitute only lines, starting with a '.'
		if ($template =~ /^(\d*)\.\s*/) {
			my $indent = "  "; # default indent is 2 spaces

			$indent = " " x $1 if ($1 && $1 > 0);
			# remove indent, dot and trailing spaces
			$template =~ s/^\d*\.\s*//;
			my $fmt = $template;
			my $cnt = 0;
			my $buf = 'cmd_buf';

			push(@obst_func, $indent."cmnt_buf[0] = '\\0';\n");
			foreach $template (split(/$comment_string_quoted/, $fmt, 2)) {
				my @params;
				my $res = "";
				$cnt++;

				$template =~ s/(\\t)*$//;

				if ($cnt == 2) {
					# add the comment begin string
					$res .= $comment_string;
					$buf  = "cmnt_buf";
				}

				# substitute all format parameter
				while ($template =~ /(\%\%)|\%([ASDX])(\d)|\%([COM])|\%(\w+)/) {
					$res  .= $`;      # get everything before the match

					if ($1) {
						$res .= "%%";
					}
					elsif ($2 && $2 eq "S") {
						push(@params, "n");
						$res .= "%".$3."S"; # substitute %Sx with %xS
					}
					elsif ($2 && $2 eq "D") {
						push(@params, "n");
						$res .= "%".$3."D"; # substitute %Dx with %xD
					}
					elsif ($2 && $2 eq "X") {
						push(@params, "n");
						$res .= "%".$3."X"; # substitute %Xx with %xX
					}
					elsif ($2 && $2 eq "A") {
						push(@params, "get_irn_n(n, ".($3 - 1).")");
						$res .= "%+F";
					}
					elsif ($4) {
						push(@params, "n");
						$res .= "%".$4;
					}
					elsif ($5) {  # backend provided function to call, has to return a string
						push(@params, $5."(n, env)");
						$res .= "\%s";
					}

					$template = $'; # scan everything after the match
				}
				$res .= $template; # get the remaining string

				my $parm = "";
				$parm = ", ".join(", ", @params) if (@params);

				push(@obst_func, $indent.'lc_esnprintf(arg_env, '.$buf.', 256, "'.$res.'"'.$parm.');'."\n");
			}
			push(@obst_func, $indent.'lc_efprintf(arg_env, F, "\t%-35s %-60s '.$comment_string.' %+F (%+G) '.$comment_string_end.'\n", cmd_buf, cmnt_buf, n, n);'."\n");
		}
		else {
			push(@obst_func, $template,"\n");
		}
	}

	push(@obst_func, "}\n\n");
}

open(OUT, ">$target_h") || die("Could not open $target_h, reason: $!\n");

my $creation_time = localtime(time());

my $tmp = uc($arch);

print OUT<<EOF;
/**
 * \@file
 * \@brief Function prototypes for the emitter functions.
 * \@note  DO NOT EDIT THIS FILE, your changes will be lost.
 *        Edit $specfile instead.
 *        created by: $0 $specfile $target_dir
 * \@date  $creation_time
 */
#ifndef FIRM_BE_${tmp}_GEN_${tmp}_EMITTER_H
#define FIRM_BE_${tmp}_GEN_${tmp}_EMITTER_H

#include "irnode.h"
#include "$arch\_emitter.h"

void $arch\_register_spec_emitters(void);

#endif

EOF

close(OUT);

open(OUT, ">$target_c") || die("Could not open $target_c, reason: $!\n");

$creation_time = localtime(time());

print OUT<<EOF;
/**
 * \@file
 * \@brief  Generated functions to emit code for assembler ir nodes.
 * \@note   DO NOT EDIT THIS FILE, your changes will be lost.
 *         Edit $specfile instead.
 *         created by: $0 $specfile $target_dir
 * \@date   $creation_time
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "irnode.h"
#include "irop_t.h"
#include "irprog_t.h"

#include "gen_$arch\_emitter.h"
#include "$arch\_new_nodes.h"

EOF

print OUT @obst_func;

print OUT<<EOF;
/**
 * Enters the emitter functions for handled nodes into the generic
 * pointer of an opcode.
 */
void $arch\_register_spec_emitters(void) {

#define BE_EMIT(a) op_$arch\_##a->ops.generic = (op_func)emit_$arch\_##a

  /* generated emitter functions */
EOF

print OUT @obst_register;

print OUT<<EOF;

#undef BE_EMIT
}

EOF

close(OUT);
