
#ifndef _FIRM_BEARCH_H
#define _FIRM_BEARCH_H

#ifdef __cplusplus
extern "C" {
#endif

struct bitset_t;

/*
 * Define the types of the arch facility.
 * All arch object names are stored in bearch_obj.def
 */
#define ARCH_OBJ(x,list) typedef struct _arch_ ## x ## _t arch_ ## x ## _t;
#include "bearch_obj.def"
#undef ARCH_OBJ

/**
 * A callback to determine the set of valid registers.
 *
 * @param irn 				The node which represents an instance of the instruction.
 * @param pos 				The number of the insn's operand to consider.
 * @param valid_regs 	A bitset where all valid registers are put.
 */
typedef void (arch_register_callback_t)(ir_node *irn, int pos, struct bitset_t *valid_regs);


/**
 * Add a new instruction set architecture.
 * @param name The name of the isa.
 * @return The isa object.
 */
arch_isa_t *arch_add_isa(const char *name);

/**
 * Add a register class to the isa.
 * @param isa The isa to add the reg class to.
 * @param name The name of the register class.
 * @param n_regs The number of registers in that class.
 * @param mode The mode of the registers in that class.
 */
arch_register_class_t *arch_add_register_class(arch_isa_t *isa, const char *name, int n_regs);

/**
 * Add a register set to an isa.
 * @param cls The register class the set belongs to.
 * @param name The name of the register set.
 * @return The register set.
 */
arch_register_set_t *arch_add_register_set(arch_isa_t *isa,
		const arch_register_class_t *cls, const char *name);

/**
 * Add a register to a register set.
 * @param set The register set.
 * @param index The index of the register in the class.
 */
void arch_register_set_add_register(arch_register_set_t *set, int index);

/**
 * Add a register to a register class.
 * @param cls The register class.
 * @param index The index of the register (its number within the
 * class).
 * @param name The name of the register.
 * @return The register.
 */
arch_register_t *arch_add_register(arch_register_class_t *cls, int index, const char *name);

/**
 * Add an immediate to the instruction set architecture.
 * @param isa The isa.
 * @param name The name of the immediate.
 * @param mode The mode of the immediate.
 * @return The immediate.
 */
arch_immediate_t *arch_add_immediate(arch_isa_t *isa, const char *name, ir_mode *mode);

/**
 * Add an instruction format to an isa.
 * @param isa The isa.
 * @param name The name of the instruction format.
 * @param n_in The number of in operands.
 * @param n_out The number of out operands.
 * @return The format.
 */
arch_insn_format_t *arch_add_insn_format(arch_isa_t *isa, const char *name, int n_in, int n_out);

/**
 * Add a register set as an operand type.
 * @param fmt The instruction format whose operand is to be set.
 * @param pos The position of the operand. Note that input operands are
 * numbered from 0 to n and output operands from -1 to -m.
 * @param set The register set.
 * @return The corresponding operand type.
 */
arch_operand_t *arch_set_operand_register_set(arch_insn_format_t *fmt,
		int pos, const arch_register_set_t *set);

/**
 * Set the operand to a callback.
 * @param fmt The instruction format.
 * @param pos The position of the operand. See also
 * arch_set_operand_register_set().
 * @param cb The callback function which decides about the registers to
 * allocate.
 * @return The operand.
 */
arch_operand_t *arch_set_operand_callback(arch_insn_format_t *fmt,
		int pos, arch_register_callback_t *cb);

/**
 * Mark an operand as an immediate.
 * @param fmt The instructionm format.
 * @param pos The position. See also arch_set_operand_register_set().
 * @param imm The immediate which expected.
 * @return The operand.
 */
arch_operand_t *arch_set_operand_immediate(arch_insn_format_t *fmt,
		int pos, const arch_immediate_t *imm);

/**
 * Mark an operand as a memory operand.
 * @param fmt The format.
 * @param pos The position of the operand.
 * @return The operand.
 */
arch_operand_t *arch_set_operand_memory(arch_insn_format_t *fmt, int pos);

/**
 * Denote, that an operand must equal another.
 * This only makes sense with registers. Then, this operand must get the
 * same register as the one denoted by same_as_pos.
 *
 * @param fmt The instruction format.
 * @param pos The position of the operand.
 * @param same_as_pos The position of the other operand.
 * @return The operand.
 */
arch_operand_t *arch_set_operand_equals(arch_insn_format_t *fmt, int pos, int same_as_pos);


/**
 * Add an instruction to the isa.
 * @param fmt The instructon format.
 * @param name The name of the instruction.
 */
arch_insn_t *arch_add_insn(arch_insn_format_t *fmt, const char *name);


/**
 * Find an instruction format.
 * @param isa The isa.
 * @param name The name of the instruction format.
 * @return The instruction format, if it was added before, or NULL if it
 * is unknown.
 */
arch_insn_format_t *arch_find_insn_format(const arch_isa_t *isa, const char *name);

/**
 * Find an isa.
 * @param name The name of the isa.
 * @return The isa if it has been added, or NULl if it is unknwon.
 */
arch_isa_t *arch_find_isa(const char *name);

/**
 * Find an sintrsuction in the instruction set architecture.
 * @param isa The instruction set architecture.
 * @param name The name of the instruction.
 * @return The instruction or NULL if no such instruction exists.
 */
arch_insn_t *arch_find_insn(const arch_isa_t *isa, const char *name);

/**
 * Find a register class of an isa.
 * @param isa The isa.
 * @param name The name of the register class.
 * @return The register class, if it has been added, NULL if it is
 * unknown.
 */
arch_register_class_t *arch_find_register_class(const arch_isa_t *isa, const char *name);

/**
 * Find a register set in an isa.
 * @param isa The isa.
 * @param name The name of the register set.
 * @return The register set or NULL if it does not exist.
 */
arch_register_set_t *arch_find_register_set(const arch_isa_t *isa, const char *name);

/**
 * find an immediate registered in some isa.
 * @param isa The isa.
 * @param name The name of the immediate.
 * @return The immediate, or NULL if it did not exist.
 */
arch_immediate_t *arch_find_immediate(const arch_isa_t *isa, const char *name);

/**
 * Get the register set for a register class.
 * Each register class possesses a set containing all registers known in
 * the class.
 * @param cls The class.
 * @return The register set for the register class.
 */
arch_register_set_t *arch_get_register_set_for_class(arch_register_class_t *cls);

/**
 * Get a mode which is a placeholder for an unknown mode.
 * @return Some mode to use, if you don't know which mode you will need,
 * yet.
 */
ir_mode *arch_get_unknown_mode(void);

/**
 * Make a new bare instance of an insn.
 * @param insn The instruction.
 * @param irg The graph.
 * @param arity The number of operands to reserve for the ir_node.
 * @return An ir node. Its block and operands are set to an Unknown
 * node.
 */
ir_node *arch_new_node_bare(const arch_insn_t *insn, ir_graph *irg, int arity);

/**
 * Make a new instance of an insn.
 * This functions works like new_ir_node() and uses the op in the
 * insn.
 */
ir_node *arch_new_node(const arch_insn_t *insn, ir_graph *irg, ir_node *block,
		ir_mode *mode, int arity, ir_node **in);

#ifdef __cplusplus
}
#endif

#endif
