/**
 * Chordal register allocation.
 * @author Sebastian Hack
 * @date 8.12.2004
 *
 * Copyright (C) Universitaet Karlsruhe
 * Released under the GPL
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#include "obst.h"
#include "pset.h"
#include "list.h"
#include "bitset.h"
#include "iterator.h"

#include "irmode_t.h"
#include "irgraph_t.h"
#include "irprintf_t.h"
#include "irgwalk.h"
#include "irdump.h"
#include "irdom.h"
#include "debug.h"
#include "xmalloc.h"

#include "beutil.h"
#include "besched.h"
#include "benumb_t.h"
#include "besched_t.h"
#include "belive_t.h"
#include "bearch.h"
#include "beifg.h"

#include "bechordal_t.h"
#include "bechordal_draw.h"

#define DBG_LEVEL SET_LEVEL_0
#define DBG_LEVEL_CHECK SET_LEVEL_0

#define NO_COLOR (-1)

#undef DUMP_INTERVALS

typedef struct _be_chordal_alloc_env_t {
	be_chordal_env_t *chordal_env;

	bitset_t *live;				/**< A liveness bitset. */
	bitset_t *colors;			/**< The color mask. */
	bitset_t *in_colors;        /**< Colors used by live in values. */
	int colors_n;               /**< The number of colors. */
} be_chordal_alloc_env_t;

#include "fourcc.h"

/* Make a fourcc for border checking. */
#define BORDER_FOURCC				FOURCC('B', 'O', 'R', 'D')

static void check_border_list(struct list_head *head)
{
  border_t *x;
  list_for_each_entry(border_t, x, head, list) {
    assert(x->magic == BORDER_FOURCC);
  }
}

static void check_heads(be_chordal_env_t *env)
{
  pmap_entry *ent;
  for(ent = pmap_first(env->border_heads); ent; ent = pmap_next(env->border_heads)) {
    /* ir_printf("checking border list of block %+F\n", ent->key); */
    check_border_list(ent->value);
  }
}


/**
 * Add an interval border to the list of a block's list
 * of interval border.
 * @note You always have to create the use before the def.
 * @param env The environment.
 * @param head The list head to enqueue the borders.
 * @param irn The node (value) the border belongs to.
 * @param pressure The pressure at this point in time.
 * @param step A time step for the border.
 * @param is_def Is the border a use or a def.
 * @return The created border.
 */
static INLINE border_t *border_add(be_chordal_env_t *env, struct list_head *head,
			ir_node *irn, unsigned step, unsigned pressure,
			unsigned is_def, unsigned is_real)
{
	border_t *b;

	if(!is_def) {
		border_t *def;

		b = obstack_alloc(&env->obst, sizeof(*b));

		/* also allocate the def and tie it to the use. */
		def = obstack_alloc(&env->obst, sizeof(*def));
		memset(def, 0, sizeof(*def));
		b->other_end = def;
		def->other_end = b;

		/*
		 * Set the link field of the irn to the def.
		 * This strongly relies on the fact, that the use is always
		 * made before the def.
		 */
		set_irn_link(irn, def);

		b->magic = BORDER_FOURCC;
		def->magic = BORDER_FOURCC;
	}

	/*
	 * If the def is encountered, the use was made and so was the
	 * the def node (see the code above). It was placed into the
	 * link field of the irn, so we can get it there.
	 */
	else {
		b = get_irn_link(irn);

		assert(b && b->magic == BORDER_FOURCC && "Illegal border encountered");
	}

	b->pressure = pressure;
	b->is_def = is_def;
	b->is_real = is_real;
	b->irn = irn;
	b->step = step;
	list_add_tail(&b->list, head);
	DBG((env->dbg, LEVEL_5, "\t\t%s adding %+F, step: %d\n", is_def ? "def" : "use", irn, step));


	return b;
}

/**
 * Check, if an irn is of the register class currently under processing.
 * @param env The chordal environment.
 * @param irn The node.
 * @return 1, if the node is of that register class, 0 if not.
 */
static INLINE int has_reg_class(const be_chordal_env_t *env, const ir_node *irn)
{
  return arch_irn_has_reg_class(env->main_env->arch_env, irn, -1, env->cls);
}

/**
 * Annotate the register pressure to the nodes and compute
 * the liveness intervals.
 * @param block The block to do it for.
 * @param env_ptr The environment.
 */
static void pressure(ir_node *block, void *env_ptr)
{
/* Convenience macro for a def */
#define border_def(irn, step, real) \
	border_add(env, head, irn, step, pressure--, 1, real)

/* Convenience macro for a use */
#define border_use(irn, step, real) \
	border_add(env, head, irn, step, ++pressure, 0, real)

	be_chordal_alloc_env_t *alloc_env = env_ptr;
	be_chordal_env_t *env             = alloc_env->chordal_env;
	bitset_t *live                    = alloc_env->live;
	firm_dbg_module_t *dbg            = env->dbg;
	ir_node *irn;

	int i, n;
	unsigned step = 0;
	unsigned pressure = 0;
	struct list_head *head;
	pset *live_in = put_live_in(block, pset_new_ptr_default());
	pset *live_end = put_live_end(block, pset_new_ptr_default());

	DBG((dbg, LEVEL_1, "Computing pressure in block %+F\n", block));
	bitset_clear_all(live);

	/* Set up the border list in the block info */
	head = obstack_alloc(&env->obst, sizeof(*head));
	INIT_LIST_HEAD(head);
	assert(pmap_get(env->border_heads, block) == NULL);
	pmap_insert(env->border_heads, block, head);

	/*
	 * Make final uses of all values live out of the block.
	 * They are necessary to build up real intervals.
	 */
	for(irn = pset_first(live_end); irn; irn = pset_next(live_end)) {
		if(has_reg_class(env, irn)) {
			DBG((dbg, LEVEL_3, "\tMaking live: %+F/%d\n", irn, get_irn_graph_nr(irn)));
			bitset_set(live, get_irn_graph_nr(irn));
			border_use(irn, step, 0);
		}
	}
	++step;

	/*
	 * Determine the last uses of a value inside the block, since they are
	 * relevant for the interval borders.
	 */
	sched_foreach_reverse(block, irn) {
		DBG((dbg, LEVEL_1, "\tinsn: %+F, pressure: %d\n", irn, pressure));
		DBG((dbg, LEVEL_2, "\tlive: %b\n", live));

	    /*
	     * If the node defines some value, which can put into a
	     * register of the current class, make a border for it.
	     */
		if(has_reg_class(env, irn)) {
			int nr = get_irn_graph_nr(irn);

			bitset_clear(live, nr);
			border_def(irn, step, 1);
		}

		/*
		 * If the node is no phi node we can examine the uses.
		 */
		if(!is_Phi(irn)) {
			for(i = 0, n = get_irn_arity(irn); i < n; ++i) {
				ir_node *op = get_irn_n(irn, i);

				if(has_reg_class(env, op)) {
					int nr = get_irn_graph_nr(op);

					DBG((dbg, LEVEL_4, "\t\tpos: %d, use: %+F\n", i, op));

					if(!bitset_is_set(live, nr)) {
						border_use(op, step, 1);
						bitset_set(live, nr);
					}
				}
			}
		}
		++step;
	}

	/*
	 * Add initial defs for all values live in.
	 */
	for(irn = pset_first(live_in); irn; irn = pset_next(live_in)) {
		if(has_reg_class(env, irn)) {

			/* Mark the value live in. */
			bitset_set(live, get_irn_graph_nr(irn));

			/* Add the def */
			border_def(irn, step, 0);
		}
	}


  del_pset(live_in);
  del_pset(live_end);
}

static void assign(ir_node *block, void *env_ptr)
{
	be_chordal_alloc_env_t *alloc_env = env_ptr;
	be_chordal_env_t *env       = alloc_env->chordal_env;
	firm_dbg_module_t *dbg      = env->dbg;
	bitset_t *live              = alloc_env->live;
	bitset_t *colors            = alloc_env->colors;
	bitset_t *in_colors         = alloc_env->in_colors;
	const arch_env_t *arch_env  = env->main_env->arch_env;

	const ir_node *irn;
	border_t *b;
	struct list_head *head = get_block_border_head(env, block);
	pset *live_in = put_live_in(block, pset_new_ptr_default());

	bitset_clear_all(live);
	bitset_clear_all(colors);
	bitset_clear_all(in_colors);

	DBG((dbg, LEVEL_4, "Assigning colors for block %+F\n", block));
	DBG((dbg, LEVEL_4, "\tusedef chain for block\n"));
	list_for_each_entry(border_t, b, head, list) {
		DBG((dbg, LEVEL_4, "\t%s %+F/%d\n", b->is_def ? "def" : "use",
					b->irn, get_irn_graph_nr(b->irn)));
	}

	/*
	 * Add initial defs for all values live in.
	 * Since their colors have already been assigned (The dominators were
	 * allocated before), we have to mark their colors as used also.
	 */
	for(irn = pset_first(live_in); irn; irn = pset_next(live_in)) {
		if(has_reg_class(env, irn)) {
			const arch_register_t *reg = arch_get_irn_register(arch_env, irn);
			int col;

			assert(reg && "Node must have been assigned a register");
			col = arch_register_get_index(reg);

			/* Mark the color of the live in value as used. */
			bitset_set(colors, col);
			bitset_set(in_colors, col);

			/* Mark the value live in. */
			bitset_set(live, get_irn_graph_nr(irn));
		}
	}

	/*
	 * Mind that the sequence of defs from back to front defines a perfect
	 * elimination order. So, coloring the definitions from first to last
	 * will work.
	 */
	list_for_each_entry_reverse(border_t, b, head, list) {
		ir_node *irn = b->irn;
		int nr = get_irn_graph_nr(irn);

		/*
		 * Assign a color, if it is a local def. Global defs already have a
		 * color.
		 */
		if(b->is_def && !is_live_in(block, irn)) {
			const arch_register_t *reg;
			int col = NO_COLOR;

			DBG((dbg, LEVEL_4, "\tcolors in use: %b\n", colors));

			col = bitset_next_clear(colors, 0);
			reg = arch_register_for_index(env->cls, col);

			assert(arch_get_irn_register(arch_env, irn) == NULL && "This node must not have been assigned a register yet");
			assert(!bitset_is_set(live, nr) && "Value's definition must not have been encountered");

			bitset_set(colors, col);
			bitset_set(live, nr);

			arch_set_irn_register(arch_env, irn, reg);
			DBG((dbg, LEVEL_1, "\tassigning register %s(%d) to %+F\n",
            arch_register_get_name(reg), col, irn));
		}

		/* Clear the color upon a use. */
		else if(!b->is_def) {
			const arch_register_t *reg = arch_get_irn_register(arch_env, irn);
			int col;

			assert(reg && "Register must have been assigned");

			col = arch_register_get_index(reg);
			assert(bitset_is_set(live, nr) && "Cannot have a non live use");

			bitset_clear(colors, col);
			bitset_clear(live, nr);
		}
	}

	del_pset(live_in);
}

void be_ra_chordal_color(be_chordal_env_t *chordal_env)
{
	int node_count        = get_graph_node_count(chordal_env->irg);
	int colors_n          = arch_register_class_n_regs(chordal_env->cls);
	ir_graph *irg         = chordal_env->irg;

	be_chordal_alloc_env_t env;

	if(get_irg_dom_state(irg) != dom_consistent)
		compute_doms(irg);

	env.chordal_env  = chordal_env;
	env.live         = bitset_obstack_alloc(&chordal_env->obst, node_count);
	env.colors       = bitset_obstack_alloc(&chordal_env->obst, colors_n);
	env.in_colors    = bitset_obstack_alloc(&chordal_env->obst, colors_n);
	env.colors_n     = colors_n;

	/* First, determine the pressure */
	dom_tree_walk_irg(irg, pressure, NULL, &env);

	/* Assign the colors */
	dom_tree_walk_irg(irg, assign, NULL, &env);

#ifdef DUMP_INTERVALS
	{
		char buf[128];
    	plotter_t *plotter;

		ir_snprintf(buf, sizeof(buf), "ifg_%s_%F.eps", cls->name, irg);
    	plotter = new_plotter_ps(buf);

    	draw_interval_tree(&draw_chordal_def_opts, chordal_env, plotter, env->arch_env, cls);
    	plotter_free(plotter);
	}
#endif

}
