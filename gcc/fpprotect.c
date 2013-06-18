/* TODO: description and legal notice */

/* TODO: remove unneeded header */
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "ggc.h"
#include "cgraph.h"
#include "tree-iterator.h"
#include "plugin.h"
#include "pointer-set.h"
#include "tree-pass.h"
#include "gimple.h"
#include "diagnostic-core.h"
#include "rtl.h"
#include "expr.h"
#include "optabs.h"

static GTY(()) tree fpp_protect_fndecl = NULL_TREE;
static GTY(()) tree fpp_verify_fndecl = NULL_TREE;
static GTY(()) tree fpp_eq_fndecl = NULL_TREE;
static GTY(()) tree fpp_deref_fndecl = NULL_TREE;
static GTY(()) rtx fpp_protect_rtx = NULL_RTX;

struct GTY((chain_next ("%h.next"))) fpp_global_var
{
  tree decl;
  struct fpp_global_var *next;
};
static GTY(()) struct fpp_global_var *globals = 0;

#define FOR_EACH_GLOBAL(global) \
   for ((global) = globals; \
        (global); \
	(global) = (global)->next)

static GTY(()) struct attribute_spec disable_attribute_spec =
  {  "fpprotect_disable",
     0,
     0,
     false,
     true,
     false,
     NULL,
     false
  };

static tree
get_protected_name (const char *name)
{
  const char *suffix;
  int len;
  char *new_name;

  suffix = ".fpp";
  len = strlen (name) + strlen(suffix);

  new_name = (char *) alloca (len + 1);
  strcpy (new_name, name);
  strcat (new_name, suffix);

  return get_identifier_with_length (new_name, len);
}

static tree
get_protected_cst_name (tree cst)
{
  const char *prefix = "CST.";
  char buf[sizeof (*prefix) + 2*HOST_BITS_PER_WIDE_INT/8 + 1];

  snprintf(buf, sizeof(buf), "%s" HOST_WIDE_INT_PRINT_DOUBLE_HEX,
      prefix,
      (unsigned HOST_WIDE_INT) TREE_INT_CST_HIGH (cst),
      (unsigned HOST_WIDE_INT) TREE_INT_CST_LOW (cst));

  return get_protected_name (buf);
}

static tree lookup_global_var (tree name)
{
  const struct fpp_global_var *global = globals;

  while (global)
    {
      if (DECL_NAME (global->decl) == name)
	return global->decl;

      global = global->next;
    }

  return NULL_TREE;
}

static bool in_globals (tree decl)
{
  struct fpp_global_var *global = globals;

  while (global)
    {
      if (decl == global->decl)
	return true;

      global = global->next;
    }

  return false;
}

static void add_global_var (tree decl)
{
  struct fpp_global_var *new_var = ggc_alloc_fpp_global_var ();
  new_var->next = globals;
  new_var->decl = decl;
  globals = new_var;
}

static tree get_protected_global_var (tree name, tree initial) {
  tree type = TREE_TYPE (initial);
  tree protected_global = lookup_global_var (name);

  if (protected_global)
      return protected_global;

  protected_global = add_new_static_var (type);
  DECL_INITIAL (protected_global) = initial;
  DECL_NAME (protected_global) = name;
  TREE_PUBLIC (protected_global) = 0;
  TREE_ADDRESSABLE (protected_global) = 1;

  /* set a custom section so that ipa_discover_readonly_nonaddressable_vars won't declare this
   * as readonly TODO: try DECL_PRESERVE_P*/
  DECL_SECTION_NAME (protected_global) = build_string (5, ".fpp");

  add_global_var (protected_global);

  return protected_global;
}

static tree replace_integer_cst (tree cst)
{
  tree type = TREE_TYPE (cst);
  tree protected_name = get_protected_cst_name (cst);
  tree protected_global;
  tree addr;

  protected_global = get_protected_global_var (protected_name, cst);

  addr = build1 (ADDR_EXPR, build_pointer_type (type), protected_global);
  return build1 (NOP_EXPR, type, addr);
}

static tree replace_addr_expr (tree fn_addr)
{
  tree protected_ptr;
  tree fn = TREE_OPERAND (fn_addr, 0);
  tree protected_name = get_protected_name (IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (fn)));
  tree type = TREE_TYPE (fn_addr);
  tree addr;

  if (in_globals (fn))
    return fn_addr;

  protected_ptr = get_protected_global_var (protected_name, fn_addr);

  addr = build1 (ADDR_EXPR, build_pointer_type (type), protected_ptr);
  return build1 (NOP_EXPR, type, addr);
}

static bool fpprotect_disable_attribute_p (tree type)
{
  tree attributes;

  for (attributes = TYPE_ATTRIBUTES (type); attributes; attributes = TREE_CHAIN (attributes))
    {
      if (is_attribute_p (disable_attribute_spec.name, TREE_PURPOSE (attributes)))
	return true;
    }

  return false;
}

void fpp_build_globals_initializer() {
  tree body = NULL_TREE;
  struct varpool_node *node;

  FOR_EACH_VARIABLE(node)
    {
      if (!in_globals (node->symbol.decl))
	continue;

      tree stmt;
      tree decl = node->symbol.decl;

      stmt = build_call_expr (fpp_protect_fndecl, 1, decl);
      stmt = build2 (MODIFY_EXPR, TREE_TYPE (decl),
		     decl, stmt);
      append_to_statement_list (stmt, &body);
    }

  /* TODO set this to the highest priority possible */
  if (body)
    cgraph_build_static_cdtor('I', body, MAX_RESERVED_INIT_PRIORITY+2);
}

static void set_fndecl_attributes (tree fndecl)
{
  TREE_NOTHROW (fndecl) = 1;
  DECL_ATTRIBUTES (fndecl) =
    tree_cons (get_identifier ("leaf"), NULL,
	DECL_ATTRIBUTES (fndecl));
  TREE_PUBLIC (fndecl) = 1;
  DECL_PRESERVE_P (fndecl) = 1;
}

static void
init_functions (void)
{
  tree fpp_protect_type = ptr_type_node;
  tree fpp_verify_type = ptr_type_node;
  tree fpp_eq_type = integer_type_node;
  tree fpp_deref_type = ptr_type_node;
  tree void_pointer_args;
  tree compare_arg_types;

  if (fpp_protect_fndecl != NULL_TREE)
    return;

  void_pointer_args = build_tree_list (NULL_TREE, ptr_type_node);
  void_pointer_args = chainon (void_pointer_args, build_tree_list (NULL_TREE, void_type_node));

  compare_arg_types = build_tree_list (NULL_TREE, ptr_type_node);
  compare_arg_types = chainon (compare_arg_types, build_tree_list (NULL_TREE, ptr_type_node));
  compare_arg_types = chainon (compare_arg_types, build_tree_list (NULL_TREE, void_type_node));

  //__fpp_protect
  fpp_protect_type = build_function_type (fpp_protect_type,
      void_pointer_args);
  fpp_protect_fndecl = build_fn_decl ("__fpp_protect",
      fpp_protect_type);
  set_fndecl_attributes (fpp_protect_fndecl);

  //__fpp_verify
  fpp_verify_type = build_function_type (fpp_verify_type,
      void_pointer_args);
  fpp_verify_fndecl = build_fn_decl ("__fpp_verify",
      fpp_verify_type);
  set_fndecl_attributes (fpp_verify_fndecl);

  //__fpp_eq
  fpp_eq_type = build_function_type (fpp_eq_type,
      compare_arg_types);
  fpp_eq_fndecl = build_fn_decl ("__fpp_eq",
      fpp_eq_type);
  set_fndecl_attributes (fpp_eq_fndecl);

  //__fpp_deref
  fpp_deref_type = build_function_type (fpp_deref_type,
      void_pointer_args);
  fpp_deref_fndecl = build_fn_decl ("__fpp_deref",
      fpp_deref_type);
  set_fndecl_attributes (fpp_deref_fndecl);

  fpp_protect_rtx = init_one_libfunc("fpp_protect_func_ptr");
}

static bool
deref_needed (tree lhs_type, tree rhs)
{
  tree rhs_type = TREE_TYPE (rhs);

  if (fpprotect_disable_attribute_p (lhs_type))
    {
      if (TREE_CODE (rhs) == VAR_DECL && !fpprotect_disable_attribute_p (rhs_type))
	return true;

      return false;
    }
  else
    {
      /* TODO raise an error instead of an assertion */
      //TODO: gcc_assert (!fpprotect_disable_attribute_p (rhs_type));
      return false;
    }
}

static tree
replace_expr (gimple_stmt_iterator *gsi, tree expr)
{
  tree new_expr = NULL_TREE;
  tree new_decl;
  gimple new_stmt;

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (expr)))
    return expr;

  if (TREE_CODE (expr) == ADDR_EXPR)
    new_expr = replace_addr_expr (expr);
  else if (TREE_CODE (expr) == INTEGER_CST && !integer_zerop (expr))
    new_expr = replace_integer_cst (expr);

  if (new_expr)
    {
      if (!gsi)
	return new_expr;

      gimple stmt = gsi_stmt (*gsi);

      new_decl = create_tmp_var (TREE_TYPE (new_expr), NULL);
      new_stmt = gimple_build_assign (new_decl, new_expr);
      gimple_set_location (new_stmt, gimple_location (stmt));
      gsi_insert_before (gsi, new_stmt, GSI_SAME_STMT);
      return new_decl;
    }

  return expr;
}

static void warn_on_assignments (tree lhs_type, tree rhs_type, location_t loc)
{
  if (FUNCTION_POINTER_TYPE_P (lhs_type) && !fpprotect_disable_attribute_p (lhs_type) && !POINTER_TYPE_P (rhs_type) && !(TREE_CODE (rhs_type) == BOOLEAN_TYPE))
    warning_at (loc, 0, "DEBUG: assigning non-pointer type to function pointer");

  if (FUNCTION_POINTER_TYPE_P (rhs_type) && !fpprotect_disable_attribute_p (rhs_type) && !POINTER_TYPE_P (lhs_type) && !(TREE_CODE (lhs_type) == BOOLEAN_TYPE))
    warning_at (loc, 0, "DEBUG: assigning function pointer to non-pointer type");

  if (FUNCTION_POINTER_TYPE_P (lhs_type) && FUNCTION_POINTER_TYPE_P (rhs_type) && !fpprotect_disable_attribute_p (lhs_type) && fpprotect_disable_attribute_p (rhs_type))
    error_at (loc, "Assigning unprotected function pointer to protected function pointer");
}

static void
transform_assign (gimple_stmt_iterator *gsi)
{
  gimple stmt = gsi_stmt (*gsi);
  tree lhs = gimple_assign_lhs (stmt);
  tree rhs = gimple_assign_rhs1 (stmt);

  warn_on_assignments(TREE_TYPE (lhs), TREE_TYPE (rhs), gimple_location (stmt));

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (rhs)))
    return;

  if (deref_needed (TREE_TYPE (lhs), rhs))
    {
	  gimple new_stmt = gimple_build_call (fpp_deref_fndecl, 1, rhs);
	  gimple_call_set_lhs (new_stmt, lhs);
	  gimple_set_location (new_stmt, gimple_location (stmt));
	  gsi_replace (gsi, new_stmt, false);
	  return;
    }

  if (fpprotect_disable_attribute_p (TREE_TYPE (lhs)))
    return;

  if (TREE_CODE (TREE_TYPE (lhs)) == BOOLEAN_TYPE)
    return;

  gimple_assign_set_rhs1 (stmt, replace_expr (gsi, rhs));
}

static bool transform_call_blacklist (tree t) {
  tree fn;

  if (TREE_CODE (t) != ADDR_EXPR)
    return false;

  fn = TREE_OPERAND (t, 0);

  if (TREE_CODE (fn) != FUNCTION_DECL)
    return false;

  if (DECL_FUNCTION_CODE (fn) != BUILT_IN_INIT_TRAMPOLINE)
    return false;

  return true;
}

static void
transform_call (gimple_stmt_iterator *gsi)
{
  gimple stmt = gsi_stmt (*gsi);
  tree lhs = gimple_call_lhs (stmt);
  tree fn = gimple_call_fn (stmt);
  //tree fndecl = TREE_CODE (fn) == ADDR_EXPR ? TREE_OPERAND (fn, 0) : fn;
  gimple new_stmt;
  tree new_decl;
  unsigned num_args = gimple_call_num_args (stmt);
  //tree arg_chain;
  //unsigned i = 0;
  
  /* TODO does this exception make it exploitable or erroneous */
  if (transform_call_blacklist (fn))
    return;

  while (num_args--)
    {
      tree arg = gimple_call_arg (stmt, num_args);
      gimple_call_set_arg (stmt, num_args, replace_expr (gsi, arg));
    }
  
  // TODO deref if needed in params (reuse code from transform_assign)
  //for (arg_chain = DECL_ARGUMENTS (fndecl); arg_chain; arg_chain = TREE_CHAIN (arg_chain))
  //  {
  //    gcc_assert (i < num_args);
  //    tree arg = gimple_call_arg (stmt, i);
  //    tree parm_type = TREE_TYPE (arg_chain);

  //    if (!FUNCTION_POINTER_TYPE_P (arg))
  //      continue;

  //    if (deref_needed (parm_type, arg))
  //      {
  //        /* TODO build temp with get_formal_tmp_var? */
  //        new_decl = create_tmp_var (parm_type, NULL);
  //        new_stmt = gimple_build_call (fpp_deref_fndecl, 1, arg);
  //        gimple_call_set_lhs (new_stmt, new_decl);
  //        gimple_set_location (new_stmt, gimple_location (stmt));
  //        gsi_insert_before (gsi, new_stmt, GSI_SAME_STMT);
  //        gimple_call_set_arg (stmt, i, new_decl);
  //        continue;
  //      }

  //    if (!fpprotect_disable_attribute_p (parm_type))
  //        gimple_call_set_arg (stmt, i, replace_expr (arg));
  //  }

  if (TREE_CODE (fn) != ADDR_EXPR && !fpprotect_disable_attribute_p (TREE_TYPE (fn)))
    {
      /* insert call to __fpp_verify */
      new_stmt = gimple_build_call (fpp_verify_fndecl, 1, fn);
      new_decl = create_tmp_var (TREE_TYPE (fn), NULL);
      gimple_call_set_lhs (new_stmt, new_decl);
      gimple_set_location (new_stmt, gimple_location (stmt));
      gimple_call_set_fn (stmt, new_decl);

      gsi_insert_before (gsi, new_stmt, GSI_SAME_STMT);
    }

  if (lhs && deref_needed (TREE_TYPE (lhs), fn))
    {
      new_stmt = gimple_build_call (fpp_deref_fndecl, 1, lhs);
      gimple_call_set_lhs (new_stmt, lhs);
      gimple_set_location (new_stmt, gimple_location (stmt));
      gsi_insert_after (gsi, new_stmt, GSI_NEW_STMT);
    }
}

static tree
deref_if_needed (gimple_stmt_iterator *gsi, tree expr)
{
  tree type = TREE_TYPE (expr);
  gimple stmt = gsi_stmt (*gsi);
  tree new_decl;
  gimple new_stmt;

  if (!FUNCTION_POINTER_TYPE_P (type))
    return expr;

  if (TREE_CODE (expr) == ADDR_EXPR)
    return expr;

  if (TREE_CODE (expr) == INTEGER_CST)
    return expr;

  if (fpprotect_disable_attribute_p (type))
    return expr;

  new_decl = create_tmp_var (type, NULL);
  new_stmt = gimple_build_call (fpp_deref_fndecl, 1, expr);
  gimple_call_set_lhs (new_stmt, new_decl);
  gimple_set_location (new_stmt, gimple_location (stmt));
  gsi_insert_before (gsi, new_stmt, GSI_SAME_STMT);

  return new_decl;
}

static void
transform_cond (gimple_stmt_iterator *gsi)
{
  gimple stmt = gsi_stmt (*gsi);
  tree lhs = gimple_cond_lhs (stmt);
  tree rhs = gimple_cond_rhs (stmt);

  gimple_cond_set_lhs (stmt, deref_if_needed (gsi, lhs));
  gimple_cond_set_rhs (stmt, deref_if_needed (gsi, rhs));
}

static void
transform_return (gimple_stmt_iterator *gsi)
{
  gimple stmt = gsi_stmt (*gsi);
  tree retval = gimple_return_retval (stmt);

  if (!retval)
    return;

  /* TODO deref if needed */

  gimple_return_set_retval (stmt, replace_expr (gsi, retval));
}

static void
transform_switch (gimple_stmt_iterator *gsi)
{
  gimple stmt = gsi_stmt (*gsi);
  tree index = gimple_switch_index(stmt);

  gimple_switch_set_index(stmt, deref_if_needed (gsi, index));
}

static tree
transform_gimple_stmt (gimple_stmt_iterator *gsi,
		    bool *handled_operands_p ATTRIBUTE_UNUSED,
		    struct walk_stmt_info *wi ATTRIBUTE_UNUSED) {
  gimple stmt = gsi_stmt (*gsi);

  switch (gimple_code (stmt))
    {
    case GIMPLE_ASSIGN:
      transform_assign (gsi);
      break;
    case GIMPLE_CALL:
      transform_call (gsi);
      break;
    case GIMPLE_COND:
      transform_cond (gsi);
      break;
    case GIMPLE_RETURN:
      transform_return (gsi);
      break;
    case GIMPLE_SWITCH:
      transform_switch (gsi);
      break;
    default:
      break;
    }

  return NULL_TREE;
}

static unsigned int
transform_current_function (void)
{
  struct gimplify_ctx gctx;
  struct walk_stmt_info wi;
  struct pointer_set_t *pset = pointer_set_create ();
  gimple_seq fnbody = gimple_body (current_function_decl);

  memset (&wi, 0, sizeof (wi));
  wi.pset = pset;

  push_gimplify_context (&gctx);
  walk_gimple_seq (fnbody, transform_gimple_stmt, NULL, &wi);
  pop_gimplify_context (NULL);

  pointer_set_destroy (pset);

  return 0;
}

static bool
gate_fpprotect (void)
{
  return flag_fp_protect != 0;
}

struct gimple_opt_pass pass_fpprotect =
{
 {
  GIMPLE_PASS,
  "fpprotect",                           /* name */
  gate_fpprotect,                         /* gate */
  transform_current_function,       /* execute */
  NULL,                                 /* sub */
  NULL,                                 /* next */
  0,                                    /* static_pass_number */
  TV_NONE,                              /* tv_id */
  PROP_gimple_any,                      /* properties_required */
  0,                                    /* properties_provided */
  0,                                    /* properties_destroyed */
  0,                                    /* todo_flags_start */
  0                                     /* todo_flags_finish */
 }
};

void fpp_register_disable_attribute () {
  register_attribute (&disable_attribute_spec);
}

static tree transform_global (tree *tp, int *walk_subtrees, void *data ATTRIBUTE_UNUSED)
{
  tree t = *tp;

  if (fpprotect_disable_attribute_p (TREE_TYPE (t)))
    {
      *walk_subtrees = 0;
      return NULL_TREE;
    }

  switch (TREE_CODE (t))
    {
    case ADDR_EXPR:
    case INTEGER_CST:
      *tp = replace_expr (/* no statement iterator */ NULL, t);
      *walk_subtrees = 0;
      break;
    default:
      break;
    }

  return NULL_TREE;
}

bool init_or_fini_section (tree decl)
{
  const char *section_name;

  if (!DECL_SECTION_NAME (decl))
    return false;

  section_name = TREE_STRING_POINTER (DECL_SECTION_NAME (decl));

  if (strcmp(section_name, ".init_array") == 0
      || strcmp(section_name, ".ctors") == 0)
    return true;

  if (strcmp(section_name, ".fini_array") == 0
      || strcmp(section_name, ".dtors") == 0)
    return true;

  return false;
}

void fpp_transform_globals ()
{
  struct varpool_node *node;

  init_functions ();

  FOR_EACH_VARIABLE(node)
    {
      tree decl = node->symbol.decl;
      if (init_or_fini_section (decl))
	continue;
      tree *initial = &DECL_INITIAL (decl);
      if (*initial && !in_globals (decl))
	walk_tree (initial, &transform_global, NULL, NULL);
	//walk_tree_without_duplicates (initial, &transform_global, NULL);
    }
}

rtx fpp_expand_protect_call (rtx fun)
{
  return fun;
  //return emit_library_call_value (fpp_protect_rtx, NULL_RTX, LCT_NORMAL, Pmode, 1, fun, Pmode);
}

#include "gt-fpprotect.h"
