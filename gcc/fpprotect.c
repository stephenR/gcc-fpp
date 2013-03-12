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

static GTY(()) tree fpp_protect_fndecl = NULL_TREE;
static GTY(()) tree fpp_verify_fndecl = NULL_TREE;
static GTY(()) tree fpp_eq_fndecl = NULL_TREE;
static GTY(()) tree fpp_deref_fndecl = NULL_TREE;

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

  /* set a custom section so that ipa_discover_readonly_nonaddressable_vars won't declare this
   * as readonly */
  DECL_SECTION_NAME (protected_global) = build_string (5, ".fpp");

  add_global_var (protected_global);

  return protected_global;
}

static tree replace_integer_cst (tree cst)
{
  tree type = TREE_TYPE (cst);
  tree protected_name = get_protected_cst_name (cst);
  tree protected_global;

  protected_global = get_protected_global_var (protected_name, cst);

  return build1 (ADDR_EXPR, type, protected_global);
}

static tree replace_addr_expr (tree fn_addr)
{
  tree protected_ptr;
  tree fn = TREE_OPERAND (fn_addr, 0);
  tree protected_name = get_protected_name (IDENTIFIER_POINTER (DECL_ASSEMBLER_NAME (fn)));
  tree type = TREE_TYPE (fn_addr);

  if (in_globals (fn))
    return fn_addr;

  protected_ptr = get_protected_global_var (protected_name, fn_addr);

  return build1 (ADDR_EXPR, type, protected_ptr);
}

static bool fpprotect_disable_attribute_p (tree node)
{
  tree attributes;
  tree type;

  if (!CODE_CONTAINS_STRUCT (TREE_CODE (node), TS_TYPED))
    return false;

  type = TREE_TYPE (node);

  if (!type || type == error_mark_node)
    return false;

  for (attributes = TYPE_ATTRIBUTES (type); attributes; attributes = TREE_CHAIN (attributes))
    {
      if (is_attribute_p (disable_attribute_spec.name, TREE_PURPOSE (attributes)))
	return true;
    }
  return false;
}

static bool read_only_p (tree var)
{
  return (TREE_CONSTANT (var) || TREE_READONLY (var));
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
}

static void fpp_walk_tree_without_duplicates (tree *tp);

void fpp_transform_globals ()
{
  struct varpool_node *node;

  init_functions ();

  FOR_EACH_VARIABLE(node) {
    if (!in_globals (node->symbol.decl))
      fpp_walk_tree_without_duplicates (&node->symbol.decl);
  }
}

static bool ptr_must_be_dereferenced (tree ptr)
{
  if (TREE_CODE (ptr) == INTEGER_CST)
    return false;

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (ptr)))
    return false;

  if (fpprotect_disable_attribute_p (ptr))
    return false;

  return true;
}

static void fpp_transform_compare_expr (tree *expr_p)
{
  tree expr = *expr_p;
  tree left = TREE_OPERAND (expr, 0);
  tree right = TREE_OPERAND (expr, 1);

  if (ptr_must_be_dereferenced (left))
    TREE_OPERAND (expr, 0) = build_call_expr (fpp_deref_fndecl, 1, left);

  if (ptr_must_be_dereferenced (right))
    TREE_OPERAND (expr, 0) = build_call_expr (fpp_deref_fndecl, 1, right);
}

static void fpp_transform_call_expr (tree *expr_p)
{
  tree expr = *expr_p;
  tree call_fn = CALL_EXPR_FN (expr);
  tree verify_call;

  if (TREE_CODE (call_fn) == ADDR_EXPR)
    return;

  if (fpprotect_disable_attribute_p (call_fn))
    return;

  call_fn = build1 (INDIRECT_REF, TREE_TYPE (call_fn), call_fn);
  verify_call = build_call_expr (fpp_verify_fndecl, 1, call_fn);
  TREE_TYPE (verify_call) = TREE_TYPE (CALL_EXPR_FN (expr));
  CALL_EXPR_FN (expr) = verify_call;
}

static bool fpp_check_transform (tree expr)
{
  if (!expr)
    return false;

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (expr)))
    return false;

  if (integer_zerop (expr))
    return false;

  if (!read_only_p (expr))
    return false;

  return true;
}

static void fpp_transform_integer_cst (tree *expr_p) {
  tree expr = *expr_p;

  if (!fpp_check_transform(expr))
      return;

  *expr_p = replace_integer_cst (expr);
}

static void fpp_transform_addr_expr (tree *expr_p) {
  tree expr = *expr_p;

  if (!fpp_check_transform(expr))
      return;

  *expr_p = replace_addr_expr (expr);
}


void fpp_analyze_function (tree fndecl)
{
  fpp_walk_tree_without_duplicates (&DECL_SAVED_TREE (fndecl));
}

static void
fpp_walk_tree (tree *tp, struct pointer_set_t *pset, bool skip_addr_expr)
{
  enum tree_code code;

  if (!*tp)
    return;

  /* Don't walk the same tree twice, if the user has requested
     that we avoid doing so.  */
  if (pset && pointer_set_insert (pset, *tp))
    return;

  if (fpprotect_disable_attribute_p (*tp))
    return;

  code = TREE_CODE (*tp);

  switch (code)
    {
    case ERROR_MARK:
    case IDENTIFIER_NODE:
    case INTEGER_CST:
    case REAL_CST:
    case FIXED_CST:
    case VECTOR_CST:
    case STRING_CST:
    case BLOCK:
    case PLACEHOLDER_EXPR:
    case SSA_NAME:
    case FIELD_DECL:
    case RESULT_DECL:
      /* None of these have subtrees other than those already walked
	 above.  */
      break;

    case ADDR_EXPR:
      break;

    case VAR_DECL:
    case PARM_DECL:
      if (DECL_INITIAL (*tp))
	fpp_walk_tree (&DECL_INITIAL (*tp), pset, false);
      break;

    case CALL_EXPR:
      {
	int i;

	fpp_walk_tree (&CALL_EXPR_FN (*tp), pset, true);

	for (i = 0; i < call_expr_nargs (*tp); ++i)
	  {
	    fpp_walk_tree (&CALL_EXPR_ARG (*tp, i), pset, false);
	  }
      }
      break;

    case TREE_LIST:
      fpp_walk_tree (&TREE_VALUE (*tp), pset, false);
      fpp_walk_tree (&TREE_CHAIN (*tp), pset, false);
      break;

    case TREE_VEC:
      {
	int len = TREE_VEC_LENGTH (*tp);

	if (len == 0)
	  break;

	while (len--)
	  fpp_walk_tree (&TREE_VEC_ELT (*tp, len), pset, false);

      }
      break;

    case CONSTRUCTOR:
      {
	unsigned HOST_WIDE_INT idx;
	constructor_elt *ce;

	for (idx = 0;
	     VEC_iterate(constructor_elt, CONSTRUCTOR_ELTS (*tp), idx, ce);
	     idx++)
	  fpp_walk_tree (&ce->value, pset, false);
      }
      break;

    case SAVE_EXPR:
      fpp_walk_tree (&TREE_OPERAND (*tp, 0), pset, false);
      break;

    case BIND_EXPR:
      {
	tree decl;
	for (decl = BIND_EXPR_VARS (*tp); decl; decl = DECL_CHAIN (decl))
	  {
	    /* Walk the DECL_INITIAL and DECL_SIZE.  We don't want to walk
	       into declarations that are just mentioned, rather than
	       declared; they don't really belong to this part of the tree.
	       And, we can see cycles: the initializer for a declaration
	       can refer to the declaration itself.  */
	    fpp_walk_tree (&DECL_INITIAL (decl), pset, false);
	    fpp_walk_tree (&DECL_SIZE (decl), pset, false);
	    fpp_walk_tree (&DECL_SIZE_UNIT (decl), pset, false);
	  }
	fpp_walk_tree (&BIND_EXPR_BODY (*tp), pset, false);
      }
      break;

    case STATEMENT_LIST:
      {
	tree_stmt_iterator i;
	for (i = tsi_start (*tp); !tsi_end_p (i); tsi_next (&i))
	  fpp_walk_tree (&(*tsi_stmt_ptr (i)), pset, false);
      }
      break;

    /* TODO: remove these? */
    case OMP_CLAUSE:
      switch (OMP_CLAUSE_CODE (*tp))
	{
	case OMP_CLAUSE_PRIVATE:
	case OMP_CLAUSE_SHARED:
	case OMP_CLAUSE_FIRSTPRIVATE:
	case OMP_CLAUSE_COPYIN:
	case OMP_CLAUSE_COPYPRIVATE:
	case OMP_CLAUSE_FINAL:
	case OMP_CLAUSE_IF:
	case OMP_CLAUSE_NUM_THREADS:
	case OMP_CLAUSE_SCHEDULE:
	  fpp_walk_tree (&OMP_CLAUSE_OPERAND (*tp, 0), pset, false);
	  /* FALLTHRU */

	case OMP_CLAUSE_NOWAIT:
	case OMP_CLAUSE_ORDERED:
	case OMP_CLAUSE_DEFAULT:
	case OMP_CLAUSE_UNTIED:
	case OMP_CLAUSE_MERGEABLE:
	  fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset, false);
	  break;

	case OMP_CLAUSE_LASTPRIVATE:
	  fpp_walk_tree (&OMP_CLAUSE_DECL (*tp), pset, false);
	  fpp_walk_tree (&OMP_CLAUSE_LASTPRIVATE_STMT (*tp), pset, false);
	  fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset, false);
	  break;

	case OMP_CLAUSE_COLLAPSE:
	  {
	    int i;
	    for (i = 0; i < 3; i++)
	      fpp_walk_tree (&OMP_CLAUSE_OPERAND (*tp, i), pset, false);
	    fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset, false);
	  }
	  break;

	case OMP_CLAUSE_REDUCTION:
	  {
	    int i;
	    for (i = 0; i < 4; i++)
	      fpp_walk_tree (&OMP_CLAUSE_OPERAND (*tp, i), pset, false);
	    fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset, false);
	  }
	  break;

	default:
	  gcc_unreachable ();
	}
      break;

    case TARGET_EXPR:
      {
	int i, len;

	/* TARGET_EXPRs are peculiar: operands 1 and 3 can be the same.
	   But, we only want to walk once.  */
	len = (TREE_OPERAND (*tp, 3) == TREE_OPERAND (*tp, 1)) ? 2 : 3;
	for (i = 0; i <= len; ++i)
	  fpp_walk_tree (&TREE_OPERAND (*tp, i), pset, false);
      }
      break;

    default:
      if (IS_EXPR_CODE_CLASS (TREE_CODE_CLASS (code)))
	{
	  int i, len;

	  /* Walk over all the sub-trees of this operand.  */
	  len = TREE_OPERAND_LENGTH (*tp);

	  /* Go through the subtrees.  We need to do this in forward order so
	     that the scope of a FOR_EXPR is handled properly.  */
	  if (len)
	    {
	      for (i = 0; i < len; ++i)
		fpp_walk_tree (&TREE_OPERAND (*tp, i), pset, false);
	    }
	}
      break;
    }

  /* Now, do the transformations after the subtrees have been handled */
  switch (code)
    {
    case CALL_EXPR:
      {
	fpp_transform_call_expr (tp);
	break;
      }
    case LT_EXPR:
    case LE_EXPR:
    case GT_EXPR:
    case GE_EXPR:
    case EQ_EXPR:
    case NE_EXPR:
      {
	fpp_transform_compare_expr (tp);
	break;
      }
    case ADDR_EXPR:
      {
	if (!skip_addr_expr)
	  fpp_transform_addr_expr (tp);
	break;
      }
    case INTEGER_CST:
      {
	if (!skip_addr_expr)
	  fpp_transform_integer_cst (tp);
	break;
      }
    default:
      break;
    }
}

static void fpp_walk_tree_without_duplicates (tree *tp)
{
  struct pointer_set_t *pset;
  struct fpp_global_var *global;

  pset = pointer_set_create ();

  FOR_EACH_GLOBAL(global)
    {
      pointer_set_insert (pset, global->decl);
    }

  fpp_walk_tree (tp, pset, false);
  pointer_set_destroy (pset);
}

void fpp_register_disable_attribute () {
  register_attribute (&disable_attribute_spec);
}

#include "gt-fpprotect.h"
