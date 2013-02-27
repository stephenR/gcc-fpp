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

struct GTY((chain_next ("%h.next"))) fpp_global_var
{
  tree decl;
  struct fpp_global_var *next;
};
static GTY(()) struct fpp_global_var *globals = 0;

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
get_protected_name (tree name)
{
  const char *suffix;
  int len;
  char *new_name;

  suffix = ".fpp";
  len = IDENTIFIER_LENGTH (name) + strlen(suffix);

  new_name = (char *) alloca (len + 1);
  strcpy (new_name, IDENTIFIER_POINTER (name));
  strcat (new_name, suffix);

  return get_identifier_with_length (new_name, len);
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

static void add_global_var (tree decl)
{
  struct fpp_global_var *new_var = ggc_alloc_fpp_global_var ();
  //struct fpp_global_var *new_var = NULL;
  new_var->next = globals;
  new_var->decl = decl;
  globals = new_var;
}

static tree protected_ptr_addr (tree fn)
{
  tree protected_ptr;
  tree protected_name = get_protected_name (DECL_ASSEMBLER_NAME (fn));

  protected_ptr = lookup_global_var (protected_name);

  if (protected_ptr)
    return protected_ptr;

  protected_ptr = add_new_static_var (build_pointer_type (TREE_TYPE (fn)));
  DECL_INITIAL (protected_ptr) = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (fn)), fn);
  DECL_NAME (protected_ptr) = protected_name;
  TREE_PUBLIC (protected_ptr) = 0;

  /* set a custom section so that ipa_discover_readonly_nonaddressable_vars won't declare this
   * as readonly */
  DECL_SECTION_NAME (protected_ptr) = build_string (5, ".fpp");

  add_global_var (protected_ptr);

  return protected_ptr;
}

static bool fpprotect_disable_attribute_p (tree node)
{
  tree attributes;

  for (attributes = TYPE_ATTRIBUTES (TREE_TYPE (node)); attributes; attributes = TREE_CHAIN (attributes))
    {
      if (is_attribute_p (disable_attribute_spec.name, TREE_PURPOSE (attributes)))
	return true;
    }
  return false;
}

static bool func_addr_expr_p (tree var)
{
  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (var)))
    return false;

  if (!(TREE_CODE (var) == ADDR_EXPR))
    return false;

  return true;
}

static bool func_pointer_has_guard (tree var)
{
  if (TREE_CONSTANT (var))
    return false;

  if (TREE_READONLY (var))
    return false;

  if (fpprotect_disable_attribute_p (var))
    return false;

  return true;
}

static void build_initializer_for_var (tree global_var, tree initial, tree *body);

static void build_initializer_for_constructor (tree var, tree constructor, tree *body)
{
  unsigned int ix;
  VEC(constructor_elt, gc) *v = CONSTRUCTOR_ELTS (constructor);
  tree index, val;

  FOR_EACH_CONSTRUCTOR_ELT (v, ix, index, val)
    {
      tree ref;

      if (RECORD_OR_UNION_TYPE_P (TREE_TYPE (var)))
	ref = build3 (COMPONENT_REF, TREE_TYPE (index), var, index, NULL_TREE);
      else
	ref = build4 (ARRAY_REF, TREE_TYPE (TREE_TYPE (var)), var, index, NULL_TREE, NULL_TREE);

      build_initializer_for_var (ref, val, body);
    }
}

static void build_initializer_for_var (tree global_var, tree initial, tree *body)
{
  tree stmt;

  if (!initial)
    return;

  if (TREE_READONLY (global_var))
    return;

  if (TREE_CODE (initial) == CONSTRUCTOR)
    {
      build_initializer_for_constructor (global_var, initial, body);
      return;
    }

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (global_var)))
    return;

  if (!func_pointer_has_guard (global_var))
    return;

  if (integer_zerop (initial))
    return;

  stmt = build_call_expr (fpp_protect_fndecl, 1, global_var);
  stmt = build2 (MODIFY_EXPR, TREE_TYPE (global_var),
		 global_var, stmt);
  append_to_statement_list (stmt, body);
}

void fpp_build_globals_initializer() {
  tree body = NULL;
  struct varpool_node *node;

  FOR_EACH_VARIABLE(node) {
    build_initializer_for_var (node->symbol.decl, DECL_INITIAL (node->symbol.decl), &body);
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
}

static void fpp_transform_addr_expr (tree *expr_p)
{
  tree expr = *expr_p;
  tree val = TREE_OPERAND (expr, 0);

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (expr)))
    return;

  *expr_p = protected_ptr_addr (val);
}

static void fpp_transform_call_expr (tree *expr_p)
{
  tree expr = *expr_p;
  tree call_fn = CALL_EXPR_FN (expr);
  tree verify_call;
  call_expr_arg_iterator iter;
  int i;

  for (i = 0; i < call_expr_nargs (expr); ++i)
    {
      tree *arg_p = &CALL_EXPR_ARG (expr, i);
      if (TREE_CODE (*arg_p) == NOP_EXPR)
	      arg_p = &TREE_OPERAND (*arg_p, 0);
      if (func_addr_expr_p (*arg_p))
	fpp_transform_addr_expr (arg_p);
    }

  if (!func_pointer_has_guard (call_fn))
    return;

  verify_call = build_call_expr (fpp_verify_fndecl, 1, call_fn);
  TREE_TYPE (verify_call) = TREE_TYPE (CALL_EXPR_FN (expr));
  CALL_EXPR_FN (expr) = verify_call;
}

static void fpp_transform_compare_expr (tree expr)
{
  tree left = TREE_OPERAND (expr, 0);
  tree right = TREE_OPERAND (expr, 1);

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (left)) && !FUNCTION_POINTER_TYPE_P (right))
    return;

  if (integer_zerop (left) || integer_zerop (right))
    return;

  gcc_assert (TREE_CODE (expr) == EQ_EXPR || TREE_CODE (expr) == NE_EXPR);

  TREE_OPERAND (expr, 0) = build_call_expr (fpp_eq_fndecl, 2, left, right);
  TREE_OPERAND (expr, 1) = integer_zero_node;
}

static void fpp_transform_assignment_expr (tree expr)
{
  tree lval = TREE_OPERAND (expr, 0);
  tree rval = TREE_OPERAND (expr, 1);

  if (TREE_CODE (rval) == NOP_EXPR)
    rval = TREE_OPERAND (rval, 0);

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (lval)))
    return;

  if (TREE_CODE (rval) == CALL_EXPR)
    return;

  if (!func_pointer_has_guard (lval))
    return;

  if (integer_zerop (rval))
    return;

  if (!func_pointer_has_guard (rval))
    {
      if (func_addr_expr_p (rval))
        {
          rval = TREE_OPERAND (rval, 0);
          TREE_OPERAND (expr, 1) = protected_ptr_addr (rval);
        }
      else
	{
	  TREE_OPERAND (expr, 1) = build_call_expr (fpp_protect_fndecl, 1, rval);
	}
    }
}

static void fpp_transform_var_decl (tree decl)
{
  tree initial = DECL_INITIAL (decl);

  if (!initial)
    return;

  if (TREE_CODE (initial) == NOP_EXPR)
    initial = TREE_OPERAND (initial, 0);

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (initial)))
    return;

  if (TREE_CODE (initial) == CALL_EXPR)
    return;

  if (!func_pointer_has_guard (decl))
    return;

  if (integer_zerop (initial))
    return;

  if (!func_pointer_has_guard (initial))
    {
      if (func_addr_expr_p (initial))
        {
          initial = TREE_OPERAND (initial, 0);
          DECL_INITIAL (decl) = protected_ptr_addr (initial);
        }
      else
	{
	  DECL_INITIAL (decl) = build_call_expr (fpp_protect_fndecl, 1, initial);
	}
    }
}

static void fpp_transform_bind_expr (tree expr)
{
  tree decl;
  tree body = NULL;

  for (decl = BIND_EXPR_VARS (expr); decl; decl = DECL_CHAIN (decl))
    {
      if (TREE_CODE (decl) == VAR_DECL)
	  fpp_transform_var_decl (decl);
    }

  if (body)
    {
      BIND_EXPR_BODY (expr) = 
	build2_loc (EXPR_LOCATION (BIND_EXPR_BODY (expr)), 
		    TRY_FINALLY_EXPR, 
		    void_type_node, 
		    BIND_EXPR_BODY (expr), 
		    body);
    }
}

static void fpp_transform_return_expr (tree expr)
{
  tree val = TREE_OPERAND (expr, 0);

  if (!val)
    return;

  if (TREE_CODE (val) == MODIFY_EXPR ||
	TREE_CODE (val) == INIT_EXPR)
    fpp_transform_assignment_expr (val);
}

static void fpp_walk_tree (tree *tp, struct pointer_set_t *pset);

void fpp_analyze_function (tree fndecl)
{
  struct pointer_set_t *pset;
  init_functions ();

  pset = pointer_set_create ();
  fpp_walk_tree (&DECL_SAVED_TREE (fndecl), pset);
  pointer_set_destroy (pset);
  //walk_tree_without_duplicates (&DECL_SAVED_TREE (fndecl), &fpp_transform_tree, NULL);
}

static void
fpp_walk_tree (tree *tp, struct pointer_set_t *pset)
{
  enum tree_code code;

  if (!*tp)
    return;

  /* Don't walk the same tree twice, if the user has requested
     that we avoid doing so.  */
  if (pset && pointer_set_insert (pset, *tp))
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

    case TREE_LIST:
      fpp_walk_tree (&TREE_VALUE (*tp), pset);
      fpp_walk_tree (&TREE_CHAIN (*tp), pset);
      break;

    case TREE_VEC:
      {
	int len = TREE_VEC_LENGTH (*tp);

	if (len == 0)
	  break;

	while (len--)
	  fpp_walk_tree (&TREE_VEC_ELT (*tp, len), pset);

      }
      break;

    case CONSTRUCTOR:
      {
	unsigned HOST_WIDE_INT idx;
	constructor_elt *ce;

	for (idx = 0;
	     VEC_iterate(constructor_elt, CONSTRUCTOR_ELTS (*tp), idx, ce);
	     idx++)
	  fpp_walk_tree (&ce->value, pset);
      }
      break;

    case SAVE_EXPR:
      fpp_walk_tree (&TREE_OPERAND (*tp, 0), pset);
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
	    fpp_walk_tree (&DECL_INITIAL (decl), pset);
	    fpp_walk_tree (&DECL_SIZE (decl), pset);
	    fpp_walk_tree (&DECL_SIZE_UNIT (decl), pset);
	  }
	fpp_walk_tree (&BIND_EXPR_BODY (*tp), pset);
      }
      break;

    case STATEMENT_LIST:
      {
	tree_stmt_iterator i;
	for (i = tsi_start (*tp); !tsi_end_p (i); tsi_next (&i))
	  fpp_walk_tree (&(*tsi_stmt_ptr (i)), pset);
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
	  fpp_walk_tree (&OMP_CLAUSE_OPERAND (*tp, 0), pset);
	  /* FALLTHRU */

	case OMP_CLAUSE_NOWAIT:
	case OMP_CLAUSE_ORDERED:
	case OMP_CLAUSE_DEFAULT:
	case OMP_CLAUSE_UNTIED:
	case OMP_CLAUSE_MERGEABLE:
	  fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset);
	  break;

	case OMP_CLAUSE_LASTPRIVATE:
	  fpp_walk_tree (&OMP_CLAUSE_DECL (*tp), pset);
	  fpp_walk_tree (&OMP_CLAUSE_LASTPRIVATE_STMT (*tp), pset);
	  fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset);
	  break;

	case OMP_CLAUSE_COLLAPSE:
	  {
	    int i;
	    for (i = 0; i < 3; i++)
	      fpp_walk_tree (&OMP_CLAUSE_OPERAND (*tp, i), pset);
	    fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset);
	  }
	  break;

	case OMP_CLAUSE_REDUCTION:
	  {
	    int i;
	    for (i = 0; i < 4; i++)
	      fpp_walk_tree (&OMP_CLAUSE_OPERAND (*tp, i), pset);
	    fpp_walk_tree (&OMP_CLAUSE_CHAIN (*tp), pset);
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
	  fpp_walk_tree (&TREE_OPERAND (*tp, i), pset);
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
		fpp_walk_tree (&TREE_OPERAND (*tp, i), pset);
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
	fpp_transform_compare_expr (*tp);
	break;
      }
    case MODIFY_EXPR:
    case INIT_EXPR:
      {
	fpp_transform_assignment_expr (*tp);
	break;
      }
    case BIND_EXPR:
      {
	fpp_transform_bind_expr (*tp);
	break;
      }
    case RETURN_EXPR:
      {
	fpp_transform_return_expr (*tp);
	break;
      }
    default:
      break;
    }
}

void fpp_register_disable_attribute () {
  register_attribute (&disable_attribute_spec);
}

#include "gt-fpprotect.h"
