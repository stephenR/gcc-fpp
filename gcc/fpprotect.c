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

static GTY(()) tree fpp_protect_fndecl = NULL_TREE;
static GTY(()) tree fpp_copy_fndecl = NULL_TREE;
static GTY(()) tree fpp_verify_fndecl = NULL_TREE;
static GTY(()) tree fpp_eq_fndecl = NULL_TREE;

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

static bool build_initializer_for_var (tree global_var, tree initial, tree *body);

static bool build_initializer_for_constructor (tree var, tree constructor, tree *body)
{
  unsigned int ix;
  VEC(constructor_elt, gc) *v = CONSTRUCTOR_ELTS (constructor);
  bool globals_found = false;
  tree index, val;

  FOR_EACH_CONSTRUCTOR_ELT (v, ix, index, val)
    {
      tree ref;

      if (RECORD_OR_UNION_TYPE_P (TREE_TYPE (var)))
	ref = build3 (COMPONENT_REF, TREE_TYPE (index), var, index, NULL_TREE);
      else
	ref = build4 (ARRAY_REF, TREE_TYPE (TREE_TYPE (var)), var, index, NULL_TREE, NULL_TREE);

      globals_found |= build_initializer_for_var (ref, val, body);
    }

  return globals_found;
}

static bool build_initializer_for_var (tree global_var, tree initial, tree *body)
{
  tree stmt;

  if (!initial)
    return false;

  if (TREE_READONLY (global_var))
    return false;

  if (TREE_CODE (initial) == CONSTRUCTOR)
    {
      return build_initializer_for_constructor (global_var, initial, body);
    }

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (global_var)))
    return false;

  if (!func_pointer_has_guard (global_var))
    return false;

  if (integer_zerop (initial))
    return false;

  stmt = build_call_expr (fpp_protect_fndecl, 1, global_var);
  stmt = build2 (MODIFY_EXPR, TREE_TYPE (global_var),
		 global_var, stmt);
  append_to_statement_list (stmt, body);

  return true;
}

void fpp_build_globals_initializer() {
  tree body = NULL;
  struct varpool_node *node;
  bool globals_found = false;

  FOR_EACH_VARIABLE(node) {
    globals_found |= build_initializer_for_var (node->symbol.decl, DECL_INITIAL (node->symbol.decl), &body);
  }

  if (globals_found)
    cgraph_build_static_cdtor('I', body, MAX_RESERVED_INIT_PRIORITY);
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
  tree fpp_copy_type = ptr_type_node;
  tree fpp_verify_type = void_type_node;
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

  //__fpp_copy
  fpp_copy_type = build_function_type (fpp_copy_type,
      void_pointer_args);
  fpp_copy_fndecl = build_fn_decl ("__fpp_copy",
      fpp_copy_type);
  set_fndecl_attributes (fpp_copy_fndecl);

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

static void fpp_transform_call_expr (tree *expr_p);

static tree fpp_transform_call_parm (tree parm)
{
  if (TREE_CODE (parm) == CALL_EXPR)
    {
      fpp_transform_call_expr (&parm);

      return parm;
    }

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (parm)))
    return parm;

  if (func_pointer_has_guard (parm))
    return parm;

  if (integer_zerop (parm))
    return parm;

  return build_call_expr (fpp_protect_fndecl, 1, parm);
}

static void fpp_transform_call_expr (tree *expr_p)
{
  tree expr = *expr_p;
  tree call_fn = CALL_EXPR_FN (expr);
  tree verify_call;
  tree arg;
  call_expr_arg_iterator iter;

  FOR_EACH_CALL_EXPR_ARG (arg, iter, expr)
    {
      tree new_arg;
      new_arg = fpp_transform_call_parm (arg);
      CALL_EXPR_ARG (expr, iter.i-1) = new_arg;
    }

  if (!func_pointer_has_guard (call_fn))
    return;

  verify_call = build_call_expr (fpp_verify_fndecl, 1, call_fn);

  *expr_p = build2 (COMPOUND_EXPR, TREE_TYPE (expr), verify_call, expr);
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

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (lval)))
    return;

  if (TREE_CODE (rval) == CALL_EXPR)
    return;

  if (!func_pointer_has_guard (lval))
    return;

  if (integer_zerop (rval))
    return;

  if (func_pointer_has_guard (rval))
    {
      TREE_OPERAND (expr, 1) = build_call_expr (fpp_copy_fndecl, 1, rval);
    }
  else
    {
      TREE_OPERAND (expr, 1) = build_call_expr (fpp_protect_fndecl, 1, rval);
    }
}

static void fpp_transform_var_decl (tree decl)
{
  tree initial = DECL_INITIAL (decl);

  if (!initial)
    return;

  if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (decl)))
    return;

  if (TREE_CODE (initial) == CALL_EXPR)
    return;

  if (!func_pointer_has_guard (decl))
    return;

  if (integer_zerop (initial))
    return;

  if (func_pointer_has_guard (initial))
    {
      DECL_INITIAL (decl) = build_call_expr (fpp_copy_fndecl, 1, initial);
    }
  else
    {
      DECL_INITIAL (decl) = build_call_expr (fpp_protect_fndecl, 1, initial);
    }

}
static void fpp_transform_bind_expr (tree expr)
{
  tree decl;

  for (decl = BIND_EXPR_VARS (expr); decl; decl = DECL_CHAIN (decl))
    {
      if (TREE_CODE (decl) == VAR_DECL)
	fpp_transform_var_decl (decl);
    }
}

static tree
fpp_transform_tree (tree *tp,
		    int *walk_subtrees,
		    void *data ATTRIBUTE_UNUSED)
{
  tree t = *tp;

  if (TYPE_P (t))
    {
      *walk_subtrees = 0;
      return NULL;
    }

  switch (TREE_CODE (t))
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
	fpp_transform_compare_expr (t);
	break;
      }
    case MODIFY_EXPR:
    case INIT_EXPR:
      {
	fpp_transform_assignment_expr (t);
	break;
      }
    case BIND_EXPR:
      {
	fpp_transform_bind_expr (t);
	break;
      }
    default:
      break;
    }

  return NULL;
}

void fpp_analyze_function (tree fndecl)
{
  init_functions ();

  walk_tree_without_duplicates (&DECL_SAVED_TREE (fndecl), &fpp_transform_tree, NULL);
}

void fpp_register_disable_attribute () {
  register_attribute (&disable_attribute_spec);
}

#include "gt-fpprotect.h"
