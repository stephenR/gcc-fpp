/* TODO: description and legal notice */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "fp_protect.h"
#include "target.h"
#include "rtl.h"
#include "expr.h"
#include "optabs.h"
#include "gimple.h"
#include "cgraph.h"
#include "toplev.h"
#include "tree-iterator.h"

//static void func_pointer_toggle_guard (rtx fp);
static void func_pointer_copy(tree to, tree from);
static void func_pointer_protect(tree to, tree from);

static tree fpp_protect_fndecl = NULL_TREE;
static tree fpp_verify_fndecl = NULL_TREE;

bool func_pointer_has_guard (tree var)
{
  /* TODO for now all pointers are protected, this will change when
     compatibility features are implemented */
  //if (CONSTANT_CLASS_P (var))
  //  return false;
  if (TREE_CONSTANT (var))
    return false;

  return true;
}

void
func_pointer_protect_assignment (tree to, tree from)
{
  if (!func_pointer_has_guard (to))
    return;

  if (func_pointer_has_guard (from) && func_pointer_has_guard (to)) { 
    func_pointer_copy(to, from);
    return;
  }

  func_pointer_protect(to, from);
}

//void func_pointer_add_guard (tree var)
//{
//  rtx fp = expand_normal (var);
//  func_pointer_toggle_guard (fp);
//}

void build_globals_initializer() {
  tree body = NULL;
  tree stmt;
  struct varpool_node *node;

  FOR_EACH_VARIABLE(node) {
    tree global_var = node->symbol.decl;
    if (!FUNCTION_POINTER_TYPE_P (TREE_TYPE (global_var)))
      continue;

    if (!func_pointer_has_guard (global_var))
      continue;

    stmt = build_call_expr (fpp_protect_fndecl, 1, global_var);
    stmt = build2 (MODIFY_EXPR, TREE_TYPE (global_var),
		   global_var, stmt);
    append_to_statement_list (stmt, &body);
  }
  cgraph_build_static_cdtor('I', body, DEFAULT_INIT_PRIORITY); //TODO: INIT_PRIORITY
}
  //tree arg_types = NULL_TREE;
  //tree fpp_init_globals_type = void_type_node;
  //tree fpp_init_globals_fndecl;

  //arg_types = build_tree_list (NULL_TREE, ptr_type_node);
  //arg_types = chainon (arg_types, build_tree_list (NULL_TREE, void_type_node));

  //fpp_init_globals_type = build_function_type (fpp_init_globals_type,
  //    arg_types);
  //fpp_init_globals_fndecl = build_fn_decl ("__fpp_init_globals",
  //    fpp_init_globals_type);
  //TREE_NOTHROW (fpp_init_globals_fndecl) = 1;
  //DECL_ATTRIBUTES (fpp_init_globals_fndecl) =
  //  tree_cons (get_identifier ("leaf"), NULL,
  //      DECL_ATTRIBUTES (fpp_init_globals_fndecl));
  //TREE_PUBLIC (fpp_init_globals_fndecl) = 0;
  //DECL_PRESERVE_P (fpp_init_globals_fndecl) = 1;
  //DECL_ARTIFICIAL (current_function_decl) = 1;
  //TREE_USED (current_function_decl) = 1;
  //DECL_STATIC_CONSTRUCTOR (current_function_decl) = 1;
//}

static void
init_functions (void)
{
  tree arg_types = NULL_TREE;
  tree fpp_protect_type = ptr_type_node;

  if (fpp_protect_fndecl != NULL_TREE)
    return;

  //__fpp_protect
  arg_types = build_tree_list (NULL_TREE, ptr_type_node);
  arg_types = chainon (arg_types, build_tree_list (NULL_TREE, void_type_node));

  fpp_protect_type = build_function_type (fpp_protect_type,
      arg_types);
  fpp_protect_fndecl = build_fn_decl ("__fpp_protect",
      fpp_protect_type);
  TREE_NOTHROW (fpp_protect_fndecl) = 1;
  DECL_ATTRIBUTES (fpp_protect_fndecl) =
    tree_cons (get_identifier ("leaf"), NULL,
	DECL_ATTRIBUTES (fpp_protect_fndecl));
  TREE_PUBLIC (fpp_protect_fndecl) = 1;
  DECL_PRESERVE_P (fpp_protect_fndecl) = 1;

  //__fpp_verify
  arg_types = NULL_TREE;
  //tree fpp_verify_type = ptr_type_node;
  tree fpp_verify_type = void_type_node;

  arg_types = build_tree_list (NULL_TREE, ptr_type_node);
  arg_types = chainon (arg_types, build_tree_list (NULL_TREE, void_type_node));

  fpp_verify_type = build_function_type (fpp_verify_type,
      arg_types);
  fpp_verify_fndecl = build_fn_decl ("__fpp_verify",
      fpp_verify_type);
  TREE_NOTHROW (fpp_verify_fndecl) = 1;
  DECL_ATTRIBUTES (fpp_verify_fndecl) =
    tree_cons (get_identifier ("leaf"), NULL,
	DECL_ATTRIBUTES (fpp_verify_fndecl));
  TREE_PUBLIC (fpp_verify_fndecl) = 1;
  DECL_PRESERVE_P (fpp_verify_fndecl) = 1;
}

static void
func_pointer_copy(tree to, tree from){
}

static void
func_pointer_protect(tree to, tree from){
  init_functions ();
  tree fpp_protect_call = build_call_expr (fpp_protect_fndecl,
                                            1, from);
  rtx to_rtx = expand_normal (to);
  rtx protected_to = expand_call (fpp_protect_call, to_rtx, /*ignore=*/ 0);
  if(protected_to != to_rtx) {
    emit_move_insn (to_rtx, protected_to);
  }
}

void func_pointer_prepare_call (tree call_dst)
{
  //rtx call_reg;

  init_functions ();

  //if (!REG_P (fp))
  //  {
  //    call_reg = gen_reg_rtx (ptr_mode);
  //    emit_move_insn (call_reg, fp);
  //  }
  //else
  //  {
  //    call_reg = fp;
  //  }

  tree fpp_verify_call = build_call_expr (fpp_verify_fndecl,
                                            1, call_dst);
  expand_call (fpp_verify_call, NULL, /*ignore=*/ 0);
  //rtx verified_to = expand_call (fpp_verify_call, call_reg, /*ignore=*/ 0);
  //if(verified_to != call_reg) {
  //  emit_move_insn (call_reg, verified_to);
  //}

  //return call_reg;
}

