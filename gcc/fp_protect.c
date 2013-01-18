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

static void func_pointer_toggle_guard (rtx fp);

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
  /* if both FROM and TO are protected, or if both are not protected, we don't
     have to do anything */
  if (func_pointer_has_guard (from) && func_pointer_has_guard (to))
    return;

  if (!func_pointer_has_guard (from) && !func_pointer_has_guard (to))
    return;

  /* TO needs a protection, but FROM is not protected, so we have to create it */
  if (func_pointer_has_guard (to))
    func_pointer_add_guard (to);
  /* TO needs to be free of protection, so remove the protection of FROM */
  else
    func_pointer_remove_guard (to);
}

void func_pointer_add_guard (tree var)
{
  rtx fp = expand_normal (var);
  func_pointer_toggle_guard (fp);
}

rtx func_pointer_prepare_call (rtx fp)
{
  rtx call_reg;

  if (!REG_P (fp))
    {
      call_reg = gen_reg_rtx (ptr_mode);
      emit_move_insn (call_reg, fp);
    }
  else
    {
      call_reg = fp;
    }

  func_pointer_toggle_guard (call_reg);

  return call_reg;
}

void func_pointer_toggle_guard (rtx fp)
{
}

void func_pointer_remove_guard (tree var)
{
  /* TODO */
  gcc_unreachable();
}

void func_pointer_generate_init_routine (const char* filename)
{
  const char *temp_name = "bla_blub";
  tree fndecl, tmp, decl;

  /* TODO */
  push_function_context ();
  tmp = build_function_type_list (void_type_node, NULL_TREE);
  fndecl = build_decl (BUILTINS_LOCATION, FUNCTION_DECL, get_identifier(temp_name), tmp);

  DECL_STATIC_CONSTRUCTOR (fndecl) = 1;
  decl_init_priority_insert (fndecl, MAX_RESERVED_INIT_PRIORITY - 1);

  decl = build_decl (input_location, RESULT_DECL, NULL_TREE, void_type_node);
  DECL_ARTIFICIAL (decl) = 1;
  DECL_IGNORED_P (decl) = 1;
  DECL_CONTEXT (decl) = fndecl;
  DECL_RESULT (fndecl) = decl;

  current_function_decl = fndecl;
  announce_function (fndecl);

  rest_of_decl_compilation (fndecl, 0, 0);
  make_decl_rtl (fndecl);

  allocate_struct_function (current_function_decl, false);
  TREE_STATIC (current_function_decl) = 1;
  TREE_USED (current_function_decl) = 1;
  DECL_PRESERVE_P (current_function_decl) = 1;

  BLOCK_SUPERCONTEXT (DECL_INITIAL (fndecl)) = fndecl;

  gimplify_function_tree (current_function_decl);
  cgraph_add_new_function (current_function_decl, false);

  cgraph_process_new_functions ();
  pop_function_context ();
}

