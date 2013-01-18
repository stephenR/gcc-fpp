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

static rtx get_guard_reg();
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
  /* TODO CMOVcc / improvement without conditional jumps */
  /* TODO branch prediction */
  rtx end_label;
  rtx clear_guard_label;

  rtx guard_reg;
  rtx fp_reg;

  rtx xor_rtx;

  rtx const_null;

  clear_guard_label = gen_label_rtx ();
  end_label = gen_label_rtx ();
  const_null = gen_rtx_CONST_INT (ptr_mode, 0);

  if (REG_P (fp))
    {
      fp_reg = fp;
    }
  else
    {
      fp_reg = gen_reg_rtx (ptr_mode);
      emit_move_insn (fp_reg, fp);
    }

  emit_cmp_and_jump_insns (fp_reg, const_null, EQ, NULL_RTX, ptr_mode, 1, end_label /*, prob=? TODO */);

  guard_reg = get_guard_reg ();

  emit_cmp_and_jump_insns (fp_reg, guard_reg, EQ, NULL_RTX, ptr_mode, 1, clear_guard_label /*, prob=? TODO */);

  xor_rtx = expand_binop (ptr_mode, xor_optab, fp_reg, guard_reg,
        		 fp_reg, 0, OPTAB_DIRECT);

  if (!REG_P (fp))
    {
      emit_move_insn (fp, xor_rtx);
    }

  /* test if xor_rtx is a new temporary location that we want to be cleared.  */
  if (xor_rtx != fp_reg)
    {
      emit_move_insn (xor_rtx, const_null);
    }

  emit_label (clear_guard_label);

  if (!REG_P (fp))
    {
      emit_move_insn (fp_reg, const_null);
    }

  emit_move_insn(guard_reg, const_null);

  emit_label (end_label);

  /* TODO: is this ok? */
  free_temp_slots ();
}

#ifndef HAVE_move_guard_to_reg
# define HAVE_move_guard_to_reg		0
# define gen_move_guard_to_reg(x,y)	(gcc_unreachable (), NULL_RTX)
#endif

rtx get_guard_reg ()
{
  rtx guard_reg = gen_reg_rtx (ptr_mode);
  rtx guard = expand_normal (targetm.stack_protect_guard ());

  if (HAVE_move_guard_to_reg)
    {
      rtx insn = gen_move_guard_to_reg (guard_reg, guard);
      if (insn)
	{
	  emit_insn (insn);
	  return guard_reg;
	}
    }

  emit_move_insn (guard_reg, guard);

  return guard_reg;
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

