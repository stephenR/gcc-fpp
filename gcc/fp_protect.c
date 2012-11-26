/* TODO: description and legal notice */

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "fp_protect.h"
#include "target.h"
#include "rtl.h"
#include "expr.h"

static rtx get_guard_rtx();

bool func_pointer_has_guard (tree var)
{
  /* TODO for now all pointers are protected, this will change when
     compatibility features are implemented */
  return !CONSTANT_CLASS_P (var);
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

#ifndef HAVE_fp_protect_add
# define HAVE_fp_protect_add		0
# define gen_fp_protect_add(x,y)	(gcc_unreachable (), NULL_RTX)
#endif

void func_pointer_add_guard (tree var)
{
  tree guard_decl;
  rtx x, y;
  //rtx xor_rtx, sub_rtx;

  guard_decl = targetm.stack_protect_guard ();

  x = expand_normal (var);
  y = expand_normal (guard_decl);

  if (HAVE_fp_protect_add)
    {
      rtx insn = gen_fp_protect_add (x, y);
      if (insn)
        {
          emit_insn (insn);
          return;
        }
    }

  gcc_unreachable();
  /* TODO add/test regular instructions */

  //xor_rtx = expand_binop (Pmode, xor_optab, x, y,
  //      		 xor_rtx, 0, OPTAB_DIRECT);
  //sub_rtx = expand_binop (Pmode, sub_optab, xor_rtx, y,
  //      		 sub_rtx, 0, OPTAB_DIRECT);

  //emit_move_insn (x, sub_rtx);
}

#ifndef HAVE_fp_protect_rm_mem
# define HAVE_fp_protect_rm_mem		0
# define gen_fp_protect_rm_mem(x,y)	(gcc_unreachable (), NULL_RTX)
#endif

void func_pointer_remove_guard (tree var)
{
  gcc_unreachable();
  /* TODO think about fp_protect_rm_mem */
  //tree guard_decl;
  //rtx x, y;
  ////rtx xor_rtx, add_rtx;

  //guard_decl = targetm.stack_protect_guard ();

  //x = expand_normal (var);
  //y = expand_normal (guard_decl);

  //if (HAVE_fp_protect_rm_mem)
  //  {
  //    rtx insn = gen_fp_protect_rm_mem (x, y);
  //    if (insn)
  //      {
  //        emit_insn (insn);
  //        return;
  //      }
  //  }

  //gcc_unreachable();
  ///* TODO add/test regular instructions */

  ////add_rtx = expand_binop (Pmode, add_optab, x, y,
  ////      		 sub_rtx, 0, OPTAB_DIRECT);
  ////xor_rtx = expand_binop (Pmode, xor_optab, add_rtx, y,
  ////      		 xor_rtx, 0, OPTAB_DIRECT);

  ////emit_move_insn (x, xor_rtx);
}

#ifndef HAVE_fp_protect_rm
# define HAVE_fp_protect_rm		0
# define gen_fp_protect_rm(x,y)	(gcc_unreachable (), NULL_RTX)
#endif

rtx func_pointer_prepare_call (rtx var)
{
  rtx call_reg = gen_reg_rtx (Pmode);
  rtx guard = get_guard_rtx ();

  if (HAVE_fp_protect_rm)
    {
      rtx insn = gen_fp_protect_rm (call_reg, guard);
      if (insn)
        {
          emit_insn (insn);
          return call_reg;
        }
    }

  gcc_unreachable();
  /* TODO add/test regular instructions */
  return var;
}

rtx get_guard_rtx()
{
  rtx ret;
  tree guard = targetm.stack_protect_guard ();

  ret = expand_normal (guard);

  return ret;
}

//void
//func_pointer_protect_check (tree node, tree guard)
//{
//  tree guard_decl = targetm.stack_protect_guard ();
//  rtx label = gen_label_rtx ();
//  rtx x, y, tmp;
//
//  x = expand_normal (guard);
//  y = expand_normal (guard_decl);
//
//  /* Allow the target to compare Y with X without leaking either into
//     a register.  */
//  switch (HAVE_stack_protect_test != 0)
//    {
//    case 1:
//      tmp = gen_stack_protect_test (x, y, label);
//      if (tmp)
//	{
//	  emit_insn (tmp);
//	  break;
//	}
//      /* FALLTHRU */
//
//    default:
//      emit_cmp_and_jump_insns (x, y, EQ, NULL_RTX, ptr_mode, 1, label);
//      break;
//    }
//
//  /* The noreturn predictor has been moved to the tree level.  The rtl-level
//     predictors estimate this branch about 20%, which isn't enough to get
//     things moved out of line.  Since this is the only extant case of adding
//     a noreturn function at the rtl level, it doesn't seem worth doing ought
//     except adding the prediction by hand.  */
//  tmp = get_last_insn ();
//  if (JUMP_P (tmp))
//    predict_insn_def (tmp, PRED_NORETURN, TAKEN);
//
//  expand_call (targetm.stack_protect_fail (), NULL_RTX, /*ignore=*/true);
//  free_temp_slots ();
//  emit_label (label);
//}

