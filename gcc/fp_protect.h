/* TODO description and legal notice */

#ifndef GCC_FP_PROTECT_H
#define GCC_FP_PROTECT_H

#include "tree.h"
#include "rtl.h"

/* TODO descriptions */
extern void func_pointer_protect_assignment (tree to, tree from);

extern bool func_pointer_has_guard (tree var);

extern void func_pointer_add_guard (tree var);

extern void func_pointer_remove_guard (tree var);

extern void func_pointer_prepare_call (tree call_dst);

extern void func_pointer_generate_init_routine (const char* filename);

extern void build_globals_initializer();

#endif /* GCC_FP_PROTECT_H */

