/* TODO description and legal notice */

#ifndef GCC_FPPROTECT_H
#define GCC_FPPROTECT_H

#include "tree.h"

/* TODO descriptions */
extern void fpp_build_globals_initializer (void);

extern void fpp_register_disable_attribute (void);

extern void fpp_transform_globals (void);

extern rtx fpp_expand_protect_call (rtx fun);

#endif /* GCC_FPPROTECT_H */

