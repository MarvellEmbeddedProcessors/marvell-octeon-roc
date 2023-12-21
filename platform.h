/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#ifndef included_oct_roc_platform_h
#define included_oct_roc_platform_h

#include <inttypes.h>
#include <assert.h>

#define OCT_UNIMPLEMENTED()                                                  \
  ({                                                                          \
    assert (0);                                                               \
  })

#include <util.h>
#include <bitmap.h>
#include <common.h>
#include <memzone.h>

/*
 * Device memory does not support unaligned access, instruct compiler to
 * not optimize the memory access when working with mailbox memory.
 */
#ifndef __io
#define __io volatile
#endif

#endif /* included_oct_roc_platform_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
