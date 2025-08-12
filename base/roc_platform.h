/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_PLATFORM_H_
#define _ROC_PLATFORM_H_

#include <platform.h>

uint16_t roc_plt_control_lmt_id_get(void);
uint16_t roc_plt_lmt_validate(void);

static inline void
roc_trace_mbox_region(const char *func, const char *msg, uint16_t pcifunc, int data,
		      uint16_t cookie)
{
}

static inline void
roc_trace_mbox_process(const char *func, const char *msg, uint16_t num_msgs, uint16_t pcifunc)
{
}

static inline void
roc_trace_mbox_interrupt(const char *func, int pcifunc, uint64_t intr, uint64_t mbox_data)
{
}

static inline void
roc_trace_mbox_vf_pf_handle(const char *func, uint16_t pcifunc, int data)
{
}

static inline void
roc_trace_mbox_error(const char *func, const char *msg, int data)
{
}

static inline void
roc_trace_mbox_vf_flr(const char *func, uint16_t from_vf, uint16_t pcifunc)
{
}

#endif /* _ROC_PLATFORM_H_ */
