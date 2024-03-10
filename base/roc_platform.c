/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"

#define PLT_INIT_CB_MAX 8

static int plt_init_cb_num;
static roc_plt_init_cb_t plt_init_cbs[PLT_INIT_CB_MAX];

int
roc_plt_init_cb_register(roc_plt_init_cb_t cb)
{
	if (plt_init_cb_num >= PLT_INIT_CB_MAX)
		return -ERANGE;

	plt_init_cbs[plt_init_cb_num++] = cb;
	return 0;
}

uint16_t
roc_plt_control_lmt_id_get(void)
{
	uint32_t lcore_id = plt_lcore_id();
	if (lcore_id != LCORE_ID_ANY)
		return lcore_id << ROC_LMT_LINES_PER_CORE_LOG2;
	else
		/* Return Last LMT ID to be use in control path functionality */
		return ROC_NUM_LMT_LINES - 1;
}

uint16_t
roc_plt_lmt_validate(void)
{
	if (!roc_model_is_cn9k()) {
		/* Last LMT line is reserved for control specific operation and can be
		 * use from any EAL or non EAL cores.
		 */
		if ((PLT_MAX_LCORE << ROC_LMT_LINES_PER_CORE_LOG2) >
		    (ROC_NUM_LMT_LINES - 1))
			return 0;
	}
	return 1;
}

int
roc_plt_init(void)
{
	int i, rc;

	for (i = 0; i < plt_init_cb_num; i++) {
		rc = (*plt_init_cbs[i])();
		if (rc)
			return rc;
	}

	return 0;
}
