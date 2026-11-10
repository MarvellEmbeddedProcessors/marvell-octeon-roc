/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

int
roc_ml_msg_id_range_set(struct roc_ml *roc_ml, uint16_t start, uint16_t end)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);

	if (start <= MBOX_MSG_GENERIC_MAX_ID || start > end)
		return -EINVAL;

	ml->msg_id_start = start;
	ml->msg_id_end = end;

	return 0;
}

bool
roc_ml_msg_id_range_check(struct roc_ml *roc_ml, uint16_t msg_id)
{
	struct ml *ml;

	if (roc_ml == NULL)
		return 0;

	ml = roc_ml_to_ml_priv(roc_ml);

	if (msg_id > ml->msg_id_start && msg_id < ml->msg_id_end)
		return 1;

	return 0;
}

int
roc_ml_msg_handler_register(struct roc_ml *roc_ml, void *cb)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct dev *dev = &ml->dev;

	if (cb == NULL)
		return -EINVAL;

	if (dev->ops)
		dev->ops->msg_process_cb = (msg_process_cb_t)cb;

	return 0;
}

int
roc_ml_msg_handler_unregister(struct roc_ml *roc_ml)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct dev *dev = &ml->dev;

	if (dev->ops)
		dev->ops->msg_process_cb = NULL;

	return 0;
}

static int
roc_ml_pfvf_mbox_msg_process(struct roc_ml *roc_ml, uint16_t vf, uint16_t msg_id, void *msg_req,
			     uint16_t req_len, void *msg_rsp, uint16_t rsp_len)
{
	struct ml *ml = roc_ml_to_ml_priv(roc_ml);
	struct mbox *mbox;
	struct msg_req *req;
	struct msg_rsp *rsp;
	int rc = -ENOSPC;
	int devid = 0;
	int hdrsz = sizeof(struct mbox_msghdr);

	if (ml->dev.vf == -1 && roc_ml_msg_id_range_check(roc_ml, msg_id)) {
		/* This is PF context */
		if (vf >= ml->dev.maxvf)
			return -EINVAL;
		devid = vf;
		mbox = mbox_get(&ml->dev.mbox_vfpf_up);
	} else {
		/* This is VF context */
		devid = 0; /* VF send all message to PF */
		mbox = mbox_get(ml->dev.mbox);
	}

	req = (struct msg_req *)mbox_alloc_msg_rsp(mbox, devid, req_len, rsp_len);
	if (!req)
		goto fail;

	req->hdr.pcifunc = roc_ml_pf_func_get(roc_ml);
	req->hdr.id = msg_id;
	req->hdr.sig = MBOX_REQ_SIG;
	mbox_memcpy((uint8_t *)req + hdrsz, (uint8_t *)msg_req + hdrsz, req_len - hdrsz);

	if (ml->dev.vf == -1) {
		mbox_msg_send_up(mbox, devid);
		rc = mbox_get_rsp(mbox, devid, (void *)&rsp);
		if (rc)
			goto fail;
	} else {
		rc = mbox_process_msg(mbox, (void *)&rsp);
		if (rc)
			goto fail;
	}

	if (rsp_len && msg_rsp != NULL)
		mbox_memcpy(msg_rsp, rsp, rsp_len);

fail:
	mbox_put(mbox);

	return rc;
}

#define M(_name, _id, _fn_name, _req_type, _rsp_type)                                              \
	int roc_##_fn_name(struct roc_ml *roc_ml, struct _req_type *req_msg,                       \
			   struct _rsp_type *rsp_msg)                                              \
	{                                                                                          \
		uint16_t msg_id = _id;                                                             \
		int rc;                                                                            \
		rc = roc_ml_pfvf_mbox_msg_process(roc_ml, 0, msg_id, req_msg,                      \
						  ml_pfvf_mbox_req_id2size(msg_id), rsp_msg,       \
						  ml_pfvf_mbox_rsp_id2size(msg_id));               \
		if (rc != 0) {                                                                     \
			plt_err("PF device is inactive");                                          \
			return rc;                                                                 \
		}                                                                                  \
		if (rsp_msg->hdr.id != msg_id) {                                                   \
			plt_err("Invalid msg response received %s  expected %s",                   \
				ml_pfvf_mbox_msg_id2name(rsp_msg->hdr.id),                         \
				ml_pfvf_mbox_msg_id2name(msg_id));                                 \
			return rc;                                                                 \
		}                                                                                  \
		return rc;                                                                         \
	}
ML_PFVF_MBOX_MESSAGES
#undef M
