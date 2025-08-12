/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

int
roc_emdev_psw_aq_qp_init(struct roc_emdev *roc_emdev, struct roc_emdev_psw_aq_qp *aq)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	union psw_apinotif_queue_config_u apinotif_q_cfg;
	union psw_apiack_queue_config_u apiack_q_cfg;
	union psw_queue_config_u q_cfg_base;
	struct psw_lf *psw_lf;
	uintptr_t rbase;
	int rc;

	/* Check if QID is within range of PSW LFs attached */
	if (aq->qid >= emdev->nb_psw_lfs)
		return -EINVAL;

	psw_lf = &emdev->psw_lfs[aq->qid];
	rbase = psw_lf->rbase;

	/* Clamp up/down number of descriptors */
	aq->nb_desc = PLT_MAX(aq->nb_desc, 4u);
	aq->nb_desc = PLT_MIN(aq->nb_desc, 64 * 1024u);
	aq->q_sz = plt_align32pow2(aq->nb_desc);
	aq->qmask = aq->q_sz - 1;
	aq->roc_emdev = roc_emdev;

	rc = -ENOMEM;
	aq->notify_q_base = plt_zmalloc(PSW_ANQ_DESC_SZ * aq->nb_desc, 256);
	if (!aq->notify_q_base)
		return rc;

	aq->ack_q_base = plt_zmalloc(PSW_AAQ_DESC_SZ * aq->nb_desc, 256);
	if (!aq->ack_q_base)
		goto error;

	/* Initialize PSW API Notification Queue config */
	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&apinotif_q_cfg, 0, sizeof(apinotif_q_cfg));
	q_cfg_base.s.base_addr = (uint64_t)aq->notify_q_base >> 6;
	q_cfg_base.s.log2ds = plt_log2_u32(PSW_ANQ_DESC_SZ) - 3;
	q_cfg_base.s.log2qs = plt_log2_u32(aq->q_sz) - 1;
	q_cfg_base.s.enable = 1;

	plt_write64(q_cfg_base.u[1], rbase + PSW_LF_ANQCX(1));
	plt_write64(q_cfg_base.u[2], rbase + PSW_LF_ANQCX(2));
	plt_write64(q_cfg_base.u[3], rbase + PSW_LF_ANQCX(3));
	plt_write64(apinotif_q_cfg.u[0], rbase + PSW_LF_ANQCX(4));
	plt_write64(apinotif_q_cfg.u[1], rbase + PSW_LF_ANQCX(5));
	plt_write64(apinotif_q_cfg.u[2], rbase + PSW_LF_ANQCX(6));
	plt_write64(apinotif_q_cfg.u[3], rbase + PSW_LF_ANQCX(7));
	plt_write64(q_cfg_base.u[0], rbase + PSW_LF_ANQCX(0));

	/* Initialize PSW API acknowledgment Queue config */
	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&apiack_q_cfg, 0, sizeof(apiack_q_cfg));
	q_cfg_base.s.base_addr = (uint64_t)aq->ack_q_base >> 6;
	q_cfg_base.s.log2ds = plt_log2_u32(PSW_AAQ_DESC_SZ) - 3;
	q_cfg_base.s.log2qs = plt_log2_u32(aq->q_sz) - 1;
	q_cfg_base.s.enable = 1;

	plt_write64(q_cfg_base.u[1], rbase + PSW_LF_AAQCX(1));
	plt_write64(q_cfg_base.u[2], rbase + PSW_LF_AAQCX(2));
	plt_write64(q_cfg_base.u[3], rbase + PSW_LF_AAQCX(3));
	plt_write64(apiack_q_cfg.u[0], rbase + PSW_LF_AAQCX(4));
	plt_write64(apiack_q_cfg.u[1], rbase + PSW_LF_AAQCX(5));
	plt_write64(apiack_q_cfg.u[2], rbase + PSW_LF_AAQCX(6));
	plt_write64(apiack_q_cfg.u[3], rbase + PSW_LF_AAQCX(7));
	plt_write64(q_cfg_base.u[0], rbase + PSW_LF_AAQCX(0));

	aq->notify_q_pi_dbell = rbase + PSW_LF_ANQCX(2);
	aq->notify_q_ci_dbell = rbase + PSW_LF_ANQCX(3);
	aq->ack_q_pi_dbell = rbase + PSW_LF_AAQCX(2);
	aq->ack_q_ci_dbell = rbase + PSW_LF_AAQCX(3);

	return 0;
error:
	plt_free(aq->notify_q_base);
	plt_free(aq->ack_q_base);
	return rc;
}

int
roc_emdev_psw_aq_qp_fini(struct roc_emdev_psw_aq_qp *aq)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(aq->roc_emdev);
	struct psw_lf *psw_lf;
	uintptr_t rbase;
	uint64_t data;

	/* Check if QID is within range of PSW LFs attached */
	if (aq->qid >= emdev->nb_psw_lfs)
		return -EINVAL;

	psw_lf = &emdev->psw_lfs[aq->qid];
	rbase = psw_lf->rbase;

	/* Disable API notification queue */
	data = plt_read64(rbase + PSW_LF_ANQCX(0));
	data &= ~BIT_ULL(0);
	plt_write64(data, rbase + PSW_LF_ANQCX(0));

	/* Disable API acknowledgment queue */
	data = plt_read64(rbase + PSW_LF_AAQCX(0));
	data &= ~BIT_ULL(0);
	plt_write64(data, rbase + PSW_LF_AAQCX(0));

	plt_free(aq->notify_q_base);
	plt_free(aq->ack_q_base);
	return 0;
}

int
roc_emdev_psw_nq_qp_init(struct roc_emdev *roc_emdev, struct roc_emdev_psw_nq_qp *nq)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	union psw_notif_queue_config_u notif_q_cfg;
	union psw_ack_queue_config_u ack_q_cfg;
	union psw_queue_config_u q_cfg_base;
	uint16_t nq_qid = nq->qid % 8;
	uint16_t nq_lf = nq->qid / 8;
	struct psw_lf *psw_lf;
	uintptr_t rbase;
	int rc;

	/* Check if QID is within range of PSW LFs attached */
	if (nq->qid >= emdev->nb_notify_qs)
		return -EINVAL;

	psw_lf = &emdev->psw_lfs[nq_lf];
	rbase = psw_lf->rbase;

	/* Clamp up/down number of descriptors */
	nq->nb_desc = PLT_MAX(nq->nb_desc, 4u);
	nq->nb_desc = PLT_MIN(nq->nb_desc, 64 * 1024u);
	nq->q_sz = plt_align32pow2(nq->nb_desc);
	nq->qmask = nq->q_sz - 1;
	nq->roc_emdev = roc_emdev;

	rc = -ENOMEM;
	nq->notify_q_base = plt_zmalloc(PSW_NQ_DESC_SZ * nq->nb_desc, 256);
	if (!nq->notify_q_base)
		return rc;

	nq->ack_q_base = plt_zmalloc(PSW_NQ_DESC_SZ * nq->nb_desc, 256);
	if (!nq->ack_q_base)
		goto error;

	/* Initialize PSW notification Queue config */
	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&notif_q_cfg, 0, sizeof(notif_q_cfg));
	q_cfg_base.s.base_addr = (uint64_t)nq->notify_q_base >> 6;
	q_cfg_base.s.log2ds = plt_log2_u32(PSW_NQ_DESC_SZ) - 3;
	q_cfg_base.s.log2qs = plt_log2_u32(nq->q_sz) - 1;
	q_cfg_base.s.enable = 1;

	plt_write64(q_cfg_base.u[1], rbase + PSW_LF_NX_QCX(nq_qid, 1));
	plt_write64(q_cfg_base.u[2], rbase + PSW_LF_NX_QCX(nq_qid, 2));
	plt_write64(q_cfg_base.u[3], rbase + PSW_LF_NX_QCX(nq_qid, 3));
	plt_write64(notif_q_cfg.u[0], rbase + PSW_LF_NX_QCX(nq_qid, 4));
	plt_write64(notif_q_cfg.u[1], rbase + PSW_LF_NX_QCX(nq_qid, 5));
	plt_write64(notif_q_cfg.u[2], rbase + PSW_LF_NX_QCX(nq_qid, 6));
	plt_write64(notif_q_cfg.u[3], rbase + PSW_LF_NX_QCX(nq_qid, 7));
	plt_write64(q_cfg_base.u[0], rbase + PSW_LF_NX_QCX(nq_qid, 0));

	/* Initialize PSW API acknowledgment Queue config */
	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&ack_q_cfg, 0, sizeof(ack_q_cfg));
	q_cfg_base.s.base_addr = (uint64_t)nq->ack_q_base >> 6;
	q_cfg_base.s.log2ds = plt_log2_u32(PSW_AQ_DESC_SZ) - 3;
	q_cfg_base.s.log2qs = plt_log2_u32(nq->q_sz) - 1;
	q_cfg_base.s.enable = 1;

	plt_write64(q_cfg_base.u[0], rbase + PSW_LF_AX_QCX(nq_qid, 0));
	plt_write64(q_cfg_base.u[1], rbase + PSW_LF_AX_QCX(nq_qid, 1));
	plt_write64(q_cfg_base.u[2], rbase + PSW_LF_AX_QCX(nq_qid, 2));
	plt_write64(q_cfg_base.u[3], rbase + PSW_LF_AX_QCX(nq_qid, 3));
	plt_write64(ack_q_cfg.u[0], rbase + PSW_LF_AX_QCX(nq_qid, 4));
	plt_write64(ack_q_cfg.u[1], rbase + PSW_LF_AX_QCX(nq_qid, 5));
	plt_write64(ack_q_cfg.u[2], rbase + PSW_LF_AX_QCX(nq_qid, 6));
	plt_write64(ack_q_cfg.u[3], rbase + PSW_LF_AX_QCX(nq_qid, 7));

	nq->notify_q_pi_dbell = rbase + PSW_LF_NX_QCX(nq_qid, 2);
	nq->notify_q_ci_dbell = rbase + PSW_LF_NX_QCX(nq_qid, 3);
	nq->ack_q_pi_dbell = rbase + PSW_LF_AX_QCX(nq_qid, 2);
	nq->ack_q_ci_dbell = rbase + PSW_LF_AX_QCX(nq_qid, 3);
	nq->enable = true;

	return 0;
error:
	plt_free(nq->notify_q_base);
	plt_free(nq->ack_q_base);
	return rc;
}

int
roc_emdev_psw_nq_qp_fini(struct roc_emdev_psw_nq_qp *nq)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(nq->roc_emdev);
	uint16_t nq_qid = nq->qid % 8;
	uint16_t nq_lfid = nq->qid / 8;
	struct psw_lf *psw_lf;
	uintptr_t rbase;
	uint64_t data;

	/* Check if QID is within range of PSW LFs attached */
	if (nq->qid >= emdev->nb_notify_qs)
		return -EINVAL;
	if (!nq->enable)
		return 0;

	psw_lf = &emdev->psw_lfs[nq_lfid];
	rbase = psw_lf->rbase;

	/* Disable notification queue */
	data = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 0));
	data &= ~BIT_ULL(0);
	plt_write64(data, rbase + PSW_LF_NX_QCX(nq_qid, 0));

	/* Disable acknowledgment queue */
	data = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 0));
	data &= ~BIT_ULL(0);
	plt_write64(data, rbase + PSW_LF_AX_QCX(nq_qid, 0));

	plt_free(nq->notify_q_base);
	plt_free(nq->ack_q_base);
	nq->enable = false;

	return 0;
}
int
roc_emdev_psw_epfvf_config(struct roc_emdev *roc_emdev, uint16_t evf_id, uint16_t notify_qbase,
			   bool enable)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_epfvf_pcie_cfg_req *pcie_req;
	struct psw_epfvf_map_cfg_req *map_req;
	struct emdev_epfvf *epfvf;
	uint16_t psw_lfid;
	int rc;

	/* Check if EVF id is within range of EPF/VFs attached */
	if (evf_id >= emdev->nb_epfvfs)
		return -EINVAL;

	epfvf = &emdev->epfvfs[evf_id];
	psw_lfid = notify_qbase / 8;

	/* Map EPFVF to PSW LF */
	map_req = mbox_alloc_msg_psw_epfvf_map_cfg(mbox);
	if (!map_req) {
		rc = -ENOMEM;
		goto exit;
	}
	map_req->evf_id = evf_id;
	map_req->lf_id = psw_lfid;
	map_req->enable = !!enable;

	rc = mbox_process(mbox);
	if (rc)
		goto exit;

	/* Configure EPFVF PCIe attributes */
	pcie_req = mbox_alloc_msg_psw_epfvf_pcie_cfg(mbox);
	if (!pcie_req) {
		rc = -ENOMEM;
		goto exit;
	}
	pcie_req->evf_id = evf_id;
	pcie_req->master_enable = !!enable;
	pcie_req->msix_enable = !!enable;

	rc = mbox_process(mbox);
	if (rc)
		goto exit;

	epfvf->psw_lfid = psw_lfid;
exit:
	mbox_put(mbox);
	return rc;
}
