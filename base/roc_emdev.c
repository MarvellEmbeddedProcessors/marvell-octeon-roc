/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#include "roc_api.h"
#include "roc_priv.h"

/* VIRTIO PCI NOTIFY area BAR offset */
#define ROC_EMDEV_VIRTIO_NOTIFY_AREA_OFF    256
#define ROC_EMDEV_VIRTIO_NOTIFY_AREA_STRIDE 8

#define PSW_EPFFUNC(port, epf, vf_id) \
	((((port) & 0x1) << 14) | (((epf) & 0x7) << 9) | ((vf_id) & 0xFF))

const struct psw_fid_entry psw_fid_base[ROC_EMDEV_TYPE_MAX][PSW_VIRTIO_FID_ENTRY_MAX] = {
	[ROC_EMDEV_TYPE_VIRTIO] = {
		/* VIRTIO PCI common config + VIRTIO DEV config area */
		[PSW_VIRTIO_FID_CFG] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_OFF,
			.size = (ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_LEN +
				 ROC_EMDEV_VIRTIO_PCI_DEV_CFG_LEN),
			.psw_type = PSW_TYPES_API,
			.read_en = 1,
			.write_en = 1,
			.read_mask = 0x0,
		},
		/* VIRTIO PCI notify area */
		[PSW_VIRTIO_FID_NOTIFY] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_NOTIFY_AREA_OFF,
			.psw_type = PSW_TYPES_PIDBL,
			.size = 0,
			.write_en = 1,
			.read_mask = 0x1,
			.stride = ROC_EMDEV_VIRTIO_NOTIFY_AREA_STRIDE,
		},
	},
};

static int
psw_lf_attach(struct dev *dev, uint8_t nb_psw_lfs)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct psw_rsrc_attach_req *req;
	int rc = -ENOMEM;

	/* Attach PSW LF */
	req = mbox_alloc_msg_psw_attach_resources(mbox);
	if (req == NULL)
		goto exit;

	req->modify = true;
	req->pswlfs = nb_psw_lfs;

	rc = mbox_process(mbox);
	if (rc)
		plt_err("Failed to attach PSW/DPI LF, rc=%d", rc);

exit:
	mbox_put(mbox);
	return rc;
}

static int
psw_lf_detach(struct dev *dev)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct psw_rsrc_detach_req *req;
	int rc = -ENOMEM;

	/* Detach PSW LF */
	req = mbox_alloc_msg_psw_detach_resources(mbox);
	if (req == NULL)
		goto exit;

	req->partial = 1;
	req->pswlfs = 1;

	rc = mbox_process(mbox);
	if (rc)
		plt_err("Failed to detach PSW/DPI LF, rc=%d", rc);

exit:
	mbox_put(mbox);
	return rc;
}

static int
emdev_lf_attach(struct emdev *emdev)
{
	uint8_t dpi_blkaddr = RVU_BLOCK_ADDR_DPI0;
	struct psw_msix_offset_rsp *msix_rsp;
	struct msg_req *msix_req;
	struct psw_lf *psw_lf;
	struct mbox *mbox;
	int rc, i;

	emdev->dpi_blkaddr = dpi_blkaddr;

	/* Attach PSW LF */
	rc = psw_lf_attach(&emdev->dev, emdev->nb_psw_lfs);
	if (rc)
		return rc;

	/* Attach DPI LF */
	rc = dpi_lf_attach(&emdev->dev, dpi_blkaddr, true, emdev->nb_dpi_lfs);
	if (rc)
		goto psw_detach;

	mbox = mbox_get(emdev->dev.mbox);
	/* Get MSIX offsets */
	msix_req = mbox_alloc_msg_psw_msix_offset(mbox);
	if (msix_req == NULL) {
		mbox_put(mbox);
		goto dpi_detach;
	}

	rc = mbox_process_msg(mbox, (void **)&msix_rsp);
	if (rc) {
		plt_err("Failed to get msix offsets for PSW/DPI LF, rc=%d", rc);
		mbox_put(mbox);
		goto dpi_detach;
	}
	mbox_put(mbox);

	/* Populate PSW LF's */
	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		psw_lf = &emdev->psw_lfs[i];
		psw_lf->lf_id = i;
		psw_lf->rbase = emdev->dev.bar2 + ((RVU_BLOCK_ADDR_PSW << 20) | (i << 12));
		psw_lf->msixoff = msix_rsp->pswlf_msixoff[i];
		psw_lf->emdev = emdev;
	}

	/* Init DPI LF's */
	for (i = 0; i < emdev->nb_dpi_lfs; i++) {
		rc = dpi_lf_init(&emdev->dpi_lfs[i], &emdev->dev, i);
		if (rc)
			goto dpi_detach;

		/* Update DPI LF's SSO/NPA PF_FUNC's */
		rc = roc_dpi_lf_pffunc_cfg(&emdev->dpi_lfs[i]);
		if (rc) {
			plt_err("Failed to configure SSO/NPA PF_FUNC for DPI LF, rc=%d", rc);
			goto dpi_detach;
		}

		/* Populate DPI queue size and first skip/later skip */
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].qsize = ROC_EMDEV_DPI_Q_SZ;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].cmd_len = DPI_CMD_SIZE_64B;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].first_skip = emdev->first_skip;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].later_skip = emdev->later_skip;

		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_OUTB].qsize = ROC_EMDEV_DPI_Q_SZ;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_OUTB].cmd_len = DPI_CMD_SIZE_64B;
	}

	return 0;
dpi_detach:
	rc |= dpi_lf_detach(&emdev->dev);
psw_detach:
	rc |= psw_lf_detach(&emdev->dev);
	return rc;
}

static int
emdev_lf_detach(struct emdev *emdev)
{
	int rc = 0;

	/* Detach DPI LF */
	rc |= dpi_lf_detach(&emdev->dev);

	/* Detach PSW LF */
	rc |= psw_lf_detach(&emdev->dev);

	return rc;
}

int
roc_emdev_init(struct roc_emdev *roc_emdev)
{
	struct plt_pci_device *pci_dev;
	struct idev_cfg *idev;
	struct emdev *emdev;
	int rc;

	idev = idev_get_cfg();
	if (idev == NULL)
		return -ENOTSUP;

	emdev = roc_emdev_to_emdev_priv(roc_emdev);
	pci_dev = roc_emdev->pci_dev;

	/* Initialize base device */
	rc = dev_init(&emdev->dev, pci_dev);
	if (rc)
		return rc;

	emdev->pci_dev = pci_dev;
	idev->emdev = emdev;

	return 0;
}

int
roc_emdev_fini(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	/* Finalize base device */
	return dev_fini(&emdev->dev, emdev->pci_dev);
}

static int
emdev_dpi_chan_tbl_config(struct emdev *emdev)
{
	struct roc_dpi_lf *lf;
	uint64_t tbl_entries[64], epf_id;
	uint16_t nb_entries, tbl_sz;
	int rc, i = 0, chan_tbl;

	/* Use default channel table if there is no one PF */
	if (emdev->nb_epfvfs == 1) {
		union roc_dpi_lf_ccfg ccfg;
		ccfg.u = BIT_ULL(63) | emdev->epf_id << 12 | 0;

		for (i = 0; i < emdev->nb_dpi_lfs; i++) {
			lf = &emdev->dpi_lfs[i];
			/* Setup default chan config */
			rc = roc_dpi_lf_ring_chan_cfg(&lf->queue[ROC_EMDEV_DPI_LF_RING_INB], &ccfg);
			rc |= roc_dpi_lf_ring_chan_cfg(&lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB],
						       &ccfg);
			if (rc) {
				plt_err("Failed to configure DPI ring default chan, rc=%d", rc);
				return rc;
			}
		}
		return 0;
	}

	/* Alloc one DPI Channel Table */
	tbl_sz = emdev->nb_epfvfs * 2;
	chan_tbl = dpi_chan_tbl_alloc(&emdev->dev, emdev->dpi_blkaddr, tbl_sz);
	if (chan_tbl < 0) {
		plt_err("Failed to allocate DPI Channel Table, rc=%d", chan_tbl);
		return chan_tbl;
	}

	emdev->dpi_chan_tbl = chan_tbl;
	emdev->dpi_chan_tbl_sz = tbl_sz;
	epf_id = emdev->epf_id;

	/* Fill DPI Channel Table entries */
	i = 0;
	while (i < emdev->nb_epfvfs) {
		/* One entry per EPF_FUNC */
		tbl_entries[i % 64] = BIT_ULL(63) | epf_id << 12 | i;
		i++;

		/* Write 64 entries at a time */
		if (i % 64 == 0) {
			nb_entries = 64;
			rc = dpi_chan_tbl_update(&emdev->dev, emdev->dpi_blkaddr, chan_tbl,
						 tbl_entries, i - nb_entries, nb_entries);
			if (rc) {
				plt_err("Failed to write DPI Channel Table, rc=%d", rc);
				return rc;
			}
		}
	}

	/* Write remaining entries */
	nb_entries = i % 64;
	if (nb_entries) {
		rc = dpi_chan_tbl_update(&emdev->dev, emdev->dpi_blkaddr, chan_tbl, tbl_entries,
					 i - nb_entries, nb_entries);
		if (rc) {
			plt_err("Failed to write DPI Channel Table, rc=%d", rc);
			return rc;
		}
	}
	return 0;
}

static void
emdev_dpi_lf_ring_ena_dis(struct roc_dpi_lf *lf, uint8_t ring_idx, uint8_t enb)
{
	uint64_t reg;

	reg = plt_read64(lf->rbase + DPI_LF_RINGX_CFG(ring_idx));
	if (enb)
		reg |= DPI_LF_QCFG_QEN;
	else
		reg &= ~DPI_LF_QCFG_QEN;
	plt_write64(reg, lf->rbase + DPI_LF_RINGX_CFG(ring_idx));
}

static int
emdev_dpi_setup(struct emdev *emdev)
{
	struct roc_dpi_lf_ring_cfg rcfg;
	struct roc_dpi_lf_que *lf_q;
	struct roc_dpi_lf *lf;
	int i, rc = 0;

	rc = emdev_dpi_chan_tbl_config(emdev);
	if (rc)
		return rc;

	/* Setup DPI rings */
	for (i = 0; i < emdev->nb_dpi_lfs; i++) {
		lf = &emdev->dpi_lfs[i];

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_INB];

		if (emdev->nb_epfvfs > 1) {
			/* Associate LF to channel table */
			rc = dpi_chan_tbl_ena_dis(&emdev->dev, lf->slot, emdev->dpi_chan_tbl, true);
			if (rc) {
				plt_err("Failed to associate DPI LF to channel table, rc=%d", rc);
				goto cleanup_ring;
			}
		}

		/* Setup DPI ring for ROC_EMDEV_DPI_LF_RING_INB */
		memset(&rcfg, 0, sizeof(rcfg));
		rcfg.xtype = DPI_XTYPE_INBOUND;
		rcfg.rport = 0;
		rcfg.isize = lf_q->cmd_len / DPI_CMD_SIZE_128B;
		rcfg.ring_idx = ROC_EMDEV_DPI_LF_RING_INB;

		rc = roc_dpi_lf_ring_init(lf_q, &rcfg);
		if (rc) {
			plt_err("Failed to setup DPI ring for DEV2MEM, rc=%d", rc);
			goto cleanup_ring;
		}

		/* enable dpi lf inbound ring */
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_INB, 1);

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
		/* Setup DPI ring for ROC_EMDEV_DPI_LF_RING_OUTB */
		memset(&rcfg, 0, sizeof(rcfg));
		rcfg.xtype = DPI_XTYPE_OUTBOUND;
		rcfg.wport = 0;
		rcfg.isize = lf_q->cmd_len / DPI_CMD_SIZE_128B;
		rcfg.ring_idx = ROC_EMDEV_DPI_LF_RING_OUTB;

		rc = roc_dpi_lf_ring_init(lf_q, &rcfg);
		if (rc) {
			plt_err("Failed to setup DPI ring for MEM2DEV, rc=%d", rc);
			goto cleanup_ring;
		}

		/* enable dpi lf outbound ring */
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_OUTB, 1);
	}

	return 0;
cleanup_ring:
	for (; i > 0; i--) {
		lf = &emdev->dpi_lfs[i - 1];
		/* Disable rings */
		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_INB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_INB, 0);
		roc_dpi_lf_ring_fini(lf_q);

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_OUTB, 0);
		roc_dpi_lf_ring_fini(lf_q);
	}
	if (emdev->nb_epfvfs > 1) {
		dpi_chan_tbl_ena_dis(&emdev->dev, emdev->dpi_blkaddr, emdev->dpi_chan_tbl, false);
		rc |= dpi_chan_tbl_free(&emdev->dev, emdev->dpi_blkaddr, emdev->dpi_chan_tbl);
	}
	return rc;
}

static int
emdev_dpi_release(struct emdev *emdev)
{
	struct roc_dpi_lf_que *lf_q;
	struct roc_dpi_lf *lf;
	int i, rc = 0;

	/* Disable DPI rings */
	for (i = 0; i < emdev->nb_dpi_lfs; i++) {
		lf = &emdev->dpi_lfs[i];
		/* Disable rings */
		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_INB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_INB, 0);
		roc_dpi_lf_ring_fini(lf_q);

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_OUTB, 0);
		roc_dpi_lf_ring_fini(lf_q);
	}

	if (emdev->nb_epfvfs > 1) {
		/* Disable DPI LF from channel table */
		dpi_chan_tbl_ena_dis(&emdev->dev, emdev->dpi_blkaddr, emdev->dpi_chan_tbl, false);
		rc = dpi_chan_tbl_free(&emdev->dev, emdev->dpi_blkaddr, emdev->dpi_chan_tbl);
	}

	return rc;
}

static int
emdev_psw_caps_get(struct emdev *emdev)
{
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_caps_get_rsp *caps;
	int rc;

	mbox_alloc_msg_psw_caps_get(mbox);

	rc = mbox_process_msg(mbox, (void *)&caps);
	if (rc) {
		plt_err("Failed to get PSW caps, rc=%d", rc);
		goto exit;
	}
	emdev->epf_id = caps->epf_id;
	emdev->caps.const0 = caps->const0;
	emdev->caps.const1 = caps->const1;
	emdev->caps.const2 = caps->const2;
	mbox_memcpy(emdev->caps.fid_type_const, caps->fid_type_const,
		    sizeof(emdev->caps.fid_type_const));
exit:
	mbox_put(mbox);
	return rc;
}

int
roc_emdev_setup(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	uint16_t nb_inb_qs, nb_outb_qs, nb_notify_qs;
	uint16_t nb_psw_lfs;
	int rc;

	nb_inb_qs = roc_emdev->nb_inb_qs;
	nb_outb_qs = roc_emdev->nb_outb_qs;
	nb_notify_qs = roc_emdev->nb_notify_qs;

	/* Each PSW LFs have 8 notify queues */
	nb_psw_lfs = nb_notify_qs / 8;
	if (nb_notify_qs % 8)
		nb_psw_lfs++;

	emdev->nb_inb_qs = nb_inb_qs;
	emdev->nb_outb_qs = nb_outb_qs;
	emdev->nb_psw_lfs = nb_psw_lfs;
	emdev->nb_notify_qs = nb_notify_qs;
	emdev->nb_epfvfs = roc_emdev->nb_epfvfs;
	emdev->nb_dpi_lfs = nb_notify_qs;
	emdev->first_skip = roc_emdev->first_skip;
	emdev->later_skip = roc_emdev->later_skip;

	rc = -ENOMEM;
	/* Allocate memory to hold AQs */
	emdev->aq_qps = plt_zmalloc(sizeof(struct roc_emdev_psw_aq_qp) * nb_psw_lfs, 0);
	if (!emdev->aq_qps)
		goto free_mem;

	/* Allocate memory to hold pointers to NQ QP's */
	emdev->nq_qps = plt_zmalloc(sizeof(struct roc_emdev_psw_nq_qp *) * nb_notify_qs, 0);
	if (!emdev->nq_qps)
		goto free_mem;

	/* Allocate memory to hold PSW LFs and its notification queues */
	emdev->psw_lfs = plt_zmalloc(sizeof(struct psw_lf) * nb_psw_lfs, 0);
	if (!emdev->psw_lfs)
		goto free_mem;

	/* Allocate memory to hold DPI LFs */
	emdev->dpi_lfs = plt_zmalloc(sizeof(struct roc_dpi_lf) * emdev->nb_dpi_lfs, 0);
	if (!emdev->dpi_lfs)
		goto free_mem;

	emdev->emul_type = ROC_EMDEV_TYPE_VIRTIO;

	rc = emdev_psw_caps_get(emdev);
	if (rc)
		goto free_mem;

	/* Attach PSW, DPI LF */
	rc = emdev_lf_attach(emdev);
	if (rc)
		goto free_mem;

	/* Setup DPI rings */
	rc = emdev_dpi_setup(emdev);
	if (rc)
		goto detach_lf;

	roc_emdev->emul_type = emdev->emul_type;

	return 0;
detach_lf:
	rc |= emdev_lf_detach(emdev);
free_mem:
	plt_free(emdev->aq_qps);
	plt_free(emdev->nq_qps);
	plt_free(emdev->psw_lfs);
	return rc;
}

int
roc_emdev_release(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	int rc;

	/* DPI LF cleanup */
	rc = emdev_dpi_release(emdev);
	if (rc)
		return rc;

	/* Detach PSW, DPI LF */
	rc = emdev_lf_detach(emdev);
	if (rc)
		return rc;

	plt_free(emdev->aq_qps);
	plt_free(emdev->nq_qps);
	plt_free(emdev->psw_lfs);
	emdev->aq_qps = NULL;
	emdev->nq_qps = NULL;
	emdev->psw_lfs = NULL;

	return 0;
}

struct roc_dpi_lf *
roc_emdev_dpi_lf_base_get(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	return emdev->dpi_lfs;
}

void
roc_emdev_flrnotif_cb_register(struct roc_emdev *roc_emdev, roc_emdev_flrnotif_cb_t cb,
			       void *cb_args)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev->flrnotif_cb = cb;
	emdev->flrnotif_cb_args = cb_args;
}

void
roc_emdev_flrnotif_cb_unregister(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev->flrnotif_cb = NULL;
	emdev->flrnotif_cb_args = NULL;
}
