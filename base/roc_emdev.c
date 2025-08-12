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
	req->pswlfs = nb_psw_lfs; /* FIXME */

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
	struct psw_msix_offset_rsp *msix_rsp;
	struct msg_req *msix_req;
	struct psw_lf *psw_lf;
	struct mbox *mbox;
	int rc, i;

	/* Attach PSW LF */
	rc = psw_lf_attach(&emdev->dev, emdev->nb_psw_lfs);
	if (rc)
		return rc;

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

	return 0;
dpi_detach:
	rc |= psw_lf_detach(&emdev->dev);
	return rc;
}

static int
emdev_lf_detach(struct emdev *emdev)
{
	int rc = 0;

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

	emdev->emul_type = ROC_EMDEV_TYPE_VIRTIO;

	rc = emdev_psw_caps_get(emdev);
	if (rc)
		goto free_mem;

	/* Attach PSW LF */
	rc = emdev_lf_attach(emdev);
	if (rc)
		goto free_mem;

	roc_emdev->emul_type = emdev->emul_type;

	return 0;
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

	/* Detach PSW LF */
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
