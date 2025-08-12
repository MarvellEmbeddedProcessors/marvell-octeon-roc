/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

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
