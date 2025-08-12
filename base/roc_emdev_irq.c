/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

static void
emdev_lf_apinotif_intr_enb_dis(struct psw_lf *lf, bool enb)
{
	if (enb)
		plt_write64(1, lf->rbase + PSW_LF_APINOTIF_INT_ENA_W1S);
	else
		plt_write64(1, lf->rbase + PSW_LF_APINOTIF_INT_ENA_W1C);
}

static void
emdev_lf_apinotif_irq(void *param)
{
	struct psw_lf *lf = (struct psw_lf *)param;
	uint64_t intr;

	intr = plt_read64(lf->rbase + PSW_LF_APINOTIF_INT);
	if (intr == 0)
		return;

	/* Clear interrupt */
	plt_write64(intr, lf->rbase + PSW_LF_APINOTIF_INT);
}

static int
emdev_lf_register_apinotif_irq(struct psw_lf *lf)
{
	struct emdev *emdev = lf->emdev;
	struct plt_pci_device *pci_dev = emdev->pci_dev;
	struct plt_intr_handle *handle;
	int rc, vec;

	if (lf->msixoff == MSIX_VECTOR_INVALID) {
		plt_err("Invalid PSWLF MSIX vector offset vector: 0x%x", lf->msixoff);
		return -EINVAL;
	}

	vec = lf->msixoff + PSW_LF_APINOTIF_INT_VEC;
	handle = pci_dev->intr_handle;

	/* Clear API notification interrupt */
	emdev_lf_apinotif_intr_enb_dis(lf, false);
	/* Register handler for API notification interrupt */
	rc = dev_irq_register(handle, emdev_lf_apinotif_irq, lf, vec);
	/* Enable API notification interrupt */
	emdev_lf_apinotif_intr_enb_dis(lf, true);

	return rc;
}

static int
emdev_lf_irqs_register(struct emdev *emdev)
{
	struct psw_lf *psw_lf;
	int rc, i;

	/* Register psw api notification interrupt  */
	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		psw_lf = &emdev->psw_lfs[i];
		rc = emdev_lf_register_apinotif_irq(psw_lf);
		if (rc) {
			plt_err("Error registering PSWLF APINOTIF irq for lf=%d, rc=%d", i, rc);
			break;
		}
	}

	return rc;
}

int
roc_emdev_irqs_register(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	return emdev_lf_irqs_register(emdev);
}

static void
emdev_lf_unregister_apinotif_irq(struct psw_lf *lf)
{
	struct plt_pci_device *pci_dev = lf->emdev->pci_dev;
	struct plt_intr_handle *handle;
	int vec;

	handle = pci_dev->intr_handle;

	vec = lf->msixoff + PSW_LF_APINOTIF_INT_VEC;
	emdev_lf_apinotif_intr_enb_dis(lf, false);
	dev_irq_unregister(handle, emdev_lf_apinotif_irq, lf, vec);
}

static void
emdev_lf_irqs_unregister(struct emdev *emdev)
{
	struct psw_lf *psw_lf;
	int i;

	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		psw_lf = &emdev->psw_lfs[i];
		emdev_lf_unregister_apinotif_irq(psw_lf);
	}
}

void
roc_emdev_irqs_unregister(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev_lf_irqs_unregister(emdev);
}
