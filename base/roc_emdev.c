/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#include "roc_api.h"
#include "roc_priv.h"

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
