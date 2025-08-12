/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_ROC_EMDEV_H__
#define __INCLUDE_ROC_EMDEV_H__

enum roc_emdev_type { ROC_EMDEV_TYPE_VIRTIO = 1, ROC_EMDEV_TYPE_NVME, ROC_EMDEV_TYPE_MAX };

struct roc_emdev {
	struct plt_pci_device *pci_dev;
	uint16_t nb_epfvfs;
	uint16_t nb_inb_qs;
	uint16_t nb_outb_qs;
	uint16_t nb_notify_qs;
	uint16_t nb_dpi_lfs;
	uint8_t first_skip;
	uint8_t later_skip;
	/* End of input params */
	enum roc_emdev_type emul_type;
#define ROC_EMDEV_MEM_SZ (6 * 1070)
	uint8_t reserved[ROC_EMDEV_MEM_SZ] __plt_cache_aligned;
};

struct roc_emdev_apinotif_handle {
	uint32_t addr;
	uint64_t data;
	uint8_t be;
	bool is_read;
};

typedef int (*roc_emdev_apinotif_cb_t)(uint16_t epf_func, struct roc_emdev_apinotif_handle *desc,
				       void *args);

typedef int (*roc_emdev_flrnotif_cb_t)(uint16_t epf_func, void *args);

int __roc_api roc_emdev_init(struct roc_emdev *roc_emdev);
int __roc_api roc_emdev_fini(struct roc_emdev *roc_emdev);

#endif /* __INCLUDE_ROC_EMDEV_H__ */
