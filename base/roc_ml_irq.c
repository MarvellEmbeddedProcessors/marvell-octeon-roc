/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

#define ML_LF_ERR_INT_JCMDQ_OVFL	    BIT(0)
#define ML_LF_ERR_INT_JOBPTR_ERR	    BIT(1)
#define ML_LF_ERR_INT_DESCRIPTOR_ERR	    BIT(2)
#define ML_LF_ERR_INT_DMA_LF_RADDR_SIZE_ERR BIT(3)
#define ML_LF_ERR_INT_DMA_LF_WADDR_SIZE_ERR BIT(4)
#define ML_LF_ERR_INT_ACC_LF_RADDR_SIZE_ERR BIT(5)
#define ML_LF_ERR_INT_ACC_LF_WADDR_SIZE_ERR BIT(6)
#define ML_LF_ERR_INT_ACC_LF_RADDR_EN_ERR   BIT(7)
#define ML_LF_ERR_INT_ACC_LF_WADDR_EN_ERR   BIT(8)

static void
ml_err_irq(void *param)
{
	struct roc_ml_lf *lf = (struct roc_ml_lf *)param;
	uint64_t intr;

	intr = plt_read64(lf->rbase + ML_LF_ERR_INT);
	if (intr == 0)
		return;

	if (intr & ML_LF_ERR_INT_JCMDQ_OVFL)
		plt_err("Err_intr=0x%" PRIx64 " : JCMDQ overflow", intr);
	if (intr & ML_LF_ERR_INT_JOBPTR_ERR)
		plt_err("Err_intr=0x%" PRIx64 " : Job pointer out of bounds", intr);
	if (intr & ML_LF_ERR_INT_DESCRIPTOR_ERR)
		plt_err("Err_intr=0x%" PRIx64 " : Job descriptor fetch error", intr);
	if (intr & ML_LF_ERR_INT_DMA_LF_RADDR_SIZE_ERR)
		plt_err("Err_intr=0x%" PRIx64
			" : MLIP DMA LF read address greater than programmed size",
			intr);
	if (intr & ML_LF_ERR_INT_DMA_LF_WADDR_SIZE_ERR)
		plt_err("Err_intr=0x%" PRIx64
			" : MLIP DMA LF write address greater than programmed size",
			intr);
	if (intr & ML_LF_ERR_INT_ACC_LF_RADDR_SIZE_ERR)
		plt_err("Err_intr=0x%" PRIx64
			" : MLIP ACC LF read address size greater than programmed size",
			intr);
	if (intr & ML_LF_ERR_INT_ACC_LF_WADDR_SIZE_ERR)
		plt_err("Err_intr=0x%" PRIx64
			" : MLIP ACC LF write address size greater than programmed size",
			intr);
	if (intr & ML_LF_ERR_INT_ACC_LF_RADDR_EN_ERR)
		plt_err("Err_intr=0x%" PRIx64 " : MLIP ACC LF read access to LF disabled by CSR",
			intr);
	if (intr & ML_LF_ERR_INT_ACC_LF_WADDR_EN_ERR)
		plt_err("Err_intr=0x%" PRIx64 " : MLIP ACC LF write access to LF disabled by CSR",
			intr);

	/* Clear interrupt */
	plt_write64(intr, lf->rbase + ML_LF_ERR_INT);
}

static int
ml_register_err_irq(struct roc_ml_lf *lf)
{
	struct plt_intr_handle *handle = lf->intr_handle;
	int rc, vec;

	vec = lf->msixoff + ML_LF_INT_VEC_ERR_INT;

	/* Clear err interrupt */
	plt_write64(~0ull, lf->rbase + ML_LF_ERR_INT_ENA_W1C);

	/* Register err interrupt vector */
	rc = dev_irq_register(handle, ml_err_irq, lf, vec);

	/* Enable hw interrupt */
	plt_write64(~0ull, lf->rbase + ML_LF_ERR_INT_ENA_W1S);

	return rc;
}

static void
ml_unregister_err_irq(struct roc_ml_lf *lf)
{
	struct plt_intr_handle *handle = lf->intr_handle;
	int vec;

	vec = lf->msixoff + ML_LF_INT_VEC_ERR_INT;

	/* Clear err interrupt */
	plt_write64(~0ull, lf->rbase + ML_LF_ERR_INT_ENA_W1C);
	dev_irq_unregister(handle, ml_err_irq, lf, vec);
}

int
ml_register_irqs(struct roc_ml_lf *lf)
{
	int rc;

	if (lf->msixoff == MSIX_VECTOR_INVALID) {
		plt_err("Invalid MLALF MSIX vector offset vector: 0x%x", lf->msixoff);
		return -1;
	}

	/* Register lf err interrupt */
	rc = ml_register_err_irq(lf);

	return rc;
}

void
ml_unregister_irqs(struct roc_ml_lf *lf)
{
	ml_unregister_err_irq(lf);
}
