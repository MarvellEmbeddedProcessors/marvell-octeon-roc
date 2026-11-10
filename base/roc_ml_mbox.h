/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ROC_ML_MBOX_H_
#define _ROC_ML_MBOX_H_

#include "roc_api.h"

/* ML mbox PF-VF messages range */
#define ML_MBOX_PFVF_MSG_START	  0xB800
#define ML_MBOX_PFVF_MSG_END	  0xBFFF
#define ML_MBOX_PFVF_MSG_MAX_SIZE 1024
#define ML_MBOX_MAX_MODELS	  128
#define ML_MBOX_NAME_LEN	  64

struct ml_pf_dev_state_rsp {
	struct mbox_msghdr hdr;
	int __io state;
	uint8_t __io capa[128];
	uint8_t __io config[32];
	uint32_t num_partitions;
};

struct ml_model_count_rsp {
	struct mbox_msghdr hdr;
	int __io num_models;
};

struct ml_model_names_req {
	struct mbox_msghdr hdr;
	int __io num_models;
};

struct ml_model_names_rsp {
	struct mbox_msghdr hdr;
	int __io num_models;
	char names[ML_MBOX_MAX_MODELS][ML_MBOX_NAME_LEN];
	uint8_t __io engine_id[ML_MBOX_MAX_MODELS];
};

struct ml_model_handle_req {
	struct mbox_msghdr hdr;
	char name[ML_MBOX_NAME_LEN];
};

struct ml_model_handle_rsp {
	struct mbox_msghdr hdr;
	char __io name[ML_MBOX_NAME_LEN];
	uint64_t __io handle;
};

struct ml_model_index_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
};

struct ml_model_index_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io index;
};

struct ml_model_info_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
};

struct ml_model_info_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	char model_info[128];
};

struct ml_input_info_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io num_inputs;
};

struct ml_input_info_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io num_inputs;
	char input_info[8][512];
};

struct ml_output_info_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io num_outputs;
};

struct ml_output_info_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io num_outputs;
	char output_info[8][512];
};

struct ml_model_extra_info_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
};

struct ml_model_extra_info_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io model_id;
	uint32_t __io partition_id;
	uint32_t __io max_compl_id;
	uint32_t __io batch_size;
	int __io stats_enabled;
};

struct ml_model_sp_sync_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io jcmd_type;
	uint64_t __io user_ptr;
};

struct ml_model_sp_sync_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io jcmd_type;
	uint64_t __io error_code;
	uint64_t __io user_ptr;
};

struct ml_model_sp_start_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io jcmd_type;
	uint32_t __io mode;
	uint32_t __io compl_id;
	uint64_t __io user_ptr;
};

struct ml_model_sp_start_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io jcmd_type;
	uint64_t __io user_ptr;
	uint32_t __io status;
};

struct ml_model_sp_status_req {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io jcmd_type;
	uint32_t __io compl_id;
	uint64_t __io user_ptr;
};

struct ml_model_sp_status_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io handle;
	uint32_t __io jcmd_type;
	uint64_t __io error_code;
	uint64_t __io user_ptr;
	uint32_t __io status;
};

struct ml_vf_dev_init_req {
	struct mbox_msghdr hdr;
	uint16_t __io is_pf;
	uint16_t __io vf_id;
	uint16_t __io acc_lf;
	uint64_t __io lf_map[4];
};

struct ml_vf_dev_init_rsp {
	struct mbox_msghdr hdr;
	uint64_t __io status;
};

/* ML mbox PF-VF Messages (range 0xB800 - 0xBFFF)*/
#define ML_PFVF_MBOX_MESSAGES                                                                      \
	M(ML_PF_DEV_STATE, 0xB801, ml_pf_dev_state, msg_req, ml_pf_dev_state_rsp)                  \
	M(ML_MODEL_COUNT, 0xB802, ml_model_count, msg_req, ml_model_count_rsp)                     \
	M(ML_MODEL_NAMES, 0xB803, ml_model_names, ml_model_names_req, ml_model_names_rsp)          \
	M(ML_MODEL_HANDLE, 0xB804, ml_model_handle, ml_model_handle_req, ml_model_handle_rsp)      \
	M(ML_MODEL_INDEX, 0xB805, ml_model_index, ml_model_index_req, ml_model_index_rsp)          \
	M(ML_MODEL_INFO, 0xB806, ml_model_info, ml_model_info_req, ml_model_info_rsp)              \
	M(ML_INPUT_INFO, 0xB807, ml_input_info, ml_input_info_req, ml_input_info_rsp)              \
	M(ML_OUTPUT_INFO, 0xB808, ml_output_info, ml_output_info_req, ml_output_info_rsp)          \
	M(ML_MODEL_EXTRA_INFO, 0xB809, ml_model_extra_info, ml_model_extra_info_req,               \
	  ml_model_extra_info_rsp)                                                                 \
	M(ML_MODEL_SP_SYNC, 0xB80A, ml_model_sp_sync, ml_model_sp_sync_req, ml_model_sp_sync_rsp)  \
	M(ML_MODEL_SP_START, 0xB80B, ml_model_sp_start, ml_model_sp_start_req,                     \
	  ml_model_sp_start_rsp)                                                                   \
	M(ML_MODEL_SP_STATUS, 0xB80C, ml_model_sp_status, ml_model_sp_status_req,                  \
	  ml_model_sp_status_rsp)                                                                  \
	M(ML_VF_DEV_INIT, 0xB80D, ml_vf_dev_init, ml_vf_dev_init_req, ml_vf_dev_init_rsp)

/* Enum for ML Mbox message IDs */
enum {
#define M(_name, _id, _1, _2, _3) MBOX_ML_MSG_##_name = _id,
	ML_PFVF_MBOX_MESSAGES
#undef M
};

__plt_unused static const char *
ml_pfvf_mbox_msg_id2name(uint16_t id)
{
	switch (id) {
	default:
		return "INVALID ID";
#define M(_name, _id, _1, _2, _3)                                                                  \
	case _id:                                                                                  \
		return #_name;
		ML_PFVF_MBOX_MESSAGES
#undef M
	}
}

__plt_unused static int
ml_pfvf_mbox_req_id2size(uint16_t id)
{
	switch (id) {
	default:
		return 0;
#define M(_1, _id, _2, _req_type, _3)                                                              \
	case _id:                                                                                  \
		return sizeof(struct _req_type);
		ML_PFVF_MBOX_MESSAGES
#undef M
	}
}

__plt_unused static int
ml_pfvf_mbox_rsp_id2size(uint16_t id)
{
	switch (id) {
	default:
		return 0;
#define M(_1, _id, _2, _3, _rsp_type)                                                              \
	case _id:                                                                                  \
		return sizeof(struct _rsp_type);
		ML_PFVF_MBOX_MESSAGES
#undef M
	}
}

/* ML mbox PF-VF messaging */
int __roc_api roc_ml_msg_id_range_set(struct roc_ml *roc_ml, uint16_t start, uint16_t end);
bool __roc_api roc_ml_msg_id_range_check(struct roc_ml *roc_ml, uint16_t msg_id);
int __roc_api roc_ml_msg_handler_register(struct roc_ml *roc_ml, void *cb);
int __roc_api roc_ml_msg_handler_unregister(struct roc_ml *roc_ml);

/* ML mbox PF-VF messaging functions */
#define M(_1, _2, _func, _req_type, _rsp_type)                                                     \
	int __roc_api roc_##_func(struct roc_ml *roc_ml, struct _req_type *req_msg,                \
				  struct _rsp_type *rsp_msg);
ML_PFVF_MBOX_MESSAGES
#undef M

#endif /*_ROC_ML_MBOX_H_*/
