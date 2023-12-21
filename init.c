/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#include <base/roc_api.h>

oct_plt_init_param_t g_param;

oct_log_class_t oct_logtype_base;
oct_log_class_t oct_logtype_cpt;
oct_log_class_t oct_logtype_mbox;
oct_log_class_t oct_logtype_npa;
oct_log_class_t oct_logtype_nix;
oct_log_class_t oct_logtype_sso;
oct_log_class_t oct_logtype_npc;
oct_log_class_t oct_logtype_tm;
oct_log_class_t oct_logtype_tim;
oct_log_class_t oct_logtype_pci;
oct_log_class_t oct_logtype_ep;
oct_log_class_t oct_logtype_bphy;
oct_log_class_t oct_logtype_iomem;
oct_log_class_t oct_logtype_ml;

int
oct_plt_init (const oct_plt_init_param_t *param)
{
  if (!param->log_reg_class || !param->oct_log || !param->oct_plt_free ||
	!param->oct_plt_zmalloc || !param->oct_plt_memzone_free ||
       	!param->oct_plt_memzone_lookup || !param->oct_get_thread_index ||
       	!param->oct_plt_memzone_reserve_aligned || !param->oct_spinlock_init ||
        !param->oct_spinlock_lock || !param->oct_spinlock_unlock ||
        !param->oct_spinlock_trylock || !param->oct_get_thread_index)
	  return -1;

  g_param = *param;

  oct_logtype_base = param->log_reg_class ("oct", "roc");

  oct_logtype_cpt = param->log_reg_class ("oct", "roc_cpt");

  oct_logtype_mbox = param->log_reg_class ("oct", "roc_mbox");

  oct_logtype_npa = param->log_reg_class ("oct", "roc_npa");

  oct_logtype_nix = param->log_reg_class ("oct", "roc_nix");

  oct_logtype_sso = param->log_reg_class ("oct", "roc_sso");

  oct_logtype_npc = param->log_reg_class ("oct", "roc_npc");

  oct_logtype_tm = param->log_reg_class ("oct", "roc_tm");

  oct_logtype_tim = param->log_reg_class ("oct", "roc_tim");

  oct_logtype_pci = param->log_reg_class ("oct", "roc_pci");

  oct_logtype_ep = param->log_reg_class ("oct", "roc_ep");

  oct_logtype_bphy = param->log_reg_class ("oct", "roc_bphy");

  oct_logtype_iomem = param->log_reg_class ("oct", "roc_iomem");

  oct_logtype_ml = param->log_reg_class ("oct", "roc_ml");

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
