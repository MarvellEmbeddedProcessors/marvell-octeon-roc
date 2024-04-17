/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#include <base/roc_api.h>

oct_plt_init_param_t g_param;

oct_plt_log_class_t oct_plt_logtype_base;
oct_plt_log_class_t oct_plt_logtype_cpt;
oct_plt_log_class_t oct_plt_logtype_mbox;
oct_plt_log_class_t oct_plt_logtype_npa;
oct_plt_log_class_t oct_plt_logtype_nix;
oct_plt_log_class_t oct_plt_logtype_sso;
oct_plt_log_class_t oct_plt_logtype_npc;
oct_plt_log_class_t oct_plt_logtype_tm;
oct_plt_log_class_t oct_plt_logtype_tim;
oct_plt_log_class_t oct_plt_logtype_pci;
oct_plt_log_class_t oct_plt_logtype_ep;
oct_plt_log_class_t oct_plt_logtype_bphy;
oct_plt_log_class_t oct_plt_logtype_iomem;
oct_plt_log_class_t oct_plt_logtype_ml;

uint32_t oct_plt_cache_line_size;

int
oct_plt_init (const oct_plt_init_param_t *param)
{
  if (!param->oct_plt_log_reg_class || !param->oct_plt_log ||
	!param->oct_plt_free || !param->oct_plt_zmalloc ||
       	!param->oct_plt_memzone_free || !param->oct_plt_memzone_lookup ||
       	!param->oct_plt_get_thread_index || !param->oct_plt_spinlock_init ||
       	!param->oct_plt_memzone_reserve_aligned ||
        !param->oct_plt_spinlock_lock || !param->oct_plt_spinlock_unlock ||
        !param->oct_plt_spinlock_trylock)
	  return -1;

  g_param = *param;

  oct_plt_logtype_base = param->oct_plt_log_reg_class ("oct", "roc");

  oct_plt_logtype_cpt = param->oct_plt_log_reg_class ("oct", "roc_cpt");

  oct_plt_logtype_mbox = param->oct_plt_log_reg_class ("oct", "roc_mbox");

  oct_plt_logtype_npa = param->oct_plt_log_reg_class ("oct", "roc_npa");

  oct_plt_logtype_nix = param->oct_plt_log_reg_class ("oct", "roc_nix");

  oct_plt_logtype_sso = param->oct_plt_log_reg_class ("oct", "roc_sso");

  oct_plt_logtype_npc = param->oct_plt_log_reg_class ("oct", "roc_npc");

  oct_plt_logtype_tm = param->oct_plt_log_reg_class ("oct", "roc_tm");

  oct_plt_logtype_tim = param->oct_plt_log_reg_class ("oct", "roc_tim");

  oct_plt_logtype_pci = param->oct_plt_log_reg_class ("oct", "roc_pci");

  oct_plt_logtype_ep = param->oct_plt_log_reg_class ("oct", "roc_ep");

  oct_plt_logtype_bphy = param->oct_plt_log_reg_class ("oct", "roc_bphy");

  oct_plt_logtype_iomem = param->oct_plt_log_reg_class ("oct", "roc_iomem");

  oct_plt_logtype_ml = param->oct_plt_log_reg_class ("oct", "roc_ml");

  if (param->oct_plt_get_cache_line_size)
	  oct_plt_cache_line_size = param->oct_plt_get_cache_line_size();
  else
	  oct_plt_cache_line_size = 64;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
