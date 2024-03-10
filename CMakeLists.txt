# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.
#

cmake_minimum_required(VERSION 3.16.3)

PROJECT(octeon-roc)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})

SET(CMAKE_C_FLAGS "-fPIC -g -O3 -Wall -Wno-address-of-packed-member -fstack-protector -fno-common ${CMAKE_C_FLAGS}")

set(OCT_ROC_SRCS
  base/roc_ae.c
  base/roc_ae_fpm_tables.c
  base/roc_aes.c
  base/roc_cpt.c
  base/roc_cpt_debug.c
  base/roc_dev.c
  base/roc_hash.c
  base/roc_idev.c
  base/roc_ie_ot.c
  base/roc_irq.c
  base/roc_mbox.c
  base/roc_model.c
  base/roc_nix.c
  base/roc_nix_bpf.c
  base/roc_nix_debug.c
  base/roc_nix_fc.c
  base/roc_nix_inl.c
  base/roc_nix_inl_dev.c
  base/roc_nix_inl_dev_irq.c
  base/roc_nix_irq.c
  base/roc_nix_mac.c
  base/roc_nix_mcast.c
  base/roc_nix_npc.c
  base/roc_nix_ops.c
  base/roc_nix_ptp.c
  base/roc_nix_queue.c
  base/roc_nix_rss.c
  base/roc_nix_stats.c
  base/roc_nix_tm.c
  base/roc_nix_tm_mark.c
  base/roc_nix_tm_ops.c
  base/roc_nix_tm_utils.c
  base/roc_nix_vlan.c
  base/roc_npa.c
  base/roc_npa_debug.c
  base/roc_npa_irq.c
  base/roc_npa_type.c
  base/roc_npc.c
  base/roc_npc_mcam.c
  base/roc_npc_mcam_dump.c
  base/roc_npc_parse.c
  base/roc_npc_utils.c
  base/roc_platform.c
  base/roc_se.c
  base/roc_sso.c
  base/roc_sso_debug.c
  base/roc_sso_irq.c
  base/roc_tim.c
  base/roc_tim_irq.c
  base/roc_utils.c
  init.c
)

set(OCT_ROC_HEADERS
  bitmap.h
  common.h
  memzone.h
  platform.h
  util.h
  base/roc_ae.h
  base/roc_ae_fpm_tables.h
  base/roc_aes.h
  base/roc_api.h
  base/roc_bitfield.h
  base/roc_bits.h
  base/roc_bphy.h
  base/roc_bphy_cgx.h
  base/roc_bphy_cgx_priv.h
  base/roc_bphy_irq.h
  base/roc_constants.h
  base/roc_cpt.h
  base/roc_cpt_priv.h
  base/roc_cpt_sg.h
  base/roc_dev_priv.h
  base/roc_dpi.h
  base/roc_dpi_priv.h
  base/roc_errata.h
  base/roc_eswitch.h
  base/roc_features.h
  base/roc_hash.h
  base/roc_idev.h
  base/roc_idev_priv.h
  base/roc_ie.h
  base/roc_ie_on.h
  base/roc_ie_ot.h
  base/roc_io.h
  base/roc_io_generic.h
  base/roc_mbox.h
  base/roc_mbox_priv.h
  base/roc_mcs.h
  base/roc_mcs_priv.h
  base/roc_ml.h
  base/roc_ml_priv.h
  base/roc_model.h
  base/roc_nix.h
  base/roc_nix_inl.h
  base/roc_nix_inl_dp.h
  base/roc_nix_inl_priv.h
  base/roc_nix_priv.h
  base/roc_nix_xstats.h
  base/roc_npa.h
  base/roc_npa_dp.h
  base/roc_npa_priv.h
  base/roc_npc.h
  base/roc_npc_priv.h
  base/roc_platform.h
  base/roc_priv.h
  base/roc_ree.h
  base/roc_ree_priv.h
  base/roc_se.h
  base/roc_sso.h
  base/roc_sso_dp.h
  base/roc_sso_priv.h
  base/roc_tim.h
  base/roc_tim_priv.h
  base/roc_util_priv.h
  base/roc_utils.h
  base/hw/cpt.h
  base/hw/dpi.h
  base/hw/ml.h
  base/hw/nix.h
  base/hw/npa.h
  base/hw/npc.h
  base/hw/ree.h
  base/hw/rvu.h
  base/hw/sdp.h
  base/hw/sso.h
  base/hw/ssow.h
  base/hw/tim.h
)

ADD_LIBRARY(octeon-roc ${OCT_ROC_SRCS})
install(TARGETS octeon-roc)

foreach(file ${OCT_ROC_HEADERS})
  get_filename_component(dir ${file} DIRECTORY)
  install(FILES ${file} DESTINATION include/octeon-roc/${dir})
endforeach()
