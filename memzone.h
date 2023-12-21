/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#ifndef included_oct_roc_memzone_h
#define included_oct_roc_memzone_h

#define PLT_MEMZONE_PHYS_CONTIG 0x00000001
#define PLT_MEMZONE_NAMESIZE	(64)

struct oct_plt_init_param;
extern struct oct_plt_init_param g_param;
typedef struct oct_plt_memzone
{
  uint32_t index;
  union
  {
    void *addr;
    uint64_t addr_64;
    plt_iova_t iova;
  };
} oct_plt_memzone_t;

typedef struct oct_plt_memzone_list
{
  oct_plt_memzone_t *mem_pool;
  uint64_t *memzone_by_name;
} oct_plt_memzone_list_t;

#define plt_memzone	   oct_plt_memzone
#define plt_memzone_free   g_param.oct_plt_memzone_free
#define plt_memzone_lookup g_param.oct_plt_memzone_lookup

#define plt_memzone_reserve_aligned(name, sz, flags, align)                   \
  g_param.oct_plt_memzone_reserve_aligned (name, sz, 0, flags, align)

#define plt_memzone_reserve_cache_align(name, sz)                             \
  g_param.oct_plt_memzone_reserve_aligned (name, sz, 0, 0, 128)

inline void *
oct_plt_realloc (void *addr, uint32_t size, uint32_t align)
{
  assert (0);

  return 0;
}

static inline const void *
plt_lmt_region_reserve_aligned (const char *name, size_t len, uint32_t align)
{
  return plt_memzone_reserve_aligned (name, len, PLT_MEMZONE_PHYS_CONTIG,
				      align);
}

#endif /* included_oct_roc_memzone_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
