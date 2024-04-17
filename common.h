/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#ifndef included_oct_roc_common_h
#define included_oct_roc_common_h

typedef uint32_t oct_plt_log_class_t;
typedef uint64_t unaligned_uint64_t __attribute__ ((aligned (1)));
typedef uint32_t unaligned_uint32_t __attribute__ ((aligned (1)));
typedef uint16_t unaligned_uint16_t __attribute__ ((aligned (1)));

#define foreach_log_level	\
  _(EMERG, emerg)		\
  _(ALERT, alert)		\
  _(CRIT, crit)			\
  _(ERR, error)			\
  _(WARNING, warn)		\
  _(NOTICE, notice)		\
  _(INFO, info)			\
  _(DEBUG, debug)		\
  _(DISABLED, disabled)

typedef enum
{
  OCT_PLT_LOG_LEVEL_UNKNOWN = 0,
#define _(uc,lc) OCT_PLT_LOG_LEVEL_##uc,
  foreach_log_level
#undef _
    OCT_PLT_LOG_N_LEVELS,
} oct_plt_log_level_t;

#define __plt_internal
#define __roc_api

struct oct_plt_spinlock_s
{
  uint32_t lock;
};

typedef struct oct_plt_spinlock_s *oct_plt_spinlock_t;

#define PLT_ASSERT	     assert
#define PLT_MEMZONE_NAME     32
#define PLT_MODEL_MZ_NAME    "roc_model_mz"

/* This macro permits both remove and free var within the loop safely. */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                            \
  for ((var) = TAILQ_FIRST ((head));                                          \
       (var) && ((tvar) = TAILQ_NEXT ((var), field), 1); (var) = (tvar))
#endif

#define PLT_TAILQ_FOREACH_SAFE TAILQ_FOREACH_SAFE

#define plt_iova_t	 oct_plt_iova_t

#define plt_mmap       mmap
#define PLT_PROT_READ  PROT_READ
#define PLT_PROT_WRITE PROT_WRITE
#define PLT_MAP_SHARED MAP_SHARED

#define plt_lcore_id()	       g_param.oct_plt_get_thread_index()
#define plt_tsc_hz	       oct_plt_get_tsc_hz
#define plt_tsc_cycles()       oct_cpu_time_now ()
#define plt_delay_ms	       oct_plt_delay_ms
#define plt_delay_us	       oct_plt_delay_us
#define plt_spinlock_t	       oct_plt_spinlock_t
#define plt_spinlock_init      g_param.oct_plt_spinlock_init
#define plt_spinlock_lock      g_param.oct_plt_spinlock_lock
#define plt_spinlock_unlock    g_param.oct_plt_spinlock_unlock
#define plt_spinlock_trylock   g_param.oct_plt_spinlock_trylock

#define MAX_VFIO_PCI_BAR_REGIONS     6 /* GENERIC MAPPABLE BAR REGIONS ONLY */
#define PLT_MAX_RXTX_INTR_VEC_ID     1024
#define PLT_INTR_VEC_RXTX_OFFSET     1
#define plt_pci_device		     oct_pci_device

#define plt_intr_callback_register   oct_plt_intr_callback_register
#define plt_intr_callback_unregister oct_plt_intr_callback_unregister
#define plt_intr_disable	     oct_plt_intr_disable
#define plt_intr_vec_list_index_get  oct_plt_intr_vec_list_index_get
#define plt_intr_vec_list_index_set  oct_plt_intr_vec_list_index_set
#define plt_intr_vec_list_alloc	     oct_plt_intr_vec_list_alloc
#define plt_intr_vec_list_free	     oct_plt_intr_vec_list_free

#define plt_thread_is_intr	     oct_plt_thread_is_intr
#define plt_intr_callback_fn	     oct_plt_pci_intr_callback_fn
#define plt_intr_handle		     oct_pci_intr_handle
#define plt_alarm_set		     oct_pltarm_set
#define plt_alarm_cancel	     oct_pltarm_cancel
#define plt_strlcpy		     oct_plt_strlcpy
#define plt_zmalloc(sz, align)	     g_param.oct_plt_zmalloc (sz, align)
#define plt_free		     g_param.oct_plt_free
#define plt_realloc		     oct_plt_realloc

#define plt_sysfs_value_parse oct_plt_sysfs_value_parse
/* We dont have a fencing func which takes args, use gcc inbuilt */
#define plt_atomic_thread_fence __atomic_thread_fence

#define oct_plt_err(fmt, args...)                                            \
  g_param.oct_plt_log (OCT_PLT_LOG_LEVEL_ERR, oct_plt_logtype_base, "%s():%u " fmt "\n",       \
	    __func__, __LINE__, ##args)

#define oct_plt_info(fmt, args...)                                           \
  g_param.oct_plt_log (OCT_PLT_LOG_LEVEL_INFO, oct_plt_logtype_base, fmt "\n", ##args)

#define oct_plt_warn(fmt, args...)                                           \
  g_param.oct_plt_log (OCT_PLT_LOG_LEVEL_WARNING, oct_plt_logtype_base, fmt "\n", ##args)

#define oct_plt_print(fmt, args...)                                          \
  g_param.oct_plt_log (OCT_PLT_LOG_LEVEL_INFO, oct_plt_logtype_base, fmt "\n", ##args)

#define oct_plt_print_no_nl(fmt, args...)                                    \
  g_param.oct_plt_log (OCT_PLT_LOG_LEVEL_INFO, oct_plt_logtype_base, fmt, ##args)

#define oct_plt_dbg(subsystem, fmt, args...)                                 \
  g_param.oct_plt_log (OCT_PLT_LOG_LEVEL_DEBUG, oct_plt_logtype_##subsystem,                   \
	    "[%s] %s():%u " fmt "\n", #subsystem, __func__, __LINE__, ##args)

#define plt_err(fmt, ...)   oct_plt_err (fmt, ##__VA_ARGS__)
#define plt_info(fmt, ...)  oct_plt_info (fmt, ##__VA_ARGS__)
#define plt_warn(fmt, ...)  oct_plt_warn (fmt, ##__VA_ARGS__)
#define plt_print(fmt, ...) oct_plt_print (fmt, ##__VA_ARGS__)
#define plt_print_no_nl(fmt, ...) oct_plt_print_no_nl (fmt, ##__VA_ARGS__)
#define plt_dump	       plt_print
#define plt_dump_no_nl		  plt_print_no_nl

#define plt_base_dbg(fmt, ...)	oct_plt_dbg (base, fmt, ##__VA_ARGS__)
#define plt_cpt_dbg(fmt, ...)	oct_plt_dbg (cpt, fmt, ##__VA_ARGS__)
#define plt_mbox_dbg(fmt, ...)	oct_plt_dbg (mbox, fmt, ##__VA_ARGS__)
#define plt_npa_dbg(fmt, ...)	oct_plt_dbg (npa, fmt, ##__VA_ARGS__)
#define plt_nix_dbg(fmt, ...)	oct_plt_dbg (nix, fmt, ##__VA_ARGS__)
#define plt_sso_dbg(fmt, ...)	oct_plt_dbg (sso, fmt, ##__VA_ARGS__)
#define plt_npc_dbg(fmt, ...)	oct_plt_dbg (npc, fmt, ##__VA_ARGS__)
#define plt_tm_dbg(fmt, ...)	oct_plt_dbg (tm, fmt, ##__VA_ARGS__)
#define plt_tim_dbg(fmt, ...)	oct_plt_dbg (tim, fmt, ##__VA_ARGS__)
#define plt_pci_dbg(fmt, ...)	oct_plt_dbg (pci, fmt, ##__VA_ARGS__)
#define plt_sdp_dbg(fmt, ...)	oct_plt_dbg (ep, fmt, ##__VA_ARGS__)
#define plt_bphy_dbg(fmt, ...)	oct_plt_dbg (bphy, fmt, ##__VA_ARGS__)
#define plt_iomem_dbg(fmt, ...) oct_plt_dbg (iomem, fmt, ##__VA_ARGS__)
#define plt_ml_dbg(fmt, ...)	oct_plt_dbg (ml, fmt, ##__VA_ARGS__)

#define ISB() __asm__ volatile("isb" : : : "memory")

#define MRS_WITH_MEM_BARRIER(reg)                                                   \
	({                                                                     \
		uint64_t val;                                                  \
		__asm__ volatile("mrs %0, " #reg : "=r"(val) :: "memory");     \
		val;                                                           \
	})

#define MRS(reg)                                                               \
	({                                                                     \
		uint64_t val;                                                  \
		__asm__ volatile("mrs %0, " #reg : "=r"(val));		       \
		val;                                                           \
	})

typedef struct
{
  uint32_t seq_num;
} oct_seqcount_t;

#define plt_seqcount_t	  oct_seqcount_t
#define plt_seqcount_init oct_seqcount_init
static inline __attribute__((__always_inline__))void
oct_seqcount_init (plt_seqcount_t *seqcount)
{
  seqcount->seq_num = 0;
}

/* Init callbacks */
typedef int (*roc_plt_init_cb_t) (void);
int __roc_api roc_plt_init_cb_register (roc_plt_init_cb_t cb);

typedef void (*oct_plt_pci_intr_callback_fn) (void *cb_arg);
typedef void (*oct_plt_pci_alarm_callback) (void *arg);
typedef uint64_t oct_plt_iova_t;

extern oct_plt_log_class_t oct_plt_logtype_base;
extern oct_plt_log_class_t oct_plt_logtype_cpt;
extern oct_plt_log_class_t oct_plt_logtype_mbox;
extern oct_plt_log_class_t oct_plt_logtype_npa;
extern oct_plt_log_class_t oct_plt_logtype_nix;
extern oct_plt_log_class_t oct_plt_logtype_sso;
extern oct_plt_log_class_t oct_plt_logtype_npc;
extern oct_plt_log_class_t oct_plt_logtype_tm;
extern oct_plt_log_class_t oct_plt_logtype_tim;
extern oct_plt_log_class_t oct_plt_logtype_pci;
extern oct_plt_log_class_t oct_plt_logtype_ep;
extern oct_plt_log_class_t oct_plt_logtype_bphy;
extern oct_plt_log_class_t oct_plt_logtype_iomem;
extern oct_plt_log_class_t oct_plt_logtype_ml;

extern uint32_t oct_plt_cache_line_size;

enum oct_pci_intr_handle_type
{
  PLT_INTR_HANDLE_UNKNOWN = 0,
  PLT_INTR_HANDLE_VFIO_MSIX,
  PLT_INTR_HANDLE_MAX
};

struct oct_pci_intr_handle
{
  int vfio_dev_fd;
  int fd;
  enum oct_pci_intr_handle_type type;
  uint32_t max_intr;
  uint32_t nb_intr;
  uint32_t nb_efd;
  uint8_t efd_counter_size;
  int efds[1024];
  int *intr_vec;
};

struct oct_pci_id
{
  uint32_t class_id;
  uint16_t vendor_id;
  uint16_t device_id;
  uint16_t subsystem_vendor_id;
  uint16_t subsystem_device_id;
};

/**
 * A structure describing the location of a PCI device.
 */
typedef struct oct_pci_addr {
    uint32_t domain;  /**< Device domain */
    uint8_t bus;      /**< Device bus */
    uint8_t devid;    /**< Device ID */
    uint8_t function; /**< Device function. */
} oct_pci_addr_t;

typedef struct pci_mem_rsrc
{
  uint64_t phys_addr;
  uint64_t len;
  void *addr;
} oct_pci_mem_rsrc_t;

typedef uint32_t oct_pci_dev_handle_t;

typedef struct oct_pci_device
{
  oct_pci_mem_rsrc_t mem_resource[MAX_VFIO_PCI_BAR_REGIONS];
  struct oct_pci_id id;
  struct oct_pci_intr_handle *intr_handle;
  uint16_t max_vfs;
  uint16_t index;
  uint8_t name[32];
  oct_pci_addr_t addr;
  oct_pci_dev_handle_t pci_handle;
} oct_pci_device_t;

struct oct_plt_memzone;
typedef oct_plt_log_class_t (*oct_plt_log_reg_class_fn_t) (char *class, char *subclass);
typedef void (*oct_plt_log_fn_t) (oct_plt_log_level_t level, oct_plt_log_class_t class, char *fmt, ...);
typedef void (*oct_plt_free_fn_t) (void *add);
typedef void * (*oct_plt_zmalloc_fn_t) (uint32_t size, uint32_t align);
typedef int (*oct_plt_memzone_free_fn_t) (const struct oct_plt_memzone *name);
typedef struct oct_plt_memzone * (*oct_plt_memzone_lookup_fn_t) (const char *name);
typedef struct oct_plt_memzone * (*oct_plt_memzone_reserve_aligned_fn_t) (const char *name, uint64_t len, uint8_t socket,
                                  uint32_t flags, uint32_t align);
typedef void (*oct_plt_spinlock_init_fn_t) (oct_plt_spinlock_t * p);
typedef void (*oct_plt_spinlock_lock_fn_t) (oct_plt_spinlock_t * p);
typedef void (*oct_plt_spinlock_unlock_fn_t) (oct_plt_spinlock_t * p);
typedef int (*oct_plt_spinlock_trylock_fn_t) (oct_plt_spinlock_t * p);
typedef uint64_t (*oct_plt_get_thread_index_fn_t)(void);
typedef uint64_t (*oct_plt_get_cache_line_size_fn_t)(void);

typedef struct oct_plt_init_param 
{
  oct_plt_log_reg_class_fn_t oct_plt_log_reg_class;
  oct_plt_log_fn_t oct_plt_log;
  oct_plt_free_fn_t oct_plt_free; 
  oct_plt_zmalloc_fn_t oct_plt_zmalloc; 
  oct_plt_memzone_free_fn_t oct_plt_memzone_free; 
  oct_plt_memzone_lookup_fn_t oct_plt_memzone_lookup; 
  oct_plt_memzone_reserve_aligned_fn_t oct_plt_memzone_reserve_aligned;
  oct_plt_spinlock_init_fn_t oct_plt_spinlock_init;
  oct_plt_spinlock_lock_fn_t oct_plt_spinlock_lock;
  oct_plt_spinlock_unlock_fn_t oct_plt_spinlock_unlock;
  oct_plt_spinlock_trylock_fn_t oct_plt_spinlock_trylock;
  oct_plt_get_thread_index_fn_t oct_plt_get_thread_index;
  oct_plt_get_cache_line_size_fn_t oct_plt_get_cache_line_size;
} oct_plt_init_param_t;
__plt_internal int oct_plt_init (const oct_plt_init_param_t *);


extern oct_plt_init_param_t g_param;

static inline __attribute__((__always_inline__))uint64_t
oct_plt_get_tsc_hz ()
{
  uint64_t hz;
  asm volatile ("mrs %0, cntfrq_el0":"=r" (hz));
  return hz;
}

static inline __attribute__((__always_inline__))uint64_t
oct_cpu_time_now()
{
 uint64_t vct;
  /* User access to cntvct_el0 is enabled in Linux kernel since 3.12. */
  asm volatile ("mrs %0, cntvct_el0":"=r" (vct));
  return vct;
  }
static inline __attribute__((__always_inline__))int
oct_plt_intr_vec_list_alloc (struct oct_pci_intr_handle *intr_handle,
			      const char *name, int size)
{
  return 0;
}

static inline __attribute__((__always_inline__))int
oct_plt_intr_vec_list_index_set (struct oct_pci_intr_handle *intr_handle,
				  int index, int vec)
{
  return 0;
}

static inline __attribute__((__always_inline__))void
oct_plt_intr_vec_list_free (struct oct_pci_intr_handle *intr_handle)
{
  return;
}

static inline __attribute__((__always_inline__))int
oct_plt_intr_disable (const struct oct_pci_intr_handle *intr_handle)
{
  OCT_UNIMPLEMENTED ();
  return 0;
}

static inline __attribute__((__always_inline__))int
oct_plt_intr_callback_register (
  const struct oct_pci_intr_handle *intr_handle,
  oct_plt_pci_intr_callback_fn cb, void *cb_arg)
{
  OCT_UNIMPLEMENTED ();
  return 0;
}

static inline __attribute__((__always_inline__))int
oct_plt_intr_callback_unregister (
  const struct oct_pci_intr_handle *intr_handle,
  oct_plt_pci_intr_callback_fn cb_fn, void *cb_arg)
{
  OCT_UNIMPLEMENTED ();
  return 0;
}

static inline __attribute__((__always_inline__))int
oct_plt_thread_is_intr (void)
{
  return 1;
}

static inline __attribute__((__always_inline__))int
oct_pltarm_set (uint64_t us, oct_plt_pci_alarm_callback cb_fn, void *cb_arg)
{
  OCT_UNIMPLEMENTED ();
  return 0;
}

static inline __attribute__((__always_inline__))int
oct_pltarm_cancel (oct_plt_pci_alarm_callback cb_fn, void *cb_arg)
{
  OCT_UNIMPLEMENTED ();
  return 0;
}

static inline __attribute__((__always_inline__))size_t
oct_plt_strlcpy (char *dst, const char *src, size_t size)
{
  /* strlcpy needs bsd-dev package */
  return snprintf (dst, size, "%s", src);
}

static inline __attribute__((__always_inline__))uint32_t
oct_plt_read32_relaxed (const volatile void *addr)
{
  return *(const volatile uint32_t *) addr;
}

static inline __attribute__((__always_inline__))void
oct_plt_write32_relaxed (uint32_t value, volatile void *addr)
{
  *(volatile uint32_t *) addr = value;
}

static inline __attribute__((__always_inline__))uint64_t
oct_plt_read64_relaxed (const volatile void *addr)
{
  return *(const volatile uint64_t *) addr;
}

static inline __attribute__((__always_inline__))void
oct_plt_write64_relaxed (uint64_t value, volatile void *addr)
{
  *(volatile uint64_t *) addr = value;
}

static inline __attribute__((__always_inline__))void
oct_plt_delay_ms (unsigned msec)
{
  usleep (msec * 1e3);
}

static inline __attribute__((__always_inline__))void
oct_plt_delay_us (unsigned usec)
{
  usleep (usec);
}

static inline __attribute__((__always_inline__))int
oct_plt_sysfs_value_parse (const char *filename, unsigned long *val)
{
  char buf[BUFSIZ];
  char *end = NULL;
  FILE *f;
  int ret = 0;

  f = fopen (filename, "r");
  if (f == NULL)
    {
      plt_err ("Cannot open sysfs entry %s", filename);
      return -1;
    }

  if (fgets (buf, sizeof (buf), f) == NULL)
    {
      plt_err ("Cannot read sysfs entry %s", filename);
      ret = -1;
      goto close_file;
    }
  *val = strtoul (buf, &end, 0);
  if ((buf[0] == '\0') || (end == NULL) || (*end != '\n'))
    {
      plt_err ("Cannot parse sysfs entry %s", filename);
      ret = -1;
      goto close_file;
    }
close_file:
  fclose (f);
  return ret;
}

#endif /* included_oct_roc_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
