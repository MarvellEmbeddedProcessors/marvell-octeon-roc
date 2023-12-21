/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 * Copyright(C) 2023 Marvell.
 */

#ifndef __OCT_UTIL_H__
#define __OCT_UTIL_H__

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PLT_USE_PMCCNTR
#define PLT_USE_PMCCNTR 0
#endif

extern __attribute__((const)) int __plt_log2_NaN(void);

#define PLT_LOG2_CONST(n)                                                                          \
	((n) < 1	     ? __plt_log2_NaN() :                                                  \
	 (n) & (BIT_ULL(63)) ? 63 :                                                                \
	 (n) & (BIT_ULL(62)) ? 62 :                                                                \
	 (n) & (BIT_ULL(61)) ? 61 :                                                                \
	 (n) & (BIT_ULL(60)) ? 60 :                                                                \
	 (n) & (BIT_ULL(59)) ? 59 :                                                                \
	 (n) & (BIT_ULL(58)) ? 58 :                                                                \
	 (n) & (BIT_ULL(57)) ? 57 :                                                                \
	 (n) & (BIT_ULL(56)) ? 56 :                                                                \
	 (n) & (BIT_ULL(55)) ? 55 :                                                                \
	 (n) & (BIT_ULL(54)) ? 54 :                                                                \
	 (n) & (BIT_ULL(53)) ? 53 :                                                                \
	 (n) & (BIT_ULL(52)) ? 52 :                                                                \
	 (n) & (BIT_ULL(51)) ? 51 :                                                                \
	 (n) & (BIT_ULL(50)) ? 50 :                                                                \
	 (n) & (BIT_ULL(49)) ? 49 :                                                                \
	 (n) & (BIT_ULL(48)) ? 48 :                                                                \
	 (n) & (BIT_ULL(47)) ? 47 :                                                                \
	 (n) & (BIT_ULL(46)) ? 46 :                                                                \
	 (n) & (BIT_ULL(45)) ? 45 :                                                                \
	 (n) & (BIT_ULL(44)) ? 44 :                                                                \
	 (n) & (BIT_ULL(43)) ? 43 :                                                                \
	 (n) & (BIT_ULL(42)) ? 42 :                                                                \
	 (n) & (BIT_ULL(41)) ? 41 :                                                                \
	 (n) & (BIT_ULL(40)) ? 40 :                                                                \
	 (n) & (BIT_ULL(39)) ? 39 :                                                                \
	 (n) & (BIT_ULL(38)) ? 38 :                                                                \
	 (n) & (BIT_ULL(37)) ? 37 :                                                                \
	 (n) & (BIT_ULL(36)) ? 36 :                                                                \
	 (n) & (BIT_ULL(35)) ? 35 :                                                                \
	 (n) & (BIT_ULL(34)) ? 34 :                                                                \
	 (n) & (BIT_ULL(33)) ? 33 :                                                                \
	 (n) & (BIT_ULL(32)) ? 32 :                                                                \
	 (n) & (BIT_ULL(31)) ? 31 :                                                                \
	 (n) & (BIT_ULL(30)) ? 30 :                                                                \
	 (n) & (BIT_ULL(29)) ? 29 :                                                                \
	 (n) & (BIT_ULL(28)) ? 28 :                                                                \
	 (n) & (BIT_ULL(27)) ? 27 :                                                                \
	 (n) & (BIT_ULL(26)) ? 26 :                                                                \
	 (n) & (BIT_ULL(25)) ? 25 :                                                                \
	 (n) & (BIT_ULL(24)) ? 24 :                                                                \
	 (n) & (BIT_ULL(23)) ? 23 :                                                                \
	 (n) & (BIT_ULL(22)) ? 22 :                                                                \
	 (n) & (BIT_ULL(21)) ? 21 :                                                                \
	 (n) & (BIT_ULL(20)) ? 20 :                                                                \
	 (n) & (BIT_ULL(19)) ? 19 :                                                                \
	 (n) & (BIT_ULL(18)) ? 18 :                                                                \
	 (n) & (BIT_ULL(17)) ? 17 :                                                                \
	 (n) & (BIT_ULL(16)) ? 16 :                                                                \
	 (n) & (BIT_ULL(15)) ? 15 :                                                                \
	 (n) & (BIT_ULL(14)) ? 14 :                                                                \
	 (n) & (BIT_ULL(13)) ? 13 :                                                                \
	 (n) & (BIT_ULL(12)) ? 12 :                                                                \
	 (n) & (BIT_ULL(11)) ? 11 :                                                                \
	 (n) & (BIT_ULL(10)) ? 10 :                                                                \
	 (n) & (BIT_ULL(9))  ? 9 :                                                                 \
	 (n) & (BIT_ULL(8))  ? 8 :                                                                 \
	 (n) & (BIT_ULL(7))  ? 7 :                                                                 \
	 (n) & (BIT_ULL(6))  ? 6 :                                                                 \
	 (n) & (BIT_ULL(5))  ? 5 :                                                                 \
	 (n) & (BIT_ULL(4))  ? 4 :                                                                 \
	 (n) & (BIT_ULL(3))  ? 3 :                                                                 \
	 (n) & (BIT_ULL(2))  ? 2 :                                                                 \
	 (n) & (BIT_ULL(1))  ? 1 :                                                                 \
	 (n) & (BIT_ULL(0))  ? 0 :                                                                 \
				     __plt_log2_NaN())

#define PLT_CACHE_LINE_SIZE	 128
#define PLT_CACHE_LINE_SIZE_LOG2 PLT_LOG2_CONST(128)
/** Cache line mask. */
#define PLT_CACHE_LINE_MASK (PLT_CACHE_LINE_SIZE - 1)

/* Function attribute mcros */
#ifndef HOT
#define HOT __attribute__((__hot__))
#endif
#ifndef __plt_always_inline
#define __plt_always_inline inline __attribute__((__always_inline__))
#endif
#ifndef __plt_noinline
#define __plt_noinline __attribute__((noinline))
#endif
#ifndef __plt_packed
#define __plt_packed __attribute__((__packed__))
#endif
#ifndef __plt_aligned
#define __plt_aligned(x) __attribute__((__aligned__(x)))
#endif
#ifndef __plt_cache_aligned
#define __plt_cache_aligned __attribute__((__aligned__(PLT_CACHE_LINE_SIZE)))
#endif

#ifndef __plt_roc_aligned
#define __plt_roc_aligned __attribute__((__aligned__(128)))
#endif

#define typeof __typeof__

#ifndef asm
#define asm __asm__
#endif

/* cpu model type for inline assembly */
#if defined(__ARM_FEATURE_SVE2)
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse+sve2\n"
#elif defined(__ARM_FEATURE_SVE)
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse+sve\n"
#else
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse\n"
#endif

/** C extension macro for environments lacking C11 features. */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#define PLT_STD_C11 __extension__
#else
#define PLT_STD_C11
#endif

#define PLT_MIN(x, y)                                                                              \
	({                                                                                         \
		typeof(x) __x = (x);                                                               \
		typeof(y) __y = (y);                                                               \
		(void)(&__x == &__y);                                                              \
		__x < __y ? __x : __y;                                                             \
	})

#define PLT_MAX(x, y)                                                                              \
	({                                                                                         \
		typeof(x) __x = (x);                                                               \
		typeof(y) __y = (y);                                                               \
		(void)(&__x == &__y);                                                              \
		__x > __y ? __x : __y;                                                             \
	})

#ifndef BIT
#define BIT(_nr) (1UL << (_nr))
#endif

#ifndef BIT_ULL
#define BIT_ULL(_nr) (1ULL << (_nr))
#endif

#define BITMASK(__len, __shift)	    (((1UL << (__len)) - 1) << (__shift))
#ifndef BITMASK_ULL
#define BITMASK_ULL(h, l)                                                     \
  (((~0ULL) - (1ULL << (l)) + 1) &                                            \
   (~0ULL >> ((__SIZEOF_LONG_LONG__ * 8) - 1 - (h))))
#endif

#define sizeof_member(__type, __member) sizeof(((__type *)0)->__member)

#ifndef container_of
#define container_of(__ptr, __type, __member)                                                      \
	({                                                                                         \
		__typeof__(((__type *)0)->__member) *__mptr = (__ptr);                             \
		(__type *)((uintptr_t)__mptr - offsetof(__type, __member));                        \
	})
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define NSEC_PER_SEC		1000000000ULL
#define NSEC2CLK(__ns, __freq)	(((__ns) * (__freq)) / NSEC_PER_SEC)
#define CLK2NSEC(__clk, __freq) (((__clk) * (NSEC_PER_SEC)) / (__freq))

/**
 * Short definition to mark a function parameter unused
 */
#define __plt_unused	  __attribute__((__unused__))
#define PLT_SET_USED(__x) (void)(__x)

/** Divide ceil */
#define PLT_DIV_CEIL(x, y)                                                                         \
	({                                                                                         \
		__typeof(x) __x = x;                                                               \
		__typeof(y) __y = y;                                                               \
		(__x + __y - 1) / __y;                                                             \
	})

/** Align ceil */
#define PLT_ALIGN_CEIL(__x, __align)                                                               \
	((typeof(__x))(__align) * (((__x) + (typeof(__x))(__align) - (1)) / (__align)))

/** Align ceil ptr */
#define PLT_PTR_ALIGN_CEIL(__x, __align)                                                           \
	((typeof(__x))PLT_ALIGN_CEIL((uintptr_t)(__x), (uintptr_t)(__align)))
/** Align floor */
#define PLT_ALIGN_FLOOR(__x, __align) (typeof(__x))((__x) & (~((typeof(__x))((__align) - (1)))))

/** Align floor ptr */
#define PLT_PTR_ALIGN_FLOOR(__x, __align)                                                          \
	((typeof(__x))PLT_ALIGN_FLOOR((uintptr_t)(__x), (uintptr_t)(__align)))

/** Align ceil ptr */
#define PLT_PTR_ALIGN(__ptr, __align) PLT_PTR_ALIGN_CEIL(__ptr, __align)

/** Align ceil */
#define PLT_ALIGN(__val, __align) PLT_ALIGN_CEIL(__val, __align)

/**
 * The resultant value will be of the same type as the first parameter and
 * will be no lower than the first parameter.
 */
#define PLT_ALIGN_MUL_CEIL(v, mul)                                                                 \
	((((v) + (typeof(v))(mul) - (1)) / ((typeof(v))(mul))) * (typeof(v))(mul))

/**
 * The resultant value will be of the same type as the first parameter and will
 * be no higher than the first parameter.
 */
#define PLT_ALIGN_MUL_FLOOR(v, mul) (((v) / ((typeof(v))(mul))) * (typeof(v))(mul))

/**
 * The resultant value might be greater than or less than the first parameter
 * whichever difference is the lowest.
 */
#define PLT_ALIGN_MUL_NEAR(v, mul)                                                                 \
	({                                                                                         \
		typeof(v) _AMN_v = (v);                                                            \
		typeof(mul) _AMN_m = (mul);                                                        \
		typeof(v) _AMN_ceil = PLT_ALIGN_MUL_CEIL(_AMN_v, _AMN_m);                          \
		typeof(v) _AMN_floor = PLT_ALIGN_MUL_FLOOR(_AMN_v, _AMN_m);                        \
		(_AMN_ceil - _AMN_v) > (_AMN_v - _AMN_floor) ? _AMN_floor : _AMN_ceil;             \
	})

/** Add pointer with scalar */
#define PLT_PTR_ADD(__ptr, __x) ((void *)((uintptr_t)(__ptr) + (__x)))

/** Sub pointer with scalar */
#define PLT_PTR_SUB(__ptr, __x) ((void *)((uintptr_t)(__ptr) - (__x)))

/** Difference between two pointers */
#define PLT_PTR_DIFF(__ptr1, __ptr2) ((uintptr_t)(__ptr1) - (uintptr_t)(__ptr2))

/** Cast to pointer */
#define PLT_PTR_CAST(val) (void *)(val)

/** Cast to uint64_t */
#define PLT_U64_CAST(val) (uint64_t)(val)

/** Cast to uint32_t */
#define PLT_U32_CAST(val) (uint32_t)(val)

/** Cast to uint16_t */
#define PLT_U16_CAST(val) (uint16_t)(val)

/** Dimension of an array */
#define PLT_DIM(__a) (sizeof((__a)) / sizeof((__a)[0]))

/** Add pointer with scalar and cast to uint64_t */
#define PLT_PTR_ADD_U64_CAST(__ptr, __x) PLT_U64_CAST(PLT_PTR_ADD(__ptr, __x))

/** Sub pointer with scalar and cast to uint64_t */
#define PLT_PTR_SUB_U64_CAST(__ptr, __x) PLT_U64_CAST(PLT_PTR_SUB(__ptr, __x))

/** Align ceil ptr and get the difference between aligned and initial pointer */
#define PLT_PTR_ALIGN_CEIL_DIFF(__ptr, __x) PLT_PTR_DIFF(PLT_PTR_ALIGN_CEIL(__ptr, __x), __ptr)

/** Take a macro value and get a string version of it */
#define PLT_STR(x) #x

#define PLT_PCI_DEV_NAME_LEN(x) (sizeof(x) + PCI_PRI_STR_SIZE)

#define PLT_CONCAT(pref, suff) pref##suff

#define PLT_PMD_EXPORT_NAME_ARRAY(n, idx) n##idx[]

#define PLT_PMD_EXPORT_NAME(name, idx)                                                             \
	static const char PLT_PMD_EXPORT_NAME_ARRAY(this_pmd_name, idx) __attribute__((used)) =    \
		PLT_STR(name)

#define PLT_PRIORITY_CONFIG 150
#define PLT_PRIORITY_LAST   65535

#define PLT_PRIO(prio) PLT_PRIORITY_##prio

#define PLT_INIT_PRIO(func, prio)                                                                  \
	static void __attribute__((constructor(PLT_PRIO(prio)), used)) func(void)

/*
 * Run constructor function before main() with last priority.
 */
#define PLT_INIT(func) PLT_INIT_PRIO(func, LAST)

#define PLT_FINI_PRIO(func, prio)                                                                  \
	static void __attribute__((destructor(PLT_PRIO(prio)), used)) func(void)

/*
 * Run destructor function after main() with last priority.
 */
#define PLT_FINI(func) PLT_FINI_PRIO(func, LAST)

typedef uint64_t plt_iova_t;

#define PLT_BAD_IOVA ((plt_iova_t)-1)

/* This macro permits both remove and free var within the loop safely. */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                                                 \
	for ((var) = TAILQ_FIRST((head)); (var) && ((tvar) = TAILQ_NEXT((var), field), 1);         \
	     (var) = (tvar))
#endif

#ifndef TAILQ_FOREACH_REVERSE_SAFE
#define TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)                               \
	for ((var) = TAILQ_LAST((head), headname);                                                 \
	     (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1); (var) = (tvar))
#endif

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)                                                  \
	for ((var) = LIST_FIRST((head)); (var) && ((tvar) = LIST_NEXT((var), field), 1);           \
	     (var) = (tvar))
#endif

#define PLT_STATIC_ASSERT(s) _Static_assert(s, #s)

#if (__BYTE_ORDER__)==( __ORDER_LITTLE_ENDIAN__)
/* Byte order */
#define plt_cpu_to_be_16(x) __builtin_bswap16((uint16_t)(x)) 
#define plt_cpu_to_be_32(x) __builtin_bswap32((uint32_t)(x))
#define plt_cpu_to_be_64(x) __builtin_bswap64((uint64_t)(x))
#define plt_be_to_cpu_16(x) __builtin_bswap16((uint16_t)(x))
#define plt_be_to_cpu_32(x) __builtin_bswap32((uint32_t)(x))
#define plt_be_to_cpu_64(x) __builtin_bswap64((uint64_t)(x))
#else
#define plt_cpu_to_be_16(x) ((uint16_t)(x))
#define plt_cpu_to_be_32(x) ((uint32_t)(x))
#define plt_cpu_to_be_64(x) ((uint64_t)(x))
#define plt_be_to_cpu_16(x) ((uint16_t)(x))
#define plt_be_to_cpu_32(x) ((uint32_t)(x))
#define plt_be_to_cpu_64(x) ((uint64_t)(x))

#endif

/* Core Id */
//#define plt_lcore_id() PLT_PER_THREAD(oxk_thread_id)

/* Control thread */
#define plt_is_ctrl_thread() !!(PLT_PER_THREAD(oxk_thread_lmt_id) & BIT(31))

/* Barrier */
#if defined(HAVE_CN10K_A0_WORKAROUNDS)
#define plt_mb() __atomic_thread_fence(__ATOMIC_ACQ_REL)

#define plt_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)

#define plt_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)

#define plt_smp_mb() plt_mb()

#define plt_smp_wmb() plt_wmb()

#define plt_smp_rmb() plt_rmb()

#define plt_io_mb() asm volatile("dmb osh" : : : "memory")

#define plt_io_wmb() asm volatile("dmb oshst" : : : "memory")

#define plt_io_rmb() asm volatile("dmb oshld" : : : "memory")

#define plt_sb() asm volatile("dsb sy" : : : "memory")
#else
#define plt_mb() asm volatile("dmb osh" : : : "memory")

#define plt_wmb() asm volatile("dmb oshst" : : : "memory")

#define plt_rmb() asm volatile("dmb oshld" : : : "memory")

#define plt_smp_mb() asm volatile("dmb ish" : : : "memory")

#define plt_smp_wmb() asm volatile("dmb ishst" : : : "memory")

#define plt_smp_rmb() asm volatile("dmb ishld" : : : "memory")

#define plt_sb() asm volatile("dsb sy" : : : "memory")

#define plt_io_mb() plt_mb()

#define plt_io_wmb() plt_wmb()

#define plt_io_rmb() plt_rmb()
#endif

#define plt_atomic_thread_fence __atomic_thread_fence

#define plt_thread_t pthread_t

/* Struct describing a Universal Unique Identifier */
typedef unsigned char plt_uuid_t[16];

/* Helper for defining UUID values for id tables */
#define PLT_UUID_INIT(a, b, c, d, e)                                                               \
	{                                                                                          \
		((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff,             \
			((b) >> 8) & 0xff, (b) & 0xff, ((c) >> 8) & 0xff, (c) & 0xff,              \
			((d) >> 8) & 0xff, (d) & 0xff, ((e) >> 40) & 0xff, ((e) >> 32) & 0xff,     \
			((e) >> 24) & 0xff, ((e) >> 16) & 0xff, ((e) >> 8) & 0xff, (e) & 0xff      \
	}

/* Max eth port defining max PKTIO.
 * Mainly used by roc_nix_inl for defining max soft expiry
 * rings if used.
 */
#define PLT_MAX_ETHPORTS 32

#define PLT_ETHER_ADDR_LEN 6

/** Externs */

extern uint64_t plt_tsc_clock_freq;

/* Delay in usec */
void plt_delay_us(unsigned int us);

/* Local version of strlcpy() */
size_t plt_strlcpy(char *dst, const char *src, size_t size);

/* Split a string to multiple tokens with a delimiter */
int plt_strsplit(char *string, int stringlen, char **tokens, int maxtokens, char delim);

/* Copy src string into dst.
 *
 * Return negative value and NUL-terminate if dst is too short,
 * Otherwise return number of bytes copied.
 */
static inline ssize_t
plt_strscpy(char *dst, const char *src, size_t dsize)
{
	size_t nleft = dsize;
	size_t res = 0;

	/* Copy as many bytes as will fit. */
	while (nleft != 0) {
		dst[res] = src[res];
		if (src[res] == '\0')
			return (ssize_t)res;
		res++;
		nleft--;
	}

	/* Not enough room in dst, set NUL and return error. */
	if (res != 0)
		dst[res - 1] = '\0';
	return -E2BIG;
}

/* Dump memory in hex format */
void plt_hexdump(FILE *f, const char *title, const void *buf, unsigned int len);

void plt_memdump(FILE *f, const char *title, const void *buf, unsigned int len);

void plt_memfill_pattern(void *mem, const void *pattern, size_t size, size_t pat_sz,
			 size_t max_pat_sz);
int plt_memcmp_pattern(void *mem, const void *pattern, size_t size, size_t pat_sz,
		       size_t max_pat_sz);
int plt_kpu_get_profile_name(char *prfl_name);

int plt_ctrl_thread_create(pthread_t *thread, const char *name, const pthread_attr_t *attr,
			   void *(*start_routine)(void *), void *arg);

/* Parse a sysfs (or other) file containing one integer value. */
//int plt_sysfs_value_parse(const char *filename, unsigned long *val);

/** Inline functions */

/** Copy uuid */
static inline void
plt_uuid_copy(plt_uuid_t dst, const plt_uuid_t src)
{
	memcpy(dst, src, sizeof(plt_uuid_t));
}

/** Test if UUID is all zeros. */
bool plt_uuid_is_null(const plt_uuid_t uu);

/** Convert UUID to string */
#define PLT_UUID_STRLEN (36 + 1)
void plt_uuid_unparse(const plt_uuid_t uu, char *out, size_t len);

/** Extract UUID from string */
int plt_uuid_parse(const char *in, plt_uuid_t uu);

static inline uint64_t
plt_tsc_hz(void)
{
	return plt_tsc_clock_freq;
}

/** Read generic counter frequency */
static __plt_always_inline uint64_t
plt_cntfrq(void)
{
	uint64_t freq;

	asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
	return freq;
}

/** Read generic counter */
static __plt_always_inline uint64_t
plt_cntvct(void)
{
	uint64_t tsc;

	asm volatile("mrs %0, cntvct_el0" : "=r"(tsc));
	return tsc;
}

/** Read PMU cycle counter */
static __plt_always_inline uint64_t
plt_pmccntr(void)
{
	uint64_t tsc;

	asm volatile("mrs %0, pmccntr_el0" : "=r"(tsc));
	return tsc;
}

#define MIDR_PARTNUM_SHIFT     4
#define MIDR_PARTNUM_MASK      (0xfff << MIDR_PARTNUM_SHIFT)
#define MIDR_PARTNUM(midr)     (((midr) & MIDR_PARTNUM_MASK) >> MIDR_PARTNUM_SHIFT)
#define MIDR_IMPLEMENTOR_SHIFT 24
#define MIDR_IMPLEMENTOR_MASK  (0xffU << MIDR_IMPLEMENTOR_SHIFT)
#define MIDR_IMPLEMENTOR(midr) (((midr) & MIDR_IMPLEMENTOR_MASK) >> MIDR_IMPLEMENTOR_SHIFT)

/** Read MIDR implementor */
static __plt_always_inline uint64_t
plt_midr_impl(void)
{
	uint64_t id;

	asm volatile("mrs %0, midr_el1" : "=r"(id));
	return MIDR_IMPLEMENTOR(id);
}

/** Read MIDR partnum */
static __plt_always_inline uint64_t
plt_midr_part(void)
{
	uint64_t id;

	asm volatile("mrs %0, midr_el1" : "=r"(id));
	return MIDR_PARTNUM(id);
}

static inline uint64_t
plt_tsc_cycles(void)
{
	uint64_t tsc;

	if (PLT_USE_PMCCNTR)
		tsc = plt_pmccntr();
	else
		tsc = plt_cntvct();
	return tsc;
}

static inline uint64_t
plt_tsc_cycles_precise(void)
{
	__asm__ volatile("isb" : : : "memory");
	return plt_tsc_cycles();
}

/**
 * Delay in milliseconds.
 */
static inline void
plt_delay_ms(uint32_t ms)
{
	return plt_delay_us(ms * 1000);
}

/**
 * Find the last bit set starting from the least-significant bit
 * in other words, find the most significant set bit
 *
 * @return the index of the most significant set bit
 *
 * Bits are numbered starting at 1 (the least significant bit).
 * A return value of zero from any of these functions means that the
 * argument was zero.
 */
static inline uint32_t
plt_fls_u32(uint32_t word)
{
	if (word == 0)
		return 0;
	return sizeof(uint32_t) * 8 - PLT_U32_CAST(__builtin_clz(word));
}

/**
 * Searches the input parameter for the least significant set bit
 * (starting from zero).
 * If a least significant 1 bit is found, its bit index is returned.
 * If the content of the input parameter is zero, then the content of the return
 * value is undefined.
 * @param v
 *     input parameter, should not be zero.
 * @return
 *     least significant set bit in the input parameter.
 */
static inline uint32_t
plt_bsf64(uint64_t v)
{
	return PLT_U32_CAST(__builtin_ctzll(v));
}

/**
 * Searches the input parameter for the least significant set bit
 * (starting from zero). Safe version (checks for input parameter being zero).
 *
 * @warning ``pos`` must be a valid pointer. It is not checked!
 *
 * @param v
 *     The input parameter.
 * @param pos
 *     If ``v`` was not 0, this value will contain position of least significant
 *     bit within the input parameter.
 * @return
 *     Returns 0 if ``v`` was 0, otherwise returns 1.
 */
static inline int
plt_bsf64_safe(uint64_t v, uint32_t *pos)
{
	if (v == 0)
		return 0;

	*pos = plt_bsf64(v);
	return 1;
}

/**
 * Return the last (most-significant) bit set.
 *
 * @note The last (most significant) bit is at position 64.
 * @note plt_fls_u64(0) = 0, plt_fls_u64(1) = 1,
 *       plt_fls_u64(0x8000000000000000) = 64
 *
 * @param x
 *     The input parameter.
 * @return
 *     The last (most-significant) bit set, or 0 if the input is 0.
 */
static inline int
plt_fls_u64(uint64_t x)
{
	return (x == 0) ? 0 : 64 - __builtin_clzll(x);
}

/**
 * Checks if input parameter is power of 2.
 *
 * @param n
 *   The integer to be checked.
 * @return
 *   1 if power of 2.
 *   0 if otherwise.
 */

static inline int
plt_is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

/**
 * Combines 32b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param x
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
static inline uint32_t
plt_combine32ms1b(uint32_t x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x;
}

/**
 * Combines 64b inputs most significant set bits into the least
 * significant bits to construct a value with the same MSBs as x
 * but all 1's under it.
 *
 * @param v
 *    The integer whose MSBs need to be combined with its LSBs
 * @return
 *    The combined value.
 */
static inline uint64_t
plt_combine64ms1b(uint64_t v)
{
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;

	return v;
}

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 *   The integer value to align
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint32_t
plt_align32pow2(uint32_t x)
{
	x--;
	x = plt_combine32ms1b(x);

	return x + 1;
}

/**
 * Aligns input parameter to the previous power of 2
 *
 * @param x
 *   The integer value to align
 *
 * @return
 *   Input parameter aligned to the previous power of 2
 */
static inline uint32_t
plt_align32prevpow2(uint32_t x)
{
	x = plt_combine32ms1b(x);

	return x - (x >> 1);
}

/**
 * Aligns 64b input parameter to the next power of 2
 *
 * @param v
 *   The 64b value to align
 *
 * @return
 *   Input parameter aligned to the next power of 2
 */
static inline uint64_t
plt_align64pow2(uint64_t v)
{
	v--;
	v = plt_combine64ms1b(v);

	return v + 1;
}

/**
 * Aligns input parameter to the previous power of 2
 *
 * @param x
 *   The integer value to align
 *
 * @return
 *   Input parameter aligned to the previous power of 2
 */
static inline uint64_t
plt_align64prevpow2(uint64_t x)
{
	x = plt_combine64ms1b(x);

	return x - (x >> 1);
}

/**
 * Searches the input parameter for the least significant set bit
 * (starting from zero).
 * If a least significant 1 bit is found, its bit index is returned.
 * If the content of the input parameter is zero, then the content of the return
 * value is undefined.
 * @param v
 *     input parameter, should not be zero.
 * @return
 *     least significant set bit in the input parameter.
 */
static inline uint32_t
plt_bsf32(uint32_t v)
{
	return (uint32_t)__builtin_ctz(v);
}

/**
 * Return the rounded-up log2 of a integer.
 *
 * @note Contrary to the logarithm mathematical operation,
 * rte_log2_u32(0) == 0 and not -inf.
 *
 * @param v
 *     The input parameter.
 * @return
 *     The rounded-up log2 of the input, or 0 if the input is 0.
 */
static inline uint32_t
plt_log2_u32(uint32_t v)
{
	if (v == 0)
		return 0;
	v = plt_align32pow2(v);
	return plt_bsf32(v);
}

/**
 * Return the rounded-down log2 of a integer.
 *
 * @note Contrary to the logarithm mathematical operation,
 * plt_log2_u32_down(0) == 0 and not -inf.
 *
 * @param v
 *     The input parameter.
 * @return
 *     The rounded-down log2 of the input, or 0 if the input is 0.
 */
static inline uint32_t
plt_log2_u32_down(uint32_t v)
{
	if (v == 0)
		return 0;
	v = plt_align32prevpow2(v);

	return plt_bsf32(v);
}

/**
 * Return the rounded-down log2 of a integer.
 *
 * @note Contrary to the logarithm mathematical operation,
 * plt_log2_u64_down(0) == 0 and not -inf.
 *
 * @param v
 *     The input parameter.
 * @return
 *     The rounded-down log2 of the input, or 0 if the input is 0.
 */
static inline uint32_t
plt_log2_u64_down(uint64_t v)
{
	if (v == 0)
		return 0;
	v = plt_align64prevpow2(v);

	return plt_bsf64(v);
}

#define PLT_LOG2(n)                                                                                \
	(__builtin_constant_p(n) ? PLT_LOG2_CONST(n) :                                             \
	 (sizeof(n) <= 4)	 ? plt_log2_u32_down(n) :                                          \
					 plt_log2_u64_down(n))
/**
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
static inline unsigned int
plt_clz32(uint32_t v)
{
	return (unsigned int)__builtin_clz(v);
}

/**
 * Get the count of leading 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of leading zero bits.
 */
static inline unsigned int
plt_clz64(uint64_t v)
{
	return (unsigned int)__builtin_clzll(v);
}

/**
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
static inline unsigned int
plt_ctz32(uint32_t v)
{
	return (unsigned int)__builtin_ctz(v);
}

/**
 * Get the count of trailing 0-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of trailing zero bits.
 */
static inline unsigned int
plt_ctz64(uint64_t v)
{
	return (unsigned int)__builtin_ctzll(v);
}

/**
 * Get the count of 1-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of 1-bits.
 */
static inline unsigned int
plt_popcount32(uint32_t v)
{
	return (unsigned int)__builtin_popcount(v);
}

/**
 * Get the count of 1-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of 1-bits.
 */
static inline unsigned int
plt_popcount64(uint64_t v)
{
	return (unsigned int)__builtin_popcountll(v);
}

static inline void
plt_prefetch0(const volatile void *p)
{
	__asm__ volatile("PRFM PLDL1KEEP, [%0]" : : "r"(p));
}

static inline void
plt_prefetch1(const volatile void *p)
{
	__asm__ volatile("PRFM PLDL2KEEP, [%0]" : : "r"(p));
}

static inline void
plt_prefetch2(const volatile void *p)
{
	__asm__ volatile("PRFM PLDL3KEEP, [%0]" : : "r"(p));
}

static inline void
plt_prefetch_non_temporal(const volatile void *p)
{
	__asm__ volatile("PRFM PLDL1STRM, [%0]" : : "r"(p));
}

/* IO Access */
static __plt_always_inline uint64_t
plt_read64_relaxed(const volatile void *addr)
{
	return *(const volatile uint64_t *)addr;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
static __plt_always_inline void
plt_write64_relaxed(uint64_t value, volatile void *addr)
{
	*(volatile uint64_t *)addr = value;
}

#pragma GCC diagnostic pop

static __plt_always_inline uint64_t
plt_read64_io(const volatile void *addr)
{
	uint64_t val;

	val = plt_read64_relaxed(addr);
	plt_io_rmb();
	return val;
}

static __plt_always_inline void
plt_write64_io(uint64_t value, volatile void *addr)
{
	plt_io_wmb();
	plt_write64_relaxed(value, addr);
}

static __plt_always_inline uint32_t
plt_read32_relaxed(const volatile void *addr)
{
	return *(const volatile uint32_t *)addr;
}

static __plt_always_inline void
plt_write32_relaxed(uint32_t value, volatile void *addr)
{
	*(volatile uint32_t *)addr = value;
}

static inline uint64_t
plt_str_to_size(const char *str)
{
	char *endptr;
	unsigned long long size;

	while (isspace((int)*str))
		str++;
	if (*str == '-')
		return 0;

	errno = 0;
	size = strtoull(str, &endptr, 0);
	if (errno)
		return 0;

	if (*endptr == ' ')
		endptr++; /* allow 1 space gap */

	switch (*endptr) {
	case 'G':
	case 'g':
		size *= 1024; /* fall-through */
	case 'M':
	case 'm':
		size *= 1024; /* fall-through */
	case 'K':
	case 'k':
		size *= 1024; /* fall-through */
	default:
		break;
	}
	return size;
}

#define plt_read64(addr) plt_read64_relaxed((volatile void *)(addr))

#define plt_write64(val, addr) plt_write64_relaxed((val), (volatile void *)(addr))

#define plt_read32(addr) plt_read32_relaxed((volatile void *)(addr))

#define plt_write32(val, addr) plt_write32_relaxed((val), (volatile void *)(addr))

/* append dbdf to name */
#define plt_pci_dev_name(devname, name, dev)                                                       \
	({                                                                                         \
		snprintf((devname), sizeof(devname), "%s" PCI_PRI_FMT, (name), (dev)->addr.domain, \
			 (dev)->addr.bus, (dev)->addr.devid, (dev)->addr.function);                \
		devname;                                                                           \
	})

/**
 * Check format string and its arguments at compile-time.
 */
#if __GNUC__
#define __plt_format_printf(format_index, first_arg)                                               \
	__attribute__((format(gnu_printf, format_index, first_arg)))
#else
#define __plt_format_printf(format_index, first_arg)                                               \
	__attribute__((format(printf, format_index, first_arg)))
#endif

#define PLT_TAILQ_FOREACH_SAFE TAILQ_FOREACH_SAFE

//const void *plt_lmt_region_reserve_aligned(const char *name, size_t len, uint32_t align);

typedef struct {
	uint32_t sn; /**< A sequence number for the protected data. */
} plt_seqcount_t;

static inline void
plt_seqcount_init(plt_seqcount_t *seqcount)
{
	seqcount->sn = 0;
}

static inline uint32_t
plt_seqcount_read_begin(const plt_seqcount_t *seqcount)
{
	/* __ATOMIC_ACQUIRE to prevent loads after (in program order)
	 * from happening before the sn load. Synchronizes-with the
	 * store release in rte_seqcount_write_end().
	 */
	return __atomic_load_n(&seqcount->sn, __ATOMIC_ACQUIRE);
}

static inline bool
plt_seqcount_read_retry(const plt_seqcount_t *seqcount, uint32_t begin_sn)
{
	uint32_t end_sn;

	/* An odd sequence number means the protected data was being
	 * modified already at the point of the plt_seqcount_read_begin()
	 * call.
	 */
	if (unlikely(begin_sn & 1))
		return true;

	/* make sure the data loads happens before the sn load */
	plt_atomic_thread_fence(__ATOMIC_ACQUIRE);

	end_sn = __atomic_load_n(&seqcount->sn, __ATOMIC_RELAXED);

	/* A writer incremented the sequence number during this read
	 * critical section.
	 */
	return begin_sn != end_sn;
}

static inline void
plt_seqcount_write_begin(plt_seqcount_t *seqcount)
{
	uint32_t sn;

	sn = seqcount->sn + 1;

	__atomic_store_n(&seqcount->sn, sn, __ATOMIC_RELAXED);

	/* __ATOMIC_RELEASE to prevent stores after (in program order)
	 * from happening before the sn store.
	 */
	plt_atomic_thread_fence(__ATOMIC_RELEASE);
}

static inline void
plt_seqcount_write_end(plt_seqcount_t *seqcount)
{
	uint32_t sn;

	sn = seqcount->sn + 1;

	/* Synchronizes-with the load acquire in plt_seqcount_read_begin(). */
	__atomic_store_n(&seqcount->sn, sn, __ATOMIC_RELEASE);
}

static __plt_always_inline void
oct_prefetch_non_temporal (const volatile void *p)
{
#if defined(__aarch64__)
  asm volatile("PRFM PLDL1STRM, [%0]" ::"r"(p));
#endif
}

static __plt_always_inline void
oct_mb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb osh" ::: "memory");
#endif
}

static __plt_always_inline void
oct_wmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb oshst" ::: "memory");
#endif
}

static __plt_always_inline void
oct_rmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb oshld" ::: "memory");
#endif
}

static __plt_always_inline void
oct_smp_mb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb ish" ::: "memory");
#endif
}

static __plt_always_inline void
oct_smp_wmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb ishst" ::: "memory");
#endif
}

static __plt_always_inline void
oct_smp_rmb (void)
{
#if defined(__aarch64__)
  asm volatile("dmb ishld" ::: "memory");
#endif
}

#endif /* __PLT_UTIL_H_ */
