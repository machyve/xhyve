#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define UNUSED __attribute__ ((unused))
#define CTASSERT(x) _Static_assert ((x), "CTASSERT")
#define XHYVE_PAGE_SIZE 0x1000
#define XHYVE_PAGE_MASK (XHYVE_PAGE_SIZE - 1)
#define XHYVE_PAGE_SHIFT 12
#define __aligned(x) __attribute__ ((aligned ((x))))
#define __packed __attribute__ ((packed))
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#define powerof2(x)	((((x)-1)&(x))==0)
#define roundup2(x, y) (((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#define min(x, y) (((x) < (y)) ? (x) : (y))

#define xhyve_abort(...) \
	do { \
		fprintf(stderr, __VA_ARGS__); \
		abort(); \
	} while (0)

#define xhyve_warn(...) \
	do { \
		fprintf(stderr, __VA_ARGS__); \
	} while (0)

#ifdef XHYVE_CONFIG_ASSERT
#define KASSERT(exp, msg) if (!(exp)) xhyve_abort msg
#define KWARN(exp, msg) if (!(exp)) xhyve_warn msg
#else
#define KASSERT(exp, msg) if (0) xhyve_abort msg
#define KWARN(exp, msg) if (0) xhyve_warn msg
#endif

#define FALSE 0
#define TRUE 1

#define XHYVE_PROT_READ 1
#define XHYVE_PROT_WRITE 2
#define XHYVE_PROT_EXECUTE 4

#define	VM_SUCCESS 0

/* sys/sys/types.h */
typedef	unsigned char u_char;
typedef	unsigned short u_short;
typedef	unsigned int u_int;
typedef	unsigned long u_long;

static inline void cpuid_count(uint32_t ax, uint32_t cx, uint32_t *p) {
	__asm__ __volatile__ ("cpuid"
		: "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
		:  "0" (ax), "c" (cx));
}

static inline void do_cpuid(unsigned ax, unsigned *p) {
	__asm__ __volatile__ ("cpuid"
		: "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
		:  "0" (ax));
}

/*
 * read_uint16_unaligned, write_uint16_unaligned,
 * read_uint32_unaligned, write_uint32_unaligned
 * read_uint64_unaligned, write_uint64_unaligned
 *
 * Routines to handle unaligned reads/writes - these are nop on AMD64 but routing
 * the reads through these bottlenecks silences the warning and provides a place
 * to put #if code to handle architectures where aligment matters (if it is ever needed).
 */

static inline uint16_t read_uint16_unaligned(void *pointer) {
    uint16_t *castPointer = (uint16_t *)pointer;
    return *castPointer;
}

static inline void write_uint16_unaligned(void *pointer, uint16_t data) {
    uint16_t *castPointer = (uint16_t *)pointer;
    *castPointer = data;
}

static inline uint32_t read_uint32_unaligned(void *pointer) {
    uint32_t *castPointer = (uint32_t *)pointer;
    return *castPointer;
}

static inline void write_uint32_unaligned(void *pointer, uint32_t data) {
    uint32_t *castPointer = (uint32_t *)pointer;
    *castPointer = data;
}

static inline uint64_t read_uint64_unaligned(void *pointer) {
    uint64_t *castPointer = (uint64_t *)pointer;
    return *castPointer;
}

static inline void write_uint64_unaligned(void *pointer, uint64_t data) {
    uint64_t *castPointer = (uint64_t *)pointer;
    *castPointer = data;
}
