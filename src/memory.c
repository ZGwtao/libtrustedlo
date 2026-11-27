/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <memory.h>

/*
 * The loader uses these wrappers in both standalone images and components
 * which embed libtrustedlo.  Their link environment supplies the
 * architecture-specific implementation vendored by libtrustedlo.
 */
extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);
extern void *memset(void *dest, int value, size_t n);

void *tsldr_miscutil_memcpy(void *restrict dest, const void *restrict src, size_t n)
{
    return memcpy(dest, src, n);
}

void *tsldr_miscutil_memset(void *dest, int c, size_t n)
{
    return memset(dest, c, n);
}

void tsldr_miscutil_ensure_i_and_dcache_coherency(void *start, size_t size)
{
#if defined(__aarch64__)
    /*
     * Adapted from the AArch64 implementation of __clear_cache in
     * LLVM compiler-rt/lib/builtins/clear_cache.c.
     *
     * The required cache-maintenance sequence is specified by the Arm
     * Architecture Reference Manual, DDI0487L.a, section B2.7.4.2. The CTR_EL0
     * DminLine and IminLine fields used to determine the cache-line sizes are
     * described in section D24.2.37 of the same manual. You can find the
     * implementation pattern in "Caches and Self-Modifying Code: Implementing
     * __clear_cache":
     * https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/caches-self-modifying-code-implementing-clear-cache
     *
     * ELF loading writes executable instructions through the data side of the
     * memory system. On AArch64, instruction fetch is not necessarily coherent
     * with those writes. Clean each affected data-cache line to the Point of
     * Unification, wait for those cleans to complete, invalidate the corresponding
     * instruction-cache lines, and finally synchronise the instruction stream.
     *
     * This requires seL4's KernelAArch64UserCacheEnable option to permit EL0 access
     * to CTR_EL0, DC CVAU, and IC IVAU.
     */
    uintptr_t ctr;
    uintptr_t begin = (uintptr_t)start;
    uintptr_t end = begin + size;

    if (size == 0) {
        return;
    }

    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));

    /* CTR_EL0 reports cache-line sizes as log2(words). */
    uintptr_t dline_size = (uintptr_t)4 << ((ctr >> 16) & 0xf);
    uintptr_t iline_size = (uintptr_t)4 << (ctr & 0xf);

    /* Clean every affected data-cache line to the Point of Unification. The
     * DSB ensures that all newly written instructions are visible there before
     * any corresponding instruction-cache entries are invalidated. */
    for (uintptr_t addr = begin & ~(dline_size - 1); addr < end; addr += dline_size) {
        __asm__ volatile("dc cvau, %0" : : "r"(addr) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");

    /* Invalidate every affected instruction-cache line to the Point of
     * Unification. The DSB waits for those invalidations to complete before
     * execution may continue. */
    for (uintptr_t addr = begin & ~(iline_size - 1); addr < end; addr += iline_size) {
        __asm__ volatile("ic ivau, %0" : : "r"(addr) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");

    /* Flush the instruction pipeline so subsequent instruction fetches observe
     * the newly installed executable code. */
    __asm__ volatile("isb" ::: "memory");

#elif defined(__x86_64__)
    (void)start;
    (void)size;

    /* x86 keeps its instruction and data caches coherent, so no cache-line
     * invalidation is required. CPUID serialises instruction execution after
     * the stores which installed the new executable segment. */
    unsigned int leaf = 0;
    __asm__ volatile("cpuid" : "+a"(leaf) : : "rbx", "rcx", "rdx", "memory");
#else
#error "Unsupported architecture"
#endif
}

int tsldr_miscutil_memcmp(const unsigned char *s1, const unsigned char *s2, int n)
{
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

int tsldr_miscutil_strcmp(const char *s1, const char *s2)
{
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;

    int i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) {
            return (a[i] - b[i]);
        }
        i++;
    }
    return (a[i] - b[i]);
}

size_t tsldr_miscutil_strlen(const char *s)
{
    size_t len = 0;

    while (s[len] != '\0')
        ++len;

    return len;
}
