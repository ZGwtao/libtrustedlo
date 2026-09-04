/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <libtrustedlo.h>

#define PANCAKE_HEAP_SIZE (10 * 1024)
#define PANCAKE_STACK_SIZE (10 * 1024)

static unsigned char pancake_memory[PANCAKE_HEAP_SIZE + PANCAKE_STACK_SIZE]
    __attribute__((aligned(16)));

extern void *cml_heap;
extern void *cml_stack;
extern void *cml_stackend;
extern void cml_main(void);

static void pancake_init(void)
{
    cml_heap = pancake_memory;
    cml_stack = pancake_memory + PANCAKE_HEAP_SIZE;
    cml_stackend = pancake_memory + sizeof(pancake_memory);
}

void cml_exit(int arg)
{
    (void)arg;
    microkit_dbg_puts("libtrustedlo: unexpected Pancake exit\n");
}

void cml_err(int arg)
{
    (void)arg;
    microkit_dbg_puts("libtrustedlo: Pancake runtime error\n");
}

void cml_clear(void)
{
}

void ffitrustedlo_hello(unsigned char *c, long clen, unsigned char *a, long alen)
{
    (void)c;
    (void)clen;
    (void)a;
    (void)alen;
    microkit_dbg_puts("libtrustedlo: hello from Pancake\n");
}

void loader_entry(void)
{
    pancake_init();
    cml_main();

    /* Trusted loading main function. */
    mktxlo_self_load_entry();
}
