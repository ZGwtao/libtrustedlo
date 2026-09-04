/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <libtrustedlo.h>
#include <tsldr_vm_layout.h>

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

void ffimktxlo_self_load_continue(unsigned char *c, long result, unsigned char *a, long alen)
{
    (void)c;
    (void)a;
    (void)alen;

    if (result != seL4_NoError) {
        microkit_dbg_puts("libtrustedlo: Pancake client image integrity check failed\n");
        return;
    }

    microkit_dbg_puts("libtrustedlo: Pancake client image integrity check passed\n");
    mktxlo_self_load_continue();
}

void mktxlo_self_load_entry_pancake(void)
{
    pancake_init();
    ((uintptr_t *)cml_heap)[0] = tsldr_vm_layout.container_image.base;
    ((uintptr_t *)cml_heap)[1] = tsldr_vm_layout.trampoline_image.base;
    cml_main();
}

void loader_entry(void)
{
    mktxlo_self_load_entry_pancake();
}
