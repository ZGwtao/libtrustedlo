/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <libtrustedlo.h>
#include <tsldr_vm_layout.h>

#include "pancake_args.h"

#define PANCAKE_HEAP_SIZE (10 * 1024)
#define PANCAKE_STACK_SIZE (10 * 1024)

static unsigned char pancake_memory[PANCAKE_HEAP_SIZE + PANCAKE_STACK_SIZE]
    __attribute__((aligned(16)));

static const unsigned char pnk_mktsymb_magic[] = PROTOCON_MKTSYMB_MAGIC;
_Static_assert(sizeof(pnk_mktsymb_magic) - 1 == MKS_MAGIC_SIZE,
               "unexpected mktsymb magic size");

static const unsigned char pnk_elf_magic[] = ELFMAG;
_Static_assert(sizeof(pnk_elf_magic) - 1 == ELF_MAGIC_SIZE,
               "unexpected ELF magic size");

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

void mktxlo_self_load_entry_pancake(void)
{
    pancake_init();
    uintptr_t *args = (uintptr_t *)cml_heap;

    args[PNK_ARG_CLIENT_IMAGE] = tsldr_vm_layout.container_image.base;
    args[PNK_ARG_TRAMPO_IMAGE] = tsldr_vm_layout.trampoline_image.base;
    args[PNK_ARG_MKS_MAGIC] = (uintptr_t)pnk_mktsymb_magic;
    args[PNK_ARG_ELF_MAGIC] = (uintptr_t)pnk_elf_magic;
    args[PNK_ARG_CLIENT_PROG_BASE] = tsldr_vm_layout.container_program.base;
    args[PNK_ARG_CLIENT_PROG_VADDR] = tsldr_vm_layout.container_program.base;
    args[PNK_ARG_CLIENT_PROG_SIZE] = tsldr_vm_layout.container_program.size;
    args[PNK_ARG_TRAMPO_PROG_BASE] = tsldr_vm_layout.trampoline_program.base;
    args[PNK_ARG_TRAMPO_PROG_VADDR] = tsldr_vm_layout.trampoline_program.base;
    args[PNK_ARG_TRAMPO_PROG_SIZE] = tsldr_vm_layout.trampoline_program.size;
    args[PNK_ARG_TRAMPO_IMAGE_SIZE] = tsldr_vm_layout.trampoline_image.size;

    cml_main();
}

void loader_entry(void)
{
    mktxlo_self_load_entry_pancake();
}
