/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <txloxrt.h>
#include <txlocap.h>
#include <txlodlg.h>
#include <libtrustedlo.h>
#include <tsldr_vm_layout.h>
#include <memory.h>

static inline Elf64_Ehdr *mktxlo_client_image_elf(uintptr_t image)
{
    protocon_image_header_t *header = (protocon_image_header_t *)image;
    return (Elf64_Ehdr *)(image + header->elf_offset);
}

static inline void *mktxlo_client_image_mktsymb(uintptr_t image)
{
    protocon_image_header_t *header = (protocon_image_header_t *)image;
    return (void *)(image + header->mktsymb_offset);
}

static inline seL4_Error mktxlo_parse_requst(void *xrt_req_header)
{
    if (!xrt_req_header) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO);
        TSLDR_DBG_PRINT(__func__);
        TSLDR_DBG_PRINT(": invalid xrt_req_header given\n");
        return -1;
    }

    TRY_OR_RETURN_ERROR(trustedlo_xrt_util_parse_xrt_header(xrt_req_header));

    TSLDR_DBG_PRINT(LIB_NAME_MACRO);
    TSLDR_DBG_PRINT(__func__);
    TSLDR_DBG_PRINT(": finished up access rights integrity checking\n");
    return seL4_NoError;
}

static inline seL4_Error
mktxlo_populate_req2ctxt(trustedlo_ctxt_t *context, void *txlo_info, void *xrt_req_header)
{
    TRY_OR_RETURN_ERROR(trustedlo_xrt_util_populate_xrts(context, txlo_info, xrt_req_header));
    return seL4_NoError;
}

static inline void mktxlo_revoke_caps(trustedlo_ctxt_t *context, void *txlo_info)
{
    if (context->txlo_monitor_init_field.switch_count == 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO);
        TSLDR_DBG_PRINT(__func__);
        TSLDR_DBG_PRINT(": no need to restore anything at the first-time execution\n");
        context->txlo_monitor_init_field.switch_count++;
        return;
    }
    /* clean up all XRT_STATE_USED caps */
    trustedlo_xrt_util_revoke_notifications(context, txlo_info);
    trustedlo_xrt_util_revoke_ppcs(context, txlo_info);
    trustedlo_xrt_util_revoke_irqs(context, txlo_info);
    trustedlo_xrt_util_revoke_mappings(context);
    /* once finished, all USED are UNSET */
}

static inline void mktxlo_restore_caps(trustedlo_ctxt_t *context, void *txlo_info)
{
    /* for XRT_STATE_KEEP, keep them as USED */
    /* for XRT_STATE_ALLOWED, create them from backup CNode */
    /* for XRT_STATE_UNSET, do nothing */
    /* and there should not be any other states (all USED are UNSET from remove_caps) */
    trustedlo_xrt_util_restore_notifications(context, txlo_info);
    trustedlo_xrt_util_restore_ppcs(context, txlo_info);
    trustedlo_xrt_util_restore_irqs(context, txlo_info);
    trustedlo_xrt_util_restore_mappings(context);
}

static inline seL4_Error mktxlo_context_activate(trustedlo_ctxt_t *context)
{
    /* do some id activation here before actually parsing access rights... */
    if (context == NULL) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO);
        TSLDR_DBG_PRINT(__func__);
        TSLDR_DBG_PRINT(": try to dereference null context pointer\n");
        return -1;
    }

    /* the only thing that needs to be renew for now. */
    context->allowed_mappings.mapping_count = 0;
    return seL4_NoError;
}

#if defined(CONFIG_ARCH_X86_64)
__attribute__((naked, noreturn)) /* don't let your compiler fuck around with the args */
void mktxlo_jumpto(void *new_stack, entry_fn_t entry, const trampoline_args_t *args)
{
    __asm__ volatile("mov %rdi, %rsp\n\t"
                     "mov %rdx, %rdi\n\t"
                     "jmp *%rsi\n\t");
}
#elif defined(CONFIG_ARCH_AARCH64)
__attribute__((naked, noreturn)) void
mktxlo_jumpto(void *new_stack, entry_fn_t entry, const trampoline_args_t *args)
{
    __asm__ volatile("mov sp, x0\n\t"
                     "mov x0, x2\n\t"
                     "br x1\n\t");
}
#else
#error "Unsupported architecture for 'mktxlo_jumpto'"
#endif

static inline seL4_Error mktxlo_payload_check_integrity(uintptr_t elf)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;

    /* check elf magic number */
    if (tsldr_miscutil_memcmp(ehdr->e_ident, (const unsigned char *)ELFMAG, SELFMAG) != 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO);
        TSLDR_DBG_PRINT(__func__);
        TSLDR_DBG_PRINT(": ELF magic number mismatch\n");
        return -1;
    }
    return seL4_NoError;
}

static inline seL4_Error mktxlo_client_image_check_integrity(uintptr_t image)
{
    protocon_image_header_t *header = (protocon_image_header_t *)image;

    if (header->magic != PROTOCON_IMAGE_MAGIC) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO);
        TSLDR_DBG_PRINT(__func__);
        TSLDR_DBG_PRINT(": client image magic mismatch\n");
        return -1;
    }

    const uint8_t *mktsymb = (const uint8_t *)mktxlo_client_image_mktsymb(image);
    if (tsldr_miscutil_memcmp(mktsymb, (const unsigned char *)PROTOCON_MKTSYMB_MAGIC, 8) != 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO);
        TSLDR_DBG_PRINT(__func__);
        TSLDR_DBG_PRINT(": mktsymb magic mismatch\n");
        return -1;
    }

    return mktxlo_payload_check_integrity((uintptr_t)mktxlo_client_image_elf(image));
}

static inline seL4_Error mktxlo_payload_load(void *base)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    tsldr_miscutil_load_elf((void *)(ehdr->e_entry), ehdr);
    return seL4_NoError;
}

static inline Elf64_Sym *
mktxlo_elf_find_symbol(Elf64_Ehdr *ehdr, const char *name, uint16_t name_len)
{
    Elf64_Shdr *shdr = (Elf64_Shdr *)((uintptr_t)ehdr + ehdr->e_shoff);

    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_type != SHT_SYMTAB) {
            continue;
        }

        Elf64_Sym *symtab = (Elf64_Sym *)((uintptr_t)ehdr + shdr[i].sh_offset);
        Elf64_Shdr *strtab_hdr = &shdr[shdr[i].sh_link];
        const char *strtab = (const char *)((uintptr_t)ehdr + strtab_hdr->sh_offset);
        uint64_t count = shdr[i].sh_size / sizeof(Elf64_Sym);

        for (uint64_t j = 0; j < count; ++j) {
            const char *sym_name = strtab + symtab[j].st_name;

            if (tsldr_miscutil_strlen(sym_name) == name_len &&
                tsldr_miscutil_memcmp((const unsigned char *)sym_name,
                                      (const unsigned char *)name,
                                      name_len) == 0) {
                return &symtab[j];
            }
        }
    }

    return NULL;
}

static inline seL4_Error mktxlo_client_patch_symbols(uintptr_t image)
{
    Elf64_Ehdr *ehdr = mktxlo_client_image_elf(image);
    mktsymb_header_t mktsymb;

    mktsymb_read(&mktsymb, mktxlo_client_image_mktsymb(image));

    const uint8_t *p = mktsymb.symbols;

    for (uint32_t i = 0; i < mktsymb.symbol_cnt; ++i) {
        mktsymb_symbol_t symbol;
        p = mktsymb_read_symbol(p, &symbol);

        Elf64_Sym *elf_symbol = mktxlo_elf_find_symbol(ehdr, symbol.name, symbol.name_len);

        if (elf_symbol == NULL) {
            TSLDR_DBG_PRINT(LIB_NAME_MACRO);
            TSLDR_DBG_PRINT(__func__);
            TSLDR_DBG_PRINT(": failed to find symbol %.*s\n", (int)symbol.name_len, symbol.name);
            return -1;
        }

        tsldr_miscutil_memcpy((void *)(uintptr_t)elf_symbol->st_value,
                              symbol.data,
                              symbol.data_len);

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "patched %.*s at %x size=%d\n",
                        (int)symbol.name_len,
                        symbol.name,
                        (uintptr_t)elf_symbol->st_value,
                        symbol.data_len);
    }

    return seL4_NoError;
}

static inline seL4_Error mktxlo_client_image_load(uintptr_t image)
{
    Elf64_Ehdr *ehdr = mktxlo_client_image_elf(image);

    TRY_OR_RETURN_ERROR(mktxlo_payload_load(ehdr));
    TRY_OR_RETURN_ERROR(mktxlo_client_patch_symbols(image));

    return seL4_NoError;
}

static inline seL4_Error mktxlo_enforce_pola(trustedlo_ctxt_t *context, void *txlo_info)
{
    mktxlo_revoke_caps(context, txlo_info);

    /* if this is not a first-time execution, restore the access rights distribution to the default
     * state */
    /* once the PD is restored to a default state, we can populate the rights with the information
     * provided above */
    mktxlo_restore_caps(context, txlo_info);

    return seL4_NoError;
}

static inline seL4_Error
mktxlo_context_refresh(void *txlo_info, trustedlo_ctxt_t *context, void *xrt_req_header)
{
    TRY_OR_RETURN_ERROR(mktxlo_parse_requst(xrt_req_header));

    /* (really) populate allowed access rights */
    // we use this function to:
    //  initialise the allowed lists for different resources for this execution round
    //  so we need the information of allowed resources that are recorded in "access_rights"
    //  and update the whitelist for resources to keep for this round
    //  we then will remove the unnecessary resources based on the whitelist to filter resources
    TRY_OR_RETURN_ERROR(mktxlo_populate_req2ctxt(context, txlo_info, xrt_req_header));

    TRY_OR_RETURN_ERROR(mktxlo_enforce_pola(context, txlo_info));

    trustedlo_cap_util_pd_deprivilege();

    return seL4_NoError;
}

static inline seL4_Error
mktxlo_context_switch(void *txlo_info, trustedlo_ctxt_t *context, void *xrt_req_header)
{
    TRY_OR_RETURN_ERROR(mktxlo_context_activate(context));
    TRY_OR_RETURN_ERROR(mktxlo_context_refresh(txlo_info, context, xrt_req_header));

    return seL4_NoError;
}

static inline seL4_Error mktxlo_fill_tramp_args(void *context, void *frame_targs)
{
    const trustedlo_ctxt_t *ctxt = context;
    trampoline_args_t *args = (trampoline_args_t *)(frame_targs);

    Elf64_Ehdr *ehdr = mktxlo_client_image_elf(tsldr_vm_layout.container_image.base);

    *args = (trampoline_args_t){
        .regions =
            {
#if defined(CONFIG_ARCH_X86_64)
                [REGION_TSLDR_STACK] =
                    {
                        tsldr_vm_layout.microkit_x86_stack.base,
                        (uintptr_t)TSLDR_VM_PAGE_SIZE,
                    },
#elif defined(CONFIG_ARCH_AARCH64)
                [REGION_TSLDR_STACK] =
                    {
                        tsldr_vm_layout.microkit_aarch64_stack.base,
                        (uintptr_t)TSLDR_VM_PAGE_SIZE,
                    },
#else
#error "Unsupported architecture"
#endif
                [REGION_TSLDR_METADATA] =
                    {
                        tsldr_vm_layout.loader_metadata.base,
                        (uintptr_t)tsldr_vm_layout.loader_metadata.size,
                    },
                [REGION_TXLO_XRT_REQ] =
                    {
                        tsldr_vm_layout.txlo_xrt_req.base,
                        (uintptr_t)tsldr_vm_layout.txlo_xrt_req.size,
                    },
                [REGION_CONTAINER_STACK] =
                    {
                        tsldr_vm_layout.container_stack.base,
                        (uintptr_t)tsldr_vm_layout.container_stack.size,
                    },
                [REGION_TSLDR_CONTEXT] =
                    {
                        tsldr_vm_layout.loader_context.base,
                        (uintptr_t)tsldr_vm_layout.loader_context.size,
                    },
                [REGION_TSLDR_PROGRAM] =
                    {
                        tsldr_vm_layout.loader_program.base,
                        (uintptr_t)tsldr_vm_layout.loader_program.size,
                    },
            },
        .container_stack_top = TSLDR_VM_CONTAINER_STACK_END,
        .client_elf = (uintptr_t)ehdr->e_entry,
        .ipc_buffer = tsldr_vm_layout.ipc_buffer.base,
        .monitor_channel = ctxt->txlo_monitor_init_field.channel,
        .monitor_pcmcall_id = ctxt->txlo_monitor_init_field.call_id,
    };

    return seL4_NoError;
}

static inline seL4_Error
mktxlo_fill_client_args(const txlo_info_t *info, const trustedlo_ctxt_t *context, void *frame_cargs)
{
    seL4_Word bitmap_opt_notifications = 0;
    seL4_Word bitmap_opt_ppcs = 0;

    for (int i = 0; i < MICROKIT_MAX_CHANNELS; ++i) {
        if (context->allowed_notifications[i] == XRT_STATE_USED) {
            bitmap_opt_notifications |= (1 << i);
        }
        if (context->allowed_ppcs[i] == XRT_STATE_USED) {
            bitmap_opt_ppcs |= (1 << i);
        }
    }

    seL4_Word bitmap_notifications =
        (info->microkit_notifications & (~info->bitmap_opt_notifications)) |
        bitmap_opt_notifications;

    seL4_Word bitmap_ppcs = (info->microkit_pps & (~info->bitmap_opt_ppcs)) | bitmap_opt_ppcs;

    client_args_t *cargs = (client_args_t *)(frame_cargs);

    *cargs = (client_args_t){
        .bitmap_notifications = bitmap_notifications,
        .bitmap_ppcs = bitmap_ppcs,
        .bitmap_irqs = info->microkit_irqs,
        .bitmap_ioports = info->microkit_ioports,
    };

    return seL4_NoError;
}

void mktxlo_self_load_entry(void)
{
    void *txlo_info = (void *)tsldr_vm_layout.loader_metadata.base;
    void *xrt_req_header = (void *)tsldr_vm_layout.txlo_xrt_req.base;

    trustedlo_ctxt_t *context = (trustedlo_ctxt_t *)tsldr_vm_layout.loader_context.base;

    uintptr_t client_elf = tsldr_vm_layout.container_image.base;
    uintptr_t trampo_elf = tsldr_vm_layout.trampoline_image.base;

    trampoline_args_t *trampo_args = (trampoline_args_t *)(tsldr_vm_layout.trampoline_args.base);
    client_args_t *client_args =
        (client_args_t *)((unsigned char *)trampo_args + sizeof(trampoline_args_t));

    TRY_OR_RETURN_VOID(mktxlo_client_image_check_integrity(client_elf));
    TRY_OR_RETURN_VOID(mktxlo_payload_check_integrity(trampo_elf));

    TRY_OR_RETURN_VOID(mktxlo_context_switch(txlo_info, context, xrt_req_header));

    TRY_OR_RETURN_VOID(mktxlo_client_image_load(client_elf));
    TRY_OR_RETURN_VOID(mktxlo_payload_load((Elf64_Ehdr *)trampo_elf));

    TRY_OR_RETURN_VOID(mktxlo_fill_tramp_args(context, trampo_args));
    TRY_OR_RETURN_VOID(mktxlo_fill_client_args(txlo_info, context, client_args));

    /* ---- jump to trampoline's entry ---- */

    uintptr_t tramp_entry = ((Elf64_Ehdr *)trampo_elf)->e_entry;

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Switch to the trampoline's code to execute: "
                                   "stack: %x, entry: %x\n",
                    (void *)(TSLDR_VM_TRAMPOLINE_STACK_END),
                    (void *)tramp_entry);

    mktxlo_jumpto((void *)(TSLDR_VM_TRAMPOLINE_STACK_END), (entry_fn_t)tramp_entry, trampo_args);
}
