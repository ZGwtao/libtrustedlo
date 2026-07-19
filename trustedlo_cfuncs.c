
#include <acrtutils.h>
#include <caputils.h>
#include <libtrustedlo.h>
#include <tsldr_vm_layout.h>


static inline seL4_Error
microkit_trustedlo_parse_requst(void *data)
{
    if (!data) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "invalid request given\n");
        return -1;
    }

    tsldr_acrtutil_check_access_rights_table(data);

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "finished up access rights integrity checking\n");

    return seL4_NoError;
}


static inline seL4_Error
microkit_trustedlo_populate_req2ctxt(trustedlo_ctxt_t *context, void *mdinfo, void *data)
{
    if (!context || !mdinfo) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid context/mdinfo pointer given\n");
        return -1;
    }

    tsldr_acrtutil_populate_all_rights(context, data);

    context->allowed_mappings.mapping_count = 0;

    tsldr_acrt_table_t *rights = &context->acrt_required_table;
    uint64_t entry_num = rights->num_entries;

    for (uint64_t i = 0; i < entry_num; i++) {
        TRY_OR_RETURN_ERROR(
        tsldr_acrtutil_add_rights_to_whitelist(
            context,
            &rights->entries[i],
            mdinfo
        ));
    }
    return seL4_NoError;
}


static inline void
tsldr_main_remove_caps(trustedlo_ctxt_t *context, void *mdinfo)
{
    if (!context) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts("tsldr_main_remove_caps: ");
        microkit_dbg_puts(" invalid context pointer given\n");
        microkit_internal_crash(-1);
    }
    /* set the flag to restore cap during restart */
    if (context->restore == false) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "tsldr_main_remove_caps: need to restore access rights in next round\n");
        context->restore = true;
        return;
    }
    /* clean up all ACCESS_RIGHTS_USED caps */
    tsldr_acrtutil_revoke_notifications(context, mdinfo);
    tsldr_acrtutil_revoke_ppcs(context, mdinfo);
    tsldr_acrtutil_revoke_irqs(context, mdinfo);
    tsldr_acrtutil_revoke_mappings(context);
    /* once finished, all USED are UNSET */
}

static inline void
tsldr_main_restore_caps(trustedlo_ctxt_t *context, void *mdinfo)
{
    if (!context) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts("tsldr_main_restore_caps: ");
        microkit_dbg_puts(" invalid context pointer given\n");
        microkit_internal_crash(-1);
    }

    /* for ACCESS_RIGHTS_KEEP, keep them as USED */
    /* for ACCESS_RIGHTS_ALLOWED, create them from backup CNode */
    /* for ACCESS_RIGHTS_UNSET, do nothing */
    /* and there should not be any other states (all USED are UNSET from remove_caps) */
    tsldr_acrtutil_restore_notifications(context, mdinfo);
    tsldr_acrtutil_restore_ppcs(context, mdinfo);
    tsldr_acrtutil_restore_irqs(context, mdinfo);
    tsldr_acrtutil_restore_mappings(context);
}


static inline seL4_Error
microkit_trustedlo_context_activate(void *mdinfo, trustedlo_ctxt_t *context)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    if (!md->init) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "trusted loading metadata is not prepared...\n");
        return -1;
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "trusted loading metadata is ready...\n");
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "trusted context init prologue\n");

    /* do some id activation here before actually parsing access rights... */
    if (context == NULL) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Try to init null context\n");
        return -1;
    }
    if (context->init != true) {
        context->child_id = md->child_id;
        context->init = true;
        context->restore = false;
    }
    return seL4_NoError;
}


#if defined(CONFIG_ARCH_X86_64)
__attribute__((naked, noreturn)) /* don't let your compiler fuck around with the args */
void tsldr_main_jump_with_stack(void *new_stack, entry_fn_t entry, const trampoline_args_t *args)
{
    __asm__ volatile(
        "mov %rdi, %rsp\n\t"
        "mov %rdx, %rdi\n\t"
        "jmp *%rsi\n\t"
    );
}
#elif defined(CONFIG_ARCH_AARCH64)
__attribute__((naked, noreturn))
void tsldr_main_jump_with_stack(void *new_stack, entry_fn_t entry, const trampoline_args_t *args)
{
    __asm__ volatile(
        "mov sp, x0\n\t"
        "mov x0, x2\n\t"
        "br x1\n\t"
    );
}
#else
#error "Unsupported architecture for 'tsldr_main_jump_with_stack'"
#endif


static inline seL4_Error
microkit_trustedlo_payload_check_integrity(uintptr_t elf)
{
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Check ELF integrity\n");
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    /* check elf integrity */
    if (tsldr_miscutil_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "ELF magic number mismatch\n");
        return -1;
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "ELF magic number verified\n");
    return seL4_NoError;
}


static inline seL4_Error
microkit_trustedlo_payload_load(void *base)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    tsldr_miscutil_load_elf(
        (void *)(ehdr->e_entry),
        ehdr
    );
    return seL4_NoError;
}


static inline seL4_Error
microkit_trustedlo_enforce_pola(trustedlo_ctxt_t *context, void *mdinfo)
{
    tsldr_main_remove_caps(context, mdinfo);

    /* if this is not a first-time execution, restore the access rights distribution to the default state */
    /* once the PD is restored to a default state, we can populate the rights with the information provided above */
    tsldr_main_restore_caps(context, mdinfo);

    return seL4_NoError;
}


static inline seL4_Error
microkit_trustedlo_context_refresh(void *mdinfo, trustedlo_ctxt_t *context, void *acrt_stat_base)
{
    /* populate the required access rights to the loader */
    /* but not populate the rights immediately */
    // it records the required access rights in "tsldr_acrt_table_t access_rights"
    // while the state of last execution are recorded in "allowed_xxx"
    // we populate the rights to access_rights here, and compared the information from last run with it
    TRY_OR_RETURN_ERROR(microkit_trustedlo_parse_requst(acrt_stat_base));

    /* (really) populate allowed access rights */
    // we use this function to:
    //  initialise the allowed lists for different resources for this execution round
    //  so we need the information of allowed resources that are recorded in "access_rights"
    //  and update the whitelist for resources to keep for this round
    //  we then will remove the unnecessary resources based on the whitelist to filter resources
    TRY_OR_RETURN_ERROR(microkit_trustedlo_populate_req2ctxt(context, mdinfo, acrt_stat_base));

    TRY_OR_RETURN_ERROR(microkit_trustedlo_enforce_pola(context, mdinfo));

    tsldr_caputil_pd_deprivilege();

    return seL4_NoError;
}

static inline seL4_Error
microkit_trustedlo_context_switch(void *mdinfo, trustedlo_ctxt_t *context, void *acrt_stat_base)
{
    TRY_OR_RETURN_ERROR(microkit_trustedlo_context_activate(mdinfo, context));
    TRY_OR_RETURN_ERROR(microkit_trustedlo_context_refresh(mdinfo, context, acrt_stat_base));

    return seL4_NoError;
}


static inline seL4_Error
microkit_trustedlo_fill_tramp_args(void *frame_targs)
{
    trampoline_args_t *args = (trampoline_args_t *)(frame_targs);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)(tsldr_vm_layout.container_image.base);

    *args = (trampoline_args_t) {
        .regions = {
#if defined(CONFIG_ARCH_X86_64)
            [REGION_TSLDR_STACK] = {
                tsldr_vm_layout.microkit_x86_stack.base,
                (uintptr_t)TSLDR_VM_PAGE_SIZE,
            },
#elif defined(CONFIG_ARCH_AARCH64)
            [REGION_TSLDR_STACK] = {
                tsldr_vm_layout.microkit_aarch64_stack.base,
                (uintptr_t)TSLDR_VM_PAGE_SIZE,
            },
#else
#error "Unsupported architecture"
#endif
            [REGION_TSLDR_METADATA] = {
                tsldr_vm_layout.loader_metadata.base,
                (uintptr_t)
                    tsldr_vm_layout.loader_metadata.size,
            },
            [REGION_OSSVC_METADATA] = {
                tsldr_vm_layout.ossvc_metadata.base,
                (uintptr_t)
                    tsldr_vm_layout.ossvc_metadata.size,
            },
            [REGION_CONTAINER_STACK] = {
                tsldr_vm_layout.container_stack.base,
                (uintptr_t)
                    tsldr_vm_layout.container_stack.size,
            },
            [REGION_TSLDR_CONTEXT] = {
                tsldr_vm_layout.loader_context.base,
                (uintptr_t)
                    tsldr_vm_layout.loader_context.size,
            },
            [REGION_TSLDR_PROGRAM] = {
                tsldr_vm_layout.loader_program.base,
                (uintptr_t)
                    tsldr_vm_layout.loader_program.size,
            },
        },
        .container_stack_top = TSLDR_VM_CONTAINER_STACK_END,
        .client_elf = (uintptr_t)ehdr->e_entry,
        .ipc_buffer = tsldr_vm_layout.ipc_buffer.base,
        .monitor_channel = 74 + 15,
        .monitor_pcmcall_id = 20,
    };

    return seL4_NoError;
}


static inline seL4_Error
microkit_trustedlo_fill_client_args(const tsldr_mdinfo_t *info, const trustedlo_ctxt_t *context, void *frame_cargs)
{
    seL4_Word bitmap_opt_notifications = 0;
    seL4_Word bitmap_opt_ppcs = 0;

    for (int i = 0; i < MICROKIT_MAX_CHANNELS; ++i) {
        if (context->allowed_notifications[i] == ACCESS_RIGHTS_USED) {
            bitmap_opt_notifications |= (1 << i);
        }
        if (context->allowed_ppcs[i] == ACCESS_RIGHTS_USED) {
            bitmap_opt_ppcs |= (1 << i);
        }
    }

    seL4_Word bitmap_notifications = 
        (info->microkit_notifications & (~info->bitmap_opt_notifications)) | bitmap_opt_notifications;

    seL4_Word bitmap_ppcs = 
        (info->microkit_pps & (~info->bitmap_opt_ppcs)) | bitmap_opt_ppcs;

    client_args_t *cargs = (client_args_t *)(frame_cargs);

    *cargs = (client_args_t) {
        .bitmap_notifications = bitmap_notifications,
        .bitmap_ppcs = bitmap_ppcs,
        .bitmap_irqs = info->microkit_irqs,
        .bitmap_ioports = info->microkit_ioports,
    };

    return seL4_NoError;
}


void microkit_trustedlo_selfload_entry(void)
{
    /*
     * All VM layout values are generated by vm_layout.py and
     * obtained directly from tsldr_vm_layout.
     */
    void *mdinfo = (void *)tsldr_vm_layout.loader_metadata.base;
    void *acrt_stat_base = (void *)tsldr_vm_layout.ossvc_metadata.base;
    trustedlo_ctxt_t *context = (trustedlo_ctxt_t *) tsldr_vm_layout.loader_context.base;

    uintptr_t client_elf = tsldr_vm_layout.container_image.base;
    uintptr_t trampoline_elf = tsldr_vm_layout.trampoline_image.base;

    TRY_OR_RETURN_VOID(microkit_trustedlo_payload_check_integrity(client_elf));
    TRY_OR_RETURN_VOID(microkit_trustedlo_payload_check_integrity(trampoline_elf));
    TRY_OR_RETURN_VOID(microkit_trustedlo_context_switch(mdinfo, context, acrt_stat_base));

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)client_elf;
    Elf64_Ehdr *trampoline_ehdr = (Elf64_Ehdr *)trampoline_elf;

    TRY_OR_RETURN_VOID(microkit_trustedlo_payload_load(ehdr));
    TRY_OR_RETURN_VOID(microkit_trustedlo_payload_load(trampoline_ehdr));

    trampoline_args_t *args = (trampoline_args_t *)(tsldr_vm_layout.trampoline_args.base);
    client_args_t *frame_cargs = (client_args_t *)((unsigned char *)args + sizeof(trampoline_args_t));

    TRY_OR_RETURN_VOID(microkit_trustedlo_fill_tramp_args(args));
    TRY_OR_RETURN_VOID(microkit_trustedlo_fill_client_args(mdinfo, context, frame_cargs));

    TSLDR_DBG_PRINT(
        LIB_NAME_MACRO
        "Switch to the trampoline's code to execute: "
        "stack: %x, entry: %x\n",
        (void *)(TSLDR_VM_TRAMPOLINE_STACK_END),
        (void *)(uintptr_t)trampoline_ehdr->e_entry
    );

    tsldr_main_jump_with_stack(
        (void *)(TSLDR_VM_TRAMPOLINE_STACK_END),
        (entry_fn_t)(uintptr_t)trampoline_ehdr->e_entry,
        args
    );
}
