
#include <acrtutils.h>
#include <caputils.h>
#include <libtrustedlo.h>
#include <tsldr_vm_layout.h>

void tsldr_main_declare_required_rights(tsldr_context_t *loader, void *data)
{
    if (!loader || !data) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "invalid loader pointer given\n");
        microkit_internal_crash(-1);
    }

    seL4_Word num = tsldr_acrtutil_check_access_rights_table(data);
    seL4_Word *p = (seL4_Word *)data;

    tsldr_acrtutil_populate_all_rights(loader, ++p, num);

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "finished up access rights integrity checking\n");
}


void tsldr_main_pin_required_rights_before_pola(tsldr_context_t *loader, void *mdinfo)
{
    if (!loader) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid loader pointer given\n");
        microkit_internal_crash(-1);
    }
    loader->mp_cnt = 0;
    tsldr_acrt_table_t *rights = &loader->acrt_required_table;
    for (int i = 0; i < rights->num_entries; i++)
        tsldr_acrtutil_add_rights_to_whitelist((void *)loader, (void *)(&rights->entries[i]), mdinfo);

}

void tsldr_main_try_init_loader(tsldr_context_t *c, size_t id)
{
    if (!c) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Try to init null loader\n");
        return;
    }
    if (c->init != true) {
        c->child_id = id;
        c->init = true;
        c->restore = false;
    }
}

void tsldr_main_remove_caps(tsldr_context_t *loader, void *mdinfo)
{
    if (!loader) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts("tsldr_main_remove_caps: ");
        microkit_dbg_puts(" invalid loader pointer given\n");
        microkit_internal_crash(-1);
    }
    /* set the flag to restore cap during restart */
    if (loader->restore == false) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "tsldr_main_remove_caps: need to restore access rights in next round\n");
        loader->restore = true;
        return;
    }
    /* clean up all ACCESS_RIGHTS_USED caps */
    tsldr_acrtutil_revoke_notifications(loader, mdinfo);
    tsldr_acrtutil_revoke_ppcs(loader, mdinfo);
    tsldr_acrtutil_revoke_irqs(loader, mdinfo);
    tsldr_acrtutil_revoke_mappings(loader);
    /* once finished, all USED are UNSET */
}

void tsldr_main_restore_caps(tsldr_context_t *loader, void *mdinfo)
{
    if (!loader) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts("tsldr_main_restore_caps: ");
        microkit_dbg_puts(" invalid loader pointer given\n");
        microkit_internal_crash(-1);
    }

    /* for ACCESS_RIGHTS_KEEP, keep them as USED */
    /* for ACCESS_RIGHTS_ALLOWED, create them from backup CNode */
    /* for ACCESS_RIGHTS_UNSET, do nothing */
    /* and there should not be any other states (all USED are UNSET from remove_caps) */
    tsldr_acrtutil_restore_notifications(loader, mdinfo);
    tsldr_acrtutil_restore_ppcs(loader, mdinfo);
    tsldr_acrtutil_restore_irqs(loader, mdinfo);
    tsldr_acrtutil_restore_mappings(loader);
}


void tsldr_main_loading_epilogue(uintptr_t client_exec, uintptr_t client_stack)
{
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Entry of trusted loader epilogue\n");

    tsldr_caputil_pd_deprivilege();

    // FIXME: currently the size of exec section is fixed
    tsldr_miscutil_memset((void *)client_exec, 0, 0x1000);

    // TODO: refresh the client stack...
    // -> the client should use a different stack with the trusted loader

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Exit of trusted loader epilogue\n");
}


void tsldr_main_loading_prologue(void *mdinfo, tsldr_context_t *loader)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    if (!md->init) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "trusted loading metadata is not prepared...\n");
        microkit_internal_crash(-1);
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "trusted loading metadata is ready...\n");
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "trusted loader init prologue\n");

    /* do some id activation here before actually parsing access rights... */
    tsldr_main_try_init_loader(loader, md->child_id);
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


void tsldr_main_check_elf_integrity(uintptr_t elf, seL4_Word *err)
{
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Check ELF integrity\n");
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    /* check elf integrity */
    if (tsldr_miscutil_memcmp(ehdr->e_ident, (const unsigned char*)ELFMAG, SELFMAG) != 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "ELF magic number mismatch\n");
        *err = 1;
        //microkit_internal_crash(-1);
    } else {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "ELF magic number verified\n");
        *err = 0;
    }
}


void tsldr_main_handle_access_rights(tsldr_context_t *context, void *acrt_stat_base, void *mdinfo)
{
    /* populate the required access rights to the loader */
    /* but not populate the rights immediately */
    // it records the required access rights in "tsldr_acrt_table_t access_rights"
    // while the state of last execution are recorded in "allowed_xxx"
    // we populate the rights to access_rights here, and compared the information from last run with it
    tsldr_main_declare_required_rights(context, acrt_stat_base);

    /* (really) populate allowed access rights */
    // we use this function to:
    //  initialise the allowed lists for different resources for this execution round
    //  so we need the information of allowed resources that are recorded in "access_rights"
    //  and update the whitelist for resources to keep for this round
    //  we then will remove the unnecessary resources based on the whitelist to filter resources
    tsldr_main_pin_required_rights_before_pola(context, mdinfo);


    tsldr_main_remove_caps(context, mdinfo);

    /* if this is not a first-time execution, restore the access rights distribution to the default state */
    /* once the PD is restored to a default state, we can populate the rights with the information provided above */
    tsldr_main_restore_caps(context, mdinfo);

}

void tsldr_main_self_loading(void)
{
    /*
     * All VM layout values are generated by vm_layout.py and
     * obtained directly from tsldr_vm_layout.
     */
    void *mdinfo =
        (void *)tsldr_vm_layout.loader_metadata.base;

    void *acrt_stat_base =
        (void *)tsldr_vm_layout.ossvc_metadata.base;

    tsldr_context_t *context =
        (tsldr_context_t *)
            tsldr_vm_layout.loader_context.base;

    uintptr_t client_elf =
        tsldr_vm_layout.container_image.base;

    uintptr_t client_exec_region =
        tsldr_vm_layout.container_program.base;

    uintptr_t trampoline_elf =
        tsldr_vm_layout.trampoline_image.base;

    uintptr_t trampoline_stack_top =
        tsldr_vm_layout.trampoline_stack.base;

    tsldr_main_loading_prologue(mdinfo, context);

    seL4_Word err;

    tsldr_main_check_elf_integrity(client_elf, &err);
    if (err) {
        TSLDR_DBG_PRINT(
            LIB_NAME_MACRO "Failed to check client elf integrity\n"
        );
        return;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)client_elf;

    tsldr_main_check_elf_integrity(trampoline_elf, &err);
    if (err) {
        TSLDR_DBG_PRINT(
            LIB_NAME_MACRO "Failed to check trampoline elf integrity\n"
        );
        return;
    }

    Elf64_Ehdr *trampoline_ehdr = (Elf64_Ehdr *)trampoline_elf;

    tsldr_main_handle_access_rights(
        context,
        acrt_stat_base,
        mdinfo
    );

    tsldr_main_loading_epilogue(
        client_exec_region,
        (uintptr_t)0x0
    );

    tsldr_miscutil_load_elf(
        (void *)(uintptr_t)ehdr->e_entry,
        ehdr
    );

    TSLDR_DBG_PRINT(
        LIB_NAME_MACRO
        "Load client elf to the targeting memory region\n"
    );

    tsldr_miscutil_load_elf(
        (void *)(uintptr_t)trampoline_ehdr->e_entry,
        trampoline_ehdr
    );

    TSLDR_DBG_PRINT(
        LIB_NAME_MACRO
        "Load trampoline elf to the targeting memory region\n"
    );

#if defined(CONFIG_ARCH_X86_64)
    uintptr_t tsldr_stack_bottom = (0x7fffffffe000);
#elif defined(CONFIG_ARCH_AARCH64)
    uintptr_t tsldr_stack_bottom = (0x0000000fffffff000);
#else
#error "Unsupported architecture"
#endif

    trampoline_args_t *args =
        (trampoline_args_t *)
            tsldr_vm_layout.trampoline_args.base;

    *args = (trampoline_args_t) {
        .regions = {
            [REGION_TSLDR_STACK] = {
                tsldr_stack_bottom,
                (uintptr_t)TSLDR_VM_PAGE_SIZE,
            },
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
    };

    tsldr_mdinfo_t *mdi = (tsldr_mdinfo_t *)mdinfo;

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
        (mdi->microkit_notifications & (~mdi->bitmap_opt_notifications)) | bitmap_opt_notifications;

    seL4_Word bitmap_ppcs = 
        (mdi->microkit_pps & (~mdi->bitmap_opt_ppcs)) | bitmap_opt_ppcs;

    client_args_t *cargs =
        (client_args_t *)((unsigned char *)args + sizeof(trampoline_args_t));

    *cargs = (client_args_t) {
        .bitmap_notifications = bitmap_notifications,
        .bitmap_ppcs = bitmap_ppcs,
        .bitmap_irqs = mdi->microkit_irqs,
        .bitmap_ioports = mdi->microkit_ioports,
    };

    TSLDR_DBG_PRINT(
        LIB_NAME_MACRO
        "Switch to the trampoline's code to execute: "
        "stack: %x, entry: %x\n",
        (void *)trampoline_stack_top,
        (void *)(uintptr_t)trampoline_ehdr->e_entry
    );

    tsldr_main_jump_with_stack(
        (void *)trampoline_stack_top,
        (entry_fn_t)(uintptr_t)trampoline_ehdr->e_entry,
        args
    );
}


void tsldr_main_monitor_init_mdinfo(tsldr_mdinfodb_t *db, size_t id, void *mdinfo)
{
    if (!db || !mdinfo) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid mdinfo database pointer given\n");
        return;
    }
    if (id >= 16 || id < 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid template PD child ID given: %d\n", id);
        return;
    }
    tsldr_mdinfo_t *dest = (tsldr_mdinfo_t *)mdinfo;
    tsldr_mdinfo_t *src = &db->infodb[id];

    tsldr_miscutil_memset(dest, 0, sizeof(tsldr_mdinfo_t));
    tsldr_miscutil_memcpy(dest, src, sizeof(tsldr_mdinfo_t));

    dest->init = true;

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "child_loc: %d\n", id);
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "child_id: %d\n", dest->child_id);
}


void tsldr_main_monitor_privilege_pd(seL4_Word cid)
{
    tsldr_caputil_pd_privilege(cid);
}

void tsldr_main_monitor_encode_required_rights(
    void *base,
    tsldr_acrtreq_t *req_acrt)
{
    tsldr_acrtutil_encode_rights(
        base,
        req_acrt->notifications,
        req_acrt->num_req_notifications,
        req_acrt->ppcs,
        req_acrt->num_req_ppcs,
        req_acrt->irqs,
        req_acrt->num_req_irqs,
        req_acrt->ioports,
        req_acrt->num_req_ioports,
        req_acrt->mappings,
        req_acrt->num_req_mappings
    );
}
