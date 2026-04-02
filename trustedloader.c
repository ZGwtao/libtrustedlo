
#include <acrtutils.h>
#include <caputils.h>
#include <libtrustedlo.h>

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
    tsldr_miscutil_memset(loader->allowed_channels, 0, sizeof(loader->allowed_channels));
    tsldr_miscutil_memset(loader->allowed_irqs, 0, sizeof(loader->allowed_irqs));

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
    tsldr_acrtutil_revoke_channels(loader, mdinfo);
    tsldr_acrtutil_revoke_irqs(loader, mdinfo);
    tsldr_acrtutil_revoke_mappings(loader);
}

void tsldr_main_restore_caps(tsldr_context_t *loader, void *mdinfo)
{
    if (!loader) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts("tsldr_main_restore_caps: ");
        microkit_dbg_puts(" invalid loader pointer given\n");
        microkit_internal_crash(-1);
    }
    /* if no need to restore caps */
    // if (loader->restore == false) {
    //     TSLDR_DBG_PRINT(LIB_NAME_MACRO "tsldr_main_restore_caps: first run, no need to restore anything\n");
    //     return;
    // }
    tsldr_acrtutil_restore_channels(loader, mdinfo);
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
void tsldr_main_jump_with_stack(void *new_stack, void (*entry)(void))
{
    __asm__ volatile(
        "mov %rdi, %rsp\n\t"   /* new_stack in rdi */
        "jmp *%rsi\n\t"        /* entry in rsi */
    );
}
#elif defined(CONFIG_ARCH_AARCH64)
__attribute__((noreturn))
void tsldr_main_jump_with_stack(void *new_stack, void (*entry)(void))
{
    /* jump tp trampoline */
    asm volatile (
        "mov sp, %[new_stack]\n\t" /* set new SP */
        "br  %[func]\n\t"          /* branch directly, never return */
        :
        : [new_stack] "r" (new_stack),
          [func] "r" (entry)
        : "x30", "memory"
    );
    __builtin_unreachable();
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


void tsldr_main_pd_restore_caps_for_required_rights(tsldr_context_t *context, void *mdinfo)
{
    tsldr_main_restore_caps(context, mdinfo);
}

void tsldr_main_pd_remove_caps_for_redundant_rights(tsldr_context_t *context, void *mdinfo)
{
    tsldr_main_remove_caps(context, mdinfo);
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

    tsldr_main_pd_remove_caps_for_redundant_rights(context, mdinfo);

    /* if this is not a first-time execution, restore the access rights distribution to the default state */
    /* once the PD is restored to a default state, we can populate the rights with the information provided above */
    tsldr_main_pd_restore_caps_for_required_rights(context, mdinfo);

}


void tsldr_main_self_loading(void *mdinfo, void *acrt_stat_base, tsldr_context_t *context, uintptr_t client_elf, uintptr_t client_exec_region, uintptr_t trampoline_elf, uintptr_t trampoline_stack_top)
{
    tsldr_main_loading_prologue(mdinfo, context);

    seL4_Word err;
    /* start to parse client elf information */
    tsldr_main_check_elf_integrity(client_elf, &err);
    if (err) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Failed to check client elf integrity\n");
        return;
    }
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)client_elf;
    tsldr_main_check_elf_integrity(trampoline_elf, &err);
    if (err) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Failed to check trampoline elf integrity\n");
        return;
    }
    Elf64_Ehdr *trampoline_ehdr = (Elf64_Ehdr *)trampoline_elf;


    tsldr_main_handle_access_rights(context, acrt_stat_base, mdinfo);


    tsldr_main_loading_epilogue(client_exec_region, (uintptr_t)0x0);

    tsldr_miscutil_load_elf((void *)ehdr->e_entry, ehdr);
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Load client elf to the targeting memory region\n");

    tsldr_miscutil_load_elf((void *)trampoline_ehdr->e_entry, trampoline_ehdr);
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Load trampoline elf to the targeting memory region\n");

    /* -- now we are ready to jump to the trampoline -- */

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "Switch to the trampoline's code to execute: stack: %x, entry: %x\n",
                    (void *)trampoline_stack_top, (void *)trampoline_ehdr->e_entry);
    tsldr_main_jump_with_stack((void *)trampoline_stack_top, (entry_fn_t)trampoline_ehdr->e_entry);   
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

void tsldr_main_monitor_encode_required_rights(void *base, tsldr_acrtreq_t *req_acrt)
{
    tsldr_acrtutil_encode_rights(base, req_acrt->channels, req_acrt->num_req_channels, req_acrt->irqs, req_acrt->num_req_irqs, req_acrt->mappings, req_acrt->num_req_mappings);
}
