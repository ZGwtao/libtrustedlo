
#include <caputils.h>
#include <miscutils.h>

void tsldr_caputil_delete_cap(seL4_Word cap_idx)
{
    seL4_Word err = seL4_CNode_Delete(CNODE_SELF_CAP, cap_idx, PD_CAP_BITS);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_delete_cap: ");
        microkit_dbg_puts(" failed to delete cap_idx from working cnode '");
        microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void tsldr_caputil_delete_cap_from_cnode(seL4_Word cap_idx, seL4_Word cnode_idx)
{
    seL4_Word err = seL4_CNode_Delete(cnode_idx, cap_idx, PD_CAP_BITS);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_delete_cap_from_cnode: ");
        microkit_dbg_puts(" failed to delete cap_idx '");
        microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("' from cnode: '");
        microkit_dbg_put32(cnode_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void tsldr_caputil_load_cap_from_backup_cnode(seL4_Word dest_idx, seL4_Word src_idx)
{
    seL4_Word err = seL4_CNode_Move(
        CNODE_SELF_CAP, dest_idx, PD_CAP_BITS,
        CNODE_BACKUP_CAP, src_idx, PD_CAP_BITS
    );
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_load_cap_from_backup_cnode: ");
        microkit_dbg_puts(" failed to load cap_idx from backup cnode '");
        //microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void tsldr_caputil_store_cap_to_backup_cnode(seL4_Word dest_idx, seL4_Word src_idx)
{
    seL4_Word err = seL4_CNode_Move(
        CNODE_BACKUP_CAP, dest_idx, PD_CAP_BITS,
        CNODE_SELF_CAP, src_idx, PD_CAP_BITS
    );
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_store_cap_to_backup_cnode: ");
        microkit_dbg_puts(" failed to store cap_idx to backup cnode '");
        //microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void tsldr_caputil_copy_cap_from_backup_cnode(seL4_Word dest_idx, seL4_Word src_idx, seL4_CapRights_t rights)
{
    seL4_Word err = seL4_CNode_Copy(
        CNODE_SELF_CAP, dest_idx, PD_CAP_BITS,
        CNODE_BACKUP_CAP, src_idx, PD_CAP_BITS,
        rights
    );
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_copy_cap_from_backup_cnode: ");
        microkit_dbg_puts(" failed to copy cap_idx from backup cnode '");
        //microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void tsldr_caputil_copy_cap_between_cnode(seL4_Word cap_dest, seL4_Word cnode_dest, seL4_Word cap_src, seL4_Word cnode_src)
{
    // FIXME: copy rights
    seL4_Word err = seL4_CNode_Copy(cnode_dest, cap_dest, PD_CAP_BITS, cnode_src, cap_src, PD_CAP_BITS, seL4_AllRights);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_copy_cap_between_cnode: ");
        //microkit_dbg_puts(" failed to copy cap_idx from backup cnode '");
        //microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}


void tsldr_caputil_pd_deprivilege(void)
{
    tsldr_caputil_delete_cap(CNODE_BACKUP_CAP);

    tsldr_caputil_delete_cap(CNODE_SELF_CAP);
}

void tsldr_caputil_pd_privilege(seL4_Word pd_idx)
{
    tsldr_caputil_delete_cap_from_cnode(CNODE_SELF_CAP, CHILD_CSPACE_BASE + pd_idx);
    tsldr_caputil_delete_cap_from_cnode(CNODE_BACKUP_CAP, CHILD_CSPACE_BASE + pd_idx);
    tsldr_caputil_copy_cap_between_cnode(CNODE_SELF_CAP, CHILD_CSPACE_BASE + pd_idx, CHILD_CSPACE_BASE + pd_idx, CNODE_SELF_CAP);
    tsldr_caputil_copy_cap_between_cnode(CNODE_BACKUP_CAP, CHILD_CSPACE_BASE + pd_idx, CHILD_BACKUP_BASE + pd_idx, CNODE_SELF_CAP);
}



void tsldr_caputil_pd_grant_vspace_access(void)
{
    // TODO: add log here
    tsldr_caputil_load_cap_from_backup_cnode(VSPACE_SELF_CAP, VSPACE_BACKUP_CAP);
}


void tsldr_caputil_pd_revoke_vspace_access(void)
{
    // TODO: add log here
    tsldr_caputil_store_cap_to_backup_cnode(VSPACE_BACKUP_CAP, VSPACE_SELF_CAP);
}


void tsldr_caputil_pd_grant_page_access(seL4_Word page_idx, seL4_Word vaddr, seL4_CapRights_t rights, seL4_Word attrs, seL4_Word page_num)
{
#if 0
    if (page_idx >= MICROKIT_MAX_CHANNELS) {
        // FIXME
        microkit_dbg_puts(" tsldr_caputil_pd_grant_page_access:\n");
        microkit_dbg_puts(" invalid page id given '");
        microkit_dbg_put32(page_idx);
        microkit_dbg_puts("'\n");
        return;
    }
#endif
    seL4_Word backup_idx = BACKUP_MAPPING_BASE_CAP + page_idx;
#if defined(CONFIG_ARM_ABS_MAP)
    //tsldr_caputil_pd_page_map(backup_idx, vaddr, rights, attrs, 1);
    seL4_Error err = seL4_ARM_VSpace_Map_Absolute(VSPACE_SELF_CAP, CNODE_BACKUP_CAP, backup_idx, PD_CAP_BITS, vaddr, rights, attrs, page_num);
    if (err != seL4_NoError) {
        microkit_internal_crash(err);
    }
#else
    seL4_Word target_idx = MAPPING_BASE_CAP;
    for (seL4_Word i = 0; i < page_num; ++i) {
        /* Load the page to map from the background CNode */
        tsldr_caputil_load_cap_from_backup_cnode(target_idx, backup_idx + i);
        /* Do the actual mappings here... */
        tsldr_caputil_pd_page_map(target_idx, vaddr, rights, attrs, 0);
        /* Move the mapped page back to the background CNode */
        tsldr_caputil_store_cap_to_backup_cnode(backup_idx + i, target_idx);
    }
#endif
}


void tsldr_caputil_pd_revoke_page_access(seL4_Word page_idx, seL4_Word page_num)
{
    seL4_Word backup_idx = BACKUP_MAPPING_BASE_CAP + page_idx;
#if defined(CONFIG_ARM_ABS_MAP)
    //tsldr_caputil_pd_page_unmap(backup_idx, 1);
    seL4_Error err = seL4_ARM_VSpace_Unmap_Absolute(VSPACE_SELF_CAP, CNODE_BACKUP_CAP, backup_idx, PD_CAP_BITS, page_num);
    if (err != seL4_NoError) {
        microkit_internal_crash(err);
    }
#else
    seL4_Word target_idx = MAPPING_BASE_CAP;
    for (seL4_Word i = 0; i < page_num; ++i) {
        tsldr_caputil_load_cap_from_backup_cnode(target_idx, backup_idx + i);
        tsldr_caputil_pd_page_unmap(target_idx, 0);
        tsldr_caputil_store_cap_to_backup_cnode(backup_idx + i, target_idx);
    }
#endif
}


void tsldr_caputil_revoke_irq_cap(seL4_Word irq_idx)
{
    if (irq_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_revoke_irq_cap: ");
        microkit_dbg_puts(" invalid IRQ id given '");
        microkit_dbg_put32(irq_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    tsldr_caputil_delete_cap(IRQ_BASE_CAP + irq_idx);
}

void tsldr_caputil_revoke_ppc_cap(seL4_Word ppc_idx)
{
    if (ppc_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_revoke_ppc_cap: ");
        microkit_dbg_puts(" invalid PPC id given '");
        microkit_dbg_put32(ppc_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    tsldr_caputil_delete_cap(PPC_BASE_CAP + ppc_idx);
}

void tsldr_caputil_revoke_notification_cap(seL4_Word ntfn_idx)
{
    if (ntfn_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_revoke_ntfn_cap: ");
        microkit_dbg_puts(" invalid Notification id given '");
        microkit_dbg_put32(ntfn_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    tsldr_caputil_delete_cap(NTFN_BASE_CAP + ntfn_idx);
}

void tsldr_caputil_restore_irq_cap(seL4_Word irq_idx)
{
    if (irq_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_restore_irq_cap: ");
        microkit_dbg_puts(" invalid IRQ id given '");
        microkit_dbg_put32(irq_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    // FIXME: should we allow full access in each access right restoring operation?
    tsldr_caputil_copy_cap_from_backup_cnode(IRQ_BASE_CAP + irq_idx, BACKUP_IRQ_BASE_CAP + irq_idx, seL4_AllRights);
}

void tsldr_caputil_restore_ppc_cap(seL4_Word ppc_idx)
{
    if (ppc_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_restore_ppc_cap: ");
        microkit_dbg_puts(" invalid PPC id given '");
        microkit_dbg_put32(ppc_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    tsldr_caputil_copy_cap_from_backup_cnode(PPC_BASE_CAP + ppc_idx, BACKUP_PPC_BASE_CAP + ppc_idx, seL4_AllRights);
}

void tsldr_caputil_restore_notification_cap(seL4_Word ntfn_idx)
{
    if (ntfn_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_restore_notification_cap: ");
        microkit_dbg_puts(" invalid Notification id given '");
        microkit_dbg_put32(ntfn_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    tsldr_caputil_copy_cap_from_backup_cnode(NTFN_BASE_CAP + ntfn_idx, BACKUP_NTFN_BASE_CAP + ntfn_idx, seL4_AllRights);
}


void tsldr_caputil_pd_page_map(seL4_Word page_idx, uintptr_t vaddr, seL4_CapRights_t rights, seL4_Word attrs, uint8_t flags)
{
    seL4_Word err;
#if defined(CONFIG_ARCH_X86_64)
    err = seL4_X64_PML4_Map_Absolute(VSPACE_SELF_CAP, CNODE_SELF_CAP, page_idx, PD_CAP_BITS, vaddr, rights, attrs, 1);
#elif defined(CONFIG_ARCH_AARCH64)
    if (flags == 0)
        err = seL4_ARM_Page_Map(page_idx, VSPACE_SELF_CAP, vaddr, rights, attrs);
    else {
#if defined(CONFIG_ARM_ABS_MAP)
        err = seL4_ARM_VSpace_Map_Absolute(VSPACE_SELF_CAP, CNODE_BACKUP_CAP, page_idx, PD_CAP_BITS, vaddr, rights, attrs, 1);
#else
#error "Unsupported syscall for tsldr_caputil_pd_page_map, try enable KernelArmAbsMap"
#endif
    }
#else
#error "Unsupported architecture for 'tsldr_caputil_pd_page_map'"
#endif
    if (err != seL4_NoError) {
        // FIXME
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_pd_page_map: ");
        microkit_dbg_puts(" failed to map page with id '");
        microkit_dbg_put32(page_idx);
        //microkit_dbg_puts("', in vaddr: '");
        //microkit_dbg_put64(vaddr);
        microkit_dbg_puts("'\n with rights: '");
        microkit_dbg_put32(rights.words[0]);
        microkit_dbg_puts("' and attribute: '");
        microkit_dbg_put32(attrs);
        microkit_dbg_puts("'\n");
        microkit_internal_crash(err);
    }
}

void tsldr_caputil_pd_page_unmap(seL4_Word page_idx, uint8_t flags)
{
    seL4_Word err;
#if defined(CONFIG_ARCH_X86_64)
    err = seL4_X64_PML4_Unmap_Absolute(VSPACE_SELF_CAP, CNODE_SELF_CAP, page_idx, PD_CAP_BITS, 1);
#elif defined(CONFIG_ARCH_AARCH64)
    if (flags == 0)
        err = seL4_ARM_Page_Unmap(page_idx);
    else {
#if defined(CONFIG_ARM_ABS_MAP)
        err = seL4_ARM_VSpace_Unmap_Absolute(VSPACE_SELF_CAP, CNODE_BACKUP_CAP, page_idx, PD_CAP_BITS, 1);
#else
#error "Unsupported syscall for tsldr_caputil_pd_page_map, try enable KernelArmAbsMap"
#endif
    }
#else
#error "Unsupported architecture for 'tsldr_caputil_pd_page_unmap'"
#endif
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_caputil_pd_page_unmap: ");
        microkit_dbg_puts(" failed to unmap page with id '");
        microkit_dbg_put32(page_idx);
        microkit_dbg_puts("'\n");
        microkit_internal_crash(err);
    }
}


