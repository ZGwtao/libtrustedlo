/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <txlocap.h>
#include <miscutils.h>

void trustedlo_cap_util_delete_cap(seL4_Word cap_idx)
{
    seL4_Word err = seL4_CNode_Delete(DELEGATOR_MK_CNODE_CPTR_X, cap_idx, LOOKUP_DEPTH_MICROKIT);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to delete cap_idx from microkit cnode '");
        microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_load_cap_from_backup_cnode(seL4_Word dest_idx, seL4_Word src_idx)
{
    seL4_Word err = seL4_CNode_Move(DELEGATOR_MK_CNODE_CPTR_X,
                                    dest_idx,
                                    LOOKUP_DEPTH_MICROKIT,

                                    DELEGATION_CNODE_CAP,
                                    src_idx,
                                    LOOKUP_DEPTH_DELEGATION);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to load cap_idx from delegation cnode '");
        // microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_store_cap_to_backup_cnode(seL4_Word dest_idx, seL4_Word src_idx)
{
    seL4_Word err = seL4_CNode_Move(DELEGATION_CNODE_CAP,
                                    dest_idx,
                                    LOOKUP_DEPTH_DELEGATION,

                                    DELEGATOR_MK_CNODE_CPTR_X,
                                    src_idx,
                                    LOOKUP_DEPTH_MICROKIT);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to store cap_idx to delegation  cnode '");
        // microkit_dbg_put32(cap_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_copy_cap_from_backup_cnode(seL4_Word dest_idx,
                                                   seL4_Word src_idx,
                                                   seL4_CapRights_t rights)
{
    seL4_Word err = seL4_CNode_Copy(DELEGATOR_MK_CNODE_CPTR_X,
                                    dest_idx,
                                    LOOKUP_DEPTH_MICROKIT,

                                    DELEGATION_CNODE_CAP,
                                    src_idx,
                                    LOOKUP_DEPTH_DELEGATION,
                                    rights);
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to copy cap_idx from delegation cnode '");
        microkit_dbg_put32(dest_idx);
        microkit_dbg_puts("'\n");
        /* let it crash here */
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_pd_deprivilege(void)
{
    seL4_Error err = seL4_CNode_Delete(DELEGATOR_ROOT_CNODE_CPTR_X,
                                       DELEGATION_GRANT_ROOT_SLOT,
                                       LOOKUP_DEPTH_ROOT);

    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to delete delegation CNode grant\n");
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_pd_privilege(seL4_Word pd_idx)
{
    seL4_CPtr delegation_cnode = DELEGATION_CNODE_CPTR(pd_idx);
    seL4_CPtr delegator_root = DELEGATOR_ROOT_CNODE_CPTR(pd_idx);

    seL4_Error err =
        seL4_CNode_Delete(delegator_root, DELEGATION_GRANT_ROOT_SLOT, LOOKUP_DEPTH_ROOT);
    if (err != seL4_NoError && err != seL4_FailedLookup) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to clear delegation grant slot\n");
        microkit_internal_crash(err);
    }

    err = seL4_CNode_Copy(delegator_root,
                          DELEGATION_GRANT_ROOT_SLOT,
                          LOOKUP_DEPTH_ROOT,

                          delegation_cnode,
                          DELEGATION_SLOT_GRANT_CAP,
                          LOOKUP_DEPTH_DELEGATION,

                          seL4_AllRights);

    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to grant delegation CNode\n");
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_pd_grant_vspace_access(void)
{
    // TODO: add log here
    // trustedlo_cap_util_load_cap_from_backup_cnode(VSPACE_SELF_CAP, VSPACE_BACKUP_CAP);
}

void trustedlo_cap_util_pd_revoke_vspace_access(void)
{
    // TODO: add log here
    // trustedlo_cap_util_store_cap_to_backup_cnode(VSPACE_BACKUP_CAP, VSPACE_SELF_CAP);
}

void trustedlo_cap_util_pd_grant_page_access(seL4_Word page_slot,
                                             seL4_Word vaddr,
                                             seL4_CapRights_t rights,
                                             seL4_Word attrs,
                                             seL4_Word page_num)
{
#if 0
    if (page_idx >= MICROKIT_MAX_CHANNELS) {
        // FIXME
        microkit_dbg_puts(" trustedlo_cap_util_pd_grant_page_access:\n");
        microkit_dbg_puts(" invalid page id given '");
        microkit_dbg_put32(page_idx);
        microkit_dbg_puts("'\n");
        return;
    }
#endif
    // seL4_Word backup_idx = BACKUP_MAPPING_BASE_CAP + page_idx;
#if defined(CONFIG_ARM_ABS_MAP)
    seL4_Error err = seL4_ARM_VSpace_Map_Absolute(DELEGATOR_VSPACE_CPTR,
                                                  DELEGATION_CNODE_CAP,
                                                  page_slot,
                                                  LOOKUP_DEPTH_DELEGATION,
                                                  vaddr,
                                                  rights,
                                                  attrs,
                                                  page_num);
    if (err != seL4_NoError) {
        microkit_internal_crash(err);
    }
#elif defined(CONFIG_X86_ABS_MAP)
    seL4_Error err = seL4_X64_PML4_Map_Absolute(DELEGATOR_VSPACE_CPTR,
                                                DELEGATION_CNODE_CAP,
                                                page_slot,
                                                LOOKUP_DEPTH_DELEGATION,
                                                vaddr,
                                                rights,
                                                attrs,
                                                page_num);
    if (err != seL4_NoError) {
        microkit_internal_crash(err);
    }
#else
    seL4_Word target_idx = MAPPING_BASE_CAP;
    for (seL4_Word i = 0; i < page_num; ++i) {
        /* Load the page to map from the background CNode */
        trustedlo_cap_util_load_cap_from_backup_cnode(target_idx, page_slot + i);
        /* Do the actual mappings here... */
        trustedlo_cap_util_pd_page_map(target_idx, vaddr, rights, attrs, 0);
        /* Move the mapped page back to the background CNode */
        trustedlo_cap_util_store_cap_to_backup_cnode(page_slot + i, target_idx);
    }
#endif
}

void trustedlo_cap_util_pd_revoke_page_access(seL4_Word page_slot, seL4_Word page_num)
{
#if defined(CONFIG_ARM_ABS_MAP)
    seL4_Error err = seL4_ARM_VSpace_Unmap_Absolute(DELEGATOR_VSPACE_CPTR,
                                                    DELEGATION_CNODE_CAP,
                                                    page_slot,
                                                    LOOKUP_DEPTH_DELEGATION,
                                                    page_num);
    if (err != seL4_NoError) {
        microkit_internal_crash(err);
    }
#elif defined(CONFIG_X86_ABS_MAP)
    seL4_Error err = seL4_X64_PML4_Unmap_Absolute(DELEGATOR_VSPACE_CPTR,
                                                  DELEGATION_CNODE_CAP,
                                                  page_slot,
                                                  LOOKUP_DEPTH_DELEGATION,
                                                  page_num);
    if (err != seL4_NoError) {
        microkit_internal_crash(err);
    }
#else
    seL4_Word target_idx = MAPPING_BASE_CAP;
    for (seL4_Word i = 0; i < page_num; ++i) {
        trustedlo_cap_util_load_cap_from_backup_cnode(target_idx, page_slot + i);
        trustedlo_cap_util_pd_page_unmap(target_idx, 0);
        trustedlo_cap_util_store_cap_to_backup_cnode(page_slot + i, target_idx);
    }
#endif
}

void trustedlo_cap_util_revoke_irq_cap(seL4_Word irq_idx)
{
    if (irq_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": invalid IRQ id given '");
        microkit_dbg_put32(irq_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    trustedlo_cap_util_delete_cap(IRQ_BASE_CAP + irq_idx);
}

void trustedlo_cap_util_revoke_ppc_cap(seL4_Word ppc_idx)
{
    if (ppc_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": invalid PPC id given '");
        microkit_dbg_put32(ppc_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    trustedlo_cap_util_delete_cap(PPC_BASE_CAP + ppc_idx);
}

void trustedlo_cap_util_revoke_notification_cap(seL4_Word ntfn_idx)
{
    if (ntfn_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": invalid Notification id given '");
        microkit_dbg_put32(ntfn_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    trustedlo_cap_util_delete_cap(NTFN_BASE_CAP + ntfn_idx);
}

void trustedlo_cap_util_restore_irq_cap(seL4_Word irq_idx)
{
    if (irq_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": invalid IRQ id given '");
        microkit_dbg_put32(irq_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    // FIXME: should we allow full access in each access right restoring operation?
    trustedlo_cap_util_copy_cap_from_backup_cnode(IRQ_BASE_CAP + irq_idx,
                                                  BACKUP_IRQ_BASE_CAP + irq_idx,
                                                  seL4_AllRights);
}

void trustedlo_cap_util_restore_ppc_cap(seL4_Word ppc_idx)
{
    if (ppc_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": invalid PPC id given '");
        microkit_dbg_put32(ppc_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    trustedlo_cap_util_copy_cap_from_backup_cnode(PPC_BASE_CAP + ppc_idx,
                                                  PPC_BASE_CAP + ppc_idx,
                                                  seL4_AllRights);
}

void trustedlo_cap_util_restore_notification_cap(seL4_Word ntfn_idx)
{
    if (ntfn_idx >= MICROKIT_MAX_CHANNELS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": invalid Notification id given '");
        microkit_dbg_put32(ntfn_idx);
        microkit_dbg_puts("'\n");
        return;
    }
    trustedlo_cap_util_copy_cap_from_backup_cnode(NTFN_BASE_CAP + ntfn_idx,
                                                  BACKUP_NTFN_BASE_CAP + ntfn_idx,
                                                  seL4_AllRights);
}

void trustedlo_cap_util_pd_page_map(seL4_Word page_idx,
                                    uintptr_t vaddr,
                                    seL4_CapRights_t rights,
                                    seL4_Word attrs,
                                    uint8_t flags)
{
    seL4_Word err;
#if defined(CONFIG_ARCH_X86_64)
    if (flags == 0)
        err = seL4_X86_Page_Map(page_idx, DELEGATOR_VSPACE_CPTR, vaddr, rights, attrs);
    else {
#if defined(CONFIG_X86_ABS_MAP)
        err = seL4_X64_PML4_Map_Absolute(DELEGATOR_VSPACE_CPTR,
                                         DELEGATION_CNODE_CAP,
                                         page_idx,
                                         LOOKUP_DEPTH_DELEGATION,
                                         vaddr,
                                         rights,
                                         attrs,
                                         1);
#else
#error "Unsupported syscall for trustedlo_cap_util_pd_page_map, try enable KernelX86AbsMap"
#endif
    }
#elif defined(CONFIG_ARCH_AARCH64)
    if (flags == 0) {
        err = seL4_ARM_Page_Map(page_idx, DELEGATOR_VSPACE_CPTR, vaddr, rights, attrs);
    } else {
#if defined(CONFIG_ARM_ABS_MAP)
        err = seL4_ARM_VSpace_Map_Absolute(DELEGATOR_VSPACE_CPTR,
                                           DELEGATION_CNODE_CAP,
                                           page_idx,
                                           LOOKUP_DEPTH_DELEGATION,
                                           vaddr,
                                           rights,
                                           attrs,
                                           1);
#else
#error "Unsupported syscall for trustedlo_cap_util_pd_page_map, try enable KernelArmAbsMap"
#endif
    }
#else
#error "Unsupported architecture for 'trustedlo_cap_util_pd_page_map'"
#endif
    if (err != seL4_NoError) {
        // FIXME
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to map page with id '");
        microkit_dbg_put32(page_idx);
        // microkit_dbg_puts("', in vaddr: '");
        // microkit_dbg_put64(vaddr);
        microkit_dbg_puts("'\n with rights: '");
        microkit_dbg_put32(rights.words[0]);
        microkit_dbg_puts("' and attribute: '");
        microkit_dbg_put32(attrs);
        microkit_dbg_puts("'\n");
        microkit_internal_crash(err);
    }
}

void trustedlo_cap_util_pd_page_unmap(seL4_Word page_idx, uint8_t flags)
{
    seL4_Word err;
#if defined(CONFIG_ARCH_X86_64)
    if (flags == 0)
        err = seL4_X86_Page_Unmap(page_idx);
    else {
#if defined(CONFIG_X86_ABS_MAP)
        err = seL4_X64_PML4_Unmap_Absolute(DELEGATOR_VSPACE_CPTR,
                                           DELEGATION_CNODE_CAP,
                                           page_idx,
                                           LOOKUP_DEPTH_DELEGATION,
                                           1);
#else
#error "Unsupported syscall for trustedlo_cap_util_pd_page_unmap, try enable KernelX86AbsMap"
#endif
    }
#elif defined(CONFIG_ARCH_AARCH64)
    if (flags == 0) {
        err = seL4_ARM_Page_Unmap(page_idx);
    } else {
#if defined(CONFIG_ARM_ABS_MAP)
        err = seL4_ARM_VSpace_Unmap_Absolute(DELEGATOR_VSPACE_CPTR,
                                             DELEGATION_CNODE_CAP,
                                             page_idx,
                                             LOOKUP_DEPTH_DELEGATION,
                                             1);
#else
#error "Unsupported syscall for trustedlo_cap_util_pd_page_map, try enable KernelArmAbsMap"
#endif
    }
#else
#error "Unsupported architecture for 'trustedlo_cap_util_pd_page_unmap'"
#endif
    if (err != seL4_NoError) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(__func__);
        microkit_dbg_puts(": failed to unmap page with id '");
        microkit_dbg_put32(page_idx);
        microkit_dbg_puts("'\n");
        microkit_internal_crash(err);
    }
}
