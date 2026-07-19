
#include <acrtutils.h>
#include <caputils.h>
#include <miscutils.h>
#include <libtrustedlo.h>

inline uintptr_t tsldr_acrtutil_check_mapping(seL4_Word vaddr, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (md->mappings[i].vaddr == vaddr) {
            return (uintptr_t)&md->mappings[i];
        }
    }
    return 0x0;
}

bool tsldr_acrtutil_check_notification(seL4_Word ntfn, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_opt_notifications & (1 << ntfn);
}

bool tsldr_acrtutil_check_ppc(seL4_Word ppc, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_opt_ppcs & (1 << ppc);
}

bool tsldr_acrtutil_check_irq(seL4_Word irq, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_opt_irqs & (1 << irq);
}

bool tsldr_acrtutil_check_ioport(seL4_Word ioport, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_opt_ioports & (1 << ioport);
}

/* once uncomment this, you will map all frames one by one */
// #undef CONFIG_BATCHING_MAP


/* Restore disallowed notification capabilities from last run */
void tsldr_acrtutil_restore_notifications(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ntfn = 0; ntfn < MICROKIT_MAX_CHANNELS; ntfn++) {
        /*
         * If the notification id points to an allowed notification number,
         * we don't need to restore it as it stays in the CNode
         */
        if (ctxt->allowed_notifications[ntfn] == ACCESS_RIGHTS_KEEP) {
            ctxt->allowed_notifications[ntfn] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (ctxt->allowed_notifications[ntfn] == ACCESS_RIGHTS_UNSET) {
            continue;
        }
        /* the notification id given is invalid, skip it */
        if (tsldr_acrtutil_check_notification(ntfn, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "notification '%d' to restore\n", ntfn);

        tsldr_caputil_restore_notification_cap(ntfn);
        ctxt->allowed_notifications[ntfn] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore notification '%d'\n", ntfn);
    }
}

/* Restore disallowed PPC capabilities from last run */
void tsldr_acrtutil_restore_ppcs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ppc = 0; ppc < MICROKIT_MAX_CHANNELS; ppc++) {
        /*
         * If the PPC id points to an allowed PPC number,
         * we don't need to restore it as it stays in the CNode
         */
        if (ctxt->allowed_ppcs[ppc] == ACCESS_RIGHTS_KEEP) {
            ctxt->allowed_ppcs[ppc] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (ctxt->allowed_ppcs[ppc] == ACCESS_RIGHTS_UNSET) {
            continue;
        }
        /* the PPC id given is invalid, skip it */
        if (tsldr_acrtutil_check_ppc(ppc, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "ppc '%d' to restore\n", ppc);

        tsldr_caputil_restore_ppc_cap(ppc);
        ctxt->allowed_ppcs[ppc] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore ppc '%d'\n", ppc);
    }
}

/* Restore disallowed IRQ capabilities from last run */
void tsldr_acrtutil_restore_irqs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {
        /*
         * If the IRQ id points to an allowed interrupt number,
         * we don't need to restore it as it stays in the CNode
         */
        if (ctxt->allowed_irqs[irq] == ACCESS_RIGHTS_KEEP) {
            ctxt->allowed_irqs[irq] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (ctxt->allowed_irqs[irq] == ACCESS_RIGHTS_UNSET || !tsldr_acrtutil_check_irq(irq, mdinfo)) {
            continue;
        }
        
        tsldr_caputil_restore_irq_cap(irq);

        ctxt->allowed_irqs[irq] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore irq '%d'\n", irq);
    }
}

void tsldr_acrtutil_restore_mappings(void *data)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    tsldr_caputil_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < ctxt->allowed_mappings.mapping_count; i++) {
        if (ctxt->allowed_mappings.mapping_state[i] == ACCESS_RIGHTS_KEEP) {
            ctxt->allowed_mappings.mapping_state[i] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (ctxt->allowed_mappings.mapping_state[i] == ACCESS_RIGHTS_UNSET) {
            continue;
        }
        tsldr_mapping_t *m = (tsldr_mapping_t *)ctxt->allowed_mappings.mapping_data[i];

        seL4_CapRights_t rights = seL4_AllRights;
        // FIXME
        // rights.words[0] = mapping->rights;
#if defined(CONFIG_BATCHING_MAP)
        /* allow mapping in batches */
        tsldr_caputil_pd_grant_page_access(m->page, m->vaddr, rights, m->attrs, m->page_num);
#else
        for (int j = 0; j < m->page_num; ++j) {
            tsldr_caputil_pd_grant_page_access(m->page + j, m->vaddr + j * m->page_size, rights, m->attrs, 1);
        }
#endif /* CONFIG_BATCHING_MAP */
        ctxt->allowed_mappings.mapping_state[i] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }

    tsldr_caputil_pd_revoke_vspace_access();

}


void tsldr_acrtutil_revoke_notifications(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ntfn = 0; ntfn < MICROKIT_MAX_CHANNELS; ntfn++) {

        /* we simply ignore 'unset' as they never exist,*/
        /* and for allowed they should be created */
        /* for keep they should be ignored as well */
        if (ctxt->allowed_notifications[ntfn] != ACCESS_RIGHTS_USED) {
            continue;
        }

        /* the notification id given is invalid, skip it as no need to delete it */
        if (tsldr_acrtutil_check_notification(ntfn, mdinfo) == false) {
            continue;
        }
        tsldr_caputil_revoke_notification_cap(ntfn);
        ctxt->allowed_notifications[ntfn] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke notification '%d'\n", ntfn);
    }
}

void tsldr_acrtutil_revoke_ppcs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ppc = 0; ppc < MICROKIT_MAX_CHANNELS; ppc++) {

        /* we simply ignore 'unset' as they never exist,*/
        /* and for allowed they should be created */
        /* for keep they should be ignored as well */
        if (ctxt->allowed_ppcs[ppc] != ACCESS_RIGHTS_USED) {
            continue;
        }

        /* the ppc id given is invalid, skip it as no need to delete it */
        if (tsldr_acrtutil_check_ppc(ppc, mdinfo) == false) {
            continue;
        }
        tsldr_caputil_revoke_ppc_cap(ppc);
        ctxt->allowed_ppcs[ppc] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke ppc '%d'\n", ppc);
    }
}

void tsldr_acrtutil_revoke_irqs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {

        if (ctxt->allowed_irqs[irq] != ACCESS_RIGHTS_USED || !tsldr_acrtutil_check_irq(irq, mdinfo)) {
            continue;
        }
        tsldr_caputil_revoke_irq_cap(irq);

        ctxt->allowed_irqs[irq] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke irq '%d'\n", irq);
    }
}

void tsldr_acrtutil_revoke_mappings(void *data)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    tsldr_caputil_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < ctxt->allowed_mappings.mapping_count; i++) {
        /*
         * for those mapping areas that are already mapped,
         * remove them before next run to create an empty PD
         */
        if (ctxt->allowed_mappings.mapping_state[i] != ACCESS_RIGHTS_USED) {
            continue;
        }
        tsldr_mapping_t *m = (tsldr_mapping_t *)ctxt->allowed_mappings.mapping_data[i];
#if defined(CONFIG_BATCHING_MAP)
        /* allow unmap in batch... */
        tsldr_caputil_pd_revoke_page_access(m->page, m->page_num);
#else
        for (int j = 0; j < m->page_num; ++j) {
            tsldr_caputil_pd_revoke_page_access(m->page + j, 1);
        }
#endif /* CONFIG_BATCHING_MAP */

        ctxt->allowed_mappings.mapping_state[i] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }
    tsldr_caputil_pd_revoke_vspace_access();
}


void tsldr_acrtutil_populate_all_rights(void *context_data, void *src_data)
{
    const tsldr_acrtreq_header_t *header = (tsldr_acrtreq_header_t *)src_data;

    if (header->total_num > MAX_ACCESS_RIGHTS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_acrtutil_populate_all_rights: ");
        microkit_dbg_puts(" number of access rights given is too big '");
        microkit_dbg_put32(header->total_num);
        microkit_dbg_puts("'\n");
        return;
    }

    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)context_data;
    const tsldr_acrt_entry_t *input_base =
                (const tsldr_acrt_entry_t *)((char *)(header) + header->serialised_offset);
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "input base: %x\n", input_base);

    tsldr_acrt_table_t *rights_table = NULL;
    tsldr_acrt_entry_t *rights_entries = NULL;
    
    rights_table = &ctxt->acrt_required_table;
    tsldr_miscutil_memset((void *)rights_table, 0, sizeof(tsldr_acrt_table_t));
    rights_table->num_entries = header->total_num;

    for (int i = 0; i < rights_table->num_entries; ++i) {
        rights_entries = &rights_table->entries[i];
        rights_entries->type = input_base->type;
        rights_entries->data = input_base->data;
        input_base += 1;
        TSLDR_DBG_PRINT(LIB_NAME_MACRO \
            "populate access rights '%d' with type '%x' and data '%x'\n",
            i, rights_entries->type, rights_entries->data);
    }
}


void
tsldr_acrtutil_encode_rights(
    void *base,
    const seL4_Word notifications[],
    const size_t n_notifications,
    const seL4_Word ppcs[],
    const size_t n_ppcs,
    const seL4_Word irqs[],
    const size_t n_irqs,
    const seL4_Word ioports[],
    const size_t n_ioports,
    const seL4_Word mappings[],
    const size_t n_mappings
)
{
    tsldr_acrt_entry_t *p = (tsldr_acrt_entry_t *)base;

    for (size_t i = 0; i < n_notifications; ++i) {
        p->type = (uint8_t)TYPE_NOTIFICATION;
        p->data = notifications[i];
        p++;
    }
    for (size_t i = 0; i < n_ppcs; ++i) {
        p->type = (uint8_t)TYPE_PPC;
        p->data = ppcs[i];
        p++;
    }
    for (size_t i = 0; i < n_irqs; ++i) {
        p->type = (uint8_t)TYPE_IRQ;
        p->data = irqs[i];
        p++;
    }
    for (size_t i = 0; i < n_ioports; ++i) {
        p->type = (uint8_t)TYPE_IOPORT;
        p->data = ioports[i];
        p++;
    }
    for (size_t i = 0; i < n_mappings; ++i) {
        p->type = (uint8_t)TYPE_MEMORY;
        p->data = mappings[i];
        p++;
    }
}


seL4_Error tsldr_acrtutil_add_rights_to_whitelist(void *data, void *input, void *mdinfo)
{
    trustedlo_ctxt_t *ctxt = data;
    tsldr_acrt_entry_t *entry = input;

    switch (entry->type) {
    case TYPE_NOTIFICATION:
        TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(tsldr_acrtutil_check_notification(entry->data, mdinfo));
        trustedlo_ctxt_allow__ntfn(ctxt, entry);
        break;
    case TYPE_PPC:
        TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(tsldr_acrtutil_check_ppc(entry->data, mdinfo));
        trustedlo_ctxt_allow__ppcs(ctxt, entry);
        break;
    case TYPE_IRQ:
        TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(tsldr_acrtutil_check_irq(entry->data, mdinfo));
        trustedlo_ctxt_allow__irq(ctxt, entry);
        break;
    case TYPE_IOPORT:
        TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(tsldr_acrtutil_check_ioport(entry->data, mdinfo));
        trustedlo_ctxt_allow__ioport(ctxt, entry);
        break;
    case TYPE_MEMORY:
        TSLDR_ASSERT(ctxt->allowed_mappings.mapping_count < MICROKIT_MAX_CHANNELS);
        uintptr_t m = tsldr_acrtutil_check_mapping(entry->data, mdinfo);
        TSLDR_ASSERT(m);
        if (ctxt->allowed_mappings.mapping_state[ctxt->allowed_mappings.mapping_count] == ACCESS_RIGHTS_USED) {
            ctxt->allowed_mappings.mapping_state[ctxt->allowed_mappings.mapping_count] = ACCESS_RIGHTS_KEEP;
        } else {
            ctxt->allowed_mappings.mapping_state[ctxt->allowed_mappings.mapping_count] = ACCESS_RIGHTS_ALLOWED;
        }
        ctxt->allowed_mappings.mapping_data[ctxt->allowed_mappings.mapping_count++] = (seL4_Word)m;
        break;
    default:
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_acrtutil_add_rights_to_whitelist: ");
        microkit_dbg_puts(" unknown access rights '");
        microkit_dbg_put32(entry->type);
        return -1;
    }
    return seL4_NoError;
}


void tsldr_acrtutil_check_access_rights_table(void *base)
{
    const tsldr_acrtreq_header_t *header = NULL;
    if (!base) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_acrtutil_check_access_rights_table: ");
        microkit_dbg_puts(" invalid pointer given\n");
        microkit_internal_crash(-1);
    }
    header = (tsldr_acrtreq_header_t *)(base);
    TSLDR_DBG_PRINT(
        LIB_NAME_MACRO
        "number of access rights checked '%d'\n",
        header->total_num
    );
    if (header->serialised_offset < sizeof(tsldr_acrtreq_header_t)) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_acrtutil_check_access_rights_table: ");
        microkit_dbg_puts(" invalid acrtreq entry list offset given\n");
        microkit_internal_crash(-1);
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "tsldr_acrtutil_check_access_rights_table: succeeded\n");
}

