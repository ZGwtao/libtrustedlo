
#include <txloxrt.h>
#include <txlocap.h>
#include <miscutils.h>
#include <libtrustedlo.h>

bool trustedlo_xrt_util_check_mapping(seL4_Word vaddr, void *mdinfo, seL4_Word *cookie)
{
    txlo_info_t *md = (txlo_info_t *)mdinfo;
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (md->mappings[i].vaddr == vaddr) {
            *cookie = (seL4_Word)(&md->mappings[i]);
            return true;
        }
    }
    return false;
}

bool trustedlo_xrt_util_check_notification(seL4_Word ntfn, void *mdinfo)
{
    txlo_info_t *md = (txlo_info_t *)mdinfo;
    return md->bitmap_opt_notifications & (1 << ntfn);
}

bool trustedlo_xrt_util_check_ppc(seL4_Word ppc, void *mdinfo)
{
    txlo_info_t *md = (txlo_info_t *)mdinfo;
    return md->bitmap_opt_ppcs & (1 << ppc);
}

bool trustedlo_xrt_util_check_irq(seL4_Word irq, void *mdinfo)
{
    txlo_info_t *md = (txlo_info_t *)mdinfo;
    return md->bitmap_opt_irqs & (1 << irq);
}

bool trustedlo_xrt_util_check_ioport(seL4_Word ioport, void *mdinfo)
{
    txlo_info_t *md = (txlo_info_t *)mdinfo;
    return md->bitmap_opt_ioports & (1 << ioport);
}

/* once uncomment this, you will map all frames one by one */
// #undef CONFIG_BATCHING_MAP


/* Restore disallowed notification capabilities from last run */
void trustedlo_xrt_util_restore_notifications(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ntfn = 0; ntfn < MICROKIT_MAX_CHANNELS; ntfn++) {
        /*
         * If the notification id points to an allowed notification number,
         * we don't need to restore it as it stays in the CNode
         */
        if (ctxt->allowed_notifications[ntfn] == XRT_STATE_KEEP) {
            ctxt->allowed_notifications[ntfn] = XRT_STATE_USED;
            continue;
        }
        if (ctxt->allowed_notifications[ntfn] == XRT_STATE_UNSET) {
            continue;
        }
        /* the notification id given is invalid, skip it */
        if (trustedlo_xrt_util_check_notification(ntfn, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "notification '%d' to restore\n", ntfn);

        trustedlo_cap_util_restore_notification_cap(ntfn);
        ctxt->allowed_notifications[ntfn] = XRT_STATE_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore notification '%d'\n", ntfn);
    }
}

/* Restore disallowed PPC capabilities from last run */
void trustedlo_xrt_util_restore_ppcs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ppc = 0; ppc < MICROKIT_MAX_CHANNELS; ppc++) {
        /*
         * If the PPC id points to an allowed PPC number,
         * we don't need to restore it as it stays in the CNode
         */
        if (ctxt->allowed_ppcs[ppc] == XRT_STATE_KEEP) {
            ctxt->allowed_ppcs[ppc] = XRT_STATE_USED;
            continue;
        }
        if (ctxt->allowed_ppcs[ppc] == XRT_STATE_UNSET) {
            continue;
        }
        /* the PPC id given is invalid, skip it */
        if (trustedlo_xrt_util_check_ppc(ppc, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "ppc '%d' to restore\n", ppc);

        trustedlo_cap_util_restore_ppc_cap(ppc);
        ctxt->allowed_ppcs[ppc] = XRT_STATE_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore ppc '%d'\n", ppc);
    }
}

/* Restore disallowed IRQ capabilities from last run */
void trustedlo_xrt_util_restore_irqs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {
        /*
         * If the IRQ id points to an allowed interrupt number,
         * we don't need to restore it as it stays in the CNode
         */
        if (ctxt->allowed_irqs[irq] == XRT_STATE_KEEP) {
            ctxt->allowed_irqs[irq] = XRT_STATE_USED;
            continue;
        }
        if (ctxt->allowed_irqs[irq] == XRT_STATE_UNSET || !trustedlo_xrt_util_check_irq(irq, mdinfo)) {
            continue;
        }
        
        trustedlo_cap_util_restore_irq_cap(irq);

        ctxt->allowed_irqs[irq] = XRT_STATE_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore irq '%d'\n", irq);
    }
}

void trustedlo_xrt_util_restore_mappings(void *data)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    trustedlo_cap_util_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < ctxt->allowed_mappings.mapping_count; i++) {
        if (ctxt->allowed_mappings.mapping_state[i] == XRT_STATE_KEEP) {
            ctxt->allowed_mappings.mapping_state[i] = XRT_STATE_USED;
            continue;
        }
        if (ctxt->allowed_mappings.mapping_state[i] == XRT_STATE_UNSET) {
            continue;
        }
        const txlo_map_t *m = (const txlo_map_t *)(
                                    ctxt->allowed_mappings.mapping_data[i]
                               );

        seL4_CapRights_t rights = seL4_AllRights;
        // FIXME
        // rights.words[0] = mapping->rights;
#if defined(CONFIG_BATCHING_MAP)
        /* allow mapping in batches */
        trustedlo_cap_util_pd_grant_page_access(m->page, m->vaddr, rights, m->attrs, m->page_num);
#else
        for (int j = 0; j < m->page_num; ++j) {
            trustedlo_cap_util_pd_grant_page_access(m->page + j, m->vaddr + j * m->page_size, rights, m->attrs, 1);
        }
#endif /* CONFIG_BATCHING_MAP */
        ctxt->allowed_mappings.mapping_state[i] = XRT_STATE_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }

    trustedlo_cap_util_pd_revoke_vspace_access();

}


void trustedlo_xrt_util_revoke_notifications(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ntfn = 0; ntfn < MICROKIT_MAX_CHANNELS; ntfn++) {

        /* we simply ignore 'unset' as they never exist,*/
        /* and for allowed they should be created */
        /* for keep they should be ignored as well */
        if (ctxt->allowed_notifications[ntfn] != XRT_STATE_USED) {
            continue;
        }

        /* the notification id given is invalid, skip it as no need to delete it */
        if (trustedlo_xrt_util_check_notification(ntfn, mdinfo) == false) {
            continue;
        }
        trustedlo_cap_util_revoke_notification_cap(ntfn);
        ctxt->allowed_notifications[ntfn] = XRT_STATE_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke notification '%d'\n", ntfn);
    }
}

void trustedlo_xrt_util_revoke_ppcs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word ppc = 0; ppc < MICROKIT_MAX_CHANNELS; ppc++) {

        /* we simply ignore 'unset' as they never exist,*/
        /* and for allowed they should be created */
        /* for keep they should be ignored as well */
        if (ctxt->allowed_ppcs[ppc] != XRT_STATE_USED) {
            continue;
        }

        /* the ppc id given is invalid, skip it as no need to delete it */
        if (trustedlo_xrt_util_check_ppc(ppc, mdinfo) == false) {
            continue;
        }
        trustedlo_cap_util_revoke_ppc_cap(ppc);
        ctxt->allowed_ppcs[ppc] = XRT_STATE_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke ppc '%d'\n", ppc);
    }
}

void trustedlo_xrt_util_revoke_irqs(void *data, void *mdinfo)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {

        if (ctxt->allowed_irqs[irq] != XRT_STATE_USED || !trustedlo_xrt_util_check_irq(irq, mdinfo)) {
            continue;
        }
        trustedlo_cap_util_revoke_irq_cap(irq);

        ctxt->allowed_irqs[irq] = XRT_STATE_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke irq '%d'\n", irq);
    }
}

void trustedlo_xrt_util_revoke_mappings(void *data)
{
    /* initialise trusted ctxt context */
    trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;

    trustedlo_cap_util_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < ctxt->allowed_mappings.mapping_count; i++) {
        /*
         * for those mapping areas that are already mapped,
         * remove them before next run to create an empty PD
         */
        if (ctxt->allowed_mappings.mapping_state[i] != XRT_STATE_USED) {
            continue;
        }
        const txlo_map_t *m = (const txlo_map_t *)(
                                    ctxt->allowed_mappings.mapping_data[i]
                               );
#if defined(CONFIG_BATCHING_MAP)
        /* allow unmap in batch... */
        trustedlo_cap_util_pd_revoke_page_access(m->page, m->page_num);
#else
        for (int j = 0; j < m->page_num; ++j) {
            trustedlo_cap_util_pd_revoke_page_access(m->page + j, 1);
        }
#endif /* CONFIG_BATCHING_MAP */

        ctxt->allowed_mappings.mapping_state[i] = XRT_STATE_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }
    trustedlo_cap_util_pd_revoke_vspace_access();
}


void trustedlo_xrt_util_encode_rights(void *base, const void *src)
{
    xrt_entry_t *xrt_entry_list = base;
    const trustedlo_xrtreq_t *req_xrt_list = src;

    for (uint64_t i = 0; i < req_xrt_list->num_req_notifications; ++i) {
        xrt_entry_list->type = XRT_TYPE_NTFN;
        xrt_entry_list->data = req_xrt_list->notifications[i];
        xrt_entry_list++;
    }
    for (uint64_t i = 0; i < req_xrt_list->num_req_ppcs; ++i) {
        xrt_entry_list->type = XRT_TYPE_PPC;
        xrt_entry_list->data = req_xrt_list->ppcs[i];
        xrt_entry_list++;
    }
    for (uint64_t i = 0; i < req_xrt_list->num_req_irqs; ++i) {
        xrt_entry_list->type = XRT_TYPE_IRQ;
        xrt_entry_list->data = req_xrt_list->irqs[i];
        xrt_entry_list++;
    }
    for (uint64_t i = 0; i < req_xrt_list->num_req_ioports; ++i) {
        xrt_entry_list->type = XRT_TYPE_IOPORT;
        xrt_entry_list->data = req_xrt_list->ioports[i];
        xrt_entry_list++;
    }
    for (uint64_t i = 0; i < req_xrt_list->num_req_mappings; ++i) {
        xrt_entry_list->type = XRT_TYPE_MEMORY;
        xrt_entry_list->data = req_xrt_list->mappings[i];
        xrt_entry_list++;
    }
}


static inline seL4_Error
trustedlo_acrt_workerfunc(trustedlo_ctxt_t *ctxt, void *mdinfo, xrt_entry_t *xrt_entry)
{
    switch (xrt_entry->type) {
    case XRT_TYPE_NTFN: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_notification(xrt_entry->data, mdinfo));
        trustedlo_ctxt_allow__ntfn(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_PPC: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_ppc(xrt_entry->data, mdinfo));
        trustedlo_ctxt_allow__ppcs(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_IRQ: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_irq(xrt_entry->data, mdinfo));
        trustedlo_ctxt_allow__irq(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_IOPORT: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_ioport(xrt_entry->data, mdinfo));
        trustedlo_ctxt_allow__ioport(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_MEMORY: {
        seL4_Word mapping_cookie = 0;
        TSLDR_ASSERT(ctxt->allowed_mappings.mapping_count < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_mapping(xrt_entry->data, mdinfo, &mapping_cookie));
        trustedlo_ctxt_allow__mapping(ctxt, mapping_cookie);
        break;
    }
    default:
        return -1;
    }
    return seL4_NoError;
}


seL4_Error
trustedlo_xrt_util_populate_all_rights(void *context, void *mdinfo, void *xrt_req_header)
{
    trustedlo_ctxt_t *ctxt = context;
    const trustedlo_xrtreq_header_t *header = xrt_req_header;
    xrt_entry_t *xrt_entry_list = NULL;
    uint64_t xrt_entry_num;

    xrt_entry_num = header->total_num;
    xrt_entry_list = (xrt_entry_t *)(
                        (char *)(header) +
                                (header->serialised_offset)
                    );
    /* todo: check xrt region size */

    for (uint64_t i = 0;
         i < xrt_entry_num;
         i++
    ) {
        TRY_OR_RETURN_ERROR(
        trustedlo_acrt_workerfunc(
            ctxt,
            mdinfo,
            &xrt_entry_list[i]
        ));
    }
    return seL4_NoError;
}


void trustedlo_xrt_util_check_access_rights_table(void *base)
{
    const trustedlo_xrtreq_header_t *header = NULL;
    if (!base) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" trustedlo_xrt_util_check_access_rights_table: ");
        microkit_dbg_puts(" invalid pointer given\n");
        microkit_internal_crash(-1);
    }
    header = (trustedlo_xrtreq_header_t *)(base);
    TSLDR_DBG_PRINT(
        LIB_NAME_MACRO
        "number of access rights checked '%d'\n",
        header->total_num
    );
    if (header->total_num > MAX_XRT_NUM) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" trustedlo_xrt_util_check_access_rights_table: ");
        microkit_dbg_puts(" number of access rights given is too big '");
        microkit_dbg_put32(header->total_num);
        microkit_internal_crash(-1);
    }    
    if (header->serialised_offset < sizeof(trustedlo_xrtreq_header_t)) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" trustedlo_xrt_util_check_access_rights_table: ");
        microkit_dbg_puts(" invalid acrtreq entry list offset given\n");
        microkit_internal_crash(-1);
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "trustedlo_xrt_util_check_access_rights_table: succeeded\n");
}

