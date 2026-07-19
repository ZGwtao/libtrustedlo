
#include <txloxrt.h>
#include <txlocap.h>
#include <miscutils.h>
#include <libtrustedlo.h>

/* once uncomment this, you will map all frames one by one */
// #undef CONFIG_BATCHING_MAP


bool trustedlo_xrt_util_check_mapping(seL4_Word vaddr, void *txlo_info, seL4_Word *cookie)
{
    txlo_info_t *md = (txlo_info_t *)txlo_info;
    for (int i = 0; i < MICROKIT_MAX_CHANNELS; i++) {
        if (md->mappings[i].vaddr == vaddr) {
            *cookie = (seL4_Word)(&md->mappings[i]);
            return true;
        }
    }
    return false;
}

bool trustedlo_xrt_util_check_notification(seL4_Word ntfn, void *txlo_info)
{
    txlo_info_t *md = (txlo_info_t *)txlo_info;
    return md->bitmap_opt_notifications & (1 << ntfn);
}

bool trustedlo_xrt_util_check_ppc(seL4_Word ppc, void *txlo_info)
{
    txlo_info_t *md = (txlo_info_t *)txlo_info;
    return md->bitmap_opt_ppcs & (1 << ppc);
}

bool trustedlo_xrt_util_check_irq(seL4_Word irq, void *txlo_info)
{
    txlo_info_t *md = (txlo_info_t *)txlo_info;
    return md->bitmap_opt_irqs & (1 << irq);
}

bool trustedlo_xrt_util_check_ioport(seL4_Word ioport, void *txlo_info)
{
    txlo_info_t *md = (txlo_info_t *)txlo_info;
    return md->bitmap_opt_ioports & (1 << ioport);
}


#define XRT_REVOKE(                                                       \
    plural, singular, field, check_fn, revoke_fn, restore_fn)             \
    void                                                                  \
    trustedlo_xrt_util_revoke_##plural(                                   \
        void *data,                                                       \
        void *txlo_info)                                                  \
    {                                                                     \
        trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;                \
        for (seL4_Word id = 0;                                            \
             id < MICROKIT_MAX_CHANNELS;                                  \
             id++) {                                                      \
            if (ctxt->field[id] != XRT_STATE_USED) {                      \
                continue;                                                 \
            }                                                             \
            if (!check_fn(id, txlo_info)) {                               \
                continue;                                                 \
            }                                                             \
            revoke_fn(id);                                                \
            ctxt->field[id] = XRT_STATE_UNSET;                            \
        }                                                                 \
    }

#define XRT_RESTORE(                                                      \
    plural, singular, field, check_fn, revoke_fn, restore_fn)             \
    void                                                                  \
    trustedlo_xrt_util_restore_##plural(                                  \
        void *data,                                                       \
        void *txlo_info)                                                  \
    {                                                                     \
        trustedlo_ctxt_t *ctxt = (trustedlo_ctxt_t *)data;                \
        for (seL4_Word id = 0;                                            \
             id < MICROKIT_MAX_CHANNELS;                                  \
             id++) {                                                      \
            xrt_state_t *state = &ctxt->field[id];                        \
            if (*state == XRT_STATE_KEEP) {                               \
                *state = XRT_STATE_USED;                                  \
                continue;                                                 \
            }                                                             \
            if (*state == XRT_STATE_UNSET) {                              \
                continue;                                                 \
            }                                                             \
            if (!check_fn(id, txlo_info)) {                               \
                continue;                                                 \
            }                                                             \
            restore_fn(id);                                               \
            *state = XRT_STATE_USED;                                      \
        }                                                                 \
    }

#define XRTS_DEF(X)                                                       \
    X(notifications, notification, allowed_notifications,                 \
      trustedlo_xrt_util_check_notification,                              \
      trustedlo_cap_util_revoke_notification_cap,                         \
      trustedlo_cap_util_restore_notification_cap)                        \
                                                                          \
    X(ppcs, ppc, allowed_ppcs,                                            \
      trustedlo_xrt_util_check_ppc,                                       \
      trustedlo_cap_util_revoke_ppc_cap,                                  \
      trustedlo_cap_util_restore_ppc_cap)                                 \
                                                                          \
    X(irqs, irq, allowed_irqs,                                            \
      trustedlo_xrt_util_check_irq,                                       \
      trustedlo_cap_util_revoke_irq_cap,                                  \
      trustedlo_cap_util_restore_irq_cap)

XRTS_DEF(XRT_REVOKE)
XRTS_DEF(XRT_RESTORE)



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


void trustedlo_xrt_util_encode_xrts(void *base, const void *src)
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
trustedlo_acrt_workerfunc(trustedlo_ctxt_t *ctxt, void *txlo_info, xrt_entry_t *xrt_entry)
{
    switch (xrt_entry->type) {
    case XRT_TYPE_NTFN: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_notification(xrt_entry->data, txlo_info));
        trustedlo_ctxt_allow__ntfn(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_PPC: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_ppc(xrt_entry->data, txlo_info));
        trustedlo_ctxt_allow__ppcs(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_IRQ: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_irq(xrt_entry->data, txlo_info));
        trustedlo_ctxt_allow__irq(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_IOPORT: {
        TSLDR_ASSERT(xrt_entry->data < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_ioport(xrt_entry->data, txlo_info));
        trustedlo_ctxt_allow__ioport(ctxt, xrt_entry);
        break;
    }
    case XRT_TYPE_MEMORY: {
        seL4_Word mapping_cookie = 0;
        TSLDR_ASSERT(ctxt->allowed_mappings.mapping_count < MICROKIT_MAX_CHANNELS);
        TSLDR_ASSERT(trustedlo_xrt_util_check_mapping(xrt_entry->data, txlo_info, &mapping_cookie));
        trustedlo_ctxt_allow__mapping(ctxt, mapping_cookie);
        break;
    }
    default:
        return -1;
    }
    return seL4_NoError;
}


seL4_Error
trustedlo_xrt_util_populate_xrts(void *context, void *txlo_info, void *xrt_req_header)
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
            txlo_info,
            &xrt_entry_list[i]
        ));
    }
    return seL4_NoError;
}


seL4_Error trustedlo_xrt_util_parse_xrt_header(void *xrt_req_header)
{
    const trustedlo_xrtreq_header_t *header = xrt_req_header;
    if (!header) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" trustedlo_xrt_util_parse_xrt_header: ");
        microkit_dbg_puts(" invalid pointer given\n");
        return -1;
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO
        "number of xrts checked '%d'\n",
        header->total_num
    );
    if (header->total_num > MAX_XRT_NUM) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" trustedlo_xrt_util_parse_xrt_header: ");
        microkit_dbg_puts(" number of xrts given is too big '");
        microkit_dbg_put32(header->total_num);
        return -1;
    }    
    if (header->serialised_offset < sizeof(trustedlo_xrtreq_header_t)) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" trustedlo_xrt_util_parse_xrt_header: ");
        microkit_dbg_puts(" invalid xrt entry list offset given\n");
        return -1;
    }
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "trustedlo_xrt_util_parse_xrt_header: succeeded\n");
    return seL4_NoError;
}

