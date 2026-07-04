
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
    return md->bitmap_notifications & (1 << ntfn);
}

bool tsldr_acrtutil_check_ppc(seL4_Word ppc, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_ppcs & (1 << ppc);
}

bool tsldr_acrtutil_check_irq(seL4_Word irq, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_irqs & (1 << irq);
}

bool tsldr_acrtutil_check_ioport(seL4_Word ioport, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->bitmap_ioports & (1 << ioport);
}

/* once uncomment this, you will map all frames one by one */
// #undef CONFIG_BATCHING_MAP


/* Restore disallowed notification capabilities from last run */
void tsldr_acrtutil_restore_notifications(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word ntfn = 0; ntfn < MICROKIT_MAX_CHANNELS; ntfn++) {
        /*
         * If the notification id points to an allowed notification number,
         * we don't need to restore it as it stays in the CNode
         */
        if (loader->allowed_notifications[ntfn] == ACCESS_RIGHTS_KEEP) {
            loader->allowed_notifications[ntfn] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (loader->allowed_notifications[ntfn] == ACCESS_RIGHTS_UNSET) {
            continue;
        }
        /* the notification id given is invalid, skip it */
        if (tsldr_acrtutil_check_notification(ntfn, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "notification '%d' to restore\n", ntfn);

        tsldr_caputil_restore_notification_cap(ntfn);
        loader->allowed_notifications[ntfn] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore notification '%d'\n", ntfn);
    }
}

/* Restore disallowed PPC capabilities from last run */
void tsldr_acrtutil_restore_ppcs(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word ppc = 0; ppc < MICROKIT_MAX_CHANNELS; ppc++) {
        /*
         * If the PPC id points to an allowed PPC number,
         * we don't need to restore it as it stays in the CNode
         */
        if (loader->allowed_ppcs[ppc] == ACCESS_RIGHTS_KEEP) {
            loader->allowed_ppcs[ppc] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (loader->allowed_ppcs[ppc] == ACCESS_RIGHTS_UNSET) {
            continue;
        }
        /* the PPC id given is invalid, skip it */
        if (tsldr_acrtutil_check_ppc(ppc, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "ppc '%d' to restore\n", ppc);

        tsldr_caputil_restore_ppc_cap(ppc);
        loader->allowed_ppcs[ppc] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore ppc '%d'\n", ppc);
    }
}

/* Restore disallowed IRQ capabilities from last run */
void tsldr_acrtutil_restore_irqs(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {
        /*
         * If the IRQ id points to an allowed interrupt number,
         * we don't need to restore it as it stays in the CNode
         */
        if (loader->allowed_irqs[irq] == ACCESS_RIGHTS_KEEP) {
            loader->allowed_irqs[irq] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (loader->allowed_irqs[irq] == ACCESS_RIGHTS_UNSET || !tsldr_acrtutil_check_irq(irq, mdinfo)) {
            continue;
        }
        
        tsldr_caputil_restore_irq_cap(irq);

        loader->allowed_irqs[irq] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore irq '%d'\n", irq);
    }
}

void tsldr_acrtutil_restore_mappings(void *data)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    tsldr_caputil_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < loader->mp_cnt; i++) {
        if (loader->allowed_mappings[i] == ACCESS_RIGHTS_KEEP) {
            loader->allowed_mappings[i] = ACCESS_RIGHTS_USED;
            continue;
        }
        if (loader->allowed_mappings[i] == ACCESS_RIGHTS_UNSET) {
            continue;
        }
        tsldr_mapping_t *m = (tsldr_mapping_t *)loader->mapping_data[i];

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
        loader->allowed_mappings[i] = ACCESS_RIGHTS_USED;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }

    tsldr_caputil_pd_revoke_vspace_access();

}


void tsldr_acrtutil_revoke_notifications(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word ntfn = 0; ntfn < MICROKIT_MAX_CHANNELS; ntfn++) {

        /* we simply ignore 'unset' as they never exist,*/
        /* and for allowed they should be created */
        /* for keep they should be ignored as well */
        if (loader->allowed_notifications[ntfn] != ACCESS_RIGHTS_USED) {
            continue;
        }

        /* the notification id given is invalid, skip it as no need to delete it */
        if (tsldr_acrtutil_check_notification(ntfn, mdinfo) == false) {
            continue;
        }
        tsldr_caputil_revoke_notification_cap(ntfn);
        loader->allowed_notifications[ntfn] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke notification '%d'\n", ntfn);
    }
}

void tsldr_acrtutil_revoke_ppcs(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word ppc = 0; ppc < MICROKIT_MAX_CHANNELS; ppc++) {

        /* we simply ignore 'unset' as they never exist,*/
        /* and for allowed they should be created */
        /* for keep they should be ignored as well */
        if (loader->allowed_ppcs[ppc] != ACCESS_RIGHTS_USED) {
            continue;
        }

        /* the ppc id given is invalid, skip it as no need to delete it */
        if (tsldr_acrtutil_check_ppc(ppc, mdinfo) == false) {
            continue;
        }
        tsldr_caputil_revoke_ppc_cap(ppc);
        loader->allowed_ppcs[ppc] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke ppc '%d'\n", ppc);
    }
}

void tsldr_acrtutil_revoke_irqs(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {

        if (loader->allowed_irqs[irq] != ACCESS_RIGHTS_USED || !tsldr_acrtutil_check_irq(irq, mdinfo)) {
            continue;
        }
        tsldr_caputil_revoke_irq_cap(irq);

        loader->allowed_irqs[irq] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke irq '%d'\n", irq);
    }
}

void tsldr_acrtutil_revoke_mappings(void *data)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    tsldr_caputil_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < loader->mp_cnt; i++) {
        /*
         * for those mapping areas that are already mapped,
         * remove them before next run to create an empty PD
         */
        if (loader->allowed_mappings[i] != ACCESS_RIGHTS_USED) {
            continue;
        }
        tsldr_mapping_t *m = (tsldr_mapping_t *)loader->mapping_data[i];
#if defined(CONFIG_BATCHING_MAP)
        /* allow unmap in batch... */
        tsldr_caputil_pd_revoke_page_access(m->page, m->page_num);
#else
        for (int j = 0; j < m->page_num; ++j) {
            tsldr_caputil_pd_revoke_page_access(m->page + j, 1);
        }
#endif /* CONFIG_BATCHING_MAP */

        loader->allowed_mappings[i] = ACCESS_RIGHTS_UNSET;

        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }
    tsldr_caputil_pd_revoke_vspace_access();
}


void tsldr_acrtutil_populate_all_rights(void *context_data, void *src_data, seL4_Word num)
{
    if (num > MAX_ACCESS_RIGHTS) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_acrtutil_populate_all_rights: ");
        microkit_dbg_puts(" number of access rights given is too big '");
        microkit_dbg_put32(num);
        microkit_dbg_puts("'\n");
        return;
    }

    tsldr_context_t *loader = (tsldr_context_t *)context_data;
    tsldr_acrt_entry_t *input_base = (tsldr_acrt_entry_t *)(src_data);

    tsldr_acrt_table_t *rights_table = NULL;
    tsldr_acrt_entry_t *rights_entries = NULL;
    
    rights_table = &loader->acrt_required_table;
    tsldr_miscutil_memset((void *)rights_table, 0, sizeof(tsldr_acrt_table_t));
    rights_table->num_entries = num;

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


void tsldr_acrtutil_encode_rights(void *base,
    seL4_Word notifications[], size_t n_notifications, seL4_Word ppcs[], size_t n_ppcs,
    seL4_Word irqs[], size_t n_irqs, seL4_Word ioports[], size_t n_ioports,
    seL4_Word mappings[], size_t n_mappings
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


void tsldr_acrtutil_add_rights_to_whitelist(void *data, void *input, void *mdinfo)
{
    tsldr_context_t *loader = (tsldr_context_t *)data;
    tsldr_acrt_entry_t *entry = (tsldr_acrt_entry_t *)input;

    switch (entry->type) {
        case TYPE_NOTIFICATION:
        {
            TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
            TSLDR_ASSERT(tsldr_acrtutil_check_notification(entry->data, mdinfo));
            if (loader->allowed_notifications[entry->data] == ACCESS_RIGHTS_USED) {
                loader->allowed_notifications[entry->data] = ACCESS_RIGHTS_KEEP;
            } else {
                loader->allowed_notifications[entry->data] = ACCESS_RIGHTS_ALLOWED;
            }
            break;
        }
        case TYPE_PPC:
        {
            TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
            TSLDR_ASSERT(tsldr_acrtutil_check_ppc(entry->data, mdinfo));
            if (loader->allowed_ppcs[entry->data] == ACCESS_RIGHTS_USED) {
                loader->allowed_ppcs[entry->data] = ACCESS_RIGHTS_KEEP;
            } else {
                loader->allowed_ppcs[entry->data] = ACCESS_RIGHTS_ALLOWED;
            }
            break;
        }
        case TYPE_IRQ:
            TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
            TSLDR_ASSERT(tsldr_acrtutil_check_irq(entry->data, mdinfo));
            if (loader->allowed_irqs[entry->data] == ACCESS_RIGHTS_USED) {
                loader->allowed_irqs[entry->data] = ACCESS_RIGHTS_KEEP;
            } else {
                loader->allowed_irqs[entry->data] = ACCESS_RIGHTS_ALLOWED;
            }
            break;

        case TYPE_MEMORY:
            TSLDR_ASSERT(loader->mp_cnt < MICROKIT_MAX_CHANNELS);
            uintptr_t m = tsldr_acrtutil_check_mapping(entry->data, mdinfo);
            TSLDR_ASSERT(m);
            if (loader->allowed_mappings[loader->mp_cnt] == ACCESS_RIGHTS_USED) {
                loader->allowed_mappings[loader->mp_cnt] = ACCESS_RIGHTS_KEEP;
            } else {
                loader->allowed_mappings[loader->mp_cnt] = ACCESS_RIGHTS_ALLOWED;
            }
            loader->mapping_data[loader->mp_cnt++] = (seL4_Word)m;
            break;
        case TYPE_IOPORT:
            // TODO: implement this when we support x86 ioports
        default:
            microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
            microkit_dbg_puts(" tsldr_acrtutil_add_rights_to_whitelist: ");
            microkit_dbg_puts(" unknown access rights '");
            microkit_dbg_put32(entry->type);
            microkit_internal_crash(-1);
    }
}


seL4_Word tsldr_acrtutil_check_access_rights_table(void *base)
{
    if (!base) {
        microkit_dbg_puts(TSLDR_ERR_PRINT_MACRO);
        microkit_dbg_puts(" tsldr_acrtutil_check_access_rights_table: ");
        microkit_dbg_puts(" invalid pointer given\n");
        microkit_internal_crash(-1);
    }

    size_t *p = (size_t *)base;
    seL4_Word acrt_num = *p;

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "number of access rights checked '%d'\n", acrt_num);
    return acrt_num;
}

