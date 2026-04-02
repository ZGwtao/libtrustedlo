
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

inline uint8_t tsldr_acrtutil_check_channel(seL4_Word channel, uint8_t *cstate, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    if (cstate != NULL) {
        *cstate = md->cstate[channel];
    }
    return md->channels[channel];
}

inline uint8_t tsldr_acrtutil_check_irq(seL4_Word irq, void *mdinfo)
{
    tsldr_mdinfo_t *md = (tsldr_mdinfo_t *)mdinfo;
    return md->irqs[irq];
}

/* once uncomment this, you will map all frames one by one */
// #undef CONFIG_BATCHING_MAP


/* Restore disallowed channel capabilities from last run */
void tsldr_acrtutil_restore_channels(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word channel = 0; channel < MICROKIT_MAX_CHANNELS; channel++) {
        /*
         * If the channel id points to an allowed channel,
         * we don't need to restore it as it stays in the CNode
         */
        if (loader->allowed_channels[channel] == false) {
            continue;
        }
        /* try to record channel state: pp or notification */
        uint8_t is_ppc = 0;

        /* the channel id given is invalid, skip it */
        if (tsldr_acrtutil_check_channel(channel, &is_ppc, mdinfo) == false) {
            continue;
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "channel '%d' to restore\n", channel);
        if (is_ppc)
            tsldr_caputil_restore_ppc_cap(channel);
        else
            tsldr_caputil_restore_notification_cap(channel);
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore channel '%d'\n", channel);
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
        if (loader->allowed_irqs[irq] == false || !tsldr_acrtutil_check_irq(irq, mdinfo)) {
            continue;
        }
        
        tsldr_caputil_restore_irq_cap(irq);
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore irq '%d'\n", irq);
    }
}

void tsldr_acrtutil_restore_mappings(void *data)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    tsldr_caputil_pd_grant_vspace_access();

    for (seL4_Word i = 0; i < loader->mp_cnt; i++) {
        tsldr_mapping_t *m = (tsldr_mapping_t *)loader->allowed_mappings[i];

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
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "restore mapping '%d' at vaddr '%x'\n", m->page, m->vaddr);
    }

    tsldr_caputil_pd_revoke_vspace_access();

}


void tsldr_acrtutil_revoke_channels(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word channel = 0; channel < MICROKIT_MAX_CHANNELS; channel++) {

        /*  If the channel is allowed, keep it */
        if (loader->allowed_channels[channel] == false) {
            continue;
        }

        /* try to record channel state: pp or notification */
        uint8_t is_ppc = 0;

        /* the channel id given is invalid, skip it as no need to delete it */
        if (tsldr_acrtutil_check_channel(channel, &is_ppc, mdinfo) == false) {
            continue;
        }
        if (is_ppc) {
            tsldr_caputil_revoke_ppc_cap(channel);
        } else {
            tsldr_caputil_revoke_notification_cap(channel);
        }
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "revoke channel '%d'\n", channel);
    }
}

void tsldr_acrtutil_revoke_irqs(void *data, void *mdinfo)
{
    /* initialise trusted loader context */
    tsldr_context_t *loader = (tsldr_context_t *)data;

    for (seL4_Word irq = 0; irq < MICROKIT_MAX_CHANNELS; irq++) {

        if (loader->allowed_irqs[irq] == false || !tsldr_acrtutil_check_irq(irq, mdinfo)) {
            continue;
        }
        tsldr_caputil_revoke_irq_cap(irq);
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
        tsldr_mapping_t *m = (tsldr_mapping_t *)loader->allowed_mappings[i];
#if defined(CONFIG_BATCHING_MAP)
        /* allow unmap in batch... */
        tsldr_caputil_pd_revoke_page_access(m->page, m->page_num);
#else
        for (int j = 0; j < m->page_num; ++j) {
            tsldr_caputil_pd_revoke_page_access(m->page + j, 1);
        }
#endif /* CONFIG_BATCHING_MAP */
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


void tsldr_acrtutil_encode_rights(void *base, seL4_Word channels[], size_t n_channels, seL4_Word irqs[], size_t n_irqs, seL4_Word mappings[], size_t n_mps)
{
    tsldr_acrt_entry_t *p = (tsldr_acrt_entry_t *)base;
    for (size_t i = 0; i < n_channels; ++i) {
        p->type = (uint8_t)TYPE_CHANNEL;
        p->data = channels[i];
        p++;
    }
    for (size_t i = 0; i < n_irqs; ++i) {
        p->type = (uint8_t)TYPE_IRQ;
        p->data = irqs[i];
        p++;
    }
    for (size_t i = 0; i < n_mps; ++i) {
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
        case TYPE_CHANNEL:
            TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
            TSLDR_ASSERT(tsldr_acrtutil_check_channel(entry->data, NULL, mdinfo));
            loader->allowed_channels[entry->data] = true;
            break;

        case TYPE_IRQ:
            TSLDR_ASSERT(entry->data < MICROKIT_MAX_CHANNELS);
            TSLDR_ASSERT(tsldr_acrtutil_check_irq(entry->data, mdinfo));
            loader->allowed_irqs[entry->data] = true;
            break;

        case TYPE_MEMORY:
            TSLDR_ASSERT(loader->mp_cnt < MICROKIT_MAX_CHANNELS);
            uintptr_t m = tsldr_acrtutil_check_mapping(entry->data, mdinfo);
            TSLDR_ASSERT(m);
            loader->allowed_mappings[loader->mp_cnt++] = (seL4_Word)m;
            break;

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

