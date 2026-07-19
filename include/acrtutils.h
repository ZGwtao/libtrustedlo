
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>

#define CONFIG_BATCHING_MAP (1)


uintptr_t tsldr_acrtutil_check_mapping(seL4_Word vaddr, void *mdinfo);
bool tsldr_acrtutil_check_notification(seL4_Word ntfn, void *mdinfo);
bool tsldr_acrtutil_check_ppc(seL4_Word ppc, void *mdinfo);
bool tsldr_acrtutil_check_irq(seL4_Word irq, void *mdinfo);
bool tsldr_acrtutil_check_ioport(seL4_Word ioport, void *mdinfo);

void tsldr_acrtutil_restore_notifications(void *data, void *mdinfo);
void tsldr_acrtutil_restore_ppcs(void *data, void *mdinfo);
void tsldr_acrtutil_restore_irqs(void *data, void *mdinfo);
void tsldr_acrtutil_restore_mappings(void *data);


void tsldr_acrtutil_revoke_notifications(void *data, void *mdinfo);
void tsldr_acrtutil_revoke_ppcs(void *data, void *mdinfo);
void tsldr_acrtutil_revoke_irqs(void *data, void *mdinfo);
void tsldr_acrtutil_revoke_mappings(void *data);

seL4_Error tsldr_acrtutil_populate_all_rights(void *ctxt, void *mdinfo, void *req);


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
);

void tsldr_acrtutil_check_access_rights_table(void *base);
