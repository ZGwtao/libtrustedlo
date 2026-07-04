
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>

#define CONFIG_BATCHING_MAP (1)


uintptr_t tsldr_acrtutil_check_mapping(seL4_Word vaddr, void *mdinfo);
uint8_t tsldr_acrtutil_check_notification(seL4_Word ntfn, void *mdinfo);
uint8_t tsldr_acrtutil_check_ppc(seL4_Word ppc, void *mdinfo);
uint8_t tsldr_acrtutil_check_irq(seL4_Word irq, void *mdinfo);


void tsldr_acrtutil_restore_notifications(void *data, void *mdinfo);
void tsldr_acrtutil_restore_ppcs(void *data, void *mdinfo);
void tsldr_acrtutil_restore_irqs(void *data, void *mdinfo);
void tsldr_acrtutil_restore_mappings(void *data);


void tsldr_acrtutil_revoke_notifications(void *data, void *mdinfo);
void tsldr_acrtutil_revoke_ppcs(void *data, void *mdinfo);
void tsldr_acrtutil_revoke_irqs(void *data, void *mdinfo);
void tsldr_acrtutil_revoke_mappings(void *data);



void tsldr_acrtutil_add_rights_to_whitelist(void *data, void *input, void *mdinfo);
void tsldr_acrtutil_populate_all_rights(void *context_data, void *src_data, seL4_Word num);


void tsldr_acrtutil_encode_rights(void *base,
    seL4_Word notifications[], size_t n_notifications, seL4_Word ppcs[], size_t n_ppcs,
    seL4_Word irqs[], size_t n_irqs, seL4_Word ioports[], size_t n_ioports,
    seL4_Word mappings[], size_t n_mappings
);


seL4_Word tsldr_acrtutil_check_access_rights_table(void *base);
