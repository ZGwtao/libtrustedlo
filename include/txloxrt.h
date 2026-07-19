
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>

#define CONFIG_BATCHING_MAP (1)


bool trustedlo_xrt_util_check_mapping(seL4_Word vaddr, void *mdinfo, seL4_Word *cookie);
bool trustedlo_xrt_util_check_notification(seL4_Word ntfn, void *mdinfo);
bool trustedlo_xrt_util_check_ppc(seL4_Word ppc, void *mdinfo);
bool trustedlo_xrt_util_check_irq(seL4_Word irq, void *mdinfo);
bool trustedlo_xrt_util_check_ioport(seL4_Word ioport, void *mdinfo);

void trustedlo_xrt_util_restore_notifications(void *data, void *mdinfo);
void trustedlo_xrt_util_restore_ppcs(void *data, void *mdinfo);
void trustedlo_xrt_util_restore_irqs(void *data, void *mdinfo);
void trustedlo_xrt_util_restore_mappings(void *data);


void trustedlo_xrt_util_revoke_notifications(void *data, void *mdinfo);
void trustedlo_xrt_util_revoke_ppcs(void *data, void *mdinfo);
void trustedlo_xrt_util_revoke_irqs(void *data, void *mdinfo);
void trustedlo_xrt_util_revoke_mappings(void *data);

seL4_Error trustedlo_xrt_util_populate_all_rights(void *ctxt, void *mdinfo, void *req);


void trustedlo_xrt_util_encode_rights(void *base, const void *src);
void trustedlo_xrt_util_check_access_rights_table(void *base);
