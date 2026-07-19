
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>

#define CONFIG_BATCHING_MAP (1)


bool trustedlo_xrt_util_check_mapping(seL4_Word vaddr, void *txlo_info, seL4_Word *cookie);
bool trustedlo_xrt_util_check_notification(seL4_Word ntfn, void *txlo_info);
bool trustedlo_xrt_util_check_ppc(seL4_Word ppc, void *txlo_info);
bool trustedlo_xrt_util_check_irq(seL4_Word irq, void *txlo_info);
bool trustedlo_xrt_util_check_ioport(seL4_Word ioport, void *txlo_info);

void trustedlo_xrt_util_restore_notifications(void *data, void *txlo_info);
void trustedlo_xrt_util_restore_ppcs(void *data, void *txlo_info);
void trustedlo_xrt_util_restore_irqs(void *data, void *txlo_info);
void trustedlo_xrt_util_restore_mappings(void *data);


void trustedlo_xrt_util_revoke_notifications(void *data, void *txlo_info);
void trustedlo_xrt_util_revoke_ppcs(void *data, void *txlo_info);
void trustedlo_xrt_util_revoke_irqs(void *data, void *txlo_info);
void trustedlo_xrt_util_revoke_mappings(void *data);

void trustedlo_xrt_util_encode_xrts(void *base, const void *src);

seL4_Error trustedlo_xrt_util_parse_xrt_header(void *xrt_req_header);
seL4_Error trustedlo_xrt_util_populate_xrts(void *ctxt, void *txlo_info, void *req);
