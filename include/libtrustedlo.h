#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>
#include <miscutils.h>
#include <trampoline.h>


#define MAX_DYN_PD_PER_MONITOR (16)

typedef struct {
    seL4_Word vaddr;
    seL4_Word page;
    seL4_Word page_num;
    seL4_Word page_size;
    seL4_Word rights;
    seL4_Word attrs;
} microkit_trustedlo_mapping_t;
typedef microkit_trustedlo_mapping_t txlo_map_t;

typedef struct {
    size_t      child_id;

    seL4_Word   bitmap_opt_notifications;
    seL4_Word   bitmap_opt_ppcs;
    seL4_Word   bitmap_opt_irqs;
    seL4_Word   bitmap_opt_ioports;

    seL4_Word   microkit_notifications;
    seL4_Word   microkit_pps;
    seL4_Word   microkit_irqs;
    seL4_Word   microkit_ioports;

    txlo_map_t mappings[MICROKIT_MAX_CHANNELS];

    bool init;

} microkit_trustedlo_info_t;
typedef microkit_trustedlo_info_t txlo_info_t;

typedef struct {
    uint8_t avails;
    txlo_info_t infodb[MAX_DYN_PD_PER_MONITOR];
} microkit_trustedlo_monitor_t;
typedef microkit_trustedlo_monitor_t txlo_monitor_t;


typedef struct {
    uint64_t num_req_notifications;
    uint64_t num_req_ppcs;
    uint64_t num_req_irqs;
    uint64_t num_req_ioports;
    uint64_t num_req_mappings;
    seL4_Word notifications[MICROKIT_MAX_CHANNELS];
    seL4_Word ppcs[MICROKIT_MAX_CHANNELS];
    seL4_Word irqs[MICROKIT_MAX_CHANNELS];
    seL4_Word ioports[MICROKIT_MAX_CHANNELS];
    seL4_Word mappings[MICROKIT_MAX_CHANNELS];
} trustedlo_xrtreq_t;


typedef struct {
    uint64_t total_num;
    uint64_t serialised_offset;
} trustedlo_xrtreq_header_t;


typedef uint8_t xrt_state_t;
enum {
    XRT_STATE_UNSET = 0,
    XRT_STATE_ALLOWED = 1,
    XRT_STATE_USED = 2,
    XRT_STATE_KEEP = 3,
};

typedef uint8_t xrt_type_t;
enum {
    XRT_TYPE_NTFN     = 0x01,
    XRT_TYPE_PPC      = 0x02,
    XRT_TYPE_IRQ      = 0x03,
    XRT_TYPE_IOPORT   = 0x04,
    XRT_TYPE_MEMORY   = 0x05,
};

#define MAX_XRT_NUM (62 * 3)

typedef struct xrt_entry {
    xrt_type_t type;
    uint8_t _padding[7];
    /* channel id or base vaddr for memory */
    seL4_Word data;
} xrt_entry_t;

typedef struct trustedlo_ctxt {
    size_t child_id;

    bool restore;
    bool init;

    xrt_state_t allowed_notifications[MICROKIT_MAX_CHANNELS];
    xrt_state_t allowed_ppcs[MICROKIT_MAX_CHANNELS];
    xrt_state_t allowed_irqs[MICROKIT_MAX_CHANNELS];
    xrt_state_t allowed_ioports[MICROKIT_MAX_CHANNELS];

    struct {
        uint64_t mapping_count;
        seL4_Word mapping_data[MICROKIT_MAX_CHANNELS];
        xrt_state_t mapping_state[MICROKIT_MAX_CHANNELS];
    } allowed_mappings;

} trustedlo_ctxt_t;
_Static_assert(sizeof(trustedlo_ctxt_t) <= 0x1000, "unexpected trustedlo_ctxt_t size");

#define CONTEXT_ACCESSOR_LIST(X)                  \
    X(ntfn,   allowed_notifications)              \
    X(ppcs,   allowed_ppcs)                       \
    X(irq,    allowed_irqs)                       \
    X(ioport, allowed_ioports)

#define DEFINE_CONTEXT_ACCESSORS(name, field)                         \
    static inline void                                                \
    trustedlo_ctxt_set__##name(                                       \
        trustedlo_ctxt_t *ctxt,                                       \
        const xrt_entry_t *entry,                                     \
        xrt_state_t state)                                            \
    {                                                                 \
        ctxt->field[entry->data] = state;                             \
    }                                                                 \
                                                                      \
    static inline bool                                                \
    trustedlo_ctxt_check__##name(                                     \
        const trustedlo_ctxt_t *ctxt,                                 \
        const xrt_entry_t *entry,                                     \
        xrt_state_t state)                                            \
    {                                                                 \
        return ctxt->field[entry->data] == state;                     \
    }                                                                 \
                                                                      \
    static inline void                                                \
    trustedlo_ctxt_allow__##name(                                     \
        trustedlo_ctxt_t *ctxt,                                       \
        const xrt_entry_t *entry)                                     \
    {                                                                 \
        xrt_state_t next_state = XRT_STATE_ALLOWED;                   \
                                                                      \
        if (trustedlo_ctxt_check__##name(                             \
                ctxt, entry, XRT_STATE_USED)) {                       \
            next_state = XRT_STATE_KEEP;                              \
        }                                                             \
                                                                      \
        trustedlo_ctxt_set__##name(ctxt, entry, next_state);          \
    }

CONTEXT_ACCESSOR_LIST(DEFINE_CONTEXT_ACCESSORS)

#undef DEFINE_CONTEXT_ACCESSORS

static inline void
trustedlo_ctxt_allow__mapping(
    trustedlo_ctxt_t *ctxt,
    seL4_Word mapping_cookie)
{
    uint64_t index = ctxt->allowed_mappings.mapping_count;
    xrt_state_t next_state = XRT_STATE_ALLOWED;
    if (ctxt->allowed_mappings.mapping_state[index] == XRT_STATE_USED) {
        next_state = XRT_STATE_KEEP;
    }
    ctxt->allowed_mappings.mapping_state[index] = next_state;
    ctxt->allowed_mappings.mapping_data[index] = mapping_cookie;
    ctxt->allowed_mappings.mapping_count = index + 1;
}


typedef void (*entry_fn_t)(const trampoline_args_t *);



#define TRY_OR_RETURN_VOID(expr)            \
    do {                                    \
        seL4_Error _err = (expr);           \
        if (_err != seL4_NoError) {         \
            return;                         \
        }                                   \
    } while (0)

#define TRY_OR_RETURN_ERROR(expr)           \
    do {                                    \
        seL4_Error _err = (expr);           \
        if (_err != seL4_NoError) {         \
            return _err;                    \
        }                                   \
    } while (0)

#define TSLDR_ASSERT(cond)                     \
    do {                                       \
        if (!(cond)) {                         \
            microkit_internal_crash(-1);       \
        }                                      \
    } while (0)


void mktxlo_self_load_entry(void);

void mktxlo_prepare_txlo_info(txlo_monitor_t *db, size_t id, void *mdinfo);
void mktxlo_prepare_xrt_req_list(void *base, const trustedlo_xrtreq_t *req);
void mktxlo_privilege_template_pd(seL4_Word cid);
