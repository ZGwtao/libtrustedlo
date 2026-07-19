
#include <txloxrt.h>
#include <txlocap.h>
#include <libtrustedlo.h>


void mktxlo_prepare_txlo_info(txlo_monitor_t *monitor, size_t id, void *txlo_info)
{
    if (!monitor || !txlo_info) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid txlo_info database pointer given\n");
        return;
    }
    if (id >= MAX_DYN_PD_PER_MONITOR) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid template PD child ID given: %d\n", id);
        return;
    }
    txlo_info_t *dest = (txlo_info_t *)txlo_info;
    txlo_info_t *src = &monitor->tplet_pd_txlo_info_list[id];

    tsldr_miscutil_memset(dest, 0, sizeof(txlo_info_t));
    tsldr_miscutil_memcpy(dest, src, sizeof(txlo_info_t));

    dest->init = true;

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "child_loc: %d\n", id);
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "child_id: %d\n", dest->child_id);
}


void mktxlo_privilege_template_pd(seL4_Word cid)
{
    trustedlo_cap_util_pd_privilege(cid);
}


void mktxlo_prepare_xrt_req_list(
    void *xrt_entry_list, /* dest */
    const trustedlo_xrtreq_t *xrt_req_list /* src */
) {
    /*
     * This function writes serialised access rights
     *                   into 'dest' at monitor side.
     * The trustedlo loader will then use shared memory
     *            to access 'dest' at template PD side.
     */
    trustedlo_xrt_util_encode_xrts(xrt_entry_list, xrt_req_list);
}
