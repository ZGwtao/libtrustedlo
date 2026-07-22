
#include <txloxrt.h>
#include <txlocap.h>
#include <libtrustedlo.h>


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
