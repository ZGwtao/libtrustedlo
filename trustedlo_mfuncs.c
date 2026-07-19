
#include <acrtutils.h>
#include <caputils.h>
#include <libtrustedlo.h>


void tsldr_main_monitor_init_mdinfo(tsldr_mdinfodb_t *db, size_t id, void *mdinfo)
{
    if (!db || !mdinfo) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid mdinfo database pointer given\n");
        return;
    }
    if (id >= 16 || id < 0) {
        TSLDR_DBG_PRINT(LIB_NAME_MACRO "Invalid template PD child ID given: %d\n", id);
        return;
    }
    tsldr_mdinfo_t *dest = (tsldr_mdinfo_t *)mdinfo;
    tsldr_mdinfo_t *src = &db->infodb[id];

    tsldr_miscutil_memset(dest, 0, sizeof(tsldr_mdinfo_t));
    tsldr_miscutil_memcpy(dest, src, sizeof(tsldr_mdinfo_t));

    dest->init = true;

    TSLDR_DBG_PRINT(LIB_NAME_MACRO "child_loc: %d\n", id);
    TSLDR_DBG_PRINT(LIB_NAME_MACRO "child_id: %d\n", dest->child_id);
}


void tsldr_main_monitor_privilege_pd(seL4_Word cid)
{
    tsldr_caputil_pd_privilege(cid);
}


void tsldr_main_monitor_encode_required_rights(
    void *xrt_entry_list, /* dest */
    const trustedlo_xrtreq_t *xrt_req_list /* src */
) {
    /*
     * This function writes serialised access rights
     *                   into 'dest' at monitor side.
     * The trustedlo loader will then use shared memory
     *            to access 'dest' at template PD side.
     */
    tsldr_acrtutil_encode_rights(xrt_entry_list, xrt_req_list);
}
