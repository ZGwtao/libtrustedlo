#include <tsldr_vm_layout.h>
#include <libtrustedlo.h>

/* Dummy IPC buffer object for template PDs. */
seL4_IPCBuffer __sel4_ipc_buffer_obj;

void loader_entry(void)
{
    __sel4_ipc_buffer =
        (seL4_IPCBuffer *)tsldr_vm_layout.ipc_buffer.base;

    /* Trusted loading main function. */
    mktxlo_self_load_entry();
}