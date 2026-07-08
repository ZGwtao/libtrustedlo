
#include <tsldr_vm_layout.h>
#include <libtrustedlo.h>

#define TRAMPOLINE_ELF (0x1000000)
#define CONTAINER_ELF (0x2000000)
#define CONTAINER_EXEC (0x2800000)

// trampoline is going to use a different stack with both the trusted loader and the client program,
// so we need to prepare a stack for it (so that trampoline can clean up the old stack)
#define TRAMPOLINE_STACK_TOP (0x00FFFE00000)

/* dummy for template PDs */
seL4_IPCBuffer __sel4_ipc_buffer_obj;

void loader_entry(void)
{
    // 0x100000 is reserved by the microkit tool for dynamic PD's ipc buffer
    __sel4_ipc_buffer = (seL4_IPCBuffer *)tsldr_vm_layout.ipc_buffer.base;

    /* --- trusted loading main function --- */
    
    tsldr_main_self_loading(
        (void *)tsldr_vm_layout.loader_metadata.base, // the place where the trusted loader metadata is placed by the monitor
        (void *)tsldr_vm_layout.ossvc_metadata.base, // the place where the information of all OS services is placed by the monitor
        (tsldr_context_t *)tsldr_vm_layout.loader_context.base,
        (uintptr_t)(void *)CONTAINER_ELF,  // the place where client elf is placed by the monitor
        (uintptr_t)(void *)CONTAINER_EXEC, // the place where client elf is loaded and executed
        (uintptr_t)(void *)TRAMPOLINE_ELF, // the place where the trampoline elf is placed by the monitor
        TRAMPOLINE_STACK_TOP
    );
}
