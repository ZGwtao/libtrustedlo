#include <tsldr_vm_layout.h>
#include <libtrustedlo.h>

void loader_entry(void)
{
    /* Trusted loading main function. */
    mktxlo_self_load_entry();
}