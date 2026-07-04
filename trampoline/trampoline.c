#include <stdint.h>
#include <stddef.h>
#define __thread
#include <sel4/sel4.h>

#include <elf.h>
#include <memory.h>

#define MONITOR_PPC_CHANNEL (74 + 15)

typedef void (*entry_fn_t)(void);

#if defined(CONFIG_ARCH_X86_64)
__attribute__((naked, noreturn)) /* don't let your compiler fuck around with the args */
void trampoline_main_jump_with_stack(void *new_stack, void (*entry)(void))
{
    __asm__ volatile(
        "mov %rdi, %rsp\n\t"   /* new_stack in rdi */
        "jmp *%rsi\n\t"        /* entry in rsi */
    );
}
#elif defined(CONFIG_ARCH_AARCH64)
__attribute__((noreturn))
void trampoline_main_jump_with_stack(void *new_stack, void (*entry)(void))
{
    /* jump tp trampoline */
    asm volatile (
        "mov sp, %[new_stack]\n\t" /* set new SP */
        "br  %[func]\n\t"          /* branch directly, never return */
        :
        : [new_stack] "r" (new_stack),
          [func] "r" (entry)
        : "x30", "memory"
    );
    __builtin_unreachable();
}
#else
#error "Unsupported architecture for 'trampoline_main_jump_with_stack'"
#endif

static __attribute__((noreturn)) void trampoline_abort(void)
{
#if defined(CONFIG_ARCH_X86_64)
    __asm__ volatile("ud2");
#elif defined(CONFIG_ARCH_AARCH64)
    __asm__ volatile("brk #0");
#endif

    __builtin_unreachable();
}

// FIXME: read it from the arg list
seL4_IPCBuffer *__sel4_ipc_buffer = (seL4_IPCBuffer *)0x100000;

__attribute__((noreturn, used))
void trampoline_entry(void)
{
    uintptr_t ossvc_metadata  = 0xA01000;
    uintptr_t tsldr_metadata    = 0xA00000;
    uintptr_t tsldr_program     = 0x200000;
    uintptr_t tsldr_context     = 0xE00000;
    // FIXME: the stack addr is wrong for x86??
#if defined(CONFIG_ARCH_X86_64)
    uintptr_t tsldr_stack_bottom    = 0x7fffffffe000;
#elif defined(CONFIG_ARCH_AARCH64)
    uintptr_t tsldr_stack_bottom    = 0x0FFFFFFF000;
#else
#error "Unsupported architecture for stack address"
#endif
    uintptr_t container_stack_bottom    = 0x00FFFBFF000;
    uintptr_t container_stack_top       = 0x00FFFC00000;
    uintptr_t client_elf = 0x2000000;

    // TSLDR_DBG_PRINT("[@trampoline] entry of trampoline.\n");

    /* say goodbye to the old stack */
    tsldr_miscutil_memset((void *)tsldr_stack_bottom, 0, 0x1000);

    /* clean up trusted loader metadata... */
    tsldr_miscutil_memset((void *)tsldr_metadata, 0, 0x1000);

    /* clean up access rights group metadata */
    // is disposable...
    tsldr_miscutil_memset((void *)ossvc_metadata, 0, 0x1000);
    /* clean up container stack... */
    tsldr_miscutil_memset((void *)container_stack_bottom, 0, 0x1000);

    // syscall for tsldr_context cleanup
    seL4_SetMR(0, 20);
    // try to call the monitor to backup trusted loading context
    seL4_MessageInfo_t info = seL4_Call(MONITOR_PPC_CHANNEL, seL4_MessageInfo_new(0, 1, 0, 0));
    if (seL4_MessageInfo_get_label(info) != seL4_NoError) {
        trampoline_abort();
    }
    // clean up trusted loading context...
    tsldr_miscutil_memset((void *)tsldr_context, 0, 0x1000);

    /* clean up trusted loader... */
    tsldr_miscutil_memset((void *)tsldr_program, 0, 0x800000);
    /*
     * At this point, the client information is embedded in the address space,
     * while the trusted loader and all older stacks are gone for good...
     * It's fine to just jump to the new stack/function for the real container
     */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)client_elf;
    entry_fn_t entry_fn = (entry_fn_t) ehdr->e_entry;

    trampoline_main_jump_with_stack((void *)container_stack_top, entry_fn);
}
