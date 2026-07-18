
#include <trampoline.h>

#include <elf.h>
#include <memory.h>

typedef void (*entry_fn_t)(void);

seL4_IPCBuffer *__sel4_ipc_buffer;

#if defined(CONFIG_ARCH_X86_64)

__attribute__((naked, noreturn))
static void jump_with_stack(void *stack, entry_fn_t entry)
{
    __asm__ volatile(
        "mov %rdi, %rsp\n\t"
        "jmp *%rsi\n\t"
    );
}

#elif defined(CONFIG_ARCH_AARCH64)

__attribute__((naked, noreturn))
static void jump_with_stack(void *stack, entry_fn_t entry)
{
    __asm__ volatile(
        "mov sp, x0\n\t"
        "br x1\n\t"
    );
}

#else
#error "Unsupported architecture"
#endif

__attribute__((noreturn))
static void abort_trampoline(void)
{
#if defined(CONFIG_ARCH_X86_64)
    __asm__ volatile("ud2");
#elif defined(CONFIG_ARCH_AARCH64)
    __asm__ volatile("brk #0");
#endif

    __builtin_unreachable();
}

static inline void
trampoline_backup_trustedlo_context(const trampoline_args_t *args)
{
    seL4_SetMR(0, args->monitor_pcmcall_id);
    seL4_MessageInfo_t info = seL4_Call(
        args->monitor_channel, seL4_MessageInfo_new(0, 0, 0, 1)
    );
    if (seL4_MessageInfo_get_label(info) != seL4_NoError) {
        abort_trampoline();
    }
}

__attribute__((noreturn, used))
void trampoline_entry(const trampoline_args_t *args)
{
    __sel4_ipc_buffer = (seL4_IPCBuffer *)args->ipc_buffer;

    /* Before refreshing, call monitor to save valuable things. */
    trampoline_backup_trustedlo_context(args);

    for (size_t i = REGION_TSLDR_STACK;
         i <= REGION_TSLDR_PROGRAM;
         ++i) {
        tsldr_miscutil_memset(
            (void *)args->regions[i].address,
            0,
            args->regions[i].size
        );
    }
    entry_fn_t entry =
        (entry_fn_t)(uintptr_t)args->client_elf;

    jump_with_stack(
        (void *)args->container_stack_top,
        entry
    );
}