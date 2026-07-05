#pragma once

#ifndef TRAMPOLINE_ARGS_H
#define TRAMPOLINE_ARGS_H

#include <stdint.h>
#include <stddef.h>

#define __thread
#include <sel4/sel4.h>

typedef struct {
    uintptr_t address;
    size_t size;
} memory_region_t;

enum {
REGION_TSLDR_STACK,
REGION_TSLDR_METADATA,
REGION_OSSVC_METADATA,
REGION_CONTAINER_STACK,
REGION_TSLDR_CONTEXT,
REGION_TSLDR_PROGRAM,
REGION_COUNT
};

typedef struct {
    memory_region_t regions[6];
    uintptr_t container_stack_top;
    uintptr_t client_elf;
    uintptr_t ipc_buffer;
    seL4_CPtr monitor_channel;
} trampoline_args_t;

typedef struct {
    seL4_Word bitmap_irqs;
    seL4_Word bitmap_notifications;
    seL4_Word bitmap_ppcs;
    seL4_Word bitmap_ioports;
    char dynamic_pd_name[64];
} client_args_t;

#endif