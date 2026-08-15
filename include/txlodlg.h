/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBTRUSTEDLO_DLG_H
#define LIBTRUSTEDLO_DLG_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <microkit.h>

typedef struct __attribute__((packed)) {
    uint8_t kind;
    uint8_t flags;
    uint16_t slot;
    uint16_t cap_count;
    uint64_t arg0;
    uint64_t arg1;
} dlg_resource_t;

typedef struct __attribute__((packed)) {
    uint16_t record_size;
    uint16_t resource_count;
    uint32_t delegation_cap;
    uint64_t pd_id;
} dlg_delegator_t;

typedef enum {
    DLG_RESOURCE_CHANNEL_NOTIFY = 1,
    DLG_RESOURCE_CHANNEL_PPC = 2,
    DLG_RESOURCE_MEMORY_REGION = 3,
    DLG_RESOURCE_IOPORT = 4,
} dlg_resource_kind_t;

#define DLG_MAX_DELEGATORS 16
#define DLG_HEADER_SIZE 16
#define DLG_RESOURCE_SIZE sizeof(dlg_resource_t)
#define DLG_DELEGATOR_HEADER_SIZE sizeof(dlg_delegator_t)

static inline const dlg_resource_t *dlg_delegator_resource(const dlg_delegator_t *delegator,
                                                           uint16_t index)
{
    if (index >= delegator->resource_count) {
        return NULL;
    }
    return (const dlg_resource_t *)((const uint8_t *)delegator + DLG_DELEGATOR_HEADER_SIZE +
                                    index * DLG_RESOURCE_SIZE);
}

static inline const dlg_resource_t *
trustedlo_xrt_util_find_resource(const dlg_delegator_t *info, uint8_t kind, seL4_Word value)
{
    for (uint16_t i = 0; i < info->resource_count; i++) {
        const dlg_resource_t *resource = dlg_delegator_resource(info, i);
        if (resource->kind == kind && resource->arg0 == value) {
            return resource;
        }
    }
    return NULL;
}

#endif