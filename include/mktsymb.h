/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MKTSYMB_H
#define MKTSYMB_H

#include <stddef.h>
#include <stdint.h>

#define PROTOCON_IMAGE_MAGIC 0x5043494d
#define PROTOCON_MKTSYMB_MAGIC "MKTSYMB\0"

typedef struct {
    uint32_t magic;
    uint32_t reserved;
    uint64_t mktsymb_offset;
    uint64_t mktsymb_size;
    uint64_t elf_offset;
    uint64_t elf_size;
} protocon_image_header_t;

typedef struct {
    const uint8_t *base;
    size_t size;
    const char *pd_name;
    const uint8_t *symbols;
    uint16_t pd_name_len;
    uint32_t symbol_cnt;
} mktsymb_header_t;

typedef struct {
    const char *name;
    const uint8_t *data;
    uint16_t name_len;
    uint16_t setvar;
    uint32_t data_len;
    uint64_t expected_size;
} mktsymb_symbol_t;

void mktsymb_read(mktsymb_header_t *header, const void *base);
const uint8_t *mktsymb_read_symbol(const uint8_t *p, mktsymb_symbol_t *symbol);

#endif