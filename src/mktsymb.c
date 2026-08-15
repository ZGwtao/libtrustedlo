/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <mktsymb.h>

#define MKTSYMB_HEADER_SIZE 14
#define MKTSYMB_SYMBOL_HEADER_SIZE 16

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

void mktsymb_read(mktsymb_header_t *header, const void *base)
{
    const uint8_t *p = base;

    header->base = p;
    header->pd_name_len = read_le16(p + 8);
    header->symbol_cnt = read_le32(p + 10);
    header->pd_name = (const char *)(p + MKTSYMB_HEADER_SIZE);
    header->symbols = p + MKTSYMB_HEADER_SIZE + header->pd_name_len;
}

const uint8_t *mktsymb_read_symbol(const uint8_t *p, mktsymb_symbol_t *symbol)
{
    symbol->name_len = read_le16(p);
    symbol->setvar = read_le16(p + 2);
    symbol->data_len = read_le32(p + 4);
    symbol->expected_size = read_le64(p + 8);
    symbol->name = (const char *)(p + MKTSYMB_SYMBOL_HEADER_SIZE);
    symbol->data = p + MKTSYMB_SYMBOL_HEADER_SIZE + symbol->name_len;

    return symbol->data + symbol->data_len;
}
