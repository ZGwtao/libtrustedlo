/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBTRUSTEDLO_MISCUTILS_H
#define LIBTRUSTEDLO_MISCUTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdint.h>

#include <microkit.h>

#include <elf.h>

void tsldr_miscutil_dbg_print(const char *format, ...);

void tsldr_miscutil_load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr);

#ifdef CONFIG_DEBUG_BUILD
#define TSLDR_DBG_PRINT(...)                                                                       \
    do {                                                                                           \
        tsldr_miscutil_dbg_print(__VA_ARGS__);                                                     \
    } while (0)
#else
#define TSLDR_DBG_PRINT(...)                                                                       \
    do {                                                                                           \
    } while (0)
#endif

#define LIB_NAME_MACRO "    => [@trustedlo] "
#define TSLDR_ERR_PRINT_MACRO "    => [@trustedlo::error] "

#endif
