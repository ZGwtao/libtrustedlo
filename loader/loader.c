/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <libtrustedlo.h>

void loader_entry(void)
{
    /* Trusted loading main function. */
    mktxlo_self_load_entry();
}