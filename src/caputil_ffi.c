/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>

#include <txlocap.h>

/* Pancake FFI adapters are deliberately limited to trustedlo_cap_util_* calls. */
void ffitrustedlo_cap_util_pd_deprivilege(unsigned char *c, long arg, unsigned char *a, long alen)
{
    (void)c;
    (void)arg;
    (void)a;
    (void)alen;
    trustedlo_cap_util_pd_deprivilege();
}

#define CAP_FFI0(name)                                                                             \
    void ffi##name(unsigned char *c, long arg, unsigned char *a, long alen)                        \
    {                                                                                              \
        (void)c;                                                                                   \
        (void)arg;                                                                                 \
        (void)a;                                                                                   \
        (void)alen;                                                                                \
        name();                                                                                    \
    }
#define CAP_FFI1(name)                                                                             \
    void ffi##name(unsigned char *c, long arg, unsigned char *a, long alen)                        \
    {                                                                                              \
        (void)arg;                                                                                 \
        (void)a;                                                                                   \
        (void)alen;                                                                                \
        name((seL4_Word)(uintptr_t)c);                                                             \
    }

CAP_FFI0(trustedlo_cap_util_pd_grant_vspace_access)
CAP_FFI0(trustedlo_cap_util_pd_revoke_vspace_access)
CAP_FFI1(trustedlo_cap_util_revoke_notification_cap)
CAP_FFI1(trustedlo_cap_util_restore_notification_cap)
CAP_FFI1(trustedlo_cap_util_revoke_ppc_cap)
CAP_FFI1(trustedlo_cap_util_restore_ppc_cap)
CAP_FFI1(trustedlo_cap_util_revoke_irq_cap)
CAP_FFI1(trustedlo_cap_util_restore_irq_cap)

void ffitrustedlo_cap_util_pd_revoke_page_access(unsigned char *c,
                                                 long arg,
                                                 unsigned char *a,
                                                 long alen)
{
    (void)alen;
    trustedlo_cap_util_pd_revoke_page_access((seL4_Word)(uintptr_t)c, (seL4_Word)arg);
    (void)a;
}

void ffitrustedlo_cap_util_pd_grant_page_access(unsigned char *c,
                                                long arg,
                                                unsigned char *a,
                                                long alen)
{
    (void)a;
    trustedlo_cap_util_pd_grant_page_access((seL4_Word)(uintptr_t)c,
                                            (uintptr_t)arg,
                                            seL4_AllRights,
                                            0,
                                            (seL4_Word)alen);
}
