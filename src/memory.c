/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <memory.h>

void *tsldr_miscutil_memcpy(void *restrict dest, const void *restrict src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }
    return dest;
}

void *tsldr_miscutil_memset(void *dest, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dest;

    for (size_t i = 0; i < n; ++i) {
        d[i] = (unsigned char)c;
    }
    return dest;
}

int tsldr_miscutil_memcmp(const unsigned char *s1, const unsigned char *s2, int n)
{
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

int tsldr_miscutil_strcmp(const char *s1, const char *s2)
{
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;

    int i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) {
            return (a[i] - b[i]);
        }
        i++;
    }
    return (a[i] - b[i]);
}

size_t tsldr_miscutil_strlen(const char *s)
{
    size_t len = 0;

    while (s[len] != '\0')
        ++len;

    return len;
}
