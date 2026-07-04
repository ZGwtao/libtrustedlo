#pragma once

#include <stdint.h>
#include <stddef.h>

void *tsldr_miscutil_memcpy(
    void *restrict dest,
    const void *restrict src,
    size_t n
);

void *tsldr_miscutil_memset(
    void *dest,
    int value,
    size_t n
);

int tsldr_miscutil_memcmp(
    const unsigned char *lhs,
    const unsigned char *rhs,
    int n
);

int tsldr_miscutil_strcmp(
    const char *lhs,
    const char *rhs
);