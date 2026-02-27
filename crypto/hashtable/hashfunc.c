/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 */

#include "internal/hashfunc.h"

#define FNV1A_PRIME 0x00000100000001B3ULL
ossl_unused uint64_t ossl_fnv1a_hash(uint8_t *key, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    size_t i = len;

#ifndef DO_LOOP_UNROLL
    for (i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= FNV1A_PRIME;
    }
    return hash;
#else
    uint8_t *keytmp = key;
    do {
        switch (i % 8) {
        case 0:
            if (len == 0)
                break;
            hash ^= keytmp[0];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 7:
            hash ^= keytmp[7];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 6:
            hash ^= keytmp[6];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 5:
            hash ^= keytmp[5];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 4:
            hash ^= keytmp[4];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 3:
            hash ^= keytmp[3];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 2:
            hash ^= keytmp[2];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 1:
            hash ^= keytmp[1];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        default:
            break;
        }
        keytmp += 8;
        i -= 8;
    } while (i > 0);
#endif 
    return hash;
}
