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
    ssize_t i = (ssize_t) len;

#ifndef DO_LOOP_UNROLL
    for (i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= FNV1A_PRIME;
    }
    return hash;
#else
    uint8_t *keytmp = key;
    do {
        switch (i % 16) {
        case 0:
            hash ^= keytmp[15];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 15:
            hash ^= keytmp[14];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 14:
            hash ^= keytmp[13];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 13:
            hash ^= keytmp[12];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 12:
            hash ^= keytmp[11];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 11:
            hash ^= keytmp[10];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 10:
            hash ^= keytmp[9];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 9:
            hash ^= keytmp[8];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 8:
            hash ^= keytmp[7];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 7:
            hash ^= keytmp[6];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 6:
            hash ^= keytmp[5];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 5:
            hash ^= keytmp[4];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 4:
            hash ^= keytmp[3];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 3:
            hash ^= keytmp[2];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 2:
            hash ^= keytmp[1];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        case 1:
            hash ^= keytmp[0];
            hash *= FNV1A_PRIME;
            /* FALLTHROUGH */
        default:
            break;
        }
        keytmp += 16;
        i -= 16;
    } while (i > 0);
#endif 
    return hash;
}
