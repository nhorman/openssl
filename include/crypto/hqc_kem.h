/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_HQC_KEM_H
# define OPENSSL_HEADER_HQC_KEM_H
# pragma once

# define EVP_PKEY_HQC_128 NID_HQC_128
# define EVP_PKEY_HQC_192 NID_HQC_192
# define EVP_PKEY_HQC_256 NID_HQC_256

typedef enum {
    EVP_PKEY_HQC_KEM_128 = 0,
    EVP_PKEY_HQC_KEM_192 = 1,
    EVP_PKEY_HQC_KEM_256 = 2,
    EVP_PKEY_HQC_KEM_MAX
} hqc_key_type;

typedef struct hqc_variant_info_st {
    hqc_key_type type;
    int  nid;
    char *name;
    size_t ek_size;
    size_t dk_size;
    size_t seed_len;
    size_t security_bytes;
    uint32_t security_category;
    uint32_t secbits;
    uint32_t n;
    uint32_t n_mu;
    uint16_t omega;
    uint16_t omega_r;
    uint32_t rej_threshold;
} HQC_VARIANT_INFO;

/* Known as HQC_KEY via crypto/types.h */
typedef struct ossl_hqc_kem_key_st {
    const HQC_VARIANT_INFO *info; /* key size info */
    uint8_t *seed;                /* seed data */
    uint8_t *ek;                  /* encryption key */
    uint8_t *dk;                  /* decryption key */
    int selection;                /* Presence status of key parts */
} HQC_KEY;

void hqc_kem_key_free(HQC_KEY *key);
HQC_KEY *hqc_kem_new(int evp_type);

/**
 * @def VEC_SIZE(a, b)
 * @brief Computes the number of elements of size @p b required to store
 *        @p a units.
 *
 * This macro performs ceiling division of @p a by @p b, effectively
 * returning the smallest integer greater than or equal to (a / b).
 * Commonly used to determine the number of words or vector blocks
 * needed to hold a certain number of bits or bytes.
 *
 * @param a Total size (e.g., number of bits or bytes).
 * @param b Unit size (e.g., bits or bytes per word).
 * @return The number of full units of size @p b needed to store @p a.
 */
#define VEC_SIZE(a, b) (((a) / (b)) + ((a) % (b) == 0 ? 0 : 1))

#endif  /* OPENSSL_HEADER_HQC_KEM_H */
