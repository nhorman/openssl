/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef EVP_FETCH_ALL_H
#define EVP_FETCH_ALL_H

int evp_cipher_cache_constants(EVP_CIPHER *cipher);
int evp_md_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_cipher_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_kdf_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_rand_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_mac_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_keymgmt_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_skeymgmt_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_kem_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_asym_cipher_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_signature_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
int evp_keyexch_fetch_all(OSSL_LIB_CTX *ctx, OSSL_METHOD_STORE *store);
#endif
