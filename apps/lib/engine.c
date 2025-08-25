/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Here is a set of wrappers for the ENGINE API, which are no-ops when the
 * ENGINE API is disabled / removed.
 * We need to suppress deprecation warnings to make this work.
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <string.h> /* strcmp */

#include <openssl/types.h> /* Ensure we have the ENGINE type, regardless */
#include <openssl/err.h>
#include "apps.h"

ENGINE *setup_engine_methods(const char *id, unsigned int methods, int debug)
{
    ENGINE *e = NULL;

    return e;
}

void release_engine(ENGINE *e)
{
}

int init_engine(ENGINE *e)
{
    int rv = 1;

    return rv;
}

int finish_engine(ENGINE *e)
{
    int rv = 1;

    return rv;
}

char *make_engine_uri(ENGINE *e, const char *key_id, const char *desc)
{
    char *new_uri = NULL;

    BIO_printf(bio_err, "Engines not supported for loading %s\n", desc);
    return new_uri;
}

#ifndef OPENSSL_NO_DEPRECATED_3_6
int get_legacy_pkey_id(OSSL_LIB_CTX *libctx, const char *algname, ENGINE *e)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = NID_undef;

    ERR_set_mark();
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, algname, -1);

    /* We're only interested if it comes from an ENGINE */
    if (tmpeng == NULL)
        ameth = NULL;

    ERR_pop_to_mark();
    if (ameth == NULL)
        return NID_undef;

    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);

    return pkey_id;
}
#endif

const EVP_MD *get_digest_from_engine(const char *name)
{
    return NULL;
}

const EVP_CIPHER *get_cipher_from_engine(const char *name)
{
    return NULL;
}
