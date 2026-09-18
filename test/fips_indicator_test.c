/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "testutil.h"

static OSSL_LIB_CTX *libctx = NULL;

struct indicator_check_data_st {
    OSSL_LIB_CTX *ctx;
    int ret;
};

static int check_cipher_indicator_params(OSSL_LIB_CTX *ctx, EVP_CIPHER_CTX *cctx, const char *name, const char *propq)
{
    EVP_CIPHER *testciph = NULL;
    const OSSL_PARAM *params;
    const OSSL_PARAM *p;
    int ret = 0;

    /*
     * Allocate an instance of this cipher from the requested provider
     */
    ERR_clear_error();
    testciph = EVP_CIPHER_fetch(ctx, name, propq);
    if (testciph == NULL) {
        /*
         * A missing alg from a provider isn't a failure, skip that
         */
        TEST_note("Cipher %s is not present in any provider with %s, skipping", name, propq);
        ret = 1;
        goto out;
    }

    /*
     * Init the context for encryption
     */
    if (!TEST_true(EVP_EncryptInit_ex(cctx, testciph, NULL, NULL, NULL)))
        goto out;

    /*
     * Fetch its gettable parameters
     */
    params = EVP_CIPHER_CTX_gettable_params(cctx);
    if (!TEST_ptr(params))
        goto out;

    /*
     * Make sure the fips indicator is listed among them
     */
    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_FIPS_APPROVED_INDICATOR);
    if (!TEST_ptr(p)) {
        TEST_error("Cipher %s is missing a FIPS indicator parameter", name);
        goto out;
    }

    ret = 1;
out:
    EVP_CIPHER_free(testciph);
    return ret;
}

static void check_cipher_fips_indicator(EVP_CIPHER *cph, void *arg)
{
    struct indicator_check_data_st *ind_data = arg;
    const char *name = EVP_CIPHER_get0_name(cph);
    EVP_CIPHER_CTX *cctx = NULL;
    int ret = 0;

    /*
     * Don't do any more testing if we've already failed
     */
    if (ind_data->ret == 0)
        return;

    /*
     * Allocate a new CIPHER CTX
     */
    cctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(cctx)) {
        ind_data->ret = 0;
        return;
    }

    if (!check_cipher_indicator_params(ind_data->ctx, cctx, name, "provider=default"))
        goto out;

    if (!check_cipher_indicator_params(ind_data->ctx, cctx, name, "fips=yes"))
        goto out;

    ret = 1;
out:
    EVP_CIPHER_CTX_free(cctx);
    ind_data->ret = ret;
    return;
}

static int test_evp_alg_fips_indicator_present(void)
{
    int ret = 0;
    struct indicator_check_data_st ind_data;

    ind_data.ctx = libctx;
    ind_data.ret = 1;
    EVP_CIPHER_do_all_provided(libctx, check_cipher_fips_indicator, &ind_data);

    ret = ind_data.ret;
    return ret;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "config", OPT_CONFIG_FILE, '<',
            "The configuration file to use for the libctx" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    char *config_file = NULL;
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            if (!test_get_libctx(&libctx, NULL, config_file, NULL, NULL))
                return 0;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    ADD_TEST(test_evp_alg_fips_indicator_present);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(libctx);
}
