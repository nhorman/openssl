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
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include "testutil.h"

static OSSL_LIB_CTX *libctx = NULL;
static int skip_legacy = 0;

/*
 * Struct to store method specific functions for testing an indicator
 * of a given EVP type
 */
struct evp_method_fns {
    void *(*alloc_ctx)(void);
    void (*free_ctx)(void *ctx);
    const char *(*get_name)(void *alg);
    void *(*alg_fetch)(OSSL_LIB_CTX *libctx, const char *name, const char *propq);
    void (*alg_free)(void *alg);
    int (*op_init)(void **ctx, void *alg);
    int (*get_ctx_param)(void *ctx, OSSL_PARAM params[]);
};

/*
 * Method functions for EVP_CIPHER
 */
static void *alloc_cipher_ctx(void)
{
    return EVP_CIPHER_CTX_new();
}

static void free_cipher_ctx(void *ctx)
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)ctx);
}

static const char *cipher_get_name(void *alg)
{
    return EVP_CIPHER_get0_name((EVP_CIPHER *)alg);
}

static void *cipher_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    return EVP_CIPHER_fetch(ctx, name, propq);
}

static void cipher_free(void *alg)
{
    EVP_CIPHER_free((EVP_CIPHER *)alg);
}

static int evp_cipher_init(void **ctx, void *alg)
{
    return EVP_DecryptInit_ex((EVP_CIPHER_CTX *)*ctx, (EVP_CIPHER *)alg, NULL, NULL, NULL);
}

static int cipher_ctx_get_param(void *ctx, OSSL_PARAM params[])
{
    return EVP_CIPHER_CTX_get_params((EVP_CIPHER_CTX *)ctx, params);
}

static struct evp_method_fns cipher_methods = {
    alloc_cipher_ctx,
    free_cipher_ctx,
    cipher_get_name,
    cipher_fetch,
    cipher_free,
    evp_cipher_init,
    cipher_ctx_get_param
};

/*
 * Method functions for EVP_MD
 */
static void *alloc_md_ctx(void)
{
    return EVP_MD_CTX_new();
}

static void free_md_ctx(void *ctx)
{
    EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
}

static const char *md_get_name(void *alg)
{
    return EVP_MD_get0_name((EVP_MD *)alg);
}

static void *md_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    return EVP_MD_fetch(ctx, name, propq);
}

static void md_free(void *alg)
{
    EVP_MD_free((EVP_MD *)alg);
}

static int evp_md_init(void **ctx, void *alg)
{
    return EVP_DigestInit((EVP_MD_CTX *)*ctx, (EVP_MD *)alg);
}

static int md_ctx_get_param(void *ctx, OSSL_PARAM params[])
{
    return EVP_MD_CTX_get_params((EVP_MD_CTX *)ctx, params);
}

static struct evp_method_fns digest_methods = {
    alloc_md_ctx,
    free_md_ctx,
    md_get_name,
    md_fetch,
    md_free,
    evp_md_init,
    md_ctx_get_param
};

/*
 * Method functions for EVP_KDF
 */
#define DUMMY_KDF_CTX 12345
static void *alloc_kdf_ctx(void)
{
    return (void *)DUMMY_KDF_CTX;
}

static void free_kdf_ctx(void *ctx)
{
    if (ctx == (void *)DUMMY_KDF_CTX)
        return;
    EVP_KDF_CTX_free((EVP_KDF_CTX *)ctx);
}

static const char *kdf_get_name(void *alg)
{
    return EVP_KDF_get0_name((EVP_KDF *)alg);
}

static void *kdf_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    return EVP_KDF_fetch(ctx, name, propq);
}

static void kdf_free(void *alg)
{
    EVP_KDF_free((EVP_KDF *)alg);
}

static int evp_kdf_init(void **ctx, void *alg)
{
    if (*ctx != (void *)DUMMY_KDF_CTX)
        return 0;
    *ctx = EVP_KDF_CTX_new((EVP_KDF *)alg);
    if (*ctx == NULL)
        return 0;
    return 1;
}

static int kdf_ctx_get_param(void *ctx, OSSL_PARAM params[])
{
    return EVP_KDF_CTX_get_params((EVP_KDF_CTX *)ctx, params);
}

static struct evp_method_fns kdf_methods = {
    alloc_kdf_ctx,
    free_kdf_ctx,
    kdf_get_name,
    kdf_fetch,
    kdf_free,
    evp_kdf_init,
    kdf_ctx_get_param
};

/*
 * Method functions for EVP_MAC
 */
#define DUMMY_MAC_CTX 12345
static void *alloc_mac_ctx(void)
{
    return (void *)DUMMY_MAC_CTX;
}

static void free_mac_ctx(void *ctx)
{
    if (ctx == (void *)DUMMY_MAC_CTX)
        return;
    EVP_MAC_CTX_free((EVP_MAC_CTX *)ctx);
}

static const char *mac_get_name(void *alg)
{
    return EVP_MAC_get0_name((EVP_MAC *)alg);
}

static void *mac_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    return EVP_MAC_fetch(ctx, name, propq);
}

static void mac_free(void *alg)
{
    EVP_MAC_free((EVP_MAC *)alg);
}

static int evp_mac_init(void **ctx, void *alg)
{
    if (*ctx != (void *)DUMMY_MAC_CTX)
        return 0;
    *ctx = EVP_MAC_CTX_new((EVP_MAC *)alg);
    if (*ctx == NULL)
        return 0;
    return 1;
}

static int mac_ctx_get_param(void *ctx, OSSL_PARAM params[])
{
    return EVP_MAC_CTX_get_params((EVP_MAC_CTX *)ctx, params);
}

static struct evp_method_fns mac_methods = {
    alloc_mac_ctx,
    free_mac_ctx,
    mac_get_name,
    mac_fetch,
    mac_free,
    evp_mac_init,
    mac_ctx_get_param
};

/*
 * Method functions for EVP_RAND
 */
#define DUMMY_RAND_CTX 12345
static void *alloc_rand_ctx(void)
{
    return (void *)DUMMY_RAND_CTX;
}

static void free_rand_ctx(void *ctx)
{
    if (ctx == (void *)DUMMY_RAND_CTX)
        return;
    EVP_RAND_CTX_free((EVP_RAND_CTX *)ctx);
}

static const char *rand_get_name(void *alg)
{
    return EVP_RAND_get0_name((EVP_RAND *)alg);
}

static void *rand_fetch(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    return EVP_RAND_fetch(ctx, name, propq);
}

static void rand_free(void *alg)
{
    EVP_RAND_free((EVP_RAND *)alg);
}

static int evp_rand_init(void **ctx, void *alg)
{
    if (*ctx != (void *)DUMMY_RAND_CTX)
        return 0;
    *ctx = EVP_RAND_CTX_new((EVP_RAND *)alg, NULL);
    if (*ctx == NULL)
        return 0;
    return 1;
}

static int rand_ctx_get_param(void *ctx, OSSL_PARAM params[])
{
    return EVP_RAND_CTX_get_params((EVP_RAND_CTX *)ctx, params);
}

static struct evp_method_fns rand_methods = {
    alloc_rand_ctx,
    free_rand_ctx,
    rand_get_name,
    rand_fetch,
    rand_free,
    evp_rand_init,
    rand_ctx_get_param
};

struct indicator_check_data_st {
    OSSL_LIB_CTX *ctx;
    struct evp_method_fns *fns;
    void *algctx;
    int ret;
};

static int check_indicator_params(struct indicator_check_data_st *ind_data, void *cctx,
    const char *name, const char *propq,
    int expect_approved)
{
    OSSL_LIB_CTX *ctx = ind_data->ctx;
    void *testevp = NULL;
    int approved = -1;
    OSSL_PARAM testp[2] = { OSSL_PARAM_int(OSSL_ALG_PARAM_FIPS_APPROVED_INDICATOR, &approved), OSSL_PARAM_END };
    int ret = 0;

    /*
     * Allocate an instance of this evp from the requested provider
     */
    ERR_clear_error();
    testevp = ind_data->fns->alg_fetch(ctx, name, propq);
    if (testevp == NULL) {
        /*
         * A missing alg from a provider isn't a failure, skip that
         */
        TEST_note("Alg %s is not present in any provider with %s, skipping", name, propq);
        ret = 1;
        goto out;
    }

    /*
     * Init the context for decryption
     * Note: We're doing decryption here because every fips approved algorithm
     * gets an approved indicator that we can test for
     */
    if (!TEST_int_eq(ind_data->fns->op_init(&cctx, testevp), 1))
        goto out;

    /*
     * Get the indicator
     */
    if (!ind_data->fns->get_ctx_param(cctx, testp)) {
        TEST_error("Failed to get indicator parameter for %s property %s", name, propq);
        goto out;
    }

    if (!OSSL_PARAM_get_int(&testp[0], &approved)) {
        TEST_error("Failed to extract integer param for %s property %s", name, propq);
        goto out;
    }

    if (approved != expect_approved) {
        TEST_error("Alg %s property %s got approved %d expected %d", name, propq, approved, expect_approved);
        goto out;
    }

    TEST_note("Alg %s property %s is %s", name, propq, approved ? "approved" : "not approved");

    ret = 1;
out:
    ind_data->fns->alg_free(testevp);
    return ret;
}

static void check_fips_indicator(void *alg, void *arg)
{
    struct indicator_check_data_st *ind_data = arg;
    const char *name = ind_data->fns->get_name(alg);
    void *cctx = NULL;
    int ret = 0;

    /*
     * Don't do any more testing if we've already failed
     */
    if (ind_data->ret == 0)
        return;

    /*
     * Allocate a new EVP CTX
     */
    cctx = ind_data->fns->alloc_ctx();
    if (!TEST_ptr(cctx)) {
        ind_data->ret = 0;
        return;
    }

    if (!check_indicator_params(ind_data, cctx, name, "provider=default", 0))
        goto out;

    if (!check_indicator_params(ind_data, cctx, name, "fips=yes", 1)) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if (skip_legacy == 0) {
        if (!check_indicator_params(ind_data, cctx, name, "provider=legacy", 0))
            goto out;
    }
    ret = 1;
out:
    ind_data->fns->free_ctx(cctx);
    ind_data->ret = ret;
    return;
}

static void check_cipher_fips_indicator(EVP_CIPHER *cph, void *arg)
{
    check_fips_indicator((void *)cph, arg);
}

static void check_digest_fips_indicator(EVP_MD *md, void *arg)
{
    check_fips_indicator((void *)md, arg);
}

static void check_kdf_fips_indicator(EVP_KDF *kdf, void *arg)
{
    check_fips_indicator((void *)kdf, arg);
}

static void check_mac_fips_indicator(EVP_MAC *mac, void *arg)
{
    check_fips_indicator((void *)mac, arg);
}

static void check_rand_fips_indicator(EVP_RAND *rand, void *arg)
{
    check_fips_indicator((void *)rand, arg);
}

static int test_evp_alg_fips_indicator_present(void)
{
    int ret = 0;
    struct indicator_check_data_st ind_data;

    ind_data.ctx = libctx;
    ind_data.ret = 1;
    ind_data.fns = &cipher_methods;
    EVP_CIPHER_do_all_provided(libctx, check_cipher_fips_indicator, &ind_data);
    if (ind_data.ret == 0)
        goto out;

    ind_data.fns = &digest_methods;
    EVP_MD_do_all_provided(libctx, check_digest_fips_indicator, &ind_data);
    if (ind_data.ret == 0)
        goto out;

    ind_data.fns = &kdf_methods;
    EVP_KDF_do_all_provided(libctx, check_kdf_fips_indicator, &ind_data);
    if (ind_data.ret == 0)
        goto out;

    ind_data.fns = &mac_methods;
    EVP_MAC_do_all_provided(libctx, check_mac_fips_indicator, &ind_data);
    if (ind_data.ret == 0)
        goto out;

    ind_data.fns = &rand_methods;
    EVP_RAND_do_all_provided(libctx, check_rand_fips_indicator, &ind_data);

out:
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

    if (!OSSL_PROVIDER_load(libctx, "legacy"))
        skip_legacy = 1;

    ADD_TEST(test_evp_alg_fips_indicator_present);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(libctx);
}
