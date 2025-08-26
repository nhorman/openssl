/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h> /* RAND_get0_public() */
#include <openssl/proverr.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/cryptlib.h"
#include "internal/provider.h"
#include "crypto/context.h"
#include "internal/core.h"

static void ossltest_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(PROV_LIBCTX_OF(provctx));
    ossl_prov_ctx_free(provctx);
}

static const OSSL_PARAM ossltest_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ossltest_gettable_params(void *provctx)
{
    return ossltest_param_types;
}

static int ossltest_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL ossltest Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

static const OSSL_ALGORITHM *ossltest_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    return NULL;
}

static const OSSL_DISPATCH ossltest_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ossltest_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))ossltest_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ossltest_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ossltest_query },
    OSSL_DISPATCH_END
};

OSSL_provider_init_fn OSSL_provider_init_int;
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
   
    OSSL_LIB_CTX *libctx = NULL;

    if ((*provctx = ossl_prov_ctx_new()) == NULL
        || (libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
            OSSL_LIB_CTX_free(libctx);
            ossltest_teardown(*provctx);
            *provctx = NULL;
            return 0;
    }

    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    *out = ossltest_dispatch_table;

    return 1;


}

