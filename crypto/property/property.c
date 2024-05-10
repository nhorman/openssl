/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include "internal/core.h"
#include "internal/property.h"
#include "internal/provider.h"
#include "internal/tsan_assist.h"
#include "internal/hashtable.h"
#include "crypto/ctype.h"
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include "internal/thread_once.h"
#include "crypto/lhash.h"
#include "crypto/sparse_array.h"
#include "property_local.h"
#include "crypto/context.h"

/*
 * The number of elements in the query cache before we initiate a flush.
 * If reducing this, also ensure the stochastic test in test/property_test.c
 * isn't likely to fail.
 */
#define IMPL_CACHE_FLUSH_THRESHOLD  500

typedef struct {
    void *method;
    int (*up_ref)(void *);
    void (*free)(void *);
} METHOD;

typedef struct {
    int nid;
    unsigned int insert_order;
    const OSSL_PROVIDER *provider;
    OSSL_PROPERTY_LIST *properties;
    METHOD method;
} IMPLEMENTATION;


typedef struct {
    const OSSL_PROVIDER *provider;
    const char *query;
    METHOD method;
    char body[1];
} QUERY;


typedef struct {
    int nid;
    HT *iqcache;
} ALGORITHM;

#define KEY_TYPE_QUERY 0
#define KEY_TYPE_IMPLEMENTATION 1
HT_START_KEY_DEFN(STOREKEY)
HT_DEF_KEY_FIELD(type, int)
HT_DEF_KEY_FIELD_CHAR_ARRAY(propq, 128)
HT_DEF_KEY_FIELD(provptr, const void *)
HT_END_KEY_DEFN(STOREKEY)

HT_START_KEY_DEFN(ALGKEY)
HT_DEF_KEY_FIELD(nid, int)
HT_END_KEY_DEFN(ALGKEY)

IMPLEMENT_HT_VALUE_TYPE_FNS(QUERY, store, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(IMPLEMENTATION, store, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(ALGORITHM, store, static)

struct ossl_method_store_st {
    OSSL_LIB_CTX *ctx;
    HT *algcache;
    unsigned int impl_order;

    /*
     * Lock to protect the |algs| array from concurrent writing, when
     * individual implementations or queries are inserted.  This is used
     * by the appropriate functions here.
     */
    CRYPTO_RWLOCK *lock;
    /*
     * Lock to reserve the whole store.  This is used when fetching a set
     * of algorithms, via these functions, found in crypto/core_fetch.c:
     * ossl_method_construct_reserve_store()
     * ossl_method_construct_unreserve_store()
     */
    CRYPTO_RWLOCK *biglock;

    /* query cache specific values */

    /* Count of the query cache entries for all algs */
    size_t cache_nelem;

    /* Flag: 1 if query cache entries for all algs need flushing */
    int cache_need_flush;
};

typedef struct {
    size_t nelem;
    uint32_t seed;
    unsigned char using_global_seed;
} IMPL_CACHE_FLUSH;

DEFINE_SPARSE_ARRAY_OF(ALGORITHM);

typedef struct ossl_global_properties_st {
    OSSL_PROPERTY_LIST *list;
#ifndef FIPS_MODULE
    unsigned int no_mirrored : 1;
#endif
} OSSL_GLOBAL_PROPERTIES;

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
                                        ALGORITHM *alg);
static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid);

/* Global properties are stored per library context */
void ossl_ctx_global_properties_free(void *vglobp)
{
    OSSL_GLOBAL_PROPERTIES *globp = vglobp;

    if (globp != NULL) {
        ossl_property_free(globp->list);
        OPENSSL_free(globp);
    }
}

void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *ctx)
{
    return OPENSSL_zalloc(sizeof(OSSL_GLOBAL_PROPERTIES));
}

OSSL_PROPERTY_LIST **ossl_ctx_global_properties(OSSL_LIB_CTX *libctx,
                                                ossl_unused int loadconfig)
{
    OSSL_GLOBAL_PROPERTIES *globp;

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)
    if (loadconfig && !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return NULL;
#endif
    globp = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES);

    return globp != NULL ? &globp->list : NULL;
}

#ifndef FIPS_MODULE
int ossl_global_properties_no_mirrored(OSSL_LIB_CTX *libctx)
{
    OSSL_GLOBAL_PROPERTIES *globp
        = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES);

    return globp != NULL && globp->no_mirrored ? 1 : 0;
}

void ossl_global_properties_stop_mirroring(OSSL_LIB_CTX *libctx)
{
    OSSL_GLOBAL_PROPERTIES *globp
        = ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_GLOBAL_PROPERTIES);

    if (globp != NULL)
        globp->no_mirrored = 1;
}
#endif

static int ossl_method_up_ref(METHOD *method)
{
    return (*method->up_ref)(method->method);
}

static void ossl_method_free(METHOD *method)
{
    (*method->free)(method->method);
}

static __owur int ossl_property_read_lock(OSSL_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_read_lock(p->lock) : 0;
}

static __owur int ossl_property_write_lock(OSSL_METHOD_STORE *p)
{
    return p != NULL ? CRYPTO_THREAD_write_lock(p->lock) : 0;
}

static int ossl_property_unlock(OSSL_METHOD_STORE *p)
{
    return p != 0 ? CRYPTO_THREAD_unlock(p->lock) : 0;
}

static void impl_free(IMPLEMENTATION *impl)
{
    if (impl != NULL) {
        ossl_method_free(&impl->method);
        OPENSSL_free(impl);
    }
}

static void impl_cache_free(QUERY *elem)
{
    if (elem != NULL) {
        ossl_method_free(&elem->method);
        OPENSSL_free(elem);
    }
}

static int is_query(HT_VALUE *v, void *arg)
{
    QUERY *q = ossl_ht_store_QUERY_from_value(v);

    if (q != NULL)
        return 1;
    return 0;
}

static int impl_cache_flush_alg(HT_VALUE *v, void *arg)
{
    ALGORITHM *alg = ossl_ht_store_ALGORITHM_from_value(v);

    if (alg != NULL) {
        ossl_ht_write_lock(alg->iqcache);
        ossl_ht_selective_delete(alg->iqcache, is_query, NULL);
        ossl_ht_write_unlock(alg->iqcache);
    }
    return 1;
}

static void alg_cleanup(ALGORITHM *a)
{
    if (a != NULL) {
        ossl_ht_free(a->iqcache);
        OPENSSL_free(a);
    }
}

static void cache_free(HT_VALUE *v)
{
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);
    QUERY *q = ossl_ht_store_QUERY_from_value(v);

    if (i != NULL)
        impl_free(i);
    if (q != NULL)
        impl_cache_free(q);
}

static void alg_free(HT_VALUE *v)
{
    ALGORITHM *alg = ossl_ht_store_ALGORITHM_from_value(v);

    if (alg != NULL)
        alg_cleanup(alg);
}

/*
 * The OSSL_LIB_CTX param here allows access to underlying property data needed
 * for computation
 */
OSSL_METHOD_STORE *ossl_method_store_new(OSSL_LIB_CTX *ctx)
{
    OSSL_METHOD_STORE *res;
    HT_CONFIG alg_conf = { ctx, alg_free, NULL, 0 };
    res = OPENSSL_zalloc(sizeof(*res));
    if (res != NULL) {
        res->ctx = ctx;
        if ((res->algcache = ossl_ht_new(&alg_conf)) == NULL
            || (res->lock = CRYPTO_THREAD_lock_new()) == NULL
            || (res->biglock = CRYPTO_THREAD_lock_new()) == NULL) {
            ossl_method_store_free(res);
            return NULL;
        }
    }
    return res;
}

void ossl_method_store_free(OSSL_METHOD_STORE *store)
{
    if (store != NULL) {
        if (store->algcache != NULL)
            ossl_ht_free(store->algcache);
        CRYPTO_THREAD_lock_free(store->lock);
        CRYPTO_THREAD_lock_free(store->biglock);
        OPENSSL_free(store);
    }
}

int ossl_method_lock_store(OSSL_METHOD_STORE *store)
{
    return store != NULL ? CRYPTO_THREAD_write_lock(store->biglock) : 0;
}

int ossl_method_unlock_store(OSSL_METHOD_STORE *store)
{
    return store != NULL ? CRYPTO_THREAD_unlock(store->biglock) : 0;
}

int ossl_method_store_add(OSSL_METHOD_STORE *store, const OSSL_PROVIDER *prov,
                          int nid, const char *properties, void *method,
                          int (*method_up_ref)(void *),
                          void (*method_destruct)(void *))
{
    ALGORITHM *alg = NULL;
    IMPLEMENTATION *impl;
    STOREKEY key;
    ALGKEY algkey;
    HT_VALUE *v;
    HT_CONFIG ht_conf = { store->ctx, cache_free, NULL, 0 };
    int ret = 0;

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;
    if (properties == NULL)
        properties = "";

    if (!ossl_assert(prov != NULL))
        return 0;

    /* Create new entry */
    impl = OPENSSL_malloc(sizeof(*impl));
    if (impl == NULL)
        return 0;
    impl->nid = nid;
    impl->method.method = method;
    impl->method.up_ref = method_up_ref;
    impl->method.free = method_destruct;
    if (!ossl_method_up_ref(&impl->method)) {
        OPENSSL_free(impl);
        return 0;
    }
    impl->provider = prov;

    /* Insert into the hash table if required */
    if (!ossl_property_write_lock(store)) {
        OPENSSL_free(impl);
        return 0;
    }
    ossl_method_cache_flush(store, nid);
    if ((impl->properties = ossl_prop_defn_get(store->ctx, properties)) == NULL) {
        impl->properties = ossl_parse_property(store->ctx, properties);
        if (impl->properties == NULL)
            goto err;
        if (!ossl_prop_defn_set(store->ctx, properties, &impl->properties)) {
            ossl_property_free(impl->properties);
            impl->properties = NULL;
            goto err;
        }
    }

    HT_INIT_KEY(&algkey);
    HT_SET_KEY_FIELD(&algkey, nid, nid);
    ossl_ht_read_lock(store->algcache);
    alg = ossl_ht_store_ALGORITHM_get(store->algcache, TO_HT_KEY(&algkey), &v);
    if (alg == NULL) {
        ossl_ht_read_unlock(store->algcache);
        if ((alg = OPENSSL_zalloc(sizeof(*alg))) == NULL
                || (alg->iqcache = ossl_ht_new(&ht_conf)) == NULL)
            goto err;
        alg->nid = nid;
        ossl_ht_write_lock(store->algcache);
        ossl_ht_store_ALGORITHM_insert(store->algcache,
                                       TO_HT_KEY(&algkey), alg, NULL);
        ossl_ht_write_unlock(store->algcache);
        ossl_ht_read_lock(store->algcache);
        alg = ossl_ht_store_ALGORITHM_get(store->algcache,
              TO_HT_KEY(&algkey), &v);
        if (alg == NULL)
            goto err;
    }

    HT_INIT_KEY(&key);
    HT_SET_KEY_FIELD(&key, type, KEY_TYPE_IMPLEMENTATION);
    HT_SET_KEY_STRING(&key, propq, properties);
    HT_SET_KEY_FIELD(&key, provptr, prov);
    ossl_ht_write_lock(alg->iqcache);
    impl->insert_order = store->impl_order++;
    if (!ossl_ht_store_IMPLEMENTATION_insert(alg->iqcache,
                                             TO_HT_KEY(&key), impl, NULL)) {

        /* This implementation already exists */
        impl_free(impl);
        ret = 0;
    } else {
        ret = 1;
    }
    ossl_ht_write_unlock(alg->iqcache);
    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    return ret;

err:
    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    alg_cleanup(alg);
    impl_free(impl);
    return 0;
}

struct del_impl_by_method {
    const void *method;
    int nid;
    int deleted_something;
};

static int should_del_impl_by_method(HT_VALUE *v, void *arg)
{
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);
    struct del_impl_by_method *data = (struct del_impl_by_method *)arg;

    if (i != NULL && i->method.method == data->method) {
        data->deleted_something = 1;
        return 1;
    }
    return 0;
}

int ossl_method_store_remove(OSSL_METHOD_STORE *store, int nid,
                             const void *method)
{
    ALGORITHM *alg = NULL;
    ALGKEY algkey;
    HT_VALUE *v;
    struct del_impl_by_method ddata = { method, nid, 0 };

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    if (!ossl_property_write_lock(store))
        return 0;
    ossl_method_cache_flush(store, nid);
    HT_INIT_KEY(&algkey);
    HT_SET_KEY_FIELD(&algkey, nid, nid);
    ossl_ht_read_lock(store->algcache);
    alg = ossl_ht_store_ALGORITHM_get(store->algcache, TO_HT_KEY(&algkey), &v);
    if (alg == NULL) {
        ossl_ht_read_unlock(store->algcache);
        ossl_property_unlock(store);
        return 0;
    }

    ossl_ht_write_lock(alg->iqcache);
    ossl_ht_selective_delete(alg->iqcache, should_del_impl_by_method, &ddata);
    ossl_ht_write_unlock(alg->iqcache);

    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    return ddata.deleted_something;
}

struct alg_cleanup_by_provider_data_st {
    OSSL_METHOD_STORE *store;
    const OSSL_PROVIDER *prov;
};

struct del_impl_by_prov {
    const OSSL_PROVIDER *prov;
    int del_some;
};

static int should_del_impl_by_provider_and_queries(HT_VALUE *v, void *arg)
{
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);
    QUERY *q = ossl_ht_store_QUERY_from_value(v);
    struct del_impl_by_prov *data = (struct del_impl_by_prov *)arg;

    if (i != NULL && i->provider == data->prov) {
        data->del_some = 1;
        return 1;
    }
    if (q != NULL)
        return 1;
    return 0;
}

static int
alg_cleanup_by_provider(HT_VALUE *v, void *arg)
{
    ALGORITHM *a = ossl_ht_store_ALGORITHM_from_value(v);
    struct alg_cleanup_by_provider_data_st *data = arg;
    struct del_impl_by_prov dp = { data->prov, 0 };

    if (a == NULL)
        return 1;
    ossl_ht_write_lock(a->iqcache);
    ossl_ht_selective_delete(a->iqcache, should_del_impl_by_provider_and_queries, &dp);
    ossl_ht_write_unlock(a->iqcache);
    return 1;
}

int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
                                          const OSSL_PROVIDER *prov)
{
    struct alg_cleanup_by_provider_data_st data;

    if (!ossl_property_write_lock(store))
        return 0;
    data.prov = prov;
    data.store = store;
    ossl_ht_read_lock(store->algcache);
    ossl_ht_foreach_until(store->algcache, alg_cleanup_by_provider, &data);
    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    return 1;
}

struct alg_do_each_data_st {
    void (*fn)(int id, void *method, void *fnarg);
    void *fnarg;
};

static int do_each_impl(HT_VALUE *v, void *arg)
{
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);
    struct alg_do_each_data_st *data = arg;

    if (i == NULL)
        return 1;

    data->fn(i->nid, i->method.method, data->fnarg);
    return 1;
}

static int alg_do_each(HT_VALUE *v, void *arg)
{
    ALGORITHM *alg = ossl_ht_store_ALGORITHM_from_value(v);
    if (v == NULL)
        return 1;
    ossl_ht_read_lock(alg->iqcache);
    ossl_ht_foreach_until(alg->iqcache, do_each_impl, arg);
    ossl_ht_read_unlock(alg->iqcache);
    return 1;
}

void ossl_method_store_do_all(OSSL_METHOD_STORE *store,
                              void (*fn)(int id, void *method, void *fnarg),
                              void *fnarg)
{
    struct alg_do_each_data_st data;

    data.fn = fn;
    data.fnarg = fnarg;
    if (store != NULL) {
        ossl_ht_read_lock(store->algcache);
        ossl_ht_foreach_until(store->algcache, alg_do_each, &data);
        ossl_ht_read_unlock(store->algcache);
    }
}

struct best_impl_data {
    IMPLEMENTATION *best;
    OSSL_PROPERTY_LIST *pq;
    const OSSL_PROVIDER *prov;
    int nid;
    int best_score;
    int best_order;
    int optional;
};

static int get_best_impl(HT_VALUE *v, void *arg)
{
    struct best_impl_data *data = (struct best_impl_data *)arg;
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);
    int score;

    if (i == NULL)
        return 1;

    if (i->nid != data->nid)
        return 1;

    if (data->pq == NULL) {
        if (data->prov == NULL || data->prov == i->provider) {
                data->best = i;
                return 0;
        }
    } else {
        if (data->prov == NULL || data->prov == i->provider) {
            score = ossl_property_match_count(data->pq, i->properties);
            if (score > data->best_score) {
                data->best = i;
                data->best_score = score;
                data->best_order = i->insert_order;
            } else if (score == data->best_score) {
                if (i->insert_order < data->best_order) {
                    data->best = i;
                    data->best_score = score;
                    data->best_order = i->insert_order;
                }
            }
        }
    }
    return 1;
}

int ossl_method_store_fetch(OSSL_METHOD_STORE *store,
                            int nid, const char *prop_query,
                            const OSSL_PROVIDER **prov_rw, void **method)
{
    OSSL_PROPERTY_LIST **plp;
    ALGORITHM *alg;
    ALGKEY algkey;
    HT_VALUE *v;
    IMPLEMENTATION *best_impl = NULL;
    OSSL_PROPERTY_LIST *pq = NULL, *p2 = NULL;
    const OSSL_PROVIDER *prov = prov_rw != NULL ? *prov_rw : NULL;
    int ret = 0;
    struct best_impl_data bd = { NULL, NULL, NULL, nid, -1, 0, 0 };

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_AUTOLOAD_CONFIG)
    if (ossl_lib_ctx_is_default(store->ctx)
            && !OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
        return 0;
#endif

    /* This only needs to be a read lock, because the query won't create anything */
    if (!ossl_property_read_lock(store))
        return 0;
    HT_INIT_KEY(&algkey);
    HT_SET_KEY_FIELD(&algkey, nid, nid);
    ossl_ht_read_lock(store->algcache);
    alg = ossl_ht_store_ALGORITHM_get(store->algcache, TO_HT_KEY(&algkey), &v);
    if (alg == NULL) {
        ossl_ht_read_unlock(store->algcache);
        ossl_property_unlock(store);
        return 0;
    }

    if (prop_query != NULL)
        p2 = pq = ossl_parse_query(store->ctx, prop_query, 0);
    plp = ossl_ctx_global_properties(store->ctx, 0);
    if (plp != NULL && *plp != NULL) {
        if (pq == NULL) {
            pq = *plp;
        } else {
            p2 = ossl_property_merge(pq, *plp);
            ossl_property_free(pq);
            if (p2 == NULL)
                goto fin;
            pq = p2;
        }
    }

    bd.optional = ossl_property_has_optional(pq);
    bd.pq = pq;
    bd.prov = prov;
    ossl_ht_read_lock(alg->iqcache);
    ossl_ht_foreach_until(alg->iqcache, get_best_impl, &bd);
    ossl_ht_read_unlock(alg->iqcache);
    best_impl = bd.best;
    if (best_impl != NULL)
        ret = 1;

fin:
    if (ret && ossl_method_up_ref(&best_impl->method)) {
        *method = best_impl->method.method;
        if (prov_rw != NULL)
            *prov_rw = best_impl->provider;
    } else {
        ret = 0;
    }
    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    ossl_property_free(p2);
    return ret;
}

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
                                        ALGORITHM *alg)
{
    size_t delta;

    ossl_ht_write_lock(alg->iqcache);
    delta = ossl_ht_count(alg->iqcache);
    ossl_ht_selective_delete(alg->iqcache, is_query, NULL);
    delta -= ossl_ht_count(alg->iqcache);
    ossl_ht_write_unlock(alg->iqcache);
    store->cache_nelem -= delta;
}

static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid)
{
    HT_VALUE *v;
    ALGKEY algkey;
    ALGORITHM *alg;

    HT_INIT_KEY(&algkey);
    HT_SET_KEY_FIELD(&algkey, nid, nid);

    ossl_ht_read_lock(store->algcache);
    alg = ossl_ht_store_ALGORITHM_get(store->algcache, TO_HT_KEY(&algkey), &v);
    if (alg != NULL)
        ossl_method_cache_flush_alg(store, alg);
    ossl_ht_read_unlock(store->algcache);
}

int ossl_method_store_cache_flush_all(OSSL_METHOD_STORE *store)
{
    if (!ossl_property_write_lock(store))
        return 0;
    ossl_ht_read_lock(store->algcache);
    ossl_ht_foreach_until(store->algcache, impl_cache_flush_alg, NULL);
    ossl_ht_read_unlock(store->algcache);
    store->cache_nelem = 0;
    ossl_property_unlock(store);
    return 1;
}

/*
 * Flush an element from the query cache (perhaps).
 *
 * In order to avoid taking a write lock or using atomic operations
 * to keep accurate least recently used (LRU) or least frequently used
 * (LFU) information, the procedure used here is to stochastically
 * flush approximately half the cache.
 *
 * This procedure isn't ideal, LRU or LFU would be better.  However,
 * in normal operation, reaching a full cache would be unexpected.
 * It means that no steady state of algorithm queries has been reached.
 * That is, it is most likely an attack of some form.  A suboptimal clearance
 * strategy that doesn't degrade performance of the normal case is
 * preferable to a more refined approach that imposes a performance
 * impact.
 */
static int is_query_random_del(HT_VALUE *v, void *arg)
{
    uint32_t n;
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)arg;
    QUERY *q = ossl_ht_store_QUERY_from_value(v);

    if (q == NULL)
        return 0;

    n = state->seed;
    n ^= n << 13;
    n ^= n >> 17;
    state->seed ^= n << 5;

    if ((n & 1) != 0)
        return 1;
    else
        state->nelem++;
    return 0;
}

static int impl_cache_flush_one_alg(HT_VALUE *v, void *arg)
{
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)arg;
    ALGORITHM *alg = ossl_ht_store_ALGORITHM_from_value(v);

    if (alg != NULL) {
        ossl_ht_write_lock(alg->iqcache);
        ossl_ht_selective_delete(alg->iqcache, is_query_random_del, state);
        ossl_ht_write_unlock(alg->iqcache);
    }
    return 1;
}

static void ossl_method_cache_flush_some(OSSL_METHOD_STORE *store)
{
    IMPL_CACHE_FLUSH state;
    static TSAN_QUALIFIER uint32_t global_seed = 1;

    state.nelem = 0;
    state.using_global_seed = 0;
    if ((state.seed = OPENSSL_rdtsc()) == 0) {
        /* If there is no timer available, seed another way */
        state.using_global_seed = 1;
        state.seed = tsan_load(&global_seed);
    }
    store->cache_need_flush = 0;
    ossl_ht_read_lock(store->algcache);
    ossl_ht_foreach_until(store->algcache, impl_cache_flush_one_alg, &state);
    ossl_ht_read_unlock(store->algcache);
    store->cache_nelem = state.nelem;
    /* Without a timer, update the global seed */
    if (state.using_global_seed)
        tsan_add(&global_seed, state.seed);
}

static int find_null_prov_match(HT_VALUE *v, void *arg)
{
    const char *prop_query = (const char *)arg;
    QUERY *q = ossl_ht_store_QUERY_from_value(v);

    if (q == NULL)
        return 0;
    if (!strcmp(q->query, prop_query))
        return 1;
    return 0;
}

int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void **method)
{
    ALGORITHM *alg;
    STOREKEY key;
    ALGKEY algkey;
    HT_VALUE *v;
    HT_VALUE_LIST *list;
    QUERY *r = NULL;
    int res = 0;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_property_read_lock(store))
        return 0;
    HT_INIT_KEY(&algkey);
    HT_SET_KEY_FIELD(&algkey, nid, nid);
    ossl_ht_read_lock(store->algcache);
    alg = ossl_ht_store_ALGORITHM_get(store->algcache, TO_HT_KEY(&algkey), &v);
    if (alg == NULL)
        goto err;

    if (prov == NULL) {
        ossl_ht_read_lock(alg->iqcache);
        list = ossl_ht_filter(alg->iqcache, 1, find_null_prov_match,
                              (void *)prop_query);
        if (list->list_len == 1) {
            r = ossl_ht_store_QUERY_from_value(list->list[0]);
            if (r != NULL && ossl_method_up_ref(&r->method)) {
                *method = r->method.method;
                res = 1;
            }
        }
        ossl_ht_value_list_free(list);
        ossl_ht_read_unlock(alg->iqcache);
    } else {
        HT_INIT_KEY(&key);
        HT_SET_KEY_FIELD(&key, type, KEY_TYPE_QUERY);
        HT_SET_KEY_STRING(&key, propq, prop_query);
        HT_SET_KEY_FIELD(&key, provptr, prov);
        ossl_ht_read_lock(alg->iqcache);
        r = ossl_ht_store_QUERY_get(alg->iqcache, TO_HT_KEY(&key), &v);
        if (r != NULL && ossl_method_up_ref(&r->method)) {
            *method = r->method.method;
            res = 1;
        }
        ossl_ht_read_unlock(alg->iqcache);
    }
err:
    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    return res;
}

int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void *method,
                                int (*method_up_ref)(void *),
                                void (*method_destruct)(void *))
{
    QUERY *p = NULL;
    ALGORITHM *alg;
    HT_VALUE *v;
    STOREKEY key;
    ALGKEY algkey;
    size_t len;
    int res = 1;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_assert(prov != NULL))
        return 0;

    if (!ossl_property_write_lock(store))
        return 0;
    if (store->cache_need_flush)
        ossl_method_cache_flush_some(store);
    HT_INIT_KEY(&algkey);
    HT_SET_KEY_FIELD(&algkey, nid, nid);
    ossl_ht_read_lock(store->algcache);
    alg = ossl_ht_store_ALGORITHM_get(store->algcache, TO_HT_KEY(&algkey), &v);
    if (alg == NULL)
        goto err;

    HT_INIT_KEY(&key);
    HT_SET_KEY_FIELD(&key, type, KEY_TYPE_QUERY);
    HT_SET_KEY_STRING(&key, propq, prop_query);
    HT_SET_KEY_FIELD(&key, provptr, prov);

    if (method == NULL) {
        ossl_ht_write_lock(alg->iqcache);
        ossl_ht_delete(alg->iqcache, TO_HT_KEY(&key));
        store->cache_nelem--;
        ossl_ht_write_unlock(alg->iqcache);
        goto end;
    }
    p = OPENSSL_malloc(sizeof(*p) + (len = strlen(prop_query)));
    if (p != NULL) {
        p->query = p->body;
        p->provider = prov;
        p->method.method = method;
        p->method.up_ref = method_up_ref;
        p->method.free = method_destruct;
        if (!ossl_method_up_ref(&p->method))
            goto err;
        memcpy((char *)p->query, prop_query, len + 1);
        ossl_ht_write_lock(alg->iqcache);
        if (!ossl_ht_store_QUERY_insert(alg->iqcache, TO_HT_KEY(&key),
                                        p, NULL)) {
            ossl_ht_write_unlock(alg->iqcache);
            impl_cache_free(p);
            goto end;
        }
        ossl_ht_write_unlock(alg->iqcache);

        if (++store->cache_nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
            store->cache_need_flush = 1;
        goto end;
    }
err:
    res = 0;
    OPENSSL_free(p);
end:
    ossl_ht_read_unlock(store->algcache);
    ossl_property_unlock(store);
    return res;
}
