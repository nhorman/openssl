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

DEFINE_LHASH_OF_EX(QUERY);

typedef struct {
    int nid;
    HT *iqcache;
    LHASH_OF(QUERY) *cache;
} ALGORITHM;

#define KEY_TYPE_QUERY 0
#define KEY_TYPE_IMPLEMENTATION 1
HT_START_KEY_DEFN(STOREKEY)
HT_DEF_KEY_FIELD(nid, int)
HT_DEF_KEY_FIELD(type, int)
HT_DEF_KEY_FIELD_CHAR_ARRAY(propq, 128)
HT_DEF_KEY_FIELD(provptr, const void *)
HT_END_KEY_DEFN(STOREKEY)

IMPLEMENT_HT_VALUE_TYPE_FNS(QUERY, store, static)
IMPLEMENT_HT_VALUE_TYPE_FNS(IMPLEMENTATION, store, static)

struct ossl_method_store_st {
    OSSL_LIB_CTX *ctx;
    SPARSE_ARRAY_OF(ALGORITHM) *algs;
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
    LHASH_OF(QUERY) *cache;
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

static unsigned long query_hash(const QUERY *a)
{
    return OPENSSL_LH_strhash(a->query);
}

static int query_cmp(const QUERY *a, const QUERY *b)
{
    int res = strcmp(a->query, b->query);

    if (res == 0 && a->provider != NULL && b->provider != NULL)
        res = b->provider > a->provider ? 1
            : b->provider < a->provider ? -1
            : 0;
    return res;
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

static void impl_cache_flush_alg(ossl_uintmax_t idx, ALGORITHM *alg)
{
    lh_QUERY_doall(alg->cache, &impl_cache_free);
    lh_QUERY_flush(alg->cache);
}

static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a, void *arg)
{
    OSSL_METHOD_STORE *store = arg;

    if (a != NULL) {
        ossl_ht_free(a->iqcache);
        lh_QUERY_doall(a->cache, &impl_cache_free);
        lh_QUERY_free(a->cache);
        OPENSSL_free(a);
    }
    if (store != NULL)
        ossl_sa_ALGORITHM_set(store->algs, idx, NULL);
}

static void cache_free(HT_VALUE *v)
{
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);

    if (i != NULL)
        impl_free(i);
}

/*
 * The OSSL_LIB_CTX param here allows access to underlying property data needed
 * for computation
 */
OSSL_METHOD_STORE *ossl_method_store_new(OSSL_LIB_CTX *ctx)
{
    OSSL_METHOD_STORE *res;

    res = OPENSSL_zalloc(sizeof(*res));
    if (res != NULL) {
        res->ctx = ctx;
        if ((res->algs = ossl_sa_ALGORITHM_new()) == NULL
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
        if (store->algs != NULL)
            ossl_sa_ALGORITHM_doall_arg(store->algs, &alg_cleanup, store);
        ossl_sa_ALGORITHM_free(store->algs);
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

static ALGORITHM *ossl_method_store_retrieve(OSSL_METHOD_STORE *store, int nid)
{
    return ossl_sa_ALGORITHM_get(store->algs, nid);
}

static int ossl_method_store_insert(OSSL_METHOD_STORE *store, ALGORITHM *alg)
{
    return ossl_sa_ALGORITHM_set(store->algs, alg->nid, alg);
}

int ossl_method_store_add(OSSL_METHOD_STORE *store, const OSSL_PROVIDER *prov,
                          int nid, const char *properties, void *method,
                          int (*method_up_ref)(void *),
                          void (*method_destruct)(void *))
{
    ALGORITHM *alg = NULL;
    IMPLEMENTATION *impl;
    STOREKEY key;
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

    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        if ((alg = OPENSSL_zalloc(sizeof(*alg))) == NULL
                || (alg->iqcache = ossl_ht_new(&ht_conf)) == NULL
                || (alg->cache = lh_QUERY_new(&query_hash, &query_cmp)) == NULL)
            goto err;
        alg->nid = nid;
        if (!ossl_method_store_insert(store, alg))
            goto err;
    }

    HT_INIT_KEY(&key);
    HT_SET_KEY_FIELD(&key, nid, nid);
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
    ossl_property_unlock(store);
    return ret;

err:
    ossl_property_unlock(store);
    alg_cleanup(0, alg, NULL);
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

    if (i != NULL && data->nid == i->nid && i->method.method == data->method) {
        data->deleted_something = 1;
        return 1;
    }
    return 0;
}

int ossl_method_store_remove(OSSL_METHOD_STORE *store, int nid,
                             const void *method)
{
    ALGORITHM *alg = NULL;
    struct del_impl_by_method ddata = { method, nid, 0 };

    if (nid <= 0 || method == NULL || store == NULL)
        return 0;

    if (!ossl_property_write_lock(store))
        return 0;
    ossl_method_cache_flush(store, nid);
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
        ossl_property_unlock(store);
        return 0;
    }

    ossl_ht_write_lock(alg->iqcache);
    ossl_ht_selective_delete(alg->iqcache, should_del_impl_by_method, &ddata);
    ossl_ht_write_unlock(alg->iqcache);
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

static int should_del_impl_by_provider(HT_VALUE *v, void *arg)
{
    IMPLEMENTATION *i = ossl_ht_store_IMPLEMENTATION_from_value(v);
    struct del_impl_by_prov *data = (struct del_impl_by_prov *)arg;

    if (i != NULL && i->provider == data->prov) {
        data->del_some = 1;
        return 1;
    }
    return 0;
}

static void
alg_cleanup_by_provider(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
    struct alg_cleanup_by_provider_data_st *data = arg;
    struct del_impl_by_prov dp = { data->prov, 0 };

    ossl_ht_write_lock(alg->iqcache);
    ossl_ht_selective_delete(alg->iqcache, should_del_impl_by_provider, &dp);
    ossl_ht_write_unlock(alg->iqcache);

    ossl_method_cache_flush_alg(data->store, alg);
}

int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
                                          const OSSL_PROVIDER *prov)
{
    struct alg_cleanup_by_provider_data_st data;

    if (!ossl_property_write_lock(store))
        return 0;
    data.prov = prov;
    data.store = store;
    ossl_sa_ALGORITHM_doall_arg(store->algs, &alg_cleanup_by_provider, &data);
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

static void alg_do_each(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
    ossl_ht_read_lock(alg->iqcache);
    ossl_ht_foreach_until(alg->iqcache, do_each_impl, arg);
    ossl_ht_read_unlock(alg->iqcache);
}

void ossl_method_store_do_all(OSSL_METHOD_STORE *store,
                              void (*fn)(int id, void *method, void *fnarg),
                              void *fnarg)
{
    struct alg_do_each_data_st data;

    data.fn = fn;
    data.fnarg = fnarg;
    if (store != NULL)
        ossl_sa_ALGORITHM_doall_arg(store->algs, alg_do_each, &data);
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
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL) {
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
    ossl_property_unlock(store);
    ossl_property_free(p2);
    return ret;
}

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
                                        ALGORITHM *alg)
{
    store->cache_nelem -= lh_QUERY_num_items(alg->cache);
    impl_cache_flush_alg(0, alg);
}

static void ossl_method_cache_flush(OSSL_METHOD_STORE *store, int nid)
{
    ALGORITHM *alg = ossl_method_store_retrieve(store, nid);

    if (alg != NULL)
        ossl_method_cache_flush_alg(store, alg);
}

int ossl_method_store_cache_flush_all(OSSL_METHOD_STORE *store)
{
    if (!ossl_property_write_lock(store))
        return 0;
    ossl_sa_ALGORITHM_doall(store->algs, &impl_cache_flush_alg);
    store->cache_nelem = 0;
    ossl_property_unlock(store);
    return 1;
}

IMPLEMENT_LHASH_DOALL_ARG(QUERY, IMPL_CACHE_FLUSH);

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
static void impl_cache_flush_cache(QUERY *c, IMPL_CACHE_FLUSH *state)
{
    uint32_t n;

    /*
     * Implement the 32 bit xorshift as suggested by George Marsaglia in:
     *      https://doi.org/10.18637/jss.v008.i14
     *
     * This is a very fast PRNG so there is no need to extract bits one at a
     * time and use the entire value each time.
     */
    n = state->seed;
    n ^= n << 13;
    n ^= n >> 17;
    n ^= n << 5;
    state->seed = n;

    if ((n & 1) != 0)
        impl_cache_free(lh_QUERY_delete(state->cache, c));
    else
        state->nelem++;
}

static void impl_cache_flush_one_alg(ossl_uintmax_t idx, ALGORITHM *alg,
                                     void *v)
{
    IMPL_CACHE_FLUSH *state = (IMPL_CACHE_FLUSH *)v;

    state->cache = alg->cache;
    lh_QUERY_doall_IMPL_CACHE_FLUSH(state->cache, &impl_cache_flush_cache,
                                    state);
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
    ossl_sa_ALGORITHM_doall_arg(store->algs, &impl_cache_flush_one_alg, &state);
    store->cache_nelem = state.nelem;
    /* Without a timer, update the global seed */
    if (state.using_global_seed)
        tsan_add(&global_seed, state.seed);
}

int ossl_method_store_cache_get(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void **method)
{
    ALGORITHM *alg;
    QUERY elem, *r;
    int res = 0;

    if (nid <= 0 || store == NULL || prop_query == NULL)
        return 0;

    if (!ossl_property_read_lock(store))
        return 0;
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL)
        goto err;

    elem.query = prop_query;
    elem.provider = prov;
    r = lh_QUERY_retrieve(alg->cache, &elem);
    if (r == NULL)
        goto err;
    if (ossl_method_up_ref(&r->method)) {
        *method = r->method.method;
        res = 1;
    }
err:
    ossl_property_unlock(store);
    return res;
}

int ossl_method_store_cache_set(OSSL_METHOD_STORE *store, OSSL_PROVIDER *prov,
                                int nid, const char *prop_query, void *method,
                                int (*method_up_ref)(void *),
                                void (*method_destruct)(void *))
{
    QUERY elem, *old, *p = NULL;
    ALGORITHM *alg;
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
    alg = ossl_method_store_retrieve(store, nid);
    if (alg == NULL)
        goto err;

    if (method == NULL) {
        elem.query = prop_query;
        elem.provider = prov;
        if ((old = lh_QUERY_delete(alg->cache, &elem)) != NULL) {
            impl_cache_free(old);
            store->cache_nelem--;
        }
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
        if ((old = lh_QUERY_insert(alg->cache, p)) != NULL) {
            impl_cache_free(old);
            goto end;
        }
        if (!lh_QUERY_error(alg->cache)) {
            if (++store->cache_nelem >= IMPL_CACHE_FLUSH_THRESHOLD)
                store->cache_need_flush = 1;
            goto end;
        }
        ossl_method_free(&p->method);
    }
err:
    res = 0;
    OPENSSL_free(p);
end:
    ossl_property_unlock(store);
    return res;
}
