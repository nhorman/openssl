/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include "crypto/cryptlib.h"
#include "internal/thread_once.h"
#include "internal/threads_common.h"

static void cleanup_cb(EX_CALLBACK *funcs)
{
    OPENSSL_free(funcs);
}

static void EX_CALLBACKS_free(EX_CALLBACKS *cbd)
{
    int ret;

    if (cbd == NULL)
        return;

    CRYPTO_DOWN_REF(&cbd->refcount, &ret);
    if (ret == 0) {
        sk_EX_CALLBACK_pop_free(cbd->meth, cleanup_cb);
        CRYPTO_FREE_REF(&cbd->refcount);
        OPENSSL_free(cbd);
    }
}

int ossl_do_ex_data_init(OSSL_LIB_CTX *ctx)
{
    OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);
    int i;

    if (global == NULL)
        return 0;
    memset(global->ex_data, 0, CRYPTO_EX_INDEX__COUNT * sizeof(EX_CALLBACKS *));
    global->ex_data_lock = CRYPTO_THREAD_lock_new();
    if (global->ex_data_lock == NULL)
        return 0;
    for (i = 0; i < CRYPTO_EX_INDEX__COUNT; i++) {
        global->ex_data[i] = OPENSSL_zalloc(sizeof(EX_CALLBACKS));
        if (global->ex_data[i] == NULL)
            goto err;
        if (!CRYPTO_NEW_REF(&global->ex_data[i]->refcount, 1))
            goto err;
    }
    return 1;
err:
    for (i = 0; i < CRYPTO_EX_INDEX__COUNT; i++) {
        EX_CALLBACKS_free(global->ex_data[i]);
        global->ex_data[i] = NULL;
    }
    CRYPTO_THREAD_lock_free(global->ex_data_lock);
    global->ex_data_lock = NULL;
    return 0;
}

typedef struct thread_local_ex_callbacks {
    uint64_t generation[CRYPTO_EX_INDEX__COUNT];
    EX_CALLBACKS *ex_data[CRYPTO_EX_INDEX__COUNT];
} TL_EX_CALLBACKS;

static void free_thread_local_ex_data(TL_EX_CALLBACKS *local_ex_cb, OSSL_LIB_CTX *ctx)
{
    int i;

    if (local_ex_cb != NULL) {
        for (i = 0; i < CRYPTO_EX_INDEX__COUNT; i++)
            EX_CALLBACKS_free(local_ex_cb->ex_data[i]);
        OPENSSL_free(local_ex_cb);
        CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_EX_CALLBACKS_KEY, ctx, NULL);
    }
}

static void clean_thread_local_ex_data(void *arg)
{
    OSSL_LIB_CTX *ctx = arg;
    TL_EX_CALLBACKS *local_ex_cb;

    local_ex_cb = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_EX_CALLBACKS_KEY, ctx);
    free_thread_local_ex_data(local_ex_cb, ctx);
}

static int rebuild_current_ex_callbacks(TL_EX_CALLBACKS *local_cb, OSSL_EX_DATA_GLOBAL *global)
{
    int i;
    int ret;

    if (!CRYPTO_THREAD_read_lock(global->ex_data_lock))
        return 0;

    for (i = 0; i < CRYPTO_EX_INDEX__COUNT; i++) {
        EX_CALLBACKS_free(local_cb->ex_data[i]);
        local_cb->generation[i] = global->ex_data[i]->generation;
        local_cb->ex_data[i] = global->ex_data[i];
        CRYPTO_UP_REF(&local_cb->ex_data[i]->refcount, &ret);
    }

    CRYPTO_THREAD_unlock(global->ex_data_lock);
    return 1;
}

static EX_CALLBACKS *get_current_ex_callbacks(OSSL_LIB_CTX *ctx, OSSL_EX_DATA_GLOBAL *global, int class_index)
{
    TL_EX_CALLBACKS *local_ex_cb;
    uint64_t my_generation;

    if (class_index < 0 || class_index >= CRYPTO_EX_INDEX__COUNT) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (global->ex_data_lock == NULL)
        return NULL;

    local_ex_cb = CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_EX_CALLBACKS_KEY, ctx);
    if (local_ex_cb == NULL) {
        local_ex_cb = OPENSSL_zalloc(sizeof(TL_EX_CALLBACKS));
        if (local_ex_cb == NULL)
            return NULL;
        if (!rebuild_current_ex_callbacks(local_ex_cb, global)) {
            free_thread_local_ex_data(local_ex_cb, ctx);
            return NULL;
        }
        if (!CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_EX_CALLBACKS_KEY, ctx, local_ex_cb)) {
            free_thread_local_ex_data(local_ex_cb, ctx);
            return NULL;
        }
        if (!ossl_init_thread_start(NULL, ossl_lib_ctx_get_concrete(ctx),
                clean_thread_local_ex_data)) {
            free_thread_local_ex_data(local_ex_cb, ctx);
            return NULL;
        }
    }

    /*
     * Get the current generation of this class in ex_data
     */
    CRYPTO_atomic_load(&global->ex_data[class_index]->generation, &my_generation, global->ex_data_lock);
    if (my_generation != local_ex_cb->generation[class_index]) {
        /*
         * Someone has updated ex data, need to reload
         */
        if (!rebuild_current_ex_callbacks(local_ex_cb, global)) {
            free_thread_local_ex_data(local_ex_cb, ctx);
            return NULL;
        }
    }
    /*
     * Now just return the appropriate index
     */
    return local_ex_cb->ex_data[class_index];
}

/*
 * Release all "ex_data" state to prevent memory leaks. This can't be made
 * thread-safe without overhauling a lot of stuff, and shouldn't really be
 * called under potential race-conditions anyway (it's for program shutdown
 * after all).
 */
void ossl_crypto_cleanup_all_ex_data_int(OSSL_LIB_CTX *ctx)
{
    int i;
    OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);

    if (global == NULL)
        return;

    for (i = 0; i < CRYPTO_EX_INDEX__COUNT; ++i)
        EX_CALLBACKS_free(global->ex_data[i]);

    CRYPTO_THREAD_lock_free(global->ex_data_lock);
    global->ex_data_lock = NULL;
}

/*
 * Unregister a new index by replacing the callbacks with no-ops.
 * Any in-use instances are leaked.
 */
static void dummy_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
    long argl, void *argp)
{
}

static void dummy_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
    long argl, void *argp)
{
}

static int dummy_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_d, int idx,
    long argl, void *argp)
{
    return 1;
}

static EX_CALLBACK *ex_cb_copy(const EX_CALLBACK *src)
{
    return OPENSSL_memdup(src, sizeof(EX_CALLBACK));
}

static void ex_cb_free(EX_CALLBACK *cb)
{
    OPENSSL_free(cb);
}

int ossl_crypto_free_ex_index_ex(OSSL_LIB_CTX *ctx, int class_index, int idx)
{
    EX_CALLBACKS *ip;
    EX_CALLBACKS *old = NULL;
    EX_CALLBACK *a;
    int toret = 0;
    OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);

    if (global == NULL)
        return 0;

    if (!CRYPTO_THREAD_write_lock(global->ex_data_lock))
        return 0;
    ip = OPENSSL_memdup(global->ex_data[class_index], sizeof(EX_CALLBACKS));
    if (ip == NULL) {
        CRYPTO_THREAD_unlock(global->ex_data_lock);
        return 0;
    }
    CRYPTO_NEW_REF(&ip->refcount, 1);
    ip->meth = sk_EX_CALLBACK_deep_copy(global->ex_data[class_index]->meth, ex_cb_copy, ex_cb_free);
    if (ip->meth == NULL) {
        OPENSSL_free(ip);
        CRYPTO_THREAD_unlock(global->ex_data_lock);
        return 0;
    }
    if (idx < 0 || idx >= sk_EX_CALLBACK_num(ip->meth)) {
        sk_EX_CALLBACK_pop_free(ip->meth, cleanup_cb);
        OPENSSL_free(ip);
        goto err;
    }

    a = sk_EX_CALLBACK_value(ip->meth, idx);
    if (a == NULL) {
        sk_EX_CALLBACK_pop_free(ip->meth, cleanup_cb);
        OPENSSL_free(ip);
        goto err;
    }
    a->new_func = dummy_new;
    a->dup_func = dummy_dup;
    a->free_func = dummy_free;
    ip->generation++;
    old = global->ex_data[class_index];
    global->ex_data[class_index] = ip;
    toret = 1;
err:
    CRYPTO_THREAD_unlock(global->ex_data_lock);
    EX_CALLBACKS_free(old);
    return toret;
}

int CRYPTO_free_ex_index(int class_index, int idx)
{
    return ossl_crypto_free_ex_index_ex(NULL, class_index, idx);
}

/*
 * Register a new index.
 */
int ossl_crypto_get_ex_new_index_ex(OSSL_LIB_CTX *ctx, int class_index,
    long argl, void *argp,
    CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func,
    CRYPTO_EX_free *free_func,
    int priority)
{
    int toret = -1;
    EX_CALLBACK *a;
    EX_CALLBACKS *ip, *old = NULL;
    OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);

    if (global == NULL)
        return -1;

    if (!CRYPTO_THREAD_write_lock(global->ex_data_lock))
        return -1;
    ip = OPENSSL_memdup(global->ex_data[class_index], sizeof(EX_CALLBACKS));
    if (ip == NULL) {
        CRYPTO_THREAD_unlock(global->ex_data_lock);
        return -1;
    }
    CRYPTO_NEW_REF(&ip->refcount, 1);
    if (ip->meth == NULL) {
        ip->meth = sk_EX_CALLBACK_new_null();
        /* We push an initial value on the stack because the SSL
         * "app_data" routines use ex_data index zero.  See RT 3710. */
        if (ip->meth == NULL
            || !sk_EX_CALLBACK_push(ip->meth, NULL)) {
            EX_CALLBACKS_free(ip);
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB);
            goto err;
        }
    } else {
        ip->meth = sk_EX_CALLBACK_deep_copy(global->ex_data[class_index]->meth, ex_cb_copy, ex_cb_free);
        if (ip->meth == NULL) {
            EX_CALLBACKS_free(ip);
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB);
            goto err;
        }
    }

    a = (EX_CALLBACK *)OPENSSL_malloc(sizeof(*a));
    if (a == NULL)
        goto err;
    a->argl = argl;
    a->argp = argp;
    a->new_func = new_func;
    a->dup_func = dup_func;
    a->free_func = free_func;
    a->priority = priority;

    if (!sk_EX_CALLBACK_push(ip->meth, NULL)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB);
        OPENSSL_free(a);
        EX_CALLBACKS_free(ip);
        goto err;
    }
    toret = sk_EX_CALLBACK_num(ip->meth) - 1;
    (void)sk_EX_CALLBACK_set(ip->meth, toret, a);
    ip->generation++;
    old = global->ex_data[class_index];
    global->ex_data[class_index] = ip;
err:
    CRYPTO_THREAD_unlock(global->ex_data_lock);
    EX_CALLBACKS_free(old);
    return toret;
}

int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
    CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
    CRYPTO_EX_free *free_func)
{
    return ossl_crypto_get_ex_new_index_ex(NULL, class_index, argl, argp,
        new_func, dup_func, free_func, 0);
}

/*
 * Initialise a new CRYPTO_EX_DATA for use in a particular class - including
 * calling new() callbacks for each index in the class used by this variable
 * Thread-safe by copying a class's array of "EX_CALLBACK" entries
 * in the lock, then using them outside the lock. Note this only applies
 * to the global "ex_data" state (ie. class definitions), not 'ad' itself.
 */
int ossl_crypto_new_ex_data_ex(OSSL_LIB_CTX *ctx, int class_index, void *obj,
    CRYPTO_EX_DATA *ad)
{
    int mx, i;
    void *ptr;
    EX_CALLBACK *idx;
    EX_CALLBACKS *ip;
    OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);

    if (global == NULL)
        return 0;

    ip = get_current_ex_callbacks(ctx, global, class_index);
    if (ip == NULL)
        return 0;

    ad->ctx = ctx;
    ad->sk = NULL;
    mx = sk_EX_CALLBACK_num(ip->meth);
    for (i = 0; i < mx; i++) {
        idx = sk_EX_CALLBACK_value(ip->meth, i);
        if (idx != NULL && idx->new_func != NULL) {
            ptr = CRYPTO_get_ex_data(ad, i);
            idx->new_func(obj, ptr, ad, i,
                idx->argl, idx->argp);
        }
    }
    return 1;
}

int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    return ossl_crypto_new_ex_data_ex(NULL, class_index, obj, ad);
}

/*
 * Duplicate a CRYPTO_EX_DATA variable - including calling dup() callbacks
 * for each index in the class used by this variable
 */
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
    const CRYPTO_EX_DATA *from)
{
    int mx, j, i;
    void *ptr;
    EX_CALLBACK *idx;
    EX_CALLBACKS *ip;
    int toret = 0;
    OSSL_EX_DATA_GLOBAL *global;

    to->ctx = from->ctx;
    if (from->sk == NULL)
        /* Nothing to copy over */
        return 1;

    global = ossl_lib_ctx_get_ex_data_global(from->ctx);
    if (global == NULL)
        return 0;

    ip = get_current_ex_callbacks(from->ctx, global, class_index);
    if (ip == NULL)
        return 0;

    mx = sk_EX_CALLBACK_num(ip->meth);
    j = sk_void_num(from->sk);
    if (j < mx)
        mx = j;

    if (mx == 0)
        return 1;
    /*
     * Make sure the ex_data stack is at least |mx| elements long to avoid
     * issues in the for loop that follows; so go get the |mx|'th element
     * (if it does not exist CRYPTO_get_ex_data() returns NULL), and assign
     * to itself. This is normally a no-op; but ensures the stack is the
     * proper size
     */
    if (!CRYPTO_set_ex_data(to, mx - 1, CRYPTO_get_ex_data(to, mx - 1)))
        goto err;

    for (i = 0; i < mx; i++) {
        idx = sk_EX_CALLBACK_value(ip->meth, i);
        ptr = CRYPTO_get_ex_data(from, i);
        if (idx != NULL && idx->dup_func != NULL)
            if (!idx->dup_func(to, from, &ptr, i,
                    idx->argl, idx->argp))
                goto err;
        CRYPTO_set_ex_data(to, i, ptr);
    }
    toret = 1;
err:
    return toret;
}

struct ex_callback_entry {
    const EX_CALLBACK *excb;
    int index;
};

static int ex_callback_compare(const void *a, const void *b)
{
    const struct ex_callback_entry *ap = (const struct ex_callback_entry *)a;
    const struct ex_callback_entry *bp = (const struct ex_callback_entry *)b;

    if (ap->excb == bp->excb)
        return 0;

    if (ap->excb == NULL)
        return 1;
    if (bp->excb == NULL)
        return -1;
    if (ap->excb->priority == bp->excb->priority)
        return 0;
    return ap->excb->priority > bp->excb->priority ? -1 : 1;
}

/*
 * Cleanup a CRYPTO_EX_DATA variable - including calling free() callbacks for
 * each index in the class used by this variable
 */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    int mx, i;
    EX_CALLBACKS *ip;
    void *ptr;
    const EX_CALLBACK *f;
    struct ex_callback_entry stack[10];
    struct ex_callback_entry *storage = NULL;
    OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ad->ctx);

    if (global == NULL)
        goto err;

    ip = get_current_ex_callbacks(ad->ctx, global, class_index);
    if (ip == NULL)
        goto err;

    mx = sk_EX_CALLBACK_num(ip->meth);
    if (mx > 0) {
        if (mx < (int)OSSL_NELEM(stack))
            storage = stack;
        else
            storage = OPENSSL_malloc_array(mx, sizeof(*storage));
        if (storage != NULL)
            for (i = 0; i < mx; i++) {
                storage[i].excb = sk_EX_CALLBACK_value(ip->meth, i);
                storage[i].index = i;
            }
    }

    if (storage != NULL) {
        /* Sort according to priority. High priority first */
        qsort(storage, mx, sizeof(*storage), ex_callback_compare);
        for (i = 0; i < mx; i++) {
            f = storage[i].excb;

            if (f != NULL && f->free_func != NULL) {
                ptr = CRYPTO_get_ex_data(ad, storage[i].index);
                f->free_func(obj, ptr, ad, storage[i].index, f->argl, f->argp);
            }
        }
    }

    if (storage != stack)
        OPENSSL_free(storage);
err:
    sk_void_free(ad->sk);
    ad->sk = NULL;
    ad->ctx = NULL;
}

/*
 * Allocate a given CRYPTO_EX_DATA item using the class specific allocation
 * function
 */
int CRYPTO_alloc_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad,
    int idx)
{
    void *curval;

    curval = CRYPTO_get_ex_data(ad, idx);
    /* Already there, no need to allocate */
    if (curval != NULL)
        return 1;

    return ossl_crypto_alloc_ex_data_intern(class_index, obj, ad, idx);
}

int ossl_crypto_alloc_ex_data_intern(int class_index, void *obj,
    CRYPTO_EX_DATA *ad, int idx)
{
    EX_CALLBACK *f;
    EX_CALLBACKS *ip;
    OSSL_EX_DATA_GLOBAL *global;

    global = ossl_lib_ctx_get_ex_data_global(ad->ctx);
    if (global == NULL)
        return 0;

    ip = get_current_ex_callbacks(ad->ctx, global, class_index);
    if (ip == NULL)
        return 0;
    f = sk_EX_CALLBACK_value(ip->meth, idx);

    /*
     * This should end up calling CRYPTO_set_ex_data(), which allocates
     * everything necessary to support placing the new data in the right spot.
     */
    if (f->new_func == NULL)
        return 0;

    f->new_func(obj, NULL, ad, idx, f->argl, f->argp);

    return 1;
}

/*
 * For a given CRYPTO_EX_DATA variable, set the value corresponding to a
 * particular index in the class used by this variable
 */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val)
{
    int i;

    if (ad->sk == NULL) {
        if ((ad->sk = sk_void_new_null()) == NULL) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB);
            return 0;
        }
    }

    for (i = sk_void_num(ad->sk); i <= idx; ++i) {
        if (!sk_void_push(ad->sk, NULL)) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB);
            return 0;
        }
    }
    if (sk_void_set(ad->sk, idx, val) != val) {
        /* Probably the index is out of bounds */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    return 1;
}

/*
 * For a given CRYPTO_EX_DATA_ variable, get the value corresponding to a
 * particular index in the class used by this variable
 */
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx)
{
    if (ad->sk == NULL || idx >= sk_void_num(ad->sk))
        return NULL;
    return sk_void_value(ad->sk, idx);
}
