/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <string.h>
#include <internal/refcount.h>
#include <internal/rcu.h>
#include <internal/hashtable.h>
#include <openssl/rand.h>

#include "internal/numbers.h"

#ifndef INT128_MAX
# error "Your compiler doesn't appear to support 128-bit integer types"
#endif


static ossl_unused uint64_t fnv1a_hash(uint8_t *key, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x00000100000001B3ULL;
    }
    return hash;
}

/*
 * Define our bucket list length
 * Note: It should always be a power of 2
 */
#define DEFAULT_BUCKET_LEN_LOG 4
#define DEFAULT_BUCKET_LEN (1 << DEFAULT_BUCKET_LEN_LOG)
#define BUCKET_MASK (DEFAULT_BUCKET_LEN - 1)
/*
 * Defines our chains of values
 */
struct ht_internal_value {
    HT_VALUE value;
    uint64_t hash;
    CRYPTO_REF_COUNT *cnt;
    HT *ht;
    struct ht_internal_value *next;
    struct ht_internal_value *prev;
};

/*
 * A bucket holds a chain of values
 */
struct ht_bucket {
    struct ht_internal_value *vals;
};

/*
 * Updates to data in this struct
 * require an rcu sync after modification
 * prior to free
 */
struct ht_mutable_data_st {
    struct ht_bucket *buckets;
    uint64_t bucket_mask;
};

/*
 * Private data may be updated on the write
 * side only, and so do not require rcu sync
 */
struct ht_write_private_data {
    size_t bucket_len;
    size_t value_count;
    size_t rehash_value_target;
};

struct ht_internal_st {
    HT_CONFIG config;
    CRYPTO_RCU_LOCK *lock;
    struct ht_mutable_data_st *md;
    struct ht_write_private_data wpd;
};

static inline void free_value(struct ht_internal_value *v);

static struct ht_bucket *alloc_new_bucket_list(size_t len)
{
    return OPENSSL_zalloc(sizeof(struct ht_bucket) * len);
}

static int compute_max_load(size_t num_buckets)
{
    double target;

    /*
     * we don't want a load over .75, so compute the number
     * of entries that would give us that load
     */
    target = num_buckets/0.75;
    return(int)target; /* truncation is fine here */
}

HT *ossl_ht_new(HT_CONFIG *conf)
{
    HT *new = OPENSSL_zalloc(sizeof(*new));

    if (new == NULL)
        return NULL;

    memcpy(&new->config, conf, sizeof(*conf));

    if (new->config.init_bucket_len != 0) {
        new->wpd.bucket_len = new->config.init_bucket_len;
        /* round up to the next power of 2 */
        new->wpd.bucket_len--;
        new->wpd.bucket_len |= new->wpd.bucket_len >> 1;
        new->wpd.bucket_len |= new->wpd.bucket_len >> 2;
        new->wpd.bucket_len |= new->wpd.bucket_len >> 4;
        new->wpd.bucket_len |= new->wpd.bucket_len >> 8;
        new->wpd.bucket_len |= new->wpd.bucket_len >> 16;
        new->wpd.bucket_len++;
    } else {
        new->wpd.bucket_len = DEFAULT_BUCKET_LEN;
    }

    new->wpd.rehash_value_target = compute_max_load(new->wpd.bucket_len);
    new->md = OPENSSL_zalloc(sizeof(*new->md));
    if (new->md == NULL)
        goto err;

    new->md->buckets = alloc_new_bucket_list(new->wpd.bucket_len);
    if (new->md->buckets == NULL)
        goto err;
    new->md->bucket_mask = new->wpd.bucket_len - 1;

    new->lock = ossl_rcu_lock_new(1);
    if (new->lock == NULL)
        goto err;

    if (new->config.ht_hash_fn == NULL)
        new->config.ht_hash_fn = fnv1a_hash;

    return new;

err:
    ossl_rcu_lock_free(new->lock);
    OPENSSL_free(new->md->buckets);
    OPENSSL_free(new->md);
    OPENSSL_free(new);
    return NULL;
}

static int ossl_ht_flush_internal(HT *h, int replace)
{
    struct ht_mutable_data_st *newmd = NULL;
    struct ht_mutable_data_st *oldmd = NULL;
    int i, bucket_len;
    struct ht_internal_value *vidx, *tmpidx;
    size_t values;

    newmd = OPENSSL_zalloc(sizeof(*newmd));
    if (newmd == NULL)
        return 0;

    ossl_rcu_write_lock(h->lock);

    bucket_len = h->wpd.bucket_len;

    if (replace == 1) {
        newmd->buckets = alloc_new_bucket_list(bucket_len);
        if (newmd->buckets == NULL) {
            OPENSSL_free(newmd);
            return 0;
        }
    }

    newmd->bucket_mask = h->md->bucket_mask;

    /* Swap the old and new mutable data sets */
    oldmd = h->md;
    ossl_rcu_assign_ptr(&h->md, &newmd);

    /* Set the number of entries to 0 */
    values = h->wpd.value_count;
    h->wpd.value_count = 0;
    /* Now we can drop the write lock */
    ossl_rcu_write_unlock(h->lock);

    /* Synchronize the rcu lock */
    ossl_synchronize_rcu(h->lock);

    /*
     * We are now guaranteed that oldmd has no more readers
     * and so we can free the data
     */
    for (i = 0; i < bucket_len && values > 0; i++) {
        vidx = oldmd->buckets[i].vals;
        while (vidx != NULL) {
            tmpidx = vidx->next;
            ossl_ht_put((HT_VALUE *)vidx);
            if (vidx->cnt == NULL) {
                if (vidx->ht->config.ht_free_fn)
                    vidx->ht->config.ht_free_fn((HT_VALUE *)vidx);
                free_value(vidx);
            }
            vidx = tmpidx;
            values--;
        }
    }
    OPENSSL_free(oldmd->buckets);
    OPENSSL_free(oldmd);
    return 1;
}

int ossl_ht_flush(HT *h)
{
    /*
     * flushing isn't allowed in lockless read mode
     */
    if (h->config.lockless_read)
        return 0;
    return ossl_ht_flush_internal(h, 1);
}

void ossl_ht_free(HT *h)
{
    if (h == NULL)
        return;
    /*
     * Note, its the responsibility of the caller to ensure
     * that there are no further readers if we are doing
     * lockless reads.
     */
    ossl_ht_flush_internal(h, 0);
    ossl_rcu_lock_free(h->lock);
    /* Don't need to free md->buckets, as we didn't replace it */
    OPENSSL_free(h->md);
    OPENSSL_free(h);
    return;
}

size_t ossl_ht_count(HT *h)
{
    size_t count;

    ossl_rcu_write_lock(h->lock);
    count = h->wpd.value_count;
    ossl_rcu_write_unlock(h->lock);
    return count;
}

void ossl_ht_foreach(HT *h, void (*cb)(HT_VALUE *obj, void *arg),
                     void *arg)
{
    size_t i;
    struct ht_mutable_data_st *md;
    struct ht_internal_value *vidx;

    if (!h->config.lockless_read)
        ossl_rcu_read_lock(h->lock);
    md = ossl_rcu_deref(&h->md);
    for (i = 0; i < md->bucket_mask + 1; i++) {
        vidx = md->buckets[i].vals;
        while (vidx != NULL) {
            cb(&vidx->value, arg);
            vidx = vidx->next;
        }
    }
    if (!h->config.lockless_read)
        ossl_rcu_read_unlock(h->lock);
}

void ossl_ht_foreach_until(HT *h, int (*cb)(HT_VALUE *obj, void *arg),
                           void *arg)
{
    size_t i;
    struct ht_mutable_data_st *md;
    struct ht_internal_value *vidx;

    if (!h->config.lockless_read)
        ossl_rcu_read_lock(h->lock);
    md = ossl_rcu_deref(&h->md);
    for (i = 0; i < md->bucket_mask + 1; i++) {
        vidx = md->buckets[i].vals;
        while (vidx != NULL) {
            if (!cb(&vidx->value, arg))
                goto out;
            vidx = vidx->next;
        }
    }
out:
    if (!h->config.lockless_read)
        ossl_rcu_read_unlock(h->lock);
}
HT_VALUE_LIST *ossl_ht_filter(HT *h, size_t max_len,
                                     int (*filter)(HT_VALUE *obj, void *arg),
                                     void *arg)
{
    struct ht_mutable_data_st *md;
    HT_VALUE_LIST *list = OPENSSL_zalloc(sizeof(HT_VALUE_LIST)
                                         + (sizeof(HT_VALUE *) * max_len));
    struct ht_internal_value *vidx;
    size_t i;
    int ref;

    if (list == NULL)
        return NULL;

    /*
     * The list array lives just beyond the end of
     * the struct
     */
    list->list = (HT_VALUE **)(list + 1);

    if (!h->config.lockless_read)
        ossl_rcu_read_lock(h->lock);
    md = ossl_rcu_deref(&h->md);
    for (i = 0; i < md->bucket_mask + 1; i++) {
        for (vidx = md->buckets[i].vals; vidx != NULL; vidx = vidx->next) {
            if(filter(&vidx->value, arg)) {
                if (vidx->cnt != NULL)
                    CRYPTO_UP_REF(vidx->cnt, &ref);
                list->list[list->list_len++] = &vidx->value;
                if (list->list_len == max_len)
                    goto out;
            }
        }
    }
out:
    if (!h->config.lockless_read)
        ossl_rcu_read_unlock(h->lock);
    return list;
}

void ossl_ht_value_list_free(HT_VALUE_LIST *list)
{
    size_t i;

    for (i = 0; i < list->list_len; i++)
        if (list->list[i] != NULL)
            ossl_ht_put(list->list[i]);

    OPENSSL_free(list);
}

static inline int compare_hash(uint64_t hash1, uint64_t hash2)
{
    return (hash1 == hash2);
}

void ossl_ht_put(HT_VALUE *val)
{
    int ref;
    struct ht_internal_value *v = (struct ht_internal_value *)val;

    if (v == NULL)
        return;

    if (v->cnt != NULL)
        CRYPTO_DOWN_REF(v->cnt, &ref);
    else
        ref = 1; /* don't free on put if we dont refcount */

    if (ref == 0) {
        /* make sure no readers are touching this */
        ossl_synchronize_rcu(v->ht->lock);
        if (v->ht->config.ht_free_fn)
            v->ht->config.ht_free_fn(val);
        free_value(v);
    }
}


static void retire_old_md(void *data)
{
    struct ht_mutable_data_st *md = (struct ht_mutable_data_st *)data;
    size_t bucket_len = md->bucket_mask + 1;
    struct ht_internal_value *vidx, *tmpidx;
    size_t i;

    for (i = 0; i < bucket_len; i++) {
        vidx = md->buckets[i].vals;
        while (vidx != NULL) {
            tmpidx = vidx->next;
            OPENSSL_free(vidx);
            vidx = tmpidx;
        }
    }
    OPENSSL_free(md->buckets);
    OPENSSL_free(md);
}

/*
 * Increase hash table bucket list
 * must be called with write_lock held
 */
static int grow_hashtable(HT *h)
{
    struct ht_mutable_data_st *newmd = OPENSSL_zalloc(sizeof(*newmd));
    struct ht_mutable_data_st *oldmd = NULL;
    int rc = 0;
    size_t oldi, newi;
    struct ht_internal_value *newv, *vidx, *tmpidx;

    if (newmd == NULL)
        goto out;

    /* bucket list is always a power of 2 */
    newmd->buckets = alloc_new_bucket_list(h->wpd.bucket_len * 2 );
    if (newmd->buckets == NULL)
        goto out_free;

    /* being a power of 2 makes for easy mask computation */
    newmd->bucket_mask = ((h->wpd.bucket_len * 2) - 1);

    /*
     * Now we need to start rehashing entries
     * Note we don't need to use atomics here as the new
     * mutable data hasn't been published
     */
    for (oldi = 0; oldi < h->wpd.bucket_len; oldi++) {
        vidx = h->md->buckets[oldi].vals;
        for(vidx = h->md->buckets[oldi].vals;
            vidx != NULL; vidx = vidx->next) {
            newv = OPENSSL_memdup(vidx, sizeof(*vidx));
            if (newv == NULL)
                goto out_free;
            newv->prev = newv->next = NULL;
            newi = newv->hash & newmd->bucket_mask;
            newv->next = newmd->buckets[newi].vals;
            newmd->buckets[newi].vals = newv;
            if (newv->next != NULL)
                newv->next->prev = newv;
        }
    }

    /*
     * Now that our entries are all hashed into the new bucket list
     * update our bucket_len and target_max_load
     */
    h->wpd.bucket_len *= 2;
    h->wpd.rehash_value_target = compute_max_load(h->wpd.bucket_len);

    /*
     * Now we replace the old mutable data with the new
     */
    oldmd = ossl_rcu_deref(&h->md);
    ossl_rcu_assign_ptr(&h->md, &newmd);
    ossl_rcu_call(h->lock, retire_old_md, oldmd);

    /*
     * And we're done
     */
    rc = 1;

out:
    return rc;
out_free:
    if (newmd->buckets != NULL) {
        for (newi = 0; newi < h->wpd.bucket_len * 2; newi++) {
            vidx = newmd->buckets[newi].vals;
            while (vidx != NULL) {
                tmpidx = vidx->next;
                OPENSSL_free(vidx);
                vidx = tmpidx;
           }
        }
    }
    OPENSSL_free(newmd->buckets);
    OPENSSL_free(newmd);
    goto out;
}

static inline int ossl_ht_insert_locked(HT *h,
                                               struct ht_internal_value *newval,
                                               HT_VALUE **olddata)
{
    struct ht_internal_value *vidx = NULL;
    uint64_t bucket_idx = newval->hash & h->md->bucket_mask;

    vidx = h->md->buckets[bucket_idx].vals;
    while (vidx != NULL) {
        if (compare_hash(vidx->hash, newval->hash)) {
            /* We found a matching hash */
            if (olddata == NULL) {
                /* We are not doing a replace, error */
                return 0;
            } else {
                /* This is a replacement request */
                newval->next = vidx->next;
                newval->prev = vidx->prev;
                *olddata = (HT_VALUE *)vidx;

                /*
                 * This atomically makes the replacement
                 * so any subsequent readers, won't see the old value
                 * NOTE: Because we are returning the old value
                 * to the caller, theres no need for a sync and free
                 * here, as the caller will call ossl_ht_put on the
                 * returned data
                 */
                ossl_rcu_assign_ptr(&vidx->prev->next, &newval);
                ossl_rcu_assign_ptr(&vidx->next->prev, &newval);
                return 1;
            }
        }
        vidx = vidx->next;
    }

    /*
     * If we get here, there is no duplicate entry
     * just add it to the end of the list
     */
    h->wpd.value_count++;
    newval->next = h->md->buckets[bucket_idx].vals;
    if (newval->next)
        newval->next->prev = newval;
    ossl_rcu_assign_ptr(&h->md->buckets[bucket_idx].vals, &newval);
    return 1;
}

static inline struct ht_internal_value *alloc_new_value(HT *h, HT_KEY *key,
                                                        void *data,
                                                        uint32_t type)
{
    struct ht_internal_value *new;

    new  = OPENSSL_zalloc(sizeof(*new) + sizeof(*new->cnt));

    if (new == NULL)
        return NULL;


    if (h->config.dont_refcount) {
        new->cnt = NULL;
    } else {
        new->cnt = (CRYPTO_REF_COUNT *)(new + 1);
        if (!CRYPTO_NEW_REF(new->cnt, 1)) {
            OPENSSL_free(new);
            return NULL;
        }
    }

    new->ht = h;
    new->value.value = data;
    new->value.type_id = type;
    new->hash = h->config.ht_hash_fn(key->keybuf, key->keysize);

    return new;
}

static inline void free_value(struct ht_internal_value *v)
{
    if (v->cnt != NULL)
        CRYPTO_FREE_REF(v->cnt);
    OPENSSL_free(v);
}

int ossl_ht_insert(HT *h, HT_KEY *key, HT_VALUE *data, HT_VALUE **olddata)
{
    struct ht_internal_value *newval = NULL;
    int rc = 0;
    int need_sync = 0;

    if (data->value == NULL)
        goto out;

    newval = alloc_new_value(h, key, data->value, data->type_id);
    if (newval == NULL)
        goto out;

    /*
     * we have to take our lock here to prevent other changes
     * to the bucket list
     */
    ossl_rcu_write_lock(h->lock);

    /*
     * First check to see if we need a rehash
     * Note: If we are doing lockless reads, we
     * can't grow the hash table, as we won't know
     * when its safe to delete the old md
     */
    if (!h->config.lockless_read
        && h->wpd.value_count > h->wpd.rehash_value_target) {
        if (!grow_hashtable(h))
            goto out_free_unlock;
        else
            need_sync = 1;
    }
    rc = ossl_ht_insert_locked(h, newval, olddata);

    if (rc == 0)
        goto out_free_unlock;

    ossl_rcu_write_unlock(h->lock);
out:
    if (need_sync)
        ossl_synchronize_rcu(h->lock);
    return rc;
out_free_unlock:
    ossl_rcu_write_unlock(h->lock);
    free_value(newval);
    goto out;
}

HT_VALUE *ossl_ht_get(HT *h, HT_KEY *key)
{
    struct ht_mutable_data_st *md;
    uint64_t hash;
    struct ht_internal_value *vidx = NULL;
    int ref;
    HT_VALUE *ret = NULL;

    hash = h->config.ht_hash_fn(key->keybuf, key->keysize);

    if (!h->config.lockless_read)
        ossl_rcu_read_lock(h->lock);
    md = ossl_rcu_deref(&h->md);
    vidx = md->buckets[hash & md->bucket_mask].vals;
    while (vidx != NULL) {
        if (compare_hash(hash, vidx->hash)) {
            /*
             * Found a match, grab a refcount
             */
            if (vidx->cnt != NULL)
                CRYPTO_UP_REF(vidx->cnt, &ref);
            ret = (HT_VALUE *)vidx;
            break;
        }
        vidx = vidx->next;
    }
    if (!h->config.lockless_read)
        ossl_rcu_read_unlock(h->lock);
    return ret;
}

HT_VALUE *ossl_ht_delete(HT *h, HT_KEY *key)
{
    uint64_t hash;
    struct ht_internal_value *vidx = NULL;
    uint64_t bucket_idx;

    /*
     * We don't allow deletion when doing lockless read
     */
    if (h->config.lockless_read)
        return 0;

    hash = h->config.ht_hash_fn(key->keybuf, key->keysize);

    ossl_rcu_write_lock(h->lock);
    bucket_idx = hash & h->md->bucket_mask;
    vidx = h->md->buckets[bucket_idx].vals;
    while (vidx != NULL) {
        if (compare_hash(hash, vidx->hash)) {
            /* found our entry */
            h->wpd.value_count--;
            if (vidx->prev)
                ossl_rcu_assign_ptr(&vidx->prev->next, &vidx->next);
            if (vidx->next)
                ossl_rcu_assign_ptr(&vidx->next->prev, &vidx->prev);
            if (vidx == h->md->buckets[bucket_idx].vals)
                ossl_rcu_assign_ptr(&h->md->buckets[bucket_idx].vals, &vidx->next);

            /* Note, we don't drop the ref count here, thats the callers job */
            break;
        }
        vidx = vidx->next;
    }
    ossl_rcu_write_unlock(h->lock);
    if (vidx && !vidx->cnt) {
        ossl_synchronize_rcu(h->lock);
        if (h->config.ht_free_fn)
            h->config.ht_free_fn((HT_VALUE *)vidx);
        free_value(vidx);
        return NULL;
    }
    return (HT_VALUE *)vidx;
}

