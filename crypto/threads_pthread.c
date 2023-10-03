/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use the OPENSSL_fork_*() deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/crypto.h>
#include "internal/cryptlib.h"

#if defined(__sun)
# include <atomic.h>
#endif

#if defined(__apple_build_version__) && __apple_build_version__ < 6000000
/*
 * OS/X 10.7 and 10.8 had a weird version of clang which has __ATOMIC_ACQUIRE and
 * __ATOMIC_ACQ_REL but which expects only one parameter for __atomic_is_lock_free()
 * rather than two which has signature __atomic_is_lock_free(sizeof(_Atomic(T))).
 * All of this makes impossible to use __atomic_is_lock_free here.
 *
 * See: https://github.com/llvm/llvm-project/commit/a4c2602b714e6c6edb98164550a5ae829b2de760
 */
#define BROKEN_CLANG_ATOMICS
#endif

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG) && !defined(OPENSSL_SYS_WINDOWS)

# if defined(OPENSSL_SYS_UNIX)
#  include <sys/types.h>
#  include <unistd.h>
#endif

# include <assert.h>

# ifdef PTHREAD_RWLOCK_INITIALIZER
#  define USE_RWLOCK
# endif

static pthread_key_t rcu_thr_key;

struct rcu_thr_data;

/*
 * users is broken up into 2 parts
 * bits 0-15 current readers
 * bit 32-63 - ID
 */
# define READER_SHIFT 0
# define ID_SHIFT 32
# define READER_SIZE 16
# define ID_SIZE 32

# define READER_MASK     (((uint64_t)1 << READER_SIZE)-1)
# define ID_MASK         (((uint64_t)1 << ID_SIZE)-1)
# define READER_COUNT(x) (((uint64_t)(x) >> READER_SHIFT) & READER_MASK)
# define ID_VAL(x)       (((uint64_t)(x) >> ID_SHIFT) & ID_MASK)
# define VAL_READER      ((uint64_t)1 << READER_SHIFT)
# define VAL_ID(x)       ((uint64_t)x << ID_SHIFT)

/*
 * This is the core of an rcu lock
 * it tracks the the readers and writers
 * for the current quiescence point for
 * a given lock
 * users is the 64 bit value that stores
 * the READERS/ID as defined
 * above
 *
 */
struct rcu_qp {
    uint64_t users;
};

/*
 * This is the per thread tracking data
 * that is assigned to each thread participating
 * in an rcu qp
 *
 * qp points to the qp that it last acquired
 *
 * count is the threads current recursion count
 */
struct rcu_thr_data {
    struct rcu_qp *qp;
    int count;
};

/*
 * This is the internal version of a CRYPTO_RCU_LOCK
 * it is cast from CRYPTO_RCU_LOCK
 */
struct rcu_lock_internal {
    CRYPTO_RCU_LOCK lock; /* Must be first */
    struct rcu_cb_item *cb_items;
    uint32_t id_ctr;
    struct rcu_qp *qp_group;
    size_t group_count;
    uint32_t reader_idx;
    uint32_t next_to_retire;
    uint32_t current_alloc_idx;
    uint32_t writers_alloced;
    pthread_mutex_t write_lock;
    pthread_mutex_t alloc_lock;
    pthread_cond_t alloc_signal;
    pthread_mutex_t prior_lock;
    pthread_cond_t prior_signal;
};

/*
 * Called on thread exit to free the pthread key
 * associated with this thread, if any
 */
static void free_rcu_thr_data(void *ptr)
{
    struct rcu_thr_data *data = ptr;

# ifdef SANITY_CHECKS
    if (data->qp != NULL)
        abort();
# endif
    CRYPTO_free(data, __FILE__, __LINE__);
}

/*
 * Called from OPENSSL_SSL_init to initalize the
 * rcu lock system
 */
void CRYPTO_THREAD_rcu_init(void)
{
    pthread_key_create(&rcu_thr_key, free_rcu_thr_data);
}

/*
 * Read side acquisition of the current qp
 */
static inline struct rcu_qp *get_hold_current_qp(CRYPTO_RCU_LOCK *lock)
{
    uint32_t qp_idx;
    struct rcu_lock_internal *ilock =
        (struct rcu_lock_internal *)lock;

    /*
     * get the current qp index
     */
    qp_idx = __atomic_load_n(&ilock->reader_idx, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&ilock->qp_group[qp_idx].users, VAL_READER,
                       __ATOMIC_SEQ_CST);

    return (struct rcu_qp *)&ilock->qp_group[qp_idx];
}

/*
 * Public READ lock api
 */
void CRYPTO_THREAD_rcu_read_lock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_thr_data *data;

    /*
     * we're going to access current_qp here so ask the
     * processor to fetch it
     */
    data = pthread_getspecific(rcu_thr_key);

    if (unlikely(data == NULL)) {
        data = CRYPTO_zalloc(sizeof(struct rcu_thr_data), NULL, 0);
# ifdef SANITY_CHECKS
        if (data == NULL)
            abort();
# endif
        pthread_setspecific(rcu_thr_key, data);
    }

    if (likely(data->qp == NULL))
        data->qp = get_hold_current_qp(lock);

    /* inc our local count */
    data->count++;

    /* check for underflow condition */
# ifdef SANITY_CHECKS
    if (data->count <= 0)
        abort();
# endif
}

/*
 * Public READ unlock api
 */
void CRYPTO_THREAD_rcu_read_unlock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_thr_data *data = pthread_getspecific(rcu_thr_key);
    uint64_t count;
    struct rcu_lock_internal *ilock =
        (struct rcu_lock_internal *)lock;

# ifdef SANITY_CHECKS
    if (data == NULL)
        abort();
# endif

    data->count--;

# ifdef SANITY_CHECKS
    if (data->count < 0)
        abort();
# endif

    if (data->count == 0) {
        count = __atomic_sub_fetch(&data->qp->users, VAL_READER,
                                   __ATOMIC_SEQ_CST);
        data->qp = NULL;
    }
}

/*
 * Write side allocation routine to get the current qp
 * and replace it with a new one
 */
static struct rcu_qp *update_qp(struct rcu_lock_internal *ilock)
{
    uint64_t new_id;
    uint64_t old_users;
    uint32_t current_idx;

    pthread_mutex_lock(&ilock->alloc_lock);

    /*
     * we need at least one qp to be available with one
     * left over, so that readers can start working on
     * one that isn't yet being waited on
     */
    while (ilock->group_count - ilock->writers_alloced < 2) {
        /*
         * we have to wait for one to be free
         */
        pthread_cond_wait(&ilock->alloc_signal, &ilock->alloc_lock);
    }

    current_idx = ilock->current_alloc_idx;
    /*
     * Allocate the qp
     */
    ilock->writers_alloced++;

    /*
     * increment the allocation index
     */
    ilock->current_alloc_idx =
        (ilock->current_alloc_idx + 1) % ilock->group_count;

    /*
     * get and insert a new id
     */
    new_id = __atomic_fetch_add(&ilock->id_ctr, 1, __ATOMIC_SEQ_CST);

    new_id = VAL_ID(new_id);
    __atomic_and_fetch(&ilock->qp_group[current_idx].users, ID_MASK,
                       __ATOMIC_SEQ_CST);
    __atomic_or_fetch(&ilock->qp_group[current_idx].users, new_id,
                      __ATOMIC_SEQ_CST);

    /*
     * update the reader index to be the prior qp
     */
    __atomic_store_n(&ilock->reader_idx, ilock->current_alloc_idx,
                     __ATOMIC_SEQ_CST);

    /*
     * wake up any waiters
     */
    pthread_cond_signal(&ilock->alloc_signal);
    pthread_mutex_unlock(&ilock->alloc_lock);
    return (struct rcu_qp *)&ilock->qp_group[current_idx];
}

static void retire_qp(struct rcu_lock_internal *ilock,
                      struct rcu_qp *qp)
{
    pthread_mutex_lock(&ilock->alloc_lock);
    ilock->writers_alloced--;
    pthread_cond_signal(&ilock->alloc_signal);
    pthread_mutex_unlock(&ilock->alloc_lock);
}

static struct rcu_qp *allocate_new_qp_group(struct rcu_lock_internal *ilock,
                                            int count)
{
    int i;
    struct rcu_qp *new =
        CRYPTO_zalloc(sizeof(struct rcu_qp) * count, NULL, 0);

    ilock->group_count = count;
    return new;
}

/*
 * Public WRITE api
 */
void CRYPTO_THREAD_rcu_write_lock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_lock_internal *ilock = (struct rcu_lock_internal *)lock;

    pthread_mutex_lock(&ilock->write_lock);
}

/*
 * Public READ api
 */
void CRYPTO_THREAD_rcu_write_unlock(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_lock_internal *ilock = (struct rcu_lock_internal *)lock;

    pthread_mutex_unlock(&ilock->write_lock);
}

/*
 * Public WRITE api for synchronization
 */
void CRYPTO_THREAD_synchronize_rcu(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_qp *qp, *prior_qp, *tmpqp;
    struct rcu_lock_internal *ilock;
    uint64_t count;
    struct rcu_cb_item *cb_items, *tmpcb;

    /*
     * before we do anything else, lets grab the cb list
     */
    ilock = (struct rcu_lock_internal *)lock;
    cb_items = __atomic_exchange_n(&ilock->cb_items, NULL, __ATOMIC_SEQ_CST);

    qp = update_qp(ilock);

    /*
     * wait for the reader count to reach zero
     */
    do {
        count = __atomic_load_n(&qp->users, __ATOMIC_SEQ_CST);
    } while (READER_COUNT(count) != 0);

    /*
     * retire in order
     */
    pthread_mutex_lock(&ilock->prior_lock);
    while (ilock->next_to_retire != ID_VAL(count))
        pthread_cond_wait(&ilock->prior_signal, &ilock->prior_lock);
    ilock->next_to_retire++;
    pthread_cond_broadcast(&ilock->prior_signal);
    pthread_mutex_unlock(&ilock->prior_lock);

    retire_qp(ilock, qp);

    /*
     * handle any callbacks that we have
     */
    while (cb_items != NULL) {
        tmpcb = cb_items;
        cb_items = cb_items->next;
        tmpcb->fn(tmpcb->data);
        CRYPTO_free(tmpcb, NULL, 0);
    }
    /*
     * and we're done
     */
    return;
}

/*
 * Public WRITE api to schedule a callback after a
 * completed synchronization
 */
void CRYPTO_THREAD_rcu_call(CRYPTO_RCU_LOCK *lock, rcu_cb_fn cb, void *data)
{
    struct rcu_cb_item *new =
        CRYPTO_zalloc(sizeof(struct rcu_cb_item), NULL, 0);
    struct rcu_lock_internal *ilock = (struct rcu_lock_internal *)lock;

    new->data = data;
    new->fn = cb;
    new->next = __atomic_exchange_n(&ilock->cb_items, new, __ATOMIC_SEQ_CST);
}

/*
 * Public READ/WRITE api to get the value of a pointer
 */
void *CRYPTO_THREAD_rcu_uptr_derefrence(uintptr_t *p)
{
    return (void *)__atomic_load_n(p, __ATOMIC_ACQUIRE);
}

/*
 * Public WRITE api to assign a pointer value
 */
void CRYPTO_THREAD_rcu_assign_uptr(uintptr_t *p, uintptr_t *v)
{
    __atomic_store(p, v, __ATOMIC_RELEASE);
}

/*
 * Public api to allocate a new rcu lock
 */
CRYPTO_RCU_LOCK *CRYPTO_THREAD_rcu_lock_new(void)
{
    struct rcu_lock_internal *new =
        CRYPTO_zalloc(sizeof(struct rcu_lock_internal), NULL, 0);

    if (new == NULL)
        return NULL;

    pthread_mutex_init(&new->write_lock, NULL);
    pthread_mutex_init(&new->prior_lock, NULL);
    pthread_mutex_init(&new->alloc_lock, NULL);
    pthread_cond_init(&new->prior_signal, NULL);
    pthread_cond_init(&new->alloc_signal, NULL);
    new->qp_group = allocate_new_qp_group(new, 2);
    if (new->qp_group == NULL) {
        CRYPTO_free(new, NULL, 0);
        new = NULL;
    }
    return (CRYPTO_RCU_LOCK *)new;
}

/*
 * Public api to free an rcu lock
 */
void CRYPTO_THREAD_rcu_lock_free(CRYPTO_RCU_LOCK *lock)
{
    struct rcu_lock_internal *ilock =
        (struct rcu_lock_internal *)lock;

    /* make sure we're sycchronized */
    CRYPTO_THREAD_synchronize_rcu(lock);

    CRYPTO_free(ilock->qp_group, NULL, 0);
    /*
     * There should only be a single qp left now
     */
    CRYPTO_free(lock, NULL, 0);
}

CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)
{
# ifdef USE_RWLOCK
    CRYPTO_RWLOCK *lock;

    if ((lock = CRYPTO_zalloc(sizeof(pthread_rwlock_t), NULL, 0)) == NULL)
        /* Don't set error, to avoid recursion blowup. */
        return NULL;

    if (pthread_rwlock_init(lock, NULL) != 0) {
        OPENSSL_free(lock);
        return NULL;
    }
# else
    pthread_mutexattr_t attr;
    CRYPTO_RWLOCK *lock;

    if ((lock = CRYPTO_zalloc(sizeof(pthread_mutex_t), NULL, 0)) == NULL)
        /* Don't set error, to avoid recursion blowup. */
        return NULL;

    /*
     * We don't use recursive mutexes, but try to catch errors if we do.
     */
    pthread_mutexattr_init(&attr);
#  if !defined (__TANDEM) && !defined (_SPT_MODEL_)
#   if !defined(NDEBUG) && !defined(OPENSSL_NO_MUTEX_ERRORCHECK)
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#   endif
#  else
    /* The SPT Thread Library does not define MUTEX attributes. */
#  endif

    if (pthread_mutex_init(lock, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        OPENSSL_free(lock);
        return NULL;
    }

    pthread_mutexattr_destroy(&attr);
# endif

    return lock;
}

__owur int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_rdlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_lock(lock) != 0) {
        assert(errno != EDEADLK && errno != EBUSY);
        return 0;
    }
# endif

    return 1;
}

__owur int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_wrlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_lock(lock) != 0) {
        assert(errno != EDEADLK && errno != EBUSY);
        return 0;
    }
# endif

    return 1;
}

int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)
{
# ifdef USE_RWLOCK
    if (pthread_rwlock_unlock(lock) != 0)
        return 0;
# else
    if (pthread_mutex_unlock(lock) != 0) {
        assert(errno != EPERM);
        return 0;
    }
# endif

    return 1;
}

void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)
{
    if (lock == NULL)
        return;

# ifdef USE_RWLOCK
    pthread_rwlock_destroy(lock);
# else
    pthread_mutex_destroy(lock);
# endif
    OPENSSL_free(lock);

    return;
}

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (pthread_once(once, init) != 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    if (pthread_key_create(key, cleanup) != 0)
        return 0;

    return 1;
}

void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)
{
    return pthread_getspecific(*key);
}

int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (pthread_setspecific(*key, val) != 0)
        return 0;

    return 1;
}

int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (pthread_key_delete(*key) != 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)
{
    return pthread_self();
}

int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return pthread_equal(a, b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_add_fetch(val, amount, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_add_int_nv((volatile unsigned int *)val, amount);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;

    *val += amount;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_or(uint64_t *val, uint64_t op, uint64_t *ret,
                     CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQ_REL) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        *ret = __atomic_or_fetch(val, op, __ATOMIC_ACQ_REL);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_or_64_nv(val, op);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_write_lock(lock))
        return 0;
    *val |= op;
    *ret  = *val;

    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        __atomic_load(val, ret, __ATOMIC_ACQUIRE);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = atomic_or_64_nv(val, 0);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_read_lock(lock))
        return 0;
    *ret  = *val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock)
{
# if defined(__GNUC__) && defined(__ATOMIC_ACQUIRE) && !defined(BROKEN_CLANG_ATOMICS)
    if (__atomic_is_lock_free(sizeof(*val), val)) {
        __atomic_load(val, ret, __ATOMIC_ACQUIRE);
        return 1;
    }
# elif defined(__sun) && (defined(__SunOS_5_10) || defined(__SunOS_5_11))
    /* This will work for all future Solaris versions. */
    if (ret != NULL) {
        *ret = (int *)atomic_or_uint_nv((unsigned int *)val, 0);
        return 1;
    }
# endif
    if (lock == NULL || !CRYPTO_THREAD_read_lock(lock))
        return 0;
    *ret  = *val;
    if (!CRYPTO_THREAD_unlock(lock))
        return 0;

    return 1;
}

# ifndef FIPS_MODULE
int openssl_init_fork_handlers(void)
{
    return 1;
}
# endif /* FIPS_MODULE */

int openssl_get_fork_id(void)
{
    return getpid();
}
#endif
