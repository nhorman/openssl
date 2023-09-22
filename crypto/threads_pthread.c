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
#  include <linux/futex.h>
#  include <sys/syscall.h>
#endif

# include <assert.h>

# ifdef PTHREAD_RWLOCK_INITIALIZER
#  define USE_RWLOCK
# endif

#define FUTEX_IS_UNAVAILABLE 0
#define FUTEX_IS_AVAILABLE 1
static int
futex(volatile uint32_t *uaddr, int futex_op, uint32_t val,
      const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
   return syscall(SYS_futex, uaddr, futex_op, val,
                  timeout, uaddr2, val3);
}

/* Acquire the futex pointed to by 'futexp': wait for its value to
  become 1, and then set the value to 0. */

static void inline
fwait(volatile uint32_t *futexp)
{
    long            s;
    uint32_t  one = 1;
    while (1) {
        /* Is the futex available? */
        if (__atomic_compare_exchange_n(futexp, &one, 0, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            break;      /* Yes */

        /* Futex is not available; wait. */
        s = futex(futexp, FUTEX_WAIT, 0, NULL, NULL, 0);
        if (s == -1 && errno != EAGAIN)
            abort();
    }
}

static void inline
fpost(volatile uint32_t *futexp)
{
    long            s;
    uint32_t  zero = 0;

    if (__atomic_compare_exchange_n(futexp, &zero, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        s = futex(futexp, FUTEX_WAKE, 1, NULL, NULL, 0);
        if (s  == -1)
            abort();
    }
}

pthread_key_t rcu_thr_key;

struct rcu_thr_data;

/*
 * users is broken up into 4 parts
 * bits 0-15 current readers
 * bits 16-24 current writers 
 * bits 25-31 current users
 * bit 32-63 - ID
 */
#define READER_SHIFT 0
#define WRITER_SHIFT 16 
#define USER_SHIFT 24
#define ID_SHIFT 32 
#define READER_SIZE 16
#define WRITER_SIZE 8
#define USER_SIZE 8
#define ID_SIZE 32

#define READER_MASK     (((uint64_t)1 << READER_SIZE)-1)
#define WRITER_MASK     (((uint64_t)1 << WRITER_SIZE)-1)
#define USER_MASK       (((uint64_t)1 << USER_SIZE)-1)
#define ID_MASK         (((uint64_t)1 << ID_SIZE)-1)
#define READER_COUNT(x) (((uint64_t)(x) >> READER_SHIFT) & READER_MASK)
#define WRITER_COUNT(x) (((uint64_t)(x) >> WRITER_SHIFT) & WRITER_MASK) 
#define USER_COUNT(x)   (((uint64_t)(x) >> USER_SHIFT) & USER_MASK)
#define ID_VAL(x)       (((uint64_t)(x) >> ID_SHIFT) & ID_MASK) 
#define VAL_READER      ((uint64_t)1 << READER_SHIFT)
#define VAL_WRITER      ((uint64_t)1 << WRITER_SHIFT)
#define VAL_USER        ((uint64_t)1 << USER_SHIFT)
#define VAL_ID(x)       ((uint64_t)x << ID_SHIFT)

struct rcu_qp {
    volatile uint64_t users;
    volatile uint32_t futex;
    volatile uint32_t prior_complete;
    volatile struct rcu_qp *next;
};

struct rcu_thr_data {
    volatile struct rcu_qp *qp;
    int count;
};

static volatile struct rcu_qp *current_qp = NULL;

static void free_rcu_thr_data(void *ptr)
{
    struct rcu_thr_data *data = ptr;
    if (data->qp != NULL)
        abort();
    CRYPTO_free(data, __FILE__, __LINE__);
}
 
void CRYPTO_THREAD_rcu_init(void)
{
    pthread_key_create(&rcu_thr_key, free_rcu_thr_data);
    current_qp = CRYPTO_zalloc(sizeof(struct rcu_qp), NULL, 0);
    current_qp->futex = 0; /*start locked */
    current_qp->users = VAL_ID(1);
}

static pthread_mutex_t qp_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t  id_ctr = 1;

static inline volatile struct rcu_qp* swap_current_qp(volatile struct rcu_qp *new)
{
    uint64_t count;
    volatile struct rcu_qp *old_qp;

    pthread_mutex_lock(&qp_lock);
    count = __atomic_add_fetch(&id_ctr, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&new->users, VAL_ID(count), __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&current_qp->users, VAL_WRITER, __ATOMIC_SEQ_CST);
    /* exchange the current qp for a new one */
    __atomic_store_n(&new->next, current_qp, __ATOMIC_SEQ_CST);
    old_qp = __atomic_exchange_n(&current_qp, new, __ATOMIC_SEQ_CST);
    pthread_mutex_unlock(&qp_lock);
    return old_qp;
}

static inline volatile struct rcu_qp* get_hold_current_qp(void)
{
    uint32_t id;
    uint64_t old_count;
    uint64_t count;
#ifdef SANITY_CHECKS
    uint64_t tmp;
    uint64_t tmp_mask;
    uint32_t tmp_ctr;
#endif
    volatile struct rcu_qp *old_qp;
    count = __atomic_add_fetch(&current_qp->users, VAL_READER+VAL_USER, __ATOMIC_SEQ_CST);
    id = ID_VAL(count);

#ifdef SANITY_CHECKS
    tmp_ctr = __atomic_load_n(&id_ctr, __ATOMIC_SEQ_CST);
    if (USER_COUNT(count) == 0)
        abort();
    /* sanity check */
    tmp = VAL_ID(id);
    tmp_mask = ~ID_MASK;
    if (tmp != (count & tmp_mask))
        abort();
    if (id == 0)
        abort();
    /* overflow check */
    if (USER_COUNT(count) == 0)
        abort();
#endif

    /* Now that we've taken our refcount, find the qp by its id */
    old_qp = current_qp; 
    do {
        if (ID_VAL(old_qp->users) == id)
            break;
        old_qp = old_qp->next;
    } while (old_qp != NULL);

#ifdef SANITY_CHECKS
    if (old_qp == NULL) {
        fprintf(stderr, "id %x is missing from list, try again\n", id);
        abort();
    }
#endif
    __atomic_fetch_sub(&old_qp->users, VAL_USER, __ATOMIC_SEQ_CST);
    return old_qp;
}

void CRYPTO_THREAD_rcu_read_lock(void)
{
    struct rcu_thr_data *data;

    /*
     * we're going to access current_qp here so ask the 
     * processor to fetch it
     */
    __builtin_prefetch(&current_qp, 1, 3);
    data = pthread_getspecific(rcu_thr_key);

    if (unlikely(data == NULL)) {
        data = CRYPTO_zalloc(sizeof(struct rcu_thr_data), NULL, 0);
        if (data == NULL)
            abort();
        data->qp = NULL;
        pthread_setspecific(rcu_thr_key, data);
    }

    if (likely(data->qp == NULL))
        data->qp = get_hold_current_qp();

    /* inc our local count */
    data->count++;

    /* check for underflow condition */
#ifdef SANITY_CHECKS
    if (data->count <= 0)
        abort();
#endif
}


void CRYPTO_THREAD_rcu_read_unlock(void)
{
    struct rcu_thr_data *data = pthread_getspecific(rcu_thr_key);
    uint64_t count;

    /*
     * we're likely to access data->qp, so lets fetch it now
     */
    __builtin_prefetch(&data, 1, 3);

#ifdef SANITY_CHECKS
    if (data == NULL)
        abort();
    if (data->qp == NULL)
        abort();
#endif

    data->count--;

#ifdef SANITY_CHECKS
    if (data->count < 0)
        abort();
#endif

    if (data->count == 0) {
        count = __atomic_sub_fetch(&data->qp->users, VAL_READER, __ATOMIC_SEQ_CST);
        /*
         * we check the writer count here to avoid posting a mutex that
         * would then not block in the event that a writer claimed this 
         * qp later
         */
        if (READER_COUNT(count) == 0 && WRITER_COUNT(count) != 0) {
            fpost(&data->qp->futex);
        }
        data->qp = NULL;
    }
}

void CRYPTO_THREAD_synchronize_rcu(void)
{
    volatile struct rcu_qp *qp, *next_qp, *tmpqp;
    struct rcu_qp *new;
    uint64_t count;
    uint32_t ctr;
   
    __builtin_prefetch(&current_qp, 1, 0); 

    new = CRYPTO_zalloc(sizeof(struct rcu_qp), NULL, 0);

    qp = swap_current_qp(new);

    for (;;) {
        count = __atomic_load_n(&qp->users, __ATOMIC_SEQ_CST);
        if (USER_COUNT(count) == 0) {
            break;
        }
    }

    if (READER_COUNT(count) != 0)
        fwait(&qp->futex);

    next_qp = __atomic_load_n(&qp->next, __ATOMIC_SEQ_CST);
    if (next_qp != NULL)
        fwait(&next_qp->prior_complete);

    pthread_mutex_lock(&qp_lock);
    ctr = __atomic_load_n(&id_ctr, __ATOMIC_SEQ_CST);
    /*
     * only clean if we're the last sync
     * we determine this by checking to see if no other writers
     * have incremented the id counter
     */
    if (ID_VAL(count) == (ctr - 1) && next_qp != NULL) {
        /*
         * we need to wait until no one is using our qp on the read side
         * so spin until the user count reaches zero
         */
        for (;;) {
            count = __atomic_load_n(&qp->users, __ATOMIC_SEQ_CST);
            if (USER_COUNT(count) == 0)
                break;
        }

        /*
         * do a sanity check to ensure that no one ahead of us is still
         * waiting
         */
        next_qp = __atomic_load_n(&qp->next, __ATOMIC_SEQ_CST);
        while (next_qp != NULL) {
            count = __atomic_load_n(&next_qp->users, __ATOMIC_SEQ_CST);
            if (READER_COUNT(count) != 0) {
                pthread_mutex_unlock(&qp_lock);
                goto out;
            }
            if (USER_COUNT(count) != 0) {
                pthread_mutex_unlock(&qp_lock);
                goto out;
            }
            ctr = __atomic_load_n(&next_qp->prior_complete, __ATOMIC_SEQ_CST);
            if (ctr == 0) {
                pthread_mutex_unlock(&qp_lock);
                goto out;
            }
            next_qp = __atomic_load_n(&next_qp->next, __ATOMIC_SEQ_CST);
        }

        /*
         * now that we are user free, we can orphan the list
         * from this qp forward
         */
        next_qp = __atomic_load_n(&qp->next, __ATOMIC_SEQ_CST);
        /*
         * and now we can orphan part of the list
         */
        __atomic_store_n(&qp->next, NULL, __ATOMIC_SEQ_CST);

        /*
         * now that we have snapped off our list
         * it should be safe to unlock, and allow other writers
         * to procede
         */
        pthread_mutex_unlock(&qp_lock);

        while (next_qp != NULL) {
            tmpqp = __atomic_load_n(&next_qp->next, __ATOMIC_SEQ_CST);
            count = __atomic_load_n(&next_qp->users, __ATOMIC_SEQ_CST);
#ifdef SANITY_CHECKS
            if (READER_COUNT(count) != 0)
                abort();
            if (USER_COUNT(count) != 0)
                abort();
#endif
            CRYPTO_free((void *)next_qp, __FILE__, __LINE__);
            next_qp = tmpqp;
        }
    } else {
        pthread_mutex_unlock(&qp_lock);
    }

out:
    /* now signal that we are done, and let the next sync clean up our qp */
    fpost(&qp->prior_complete);
    return;
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
