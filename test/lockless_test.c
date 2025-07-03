/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <internal/lockless.h>
#include "threadstest.h"
#include "testutil.h"

static int list_compare(void *a, void *b, void *arg, int restart)
{
    int *node = (int *)a;
    int *new = (int *)b;

    if (*node < *new)
        return -1;
    if (*node > *new)
        return 1;
    return 0;
}

static int list_iterate(void *a, void *b, void *arg, int restart)
{
    int *ordering = (int *)arg;
    int *node = (int *)a;

    if (restart == 1)
        *ordering = INT_MAX;

    if (*ordering == -1)
        return 0;

    if (*ordering == INT_MAX) {
        *ordering = *node;
    } else if (*ordering > *node) {
        TEST_info("Node %d is less than node %d", *node, *ordering);
        *ordering = -1;
    } else {
        *ordering = *node;
    }
    return -1;
}

static void list_free(void *data)
{
    return;
}

static int test_linkedlist_singlethread(void)
{
    LLL *list;
    int ret = 0;
    size_t i;
    int list_vals[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    int extra_list_vals[] = { 20, 11 };
    int vals_to_del[] = { 11, 20, 5, 0 };
    int list_is_ordered = INT_MAX;
    int val_to_find_good = 6;
    int val_to_find_bad = 13;

    list = LLL_new(list_compare, list_free, 1);

    if (!TEST_ptr(list))
        return 0;

    /*
     * populate our linked list with some ordinal values
     */
    for (i = 0; i < 10; i++) {
        if (!TEST_int_eq(LLL_insert(list, &list_vals[i], NULL), 1))
            goto err;
    }

    /*
     * Now add it two more, first a large one to create an ordinal gap
     * then one that will be forced to be an insert in the middle of the 
     * list
     */
    for (i = 0; i < 2; i++) {
        if (!TEST_int_eq(LLL_insert(list, &extra_list_vals[i], NULL), 1))
            goto err;
    }

    /*
     * Try a find operation on an element we know is in the list
     */
    if (!TEST_int_eq(LLL_find(list, &val_to_find_good, NULL), 1))
        goto err;

    /*
     * Try a find operation on an element we know is not in the list
     */
    if (!TEST_int_eq(LLL_find(list, &val_to_find_bad, NULL), 0))
        goto err;

    /*
     * At this point we should have a list that looks like this
     * 0->1->2->3...->10->11->20
     * lets iterate over the list and confirm that
     */
    if (!TEST_int_eq(LLL_iterate(list, list_iterate, &list_is_ordered), 1))
        goto err;

    /*
     * Need to check to make sure our list_is_ordered flag
     * indicates all is well.  It will be set to -1 if anything
     * was out of order
     */
    if (!TEST_int_eq(list_is_ordered, 20))
        goto err;

    /*
     * Delete a few entries out of order
     */
    for (i = 0; i < 4; i++) {
        if (!TEST_int_eq(LLL_delete(list, &vals_to_del[i], NULL), 1))
            goto err;
    }

    ret = 1;
err:
    LLL_free(list);
    return ret;
}


static void list_mt_free(void *data)
{
    OPENSSL_free(data);
}

LLL *mt_list = NULL;
static uint64_t hit_error = 0;
static uint64_t tnum = 0;
static uint64_t dnum = 0;
static int val_to_add[] = {0, 1};
static int val_to_del[] = {0, 1};
static CRYPTO_RWLOCK *alock = NULL;
static uint64_t op_count = 0;
static uint64_t add_count = 0;
static uint64_t del_count = 0;
static uint64_t iter_count = 0;

#define MAX_OPS 500000
static void run_add_ops(void)
{
    uint64_t idx;
    uint64_t ret;
    uint64_t err;
    int val;
    int *newvalptr = NULL;
    uint64_t myops = 0;

    if (!CRYPTO_atomic_add64(&tnum, 1, &idx, alock))
        goto err;

    /*
     * Adjust our index to be zero based
     */
    idx -= 1;

    for (;;) {
        if (!TEST_int_eq(CRYPTO_atomic_add64(&hit_error, 0, &err, alock), 1))
            goto err;
        if (err != 0)
            goto err;

        if (!TEST_int_eq(CRYPTO_atomic_add64(&op_count, 1, &err, alock), 1))
            goto err;

        /*
         * test ends after MAX_OPS operations
         */
        if (err >= MAX_OPS)
            return;

        myops++;
        if (myops % 10000 == 0) {
            TEST_info("Adder %lu completed %lu iterate ops", idx, myops);
        }
        CRYPTO_atomic_add64(&add_count, 1, &ret, alock);

        if (!TEST_int_eq(CRYPTO_atomic_add(&val_to_add[idx], 2, &val, alock), 1))
            goto err;

        newvalptr = OPENSSL_zalloc(sizeof(int));
        if (!TEST_ptr(newvalptr))
            goto err;

        *newvalptr = val;

        //TEST_info("Adding value %d\n", *newvalptr);
        if (!TEST_int_eq(LLL_insert(mt_list, newvalptr, NULL), 1)) {
            TEST_info("Failed inserting value %d\n", *newvalptr);
            goto err;
        }
    }

err:
    CRYPTO_atomic_add64(&hit_error, 1, &err, alock);
    return;
}

static void run_delete_ops(void)
{
    uint64_t err;
    uint64_t idx;
    uint64_t ret;
    uint64_t count;
    int my_val_to_del;
    uint64_t myops = 0;

    if (!CRYPTO_atomic_add64(&dnum, 1, &idx, alock))
        goto err;

    idx -= 1;

    for (;;) {
        if (!TEST_int_eq(CRYPTO_atomic_add64(&hit_error, 0, &err, alock), 1))
            goto err;
        if (err != 0)
            goto err;

        if (!TEST_int_eq(CRYPTO_atomic_add64(&op_count, 1, &count, alock), 1))
            goto err;
        if (count >= MAX_OPS)
            return;

        myops++;
        if (myops % 10000 == 0) {
            TEST_info("Deleter %lu completed %lu iterate ops", idx, myops);
        }
        CRYPTO_atomic_add64(&del_count, 1, &ret, alock);

        if (!TEST_int_eq(CRYPTO_atomic_add(&val_to_del[idx], 2, &my_val_to_del, alock), 1))
            goto err;
        /*
         * wait until we have at least 200 values in the table
         */
        if (my_val_to_del < 200)
            continue;

        /*
         * we can't guarantee that we don't be deleting the same entry
         * twice so just do our best here
         */
        //TEST_info("Deleting val %d\n", val_to_del);
        LLL_delete(mt_list, &my_val_to_del, NULL);
    }
err:
    CRYPTO_atomic_add64(&hit_error, 1, &err, alock);
    return;
}

static void run_iterate_ops(void)
{
    uint64_t count;
    uint64_t ret;
    uint64_t err;
    int list_is_ordered;
    uint64_t myops = 0;

    for (;;) {
        if (!TEST_int_eq(CRYPTO_atomic_add64(&hit_error, 0, &err, alock), 1))
            goto err;
        if (err != 0)
            goto err;

        if (!TEST_int_eq(CRYPTO_atomic_add64(&op_count, 1, &count, alock), 1))
            goto err;
        if (count >= MAX_OPS)
            return;

        myops++;
        if (myops % 10000 == 0) {
            TEST_info("iterator completed %lu iterate ops", myops);
        }
        CRYPTO_atomic_add64(&iter_count, 1, &ret, alock);
        list_is_ordered = INT_MAX;

        if (!TEST_int_eq(LLL_iterate(mt_list, list_iterate, &list_is_ordered), 1))
            goto err;

        //TEST_info("LIST_IS_ORDERED returns %d", list_is_ordered);

        if (!TEST_int_gt(list_is_ordered, -1)) {
            TEST_info("Failed list iteration\n");
            goto err;
        }
    }
err:
    CRYPTO_atomic_add64(&hit_error, 1, &err, alock);
    return;
}

static thread_t adder1;
static thread_t adder2;
static thread_t deleter1;
static thread_t deleter2;
static thread_t iterator;

static int test_linkedlist_multithread(void)
{
    int ret = 0;

    srandom(47);

    if (!TEST_ptr((alock = CRYPTO_THREAD_lock_new())))
        goto err;

    if (!TEST_ptr(mt_list = LLL_new(list_compare, list_mt_free, 1)))
        goto err;

    if (!TEST_true(run_thread(&adder1, run_add_ops)))
        goto err;

    if (!TEST_true(run_thread(&adder2, run_add_ops)))
        goto err;

    if (!TEST_true(run_thread(&deleter1, run_delete_ops)))
        goto err;

    if (!TEST_true(run_thread(&deleter2, run_delete_ops)))
        goto err;

    if (!TEST_true(run_thread(&iterator, run_iterate_ops)))
        goto err;

    if (!TEST_true(wait_for_thread(adder1)))
        goto err;

    if (!TEST_true(wait_for_thread(adder2)))
        goto err;

    if (!TEST_true(wait_for_thread(deleter1)))
        goto err;

    if (!TEST_true(wait_for_thread(deleter2)))
        goto err;

    if (!TEST_true(wait_for_thread(iterator)))
        goto err;
    
    if (hit_error == 0) {
        TEST_info("Completed %lu add operations", add_count);
        TEST_info("Completed %lu del operations", del_count);
        TEST_info("Completed %lu iter operations", iter_count);
        ret = 1;
    }
err:
    LLL_free(mt_list);
    CRYPTO_THREAD_lock_free(alock);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_linkedlist_singlethread);
    ADD_TEST(test_linkedlist_multithread);
    return 1;
}
