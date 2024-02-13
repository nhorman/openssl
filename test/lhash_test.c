/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/lhash.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <internal/hashtable.h>

#include "internal/nelem.h"
#include "testutil.h"

/*
 * The macros below generate unused functions which error out one of the clang
 * builds.  We disable this check here.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

DEFINE_LHASH_OF_EX(int);

static int int_tests[] = { 65537, 13, 1, 3, -5, 6, 7, 4, -10, -12, -14, 22, 9,
                           -17, 16, 17, -23, 35, 37, 173, 11 };
static const unsigned int n_int_tests = OSSL_NELEM(int_tests);
static short int_found[OSSL_NELEM(int_tests)];
static short int_not_found;

static unsigned long int int_hash(const int *p)
{
    return 3 & *p;      /* To force collisions */
}

static int int_cmp(const int *p, const int *q)
{
    return *p != *q;
}

static int int_find(int n)
{
    unsigned int i;

    for (i = 0; i < n_int_tests; i++)
        if (int_tests[i] == n)
            return i;
    return -1;
}

static void int_doall(int *v)
{
    const int n = int_find(*v);

    if (n < 0)
        int_not_found++;
    else
        int_found[n]++;
}

static void int_doall_arg(int *p, short *f)
{
    const int n = int_find(*p);

    if (n < 0)
        int_not_found++;
    else
        f[n]++;
}

IMPLEMENT_LHASH_DOALL_ARG(int, short);

static int test_int_lhash(void)
{
    static struct {
        int data;
        int null;
    } dels[] = {
        { 65537,    0 },
        { 173,      0 },
        { 999,      1 },
        { 37,       0 },
        { 1,        0 },
        { 34,       1 }
    };
    const unsigned int n_dels = OSSL_NELEM(dels);
    LHASH_OF(int) *h = lh_int_new(&int_hash, &int_cmp);
    unsigned int i;
    int testresult = 0, j, *p;

    if (!TEST_ptr(h))
        goto end;

    /* insert */
    for (i = 0; i < n_int_tests; i++)
        if (!TEST_ptr_null(lh_int_insert(h, int_tests + i))) {
            TEST_info("int insert %d", i);
            goto end;
        }

    /* num_items */
    if (!TEST_int_eq(lh_int_num_items(h), n_int_tests))
        goto end;

    /* retrieve */
    for (i = 0; i < n_int_tests; i++)
        if (!TEST_int_eq(*lh_int_retrieve(h, int_tests + i), int_tests[i])) {
            TEST_info("lhash int retrieve value %d", i);
            goto end;
        }
    for (i = 0; i < n_int_tests; i++)
        if (!TEST_ptr_eq(lh_int_retrieve(h, int_tests + i), int_tests + i)) {
            TEST_info("lhash int retrieve address %d", i);
            goto end;
        }
    j = 1;
    if (!TEST_ptr_eq(lh_int_retrieve(h, &j), int_tests + 2))
        goto end;

    /* replace */
    j = 13;
    if (!TEST_ptr(p = lh_int_insert(h, &j)))
        goto end;
    if (!TEST_ptr_eq(p, int_tests + 1))
        goto end;
    if (!TEST_ptr_eq(lh_int_retrieve(h, int_tests + 1), &j))
        goto end;

    /* do_all */
    memset(int_found, 0, sizeof(int_found));
    int_not_found = 0;
    lh_int_doall(h, &int_doall);
    if (!TEST_int_eq(int_not_found, 0)) {
        TEST_info("lhash int doall encountered a not found condition");
        goto end;
    }
    for (i = 0; i < n_int_tests; i++)
        if (!TEST_int_eq(int_found[i], 1)) {
            TEST_info("lhash int doall %d", i);
            goto end;
        }

    /* do_all_arg */
    memset(int_found, 0, sizeof(int_found));
    int_not_found = 0;
    lh_int_doall_short(h, int_doall_arg, int_found);
    if (!TEST_int_eq(int_not_found, 0)) {
        TEST_info("lhash int doall arg encountered a not found condition");
        goto end;
    }
    for (i = 0; i < n_int_tests; i++)
        if (!TEST_int_eq(int_found[i], 1)) {
            TEST_info("lhash int doall arg %d", i);
            goto end;
        }

    /* delete */
    for (i = 0; i < n_dels; i++) {
        const int b = lh_int_delete(h, &dels[i].data) == NULL;
        if (!TEST_int_eq(b ^ dels[i].null,  0)) {
            TEST_info("lhash int delete %d", i);
            goto end;
        }
    }

    /* error */
    if (!TEST_int_eq(lh_int_error(h), 0))
        goto end;

    testresult = 1;
end:
    lh_int_free(h);
    return testresult;
}


static int int_filter_all(HT_VALUE *v, void *arg)
{
    return 1;
}

HT_START_KEY_DEFN(intkey)
HT_DEF_KEY_FIELD(mykey, int)
HT_DEF_KEY_FIELD(pad, int)
HT_END_KEY_DEFN(INTKEY)

IMPLEMENT_HT_VALUE_TYPE_FNS(int, test, static)

static void int_foreach(HT_VALUE *v, void *arg)
{
    int *vd = ossl_ht_test_int_from_value(v);
    const int n = int_find(*vd);

    if (n < 0)
        int_not_found++;
    else
        int_found[n]++;
}

static uint64_t hashtable_hash(uint8_t *key, size_t keylen)
{
    return (uint64_t)(*(uint32_t *)key);
}

static int test_int_hashtable(void)
{
    static struct {
        int data;
        int should_del;
    } dels[] = {
        { 65537 , 1},
        { 173 , 1},
        { 999 , 0 },
        { 37 , 1 },
        { 1 , 1 },
        { 34 , 0 }
    };
    const unsigned int n_dels = OSSL_NELEM(dels);
    HT_CONFIG hash_conf = {
        NULL,
        NULL,
        0,
        0,
        0
    };
    INTKEY key;
    int rc = 0;
    size_t i;
    HT *ht = NULL;
    HT_VALUE *todel = NULL;
    HT_VALUE_LIST *list = NULL;

    ht = ossl_ht_new(&hash_conf);

    if (ht == NULL)
        return 0;

    /* insert */
    HT_INIT_KEY(&key);
    for (i = 0; i < n_int_tests; i++) {
        HT_SET_KEY_FIELD(&key, mykey, int_tests[i]);
        if (!TEST_int_eq(ossl_ht_test_int_insert(ht, TO_HT_KEY(&key),
                         &int_tests[i], NULL), 1)) {
            TEST_info("int insert %zu", i);
            goto end;
        }
    }

    /* num_items */
    if (!TEST_int_eq(ossl_ht_count(ht), n_int_tests))
        goto end;

    /* foreach, no arg */
    memset(int_found, 0, sizeof(int_found));
    int_not_found = 0;
    ossl_ht_foreach(ht, int_foreach, NULL);
    if (!TEST_int_eq(int_not_found, 0)) {
        TEST_info("hashtable int foreach encountered a not found condition");
        goto end;
    }

    for (i = 0; i < n_int_tests; i++)
        if (!TEST_int_eq(int_found[i], 1)) {
            TEST_info("hashtable int foreach %zu", i);
            goto end;
    }

    /* filter */
    list = ossl_ht_filter(ht, 64, int_filter_all, NULL);
    if (!TEST_int_eq(list->list_len, n_int_tests))
        goto end;
    ossl_ht_value_list_free(list);

    /* delete */
    for (i = 0; i < n_dels; i++) {
        HT_SET_KEY_FIELD(&key, mykey, dels[i].data);
        todel = ossl_ht_delete(ht, TO_HT_KEY(&key));
        if (dels[i].should_del) {
            if (!TEST_ptr(todel)) {
                TEST_info("hashtable couldn't find entry to delete\n");
                goto end;
            }
        } else {
            if (!TEST_ptr_null(todel)) {
                TEST_info("%d found an entry that shouldn't be there\n", dels[i].data);
                goto end;
            }
       }
        ossl_ht_put(todel);
    }

    rc = 1;
end:
    ossl_ht_free(ht);
    return rc;
}

static unsigned long int stress_hash(const int *p)
{
    return *p;
}

static int test_stress(void)
{
    LHASH_OF(int) *h = lh_int_new(&stress_hash, &int_cmp);
    const unsigned int n = 2500000;
    unsigned int i;
    int testresult = 0, *p;

    if (!TEST_ptr(h))
        goto end;

    /* insert */
    for (i = 0; i < n; i++) {
        p = OPENSSL_malloc(sizeof(i));
        if (!TEST_ptr(p)) {
            TEST_info("lhash stress out of memory %d", i);
            goto end;
        }
        *p = 3 * i + 1;
        lh_int_insert(h, p);
    }

    /* num_items */
    if (!TEST_int_eq(lh_int_num_items(h), n))
            goto end;

    /* delete in a different order */
    for (i = 0; i < n; i++) {
        const int j = (7 * i + 4) % n * 3 + 1;

        if (!TEST_ptr(p = lh_int_delete(h, &j))) {
            TEST_info("lhash stress delete %d\n", i);
            goto end;
        }
        if (!TEST_int_eq(*p, j)) {
            TEST_info("lhash stress bad value %d", i);
            goto end;
        }
        OPENSSL_free(p);
    }

    testresult = 1;
end:
    lh_int_free(h);
    return testresult;
}

static void hashtable_intfree(HT_VALUE *v)
{
    OPENSSL_free(v->value);
}

static int test_hashtable_stress(void)
{
    const unsigned int n = 2500000;
    unsigned int i;
    int testresult = 0, *p;
    HT_CONFIG hash_conf = {
        hashtable_intfree,
        hashtable_hash,
        2500000,
        0,
        0
    };
    HT *h;
    INTKEY key;
    HT_VALUE *v;

    h = ossl_ht_new(&hash_conf);


    if (!TEST_ptr(h))
        goto end;

    HT_INIT_KEY(&key);

    /* insert */
    for (i = 0; i < n; i++) {
        p = OPENSSL_malloc(sizeof(i));
        if (!TEST_ptr(p)) {
            TEST_info("hashtable stress out of memory %d", i);
            goto end;
        }
        *p = 3 * i + 1;
        HT_SET_KEY_FIELD(&key, mykey, *p);
        if (!TEST_int_eq(ossl_ht_test_int_insert(h, TO_HT_KEY(&key),
                         p, NULL), 1)) {
            TEST_info("hashtable unable to insert element %d\n", *p);
            goto end;
        }
    }

    /* make sure we stored everything */
    if (!TEST_int_eq(ossl_ht_count(h), n))
            goto end;

    /* Can't do deletes in lockless read mode */
    if (!hash_conf.lockless_read) {
        /* delete in a different order */
        for (i = 0; i < n; i++) {
            const int j = (7 * i + 4) % n * 3 + 1;
            HT_SET_KEY_FIELD(&key, mykey, j);
            if (!TEST_ptr(v = ossl_ht_delete(h, TO_HT_KEY(&key)))) {
                TEST_info("hashtable stress delete %d\n", i);
                goto end;
            }
            if (!TEST_int_eq(*((int *)v->value), j)) {
                TEST_info("hashtalbe stress bad value %d", i);
                goto end;
            }
            ossl_ht_put(v);
        }
    }

    testresult = 1;
end:
    ossl_ht_free(h);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_int_lhash);
    ADD_TEST(test_stress);
    ADD_TEST(test_int_hashtable);
    ADD_TEST(test_hashtable_stress);
    return 1;
}
