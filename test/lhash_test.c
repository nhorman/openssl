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

#include "internal/nelem.h"
#include "testutil.h"

/*
 * The macros below generate unused functions which error out one of the clang
 * builds.  We disable this check here.
 */
#ifdef __clang__
#pragma clang diagnostic ignored "-Wunused-function"
#endif

typedef struct int_struct {
    LHASH_REF objref;
    int val;
} INT;

DEFINE_REFCNT_LHASH_OF_EX(INT);

static int int_tests[] = { 65537, 13, 1, 3, -5, 6, 7, 4, -10, -12, -14, 22, 9,
                           -17, 16, 17, -23, 35, 37, 173, 11 };
static const unsigned int n_int_tests = OSSL_NELEM(int_tests);
static short int_found[OSSL_NELEM(int_tests)];
static short int_not_found;

static unsigned long int int_hash(const INT *p)
{
    return 3 & p->val;      /* To force collisions */
}

static int int_cmp(const INT *p, const INT *q)
{
    return p->val != q->val;
}

static void int_free(INT *data)
{
    OPENSSL_free(data);
}

static int int_find(int n)
{
    unsigned int i;

    for (i = 0; i < n_int_tests; i++)
        if (int_tests[i] == n)
            return i;
    return -1;
}

static void int_doall(INT *v)
{
    const int n = int_find(v->val);

    if (n < 0)
        int_not_found++;
    else
        int_found[n]++;
}

static void int_doall_arg(INT *p, short *f)
{
    const int n = int_find(p->val);

    if (n < 0)
        int_not_found++;
    else
        f[n]++;
}

IMPLEMENT_LHASH_REFCNT_DOALL_ARG(INT, short);

static int test_int_lhash(void)
{
    static struct {
        int data;
        int should_del;
    } dels[] = {
        { 65537, 1 },
        { 173 , 1 },
        { 999, 0 },
        { 37, 1 },
        { 1, 1 },
        { 34, 0 }
    };
    INT *intval, *r, *p;
    INT tmpl = LHASH_INIT;
    const unsigned int n_dels = OSSL_NELEM(dels);
    LHASH_OF(INT) *h = lh_INT_new(&int_hash, &int_cmp, int_free);
    unsigned int i;
    int testresult = 0, j;

    if (!TEST_ptr(h))
        goto end;

    /* insert */
    for (i = 0; i < n_int_tests; i++) {
        intval = OPENSSL_zalloc(sizeof(INT));
        if (!TEST_ptr(intval))
            goto end;
        intval->val = int_tests[i];
        if (!TEST_ptr_null(lh_INT_insert(h, intval))) {
            TEST_info("int insert %d", intval->val);
            goto end;
        }
    }

    /* num_items */
    if (!TEST_int_eq(lh_INT_num_items(h), n_int_tests))
        goto end;

    /* retrieve */
    for (i = 0; i < n_int_tests; i++) {
        tmpl.val = int_tests[i];
        r = lh_INT_retrieve(h, &tmpl);
        if (!TEST_ptr(r)) {
            TEST_info("lhash INT test could not find %d", tmpl.val);
            goto end;
        }
        if (!TEST_int_eq(r->val, int_tests[i])) {
            TEST_info("lhash int retrieve value %d", i);
            goto end;
        }
        lh_INT_obj_put(r);
    }
    for (i = 0; i < n_int_tests; i++) {
        tmpl.val = int_tests[i];
        r = lh_INT_retrieve(h, &tmpl);
        if (!TEST_ptr(r)) {
            TEST_info("lhash INT test could nt find %d", tmpl.val);
            goto end;
        }
        if (!TEST_int_eq(r->val, int_tests[i])) {
            TEST_info("lhash int retrieve address %d", i);
            goto end;
        }
        lh_INT_obj_put(r);
    }
    tmpl.val = 1;
    r = lh_INT_retrieve(h, &tmpl);
    if (!TEST_ptr(r)) {
        TEST_info("lhash could not find %d", tmpl.val);
        goto end;
    }
    if (!TEST_int_eq(r->val, int_tests[2]))
        goto end;
    lh_INT_obj_put(r);

    /* replace */
    p = OPENSSL_zalloc(sizeof(INT));
    if (!TEST_ptr(p)) {
        TEST_info("lhash failed malloc on replace");
        goto end;
    }
    p->val = 13;
    /*
     * Note, insert swaps the existing p data
     * for the new one we inserted here
     * put it to make sure its freed
     */
    if (!TEST_ptr(p = lh_INT_insert(h, p)))
        goto end;
    if (!TEST_int_eq(p->val, int_tests[1]))
        goto end;
    lh_INT_obj_put(p);

    tmpl.val = int_tests[1];
    p = lh_INT_retrieve(h, &tmpl);
    if (!TEST_int_eq(p->val, tmpl.val))
        goto end;
    lh_INT_obj_put(p);

    /* do_all */
    memset(int_found, 0, sizeof(int_found));
    int_not_found = 0;
    lh_INT_doall(h, &int_doall);
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
    lh_INT_doall_short(h, int_doall_arg, int_found);
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
        tmpl.val = dels[i].data;
        INT *b = lh_INT_delete(h, &tmpl);
        if (dels[i].should_del == 1) {
            if (!TEST_ptr(b)) {
                TEST_info("lhash unable to delete %d\n", tmpl.val);
                goto end;
            }
            if (!TEST_int_eq(b->val, dels[i].data)) {
                TEST_info("lhash int delete %d", i);
                goto end;
            }
            lh_INT_obj_put(b);
        } else {
            if (!TEST_ptr_null(b)) {
                TEST_info("lhash deleted an item not added %d", dels[i]);
                goto end;
            }
        }
    }

    /* error */
    if (!TEST_int_eq(lh_INT_error(h), 0))
        goto end;

    testresult = 1;
end:
    lh_INT_free(h);
    return testresult;
}

static unsigned long int stress_hash(const INT *p)
{
    return p->val;
}

static int test_stress(void)
{
    LHASH_OF(INT) *h = lh_INT_new(&stress_hash, &int_cmp, int_free);
    const unsigned int n = 2500000;
    unsigned int i;
    INT tmpl = LHASH_INIT;
    INT *p;
    int testresult = 0;

    if (!TEST_ptr(h))
        goto end;

    /* insert */
    for (i = 0; i < n; i++) {
        p = OPENSSL_malloc(sizeof(INT));
        if (!TEST_ptr(p)) {
            TEST_info("lhash stress out of memory %d", i);
            goto end;
        }
        p->val = 3 * i + 1;
        lh_INT_insert(h, p);
    }

    /* num_items */
    if (!TEST_int_eq(lh_INT_num_items(h), n))
            goto end;

    /* delete in a different order */
    for (i = 0; i < n; i++) {
        const int j = (7 * i + 4) % n * 3 + 1;
        tmpl.val = j;
        if (!TEST_ptr(p = lh_INT_delete(h, &tmpl))) {
            TEST_info("lhash stress delete %d\n", i);
            goto end;
        }
        if (!TEST_int_eq(p->val, j)) {
            TEST_info("lhash stress bad value %d", i);
            goto end;
        }
        lh_INT_obj_put(p);
    }

    testresult = 1;
end:
    lh_INT_free(h);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_int_lhash);
    ADD_TEST(test_stress);
    return 1;
}
