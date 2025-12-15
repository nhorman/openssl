/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "testutil.h"
extern int do_dso1_setup(int cleanup);
extern int do_dso1_fini();
extern int do_dso2_setup(int cleanup);
extern int do_dso2_fini();

static int test_library_refcount_init_and_clean(void)
{
    int ret = 0;
    if(!TEST_true(do_dso1_setup(3)))
        goto err;
    if(!TEST_true(do_dso2_setup(3)))
        goto err;
    if (!TEST_true(do_dso1_fini()))
        goto err;
    if (!TEST_true(do_dso2_fini()))
        goto err;
    ret = 1;
err:
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_library_refcount_init_and_clean);
    return 1;
}
