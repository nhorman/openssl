/*
 * Copyright 2000-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/e_os2.h>

# include "testutil.h"

int global_init(void)
{
    /*
     * If the config file gets loaded, the dynamic engine will be loaded,
     * and that interferes with our test above.
     */
    return OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
}

OPT_TEST_DECLARE_USAGE("certfile\n")

int setup_tests(void)
{
    TEST_note("No ENGINE support");
    return 1;
}
