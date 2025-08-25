/*
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Here is an STORE loader for ENGINE backed keys.  It relies on deprecated
 * functions, and therefore need to have deprecation warnings suppressed.
 * This file is not compiled at all in a '--api=3 no-deprecated' configuration.
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include "internal/e_os.h"
#include "apps.h"

int setup_engine_loader(void)
{
    return 0;
}

void destroy_engine_loader(void)
{
}

