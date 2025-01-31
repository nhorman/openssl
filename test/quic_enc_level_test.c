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

#include <openssl/quic.h>

#include "testutil.h"
#include "testutil/output.h"
#include "internal/quic_error.h"
#include "ssl/quic/quic_record_shared.h"

static int test_quic_has_keyslot()
{
    OSSL_QRL_ENC_LEVEL_SET els;

    memset(&els, 0, sizeof(OSSL_QRL_ENC_LEVEL));

#ifdef NDEBUG
    /* only do these tests if ossl_assert isn't going to crash */

    /* Confirm that a NULL el set returns zero */
    if (!TEST_false(ossl_qrl_enc_level_set_has_keyslot(NULL,
                                                       QUIC_ENC_LEVEL_1RTT,
                                                       QRL_EL_STATE_PROV_NORMAL,
                                                       0)))
        goto err;

    /* Confirm that an out of range keyslot returns zero */
    if (!TEST_false(ossl_qrl_enc_level_set_has_keyslot(&els,
                                                       QUIC_ENC_LEVEL_1RTT,
                                                       QRL_EL_STATE_PROV_NORMAL,
                                                       3)))
        goto err;

#endif 

    /* dummy up a working keyslot */
    els.el[QUIC_ENC_LEVEL_1RTT].state = QRL_EL_STATE_PROV_COOLDOWN;

    /* 
     * if the el state is cooldown, has_keyslot should return 0 if the key_epoch
     * least significant bit is 0 and the keyslot is not also 0
     * since our key epoch is currently zero, this should fail
     */
    if (!TEST_false(ossl_qrl_enc_level_set_has_keyslot(&els,
                                                       QUIC_ENC_LEVEL_1RTT,
                                                       QRL_EL_STATE_PROV_COOLDOWN,
                                                       1)))
        goto err;

    /*
     * If we call it again with a keyslot of zero, it should return true
     */
    if (!TEST_true(ossl_qrl_enc_level_set_has_keyslot(&els,
                                                      QUIC_ENC_LEVEL_1RTT,
                                                      QRL_EL_STATE_PROV_COOLDOWN,
                                                      0)))
        goto err;

    return 1;
err:
    return 0;
}

/***********************************************************************************/

int setup_tests(void)
{
    ADD_TEST(test_quic_has_keyslot);
    return 1;
}

void cleanup_tests(void)
{
    return;
}
