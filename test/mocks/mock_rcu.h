#ifndef mock_rcu_H
#define mock_rcu_H

/*
    Auto-generated mock file for FFF.
*/
#include <openssl/crypto.h>
#include <internal/rcu.h>
#include <string.h>
#include "fff.h"

DEFINE_FFF_GLOBALS;


FAKE_VALUE_FUNC(CRYPTO_RCU_LOCK*, ossl_rcu_lock_new, int, OSSL_LIB_CTX*);
FAKE_VOID_FUNC(ossl_rcu_lock_free, CRYPTO_RCU_LOCK*);
FAKE_VOID_FUNC(ossl_rcu_read_lock, CRYPTO_RCU_LOCK*);
FAKE_VOID_FUNC(ossl_rcu_write_lock, CRYPTO_RCU_LOCK*);
FAKE_VOID_FUNC(ossl_rcu_write_unlock, CRYPTO_RCU_LOCK*);
FAKE_VOID_FUNC(ossl_rcu_read_unlock, CRYPTO_RCU_LOCK*);
FAKE_VOID_FUNC(ossl_synchronize_rcu, CRYPTO_RCU_LOCK*);
FAKE_VALUE_FUNC(int, ossl_rcu_call, CRYPTO_RCU_LOCK*, rcu_cb_fn, void*);
FAKE_VALUE_FUNC(void*, ossl_rcu_uptr_deref, void**);
FAKE_VOID_FUNC(ossl_rcu_assign_uptr, void**, void**);

#define RESET_MOCK_RCU() \
    RESET_FAKE(ossl_rcu_lock_new); \
    RESET_FAKE(ossl_rcu_lock_free); \
    RESET_FAKE(ossl_rcu_read_lock); \
    RESET_FAKE(ossl_rcu_write_lock); \
    RESET_FAKE(ossl_rcu_write_unlock); \
    RESET_FAKE(ossl_rcu_read_unlock); \
    RESET_FAKE(ossl_synchronize_rcu); \
    RESET_FAKE(ossl_rcu_call); \
    RESET_FAKE(ossl_rcu_uptr_deref); \
    RESET_FAKE(ossl_rcu_assign_uptr);

#endif // mock_rcu_H
