#include "fff.h"
#include "mocks/mock_rcu.h"
#include "mocks/mock_crypto.h"
#include <openssl/crypto.h>
#include <internal/hashtable.h>
#include <assert.h>
#include <stdio.h>

#undef NDEBUG

#define TEST_F(SUITE, NAME) void NAME()
#define RUN_TEST(SUITE, TESTNAME) printf(" Running %s.%s: \n", #SUITE, #TESTNAME); setup(); TESTNAME(); printf(" SUCCESS\n");

DEFINE_FFF_GLOBALS;

void setup()
{
    RESET_MOCK_RCU();
    RESET_MOCK_CRYPTO();
    return;
}

TEST_F(hashtable_tests, ossl_ht_new_test_failure_on_null_config)
{
    HT *hashtable;

    hashtable = ossl_ht_new(NULL);

    assert(hashtable == NULL);

    ossl_ht_free(hashtable);

}

TEST_F(hashtable_tests, ossl_ht_new_test_null_return_on_ht_allocation)
{
    HT *hashtable;
    HT_CONFIG conf = {
        NULL,
        NULL,
        NULL,
        0,
        1,
        0
    };

    CRYPTO_zalloc_fake.return_val = NULL;

    hashtable = ossl_ht_new(&conf);

    assert(hashtable == NULL);
    assert(CRYPTO_zalloc_fake.call_count == 1);
    ossl_ht_free(hashtable);
}

TEST_F(hashtable_tests, ossl_ht_new_test_null_return_on_lock_alloc_failure)
{
    HT *hashtable;
    HT_CONFIG conf = {
        NULL,
        NULL,
        NULL,
        0,
        1,
        0
    };
    uint8_t retval1[256];
    void *my_return_vals[2];

    my_return_vals[0] = retval1; /*dummy allocation for ht_internal_st */
    my_return_vals[1] = NULL;
    memset(retval1, 0, 256);

    SET_RETURN_SEQ(CRYPTO_zalloc, my_return_vals, 2);

    hashtable = ossl_ht_new(&conf);

    assert(hashtable == NULL);
    assert(CRYPTO_zalloc_fake.call_count == 2);
    ossl_ht_free(hashtable);
}

int main()
{
    setbuf(stdout, NULL);
    fprintf(stdout, "----------------\n");
    fprintf(stdout, "Running Tests\n");
    fprintf(stdout, "-------------\n\n");
    fflush(0);

    RUN_TEST(hashtable_tests, ossl_ht_new_test_failure_on_null_config);
    RUN_TEST(hashtable_tests, ossl_ht_new_test_null_return_on_ht_allocation);
    RUN_TEST(hashtable_tests, ossl_ht_new_test_null_return_on_lock_alloc_failure);
    printf("complete\n");
    return 0;
}


