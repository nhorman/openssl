#include "gtest/gtest.h"
#include <internal/hashtable.h>

TEST(ossl_ht_new, Poistive) {
    HT_CONFIG conf = {
        NULL,
        NULL,
        NULL,
        0,
        0,
        0
    };
    HT *hashtable;

    hashtable = ossl_ht_new(&conf);
    ASSERT_TRUE(hashtable != NULL);
    ossl_ht_free(hashtable);
}

TEST(ossl_ht_new, Negative) {
    HT *hashtable;

    hashtable = ossl_ht_new(NULL);
    ASSERT_TRUE(hashtable == NULL);
    ossl_ht_free(hashtable);
}

GTEST_API_ int main(int argc, char **argv)
{
    printf("Running hashtable tests\n");
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

