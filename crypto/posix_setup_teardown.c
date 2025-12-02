#include <openssl/crypto.h>


static void __attribute__((destructor, used)) OpenSSL_library_teardown();

void *force_destructor_inclusion()
{
    void *ptr = OpenSSL_library_teardown;
    return ptr;
}

static void OpenSSL_library_teardown()
{
    OPENSSL_cleanup();
}

