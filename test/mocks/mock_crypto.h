#ifndef mock_crypto_H
#define mock_crypto_H

/*
    Auto-generated mock file for FFF.
*/

#include <string.h>
#include "fff.h"

DEFINE_FFF_GLOBALS;

typedef int(*cmock_crypto_func_ptr1)(const char* str, size_t len, void* u);
typedef void(*cmock_crypto_func_ptr2)(void);
typedef void(*cmock_crypto_func_ptr3)(void);
typedef void(*cmock_crypto_func_ptr4)(void*);

FAKE_VALUE_FUNC(CRYPTO_RWLOCK*, CRYPTO_THREAD_lock_new);
FAKE_VALUE_FUNC(__owur int, CRYPTO_THREAD_read_lock, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(__owur int, CRYPTO_THREAD_write_lock, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_THREAD_unlock, CRYPTO_RWLOCK*);
FAKE_VOID_FUNC(CRYPTO_THREAD_lock_free, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_add, int*, int, int*, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_add64, uint64_t*, uint64_t, uint64_t*, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_and, uint64_t*, uint64_t, uint64_t*, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_or, uint64_t*, uint64_t, uint64_t*, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_load, uint64_t*, uint64_t*, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_load_int, int*, int*, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(int, CRYPTO_atomic_store, uint64_t*, uint64_t, CRYPTO_RWLOCK*);
FAKE_VALUE_FUNC(size_t, OPENSSL_strlcpy, char*, const char*, size_t);
FAKE_VALUE_FUNC(size_t, OPENSSL_strlcat, char*, const char*, size_t);
FAKE_VALUE_FUNC(size_t, OPENSSL_strnlen, const char*, size_t);
FAKE_VALUE_FUNC(int, OPENSSL_strtoul, const char*, char**, int, unsigned long*);
FAKE_VALUE_FUNC(int, OPENSSL_buf2hexstr_ex, char*, size_t, size_t*, const unsigned char*, size_t, char);
FAKE_VALUE_FUNC(char*, OPENSSL_buf2hexstr, const unsigned char*, long);
FAKE_VALUE_FUNC(int, OPENSSL_hexstr2buf_ex, unsigned char*, size_t, size_t*, const char*, char);
FAKE_VALUE_FUNC(unsigned char*, OPENSSL_hexstr2buf, const char*, long*);
FAKE_VALUE_FUNC(int, OPENSSL_hexchar2int, unsigned char);
FAKE_VALUE_FUNC(int, OPENSSL_strcasecmp, const char*, const char*);
FAKE_VALUE_FUNC(int, OPENSSL_strncasecmp, const char*, const char*, size_t);
FAKE_VALUE_FUNC(unsigned int, OPENSSL_version_major);
FAKE_VALUE_FUNC(unsigned int, OPENSSL_version_minor);
FAKE_VALUE_FUNC(unsigned int, OPENSSL_version_patch);
FAKE_VALUE_FUNC(const char*, OPENSSL_version_pre_release);
FAKE_VALUE_FUNC(const char*, OPENSSL_version_build_metadata);
FAKE_VALUE_FUNC(unsigned long, OpenSSL_version_num);
FAKE_VALUE_FUNC(const char*, OpenSSL_version, int);
FAKE_VALUE_FUNC(const char*, OPENSSL_info, int);
FAKE_VALUE_FUNC(int, OPENSSL_issetugid);
FAKE_VALUE_FUNC(__owur int, CRYPTO_get_ex_new_index, int, long, void*, CRYPTO_EX_new*, CRYPTO_EX_dup*, CRYPTO_EX_free*);
FAKE_VALUE_FUNC(int, CRYPTO_free_ex_index, int, int);
FAKE_VALUE_FUNC(int, CRYPTO_new_ex_data, int, void*, CRYPTO_EX_DATA*);
FAKE_VALUE_FUNC(int, CRYPTO_dup_ex_data, int, CRYPTO_EX_DATA*, const CRYPTO_EX_DATA*);
FAKE_VOID_FUNC(CRYPTO_free_ex_data, int, void*, CRYPTO_EX_DATA*);
FAKE_VALUE_FUNC(int, CRYPTO_alloc_ex_data, int, void*, CRYPTO_EX_DATA*, int);
FAKE_VALUE_FUNC(int, CRYPTO_set_ex_data, CRYPTO_EX_DATA*, int, void*);
FAKE_VALUE_FUNC(void*, CRYPTO_get_ex_data, const CRYPTO_EX_DATA*, int);
FAKE_VALUE_FUNC(int, CRYPTO_set_mem_functions, CRYPTO_malloc_fn, CRYPTO_realloc_fn, CRYPTO_free_fn);
FAKE_VOID_FUNC(CRYPTO_get_mem_functions, CRYPTO_malloc_fn*, CRYPTO_realloc_fn*, CRYPTO_free_fn*);
FAKE_VALUE_FUNC(void*, CRYPTO_malloc, size_t, const char*, int);
FAKE_VALUE_FUNC(void*, CRYPTO_zalloc, size_t, const char*, int);
FAKE_VALUE_FUNC(void*, CRYPTO_aligned_alloc, size_t, size_t, void**, const char*, int);
FAKE_VALUE_FUNC(void*, CRYPTO_memdup, const void*, size_t, const char*, int);
FAKE_VALUE_FUNC(char*, CRYPTO_strdup, const char*, const char*, int);
FAKE_VALUE_FUNC(char*, CRYPTO_strndup, const char*, size_t, const char*, int);
FAKE_VOID_FUNC(CRYPTO_free, void*, const char*, int);
FAKE_VOID_FUNC(CRYPTO_clear_free, void*, size_t, const char*, int);
FAKE_VALUE_FUNC(void*, CRYPTO_realloc, void*, size_t, const char*, int);
FAKE_VALUE_FUNC(void*, CRYPTO_clear_realloc, void*, size_t, size_t, const char*, int);
FAKE_VALUE_FUNC(int, CRYPTO_secure_malloc_init, size_t, size_t);
FAKE_VALUE_FUNC(int, CRYPTO_secure_malloc_done);
FAKE_VALUE_FUNC(void*, CRYPTO_secure_malloc, size_t, const char*, int);
FAKE_VALUE_FUNC(void*, CRYPTO_secure_zalloc, size_t, const char*, int);
FAKE_VOID_FUNC(CRYPTO_secure_free, void*, const char*, int);
FAKE_VOID_FUNC(CRYPTO_secure_clear_free, void*, size_t, const char*, int);
FAKE_VALUE_FUNC(int, CRYPTO_secure_allocated, const void*);
FAKE_VALUE_FUNC(int, CRYPTO_secure_malloc_initialized);
FAKE_VALUE_FUNC(size_t, CRYPTO_secure_actual_size, void*);
FAKE_VALUE_FUNC(size_t, CRYPTO_secure_used);
FAKE_VOID_FUNC(OPENSSL_cleanse, void*, size_t);
FAKE_VOID_FUNC(CRYPTO_get_alloc_counts, int*, int*, int*);
FAKE_VALUE_FUNC(int, CRYPTO_set_mem_debug, int);
FAKE_VALUE_FUNC(int, CRYPTO_mem_ctrl, int);
FAKE_VALUE_FUNC(int, CRYPTO_mem_debug_push, char*, char*, int);
FAKE_VALUE_FUNC(int, CRYPTO_mem_debug_pop);
FAKE_VOID_FUNC(CRYPTO_mem_debug_malloc, void*, size_t, int, const char*, int);
FAKE_VOID_FUNC(CRYPTO_mem_debug_realloc, void*, void*, size_t, int, const char*, int);
FAKE_VOID_FUNC(CRYPTO_mem_debug_free, void*, int, const char*, int);
FAKE_VALUE_FUNC(int, CRYPTO_mem_leaks_cb, cmock_crypto_func_ptr1, void*);
FAKE_VALUE_FUNC(int, CRYPTO_mem_leaks_fp, FILE*);
FAKE_VALUE_FUNC(int, CRYPTO_mem_leaks, BIO*);
FAKE_VALUE_FUNC(int, OPENSSL_isservice);
FAKE_VOID_FUNC(OPENSSL_init);
FAKE_VALUE_FUNC(struct tm*, OPENSSL_gmtime, const time_t*, struct tm*);
FAKE_VALUE_FUNC(int, OPENSSL_gmtime_adj, struct tm*, int, long);
FAKE_VALUE_FUNC(int, OPENSSL_gmtime_diff, int*, int*, const struct tm*, const struct tm*);
FAKE_VALUE_FUNC(int, CRYPTO_memcmp, const void*, const void*, size_t);
FAKE_VOID_FUNC(OPENSSL_cleanup);
FAKE_VALUE_FUNC(int, OPENSSL_init_crypto, uint64_t, const OPENSSL_INIT_SETTINGS*);
FAKE_VALUE_FUNC(int, OPENSSL_atexit, cmock_crypto_func_ptr2);
FAKE_VOID_FUNC(OPENSSL_thread_stop);
FAKE_VOID_FUNC(OPENSSL_thread_stop_ex, OSSL_LIB_CTX*);
FAKE_VALUE_FUNC(OPENSSL_INIT_SETTINGS*, OPENSSL_INIT_new);
FAKE_VALUE_FUNC(int, OPENSSL_INIT_set_config_filename, OPENSSL_INIT_SETTINGS*, const char*);
FAKE_VOID_FUNC(OPENSSL_INIT_set_config_file_flags, OPENSSL_INIT_SETTINGS*, unsigned long);
FAKE_VALUE_FUNC(int, OPENSSL_INIT_set_config_appname, OPENSSL_INIT_SETTINGS*, const char*);
FAKE_VOID_FUNC(OPENSSL_INIT_free, OPENSSL_INIT_SETTINGS*);
FAKE_VALUE_FUNC(int, CRYPTO_THREAD_run_once, CRYPTO_ONCE*, cmock_crypto_func_ptr3);
FAKE_VALUE_FUNC(int, CRYPTO_THREAD_init_local, CRYPTO_THREAD_LOCAL*, cmock_crypto_func_ptr4);
FAKE_VALUE_FUNC(void*, CRYPTO_THREAD_get_local, CRYPTO_THREAD_LOCAL*);
FAKE_VALUE_FUNC(int, CRYPTO_THREAD_set_local, CRYPTO_THREAD_LOCAL*, void*);
FAKE_VALUE_FUNC(int, CRYPTO_THREAD_cleanup_local, CRYPTO_THREAD_LOCAL*);
FAKE_VALUE_FUNC(CRYPTO_THREAD_ID, CRYPTO_THREAD_get_current_id);
FAKE_VALUE_FUNC(int, CRYPTO_THREAD_compare_id, CRYPTO_THREAD_ID, CRYPTO_THREAD_ID);
FAKE_VALUE_FUNC(OSSL_LIB_CTX*, OSSL_LIB_CTX_new);
FAKE_VALUE_FUNC(OSSL_LIB_CTX*, OSSL_LIB_CTX_new_from_dispatch, const OSSL_CORE_HANDLE*, const OSSL_DISPATCH*);
FAKE_VALUE_FUNC(OSSL_LIB_CTX*, OSSL_LIB_CTX_new_child, const OSSL_CORE_HANDLE*, const OSSL_DISPATCH*);
FAKE_VALUE_FUNC(int, OSSL_LIB_CTX_load_config, OSSL_LIB_CTX*, const char*);
FAKE_VOID_FUNC(OSSL_LIB_CTX_free, OSSL_LIB_CTX*);
FAKE_VALUE_FUNC(OSSL_LIB_CTX*, OSSL_LIB_CTX_get0_global_default);
FAKE_VALUE_FUNC(OSSL_LIB_CTX*, OSSL_LIB_CTX_set0_default, OSSL_LIB_CTX*);
FAKE_VALUE_FUNC(int, OSSL_LIB_CTX_get_conf_diagnostics, OSSL_LIB_CTX*);
FAKE_VOID_FUNC(OSSL_LIB_CTX_set_conf_diagnostics, OSSL_LIB_CTX*, int);
FAKE_VOID_FUNC(OSSL_sleep, uint64_t);
FAKE_VALUE_FUNC(void*, OSSL_LIB_CTX_get_data, OSSL_LIB_CTX*, int);

#define RESET_MOCK_CRYPTO() \
    RESET_FAKE(CRYPTO_THREAD_lock_new); \
    RESET_FAKE(CRYPTO_THREAD_read_lock); \
    RESET_FAKE(CRYPTO_THREAD_write_lock); \
    RESET_FAKE(CRYPTO_THREAD_unlock); \
    RESET_FAKE(CRYPTO_THREAD_lock_free); \
    RESET_FAKE(CRYPTO_atomic_add); \
    RESET_FAKE(CRYPTO_atomic_add64); \
    RESET_FAKE(CRYPTO_atomic_and); \
    RESET_FAKE(CRYPTO_atomic_or); \
    RESET_FAKE(CRYPTO_atomic_load); \
    RESET_FAKE(CRYPTO_atomic_load_int); \
    RESET_FAKE(CRYPTO_atomic_store); \
    RESET_FAKE(OPENSSL_strlcpy); \
    RESET_FAKE(OPENSSL_strlcat); \
    RESET_FAKE(OPENSSL_strnlen); \
    RESET_FAKE(OPENSSL_strtoul); \
    RESET_FAKE(OPENSSL_buf2hexstr_ex); \
    RESET_FAKE(OPENSSL_buf2hexstr); \
    RESET_FAKE(OPENSSL_hexstr2buf_ex); \
    RESET_FAKE(OPENSSL_hexstr2buf); \
    RESET_FAKE(OPENSSL_hexchar2int); \
    RESET_FAKE(OPENSSL_strcasecmp); \
    RESET_FAKE(OPENSSL_strncasecmp); \
    RESET_FAKE(OPENSSL_version_major); \
    RESET_FAKE(OPENSSL_version_minor); \
    RESET_FAKE(OPENSSL_version_patch); \
    RESET_FAKE(OPENSSL_version_pre_release); \
    RESET_FAKE(OPENSSL_version_build_metadata); \
    RESET_FAKE(OpenSSL_version_num); \
    RESET_FAKE(OpenSSL_version); \
    RESET_FAKE(OPENSSL_info); \
    RESET_FAKE(OPENSSL_issetugid); \
    RESET_FAKE(CRYPTO_get_ex_new_index); \
    RESET_FAKE(CRYPTO_free_ex_index); \
    RESET_FAKE(CRYPTO_new_ex_data); \
    RESET_FAKE(CRYPTO_dup_ex_data); \
    RESET_FAKE(CRYPTO_free_ex_data); \
    RESET_FAKE(CRYPTO_alloc_ex_data); \
    RESET_FAKE(CRYPTO_set_ex_data); \
    RESET_FAKE(CRYPTO_get_ex_data); \
    RESET_FAKE(CRYPTO_set_mem_functions); \
    RESET_FAKE(CRYPTO_get_mem_functions); \
    RESET_FAKE(CRYPTO_malloc); \
    RESET_FAKE(CRYPTO_zalloc); \
    RESET_FAKE(CRYPTO_aligned_alloc); \
    RESET_FAKE(CRYPTO_memdup); \
    RESET_FAKE(CRYPTO_strdup); \
    RESET_FAKE(CRYPTO_strndup); \
    RESET_FAKE(CRYPTO_free); \
    RESET_FAKE(CRYPTO_clear_free); \
    RESET_FAKE(CRYPTO_realloc); \
    RESET_FAKE(CRYPTO_clear_realloc); \
    RESET_FAKE(CRYPTO_secure_malloc_init); \
    RESET_FAKE(CRYPTO_secure_malloc_done); \
    RESET_FAKE(CRYPTO_secure_malloc); \
    RESET_FAKE(CRYPTO_secure_zalloc); \
    RESET_FAKE(CRYPTO_secure_free); \
    RESET_FAKE(CRYPTO_secure_clear_free); \
    RESET_FAKE(CRYPTO_secure_allocated); \
    RESET_FAKE(CRYPTO_secure_malloc_initialized); \
    RESET_FAKE(CRYPTO_secure_actual_size); \
    RESET_FAKE(CRYPTO_secure_used); \
    RESET_FAKE(OPENSSL_cleanse); \
    RESET_FAKE(CRYPTO_get_alloc_counts); \
    RESET_FAKE(CRYPTO_set_mem_debug); \
    RESET_FAKE(CRYPTO_mem_ctrl); \
    RESET_FAKE(CRYPTO_mem_debug_push); \
    RESET_FAKE(CRYPTO_mem_debug_pop); \
    RESET_FAKE(CRYPTO_mem_debug_malloc); \
    RESET_FAKE(CRYPTO_mem_debug_realloc); \
    RESET_FAKE(CRYPTO_mem_debug_free); \
    RESET_FAKE(CRYPTO_mem_leaks_cb); \
    RESET_FAKE(CRYPTO_mem_leaks_fp); \
    RESET_FAKE(CRYPTO_mem_leaks); \
    RESET_FAKE(OPENSSL_isservice); \
    RESET_FAKE(OPENSSL_init); \
    RESET_FAKE(OPENSSL_gmtime); \
    RESET_FAKE(OPENSSL_gmtime_adj); \
    RESET_FAKE(OPENSSL_gmtime_diff); \
    RESET_FAKE(CRYPTO_memcmp); \
    RESET_FAKE(OPENSSL_cleanup); \
    RESET_FAKE(OPENSSL_init_crypto); \
    RESET_FAKE(OPENSSL_atexit); \
    RESET_FAKE(OPENSSL_thread_stop); \
    RESET_FAKE(OPENSSL_thread_stop_ex); \
    RESET_FAKE(OPENSSL_INIT_new); \
    RESET_FAKE(OPENSSL_INIT_set_config_filename); \
    RESET_FAKE(OPENSSL_INIT_set_config_file_flags); \
    RESET_FAKE(OPENSSL_INIT_set_config_appname); \
    RESET_FAKE(OPENSSL_INIT_free); \
    RESET_FAKE(CRYPTO_THREAD_run_once); \
    RESET_FAKE(CRYPTO_THREAD_init_local); \
    RESET_FAKE(CRYPTO_THREAD_get_local); \
    RESET_FAKE(CRYPTO_THREAD_set_local); \
    RESET_FAKE(CRYPTO_THREAD_cleanup_local); \
    RESET_FAKE(CRYPTO_THREAD_get_current_id); \
    RESET_FAKE(CRYPTO_THREAD_compare_id); \
    RESET_FAKE(OSSL_LIB_CTX_new); \
    RESET_FAKE(OSSL_LIB_CTX_new_from_dispatch); \
    RESET_FAKE(OSSL_LIB_CTX_new_child); \
    RESET_FAKE(OSSL_LIB_CTX_load_config); \
    RESET_FAKE(OSSL_LIB_CTX_free); \
    RESET_FAKE(OSSL_LIB_CTX_get0_global_default); \
    RESET_FAKE(OSSL_LIB_CTX_set0_default); \
    RESET_FAKE(OSSL_LIB_CTX_get_conf_diagnostics); \
    RESET_FAKE(OSSL_LIB_CTX_set_conf_diagnostics); \
    RESET_FAKE(OSSL_sleep); \
    RESET_FAKE(OSSL_LIB_CTX_get_data);

#endif // mock_crypto_H
