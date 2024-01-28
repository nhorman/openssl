/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HASHTABLE_H
# define OPENSSL_HASHTABLE_H
# pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct ht_internal_st HT;

/*
 * Represents a value in the hash table
 */
typedef struct ht_value_st {
    void *value;
    uint32_t type_id;
} HT_VALUE;

/*
 * Represents a list of values filtered from a hash table
 */
typedef struct ht_value_list_st {
    size_t list_len;
    HT_VALUE **list;
} HT_VALUE_LIST;

/*
 * Hashtable configuration
 */
typedef struct ht_config_st {
    void (*ht_free_fn)(HT_VALUE *obj);
    uint64_t (*ht_hash_fn)(uint8_t *key, size_t keylen);
    uint32_t init_bucket_len;
    int lockless_read;
    int dont_refcount;
} HT_CONFIG;

/*
 * Key value for a hash lookup
 */
typedef struct ht_key_header_st {
    size_t keysize;
    uint8_t *keybuf;
} HT_KEY;

/*
 * Hashtable key rules
 * Any struct can be used to formulate a hash table key, as long as the
 * following rules
 * 1) The first element of the struct defining the key must be an HT_KEY
 * 2) All struct elements must have a compile time defined length
 * 3) No pointers may be used
 * The key definition macros will assist with enforcing these rules
 */

/*
 * Starts the defintion of a hash table key
 */
#define HT_START_KEY_DEFN(keyname) \
typedef struct keyname##_st { \
    HT_KEY key_header; \
    struct {

/*
 * Ends a hash table key definitions
 */
#define HT_END_KEY_DEFN(keyname) \
    }; \
} keyname;

/*
 * Defines a field in a hash table key
 */
#define HT_DEF_KEY_FIELD(name, type) type name;

/*
 * convienience macro to define a static char
 * array field in a hash table key
 */
#define HT_DEF_KEY_FIELD_CHAR_ARRAY(name, size) \
     HT_DEF_KEY_FIELD(name[size], char)

/*
 * Defines a uint8_t (blob) field in a hash table key
 */
#define HT_DEF_KEY_FIELD_UINT8T_ARRAY(name, size) \
    HT_DEF_KEY_FIELD(name[size], uint8_t)

/*
 * Initalizes a key
 */
#define HT_INIT_KEY(key) do { \
memset((key), 0, sizeof(*(key))); \
(key)->key_header.keysize = (sizeof(*(key)) - sizeof(HT_KEY)); \
(key)->key_header.keybuf = (((uint8_t *)key) + sizeof(HT_KEY)); \
} while(0)

/*
 * Resets a hash table key to a known state
 */
#define HT_KEY_RESET(key) memset((key)->key_header.keybuf, 0, (key)->key_header.keysize)

/*
 * Sets a scalar field in a hash table key
 */
#define HT_SET_KEY_FIELD(key, member, value) (key)->member = value;

/*
 * Sets a string field in a hash table key, preserving
 * null terminator
 */
#define HT_SET_KEY_STRING(key, member, value) do { \
    if ((value) != NULL) \
        strncpy((key)->member, value, sizeof((key)->member) - 1); \
} while(0)

#define HT_SET_KEY_STRING_CASE(key, member, value) do { \
   ossl_ht_strcase((key)->member, value, sizeof((key)->member) -1); \
} while(0)

/*
 * Sets a uint8_t (blob) field in a hash table key
 */
#define HT_SET_KEY_BLOB(key, member, value, len) do { \
    if (value != NULL) \
        memcpy((key)->member, value, len); \
} while(0)

/*
 * Converts a defined key type to an HT_KEY
 */
#define TO_HT_KEY(key) &(key)->key_header

/*
 * Converts an HT_KEY back to its defined
 * type
 */
#define FROM_HT_KEY(key, type) (type)(key)

/*
 * Implements the following type safe operations for a hash table
 * ossl_ht_NAME_TYPE_insert - insert a value to a hash table of type TYPE
 * ossl_ht_NAME_TYPE_from_value - converts an HT_VALUE to its type
 * ossl_ht_NAME_TYPE_to_value - converts a TYPE to an HT_VALUE
 * ossl_ht_NAME_TYPE_type - boolean to detect if a value is of TYPE
 */
#define IMPLEMENT_HT_VALUE_TYPE_FNS(vtype, name, pfx) \
static uint32_t name##_##vtype##_id = __LINE__; \
pfx ossl_unused int ossl_ht_##name##_##vtype##_insert(HT *h, HT_KEY *key, vtype *data, vtype **olddata) {\
    HT_VALUE inval;                                                            \
    HT_VALUE *oval = NULL;                                                     \
    int rc;                                                                    \
                                                                               \
    inval.value = data;                                                        \
    inval.type_id = name##_##vtype##_id;                                       \
    rc = ossl_ht_insert(h, key, &inval, olddata == NULL ? NULL : &oval);\
    if (oval != NULL)                                                          \
        *olddata = (vtype *)oval->value;                                       \
    return rc;                                                                 \
}                                                                              \
                                                                               \
pfx ossl_unused vtype *ossl_ht_##name##_##vtype##_from_value(HT_VALUE *v)\
{                                                                              \
    uint32_t expect_type = name##_##vtype##_id;                                \
    if (!ossl_assert(v->type_id == expect_type)) {                             \
        return NULL;                                                           \
    }                                                                          \
    return (vtype *)v->value;                                                  \
}                                                                              \
                                                                               \
pfx ossl_unused HT_VALUE *ossl_ht_##name##_##vtype##_to_value(vtype *data, HT_VALUE *v)      \
{                                                                              \
    v->type_id = name##_##vtype##_id;                                          \
    v->value = data;                                                           \
    return v;                                                                  \
}                                                                              \
                                                                               \
pfx ossl_unused inline int ossl_ht_##name##_##vtype##_type(HT_VALUE *h) \
{                                                                              \
    return h->type_id == name##_##vtype##_id;                                  \
}

/*
 * Helper function to construct case insensitive keys
 */
static inline void ossl_ht_strcase(char *tgt, const char *src, int len)
{
    int i;
#if defined(CHARSET_EBCDIC) && !defined(CHARSET_EBCDIC_TEST)
    const long int case_adjust = ~0x40;
#else
    const long int case_adjust = ~0x20;
#endif

    if (src == NULL)
        return;

    for (i = 0; src[i] != '\0' && i < len; i++)
        tgt[i] = case_adjust & src[i];
}

/*
 * Create a new hashtable
 */
HT *ossl_ht_new(HT_CONFIG *conf);

/*
 * Frees a hash table, potentially freeing all elements
 */
void ossl_ht_free(HT *htable);

/*
 * Empties a hash table, potentially freeing all elements
 */
int  ossl_ht_flush(HT *htable);

/*
 * Inserts an element to a hash table, optionally returning
 * replaced data to caller
 */
int ossl_ht_insert(HT *htable, HT_KEY *key, HT_VALUE *data,
                          HT_VALUE **olddata);

/*
 * Deletes a value from a hash table, based on key
 */
HT_VALUE *ossl_ht_delete(HT *htable, HT_KEY *key);

/*
 * Returns number of elements in the hash table
 */
size_t ossl_ht_count(HT *htable);

/*
 * Iterates of the hash table calling cb for each element
 */
void ossl_ht_foreach(HT *htable, void (*cb)(HT_VALUE *obj, void *arg),
                     void *arg);

/*
 * Variant of foreach, but aborts the loop when cb returns 0
 */
void ossl_ht_foreach_until(HT *htable, int (*cb)(HT_VALUE *obj, void *arg),
                           void *arg);
/*
 * Returns a list of elements in a hash table based on
 * filter function return value
 */
HT_VALUE_LIST *ossl_ht_filter(HT *htable, size_t max_len,
                                     int (*filter)(HT_VALUE *obj, void *arg),
                                     void *arg);
/*
 * Frees the list returned from ossl_ht_filter
 */
void ossl_ht_value_list_free(HT_VALUE_LIST *list);

/*
 * Fetches a value from the hash table, based
 * on key
 */
HT_VALUE *ossl_ht_get(HT *htable, HT_KEY *key);

/*
 * Drops the reference count on hash table values
 * returned from ossl_ht_filter, ossl_ht_get, and
 * ossl_ht_insert, potentially freeing the value
 */
void ossl_ht_put(HT_VALUE *value);


#endif
