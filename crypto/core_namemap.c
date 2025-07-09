/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/namemap.h"
#include "internal/tsan_assist.h"
#include "internal/hashtable.h"
#include "internal/lockless.h"
#include "internal/sizes.h"
#include "crypto/context.h"

#define NAMEMAP_HT_BUCKETS 512

HT_START_KEY_DEFN(namenum_key)
HT_DEF_KEY_FIELD_CHAR_ARRAY(name, 64)
HT_END_KEY_DEFN(NAMENUM_KEY)

/*-
 * The namemap itself
 * ==================
 */

struct ossl_namemap_st {
    /* Flags */
    unsigned int stored:1; /* If 1, it's stored in a library context */

    HT *namenum_ht;        /* Name->number mapping */

    LLL *numname_list;                 /* list of number to name mappings */
    TSAN_QUALIFIER int max_number;     /* Current max number */
};

/* OSSL_LIB_CTX_METHOD functions for a namemap stored in a library context */

void *ossl_stored_namemap_new(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_namemap_new(libctx);

    if (namemap != NULL)
        namemap->stored = 1;

    return namemap;
}

void ossl_stored_namemap_free(void *vnamemap)
{
    OSSL_NAMEMAP *namemap = vnamemap;

    if (namemap != NULL) {
        /* Pretend it isn't stored, or ossl_namemap_free() will do nothing */
        namemap->stored = 0;
        ossl_namemap_free(namemap);
    }
}

/*-
 * API functions
 * =============
 */

int ossl_namemap_empty(OSSL_NAMEMAP *namemap)
{
#ifdef TSAN_REQUIRES_LOCKING
    /* No TSAN support */
    int rv;

    if (namemap == NULL)
        return 1;

        return -1;
    rv = namemap->max_number == 0;
    return rv;
#else
    /* Have TSAN support */
    return namemap == NULL || tsan_load(&namemap->max_number) == 0;
#endif
}

typedef struct nm_numname_st {
    char *tmpinsert;
    int number;
    LLL *names_list;
} NUMNAME;

struct doall_names_info {
    int number;
    void (*fn)(const char *name, void *data);
    void *data;
};

static int call_for_name(void *a, void *b, void *arg, int restart)
{
    char *name = (char *)a;
    struct doall_names_info *info = (struct doall_names_info *)arg;

    info->fn(name, info->data);
    return -1;
}

static int find_numname_number(void *a, void *b, void *arg, int restart)
{
    NUMNAME *node = (NUMNAME *)a;
    struct doall_names_info *info = (struct doall_names_info *)arg;

    if (node->number == info->number) {
        LLL_iterate(node->names_list, call_for_name, arg);
        return 0;
    }
    return -1;

}

/*
 * Call the callback for all names in the namemap with the given number.
 * A return value 1 means that the callback was called for all names. A
 * return value of 0 means that the callback was not called for any names.
 */
int ossl_namemap_doall_names(const OSSL_NAMEMAP *namemap, int number,
                             void (*fn)(const char *name, void *data),
                             void *data)
{
    struct doall_names_info info = { number, fn, data };

    if (namemap == NULL || number <= 0)
        return 0;
    if (!LLL_iterate(namemap->numname_list, find_numname_number, &info))
        return 0;
    return 1;
}

int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)
{
    int number = 0;
    HT_VALUE *val;
    NAMENUM_KEY key;

#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE(&key, name, name);

    val = ossl_ht_get(namemap->namenum_ht, TO_HT_KEY(&key));

    if (val != NULL)
        /* We store a (small) int directly instead of a pointer to it. */
        number = (int)(intptr_t)val->value;

    return number;
}

int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap,
                            const char *name, size_t name_len)
{
    int number = 0;
    HT_VALUE *val;
    NAMENUM_KEY key;

#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE_N(&key, name, name, (int)name_len);

    val = ossl_ht_get(namemap->namenum_ht, TO_HT_KEY(&key));

    if (val != NULL)
        /* We store a (small) int directly instead of a pointer to it. */
        number = (int)(intptr_t)val->value;

    return number;
}

struct num2name_info {
    int number;
    int idx;
    int idx_counter;
    const char *name;
};

static int find_idx_in_names(void *a, void *b, void *arg, int restart)
{
    const char *name = (char *)a;
    struct num2name_info *info = (struct num2name_info *)arg;

    if (restart == 1)
        info->idx_counter = 0;

    if (info->idx == info->idx_counter) {
        info->name = name;
        return 0;
    }
    info->idx_counter++;
    return -1;
}

static int find_num_in_numnames(void *a, void *b, void *arg, int restart)
{
    NUMNAME *node = (NUMNAME *)a;
    struct num2name_info *info = (struct num2name_info *)arg;

    if (node->number == info->number) {
        LLL_iterate(node->names_list, find_idx_in_names, arg);
        return 0;
    }
    return -1;
}

const char *ossl_namemap_num2name(const OSSL_NAMEMAP *namemap, int number,
                                  int idx)
{
    struct num2name_info info = { number, idx, 0, NULL };

    if (namemap == NULL || number <= 0)
        return NULL;

    if (!LLL_iterate(namemap->numname_list, find_num_in_numnames, &info))
        return NULL;
    return info.name;
}

struct numname_cmp_st {
    int number_count;
    int initial_num_request;
};

static int names_list_compare(void *a, void *b, void *arg, int restart)
{
    char *node = (char *)a;
    char *key = (char *)b;

    return strcmp(node, key);
}

static void names_list_free(void *data)
{
    OPENSSL_free(data);
}

static int find_insert_name(void *a, void *b, void *arg, int restart)
{
    NUMNAME *node = (NUMNAME *)a;
    NUMNAME *key = (NUMNAME *)arg; /* note this is an iterator, key is in arg */

    if (node->number != key->number)
        return -1;

    /*
     * We found a match, add the new name
     */
    LLL_insert(node->names_list, key->tmpinsert, NULL);
    return 0;
}

static int numname_insert(OSSL_NAMEMAP *namemap, int number,
                          const char *name)
{
    char *tmpname;
    NUMNAME *numname;
    NUMNAME key;

    if (number == 0) {
        /*
         * We're inserting a new name at a newly allocated number
         */

        /*
         * Allocate a new numname
         */
        numname = OPENSSL_zalloc(sizeof(NUMNAME));
        if (numname == NULL)
            return 0;
        /*
         * And a new names list
         */
        numname->names_list = LLL_new(names_list_compare, names_list_free, 1);
        if (numname->names_list == NULL) {
            OPENSSL_free(numname);
            return 0;
        }

        /*
         * Dup our name to insert into the names list
         */
        tmpname = OPENSSL_strdup(name);
        if (tmpname == NULL) {
            LLL_free(numname->names_list);
            OPENSSL_free(numname);
            return 0;
        }

        /*
         * Because we privately hold the names_list still, insert the new
         * name now
         */
        if (!LLL_insert(numname->names_list, tmpname, NULL)) {
            /*
             * Something wen't wrong, free up memory
             */
            OPENSSL_free(tmpname);
            LLL_free(numname->names_list);
            OPENSSL_free(numname);
            return 0;
        }

        /*
         * Get a new number
         */
        numname->number = tsan_counter(&namemap->max_number) + 1;

        /*
         * and insert our new entry into the numname list
         */
        if (!LLL_insert(namemap->numname_list, numname, NULL)) {
            /*
             * insert went bad, back everything out
             * Note we don't need to free tmpname here
             * as the LLL_free handles that
             */
            LLL_free(numname->names_list);
            OPENSSL_free(numname);
            return 0;
        }
        number = numname->number;
    } else {
        /*
         * We're inserting to an already allocated number here, so 
         * we need to iterate through the list, looking for the matching
         * value, at which point we insert to its names list
         */

        /* create the key to search for */
        key.number = number;
        key.tmpinsert = OPENSSL_strdup(name);
        if (key.tmpinsert == NULL)
            return 0;

        /*
         * search for the key in the list, and add the new name, passed as arg
         * to that entries name list
         */
        if (!LLL_iterate(namemap->numname_list, find_insert_name, &key)) {
            /*
             * We didn't find a matching number, thats bad, get out
             */
            OPENSSL_free(key.tmpinsert);
            return 0;
        }
        number = key.number;
    }
    return number;
}

static int namemap_add_name(OSSL_NAMEMAP *namemap, int number,
                            const char *name)
{
    int ret;
    HT_VALUE val = { 0 };
    NAMENUM_KEY key;

    /* If it already exists, we don't add it */
    if ((ret = ossl_namemap_name2num(namemap, name)) != 0) {
        return ret;
    }

    if ((number = numname_insert(namemap, number, name)) == 0)
        return 0;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE(&key, name, name);
    val.value = (void *)(intptr_t)number;
    ret = ossl_ht_insert(namemap->namenum_ht, TO_HT_KEY(&key), &val, NULL);
    if (!ossl_assert(ret != 0))
        return 0;
    if (ret < 1) {
        /* unable to insert due to too many collisions */
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_NAMES);
        return 0;
    }
    return number;
}

int ossl_namemap_add_name(OSSL_NAMEMAP *namemap, int number,
                          const char *name)
{
    int tmp_number;
#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (name == NULL || *name == 0 || namemap == NULL)
        return 0;

    tmp_number = namemap_add_name(namemap, number, name);
    return tmp_number;
}

int ossl_namemap_add_names(OSSL_NAMEMAP *namemap, int number,
                           const char *names, const char separator)
{
    char *tmp, *p, *q, *endp;

    /* Check that we have a namemap */
    if (!ossl_assert(namemap != NULL)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((tmp = OPENSSL_strdup(names)) == NULL)
        return 0;

    /*
     * Check that no name is an empty string, and that all names have at
     * most one numeric identity together.
     */
    for (p = tmp; *p != '\0'; p = q) {
        size_t l;

        if ((q = strchr(p, separator)) == NULL) {
            l = strlen(p);       /* offset to \0 */
            q = p + l;
        } else {
            l = q - p;           /* offset to the next separator */
            *q++ = '\0';
        }

        if (*p == '\0') {
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_BAD_ALGORITHM_NAME);
            number = 0;
            goto end;
        }
    }
    endp = p;

    /*
     * make sure that we have one unique number for all the names in this list
     */
    for (p = tmp; p < endp; p = q) {
        int this_number;

        this_number = ossl_namemap_name2num(namemap, p);

        if (number == 0 && this_number != 0) {
            number = this_number;
            break;
        }

        q = p + strlen(p) + 1;
    }

    /* Now that we have checked, register all names */
    for (p = tmp; p < endp; p = q) {
        int this_number;

        this_number = namemap_add_name(namemap, number, p);
        if (number == 0)
            number = this_number;
        if (number != 0 && this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_CONFLICTING_NAMES,
                           "\"%s\" has an existing different identity %d (from \"%s\")",
                           p, this_number, names);
            number = 0;
            goto end;
        }
        q = p + strlen(p) + 1;
    }

 end:
    return number;
}

/*-
 * Pre-population
 * ==============
 */

#ifndef FIPS_MODULE
#include <openssl/evp.h>

/* Creates an initial namemap with names found in the legacy method db */
static void get_legacy_evp_names(int base_nid, int nid, const char *pem_name,
                                 void *arg)
{
    int num = 0;
    ASN1_OBJECT *obj;

    if (base_nid != NID_undef) {
        num = ossl_namemap_add_name(arg, num, OBJ_nid2sn(base_nid));
        num = ossl_namemap_add_name(arg, num, OBJ_nid2ln(base_nid));
    }

    if (nid != NID_undef) {
        num = ossl_namemap_add_name(arg, num, OBJ_nid2sn(nid));
        num = ossl_namemap_add_name(arg, num, OBJ_nid2ln(nid));
        if ((obj = OBJ_nid2obj(nid)) != NULL) {
            char txtoid[OSSL_MAX_NAME_SIZE];

            if (OBJ_obj2txt(txtoid, sizeof(txtoid), obj, 1) > 0)
                num = ossl_namemap_add_name(arg, num, txtoid);
        }
    }
    if (pem_name != NULL)
        num = ossl_namemap_add_name(arg, num, pem_name);
}

static void get_legacy_cipher_names(const OBJ_NAME *on, void *arg)
{
    const EVP_CIPHER *cipher = (void *)OBJ_NAME_get(on->name, on->type);

    if (cipher != NULL)
        get_legacy_evp_names(NID_undef, EVP_CIPHER_get_type(cipher), NULL, arg);
}

static void get_legacy_md_names(const OBJ_NAME *on, void *arg)
{
    const EVP_MD *md = (void *)OBJ_NAME_get(on->name, on->type);

    if (md != NULL)
        get_legacy_evp_names(0, EVP_MD_get_type(md), NULL, arg);
}

static void get_legacy_pkey_meth_names(const EVP_PKEY_ASN1_METHOD *ameth,
                                       void *arg)
{
    int nid = 0, base_nid = 0, flags = 0;
    const char *pem_name = NULL;

    EVP_PKEY_asn1_get0_info(&nid, &base_nid, &flags, NULL, &pem_name, ameth);
    if (nid != NID_undef) {
        if ((flags & ASN1_PKEY_ALIAS) == 0) {
            switch (nid) {
            case EVP_PKEY_DHX:
                /* We know that the name "DHX" is used too */
                get_legacy_evp_names(0, nid, "DHX", arg);
                /* FALLTHRU */
            default:
                get_legacy_evp_names(0, nid, pem_name, arg);
            }
        } else {
            /*
             * Treat aliases carefully, some of them are undesirable, or
             * should not be treated as such for providers.
             */

            switch (nid) {
            case EVP_PKEY_SM2:
                /*
                 * SM2 is a separate keytype with providers, not an alias for
                 * EC.
                 */
                get_legacy_evp_names(0, nid, pem_name, arg);
                break;
            default:
                /* Use the short name of the base nid as the common reference */
                get_legacy_evp_names(base_nid, nid, pem_name, arg);
            }
        }
    }
}
#endif

/*-
 * Constructors / destructors
 * ==========================
 */

OSSL_NAMEMAP *ossl_namemap_stored(OSSL_LIB_CTX *libctx)
{
#ifndef FIPS_MODULE
    int nms;
#endif
    OSSL_NAMEMAP *namemap =
        ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_NAMEMAP_INDEX);

    if (namemap == NULL)
        return NULL;

#ifndef FIPS_MODULE
    nms = ossl_namemap_empty(namemap);
    if (nms < 0) {
        /*
         * Could not get lock to make the count, so maybe internal objects
         * weren't added. This seems safest.
         */
        return NULL;
    }
    if (nms == 1) {
        int i, end;

        /* Before pilfering, we make sure the legacy database is populated */
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                            | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

        OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH,
                        get_legacy_cipher_names, namemap);
        OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH,
                        get_legacy_md_names, namemap);

        /* We also pilfer data from the legacy EVP_PKEY_ASN1_METHODs */
        for (i = 0, end = EVP_PKEY_asn1_get_count(); i < end; i++)
            get_legacy_pkey_meth_names(EVP_PKEY_asn1_get0(i), namemap);
    }
#endif

    return namemap;
}

static int numname_compare(void *a, void *b, void *arg, int restart)
{
    NUMNAME *node = (NUMNAME *)a;
    NUMNAME *new = (NUMNAME *)b;

    if (node->number < new->number)
        return -1;
    else if (node->number > new->number)
        return 1;
    return 0;
}

static void numname_free(void *data)
{
    NUMNAME *d = (NUMNAME *)data;

    LLL_free(d->names_list);
    OPENSSL_free(d);
}

OSSL_NAMEMAP *ossl_namemap_new(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap;
    HT_CONFIG htconf = { NULL, NULL, NULL, NAMEMAP_HT_BUCKETS, 1, 1 };

    htconf.ctx = libctx;

    if ((namemap = OPENSSL_zalloc(sizeof(*namemap))) == NULL)
        goto err;

    if ((namemap->namenum_ht = ossl_ht_new(&htconf)) == NULL)
        goto err;

    if ((namemap->numname_list = LLL_new(numname_compare, numname_free, 1)) == NULL)
        goto err;

    return namemap;

 err:
    ossl_namemap_free(namemap);
    return NULL;
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
    if (namemap == NULL || namemap->stored)
        return;

    ossl_ht_free(namemap->namenum_ht);
    LLL_free(namemap->numname_list);
    OPENSSL_free(namemap);
}
