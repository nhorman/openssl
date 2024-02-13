/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/namemap.h"
#include <openssl/lhash.h>
#include "crypto/lhash.h"      /* ossl_lh_strcasehash */
#include "internal/hashtable.h"
#include "internal/tsan_assist.h"
#include "internal/sizes.h"
#include "crypto/context.h"

/*-
 * The namenum entry
 * =================
 */
typedef struct {
    char *name;
    int number;
} NAMENUM_ENTRY;

/*
 * Defines our NAMENUM_ENTRY hashtable key
 */
HT_START_KEY_DEFN(namenum_key)
HT_DEF_KEY_FIELD_CHAR_ARRAY(name, 64)
HT_END_KEY_DEFN(NAMENUM_KEY)

HT_START_KEY_DEFN(numname_key)
HT_DEF_KEY_FIELD(number, int)
HT_END_KEY_DEFN(NUMNAME_KEY)

IMPLEMENT_HT_VALUE_TYPE_FNS(NAMENUM_ENTRY, nne, static)

/*-
 * The namemap itself
 * ==================
 */

struct ossl_namemap_st {
    /* Flags */
    unsigned int stored:1; /* If 1, it's stored in a library context */

    HT *namenum;  /* Name->number mapping */

    HT *numname; /* Number->name mapping */

    TSAN_QUALIFIER int max_number;     /* Current max number */
};

static void namenum_free(NAMENUM_ENTRY *n)
{
    if (n != NULL)
        OPENSSL_free(n->name);
    OPENSSL_free(n);
}

/* OSSL_LIB_CTX_METHOD functions for a namemap stored in a library context */

void *ossl_stored_namemap_new(OSSL_LIB_CTX *libctx)
{
    OSSL_NAMEMAP *namemap = ossl_namemap_new();

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

    rv = namemap->max_number == 0;
    return rv;
#else
    /* Have TSAN support */
    return namemap == NULL || tsan_load(&namemap->max_number) == 0;
#endif
}

struct do_each_name_data {
    union {
        void (*fn)(const char *name, void *data);
        int (*fnu)(const char *name, void *data);
    };
    void *data;
    int number;
};

static void do_each_name(HT_VALUE *v, void *arg)
{
    NAMENUM_ENTRY *namenum = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);
    struct do_each_name_data *data = arg;

    if (namenum != NULL && namenum->number == data->number)
        data->fn(namenum->name, data->data);
}

static int do_each_name_until(HT_VALUE *v, void *arg)
{
    NAMENUM_ENTRY *namenum = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);
    struct do_each_name_data *data = arg;

    if (namenum != NULL && namenum->number == data->number)
        return data->fnu(namenum->name, data->data);
    return 1;
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
    struct do_each_name_data foreach_data;

    foreach_data.fn = fn;
    foreach_data.data = data;
    foreach_data.number = number;

    if (namemap == NULL)
        return 0;

    ossl_ht_foreach(namemap->namenum, do_each_name, &foreach_data);

    return 1;
}

int ossl_namemap_doall_names_until(const OSSL_NAMEMAP *namemap, int number,
                                   int (*fn)(const char *name, void *data),
                                   void *data)
{
    struct do_each_name_data foreach_data;

    foreach_data.fnu = fn;
    foreach_data.data = data;
    foreach_data.number = number;

    if (namemap == NULL)
        return 0;

    ossl_ht_foreach_until(namemap->namenum, do_each_name_until, &foreach_data);

    return 1;
}
static int namemap_name2num(const OSSL_NAMEMAP *namemap,
                            const char *name)
{
    NAMENUM_ENTRY *namenum_entry;
    HT_VALUE *v;
    NAMENUM_KEY key;
    int num;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE(&key, name, name);

    v = ossl_ht_get(namemap->namenum, TO_HT_KEY(&key));
    if (v == NULL) {
        num = 0;
    } else {
        namenum_entry = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);
        num = namenum_entry->number;
        ossl_ht_put(v);
    }
    return num;
}

int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)
{
    int number;

#ifndef FIPS_MODULE
    if (namemap == NULL)
        namemap = ossl_namemap_stored(NULL);
#endif

    if (namemap == NULL)
        return 0;

    number = namemap_name2num(namemap, name);

    return number;
}

int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap,
                            const char *name, size_t name_len)
{
    char *tmp;
    int ret;

    if (name == NULL || (tmp = OPENSSL_strndup(name, name_len)) == NULL)
        return 0;

    ret = ossl_namemap_name2num(namemap, tmp);
    OPENSSL_free(tmp);
    return ret;
}

const char *ossl_namemap_num2name(const OSSL_NAMEMAP *namemap, int number,
                                  size_t idx)
{
    NAMENUM_ENTRY *e;
    NUMNAME_KEY key;
    HT_VALUE *v;

    HT_INIT_KEY(&key);
    HT_SET_KEY_FIELD(&key, number, number);

    v = ossl_ht_get(namemap->numname, TO_HT_KEY(&key));
    e = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);

    return e != NULL ? e->name : NULL;
}

static int namemap_add_name(OSSL_NAMEMAP *namemap, int number,
                            const char *name)
{
    NAMENUM_ENTRY *namenum = NULL;
    int rc;
    int tmp_number;
    NAMENUM_KEY key;
    NUMNAME_KEY rkey;

    HT_INIT_KEY(&key);
    HT_SET_KEY_STRING_CASE(&key, name, name);
    HT_INIT_KEY(&rkey);

    /* If it already exists, we don't add it */
    if ((tmp_number = namemap_name2num(namemap, name)) != 0)
        return tmp_number;

    if ((namenum = OPENSSL_zalloc(sizeof(*namenum))) == NULL)
        return 0;

    if ((namenum->name = OPENSSL_strdup(name)) == NULL)
        goto err;

    /* The tsan_counter use here is safe since it uses atomics */
    namenum->number =
        number != 0 ? number : 1 + tsan_counter(&namemap->max_number);

    rc = ossl_ht_nne_NAMENUM_ENTRY_insert(namemap->namenum,
                                          TO_HT_KEY(&key), namenum, NULL);
    if (rc == 0)
        goto err;

    HT_SET_KEY_FIELD(&rkey, number, namenum->number);

    /* Note:
     * insert failure is ok here, as it indicates that we have multiple
     * names mapping to a number, and we only need one reverse mapping
     */
    ossl_ht_nne_NAMENUM_ENTRY_insert(namemap->numname,
                                     TO_HT_KEY(&rkey), namenum, NULL);

    return namenum->number;

 err:
    namenum_free(namenum);
    return 0;
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
        int this_number;
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

        this_number = namemap_name2num(namemap, p);

        if (number == 0) {
            number = this_number;
        } else if (this_number != 0 && this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_CONFLICTING_NAMES,
                           "\"%s\" has an existing different identity %d (from \"%s\")",
                           p, this_number, names);
            number = 0;
            goto end;
        }
    }
    endp = p;

    /* Now that we have checked, register all names */
    for (p = tmp; p < endp; p = q) {
        int this_number;

        q = p + strlen(p) + 1;

        this_number = namemap_add_name(namemap, number, p);
        if (number == 0) {
            number = this_number;
        } else if (this_number != number) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                           "Got number %d when expecting %d",
                           this_number, number);
            number = 0;
            goto end;
        }
    }

 end:
    OPENSSL_free(tmp);
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

static void namenum_ht_free(HT_VALUE *v)
{
    NAMENUM_ENTRY *e = NULL;

    e = ossl_ht_nne_NAMENUM_ENTRY_from_value(v);
    namenum_free(e);
    return;
}

OSSL_NAMEMAP *ossl_namemap_new(void)
{
    OSSL_NAMEMAP *namemap;

    /*
     * Hash table config
     * namenum_ht_free is our free fn
     * use the internal fnv1a hash
     * 1024 initial buckets
     * do lockless reads
     */
    HT_CONFIG ht_conf = {
        namenum_ht_free,
        NULL,
        1024,
        1,
        1
    };
    HT_CONFIG reverse_ht_conf = {
        NULL, /* all entries owned by namemap, dont free */
        NULL, /* use default hash function */
        1024, /* same size of namemap */
        1,    /* don't refcount */
        1     /* lockless */
    };

    if ((namemap = OPENSSL_zalloc(sizeof(*namemap))) == NULL)
        return NULL;

    namemap->namenum = ossl_ht_new(&ht_conf);
    namemap->numname = ossl_ht_new(&reverse_ht_conf);

    if ((namemap->namenum == NULL) || (namemap->numname == NULL)) {
        ossl_namemap_free(namemap);
        namemap = NULL;
    }

    return namemap;
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
    if (namemap == NULL || namemap->stored)
        return;

    ossl_ht_free(namemap->numname);
    ossl_ht_free(namemap->namenum);

    OPENSSL_free(namemap);
}
