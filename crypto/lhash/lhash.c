/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/err.h>
#include "crypto/ctype.h"
#include "crypto/lhash.h"
#include "internal/refcount.h"
#include "lhash_local.h"

/*
 * A hashing implementation that appears to be based on the linear hashing
 * algorithm:
 * https://en.wikipedia.org/wiki/Linear_hashing
 *
 * Litwin, Witold (1980), "Linear hashing: A new tool for file and table
 * addressing", Proc. 6th Conference on Very Large Databases: 212-223
 * https://hackthology.com/pdfs/Litwin-1980-Linear_Hashing.pdf
 *
 * From the Wikipedia article "Linear hashing is used in the BDB Berkeley
 * database system, which in turn is used by many software systems such as
 * OpenLDAP, using a C implementation derived from the CACM article and first
 * published on the Usenet in 1988 by Esmond Pitt."
 *
 * The CACM paper is available here:
 * https://pdfs.semanticscholar.org/ff4d/1c5deca6269cc316bfd952172284dbf610ee.pdf
 */

#undef MIN_NODES
#define MIN_NODES       16
#define UP_LOAD         (2*LH_LOAD_MULT) /* load times 256 (default 2) */
#define DOWN_LOAD       (LH_LOAD_MULT) /* load times 256 (default 1) */

static int expand(struct lhash_ctrl_st *lhctrl, CRYPTO_RCU_LOCK *lock);
static int expand_rcu(struct lhash_ctrl_st *lhctrl, struct lhash_ctrl_st **new);
static void contract(struct lhash_ctrl_st *lhctrl);
static void contract_rcu(struct lhash_ctrl_st *lhctrl, struct lhash_ctrl_st **new);
static OPENSSL_LH_NODE **getrn(struct lhash_ctrl_st *lhcrtl,
                               OPENSSL_LH_COMPFUNC cf,
                               OPENSSL_LH_HASHFUNC hf,
                               const void *data, unsigned long *rhash);
static OPENSSL_LH_NODE **getrn_rcu(struct lhash_ctrl_st *lhcrtl,
                               OPENSSL_LH_COMPFUNC cf,
                               OPENSSL_LH_HASHFUNC hf,
                               const void *data, unsigned long *rhash);

OPENSSL_LHASH *OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c)
{
    OPENSSL_LHASH *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    if ((ret->ctrl.b =
         OPENSSL_zalloc(sizeof(*ret->ctrl.b) * MIN_NODES)) == NULL)
        goto err;
    ret->comp = ((c == NULL) ? (OPENSSL_LH_COMPFUNC)strcmp : c);
    ret->hash = ((h == NULL) ? (OPENSSL_LH_HASHFUNC)OPENSSL_LH_strhash : h);
    ret->ctrl.num_nodes = MIN_NODES / 2;
    ret->ctrl.num_alloc_nodes = MIN_NODES;
    ret->ctrl.pmax = MIN_NODES / 2;
    ret->ctrl.up_load = UP_LOAD;
    ret->ctrl.down_load = DOWN_LOAD;
    return ret;

err:
    OPENSSL_free(ret->ctrl.b);
    OPENSSL_free(ret);
    return NULL;
}

OPENSSL_LHASH *OPENSSL_LH_rc_new(OPENSSL_LH_HASHFUNC h,
                                 OPENSSL_LH_COMPFUNC c, OPENSSL_LH_FREEFUNC f)
{
    OPENSSL_LHASH *ret;
    struct lhash_ctrl_st *newctrl;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    if ((newctrl = OPENSSL_zalloc(sizeof(struct lhash_ctrl_st))) == NULL)
        goto err;
    if ((newctrl->b = OPENSSL_zalloc(sizeof(*newctrl->b) * MIN_NODES)) == NULL)
        goto err;
    if ((ret->lock = CRYPTO_THREAD_rcu_lock_new()) == NULL)
        goto err;

    ret->comp = ((c == NULL) ? (OPENSSL_LH_COMPFUNC)strcmp : c);
    ret->hash = ((h == NULL) ? (OPENSSL_LH_HASHFUNC)OPENSSL_LH_strhash : h);
    newctrl->num_nodes = MIN_NODES / 2;
    newctrl->num_alloc_nodes = MIN_NODES;
    newctrl->pmax = MIN_NODES / 2;
    newctrl->up_load = UP_LOAD;
    newctrl->down_load = DOWN_LOAD;
    newctrl->free = f;
    CRYPTO_THREAD_rcu_assign_pointer(&ret->ctrlptr, &newctrl);

    return ret;

err:
    CRYPTO_THREAD_rcu_lock_free(ret->lock);
    OPENSSL_free(newctrl->b);
    OPENSSL_free(newctrl);
    OPENSSL_free(ret);
    return NULL;
}

void OPENSSL_LH_free(OPENSSL_LHASH *lh)
{
    if (lh == NULL)
        return;

    OPENSSL_LH_flush(lh);
    OPENSSL_free(lh->ctrl.b);
    OPENSSL_free(lh);
}

void OPENSSL_LH_rc_free(OPENSSL_LHASH *lh)
{
    int num_nodes;

    if (lh == NULL)
        return;
    OPENSSL_LH_rc_flush(lh);
    num_nodes = OPENSSL_LH_rc_num_items(lh);
    if (num_nodes != 0)
        abort();
    CRYPTO_THREAD_rcu_lock_free(lh->lock);
    OPENSSL_free(lh->ctrlptr->b);
    OPENSSL_free(lh->ctrlptr);
    OPENSSL_free(lh);
}

void OPENSSL_LH_read_lock(const OPENSSL_LHASH *lh)
{
    CRYPTO_THREAD_rcu_read_lock(lh->lock);
}

void OPENSSL_LH_read_unlock(const OPENSSL_LHASH *lh)
{
    CRYPTO_THREAD_rcu_read_unlock(lh->lock);
}

void OPENSSL_LH_write_lock(const OPENSSL_LHASH *lh)
{
    CRYPTO_THREAD_rcu_write_lock(lh->lock);
}

void OPENSSL_LH_write_unlock(const OPENSSL_LHASH *lh)
{
    CRYPTO_THREAD_rcu_write_unlock(lh->lock);
    CRYPTO_THREAD_synchronize_rcu(lh->lock);
}

void OPENSSL_LH_flush(OPENSSL_LHASH *lh)
{
    unsigned int i;
    OPENSSL_LH_NODE *n, *nn;

    if (lh == NULL)
        return;

    for (i = 0; i < lh->ctrl.num_nodes; i++) {
        n = lh->ctrl.b[i];
        while (n != NULL) {
            nn = n->next;
            OPENSSL_free(n);
            n = nn;
        }
        lh->ctrl.b[i] = NULL;
    }

    lh->ctrl.num_items = 0;
}

static void ctrl_flush_cb(void *data)
{
    struct lhash_ctrl_st *ctrl = data;
    unsigned int i;
    OPENSSL_LH_NODE *n, *nn;
    LHASH_REF *dref;

    for (i = 0; i < ctrl->num_alloc_nodes; i++) {
        n = ctrl->b[i];
        while (n != NULL) {
            nn = n->nexts[ctrl->whichnextidx];
            OPENSSL_free(n);
            n = nn;
        }
    }
    OPENSSL_free(ctrl->b);
    OPENSSL_free(ctrl);
}

void OPENSSL_LH_rc_flush(OPENSSL_LHASH *lh)
{
    struct lhash_ctrl_st *ctrl, *newctrl = NULL;
    OPENSSL_LH_NODE *n, *nn;
    unsigned int i;
    int oldref;
    LHASH_REF *dref;

    OPENSSL_LH_write_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    /*
     * sanity check
     * scan the list to see if there are any outstanding references
     */
    for (i = 0; i < ctrl->num_alloc_nodes; i++) {
        n = ctrl->b[i];
        while (n != NULL) {
            nn = n->nexts[ctrl->whichnextidx];
            dref = n->data;
            OPENSSL_LH_rc_obj_put(n->data);
            n = nn;
        }
    }

    /*
     * allocate a new control structure
     */
    newctrl = OPENSSL_memdup(ctrl, sizeof(struct lhash_ctrl_st));
    if (newctrl == NULL)
        abort();
    newctrl->b =
        OPENSSL_zalloc(sizeof(OPENSSL_LH_NODE) * ctrl->num_alloc_nodes);
    if (newctrl->b == NULL)
        abort();
    newctrl->num_alloc_nodes = ctrl->num_alloc_nodes;
    newctrl->whichnextidx = !ctrl->whichnextidx;
    newctrl->num_items = 0;

    /*
     * swap in the new ctrl structure
     */
    CRYPTO_THREAD_rcu_assign_pointer(&lh->ctrlptr, &newctrl);
    /*
     * queue the old structure for removal
     */
    CRYPTO_THREAD_rcu_call(lh->lock, ctrl_flush_cb, ctrl);

    OPENSSL_LH_write_unlock(lh);
}

void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data)
{
    unsigned long hash;
    OPENSSL_LH_NODE *nn, **rn;
    void *ret;

    lh->ctrl.error = 0;
    if ((lh->ctrl.up_load <= (lh->ctrl.num_items * LH_LOAD_MULT / lh->ctrl.num_nodes)) && !expand(&lh->ctrl, NULL))
        return NULL;        /* 'lh->error++' already done in 'expand' */

    rn = getrn(&lh->ctrl, lh->comp, lh->hash, data, &hash);

    if (*rn == NULL) {
        if ((nn = OPENSSL_malloc(sizeof(*nn))) == NULL) {
            lh->ctrl.error++;
            return NULL;
        }
        nn->data = data;
        nn->next = NULL;
        nn->hash = hash;
        *rn = nn;
        ret = NULL;
        lh->ctrl.num_items++;
    } else {                    /* replace same key */
        ret = (*rn)->data;
        (*rn)->data = data;
    }
    return ret;
}

static void ctrl_retire_cb(void *data)
{
    struct lhash_ctrl_st *ctrl = data;

    OPENSSL_free(ctrl->b);
    OPENSSL_free(ctrl);
}

void *OPENSSL_LH_rc_insert(OPENSSL_LHASH *lh, void *data)
{
    unsigned long hash;
    OPENSSL_LH_NODE *nn, **rn;
    void *ret;
    int oldref;
    LHASH_REF *dref;
    struct lhash_ctrl_st *ctrl = NULL, *newctrl = NULL, *oldctrl = NULL;

    OPENSSL_LH_write_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);

    ctrl->error = 0;

    if ((ctrl->up_load <= (ctrl->num_items * LH_LOAD_MULT / ctrl->num_alloc_nodes))) {

        expand_rcu(ctrl, &newctrl);

        if (newctrl != NULL) {
            /*
             * now that we have a new control structure thats
             * been expanded to our needs, queue the old one for
             * removal
             */
            CRYPTO_THREAD_rcu_call(lh->lock, ctrl_retire_cb, ctrl);

            ctrl = newctrl;
        }
    }

    rn = getrn_rcu(ctrl, lh->comp, lh->hash, data, &hash);

    if (*rn == NULL) {
        if ((nn = OPENSSL_zalloc(sizeof(*nn))) == NULL) {
            oldctrl->error++;
            OPENSSL_free(newctrl->b);
            OPENSSL_free(newctrl);
            goto out;
        }
        /* reference counted objects always have an LHASH_REF first */
        dref = (LHASH_REF *)data;
        dref->refptr = OPENSSL_zalloc(sizeof(CRYPTO_REF_COUNT));
        CRYPTO_NEW_REF(dref->refptr, 1); /* initial internal reference */
        dref->freefn = ctrl->free;
        nn->data = data;
        nn->hash = hash;
        *rn = nn; /* might need rcu_assign_pointer here */
        ret = NULL;
        ctrl->num_items++;
    } else {                    /* replace same key */
        ret = (*rn)->data;
        dref = (LHASH_REF *)data;
        if (dref->refptr == NULL) {
            dref->refptr = OPENSSL_zalloc(sizeof(CRYPTO_REF_COUNT));
            CRYPTO_NEW_REF(dref->refptr, 1);
            dref->freefn = ctrl->free;
        } else {
            abort();
        }
        /*
         * The old data is now effectively orphaned
         * just return it, expecting that the caller will
         * detect that we have returned prior data and put it
         * appropriately
         */
        (*rn)->data = data;
    }

    if (newctrl != NULL) {

        /*
         * we updated our control structure, assign it
         * to the hash table
         */
        CRYPTO_THREAD_rcu_assign_pointer(&lh->ctrlptr, &newctrl);
    }
out:
    OPENSSL_LH_write_unlock(lh);
    return ret;
}

void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data)
{
    unsigned long hash;
    OPENSSL_LH_NODE *nn, **rn;
    void *ret;

    lh->ctrl.error = 0;
    rn = getrn(&lh->ctrl, lh->comp, lh->hash, data, &hash);

    if (*rn == NULL) {
        return NULL;
    } else {
        nn = *rn;
        *rn = nn->next;
        ret = nn->data;
        OPENSSL_free(nn);
    }

    lh->ctrl.num_items--;
    if ((lh->ctrl.num_nodes > MIN_NODES) &&
        (lh->ctrl.down_load >= (lh->ctrl.num_items * LH_LOAD_MULT / lh->ctrl.num_nodes)))
        contract(&lh->ctrl);

    return ret;
}

static void ctrl_retire_node(void *data)
{
    OPENSSL_LH_NODE *nn = data;
    OPENSSL_free(nn);
}

void *OPENSSL_LH_rc_delete(OPENSSL_LHASH *lh, const void *data)
{
    unsigned long hash;
    OPENSSL_LH_NODE *nn, **rn;
    void *ret = NULL;
    struct lhash_ctrl_st *ctrl = NULL, *newctrl = NULL;

    OPENSSL_LH_write_lock(lh);

    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    ctrl->error = 0;

    if ((ctrl->num_alloc_nodes > MIN_NODES) &&
        (ctrl->down_load >=
         (ctrl->num_items * LH_LOAD_MULT / ctrl->num_alloc_nodes))) {

        /* contract the new ctrl structure */
        contract_rcu(ctrl, &newctrl);

        if (newctrl != NULL) {
            /*
             * now that we have a new control structure thats
             * been expanded to our needs, queue the old one for
             * removal
             */
            CRYPTO_THREAD_rcu_call(lh->lock, ctrl_retire_cb, ctrl);

            /*
             * and point ctrl to the new ctrl
             */
            ctrl = newctrl;
        }
    }

    rn = getrn_rcu(ctrl, lh->comp, lh->hash, data, &hash);

    if (*rn == NULL) {
        goto out;
    } else {
        /* this is a bit wonky, as ctrl might point to the current struct */
        ctrl->num_items--;
        nn = *rn;
        *rn = nn->nexts[ctrl->whichnextidx];
        ret = nn->data;
        CRYPTO_THREAD_rcu_call(lh->lock, ctrl_retire_node, nn);
        /*
         * Note, don't drop the refcount here
         * we assume the caller, having the returned
         * data, will call obj_put
         */
    }

    /*
     * now that we've done the delete, if we have a new
     * ctrl structure, swap it in
     */
    if (newctrl != NULL)
        CRYPTO_THREAD_rcu_assign_pointer(&lh->ctrlptr, &newctrl);

out:
    OPENSSL_LH_write_unlock(lh);
    return ret;
}
void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data)
{
    unsigned long hash;
    OPENSSL_LH_NODE **rn;

    if (lh->ctrl.error != 0)
        lh->ctrl.error = 0;

    rn = getrn(&lh->ctrl, lh->comp, lh->hash, data, &hash);

    return *rn == NULL ? NULL : (*rn)->data;
}

void *OPENSSL_LH_rc_retrieve(OPENSSL_LHASH *lh, const void *data)
{
    unsigned long hash;
    OPENSSL_LH_NODE **rn;
    struct lhash_ctrl_st *ctrl;
    int refcount;
    LHASH_REF *dref;

    OPENSSL_LH_read_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    ctrl->error = 0;

    rn = getrn_rcu(ctrl, lh->comp, lh->hash, data, &hash);
    if ((*rn) == NULL) {
        dref = NULL;
    } else {
        dref = (*rn)->data;
        if (dref->refptr == NULL) {
            abort();
        } else {
            CRYPTO_UP_REF(dref->refptr, &refcount);
            if (refcount == 0)
                abort();
        }
    }

    OPENSSL_LH_read_unlock(lh);
    return (void *)dref;
}

static void doall_util_fn(struct lhash_ctrl_st *ctrl, int use_arg,
                          OPENSSL_LH_DOALL_FUNC func,
                          OPENSSL_LH_DOALL_FUNCARG func_arg, void *arg)
{
    int i;
    OPENSSL_LH_NODE *a, *n;

    /*
     * reverse the order so we search from 'top to bottom' We were having
     * memory leaks otherwise
     */
    for (i = ctrl->num_nodes - 1; i >= 0; i--) {
        a = ctrl->b[i];
        while (a != NULL) {
            n = a->next;
            if (use_arg)
                func_arg(a->data, arg);
            else
                func(a->data);
            a = n;
        }
    }
}

static void doall_util_fn_rc(struct lhash_ctrl_st *ctrl, int use_arg,
                             OPENSSL_LH_DOALL_FUNC func,
                             OPENSSL_LH_DOALL_FUNCARG func_arg, void *arg)
{
    int i;
    OPENSSL_LH_NODE *a, *n;

    /*
     * reverse the order so we search from 'top to bottom' We were having
     * memory leaks otherwise
     */
    for (i = ctrl->num_alloc_nodes - 1; i >= 0; i--) {
        a = ctrl->b[i];
        while (a != NULL) {
            n = a->nexts[ctrl->whichnextidx];
            if (use_arg)
                func_arg(a->data, arg);
            else
                func(a->data);
            a = n;
        }
    }
}

void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func)
{
    if (lh == NULL)
        return;
    doall_util_fn(&lh->ctrl, 0, func, (OPENSSL_LH_DOALL_FUNCARG)0, NULL);
}

void OPENSSL_LH_rc_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func,
                        int write_lock)
{
    struct lhash_ctrl_st *ctrl;

    if (lh == NULL)
        return;
    (write_lock == 1) ? OPENSSL_LH_write_lock(lh) : OPENSSL_LH_read_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    doall_util_fn_rc(ctrl, 0, func, (OPENSSL_LH_DOALL_FUNCARG)0, NULL);
    (write_lock == 1) ? OPENSSL_LH_write_unlock(lh) : OPENSSL_LH_read_unlock(lh);
}

void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG func,
                         void *arg)
{
    doall_util_fn(&lh->ctrl, 1, (OPENSSL_LH_DOALL_FUNC)0, func, arg);
}

void OPENSSL_LH_rc_doall_arg(OPENSSL_LHASH *lh,
                             OPENSSL_LH_DOALL_FUNCARG func, void *arg,
                             int write_lock)
{
    struct lhash_ctrl_st *ctrl;

    (write_lock == 1) ? OPENSSL_LH_write_lock(lh) : OPENSSL_LH_read_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    doall_util_fn_rc(ctrl, 1, (OPENSSL_LH_DOALL_FUNC)0, func, arg);
    (write_lock == 1) ? OPENSSL_LH_write_unlock(lh) : OPENSSL_LH_read_unlock(lh);
}

int OPENSSL_LH_rc_obj_put(void *data)
{
    OPENSSL_LH_FREEFUNC freefn;
    LHASH_REF *dref = data;
    int oldcount;

    if (data == NULL)
        return 0;

    CRYPTO_DOWN_REF(dref->refptr, &oldcount);

    if (oldcount < 0)
        abort();

    if (oldcount == 0) {
        /*
         * This was our last refcount, free the object
         */
        CRYPTO_FREE_REF(dref->refptr);
        OPENSSL_free(dref->refptr);
        freefn = (OPENSSL_LH_FREEFUNC)dref->freefn;
        if (freefn != NULL)
            freefn(data);
        /*
         * Don't need to free the hash node here
         * as we're no longer in the hash
         */
    }
    return oldcount;
}

int OPENSSL_LH_rc_obj_get(void *data)
{
    OPENSSL_LH_FREEFUNC freefn;
    LHASH_REF *dref = data;
    int oldcount;

    if (data == NULL)
        return 0;

    CRYPTO_UP_REF(dref->refptr, &oldcount);
    if (oldcount == 0) {
        /*
         * we underflowed somewhere
         */
        abort();
    }
    return oldcount;
}

static void lhash_node_retire_cb(void *data)
{
    OPENSSL_LH_NODE *nn = (OPENSSL_LH_NODE *)data;
    OPENSSL_free(nn);
}

static int expand_rcu(struct lhash_ctrl_st *lhctrl, struct lhash_ctrl_st **new)
{
    int i;
    OPENSSL_LH_NODE *cidx;
    OPENSSL_LH_NODE *nidx;
    unsigned long hash;
    unsigned int newidx;

   *new =
    OPENSSL_memdup(lhctrl, sizeof (struct lhash_ctrl_st));

    if (*new == NULL)
        return 0;

    (*new)->b =
    OPENSSL_zalloc(sizeof(OPENSSL_LH_NODE *) * lhctrl->num_alloc_nodes * 2);

    if ((*new)->b == NULL) {
        OPENSSL_free(*new);
        *new = NULL;
        return 0;
    }

    (*new)->whichnextidx = !lhctrl->whichnextidx;
    (*new)->num_alloc_nodes = lhctrl->num_alloc_nodes * 2;
    /*
     * rehash the table
     */
    for (i = 0; i < lhctrl->num_alloc_nodes; i++) {
        cidx = lhctrl->b[i];
        while (cidx != NULL) {
            hash = cidx->hash;
            newidx = hash % (*new)->num_alloc_nodes;
            nidx = (*new)->b[newidx];
            cidx->nexts[(*new)->whichnextidx] = (*new)->b[newidx];
            (*new)->b[newidx] = cidx;
            cidx = cidx->nexts[lhctrl->whichnextidx];
        }
    }

    return 1;
}

static int expand(struct lhash_ctrl_st *lhctrl, CRYPTO_RCU_LOCK *lock)
{
    OPENSSL_LH_NODE **n, **n1, **n2, *np, *nn;
    unsigned int p, pmax, nni, j;
    unsigned long hash;

    nni = lhctrl->num_alloc_nodes;
    p = lhctrl->p;
    pmax = lhctrl->pmax;
    if (p + 1 >= pmax) {
        j = nni * 2;
        n = OPENSSL_realloc(lhctrl->b, sizeof(OPENSSL_LH_NODE *) * j);
        if (n == NULL) {
            lhctrl->error++;
            return 0;
        }
        lhctrl->b = n;
        memset(n + nni, 0, sizeof(*n) * (j - nni));
        lhctrl->pmax = nni;
        lhctrl->num_alloc_nodes = j;
        lhctrl->p = 0;
    } else {
        lhctrl->p++;
    }

    lhctrl->num_nodes++;
    n1 = &(lhctrl->b[p]);
    n2 = &(lhctrl->b[p + pmax]);
    *n2 = NULL;

    for (np = *n1; np != NULL;) {
        hash = np->hash;
        if ((hash % nni) != p) { /* move it */
            if (lock != NULL) {
                nn = OPENSSL_memdup(np, sizeof (OPENSSL_LH_NODE));
                if (nn == NULL)
                    abort();
                *n1 = (*n1)->next;
                nn->next = *n2;
                *n2 = nn;
                CRYPTO_THREAD_rcu_call(lock, lhash_node_retire_cb, np);
            } else {
                *n1 = (*n1)->next;
                np->next = *n2;
                *n2 = np;
            }
        } else {
            n1 = &((*n1)->next);
        }
        np = *n1;
    }

    return 1;
}

static void contract_rcu(struct lhash_ctrl_st *lhctrl, struct lhash_ctrl_st **new)
{
    unsigned int newcnt;
    unsigned int i, newidx;
    OPENSSL_LH_NODE *cidx, *nidx;
    unsigned long hash;

    newcnt = lhctrl->num_alloc_nodes / 2;

    *new = NULL;
    if (newcnt <= MIN_NODES)
        return;

    *new =
        OPENSSL_memdup(lhctrl, sizeof(struct lhash_ctrl_st));

    if (*new == NULL)
        return;

    (*new)->b =
        OPENSSL_zalloc(sizeof(OPENSSL_LH_NODE *) * newcnt);

    if ((*new)->b == NULL) {
        OPENSSL_free(*new);
        *new = NULL;
        return;
    }

    (*new)->whichnextidx = !lhctrl->whichnextidx;
    (*new)->num_alloc_nodes = newcnt;

    /*
     * rehash the table
     */
    for (i = 0; i < lhctrl->num_alloc_nodes; i++) {
        cidx = lhctrl->b[i];
        while (cidx != NULL) {
            hash = cidx->hash;
            newidx = hash % (*new)->num_alloc_nodes;
            nidx = (*new)->b[newidx];
            cidx->nexts[(*new)->whichnextidx] = (*new)->b[newidx];
            (*new)->b[newidx] = cidx;
            cidx = cidx->nexts[lhctrl->whichnextidx];
        }
    }
    return;
}

static void contract(struct lhash_ctrl_st *lhctrl)
{
    OPENSSL_LH_NODE **n, *n1, *np;

    np = lhctrl->b[lhctrl->p + lhctrl->pmax - 1];
    lhctrl->b[lhctrl->p + lhctrl->pmax - 1] = NULL; /* 24/07-92 - eay - weird but :-( */
    if (lhctrl->p == 0) {
        n = OPENSSL_realloc(lhctrl->b,
                            (unsigned int)(sizeof(OPENSSL_LH_NODE *) * lhctrl->pmax));
        if (n == NULL) {
            /* fputs("realloc error in lhash", stderr); */
            lhctrl->error++;
        } else {
            lhctrl->b = n;
        }

        lhctrl->num_alloc_nodes /= 2;
        lhctrl->pmax /= 2;
        lhctrl->p = lhctrl->pmax - 1;
    } else {
        lhctrl->p--;
    }

    lhctrl->num_nodes--;

    n1 = lhctrl->b[(int)lhctrl->p];
    if (n1 == NULL) {
        lhctrl->b[(int)lhctrl->p] = np;
    } else {
        while (n1->next != NULL)
            n1 = n1->next;
        n1->next = np;
    }
}

static OPENSSL_LH_NODE **getrn(struct lhash_ctrl_st *lhctrl,
                               OPENSSL_LH_COMPFUNC cf,
                               OPENSSL_LH_HASHFUNC hf,
                               const void *data, unsigned long *rhash)
{
    OPENSSL_LH_NODE **ret, *n1;
    unsigned long hash, nn;

    hash = hf(data);
    *rhash = hash;

    nn = hash % lhctrl->pmax;
    if (nn < lhctrl->p)
        nn = hash % lhctrl->num_alloc_nodes;

    ret = &(lhctrl->b[(int)nn]);
    for (n1 = *ret; n1 != NULL; n1 = n1->next) {
        if (n1->hash != hash) {
            ret = &(n1->next);
            continue;
        }
        if (cf(n1->data, data) == 0)
            break;
        ret = &(n1->next);
    }
    return ret;
}

static OPENSSL_LH_NODE **getrn_rcu(struct lhash_ctrl_st *lhctrl,
                               OPENSSL_LH_COMPFUNC cf,
                               OPENSSL_LH_HASHFUNC hf,
                               const void *data, unsigned long *rhash)
{
    OPENSSL_LH_NODE **ret, *n1;
    unsigned long hash, nn;

    hash = hf(data);
    *rhash = hash;

    nn = hash % lhctrl->num_alloc_nodes;

    ret = &(lhctrl->b[(int)nn]);
    for (n1 = *ret; n1 != NULL; n1 = n1->nexts[lhctrl->whichnextidx]) {
        if (n1->hash != hash) {
            ret = &(n1->nexts[lhctrl->whichnextidx]);
            continue;
        }
        if (cf(n1->data, data) == 0)
            break;
        ret = &(n1->nexts[lhctrl->whichnextidx]);
    }
    return ret;
}
/*
 * The following hash seems to work very well on normal text strings no
 * collisions on /usr/dict/words and it distributes on %2^n quite well, not
 * as good as MD5, but still good.
 */
unsigned long OPENSSL_LH_strhash(const char *c)
{
    unsigned long ret = 0;
    long n;
    unsigned long v;
    int r;

    if ((c == NULL) || (*c == '\0'))
        return ret;

    n = 0x100;
    while (*c) {
        v = n | (*c);
        n += 0x100;
        r = (int)((v >> 2) ^ v) & 0x0f;
        /* cast to uint64_t to avoid 32 bit shift of 32 bit value */
        ret = (ret << r) | (unsigned long)((uint64_t)ret >> (32 - r));
        ret &= 0xFFFFFFFFL;
        ret ^= v * v;
        c++;
    }
    return (ret >> 16) ^ ret;
}

/*
 * Case insensitive string hashing.
 *
 * The lower/upper case bit is masked out (forcing all letters to be capitals).
 * The major side effect on non-alpha characters is mapping the symbols and
 * digits into the control character range (which should be harmless).
 * The duplication (with respect to the hash value) of printable characters
 * are that '`', '{', '|', '}' and '~' map to '@', '[', '\', ']' and '^'
 * respectively (which seems tolerable).
 *
 * For EBCDIC, the alpha mapping is to lower case, most symbols go to control
 * characters.  The only duplication is '0' mapping to '^', which is better
 * than for ASCII.
 */
unsigned long ossl_lh_strcasehash(const char *c)
{
    unsigned long ret = 0;
    long n;
    unsigned long v;
    int r;
#if defined(CHARSET_EBCDIC) && !defined(CHARSET_EBCDIC_TEST)
    const long int case_adjust = ~0x40;
#else
    const long int case_adjust = ~0x20;
#endif

    if (c == NULL || *c == '\0')
        return ret;

    for (n = 0x100; *c != '\0'; n += 0x100) {
        v = n | (case_adjust & *c);
        r = (int)((v >> 2) ^ v) & 0x0f;
        /* cast to uint64_t to avoid 32 bit shift of 32 bit value */
        ret = (ret << r) | (unsigned long)((uint64_t)ret >> (32 - r));
        ret &= 0xFFFFFFFFL;
        ret ^= v * v;
        c++;
    }
    return (ret >> 16) ^ ret;
}

unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh)
{
    return lh ? lh->ctrl.num_items : 0;
}

unsigned long OPENSSL_LH_rc_num_items(const OPENSSL_LHASH *lh)
{
    struct lhash_ctrl_st *ctrl;
    unsigned long ret;

    if (lh == NULL)
        return 0;

    OPENSSL_LH_read_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    ret = ctrl->num_items;
    OPENSSL_LH_read_unlock(lh);
    return ret;
}

unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh)
{
    return lh->ctrl.down_load;
}

unsigned long OPENSSL_LH_rc_get_down_load(OPENSSL_LHASH *lh)
{
    struct lhash_ctrl_st *ctrl;
    unsigned long ret;

    OPENSSL_LH_read_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    ret = ctrl->down_load;
    OPENSSL_LH_read_unlock(lh);
    return ret;
}

void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load)
{
    lh->ctrl.down_load = down_load;
}

static void ctrl_update_cb(void *old)
{
    struct lhash_ctrl_st *data = old;

    OPENSSL_free(data);
}

void OPENSSL_LH_rc_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load)
{
    struct lhash_ctrl_st *ctrl, *newctrl;

    OPENSSL_LH_write_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    newctrl = OPENSSL_memdup(ctrl, sizeof(struct lhash_ctrl_st));
    if (newctrl == NULL)
        goto out;
    newctrl->down_load = down_load;
    CRYPTO_THREAD_rcu_call(lh->lock, ctrl_update_cb, ctrl);
    CRYPTO_THREAD_rcu_assign_pointer(&lh->ctrlptr, &newctrl);
out:
    OPENSSL_LH_write_unlock(lh);
}

int OPENSSL_LH_error(OPENSSL_LHASH *lh)
{
    return lh->ctrl.error;
}

int OPENSSL_LH_rc_error(OPENSSL_LHASH *lh)
{
    struct lhash_ctrl_st *ctrl;
    int ret;

    OPENSSL_LH_read_lock(lh);
    ctrl = CRYPTO_THREAD_rcu_derefrence(&lh->ctrlptr);
    ret = ctrl->error;
    OPENSSL_LH_read_unlock(lh);
    return ret;
}

