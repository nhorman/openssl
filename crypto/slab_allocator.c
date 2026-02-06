/**
 * Copyright 2026 Neil Horman. All Rights Reserved.
 * @file slab_allocator.c
 * @brief Page-based slab allocator integrated with OpenSSL memory hooks.
 *
 * This file implements a fixed-size slab allocator optimized for small
 * allocations. Allocation sizes are rounded up to the nearest power of
 * two and mapped to a corresponding slab class. Each slab occupies a
 * single memory page obtained via mmap(2) and is subdivided into equal-
 * sized objects tracked by a lock-free bitmap.
 *
 * The allocator is designed for high concurrency. Object allocation
 * within a slab uses atomic bitmap operations, while slab list
 * management is protected by a read-write lock. Slabs are created on
 * demand and released back to the operating system when they become
 * completely free.
 *
 * At initialization time, the allocator installs itself as the global
 * memory provider for OpenSSL using CRYPTO_set_mem_functions(), allowing
 * OpenSSL allocations up to MAX_SLAB bytes to be serviced by the slab
 * allocator. Larger allocations transparently fall back to the system
 * malloc implementation.
 *
 * Key features:
 *   - Power-of-two size classes up to MAX_SLAB
 *   - One slab per system page
 *   - Atomic bitmap-based object tracking
 *   - Automatic slab reclamation when empty
 *   - Optional allocation statistics via SLAB_STATS
 *
 * Thread safety:
 *   - Object allocation/free within a slab is lock-free
 *   - Slab list modifications are protected by a rwlock
 *
 * Limitations:
 *   - Objects larger than MAX_SLAB bypass the slab allocator
 *   - Slabs are page-sized and may waste space for large object sizes
 *
 * @note This allocator assumes page-aligned mmap() allocations and
 *       relies on a magic value stored at the start of each slab to
 *       distinguish slab-managed objects from heap allocations.
 */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <openssl/crypto.h>

/* __has_feature is a clang-ism, while __SANITIZE_ADDRESS__ is a gcc-ism */
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#ifdef __SANITIZE_ADDRESS__
#error Slab allocator cannot be used with asan, please disable slab-allocator
#endif

/**
 * @brief Global and supporting definitions for the slab allocator.
 *
 * @var page_size
 * Cached system page size in bytes. Initialized on first use and shared
 * by all slab allocator components to ensure consistent slab sizing.
 *
 * @struct slab_class
 * Forward declaration of the internal slab metadata structure. The full
 * definition is private to the allocator implementation.
 *
 * @def SLAB_MAGIC
 * Magic value stored at the beginning of each slab allocation. This value
 * is used to distinguish slab-managed memory from non-slab allocations
 * during free operations and for basic corruption detection.
 *
 * @struct slab_stats
 * Optional per-process statistics for slab allocator activity. These
 * counters are only present when SLAB_STATS is defined at compile time.
 *
 * @var slab_stats::allocs
 * Number of successful object allocations from slabs.
 *
 * @var slab_stats::frees
 * Number of successful object frees back to slabs.
 *
 * @var slab_stats::slab_allocs
 * Number of slab pages allocated from the operating system.
 *
 * @var slab_stats::slab_frees
 * Number of slab pages released back to the operating system.
 *
 * @var slab_stats::failed_slab_frees
 * Number of attempted frees that did not correspond to a valid slab
 * allocation.
 *
 * @def INC_SLAB_STAT
 * Atomically increments the specified slab statistic counter using
 * relaxed memory ordering. When SLAB_STATS is not enabled, this macro
 * expands to a no-op.
 */

#ifdef SLAB_STATS
static size_t current_alloced_pages = 0;
static size_t max_alloced_pages = 0;
#endif

static long page_size = 0;

static pthread_key_t thread_slab_key;

struct slab_class;

#define SLAB_MAX_PAGE_POOL_COUNT 1024 

#ifdef SLAB_DEBUG
FILE *slab_fp = NULL;
#define SLAB_DBG_LOG(fmt, ...) fprintf(slab_fp, fmt, __VA_ARGS__); fflush(slab_fp)
#else
#define SLAB_DBG_LOG(fmt, ...)
#endif

#define SLAB_DBG_EVENT_SZ(typ, addr, sz, event, file, line) SLAB_DBG_LOG("type:%s|addr:%p|event:%s|size:%lu|func:%s|line:%d\n", typ, (void *)addr, event, sz, file == NULL ? OPENSSL_FUNC : file, file == NULL ? OPENSSL_LINE: line)
#define SLAB_DBG_EVENT(typ, addr, event, file, line) SLAB_DBG_LOG("type:%s|addr:%p|event:%s|func:%s|line:%d\n", typ, (void *)addr, event, file == NULL ? OPENSSL_FUNC : file, file == NULL ? OPENSSL_LINE : line)
#define SLAB_MAGIC 0xdeadf00ddeadf00dUL

#ifdef SLAB_STATS
struct slab_stats {
    size_t allocs;
    size_t frees;
    size_t slab_allocs;
    size_t slab_frees;
    size_t slab_mmaps;
    size_t slab_munmaps;
    size_t slab_pool_allocs;
    size_t failed_slab_frees;
    size_t pool_size_increases;
};

#define ADD_SLAB_STAT(metric, value) __atomic_add_fetch(metric, value, __ATOMIC_ACQ_REL)
#define SUB_SLAB_STAT(metric, value) __atomic_sub_fetch(metric, value, __ATOMIC_ACQ_REL)
#define INC_SLAB_STAT(metric) ADD_SLAB_STAT((metric), 1) 
#else
#define ADD_SLAB_STAT(metric, value)
#define SUB_SLAB_STAT(metric, value)
#define INC_SLAB_STAT(metric)
#endif

/**
 * @struct slab_data
 * @brief Runtime metadata for a single slab page.
 *
 * This structure represents one slab instance backing allocations of a
 * specific size class. Each slab corresponds to a single page of memory
 * and is subdivided into a fixed number of equal-sized objects.
 *
 * The slab is tracked in a linked list belonging to its size class. Object
 * availability is managed via a bitmap, where each bit represents the
 * allocation state of a single object within the slab.
 */
struct slab_data {
    struct slab_data *page_leader;

#ifdef SLAB_STATS
    /**
     * Pointer to the slab size-class descriptor associated with this slab.
     */
    struct slab_stats *stats;
#endif
    /**
     * number of objects allocated on this slab 
     */
    uint64_t allocated_state;

    /**
     * Number of pages in use in this slabs pool 
     */
    uint64_t page_pool_state;

    /**
     * size of objects in this slab
     */
    size_t obj_size;

    /**
     * Bitmap tracking object allocation state. A set bit indicates an
     * allocated object; a cleared bit indicates a free object.
     */
    uint64_t *bitmap;

    /**
     * Number of 64-bit words used by the allocation bitmap.
     */
    uint32_t bitmap_word_count;
    uint32_t full_page_count;

    /**
     * Pointer to the start of the object storage region within the slab.
     */
    void *obj_start;

    /**
     * Magic value identifying this memory region as a valid slab.
     * Used for validation and corruption detection.
     */
    uint64_t magic;
};

/**
 * @struct slab_template
 * @brief Precomputed layout parameters for a slab size class.
 *
 * This structure contains derived values used to initialize and manage
 * slabs of a given object size. The values are computed once when a size
 * class is created and reused for all slabs belonging to that class.
 */
struct slab_template {
    /**
     * Total number of objects that can be allocated from a slab of this
     * size class.
     */
    uint32_t available_objs;

    /**
     * Number of 64-bit words required to represent the allocation bitmap
     * for this slab.
     */
    uint32_t bitmap_word_count;

    /**
     * Bit mask applied to the final bitmap word to ignore unused bits
     * that do not correspond to valid objects.
     */
    uint64_t last_word_mask;
};

/**
 * @struct slab_class
 * @brief Size-class descriptor for the slab allocator.
 *
 * This structure represents a single allocation size class and owns all
 * slabs that service allocations of a specific object size. It maintains
 * the list of active slabs, synchronization primitives, and precomputed
 * layout information shared by those slabs.
 */
struct slab_class {
    /**
     * Pointer to a slab that currently has free objects available.
     * This is a fast-path hint and may be NULL if no slab is available.
     */
    struct slab_data *available;

    /**
     * pointer to the pool of pages we have available
     */
    void *page_pool;

    /**
     * number of pages in a pool
     */
    uint32_t page_pool_count;

    /*
     * page pool index we are on
     */
    uint32_t page_pool_idx;

    /**
     * Number of times we call mmap for this slab
     */
    uint32_t mmap_count;

    /**
     * Size in bytes of each object allocated from this size class.
     */
    size_t obj_size;

    /**
     * Allocation and slab lifecycle statistics for this size class.
     */
#ifdef SLAB_STATS
    struct slab_stats *stats;
#endif

    /**
     * Precomputed template values used when creating new slabs for this
     * size class.
     */
    struct slab_template template;
};

/**
 * @brief Slab allocator size limits and initializers.
 *
 * These macros define the maximum supported slab size class and provide
 * convenience initializers for slab metadata structures.
 *
 * @def MAX_SLAB_IDX
 * Maximum power-of-two exponent supported by the slab allocator.
 * The largest slab-managed allocation size is 1 << MAX_SLAB_IDX bytes.
 *
 * @def MAX_SLAB
 * Maximum allocation size, in bytes, that will be serviced by the slab
 * allocator. Requests larger than this value fall back to the system
 * allocator.
 *
 * @def EMPTY_SLAB_TEMPLATE
 * Zero-initialized @ref slab_template initializer used as a placeholder
 * before template values are computed.
 *
 * @def SLAB_INFO_INITIALIZER
 * Static initializer for a @ref slab_class structure. Initializes the
 * read-write lock, slab list, object size (derived from @p order), and
 * assigns an empty slab template.
 *
 * @param order
 * Power-of-two exponent used to derive the object size for the slab
 * size class.
 */
#define MAX_SLAB_IDX 10
#define MAX_SLAB 1 << MAX_SLAB_IDX

#ifdef SLAB_STATS
#define SLAB_INFO_INITIALIZER(order, poolcnt) { NULL, NULL, (poolcnt), 0, 0,  1 << (order), &stats[(order)], { 0 } }
#else
#define SLAB_INFO_INITIALIZER(order, poolcnt) { NULL, NULL, (poolcnt), 0, 0,  1 << (order), { 0 } }
#endif

#ifdef SLAB_STATS
static struct slab_stats stats[MAX_SLAB_IDX + 1] = { { 0 } };
#endif

/**
 * @brief Global slab size-class table.
 *
 * This array defines all slab allocator size classes supported by the
 * system. Each entry corresponds to a power-of-two object size, starting
 * at 1 byte (order 0) and extending up to @ref MAX_SLAB bytes.
 *
 * The array index represents the size-class order, and the associated
 * @ref slab_class structure manages all slabs servicing allocations of
 * size 1 << index.
 *
 * Entries are statically initialized using @ref SLAB_INFO_INITIALIZER
 * and completed during allocator initialization.
 */
static struct slab_class slabs[] = {
    SLAB_INFO_INITIALIZER(0, 1),
    SLAB_INFO_INITIALIZER(1, 1),
    SLAB_INFO_INITIALIZER(2, 1),
    SLAB_INFO_INITIALIZER(3, 1),
    SLAB_INFO_INITIALIZER(4, 1),
    SLAB_INFO_INITIALIZER(5, 1),
    SLAB_INFO_INITIALIZER(6, 1),
    SLAB_INFO_INITIALIZER(7, 1),
    SLAB_INFO_INITIALIZER(8, 1),
    SLAB_INFO_INITIALIZER(9, 1),
    SLAB_INFO_INITIALIZER(10, 1),
};

/**
 * @brief get the slab allocator for this thread
 *
 * Fetches the per-thread allocator for this thread,
 * creating it if it doesnt yet exist
 */
static inline struct slab_class *get_thread_slab_table()
{
    struct slab_class *info = pthread_getspecific(thread_slab_key);

    if (info == NULL) {
        /*
         * allocate enough space for our thread allocator
         */
        info = calloc(1, sizeof(slabs));
        if (info == NULL)
            return NULL;
        memcpy(info, slabs, sizeof(slabs));

        pthread_setspecific(thread_slab_key, info);
        SLAB_DBG_EVENT_SZ("allocator", info, sizeof(slabs), "allocate", NULL, 0);
    }
    return info;
}

/**
 * @brief Round a value up to the next power of two.
 *
 * Computes the smallest power-of-two value that is greater than or equal
 * to the input. This is used by the slab allocator to map arbitrary
 * allocation sizes to the appropriate size class.
 *
 * A value of zero is treated as a special case and returns zero, which
 * corresponds to size-class index zero.
 *
 * @param num
 * Requested size in bytes.
 *
 * @return
 * The smallest power-of-two value greater than or equal to @p num, or
 * zero if @p num is zero.
 */
static inline size_t slab_size(size_t num)
{
    if (num == 0)
        return 0; /* return index zero */

    /* round up to the next power of two */
    num--;
    num |= num >> 1;
    num |= num >> 2;
    num |= num >> 4;
    num |= num >> 8;
    num |= num >> 16;
    num |= num >> 32;
    num++;
    return num;
}

/**
 * @brief Compute the slab index for a given size.
 *
 * This function rounds the requested size using slab_size() and
 * returns the index of the slab corresponding to that size. The
 * index is computed as the count of trailing zero bits in the
 * rounded-up size, which effectively yields log2(up_size) for
 * power-of-two slab sizes.
 *
 * @param num  Requested size.
 *
 * @return Slab index corresponding to the rounded-up size.
 */
static unsigned int get_slab_idx(size_t num)
{
    size_t up_size = slab_size(num);

    return __builtin_ctzl(up_size);
}

/**
 * @def SLAB_RING_ORPHANED
 * @brief flag to indicate the slab is no longer used by the allocation
 *        side of the allocator
 */
#define SLAB_RING_ORPHANED (1 << 0)

/**
 * @brief atomically modify the allocation_state variable in a slab
 *
 * This function atomically adds the delta value provided to the atomic
 * state (which may be negative) to the count field, and optionally
 * sets any flags in the flags field.  After doing so the new value
 * of the count and flags filed are returned in the new_count and new_flags
 * pointers
 *
 * @param ring The ring to modify
 * @param delta The value to add to the count field (may be negative)
 * @param flags The flags to set in the flags field
 * @param new_count the modified count after the operation
 * @param new_flags the modified flags after the operation
 */
static inline void slab_data_mod_counter_state(uint64_t *counter,
                                               int delta,
                                               uint32_t flags,
                                               uint32_t *new_count,
                                               uint32_t *new_flags)
{
    uint64_t curr_counter_state;
    uint64_t new_counter_state;

    curr_counter_state = __atomic_load_n(counter, __ATOMIC_RELAXED);
    for (;;) {
        new_counter_state = ((uint64_t)(curr_counter_state & 0x00000000ffffffffUL) + delta) |
                             ((uint64_t)((curr_counter_state >> 32) | flags) << 32);

        if (__atomic_compare_exchange_n(counter, &curr_counter_state,
                                        new_counter_state, 0, __ATOMIC_ACQ_REL,
                                        __ATOMIC_RELAXED))
            break;
    }
    *new_count = (uint32_t)(new_counter_state & 0x00000000ffffffffUL);
    *new_flags = (uint32_t)(new_counter_state >> 32);
}

/**
 * @brief sets flags on a slab_data
 *
 * sets flags on a slab_data 
 *
 * @param ring The ring to operate on
 * @param flags The flags to set
 * @param newcount Returns the value of the obj count of the slab
 * @param newflags Returns the flag state of the ring
 */
static inline void slab_data_set_flags(struct slab_data *ring,
                                       uint32_t flags,
                                       uint32_t *newcount,
                                       uint32_t *newflags)
{
    slab_data_mod_counter_state(&ring->allocated_state, 0, flags, newcount, newflags);
}

/**
 * @brief increment count and set flags on a slab_data
 *
 * increment count and set flags on a slab_data
 *
 * @param ring The ring to operate on
 * @param flags The flags to set
 * @param newcount Returns the value of the obj count of the slab
 * @param newflags Returns the flag state of the ring
 */
static inline void slab_data_inc_obj_count(struct slab_data *ring,
                                           uint32_t *ret_count,
                                           uint32_t *ret_flags)
{
    slab_data_mod_counter_state(&ring->allocated_state, 1, 0, ret_count, ret_flags);
}

/**
 * @brief decrement count and set flags on a slab_data
 *
 * decrement count and set flags on a slab_data
 *
 * @param ring The ring to operate on
 * @param flags The flags to set
 * @param newcount Returns the value of the obj count of the slab
 * @param newflags Returns the flag state of the ring
 */
static inline void slab_data_dec_obj_count(struct slab_data *ring,
                                           uint32_t *ret_count,
                                           uint32_t *ret_flags)
{
    slab_data_mod_counter_state(&ring->allocated_state, -1, 0, ret_count, ret_flags);
}

/**
 * @brief modify the page_pool_state of a slab
 *
 * This function adds (or subtracts a count from the page_pool_state
 */
static inline void slab_pool_mod_obj_count(struct slab_data *ring,
                                           int delta,
                                           uint32_t *ret_count,
                                           uint32_t *ret_flags)
{
    slab_data_mod_counter_state(&ring->page_pool_state, delta,
                                0, ret_count, ret_flags);
}

/**
 * @def PAGE_MASK
 * @brief Mask for aligning addresses down to a page boundary.
 *
 * This mask clears the lower bits of an address that represent the
 * offset within a page, assuming page_size is a power of two.
 */
#define PAGE_MASK (~(page_size - 1))

/**
 * @def PAGE_START
 * @brief Compute the starting address of the page containing an address.
 *
 * This macro applies PAGE_MASK to the given address, yielding the
 * base (lowest) address of the memory page that contains it.
 *
 * @param x  Address within the desired page.
 *
 * @return Pointer to the start of the containing page.
 */
#define PAGE_START(x) (void *)((uintptr_t)(x) & PAGE_MASK)

/**
 * @brief Obtain the slab ring associated with an address.
 *
 * This function computes the base address of the memory page
 * containing the given address and treats it as a slab_data
 * structure. It is assumed that each slab ring is page-aligned
 * and located at the start of its corresponding page.
 *
 * @param addr  Address within a slab ring page.
 *
 * @return Pointer to the slab_data for the page containing @p addr.
 */
static inline struct slab_data *get_slab_data(void *addr)
{
    return (struct slab_data *)PAGE_START(addr);
}

/**
 * @brief checks if the slab magic value is correct
 */
static inline __attribute__((no_sanitize("address"))) int is_slab_magic_correct(void *addr)
{
    struct slab_data *ring = get_slab_data(addr);

    return (ring->magic == SLAB_MAGIC) ? 1 : 0;
}

/**
 * @brief Determine whether an address belongs to an object slab.
 *
 * This function retrieves the slab_data associated with the page
 * containing the given address and checks its magic value to
 * determine whether the page represents a valid object slab.
 *
 * @param addr  Address to test.
 *
 * @return 1 if the address is within an object slab, 0 otherwise.
 */
static inline int is_obj_slab(void *addr)
{
    /*
     * also check if the address is on a page boundary
     * This indicates that it is not a slab, as slab objects
     * never start on a page boundary, due to the page_ring meta
     * data being at the start of every slab
     */
    if ((uintptr_t)addr == (uintptr_t)PAGE_START(addr))
        return 0;

    return is_slab_magic_correct(addr);
}

/**
 * @brief Select and reserve a free object from a slab.
 *
 * This function scans the slab's allocation bitmap to locate a free
 * object slot. For each bitmap word, it searches for a clear bit,
 * then atomically sets that bit to reserve the corresponding object.
 * If another thread races and claims the same bit, the operation is
 * retried.
 *
 * The object address is computed from the bitmap index, bit position,
 * and object size recorded in the slab metadata.
 *
 * @param slab  Pointer to the slab_data from which to allocate.
 *
 * @return Pointer to the allocated object, or NULL if no free objects
 *         are available in the slab.
 */
static inline void *select_obj(struct slab_data *slab)
{
    uint32_t i;
    uint64_t value;
    uint32_t available_bit;
    uint64_t new_mask;
    uint32_t obj_offset;
    uint32_t ring_count, flags;

    for (i = 0; i < slab->bitmap_word_count; i++) {
        value = __atomic_load_n(&slab->bitmap[i], __ATOMIC_RELAXED);
        if (value < UINT64_MAX) {
            /*
             * Theres an available object somewhere in here
             * so invert the bitmap of this word to turn all our
             * 1's to 0's and vice versa, then count the leading
             * zeros.  The result is the first bit in the bitmap that
             * is 0, which is our next free object
             */
            value = ~value;
            available_bit = __builtin_ctzl(value);

            /*
             * Build a mask to turn the bit we found on
             */
            new_mask = (uint64_t)1 << available_bit;
            __atomic_fetch_or(&slab->bitmap[i], new_mask, __ATOMIC_RELAXED);
            /*
             * We got an object!
             * compute the object location based on the bit in the bitmap that we just set
             */
            slab_data_inc_obj_count(slab, &ring_count, &flags);
            obj_offset = (slab->obj_size * (i * 64)) + (available_bit * slab->obj_size);
            return (void *)((unsigned char *)slab->obj_start + obj_offset);
        }
    }
    return NULL;
}

#ifdef SLAB_STATS
/**
 * @brief update the maximum number of allocated pages we have outstanding
 * 
 * Used when stats are enabled, this function computes the current number
 * of allocated pages, and stores that value to max_allocated_pages, if
 * and only if the current computed value is larger than the value of
 * max_alloced_pages
 */
static inline void update_max_alloced_pages()
{
    size_t my_max_alloced_pages;
    size_t my_current_alloced_pages;
    size_t my_new_max_alloced_pages;

    my_max_alloced_pages = __atomic_load_n(&max_alloced_pages, __ATOMIC_RELAXED);
    my_current_alloced_pages = __atomic_load_n(&current_alloced_pages, __ATOMIC_RELAXED);

    for(;;) {
        if (my_current_alloced_pages < my_max_alloced_pages)
            break;
        my_new_max_alloced_pages = my_current_alloced_pages;

        if (__atomic_compare_exchange_n(&max_alloced_pages, &my_max_alloced_pages,
                                        my_new_max_alloced_pages, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            break;
        }
    }
}
#endif

/**
 * @brief Allocate and initialize a new slab ring page.
 *
 * This function uses mmap() to allocate a single page and initializes
 * a slab_data structure at the start of that page. It configures the
 * ring's metadata from the provided slab_class/template, sets up and
 * clears the allocation bitmap, applies the template's last-word mask
 * (to mark unusable bits as allocated), computes the object region
 * start immediately after the bitmap, and sets the slab magic value.
 *
 * On success, the slab allocation statistics counter is incremented.
 *
 * @param slab  Slab descriptor providing sizing and template data.
 *
 * @return Pointer to the initialized slab_data, or NULL on failure.
 */
static inline struct slab_data *create_new_slab(struct slab_class *slab)
{
    void *new;
    size_t page_size_long = (size_t)page_size;
    struct slab_data *new_ring;
    struct slab_data *slab_page;
    uint32_t page_idx;

    /*
     * Note, we don't always just allocate a single page here, to save time
     * and avoid using mmap too much, we try to batch this operation, by allocating
     * page_pool_count pages to a pool for this allocator, and then iterate over
     * them on the allocation side.  This keeps us from having to use the slow mmap
     * call too often
     */
    INC_SLAB_STAT(&slab->stats->slab_allocs);
    if (slab->page_pool != NULL && slab->page_pool_idx < slab->page_pool_count) {
        new = slab->page_pool;
        slab->page_pool_idx++;
        slab->page_pool = (void *)(((unsigned char *)new) + page_size_long);
        INC_SLAB_STAT(&slab->stats->slab_pool_allocs);
    } else {
        if (slab->mmap_count > slab->template.available_objs * slab->page_pool_count) {
            /*
             * We're using this slab alot
             * specifically we're using a heuristic here by checking
             * to see if we've mapped as many page as we have in any single
             * slab.  If we've done that, lets allocate more pages per
             * mmap to try reduce the number of times we have to call mmap
             * NOTE: We don't ever try to map more than SLAB_MAX_PAGE_POOL_COUNT
             * pages at once.
             */
            if (slab->page_pool_count < SLAB_MAX_PAGE_POOL_COUNT) {
                slab->page_pool_count *= 2;
                INC_SLAB_STAT(&slab->stats->pool_size_increases);
            }
            slab->mmap_count = 0;
        }
        slab->mmap_count++;
        /*
         * New slabs must be page aligned so that our page offset math works.
         * So use mmap to grab a pool of pages
         */
        new = mmap(NULL, page_size_long * slab->page_pool_count, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (new == NULL)
            return NULL;
        INC_SLAB_STAT(&slab->stats->slab_mmaps);
        SLAB_DBG_EVENT_SZ("mmap",new, page_size_long * slab->page_pool_count, "allocate", NULL, 0); 
        for (page_idx = 0; page_idx < slab->page_pool_count; page_idx++) {
            slab_page = (struct slab_data *)(((uint8_t *)new) + (page_size_long * page_idx));
            slab_page->page_leader = (struct slab_data *)new;
            if (slab_page == (struct slab_data *)new) {
                slab_page->page_pool_state = slab->page_pool_count;
                slab_page->full_page_count = slab->page_pool_count;
            }
        }

        ADD_SLAB_STAT(&current_alloced_pages, slab->page_pool_count);
#ifdef SLAB_STATS
        update_max_alloced_pages();
#endif
        slab->page_pool_idx = 1;
        slab->page_pool = (void *)(((unsigned char *)new) + page_size_long);
   }

    /*
     * setup this slab
     */
    new_ring = get_slab_data(new);

    SLAB_DBG_EVENT_SZ("slab",new_ring, page_size_long, "allocate", NULL, 0);
#ifdef SLAB_STATS
    new_ring->stats = slab->stats;
#endif

    new_ring->allocated_state = 0;
    new_ring->obj_size = slab->obj_size;
    new_ring->bitmap_word_count = slab->template.bitmap_word_count;
    new_ring->bitmap = (uint64_t *)(((unsigned char *)new_ring) + sizeof(struct slab_data));
    memset(new_ring->bitmap, 0, sizeof(uint64_t) * new_ring->bitmap_word_count);
    new_ring->bitmap[new_ring->bitmap_word_count - 1] = slab->template.last_word_mask;
    new_ring->obj_start = (void *)(new_ring->bitmap + new_ring->bitmap_word_count);
    new_ring->magic = SLAB_MAGIC;
    return new_ring;
}

/**
 * @brief Create a new slab and allocate its first object.
 *
 * This function allocates and initializes a new slab page via
 * create_new_slab(), then reserves the first object slot and returns
 * its address. Since the slab has not yet been published, it sets the
 * first bitmap bit directly (non-atomically) as an optimization.
 *
 * After selecting the object, the new slab is inserted into the slab's
 * ring list under a write lock, and the slab's "available" pointer is
 * updated to publish the new slab for future allocations.
 *
 * @param slab  Slab descriptor to which the new slab will be added.
 *
 * @return Pointer to the first allocated object in the new slab, or
 *         NULL on failure.
 */
static inline void *create_obj_in_new_slab(struct slab_class *slab)
{
    struct slab_data *new = create_new_slab(slab);
    struct slab_data *old;
    void *obj;
    uint32_t ring_count, flags;
    size_t page_size_long = (size_t)page_size;
    uint32_t page_count;

    if (new == NULL)
        return NULL;
    /*
     * we can cheat here a bit, since no one else sees this slab yet
     */
    new->bitmap[0] |= 0x1;
    obj = new->obj_start;
    slab_data_inc_obj_count(new, &ring_count, &flags);
    old = slab->available;
    slab->available = new;
    if (old != NULL) {
        slab_data_set_flags(old, SLAB_RING_ORPHANED, &ring_count, &flags);
        if (ring_count == 0) {
            INC_SLAB_STAT(&old->stats->slab_frees);
            SLAB_DBG_EVENT("slab",old,"free", NULL, 0);
            slab_pool_mod_obj_count(old->page_leader, -1, &page_count, &flags);
            if (page_count == 0) {
                /*
                 * We're the last user of this pool, and the allocation side
                 * isn't using it anymore, we can return it to the os
                 */
                INC_SLAB_STAT(&old->stats->slab_munmaps);
                SLAB_DBG_EVENT_SZ("mmap",old->page_leader,
                                  page_size_long * old->page_leader->full_page_count,
                                  "free", NULL, 0); 
                SUB_SLAB_STAT(&current_alloced_pages, old->page_leader->full_page_count);
                if (munmap(old->page_leader, page_size_long * old->page_leader->full_page_count)) {
                    INC_SLAB_STAT(&old->stats->failed_slab_frees);
                }
            }
        }
    }
    return obj;
}

/**
 * @brief Allocate an object from a slab_class.
 *
 * This function attempts to allocate an object from the slab currently
 * advertised as having availability (slab->available). It loads that
 * slab pointer atomically and calls select_obj() to reserve a free
 * object from it.
 *
 * If no slab is available, or the selected slab has no free objects,
 * the function falls back to creating a new slab and returning the
 * first object from it.
 *
 * @param slab  Slab descriptor from which to allocate an object.
 *
 * @return Pointer to an allocated object, or NULL on failure.
 */
static inline void *get_slab_obj(struct slab_class *slab)
{
    struct slab_data *idx;
    void *obj = NULL;

    idx = slab->available;
    if (idx != NULL)
        obj = select_obj(idx);
    if (obj != NULL)
        return obj;

    /* We need to create a new slab */
    return create_obj_in_new_slab(slab);
}

/**
 * @brief Return an object to its owning slab and free empty slabs.
 *
 * This function computes the bitmap position corresponding to @p addr
 * within the slab's object area and clears that allocation bit,
 * marking the object as free.
 *
 * After freeing the object, if the slab is not the one currently
 * advertised for allocation (ring->info->available), the function
 * checks whether the slab has become completely empty. Emptiness is
 * detected by verifying that all bitmap words are zero except the
 * final word, which must equal the template's last_word_mask (i.e.,
 * only the permanently-unusable bits remain set).
 *
 * If the slab is empty, it is removed from the slab list under a write
 * lock and unmapped via munmap(). Statistics counters are updated for
 * successful and failed frees.
 *
 * @param addr  Object address being returned to the slab.
 * @param ring  Slab ring page that owns @p addr.
 */
static void return_to_slab(void *addr, struct slab_data *ring)
{
    uintptr_t base;
    uintptr_t offset;
    size_t bit_idx;
    size_t word_idx;
    uint64_t value;
    size_t page_size_long = (size_t)page_size;
    uint32_t obj_count, flags;
    uint32_t page_count;

    /*
     * compute the offset of the object from the start of the slab
     * and use it to compute the bitmap word and bit we need to clear
     */
    base = (uintptr_t)ring->obj_start;
    offset = (uintptr_t)addr - base;
    bit_idx = offset / ring->obj_size;
    word_idx = bit_idx / 64;

    bit_idx = bit_idx % 64;

    value = (uint64_t)1 << bit_idx;
    value = ~value;

    /*
     * and our local slab count of objects
     */
    slab_data_dec_obj_count(ring, &obj_count, &flags);

    /*
     * check to see if we are removing the last object in this slab 
     */
    if (obj_count == 0 && (flags & SLAB_RING_ORPHANED)) {
        INC_SLAB_STAT(&ring->stats->slab_frees);
        SLAB_DBG_EVENT("slab",ring,"free", NULL, 0);
        slab_pool_mod_obj_count(ring->page_leader, -1, &page_count, &flags);
        if (page_count == 0) {
            /*
             * return the slab to the OS with munmap
             */
            INC_SLAB_STAT(&ring->stats->slab_munmaps);
            SLAB_DBG_EVENT_SZ("mmap", ring->page_leader,
                              page_size_long * ring->page_leader->full_page_count,
                              "free", NULL, 0); 
            SUB_SLAB_STAT(&current_alloced_pages, ring->page_leader->full_page_count);
            if (munmap(ring->page_leader, page_size_long * ring->page_leader->full_page_count)) {
                INC_SLAB_STAT(&ring->stats->failed_slab_frees);
            }
            return;
        }
    }

    /*
     * We didn't free the slab. Clear the bit for this object
     */
    __atomic_and_fetch(&ring->bitmap[word_idx], value, __ATOMIC_RELAXED);
}
/**
 * @brief Allocate memory using the slab allocator.
 *
 * This function selects an appropriate slab based on the requested
 * allocation size. If the requested size exceeds the maximum slab
 * size, the allocation is delegated to the system malloc().
 *
 * For slab-eligible sizes, the slab index is computed, allocation
 * statistics are updated, and an object is allocated from the
 * corresponding slab via get_slab_obj().
 *
 * The @p file and @p line parameters are provided for debugging or
 * accounting purposes and are not otherwise used here.
 *
 * @param num   Number of bytes requested.
 * @param file  Source file requesting the allocation.
 * @param line  Source line requesting the allocation.
 *
 * @return Pointer to the allocated memory, or NULL on failure.
 */
#ifdef OPENSSL_BUILDING_OPENSSL
void *slab_malloc(size_t num, const char *file, int line);
void *slab_malloc(size_t num, const char *file, int line)
#else
static void *slab_malloc(size_t num, const char *file, int line)
#endif
{
    unsigned int slab_idx;
    struct slab_class *myslabs = get_thread_slab_table();
    void *ret;

    if (myslabs == NULL || num == 0)
        return NULL;

    /*
     * if we are requested to provide an allocation larger than our biggest
     * slab, just use malloc
     */
    if (num > MAX_SLAB) {
        ret = malloc(num);
        SLAB_DBG_EVENT_SZ("nonslab-obj", ret, num, "allocate", file, line);
        return ret;
    }

    slab_idx = get_slab_idx(num);
    INC_SLAB_STAT(&myslabs[slab_idx].stats->allocs);
    ret = get_slab_obj(&myslabs[slab_idx]);
    SLAB_DBG_EVENT_SZ("obj", ret, num, "allocate", file, line);
    return ret;
}

/**
 * @brief Free memory allocated by the slab allocator.
 *
 * This function determines whether the given address belongs to a slab
 * allocation. If the address is NULL or does not correspond to an
 * object slab, it is passed through to the system free().
 *
 * For slab-allocated objects, the owning slab ring is determined, the
 * slab free statistics counter is updated, and the object is returned
 * to its slab via return_to_slab().
 *
 * The @p file and @p line parameters are provided for debugging or
 * accounting purposes and are not otherwise used here.
 *
 * @param addr  Address to be freed.
 * @param file  Source file requesting the free.
 * @param line  Source line requesting the free.
 */
#ifdef OPENSSL_BUILDING_OPENSSL
void slab_free(void *addr, const char *file, int line);
void slab_free(void *addr, const char *file, int line)
#else
static void slab_free(void *addr, const char *file, int line)
#endif
{
    struct slab_data *ring;

    /*
     * NULL addresses and objects that are not part of a slab
     * just get freed as they normally would
     */
    if (addr == NULL || !is_obj_slab(addr)) {
        SLAB_DBG_EVENT("nonslab-obj", addr, "free", file, line);
        free(addr);
        return;
    }
    ring = get_slab_data(addr);
    INC_SLAB_STAT(&ring->stats->frees);
    SLAB_DBG_EVENT("obj", addr, "free", file, line);
    return_to_slab(addr, ring);
}

/**
 * @brief Reallocate memory previously allocated by the slab allocator.
 *
 * This function resizes an existing allocation, handling both slab
 * and non-slab pointers. If @p addr is NULL, it behaves like
 * slab_malloc().
 *
 * If the pointer does not refer to a slab allocation, the request is
 * delegated to the system realloc(). For slab allocations, the
 * behavior depends on the new size:
 *
 * - If the new size exceeds the maximum slab size, a new buffer is
 *   allocated with malloc(), the existing object contents (up to the
 *   slab object size) are copied, and the original slab object is
 *   freed.
 * - If the new size fits within the existing slab object size, the
 *   original pointer is returned unchanged.
 * - Otherwise, a new slab allocation is made, the contents are copied,
 *   and the old slab object is freed.
 *
 * The @p file and @p line parameters are provided for debugging or
 * accounting purposes and are not otherwise used here.
 *
 * @param addr  Existing allocation, or NULL.
 * @param num   New size in bytes.
 * @param file  Source file requesting the reallocation.
 * @param line  Source line requesting the reallocation.
 *
 * @return Pointer to the resized allocation, or NULL on failure.
 */
#ifdef OPENSSL_BUILDING_OPENSSL
void *slab_realloc(void *addr, size_t num, const char *file, int line);
void *slab_realloc(void *addr, size_t num, const char *file, int line)
#else
static void *slab_realloc(void *addr, size_t num, const char *file, int line)
#endif
{
    void *new;
    struct slab_data *ring;

    /*
     * reallocs for NULL are just malloc, so check with the slab allocator
     */
    if (addr == NULL)
        return slab_malloc(num, NULL, 0);

    /*
     * if the incomming address is not part of a slab already, then its
     * too big for the slab allocator, and se just use realloc
     */
    if (!is_obj_slab(addr)) {
        SLAB_DBG_EVENT("nonslab-obj", addr, "free", file, line);
        new = realloc(addr, num);
        SLAB_DBG_EVENT_SZ("nonslab-obj", new, num, "allocate", file, line);
        return new;
    }

    ring = get_slab_data(addr);

    /*
     * If the request is too big, then we just use malloc
     */
    if (num > MAX_SLAB) {
        new = malloc(num);
        SLAB_DBG_EVENT_SZ("nonslab-obj", new, num, "allocate", file, line);
        /*
         * If we get an object, then copy the size of the old object
         * to the new object, which is guaranteed to be less than what
         * is returned from malloc above
         */
        if (new != NULL)
            memcpy(new, addr, ring->obj_size);
        /*
         * and free the old object back to the slab allocator
         */
        slab_free(addr, NULL, 0);
        return new;
    }

    /*
     * Handy shortcut
     * If the new requested size still fits into the old object
     * we can just reuse it
     */
    if (num <= ring->obj_size)
        return addr;

    /*
     * We need to swap slab objects, so get one from the next size we need
     */

    new = slab_malloc(num, file, line);

    /*
     * And if its not null, copy the old object into the new space
     */
    if (new != NULL)
        memcpy(new, addr, ring->obj_size);

    /*
     * and free the old object
     */
    slab_free(addr, file, line);
    return new;
}

/**
 * @brief Compute per-page slab layout parameters for a slab_class.
 *
 * This function determines how many fixed-size objects (@c slab->obj_size)
 * can fit into a single page once the slab_data header and allocation
 * bitmap are accounted for. It iteratively increases the candidate object
 * count, expanding the bitmap by one 64-bit word whenever the object count
 * crosses a multiple of 64, and stops when the object area would exceed the
 * remaining space in the page.
 *
 * The results are stored in @c slab->template:
 * - @c available_objs: number of objects that fit in the page
 * - @c bitmap_word_count: number of 64-bit bitmap words required
 * - @c last_word_mask: mask for the final bitmap word, with bits that do
 *   not correspond to valid objects set to 1 (treated as permanently
 *   allocated/unavailable).
 *
 * @param slab  Slab descriptor whose template fields will be populated.
 */
static void compute_slab_template(struct slab_class *slab)
{
    uint32_t bitmap_words = 1; /* need at least one bitmap word */
    uint32_t obj_count;
    size_t objs_size;
    size_t available_size = (page_size - sizeof(struct slab_data)) - (bitmap_words * sizeof(uint64_t));
    int word_size_increased;
    int i;

    /*
     * play some guess and check here, as we are growing both the bitmap and the size of the
     * objects we are storing in the slab.
     * iteratively compare an increasing number of objects' storage needs to the available size
     * in the slab, based on the storage needed to track its meta data.  Stop when we get too big
     */
    for (obj_count = 1;; obj_count++) {
        word_size_increased = 0;
        if ((obj_count % 64) == 0) {
            bitmap_words++;
            available_size = (page_size - sizeof(struct slab_data)) - (bitmap_words * sizeof(uint64_t));
            word_size_increased = 1;
        }
        objs_size = obj_count * slab->obj_size;
        if (objs_size > available_size) {
            /* we went too far */
            if (word_size_increased == 1)
                bitmap_words--;
            obj_count--;
            break;
        }
    }
    slab->template.available_objs = obj_count;
    slab->template.bitmap_word_count = bitmap_words;
    /*
     * Compute the last_word_mask, which pre-emptively turns on bits in the last word of
     * the bitmap for objects we don't have space to store.
     */
    slab->template.last_word_mask = (uint64_t)1 << (slab->template.available_objs % 64);
    for (i = slab->template.available_objs % 64; i < 64; i++)
        slab->template.last_word_mask = slab->template.last_word_mask | (uint64_t)1 << i;
    return;
}

static void destroy_slab_table(void *data)
{
    struct slab_class *info = (struct slab_class *)data;
    uint32_t i;
    uint32_t count, flags;
    size_t page_size_long = (size_t)page_size;
    uint32_t page_count;

    if (info == NULL)
        return;
    for (i = 0; i <= MAX_SLAB_IDX; i++) {
        if(info[i].available != NULL) {
            slab_data_set_flags(info[i].available, SLAB_RING_ORPHANED, &count, &flags);
            if (count == 0) {
                INC_SLAB_STAT(&info[i].stats->slab_frees);
                SLAB_DBG_EVENT("slab",info[i].available,"free", NULL, 0);
                /*
                 * We have to be a bit tricky here.
                 * We can't just drop the page count by one, as there may be more pages
                 * in the pool that haven't been touched yet.  But since we know
                 * we're never going to allocate from this pool again, we can subtract
                 * all the pages remaining in the pool to see if we hit zero
                 */
                slab_pool_mod_obj_count(info[i].available->page_leader,
                                        (info[i].page_pool_idx - 1) - info[i].available->page_leader->full_page_count,
                                        &page_count, &flags); 
                if (page_count == 0) {
                    INC_SLAB_STAT(&info[i].stats->slab_munmaps);
                    SLAB_DBG_EVENT_SZ("mmap", info[i].available->page_leader,
                                      page_size_long * info[i].available->page_leader->full_page_count,
                                      "free", NULL, 0);
                    SUB_SLAB_STAT(&current_alloced_pages, info[i].available->page_leader->full_page_count);
                    if (munmap(info[i].available->page_leader,
                               page_size_long * info[i].available->page_leader->full_page_count)) {
                        INC_SLAB_STAT(&info[i].stats->failed_slab_frees);
                    }
                }
            }
        }
    }
    SLAB_DBG_EVENT("allocator", info, "free", NULL, 0);
    pthread_setspecific(thread_slab_key, NULL);
    free(info);
}

/**
 * @brief Initialize the slab allocator at program startup.
 *
 * This constructor function is executed automatically before main().
 * It installs the slab allocator's malloc/realloc/free hooks via
 * CRYPTO_set_mem_functions(), retrieves the system page size, and
 * computes per-slab template parameters for each slab class.
 *
 * Errors are reported to stderr; initialization continues even if
 * individual steps fail.
 */
static __attribute__((constructor)) void setup_slab_allocator()
{
    int i;
#ifdef SLAB_DEBUG
    char *slab_debug_path = getenv("SLAB_ALLOCATOR_DEBUG_LOG");
#endif

#ifndef OPENSSL_BUILDING_OPENSSL
    fprintf(stderr, "Setting up slab allocator\n");
    if (!CRYPTO_set_mem_functions(slab_malloc, slab_realloc, slab_free))
        fprintf(stderr, "Failed to setup slag allocator\n");
#endif
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1)
        fprintf(stderr, "Failed to get page size\n");
    for (i = 0; i <= MAX_SLAB_IDX; i++) {
        compute_slab_template(&slabs[i]);
    }
    pthread_key_create(&thread_slab_key, destroy_slab_table);
#ifdef SLAB_DEBUG
    if (slab_debug_path == NULL)
        slab_fp = stderr;
    else
        slab_fp = fopen(slab_debug_path, "w");

    if (slab_fp == NULL)
        slab_fp = stderr;
#endif
}

/**
 * @brief Emit slab allocator statistics at program shutdown.
 *
 * This destructor function is executed automatically at program exit
 * when SLAB_STATS is enabled. It emits a JSON-formatted summary of
 * slab allocator statistics, including object sizes, per-slab object
 * counts, allocation/free counts, slab allocations, slab frees, and
 * failed slab frees.
 *
 * By default, output is written to stderr. If the environment variable
 * SLAB_ALLOCATOR_LOG is set, statistics are written to the specified
 * file instead, falling back to stderr on failure.
 */
static __attribute__((destructor)) void slab_cleanup()
{

    /*
     * Clear the main thread allocator
     */
    destroy_slab_table(pthread_getspecific(thread_slab_key));
#ifdef SLAB_DEBUG
    fclose(slab_fp);
#endif

#ifdef SLAB_STATS
    FILE *fp = stderr;
    FILE *cmd = NULL;
    char cmdstring[PATH_MAX] = { 0 };
    char *path = getenv("SLAB_ALLOCATOR_LOG");
    int i;

    if (path != NULL) {
        fp = fopen(path, "w");
        if (fp == NULL)
            fp = stderr;
    }
    cmd = fopen("/proc/self/cmdline", "r");
    fread(cmdstring, PATH_MAX, 1, cmd);
    fclose(cmd);
    fprintf(fp, "{ \"cmd\": \"%s\", \"slabs\": [", cmdstring);

    for (i = 0; i <= MAX_SLAB_IDX; i++) {
        fprintf(fp, "{\"obj_size\":%lu, \"objs_per_slab\":%u, \"allocs\":%lu, \"frees\":%lu, \"slab_allocs\":%lu, \"slab_frees\":%lu, \"failed_slab_frees\":%lu, \"pool_size_increases\":%lu, \"slab_maps\":%lu, \"slab_munmaps\":%lu}",
            slabs[i].obj_size, slabs[i].template.available_objs,
            slabs[i].stats->allocs, slabs[i].stats->frees,
            slabs[i].stats->slab_allocs, slabs[i].stats->slab_frees,
            slabs[i].stats->failed_slab_frees,
            slabs[i].stats->pool_size_increases,
            slabs[i].stats->slab_mmaps,
            slabs[i].stats->slab_munmaps);
        if (i != MAX_SLAB_IDX)
            fprintf(fp, ",");
    }
    fprintf(fp, "],");
    fprintf(fp, "\"max_alloced_pages\":%lu}", max_alloced_pages);
    if (fp != stderr)
        fclose(fp);
#endif

    pthread_key_delete(thread_slab_key);
}
