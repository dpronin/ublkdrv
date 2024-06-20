#ifndef UBLKDRV_DYNAMIC_BITMAP_SEMAPHORE_H
#define UBLKDRV_DYNAMIC_BITMAP_SEMAPHORE_H

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>

struct dynamic_bitmap_semaphore {
    unsigned long* map;
    unsigned int bits;
    unsigned int set_bits;
};

static inline int dynamic_bitmap_semaphore_init(struct dynamic_bitmap_semaphore* dbsem, unsigned int bits, int nid)
{
    unsigned int const len = BITS_TO_LONGS(bits);

    dbsem->map = kcalloc_node(len, sizeof(dbsem->map[0]), GFP_KERNEL, nid);
    if (!dbsem->map)
        return -ENOMEM;

    bitmap_fill(dbsem->map, bits);

    dbsem->bits     = bits;
    dbsem->set_bits = bits;

    return 0;
}

static inline void dynamic_bitmap_semaphore_destroy(struct dynamic_bitmap_semaphore* dbsem)
{
    kfree(dbsem->map);
    dbsem->map = NULL;
}

static inline unsigned int dynamic_bitmap_semaphore_weight(struct dynamic_bitmap_semaphore const* dbsem)
{
    return dbsem->set_bits;
}

static inline unsigned int dynamic_bitmap_semaphore_weight_max(struct dynamic_bitmap_semaphore const* dbsem)
{
    return dbsem->bits;
}

static inline int dynamic_bitmap_semaphore_trywait(struct dynamic_bitmap_semaphore* dbsem)
{
    unsigned long bit;

    if (unlikely(!dynamic_bitmap_semaphore_weight(dbsem)))
        return -EBUSY;

    bit = find_first_bit(dbsem->map, dynamic_bitmap_semaphore_weight_max(dbsem));
    clear_bit(bit, dbsem->map);
    --dbsem->set_bits;

    return (int)bit;
}

static inline int dynamic_bitmap_semaphore_post(struct dynamic_bitmap_semaphore* dbsem, unsigned int pos)
{
    if (unlikely(!(pos < dynamic_bitmap_semaphore_weight_max(dbsem))))
        return -EINVAL;

    if (test_and_set_bit(pos, dbsem->map))
        return -EBUSY;

    ++dbsem->set_bits;

    return 0;
}

#endif /* UBLKDRV_DYNAMIC_BITMAP_SEMAPHORE_H */
