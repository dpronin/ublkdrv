#ifndef UBLKDRV_CELLS_GROUP_SEMAPHORE_H
#define UBLKDRV_CELLS_GROUP_SEMAPHORE_H

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>

struct cells_group_semaphore {
    unsigned long* map;
    unsigned int bits;
    unsigned int set_bits;
};

static inline int cells_group_semaphore_init(struct cells_group_semaphore* smbset, unsigned int bits, int nid)
{
    unsigned int const len = BITS_TO_LONGS(bits);

    smbset->map = kcalloc_node(len, sizeof(smbset->map[0]), GFP_KERNEL, nid);
    if (!smbset->map)
        return -ENOMEM;

    bitmap_fill(smbset->map, bits);

    smbset->bits     = bits;
    smbset->set_bits = bits;

    return 0;
}

static inline void cells_group_semaphore_destroy(struct cells_group_semaphore* smbset)
{
    kfree(smbset->map);
    smbset->map = NULL;
}

static inline unsigned int cells_group_semaphore_weight(struct cells_group_semaphore const* smbset)
{
    return smbset->set_bits;
}

static inline unsigned int cells_group_semaphore_weight_max(struct cells_group_semaphore const* smbset)
{
    return smbset->bits;
}

static inline int cells_group_semaphore_trywait(struct cells_group_semaphore* smbset)
{
    unsigned long bit;

    if (unlikely(!cells_group_semaphore_weight(smbset)))
        return -EBUSY;

    bit = find_first_bit(smbset->map, cells_group_semaphore_weight_max(smbset));
    clear_bit(bit, smbset->map);
    --smbset->set_bits;

    return (int)bit;
}

static inline int cells_group_semaphore_post(struct cells_group_semaphore* smbset, unsigned int pos)
{
    if (unlikely(!(pos < cells_group_semaphore_weight_max(smbset))))
        return -EINVAL;

    if (test_and_set_bit(pos, smbset->map))
        return -EBUSY;

    ++smbset->set_bits;

    return 0;
}

#endif /* UBLKDRV_CELLS_GROUP_SEMAPHORE_H */
