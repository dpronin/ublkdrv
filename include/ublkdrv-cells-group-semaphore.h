#ifndef UBLKDRV_CELLS_GROUP_SEMAPHORE_H
#define UBLKDRV_CELLS_GROUP_SEMAPHORE_H

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/types.h>

#define UBLKDRV_CTX_CELLS_PER_GROUP 32

struct cells_group_semaphore {
    DECLARE_BITMAP(map, UBLKDRV_CTX_CELLS_PER_GROUP);
    unsigned int set_bits;
};

static inline int cells_group_semaphore_init(struct cells_group_semaphore* smbset)
{
    bitmap_fill(smbset->map, UBLKDRV_CTX_CELLS_PER_GROUP);
    smbset->set_bits = UBLKDRV_CTX_CELLS_PER_GROUP;
    return 0;
}

static inline void cells_group_semaphore_destroy(struct cells_group_semaphore* smbset)
{
}

static inline unsigned int cells_group_semaphore_weight(struct cells_group_semaphore const* smbset)
{
    return smbset->set_bits;
}

static inline unsigned int cells_group_semaphore_weight_max(struct cells_group_semaphore const* smbset)
{
    return UBLKDRV_CTX_CELLS_PER_GROUP;
}

static inline int cells_group_semaphore_trywait(struct cells_group_semaphore* smbset)
{
    unsigned long bit;

    if (unlikely(!cells_group_semaphore_weight(smbset)))
        return -EBUSY;

    bit = find_first_bit(smbset->map, UBLKDRV_CTX_CELLS_PER_GROUP);
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
