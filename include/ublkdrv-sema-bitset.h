#ifndef UBLKDRV_SEMA_BITSET_H
#define UBLKDRV_SEMA_BITSET_H

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/types.h>

#define UBLKDRV_CTX_CELLS_PER_BITSET 32

struct sema_bitset {
    DECLARE_BITMAP(map, UBLKDRV_CTX_CELLS_PER_BITSET);
    unsigned int set_bits;
};

static inline int sema_bitset_init(struct sema_bitset* smbset)
{
    bitmap_fill(smbset->map, UBLKDRV_CTX_CELLS_PER_BITSET);
    smbset->set_bits = UBLKDRV_CTX_CELLS_PER_BITSET;
    return 0;
}

static inline void sema_bitset_destroy(struct sema_bitset* smbset)
{
}

static inline unsigned int sema_bitset_weight(struct sema_bitset const* smbset)
{
    return smbset->set_bits;
}

static inline unsigned int sema_bitset_weight_max(struct sema_bitset const* smbset)
{
    return UBLKDRV_CTX_CELLS_PER_BITSET;
}

static inline int sema_bitset_trywait(struct sema_bitset* smbset)
{
    unsigned long bit;

    if (unlikely(!sema_bitset_weight(smbset)))
        return -EBUSY;

    bit = find_first_bit(smbset->map, UBLKDRV_CTX_CELLS_PER_BITSET);
    clear_bit(bit, smbset->map);
    --smbset->set_bits;

    return (int)bit;
}

static inline int sema_bitset_post(struct sema_bitset* smbset, unsigned int pos)
{
    if (unlikely(!(pos < sema_bitset_weight_max(smbset))))
        return -EINVAL;

    if (test_and_set_bit(pos, smbset->map))
        return -EBUSY;

    ++smbset->set_bits;

    return 0;
}

#endif /* UBLKDRV_SEMA_BITSET_H */
