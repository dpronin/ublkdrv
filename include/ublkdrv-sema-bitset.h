#ifndef UBLKDRV_SEMA_BITSET_H
#define UBLKDRV_SEMA_BITSET_H

#include <asm/bitsperlong.h>

#include <linux/gfp.h>
#include <linux/log2.h>
#include <linux/math.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <vdso/bits.h>

struct sema_bitset {
    unsigned long* map;
    unsigned int len;
    unsigned int bits;
    unsigned int set_bits;
};

static inline int sema_bitset_init(struct sema_bitset* smbset, unsigned int bits)
{
    static_assert(order_base_2(BITS_PER_LONG));

    unsigned int const len = DIV_ROUND_UP(bits, BITS_PER_LONG);
    unsigned int const rem = bits & (BITS_PER_LONG - 1);

    smbset->map = kmalloc_array(len, sizeof(smbset->map[0]), GFP_KERNEL);
    if (!smbset->map)
        return -ENOMEM;

    smbset->len = len;

    memset(smbset->map, 0xff, smbset->len * sizeof(smbset->map[0]));
    if (rem)
        smbset->map[smbset->len - 1] &= BIT(rem) - 1;

    smbset->bits     = bits;
    smbset->set_bits = smbset->bits;

    return 0;
}

static inline void sema_bitset_destroy(struct sema_bitset* smbset)
{
    kfree(smbset->map);
    smbset->map = NULL;
}

static inline unsigned int sema_bitset_weight(struct sema_bitset const* smbset)
{
    return smbset->set_bits;
}

static inline unsigned int sema_bitset_weight_max(struct sema_bitset const* smbset)
{
    return smbset->bits;
}

static inline int sema_bitset_trywait(struct sema_bitset* smbset)
{
    static_assert(order_base_2(BITS_PER_LONG));

    unsigned int i, j;

    if (unlikely(!sema_bitset_weight(smbset)))
        return -EBUSY;

    for (i = 0; i < smbset->len && !smbset->map[i]; ++i)
        ;

    BUG_ON(!(i < smbset->len));

    j = __ffs(smbset->map[i]);
    smbset->map[i] &= ~BIT(j);
    --smbset->set_bits;

    return (i << order_base_2(BITS_PER_LONG)) + j;
}

static inline int sema_bitset_post(struct sema_bitset* smbset, unsigned int pos)
{
    static_assert(order_base_2(BITS_PER_LONG));

    unsigned int i, j;

    if (unlikely(!(pos < smbset->bits)))
        return -EINVAL;

    i = pos >> order_base_2(BITS_PER_LONG);
    j = pos & (BITS_PER_LONG - 1);
    if (unlikely(smbset->map[i] & BIT(j)))
        return -EBUSY;

    smbset->map[i] |= BIT(j);
    ++smbset->set_bits;

    return 0;
}

#endif /* UBLKDRV_SEMA_BITSET_H */
