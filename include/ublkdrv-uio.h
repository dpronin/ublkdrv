#ifndef UBLKDRV_UIO_H
#define UBLKDRV_UIO_H

#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/uio_driver.h>

#include "ublkdrv-mapping.h"

struct ublkdrv_dev;

struct ublkdrv_uio {
    struct uio_info uio;
    char const* name;
    int mems_len;
    unsigned long flags;
    void* priv;
};
static_assert(UBLKDRV_UIO_MEM_IDS_QTY <= BITS_PER_LONG);

int ublkdrv_uios_register(struct ublkdrv_dev* ubd);
void ublkdrv_uios_unregister(struct ublkdrv_dev* ubd);

#endif /* UBLKDRV_UIO_H */
