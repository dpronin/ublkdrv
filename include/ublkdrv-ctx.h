#ifndef UBLKDRV_CTX_H
#define UBLKDRV_CTX_H

#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/cmdb.h"
#include "uapi/ublkdrv/cmdb_ack.h"

#include "ublkdrv-sema-bitset.h"

#define UBLKDRV_CELL_SZ_MIN PAGE_SIZE
#define UBLKDRV_CELL_SZ_MAX (1U << 20)
static_assert(0 != UBLKDRV_CELL_SZ_MIN && 0 == (UBLKDRV_CELL_SZ_MIN & (UBLKDRV_CELL_SZ_MIN - 1)), "UBLKDRV_CELL_SZ_MIN must be a power of 2");
static_assert(0 != UBLKDRV_CELL_SZ_MAX && 0 == (UBLKDRV_CELL_SZ_MAX & (UBLKDRV_CELL_SZ_MAX - 1)), "UBLKDRV_CELL_SZ_MAX must be a power of 2");
static_assert(PAGE_SIZE <= UBLKDRV_CELL_SZ_MIN && UBLKDRV_CELL_SZ_MIN <= UBLKDRV_CELL_SZ_MAX, "UBLKDRV_CELL_SZ_MIN must be in range [PAGE_SIZE, UBLKDRV_CELL_SZ_MAX]");

#define UBLKDRV_CTX_CELLS_PER_BITSET 32
#define UBLKDRV_CTX_SEMA_BITSETS_NR (order_base_2(UBLKDRV_CELL_SZ_MAX / UBLKDRV_CELL_SZ_MIN) + 1)

struct ublkdrv_sema_bitset {
    spinlock_t lock;
    struct sema_bitset* semas[UBLKDRV_CTX_SEMA_BITSETS_NR];
};

struct ublkdrv_ctx_params {
    u32 max_req_sz;
};

struct ublkdrv_ctx {
    struct ublkdrv_ctx_params const* params;

    struct ublkdrv_cmdb* cmdb;
    size_t cmdb_sz;

    struct ublkdrv_cellc* cellc;
    size_t cellc_sz;

    void* cells;
    size_t cells_sz;

    struct ublkdrv_cmdb_ack* cmdb_ack;
    size_t cmdb_ack_sz;

    struct idr* reqs;
    struct ublkdrv_sema_bitset* cells_sema;
};

#endif /* UBLKDRV_CTX_H */
