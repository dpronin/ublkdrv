#ifndef UBLKDRV_CTX_H
#define UBLKDRV_CTX_H

#include <linux/bug.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/cmdb.h"
#include "uapi/ublkdrv/cmdb_ack.h"

#include "ublkdrv-cells-group-semaphore.h"

#define UBLKDRV_CMDS_LEN_MIN 2u
#define UBLKDRV_CMDS_LEN_MAX U8_MAX
static_assert(!(UBLKDRV_CMDS_LEN_MIN < 2), "UBLKDRV_CMDS_LEN_MIN must be at least 2, this is by design");
static_assert(UBLKDRV_CMDS_LEN_MAX <= U8_MAX, "UBLKDRV_CMDS_LEN_MAX must be at least U8_MAX, this is by design");

#define UBLKDRV_CELL_SZ_MIN PAGE_SIZE
#define UBLKDRV_CELL_SZ_MAX (1U << 20)
static_assert(0 != UBLKDRV_CELL_SZ_MIN && 0 == (UBLKDRV_CELL_SZ_MIN & (UBLKDRV_CELL_SZ_MIN - 1)), "UBLKDRV_CELL_SZ_MIN must be a power of 2");
static_assert(0 != UBLKDRV_CELL_SZ_MAX && 0 == (UBLKDRV_CELL_SZ_MAX & (UBLKDRV_CELL_SZ_MAX - 1)), "UBLKDRV_CELL_SZ_MAX must be a power of 2");
static_assert(PAGE_SIZE <= UBLKDRV_CELL_SZ_MIN && UBLKDRV_CELL_SZ_MIN <= UBLKDRV_CELL_SZ_MAX, "UBLKDRV_CELL_SZ_MIN must be in range [PAGE_SIZE, UBLKDRV_CELL_SZ_MAX]");

#define UBLKDRV_CTX_CELLS_GROUPS_NR (order_base_2(UBLKDRV_CELL_SZ_MAX / UBLKDRV_CELL_SZ_MIN) + 1)
#define UBLKDRV_CTX_CELLS_PER_GROUP 32

struct ublkdrv_cells_groups_ctx {
    spinlock_t lock;
    struct cells_group_semaphore* cells_groups_state[UBLKDRV_CTX_CELLS_GROUPS_NR];
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
    struct ublkdrv_cells_groups_ctx* cells_groups_ctx;

    struct wait_queue_head wq;
};

static inline void ublkdrv_sema_cells_free(struct ublkdrv_ctx* ctx, u32 celldn, u16 cellds_len)
{
    struct ublkdrv_celld const* celld = &ctx->cellc->cellds[celldn];
    for (; cellds_len && celldn < ctx->cellc->cellds_len;
         --cellds_len, celldn = celld->ncelld, celld = &ctx->cellc->cellds[celldn]) {

        BUG_ON(cells_group_semaphore_post(ctx->cells_groups_ctx->cells_groups_state[celldn / UBLKDRV_CTX_CELLS_PER_GROUP], celldn % UBLKDRV_CTX_CELLS_PER_GROUP));
    }
}

static inline void __ublkdrv_sema_cells_free(struct ublkdrv_ctx* ctx, u32 celldn, u16 cellds_len)
{
    spin_lock(&ctx->cells_groups_ctx->lock);
    ublkdrv_sema_cells_free(ctx, celldn, cellds_len);
    spin_unlock(&ctx->cells_groups_ctx->lock);
}

#endif /* UBLKDRV_CTX_H */
