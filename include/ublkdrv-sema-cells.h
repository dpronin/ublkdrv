#ifndef UBLKDRV_SEMA_CELLS_H
#define UBLKDRV_SEMA_CELLS_H

#include <linux/bug.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "ublkdrv-ctx.h"

#include "ublkdrv-sema-bitset.h"

static inline void ublkdrv_sema_cells_free(struct ublkdrv_ctx* ctx, u32 celldn, u16 cellds_len)
{
    struct ublkdrv_celld const* celld = &ctx->cellc->cellds[celldn];
    for (; cellds_len && celldn < ctx->cellc->cellds_len;
         --cellds_len, celldn = celld->ncelld, celld = &ctx->cellc->cellds[celldn]) {

        BUG_ON(sema_bitset_post(ctx->cells_sema->semas[celldn / UBLKDRV_CTX_CELLS_PER_BITSET], celldn % UBLKDRV_CTX_CELLS_PER_BITSET));
    }
}

static inline void __ublkdrv_sema_cells_free(struct ublkdrv_ctx* ctx, u32 celldn, u16 cellds_len)
{
    spin_lock(&ctx->cells_sema->lock);
    ublkdrv_sema_cells_free(ctx, celldn, cellds_len);
    spin_unlock(&ctx->cells_sema->lock);
}

#endif /* UBLKDRV_SEMA_CELLS_H */
