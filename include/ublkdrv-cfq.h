#ifndef UBLKDRV_CFQ_H
#define UBLKDRV_CFQ_H

#include <asm/barrier.h>

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/types.h>

#include "uapi/ublkdrv/cmd.h"
#include "uapi/ublkdrv/cmd_ack.h"

static inline bool ublkdrv_cfq_ack_pop(struct ublkdrv_cmd_ack const cmds[], u8 cmds_len, u8* phead, u8 const* ptail, struct ublkdrv_cmd_ack* cmd_out)
{
    u8 const ch = READ_ONCE(*phead);
    u8 const ct = smp_load_acquire(ptail);
    if (likely(ct != ch)) {
        BUG_ON(!(ch < cmds_len));
        *cmd_out = cmds[ch];
        smp_store_release(phead, (ch + 1) % cmds_len);
        return true;
    }

    return false;
}

static inline bool ublkdrv_cfq_push(struct ublkdrv_cmd cmds[], u8 cmds_len, u8 const* phead, u8* ptail, struct ublkdrv_cmd const* cmd_in)
{
    u8 const ct  = *ptail;
    u8 const nct = (ct + 1) % cmds_len;
    if (likely(nct != READ_ONCE(*phead))) {
        BUG_ON(!(ct < cmds_len));
        cmds[ct] = *cmd_in;
        smp_store_release(ptail, nct);
        return true;
    }
    return false;
}

#endif /* UBLKDRV_CFQ_H */
