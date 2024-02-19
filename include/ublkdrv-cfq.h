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
    u8 ph = smp_load_acquire(phead);
    u8 ph_old;
    do {
        u8 const pt = smp_load_acquire(ptail);
        ph_old      = ph;
        if (unlikely(pt == ph))
            return false;
        BUG_ON(!(ph < cmds_len));
        *cmd_out = cmds[ph];
    } while (ph_old != (ph = cmpxchg_release(phead, ph, (ph + 1) % cmds_len)));

    return true;
}

static inline bool ublkdrv_cfq_push(struct ublkdrv_cmd cmds[], u8 cmds_len, u8 const* phead, u8* ptail, struct ublkdrv_cmd const* cmd_in)
{
    __u8 const pt  = *ptail;
    __u8 const npt = (pt + 1) % cmds_len;
    if (unlikely(npt == smp_load_acquire(phead)))
        return false;
    BUG_ON(!(pt < cmds_len));
    cmds[pt] = *cmd_in;
    smp_store_release(ptail, npt);
    return true;
}

#endif /* UBLKDRV_CFQ_H */
