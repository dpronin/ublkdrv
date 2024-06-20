#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ublkdrv-dev.h"

#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/math.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/uio_driver.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "uapi/ublkdrv/cmd.h"
#include "uapi/ublkdrv/cmdb.h"

#include "ublkdrv-cfq.h"
#include "ublkdrv-ctx.h"
#include "ublkdrv-dynamic-bitmap-semaphore.h"
#include "ublkdrv-priv.h"
#include "ublkdrv-req.h"
#include "ublkdrv-uio.h"

static inline int ublkdrv_bio_to_cmd_op(struct bio const* bio)
{
    blk_opf_t const op = bio_op(bio);
    switch (op) {
        case REQ_OP_READ:
            return UBLKDRV_CMD_OP_READ;
        case REQ_OP_WRITE:
            return op_is_flush(bio->bi_opf) && !bio_sectors(bio) ? UBLKDRV_CMD_OP_FLUSH : UBLKDRV_CMD_OP_WRITE;
        case REQ_OP_FLUSH:
            return UBLKDRV_CMD_OP_FLUSH;
        case REQ_OP_DISCARD:
            return UBLKDRV_CMD_OP_DISCARD;
        case REQ_OP_WRITE_ZEROES:
        case REQ_OP_SECURE_ERASE:
            return UBLKDRV_CMD_OP_WRITE_ZEROES;
        default:
            return -1;
    }
}

static inline void __ublkdrv_req_cells_free(struct ublkdrv_req const* req, struct ublkdrv_ctx* kctx)
{
    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_READ:
            __ublkdrv_sema_cells_free(kctx, ublkdrv_cmd_read_get_fcdn(&req->cmd.u.r), ublkdrv_cmd_read_get_cds_nr(&req->cmd.u.r));
            break;
        case UBLKDRV_CMD_OP_WRITE:
            __ublkdrv_sema_cells_free(kctx, ublkdrv_cmd_write_get_fcdn(&req->cmd.u.w), ublkdrv_cmd_write_get_cds_nr(&req->cmd.u.w));
            break;
        default:
            break;
    }
    wake_up_interruptible(&kctx->wq);
}

static void ublkdrv_req_cfq_push_work_h(struct work_struct* work)
{
    struct ublkdrv_ctx* uctx;
    u32 cmd_id;
    int r;
    bool reqs_preloaded;

    struct ublkdrv_req* req  = container_of(work, struct ublkdrv_req, work);
    struct ublkdrv_dev* ubd  = req->ubd;
    struct ublkdrv_ctx* kctx = ubd->kctx;
    struct uio_info* uinfo   = &ubd->uios[UBLKDRV_UIO_DIR_KERNEL_TO_USER]->uio;

retry:
    cmd_id = 0;

    idr_preload(GFP_KERNEL);

    rcu_read_lock();

    uctx = rcu_dereference(ubd->uctx);
    if (unlikely(!uctx)) {
        __ublkdrv_req_cells_free(req, kctx);
        rcu_read_unlock();
        idr_preload_end();
        ublkdrv_req_endio(req, BLK_STS_TRANSPORT);
        return;
    }

    idr_lock(uctx->reqs);

    r = idr_alloc_u32(uctx->reqs, req, &cmd_id, uctx->cmdb->cmds_len - 2, GFP_NOWAIT);
    if (unlikely(r)) {
        DEFINE_WAIT(wq_entry);
        idr_unlock(uctx->reqs);
        rcu_read_unlock();
        idr_preload_end();
        prepare_to_wait(&kctx->wq, &wq_entry, TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(100));
        finish_wait(&kctx->wq, &wq_entry);
        goto retry;
    }

    ublkdrv_cmd_set_id(&req->cmd, (u8)cmd_id);

    for (reqs_preloaded = true; uctx && !ublkdrv_cfq_push(uctx->cmdb->cmds, uctx->cmdb->cmds_len, &uctx->cellc->cmdb_head, &uctx->cmdb->tail, &req->cmd);) {
        idr_unlock(uctx->reqs);
        rcu_read_unlock();

        if (reqs_preloaded) {
            idr_preload_end();
            reqs_preloaded = false;
        }

        schedule();

        rcu_read_lock();

        uctx = rcu_dereference(ubd->uctx);
        if (unlikely(!uctx)) {
            rcu_read_unlock();
            continue;
        }

        idr_lock(uctx->reqs);
    }

    if (likely(uctx)) {
        idr_unlock(uctx->reqs);
        rcu_read_unlock();
    }

    if (likely(reqs_preloaded))
        idr_preload_end();

    if (likely(uctx)) {
        uio_event_notify(uinfo);
    } else {
        idr_lock(kctx->reqs);
        idr_remove(kctx->reqs, cmd_id);
        idr_unlock(kctx->reqs);
        __ublkdrv_req_cells_free(req, kctx);
        ublkdrv_req_endio(req, BLK_STS_TRANSPORT);
    }
}

void ublkdrv_req_finish_work_h(struct work_struct* work)
{
    struct ublkdrv_req* req  = container_of(work, struct ublkdrv_req, work);
    struct ublkdrv_dev* ubd  = req->ubd;
    struct ublkdrv_ctx* kctx = ubd->kctx;

    __ublkdrv_req_cells_free(req, kctx);
    if (req->start_j)
        bio_end_io_acct(req->bio, req->start_j);

    ublkdrv_req_endio(req, errno_to_blk_status(req->err));
}

void ublkdrv_req_copy_work_h(struct work_struct* work)
{
    void (*nwh)(struct work_struct*);
    struct workqueue_struct* nwq;

    struct ublkdrv_req* req           = container_of(work, struct ublkdrv_req, work);
    struct bio* bio                   = req->bio;
    struct ublkdrv_dev* ubd           = req->ubd;
    struct ublkdrv_ctx* kctx          = ubd->kctx;
    struct ublkdrv_cellc const* cellc = kctx->cellc;

    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_READ:
            ublkdrv_req_from_cells_to_bio_copy(cellc, bio, kctx->cells, ublkdrv_cmd_read_get_fcdn(&req->cmd.u.r));
            nwh = ublkdrv_req_finish_work_h;
            nwq = ubd->wqs[UBLKDRV_FIN_WQ];
            break;
        case UBLKDRV_CMD_OP_WRITE:
            ublkdrv_req_from_bio_to_cells_copy(cellc, kctx->cells, bio, ublkdrv_cmd_write_get_fcdn(&req->cmd.u.w));
            fallthrough;
        default:
            nwh = ublkdrv_req_cfq_push_work_h;
            nwq = ubd->wqs[UBLKDRV_CFQ_PUSH_WQ];
            break;
    }

    ublkdrv_req_submit(req, nwq, nwh);
}

static inline u32 ublkdrv_order_rounddown_and_clamp(u32 value, u32 min, u32 max)
{
    u32 const order = order_base_2(rounddown_pow_of_two(value));
    return clamp_t(u32, order, min, max);
}

static inline u32 ublkdrv_get_sema_index(struct ublkdrv_cells_groups_ctx* ctx, u32 pages_nr)
{
    return ublkdrv_order_rounddown_and_clamp(pages_nr, 0, ARRAY_SIZE(ctx->cells_groups_state) - 1);
}

static int ublkdrv_dev_req_cells_acquire(struct ublkdrv_dev* ubd, struct ublkdrv_ctx* uctx, unsigned int bio_sz, struct ublkdrv_req* req)
{
    int sema_index;

    struct ublkdrv_cellc const* cellc = uctx->cellc;
    struct ublkdrv_celld dummy_celld  = {
         .offset  = 0u,
         .data_sz = 0u,
         .ncelld  = cellc->cellds_len,
    };
    int cells_nr                                      = 0;
    unsigned int bio_len_pgs                          = DIV_ROUND_UP(bio_sz, PAGE_SIZE);
    struct ublkdrv_cells_groups_ctx* cells_groups_ctx = uctx->cells_groups_ctx;

    spin_lock(&cells_groups_ctx->lock);

    sema_index = ARRAY_SIZE(cells_groups_ctx->cells_groups_state) - 1;

    for (struct ublkdrv_celld *prev_celld = &dummy_celld, *celld = NULL;
         cells_nr <= U16_MAX && bio_len_pgs && bio_sz;
         ++cells_nr, celld->ncelld = uctx->cellc->cellds_len, bio_sz -= celld->data_sz, prev_celld = celld) {

        u32 celldn;

        u32 const sema_index_min = ublkdrv_get_sema_index(cells_groups_ctx, bio_len_pgs);

        sema_index = min_t(int, sema_index, sema_index_min);

        for (; !(sema_index < 0); --sema_index) {
            celldn = dynamic_bitmap_semaphore_trywait(cells_groups_ctx->cells_groups_state[sema_index]);
            if (likely(!(celldn < 0) && celldn < UBLKDRV_CTX_CELLS_PER_GROUP))
                break;
        }

        if (unlikely(sema_index < 0)) {
            ublkdrv_sema_cells_free(uctx, dummy_celld.ncelld, cells_nr);
            spin_unlock(&cells_groups_ctx->lock);
            return -EBUSY;
        }

        celldn += sema_index * UBLKDRV_CTX_CELLS_PER_GROUP;

        celld = &uctx->cellc->cellds[celldn];

        celld->data_sz = min_t(u32, bio_sz, UBLKDRV_CELL_SZ_MIN << sema_index);

        prev_celld->ncelld = celldn;
        bio_len_pgs -= 1u << sema_index;
    }

    if (unlikely(!(cells_nr <= U16_MAX))) {
        ublkdrv_sema_cells_free(uctx, dummy_celld.ncelld, cells_nr);
        spin_unlock(&cells_groups_ctx->lock);
        return -ENOTSUPP;
    }

    spin_unlock(&cells_groups_ctx->lock);

    BUG_ON(bio_len_pgs || bio_sz);
    BUG_ON(cells_nr && !(dummy_celld.ncelld < uctx->cellc->cellds_len));

    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_READ:
            ublkdrv_cmd_read_set_fcdn(&req->cmd.u.r, dummy_celld.ncelld);
            ublkdrv_cmd_read_set_cds_nr(&req->cmd.u.r, (u16)cells_nr);
            break;
        case UBLKDRV_CMD_OP_WRITE:
            ublkdrv_cmd_write_set_fcdn(&req->cmd.u.w, dummy_celld.ncelld);
            ublkdrv_cmd_write_set_cds_nr(&req->cmd.u.w, (u16)cells_nr);
            break;
        default:
            BUG();
    }

    return 0;
}

static int ublkdrv_req_cells_acquire(struct ublkdrv_req* req)
{
    struct ublkdrv_ctx* uctx;
    int rc;

    struct bio const* bio    = req->bio;
    struct ublkdrv_dev* ubd  = req->ubd;
    struct ublkdrv_ctx* kctx = ubd->kctx;
    unsigned int bio_sz      = bio_sectors(bio) << SECTOR_SHIFT;

    if (unlikely(!bio_sz))
        return 1;

    BUG_ON(!(bio_sz <= kctx->params->max_req_sz));

retry:
    rcu_read_lock();

    uctx = rcu_dereference(ubd->uctx);
    if (unlikely(!uctx)) {
        rcu_read_unlock();
        return -ENOLINK;
    }

    rc = ublkdrv_dev_req_cells_acquire(ubd, uctx, bio_sz, req);

    rcu_read_unlock();

    if (unlikely(rc)) {
        DEFINE_WAIT(wq_entry);
        prepare_to_wait(&kctx->wq, &wq_entry, TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(100));
        finish_wait(&kctx->wq, &wq_entry);
        goto retry;
    }

    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_READ:
            ublkdrv_cmd_read_set_offset(&req->cmd.u.r, bio->bi_iter.bi_sector << SECTOR_SHIFT);
            break;
        case UBLKDRV_CMD_OP_WRITE:
            ublkdrv_cmd_write_set_offset(&req->cmd.u.w, bio->bi_iter.bi_sector << SECTOR_SHIFT);
            break;
        default:
            BUG();
    }

    return 0;
}

static void ublkdrv_req_submit_work_h(struct work_struct* work)
{
    void (*nwh)(struct work_struct*) = NULL;
    struct workqueue_struct* nwq     = NULL;

    struct ublkdrv_req* req = container_of(work, struct ublkdrv_req, work);
    struct ublkdrv_dev* ubd = req->ubd;
    int const op            = ublkdrv_bio_to_cmd_op(req->bio);
    if (op < 0) {
        ublkdrv_req_endio(req, BLK_STS_NOTSUPP);
        return;
    }

    ublkdrv_cmd_set_op(&req->cmd, op);

    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_WRITE:
            nwh = ublkdrv_req_copy_work_h;
            nwq = ubd->wqs[UBLKDRV_COPY_WQ];
            fallthrough;
        case UBLKDRV_CMD_OP_READ: {
            int const rc = ublkdrv_req_cells_acquire(req);
            if (unlikely(rc)) {
                ublkdrv_req_endio(req, rc < 0 ? errno_to_blk_status(rc) : BLK_STS_OK);
                return;
            }
        } break;
        case UBLKDRV_CMD_OP_FLUSH:
            break;
        case UBLKDRV_CMD_OP_DISCARD:
            ublkdrv_cmd_discard_set_sz(&req->cmd.u.d, bio_sectors(req->bio) << SECTOR_SHIFT);
            break;
        case UBLKDRV_CMD_OP_WRITE_ZEROES:
            ublkdrv_cmd_write_zeros_set_sz(&req->cmd.u.wz, bio_sectors(req->bio) << SECTOR_SHIFT);
            break;
        default:
            ublkdrv_req_endio(req, BLK_STS_NOTSUPP);
            return;
    }

    nwh = nwh ?: ublkdrv_req_cfq_push_work_h;
    nwq = nwq ?: ubd->wqs[UBLKDRV_CFQ_PUSH_WQ];

    ublkdrv_req_submit(req, nwq, nwh);
}

void ublkdrv_dev_submit(struct ublkdrv_req* req)
{
    ublkdrv_req_submit(req, req->ubd->wqs[UBLKDRV_SUBM_WQ], ublkdrv_req_submit_work_h);
}
