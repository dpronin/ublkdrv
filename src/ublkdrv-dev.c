#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ublkdrv-dev.h"

#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/container_of.h>
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
#include "ublkdrv-ku-gate.h"
#include "ublkdrv-priv.h"
#include "ublkdrv-req.h"
#include "ublkdrv-uio.h"
#include "ublkdrv-uk-gate.h"

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

static inline void __ublkdrv_req_cells_free(struct ublkdrv_req const* req, struct ublkdrv_ctx* ctx)
{
    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_READ:
            __ublkdrv_sema_cells_free(ctx, ublkdrv_cmd_read_get_fcdn(&req->cmd.u.r), ublkdrv_cmd_read_get_cds_nr(&req->cmd.u.r));
            break;
        case UBLKDRV_CMD_OP_WRITE:
            __ublkdrv_sema_cells_free(ctx, ublkdrv_cmd_write_get_fcdn(&req->cmd.u.w), ublkdrv_cmd_write_get_cds_nr(&req->cmd.u.w));
            break;
        default:
            break;
    }
    wake_up_interruptible(&ctx->wq);
}

static void ublkdrv_req_cfq_push_work_h(struct work_struct* work)
{
    struct ublkdrv_ku_gate* ku_gate;
    int cmd_id;

    struct ublkdrv_req* req = container_of(work, struct ublkdrv_req, work);
    struct ublkdrv_dev* ubd = req->ubd;
    struct ublkdrv_ctx* ctx = ubd->ctx;
    struct uio_info* uinfo  = &ubd->uios[UBLKDRV_UIO_DIR_KERNEL_TO_USER]->uio;

retry:
    cmd_id = 0;

    rcu_read_lock();

    ku_gate = rcu_dereference(ubd->ku_gate);
    if (unlikely(!ku_gate)) {
        __ublkdrv_req_cells_free(req, ctx);
        rcu_read_unlock();
        ublkdrv_req_endio(req, BLK_STS_TRANSPORT);
        return;
    }

    spin_lock(&ctx->ku_state_ctx->lock);

    cmd_id = dynamic_bitmap_semaphore_trywait(ctx->ku_state_ctx->cmds_ids);
    if (unlikely(cmd_id < 0)) {
        DEFINE_WAIT(wq_entry);
        spin_unlock(&ctx->ku_state_ctx->lock);
        rcu_read_unlock();
        prepare_to_wait(&ctx->wq, &wq_entry, TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(100));
        finish_wait(&ctx->wq, &wq_entry);
        goto retry;
    }

    BUG_ON(ctx->ku_state_ctx->reqs_pending[cmd_id]);
    ctx->ku_state_ctx->reqs_pending[cmd_id] = req;

    spin_unlock(&ctx->ku_state_ctx->lock);

    ublkdrv_cmd_set_id(&req->cmd, (u8)cmd_id);

    /* clang-format off */
    for (;
           ku_gate && !ublkdrv_cfq_push(ku_gate->cmdb->cmds,
                                       ku_gate->cmdb->cmds_len,
                                       &ku_gate->cellc->cmdb_head,
                                       &ku_gate->cmdb->tail,
                                       &req->cmd)
         ; ku_gate = rcu_dereference(ubd->ku_gate)) {
        /* clang-format on */
        rcu_read_unlock();
        schedule();
        rcu_read_lock();
    }

    if (likely(ku_gate)) {
        uio_event_notify(uinfo);
    } else {
        spin_lock(&ctx->ku_state_ctx->lock);
        BUG_ON(dynamic_bitmap_semaphore_post(ctx->ku_state_ctx->cmds_ids, cmd_id));
        ctx->ku_state_ctx->reqs_pending[cmd_id] = NULL;
        spin_unlock(&ctx->ku_state_ctx->lock);
        __ublkdrv_req_cells_free(req, ctx);
        ublkdrv_req_endio(req, BLK_STS_TRANSPORT);
    }

    rcu_read_unlock();
}

void ublkdrv_req_finish_work_h(struct work_struct* work)
{
    struct ublkdrv_req* req = container_of(work, struct ublkdrv_req, work);
    struct ublkdrv_dev* ubd = req->ubd;
    struct ublkdrv_ctx* ctx = ubd->ctx;

    __ublkdrv_req_cells_free(req, ctx);
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
    struct ublkdrv_ctx* ctx           = ubd->ctx;
    struct ublkdrv_cellc const* cellc = ctx->cellc;

    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_READ:
            ublkdrv_req_from_cells_to_bio_copy(cellc, bio, ctx->cells, ublkdrv_cmd_read_get_fcdn(&req->cmd.u.r));
            nwh = ublkdrv_req_finish_work_h;
            nwq = ubd->wqs[UBLKDRV_FIN_WQ];
            break;
        case UBLKDRV_CMD_OP_WRITE:
            ublkdrv_req_from_bio_to_cells_copy(cellc, ctx->cells, bio, ublkdrv_cmd_write_get_fcdn(&req->cmd.u.w));
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

static inline u32 ublkdrv_cell_gr_index_get(struct ublkdrv_cells_groups_ctx* ctx, u32 pages_nr)
{
    return ublkdrv_order_rounddown_and_clamp(pages_nr, 0, ARRAY_SIZE(ctx->cells_groups_state) - 1);
}

static int ublkdrv_dev_req_cells_acquire(struct ublkdrv_dev* ubd, struct ublkdrv_ctx* uctx, struct ublkdrv_ku_gate* ku_gate, unsigned int sz, struct ublkdrv_req* req)
{
    int cell_gr_index;

    struct ublkdrv_cellc const* cellc = uctx->cellc;
    struct ublkdrv_celld dummy_celld  = {
         .offset  = 0u,
         .data_sz = 0u,
         .ncelld  = cellc->cellds_len,
    };
    int cells_nr                                      = 0;
    unsigned int pages_nr                             = DIV_ROUND_UP(sz, PAGE_SIZE);
    struct ublkdrv_cells_groups_ctx* cells_groups_ctx = uctx->cells_groups_ctx;

    spin_lock(&cells_groups_ctx->lock);

    cell_gr_index = ARRAY_SIZE(cells_groups_ctx->cells_groups_state) - 1;

    for (struct ublkdrv_celld *prev_celld = &dummy_celld, *celld = NULL;
         cells_nr <= U16_MAX && pages_nr && sz;
         ++cells_nr, celld->ncelld = uctx->cellc->cellds_len, sz -= celld->data_sz, prev_celld = celld) {

        u32 celldn;

        u32 const cell_gr_index_min_required = ublkdrv_cell_gr_index_get(cells_groups_ctx, pages_nr);

        cell_gr_index = min_t(int, cell_gr_index, cell_gr_index_min_required);

        for (; !(cell_gr_index < 0); --cell_gr_index) {
            celldn = dynamic_bitmap_semaphore_trywait(cells_groups_ctx->cells_groups_state[cell_gr_index]);
            if (likely(!(celldn < 0) && celldn < UBLKDRV_CTX_CELLS_PER_GROUP))
                break;
        }

        if (unlikely(cell_gr_index < 0)) {
            ublkdrv_sema_cells_free(uctx, dummy_celld.ncelld, cells_nr);
            spin_unlock(&cells_groups_ctx->lock);
            return -EBUSY;
        }

        celldn += cell_gr_index * UBLKDRV_CTX_CELLS_PER_GROUP;

        celld = &uctx->cellc->cellds[celldn];

        celld->data_sz = min_t(u32, sz, UBLKDRV_CELL_SZ_MIN << cell_gr_index);

        prev_celld->ncelld = celldn;
        pages_nr -= 1u << cell_gr_index;
    }

    if (unlikely(!(cells_nr <= U16_MAX))) {
        ublkdrv_sema_cells_free(uctx, dummy_celld.ncelld, cells_nr);
        spin_unlock(&cells_groups_ctx->lock);
        return -ENOTSUPP;
    }

    spin_unlock(&cells_groups_ctx->lock);

    BUG_ON(pages_nr || sz);
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

static int ublkdrv_req_cells_acquire(struct ublkdrv_req* req, unsigned int sz)
{
    struct ublkdrv_ku_gate* ku_gate;
    int rc;

    struct ublkdrv_dev* ubd = req->ubd;
    struct ublkdrv_ctx* ctx = ubd->ctx;

    if (unlikely(!sz))
        return 1;

    BUG_ON(!(sz <= ctx->params->max_req_sz));

retry:
    rcu_read_lock();

    ku_gate = rcu_dereference(ubd->ku_gate);
    if (unlikely(!ku_gate)) {
        rcu_read_unlock();
        return -ENOLINK;
    }

    rc = ublkdrv_dev_req_cells_acquire(ubd, ctx, ku_gate, sz, req);

    rcu_read_unlock();

    if (unlikely(rc)) {
        DEFINE_WAIT(wq_entry);
        prepare_to_wait(&ctx->wq, &wq_entry, TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(100));
        finish_wait(&ctx->wq, &wq_entry);
        goto retry;
    }

    return 0;
}

static void ublkdrv_req_submit_work_h(struct work_struct* work)
{
    void (*nwh)(struct work_struct*) = NULL;
    struct workqueue_struct* nwq     = NULL;

    struct ublkdrv_req* req = container_of(work, struct ublkdrv_req, work);
    struct bio* bio         = req->bio;
    struct ublkdrv_dev* ubd = req->ubd;
    int const op            = ublkdrv_bio_to_cmd_op(req->bio);
    if (op < 0) {
        ublkdrv_req_endio(req, BLK_STS_NOTSUPP);
        return;
    }

    int rc = 0;

    ublkdrv_cmd_set_op(&req->cmd, op);

    switch (ublkdrv_cmd_get_op(&req->cmd)) {
        case UBLKDRV_CMD_OP_WRITE:
            ublkdrv_cmd_write_set_offset(&req->cmd.u.w, bio->bi_iter.bi_sector << SECTOR_SHIFT);
            rc  = ublkdrv_req_cells_acquire(req, bio_sectors(bio) << SECTOR_SHIFT);
            nwh = ublkdrv_req_copy_work_h;
            nwq = ubd->wqs[UBLKDRV_COPY_WQ];
            break;
        case UBLKDRV_CMD_OP_READ:
            ublkdrv_cmd_read_set_offset(&req->cmd.u.r, bio->bi_iter.bi_sector << SECTOR_SHIFT);
            rc = ublkdrv_req_cells_acquire(req, bio_sectors(bio) << SECTOR_SHIFT);
            break;
        case UBLKDRV_CMD_OP_FLUSH:
            break;
        case UBLKDRV_CMD_OP_DISCARD:
            ublkdrv_cmd_discard_set_offset(&req->cmd.u.d, bio->bi_iter.bi_sector << SECTOR_SHIFT);
            ublkdrv_cmd_discard_set_sz(&req->cmd.u.d, bio_sectors(bio) << SECTOR_SHIFT);
            break;
        case UBLKDRV_CMD_OP_WRITE_ZEROES:
            ublkdrv_cmd_write_zeros_set_offset(&req->cmd.u.wz, bio->bi_iter.bi_sector << SECTOR_SHIFT);
            ublkdrv_cmd_write_zeros_set_sz(&req->cmd.u.wz, bio_sectors(bio) << SECTOR_SHIFT);
            break;
        default:
            ublkdrv_req_endio(req, BLK_STS_NOTSUPP);
            return;
    }

    if (unlikely(rc)) {
        ublkdrv_req_endio(req, rc < 0 ? errno_to_blk_status(rc) : BLK_STS_OK);
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
