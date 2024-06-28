#ifndef UBLKDRV_REQ_H
#define UBLKDRV_REQ_H

#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/cmd.h"

#include "ublkdrv-ctx.h"
#include "ublkdrv-dev.h"

struct ublkdrv_dev;

struct ublkdrv_req {
	struct work_struct work;
	struct ublkdrv_cmd cmd;
	struct bio *bio;
	unsigned long start_j;
	struct ublkdrv_dev *ubd;
	int err;
};

void ublkdrv_req_from_bio_to_cells_copy(struct ublkdrv_cellc const *cellc,
					void *cells, struct bio const *bio,
					u32 celldn);
void ublkdrv_req_from_cells_to_bio_copy(struct ublkdrv_cellc const *cellc,
					struct bio *bio, void const *cells,
					u32 celldn);

static inline void ublkdrv_req_cells_free(struct ublkdrv_req const *req,
					  struct ublkdrv_ctx *ctx)
{
	switch (ublkdrv_cmd_get_op(&req->cmd)) {
	case UBLKDRV_CMD_OP_READ:
		ublkdrv_sema_cells_free(
			ctx, ublkdrv_cmd_read_get_fcdn(&req->cmd.u.r),
			ublkdrv_cmd_read_get_cds_nr(&req->cmd.u.r));
		break;
	case UBLKDRV_CMD_OP_WRITE:
		ublkdrv_sema_cells_free(
			ctx, ublkdrv_cmd_write_get_fcdn(&req->cmd.u.w),
			ublkdrv_cmd_write_get_cds_nr(&req->cmd.u.w));
		break;
	default:
		break;
	}
}

static inline void ublkdrv_req_endio(struct ublkdrv_req *req,
				     blk_status_t bi_status)
{
	struct bio *bio = req->bio;
	struct ublkdrv_dev *ubd = req->ubd;

	bio->bi_status = bi_status;
	kmem_cache_free(ubd->req_kc, req);

	bio_endio(bio);
}

static inline void ublkdrv_req_submit(struct ublkdrv_req *req,
				      struct workqueue_struct *wq,
				      void (*wh)(struct work_struct *))
{
	INIT_WORK(&req->work, wh);
	queue_work(wq, &req->work);
}

#endif /* UBLKDRV_REQ_H */
