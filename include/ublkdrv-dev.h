#ifndef UBLKDRV_DEV_H
#define UBLKDRV_DEV_H

#include <linux/blkdev.h>
#include <linux/compiler_types.h>
#include <linux/kref.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "ublkdrv-ctx.h"
#include "ublkdrv-ku-gate.h"
#include "ublkdrv-mapping.h"
#include "ublkdrv-req.h"
#include "ublkdrv-uk-gate.h"

struct ublkdrv_uio;

enum {
    UBLKDRV_FIN_WQ,
    UBLKDRV_COPY_WQ,
    UBLKDRV_CFQ_POP_WQ,
    UBLKDRV_CFQ_PUSH_WQ,
    UBLKDRV_SUBM_WQ,
    //
    UBLKDRV_WQS_QTY,
};

struct ublkdrv_dev;

struct ublkdrv_dev_ops {
    void (*acquire)(struct ublkdrv_dev*);
    void (*release)(struct ublkdrv_dev*);
};

struct ublkdrv_dev {
    int nid;
    int id;
    char name[16];
    struct kref ref;
    struct rcu_head rcu;
    struct ublkdrv_dev_ops const* ops;
    struct ublkdrv_ctx* ctx;
    struct ublkdrv_ku_gate __rcu* ku_gate;
    struct ublkdrv_uk_gate __rcu* uk_gate;
    struct gendisk* disk;
    struct ublkdrv_uio* uios[UBLKDRV_UIO_DIRS_QTY];
    struct workqueue_struct* wqs[UBLKDRV_WQS_QTY];
};

void ublkdrv_dev_submit(struct ublkdrv_req* req);

#endif /* UBLKDRV_DEV_H */
