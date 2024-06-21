#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/cache.h>

#include <linux/align.h>
#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/compiler_attributes.h>
#include <linux/compiler_types.h>
#include <linux/container_of.h>
#include <linux/gfp_types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/limits.h>
#include <linux/math.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uio_driver.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "uapi/ublkdrv/cellc.h"
#include "uapi/ublkdrv/celld.h"
#include "uapi/ublkdrv/cmdb.h"
#include "uapi/ublkdrv/cmdb_ack.h"
#include "uapi/ublkdrv/def.h"

#include "ublkdrv-dynamic-bitmap-semaphore.h"

#include "ublkdrv-ctx.h"
#include "ublkdrv-dev.h"
#include "ublkdrv-genl.h"
#include "ublkdrv-req.h"
#include "ublkdrv-uio.h"
#include "ublkdrv.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pronin Denis <dannftk@yandex.ru>");
MODULE_DESCRIPTION("UBLKDRV");
MODULE_INFO(supported, "external");
MODULE_VERSION("1.2.3");
// MODULE_VERSION(__stringify(VERSION));

#define KiB_SHIFT 10
#define MiB_SHIFT 20
#define GiB_SHIFT 30

static int major;

static DEFINE_IDR(dev_id_idr);
static DEFINE_MUTEX(dev_id_lock);

static void ublkdrv_dev_acquire(struct ublkdrv_dev* ubd);
static void ublkdrv_dev_release(struct ublkdrv_dev* ubd);

static struct ublkdrv_dev_ops ublkdrv_dev_ops __read_mostly = {
    .acquire = ublkdrv_dev_acquire,
    .release = ublkdrv_dev_release,
};

static void ublkdrv_submit_bio(struct bio* bio);
static int ublkdrv_open(struct gendisk* gd, blk_mode_t mode);
static void ublkdrv_release(struct gendisk* gd);

static struct block_device_operations ublkdrv_bdev_ops __read_mostly = {
    .owner      = THIS_MODULE,
    .submit_bio = ublkdrv_submit_bio,
    .open       = ublkdrv_open,
    .release    = ublkdrv_release,
};

static int ublkdrv_open(struct gendisk* gd, blk_mode_t mode)
{
    return 0;
}

static void ublkdrv_release(struct gendisk* gd)
{
}

static void ublkdrv_submit_bio_fit(struct bio* bio, unsigned long start_j, struct ublkdrv_dev* ubd)
{
    struct ublkdrv_req* req;

    req = kzalloc_node(sizeof(*req), GFP_KERNEL, ubd->nid);
    if (unlikely(!req)) {
        bio->bi_status = BLK_STS_RESOURCE;
        bio_endio(bio);
        return;
    }

    req->bio     = bio;
    req->start_j = start_j;
    req->err     = -EIO;
    req->ubd     = ubd;

    ublkdrv_dev_submit(req);
}

static void ublkdrv_submit_bio(struct bio* bio)
{
    struct block_device* bdev   = bio->bi_bdev;
    struct gendisk* gd          = bdev->bd_disk;
    struct ublkdrv_dev* ubd     = gd->private_data;
    unsigned long const start_j = blk_queue_io_stat(gd->queue) ? bio_start_io_acct(bio) : 0;

    while ((bio_sectors(bio) << SECTOR_SHIFT) > ubd->ctx->params->max_req_sz) {
        struct bio* new_bio = bio_split(bio, ubd->ctx->params->max_req_sz >> SECTOR_SHIFT, GFP_NOIO, &fs_bio_set);
        bio_chain(new_bio, bio);
        ublkdrv_submit_bio_fit(new_bio, start_j, ubd);
    }

    ublkdrv_submit_bio_fit(bio, start_j, ubd);
}

static void ublkdrv_dev_id_free(unsigned long id)
{
    mutex_lock(&dev_id_lock);
    idr_remove(&dev_id_idr, id);
    mutex_unlock(&dev_id_lock);
}

static int ublkdrv_dev_id_alloc(void)
{
    int ret;

    ret = mutex_lock_interruptible(&dev_id_lock);
    if (ret)
        return ret;

    ret = idr_alloc(&dev_id_idr, (void*)-1, 0, 1 << MINORBITS, GFP_KERNEL);

    mutex_unlock(&dev_id_lock);

    return ret;
}

static int ublkdrv_ctx_init(struct ublkdrv_ctx* ctx, int nid)
{
    struct ublkdrv_cmdb* cmdb;
    struct ublkdrv_cellc* cellc;
    void* cells;
    struct ublkdrv_cmdb_ack* cmdb_ack;
    u32 cmds_len;
    u32 cellds_len;
    u32 celldn;
    u32 cell_off;
    size_t sz;
    int i, j;
    struct ublkdrv_ctx_params* params;

    int r = -ENOMEM;

    cmds_len = (PAGE_ALIGN(sizeof(*cmdb)) - sizeof(*cmdb)) / sizeof(cmdb->cmds[0]);
    cmds_len = clamp_t(u32, cmds_len, UBLKDRV_CMDS_LEN_MIN, UBLKDRV_CMDS_LEN_MAX);

    sz   = sizeof(*cmdb) + sizeof(cmdb->cmds[0]) * cmds_len;
    cmdb = kzalloc_node(PAGE_ALIGN(sz), GFP_KERNEL, nid);
    if (!cmdb)
        goto err;
    cmdb->cmds_len = (u8)cmds_len;

    ctx->cmdb    = cmdb;
    ctx->cmdb_sz = sz;

    sz    = UBLKDRV_CTX_CELLS_PER_GROUP * UBLKDRV_CELL_SZ_MIN * ((1u << UBLKDRV_CTX_CELLS_GROUPS_NR) - 1);
    cells = vzalloc(sz);
    if (!cells)
        goto free_cmdb;

    ctx->cells    = cells;
    ctx->cells_sz = sz;

    cellds_len = UBLKDRV_CTX_CELLS_PER_GROUP * UBLKDRV_CTX_CELLS_GROUPS_NR;

    sz    = sizeof(*cellc) + sizeof(cellc->cellds[0]) * cellds_len;
    cellc = kzalloc_node(PAGE_ALIGN(sz), GFP_KERNEL, nid);
    if (!cellc)
        goto free_cells;
    cellc->cellds_len = cellds_len;

    ctx->cellc    = cellc;
    ctx->cellc_sz = sz;

    for (cell_off = 0, celldn = 0; celldn < ctx->cellc->cellds_len; ++celldn) {
        struct ublkdrv_celld* celld = &ctx->cellc->cellds[celldn];

        celld->offset  = cell_off;
        celld->data_sz = 0;
        celld->ncelld  = ctx->cellc->cellds_len;

        cell_off += UBLKDRV_CELL_SZ_MIN << (celldn / UBLKDRV_CTX_CELLS_PER_GROUP);
    }

    BUG_ON(ctx->cells_sz != cell_off);

    sz       = sizeof(*cmdb_ack) + sizeof(cmdb_ack->cmds[0]) * cmdb->cmds_len;
    cmdb_ack = kzalloc_node(PAGE_ALIGN(sz), GFP_KERNEL, nid);
    if (!cmdb_ack)
        goto free_cellc;
    cmdb_ack->cmds_len = cmdb->cmds_len;

    ctx->cmdb_ack    = cmdb_ack;
    ctx->cmdb_ack_sz = sz;

    ctx->ku_state_ctx = kzalloc_node(sizeof(*ctx->ku_state_ctx), GFP_KERNEL, nid);
    if (!ctx->ku_state_ctx) {
        pr_err("unable to allocate a kernel/user state context, out of memory\n");
        goto free_cmdb_ack;
    }

    spin_lock_init(&ctx->ku_state_ctx->lock);

    ctx->ku_state_ctx->cmds_ids = kzalloc_node(sizeof(*ctx->ku_state_ctx->cmds_ids), GFP_KERNEL, nid);
    if (!ctx->ku_state_ctx->cmds_ids) {
        pr_err("unable to allocate command IDs semaphore bitmap, out of memory\n");
        goto free_ku_state_ctx;
    }

    r = dynamic_bitmap_semaphore_init(ctx->ku_state_ctx->cmds_ids, cmdb->cmds_len - 1, nid);
    if (r) {
        pr_err("unable to init command IDs semaphore bitmap, err %i\n", r);
        goto free_cmds_ids;
    }

    ctx->ku_state_ctx->reqs_pending = kcalloc_node(cmdb->cmds_len - 1, sizeof(ctx->ku_state_ctx->reqs_pending[0]), GFP_KERNEL, nid);
    if (!ctx->ku_state_ctx->reqs_pending) {
        pr_err("unable to allocate storage for pending requests, out of memory\n");
        goto destroy_cmds_ids;
    }

    ctx->cells_groups_ctx = kzalloc_node(sizeof(*ctx->cells_groups_ctx), GFP_KERNEL, nid);
    if (!ctx->cells_groups_ctx) {
        pr_err("unable to allocate cells bitmap semaphore, out of memory\n");
        goto free_reqs_pending;
    }

    spin_lock_init(&ctx->cells_groups_ctx->lock);

    for (i = 0; i < ARRAY_SIZE(ctx->cells_groups_ctx->cells_groups_state); ++i) {
        struct dynamic_bitmap_semaphore* cells_group_state = kzalloc_node(sizeof(*cells_group_state), GFP_KERNEL, nid);
        if (!cells_group_state) {
            pr_err("unable to alloc cells semaphore bitmap[%i], out of memory\n", i);
            goto destroy_cells_groups_state;
        }

        r = dynamic_bitmap_semaphore_init(cells_group_state, UBLKDRV_CTX_CELLS_PER_GROUP, nid);
        if (r) {
            pr_err("unable to init cells semaphore bitmap[%i], err %i\n", i, r);
            kfree(cells_group_state);
            goto destroy_cells_groups_state;
        }

        ctx->cells_groups_ctx->cells_groups_state[i] = cells_group_state;
    }

    params = kzalloc_node(sizeof(*params), GFP_KERNEL, nid);
    if (!params) {
        pr_err("unable to allocate params, out of memory\n");
        goto destroy_cells_groups_state;
    }

    params->max_req_sz = ctx->cells_sz;

    ctx->params = params;

    init_waitqueue_head(&ctx->wq);

    return 0;

destroy_cells_groups_state:
    for (j = i - 1; !(j < 0); --j) {
        struct dynamic_bitmap_semaphore* cells_group_state = ctx->cells_groups_ctx->cells_groups_state[j];
        dynamic_bitmap_semaphore_destroy(cells_group_state);
        kfree(cells_group_state);
    }
    kfree(ctx->cells_groups_ctx);
    ctx->cells_groups_ctx = NULL;

free_reqs_pending:
    kfree(ctx->ku_state_ctx->reqs_pending);

destroy_cmds_ids:
    dynamic_bitmap_semaphore_destroy(ctx->ku_state_ctx->cmds_ids);

free_cmds_ids:
    kfree(ctx->ku_state_ctx->cmds_ids);

free_ku_state_ctx:
    kfree(ctx->ku_state_ctx);
    ctx->ku_state_ctx = NULL;

free_cmdb_ack:
    kfree(cmdb_ack);
    ctx->cmdb_ack    = NULL;
    ctx->cmdb_ack_sz = 0;

free_cellc:
    kfree(cellc);
    ctx->cellc    = NULL;
    ctx->cellc_sz = 0;

free_cells:
    vfree(cells);
    ctx->cells    = NULL;
    ctx->cells_sz = 0;

free_cmdb:
    kfree(cmdb);
    ctx->cmdb    = NULL;
    ctx->cmdb_sz = 0;

err:
    return r;
}

static void ublkdrv_ctx_deinit(struct ublkdrv_ctx* ctx)
{
    int i;

    kfree_const(ctx->params);
    ctx->params = NULL;

    for (i = ARRAY_SIZE(ctx->cells_groups_ctx->cells_groups_state) - 1; !(i < 0); --i) {
        struct dynamic_bitmap_semaphore* cells_groups_state = ctx->cells_groups_ctx->cells_groups_state[i];
        dynamic_bitmap_semaphore_destroy(cells_groups_state);
        kfree(cells_groups_state);
    }
    kfree(ctx->cells_groups_ctx);
    ctx->cells_groups_ctx = NULL;

    kfree(ctx->ku_state_ctx->reqs_pending);
    dynamic_bitmap_semaphore_destroy(ctx->ku_state_ctx->cmds_ids);
    kfree(ctx->ku_state_ctx->cmds_ids);
    kfree(ctx->ku_state_ctx);
    ctx->ku_state_ctx = NULL;

    kfree(ctx->cmdb_ack);
    ctx->cmdb_ack    = NULL;
    ctx->cmdb_ack_sz = 0;

    vfree(ctx->cells);
    ctx->cells    = NULL;
    ctx->cells_sz = 0;

    kfree(ctx->cellc);
    ctx->cellc    = NULL;
    ctx->cellc_sz = 0;

    kfree(ctx->cmdb);
    ctx->cmdb    = NULL;
    ctx->cmdb_sz = 0;
}

static void ublkdrv_dev_acquire(struct ublkdrv_dev* ubd)
{
    kref_get(&ubd->ref);
}

static void ublkdrv_dev_free(struct ublkdrv_dev* ubd)
{
    int i;

    for (i = ARRAY_SIZE(ubd->uios) - 1; !(i < 0); --i) {
        struct ublkdrv_uio* uio = ubd->uios[i];
        kfree_const(uio->name);
        kfree(uio);
    }
    ublkdrv_ctx_deinit(ubd->ctx);
    kfree(ubd->ctx);
    kfree(ubd);
}


static void __ublkdrv_dev_release_rcu(struct rcu_head* rcu)
{
    struct ublkdrv_dev* ubd = container_of(rcu, struct ublkdrv_dev, rcu);
    ublkdrv_dev_free(ubd);
}

static void __ublkdrv_dev_release(struct kref* ref)
{
    struct ublkdrv_dev* ubd = container_of(ref, struct ublkdrv_dev, ref);
    call_rcu(&ubd->rcu, __ublkdrv_dev_release_rcu);
}

static void ublkdrv_dev_release(struct ublkdrv_dev* ubd)
{
    kref_put(&ubd->ref, __ublkdrv_dev_release);
}

struct ublkdrv_dev* ublkdrv_dev_create(char const* disk_name, u64 capacity_sectors, bool read_only, int nid)
{
    int r, id;
    struct ublkdrv_dev* ubd;
    struct gendisk* gd;
    int i;

    if (!disk_name || !(strlen(disk_name) < DISK_NAME_LEN))
        return ERR_PTR(-EINVAL);

    if (!(0 <= nid && nid < num_online_nodes()))
        return ERR_PTR(-EINVAL);

    ubd = kzalloc_node(sizeof(*ubd), GFP_KERNEL, nid);
    if (!ubd) {
        pr_err("unable to allocate device, out of memory.\n");
        return NULL;
    }

    ubd->nid = nid;

    ubd->ctx = kzalloc_node(sizeof(*ubd->ctx), GFP_KERNEL, ubd->nid);
    if (!ubd->ctx) {
        pr_err("unable to allocate device context, out of memory.\n");
        goto free_ubd;
    }

    r = ublkdrv_ctx_init(ubd->ctx, ubd->nid);
    if (r) {
        pr_err("unable to initialize device context, err %i\n", r);
        goto free_ctx;
    }

    rcu_assign_pointer(ubd->ku_gate, NULL);
    rcu_assign_pointer(ubd->uk_gate, NULL);

    r = id = ublkdrv_dev_id_alloc();
    if (r < 0) {
        pr_err("unable to allocate device ID, err %i\n", r);
        goto deinit_ctx;
    }
    ubd->id = id;

    r = 0;

    gd = blk_alloc_disk(NULL, ubd->nid);
    if (!gd) {
        pr_err("unable to allocate gendisk, out of memory\n");
        goto free_id;
    }

    gd->major       = major;
    gd->first_minor = id;
    gd->minors      = 1;
    gd->fops        = &ublkdrv_bdev_ops;
    gd->flags |= GENHD_FL_NO_PART;
    gd->private_data = ubd;
    strncpy(gd->disk_name, disk_name, sizeof(gd->disk_name));
    set_disk_ro(gd, read_only);
    set_capacity(gd, capacity_sectors);

    blk_queue_max_hw_sectors(gd->queue, ubd->ctx->cells_sz >> SECTOR_SHIFT);
    blk_queue_chunk_sectors(gd->queue, ubd->ctx->cells_sz >> SECTOR_SHIFT);
    blk_queue_io_opt(gd->queue, ubd->ctx->cells_sz);
    blk_set_queue_depth(gd->queue, ubd->ctx->cmdb->cmds_len - 1);
    blk_queue_write_cache(gd->queue, true, false);

    blk_queue_flag_set(QUEUE_FLAG_IO_STAT, gd->queue);

    format_dev_t(ubd->name, MKDEV(major, gd->first_minor));

    ubd->wqs[UBLKDRV_FIN_WQ] = alloc_workqueue("kreqfin/%s", WQ_MEM_RECLAIM, 1, gd->disk_name);
    if (!ubd->wqs[UBLKDRV_FIN_WQ]) {
        pr_err("unable to allocate a workqueue for requests finishing, out of memory\n");
        goto destroy_wqs;
    }

    ubd->wqs[UBLKDRV_COPY_WQ] = alloc_workqueue("kcpy/%s", WQ_UNBOUND, 0, gd->disk_name);
    if (!ubd->wqs[UBLKDRV_COPY_WQ]) {
        pr_err("unable to allocate a workqueue for copying data, out of memory\n");
        goto destroy_wqs;
    }

    ubd->wqs[UBLKDRV_CFQ_POP_WQ] = alloc_workqueue("kcmdcomp/%s", WQ_UNBOUND, 1, gd->disk_name);
    if (!ubd->wqs[UBLKDRV_CFQ_POP_WQ]) {
        pr_err("unable to allocate a workqueue for cfq commands popping, out of memory\n");
        goto destroy_wqs;
    }

    ubd->wqs[UBLKDRV_CFQ_PUSH_WQ] = alloc_workqueue("kcfqpush/%s", WQ_UNBOUND, 1, gd->disk_name);
    if (!ubd->wqs[UBLKDRV_CFQ_PUSH_WQ]) {
        pr_err("unable to allocate a workqueue for cfq commands pushing, out of memory\n");
        goto put_disk;
    }

    ubd->wqs[UBLKDRV_SUBM_WQ] = alloc_workqueue("kreqsubm/%s", 0, 1, gd->disk_name);
    if (!ubd->wqs[UBLKDRV_SUBM_WQ]) {
        pr_err("unable to allocate a workqueue for requests submission, out of memory\n");
        goto destroy_wqs;
    }

    r = add_disk(gd);
    if (r)
        goto destroy_wqs;

    ubd->disk = gd;

    r = ublkdrv_uios_register(ubd);
    if (r)
        goto del_disk;

    kref_init(&ubd->ref);
    ubd->ops = &ublkdrv_dev_ops;

    return ubd;

del_disk:
    del_gendisk(gd);

destroy_wqs:
    for (i = ARRAY_SIZE(ubd->wqs) - 1; !(i < 0); --i) {
        if (ubd->wqs[i]) {
            destroy_workqueue(ubd->wqs[i]);
            ubd->wqs[i] = NULL;
        }
    }

put_disk:
    put_disk(gd);

free_id:
    ublkdrv_dev_id_free(id);

deinit_ctx:
    ublkdrv_ctx_deinit(ubd->ctx);

free_ctx:
    kfree(ubd->ctx);

free_ubd:
    kfree(ubd);

    return NULL;
}

void ublkdrv_dev_destroy(struct ublkdrv_dev* ubd)
{
    int i;

    ublkdrv_uios_unregister(ubd);
    del_gendisk(ubd->disk);
    for (i = ARRAY_SIZE(ubd->wqs) - 1; !(i < 0); --i)
        destroy_workqueue(ubd->wqs[i]);
    put_disk(ubd->disk);
    ublkdrv_dev_id_free(ubd->id);

    ubd->ops->release(ubd);
}

static int __init ublkdrv_init(void)
{
    int rc = 0;

    pr_info("%s-%s init for kernel %s %s", module_name(THIS_MODULE), THIS_MODULE ? THIS_MODULE->version : "unknown", utsname()->release, utsname()->version);

    major = register_blkdev(major, UBLKDRV_BLKDEV_NAME);
    if (major <= 0) {
        pr_err("register_blkdev() failed, err %i\n", major);
        rc = -EINVAL;
        goto out;
    }

    pr_info("register_blkdev() success, major %i\n", major);

    rc = ublkdrv_genl_init();
    if (rc) {
        pr_err("ublkdrv_genl_init() failed, err %i\n", rc);
        rc = -EINVAL;
        goto unreg;
    }

    pr_info("ublkdrv_genl_init() success\n");

    return 0;

unreg:
    unregister_blkdev(major, UBLKDRV_BLKDEV_NAME);

out:
    return rc;
}

static void __exit ublkdrv_exit(void)
{
    pr_info("ublkdrv_genl_deinit()\n");
    ublkdrv_genl_deinit();
    pr_info("unregister_blkdev(), major %i\n", major);
    unregister_blkdev(major, UBLKDRV_BLKDEV_NAME);
    idr_destroy(&dev_id_idr);
}

module_init(ublkdrv_init);
module_exit(ublkdrv_exit);
